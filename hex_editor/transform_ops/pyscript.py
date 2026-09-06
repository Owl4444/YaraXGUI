# -*- coding: utf-8 -*-
"""User-supplied Python transforms: eval, exec, and external script file.

Three flavours, in order of increasing power:

1. **Python: eval expression** — one-liner. ``data`` is in scope; the
   expression value becomes the output.
2. **Python: exec script** — multiline block. ``data`` is in scope; the
   script must assign ``result``.
3. **Python: run script file** — imports a ``.py`` from disk and calls
   its ``transform(data, params) -> bytes`` function.

All three run in-process with full host privileges. Only use code you
trust — there is no sandbox.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import traceback
from pathlib import Path

from ..transforms import (TransformError, TransformParam, debug_log_append,
                          register_transform)


_SAFETY_NOTE = ("Runs arbitrary Python in-process — use only code you trust.")


# ── result coercion ────────────────────────────────────────────────

def _coerce_result(result) -> bytes:
    if result is None:
        raise TransformError(
            "Script produced no result. Assign `result = <bytes>`."
        )
    if isinstance(result, (bytes, bytearray, memoryview)):
        return bytes(result)
    if isinstance(result, str):
        return result.encode("utf-8")
    if isinstance(result, (list, tuple)) and all(isinstance(x, int) for x in result):
        try:
            return bytes(result)
        except ValueError as e:
            raise TransformError(f"Byte values out of range: {e}") from e
    raise TransformError(
        f"Script result must be bytes / bytearray / str "
        f"(got {type(result).__name__})."
    )


def _format_user_traceback(exc: BaseException, filename: str) -> str:
    """Return the last few frames of *exc*'s traceback, trimmed to the
    user's script (frames whose filename matches *filename*)."""
    tb_lines = traceback.format_exception(type(exc), exc, exc.__traceback__, limit=6)
    # Find frames from the user's code to hoist them to the front of the message.
    user_frames = [ln.strip() for ln in tb_lines
                   if filename in ln and "line" in ln]
    head = f"{type(exc).__name__}: {exc}"
    if user_frames:
        return f"{head}  ({user_frames[-1]})"
    return head


def _flush_stdout_to_debug_log(buf: io.StringIO, prefix: str) -> None:
    """Copy captured stdout (line-by-line) into the dialog's debug log."""
    text = buf.getvalue()
    if not text:
        return
    for line in text.rstrip("\n").splitlines():
        debug_log_append(f"{prefix} {line}")


def _make_log_helper():
    """Return a `log(*args)` helper that routes through the active stdout.

    Because the Python ops wrap their exec/eval calls in
    ``contextlib.redirect_stdout``, ``log()`` ends up in the same buffer
    as ``print()`` — so calls from a user script interleave in the
    order they actually happened.
    """
    def log(*args, sep: str = " ") -> None:  # noqa: D401
        print(*args, sep=sep)
    return log


# ── 1. eval: single expression ─────────────────────────────────────

@register_transform(
    name="Python: eval expression",
    category="Python",
    params=[
        TransformParam(
            "expr", "Expression", "text",
            placeholder="data[::-1]  or  bytes(b ^ 0x5A for b in data)",
            help="A single Python expression. `data` is the bytes selection.",
        ),
    ],
    help=("Evaluate a Python expression over the selection. `data` is a "
          "bytes object; the expression value becomes the output "
          "(bytes / bytearray / str). " + _SAFETY_NOTE),
)
def py_eval(data: bytes, params: dict) -> bytes:
    expr = (params.get("expr") or "").strip()
    if not expr:
        raise TransformError("Expression is empty.")
    # Full builtins are auto-injected when __builtins__ isn't in the globals dict.
    ns = {"data": data, "params": params, "log": _make_log_helper()}
    stdout_buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout_buf):
            result = eval(expr, ns)  # noqa: S307 — user code, documented
    except SyntaxError as e:
        _flush_stdout_to_debug_log(stdout_buf, "[eval]")
        raise TransformError(f"SyntaxError: {e.msg} (col {e.offset})") from e
    except Exception as e:
        _flush_stdout_to_debug_log(stdout_buf, "[eval]")
        raise TransformError(f"{type(e).__name__}: {e}") from e
    _flush_stdout_to_debug_log(stdout_buf, "[eval]")
    return _coerce_result(result)


# ── 2. exec: full multiline script ─────────────────────────────────

_EXEC_DEFAULT = (
    "# `data` is bytes in. Assign `result` to bytes out.\n"
    "# Use print(...) or log(...) to write to the Debug panel for debugging.\n"
    "# Example: toggle bit 0 of every byte.\n"
    "print('input length:', len(data))\n"
    "result = bytes(b ^ 0x01 for b in data)\n"
)


@register_transform(
    name="Python: exec script",
    category="Python",
    params=[
        TransformParam(
            "code", "Script", "multiline",
            default=_EXEC_DEFAULT,
            help="Multiline Python. `data` is bytes; assign `result = <bytes>`.",
        ),
    ],
    help=("Execute a Python block over the selection. `data` is a bytes "
          "object; the script must assign `result` to the output. "
          + _SAFETY_NOTE),
)
def py_exec(data: bytes, params: dict) -> bytes:
    code = params.get("code", "")
    if not code.strip():
        raise TransformError("Script is empty.")
    filename = "<transform-script>"
    try:
        compiled = compile(code, filename, "exec")
    except SyntaxError as e:
        raise TransformError(
            f"SyntaxError on line {e.lineno}: {e.msg}"
        ) from e
    ns: dict = {
        "data": data, "params": params, "result": None,
        "log": _make_log_helper(),
    }
    stdout_buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout_buf):
            exec(compiled, ns)  # noqa: S102 — user code, documented
    except TransformError:
        _flush_stdout_to_debug_log(stdout_buf, "[exec]")
        raise
    except Exception as e:
        _flush_stdout_to_debug_log(stdout_buf, "[exec]")
        raise TransformError(_format_user_traceback(e, filename)) from e
    _flush_stdout_to_debug_log(stdout_buf, "[exec]")
    return _coerce_result(ns.get("result"))


# ── 3. external .py file ───────────────────────────────────────────

@register_transform(
    name="Python: run script file",
    category="Python",
    params=[
        TransformParam(
            "path", "Script path", "text",
            placeholder=r"C:\path\to\my_transform.py",
            help=r"Path to a .py file defining transform(data, params) -> bytes.",
        ),
    ],
    help=("Load a .py file and call its top-level `transform(data, params)` "
          "function. The file is re-imported on every run, so you can edit "
          "it in your editor and re-apply the recipe without restarting. "
          + _SAFETY_NOTE),
)
def py_file(data: bytes, params: dict) -> bytes:
    raw = (params.get("path") or "").strip()
    if not raw:
        raise TransformError("Script path is empty.")
    # Strip optional surrounding quotes (common when pasting from Explorer).
    if (raw.startswith('"') and raw.endswith('"')) or \
       (raw.startswith("'") and raw.endswith("'")):
        raw = raw[1:-1]
    p = Path(raw).expanduser()
    if not p.is_file():
        raise TransformError(f"Script not found: {p}")
    if p.suffix.lower() != ".py":
        raise TransformError(f"Not a .py file: {p}")

    mod_name = f"_hex_xform_user_{abs(hash(str(p.resolve())))}"
    # Always re-load so edits take effect without restarting the app.
    sys.modules.pop(mod_name, None)
    spec = importlib.util.spec_from_file_location(mod_name, str(p))
    if spec is None or spec.loader is None:
        raise TransformError(f"Cannot import script: {p}")
    module = importlib.util.module_from_spec(spec)
    # Inject a log helper so the external script can surface debug lines
    # in the dialog even without print().
    module.log = _make_log_helper()  # type: ignore[attr-defined]
    sys.modules[mod_name] = module
    stdout_buf = io.StringIO()
    prefix = f"[{p.stem}]"
    try:
        with contextlib.redirect_stdout(stdout_buf):
            spec.loader.exec_module(module)
    except Exception as e:
        sys.modules.pop(mod_name, None)
        _flush_stdout_to_debug_log(stdout_buf, prefix)
        raise TransformError(
            f"Import failed: {type(e).__name__}: {e}"
        ) from e

    fn = getattr(module, "transform", None)
    if not callable(fn):
        _flush_stdout_to_debug_log(stdout_buf, prefix)
        raise TransformError(
            f"{p.name} must define a top-level function "
            f"`transform(data, params)`."
        )
    try:
        with contextlib.redirect_stdout(stdout_buf):
            result = fn(data, params)
    except TransformError:
        _flush_stdout_to_debug_log(stdout_buf, prefix)
        raise
    except Exception as e:
        _flush_stdout_to_debug_log(stdout_buf, prefix)
        raise TransformError(
            f"transform() raised: {type(e).__name__}: {e}"
        ) from e
    _flush_stdout_to_debug_log(stdout_buf, prefix)
    return _coerce_result(result)
