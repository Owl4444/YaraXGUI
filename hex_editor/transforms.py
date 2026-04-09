# -*- coding: utf-8 -*-
"""Pure data transforms for the hex editor (no Qt imports).

This module is intentionally tiny: it owns the **types** (``TransformError``,
``TransformParam``, ``TransformSpec``, ``RecipeStep``), the **registry**
(``REGISTRY``), and a **plugin loader** that discovers operations from the
``transform_ops`` subpackage (and optionally from user-supplied directories).

Adding a new operation is now a matter of dropping a file into
``hex_editor/transform_ops/`` (or any external plugin directory) and
decorating a function::

    from hex_editor.transforms import register_transform, TransformParam

    @register_transform(
        name="Swap nibbles",
        category="Bitwise",
        length_preserving=True,
    )
    def swap_nibbles(data: bytes, params: dict) -> bytes:
        return bytes(((b << 4) | (b >> 4)) & 0xFF for b in data)

The module is Qt-free so plugins can be unit-tested standalone.
"""

from __future__ import annotations

import importlib
import importlib.util
import pkgutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


# ── Errors ──────────────────────────────────────────────────────────

class TransformError(Exception):
    """Raised when a transform cannot be applied (bad key, wrong length…)."""


# ── Parameter / spec schema ─────────────────────────────────────────

@dataclass
class TransformParam:
    key: str                     # field name in the params dict
    label: str                   # UI label
    kind: str                    # "text" | "hex" | "choice" | "int"
    default: str = ""
    choices: list = field(default_factory=list)
    placeholder: str = ""
    help: str = ""


@dataclass
class TransformSpec:
    name: str                                        # display name
    category: str                                    # grouping in UI
    params: list[TransformParam]
    func: Callable[[bytes, dict], bytes]
    length_preserving: bool                          # True → safe for overlapping regions
    help: str = ""


@dataclass
class RecipeStep:
    """A single step in a transform recipe (CyberChef-style chain)."""
    spec_name: str
    params: dict = field(default_factory=dict)


# ── Registry ────────────────────────────────────────────────────────

REGISTRY: list[TransformSpec] = []


def find_spec(name: str) -> TransformSpec | None:
    for spec in REGISTRY:
        if spec.name == name:
            return spec
    return None


def register_transform(
    name: str,
    category: str,
    params: list[TransformParam] | None = None,
    length_preserving: bool = False,
    help: str = "",
) -> Callable[[Callable[[bytes, dict], bytes]], Callable[[bytes, dict], bytes]]:
    """Decorator that registers a function as a transform operation.

    If a spec with the same *name* already exists it is replaced in place,
    so re-importing a plugin module (e.g. during hot-reload) is safe.
    """
    def _decorator(func: Callable[[bytes, dict], bytes]) -> Callable[[bytes, dict], bytes]:
        spec = TransformSpec(
            name=name,
            category=category,
            params=list(params or []),
            func=func,
            length_preserving=length_preserving,
            help=help,
        )
        # Replace existing spec with the same name (idempotent reload).
        for i, existing in enumerate(REGISTRY):
            if existing.name == name:
                REGISTRY[i] = spec
                break
        else:
            REGISTRY.append(spec)
        return func
    return _decorator


# ── Debug log (preview stdout/log capture) ─────────────────────────
#
# The transform dialog clears this list before running the recipe on the
# probe bytes, then reads it back after to show whatever the operations
# wanted to surface (print() output from Python scripts, extra info from
# analysis ops, etc.). It is intentionally global so ops don't need to
# thread a log parameter everywhere — for a single UI thread this is fine.

DEBUG_LOG: list[str] = []


def debug_log_clear() -> None:
    DEBUG_LOG.clear()


def debug_log_append(line: str) -> None:
    DEBUG_LOG.append(line)


def debug_log_get() -> list[str]:
    return list(DEBUG_LOG)


# ── Recipe helpers ──────────────────────────────────────────────────

def apply_recipe(data: bytes, steps: list[RecipeStep]) -> bytes:
    """Run a recipe of steps sequentially on *data* and return the result."""
    current = data
    for step in steps:
        spec = find_spec(step.spec_name)
        if spec is None:
            raise TransformError(f"Unknown operation: {step.spec_name}")
        current = spec.func(current, step.params)
    return current


def recipe_length_preserving(steps: list[RecipeStep]) -> bool:
    """True iff every step in *steps* is length-preserving."""
    for step in steps:
        spec = find_spec(step.spec_name)
        if spec is None or not spec.length_preserving:
            return False
    return True


# ── Key parsing helper (shared by plugins) ──────────────────────────

def parse_bytes_input(text: str) -> bytes:
    """Parse a user-supplied key/IV string as bytes.

    Accepts:
        * ``0x4D5A90...`` or ``4D5A90...`` (hex)
        * ``"hello"`` (ASCII text, strips surrounding quotes)
        * bare ASCII text if not clearly hex
    """
    s = text.strip()
    if not s:
        return b""
    # Quoted string → literal text
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1].encode("utf-8", errors="replace")
    # Leading 0x → hex
    if s.lower().startswith("0x"):
        try:
            return bytes.fromhex(s[2:])
        except ValueError as e:
            raise TransformError(f"Invalid hex value: {e}") from e
    # All hex digits (even length) → hex
    stripped = s.replace(" ", "").replace("_", "")
    if stripped and len(stripped) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in stripped):
        try:
            return bytes.fromhex(stripped)
        except ValueError:
            pass
    # Fallback: raw ASCII text
    return s.encode("utf-8", errors="replace")


# ── Plugin loader ───────────────────────────────────────────────────

# Load order for the built-in plugin modules.  Modules not listed here are
# still picked up by the fallback discovery pass, but these three define the
# canonical category ordering shown in the dialog.
BUILTIN_PLUGIN_ORDER: list[str] = ["encoding", "bitwise", "symmetric"]


def load_builtin_plugins() -> None:
    """Import every module in ``hex_editor.transform_ops``.

    The decorator calls populate ``REGISTRY`` as a side-effect of import.
    The explicit ordering in :data:`BUILTIN_PLUGIN_ORDER` is honoured first;
    any additional modules found afterwards are appended in alphabetical
    order.  Calling this function more than once is safe — ``register_transform``
    is idempotent with respect to the spec ``name``.
    """
    pkg_name = __package__ + ".transform_ops" if __package__ else "transform_ops"
    try:
        pkg = importlib.import_module(pkg_name)
    except ImportError:
        return

    # Explicit, ordered imports for the canonical built-ins.
    for mod_name in BUILTIN_PLUGIN_ORDER:
        try:
            importlib.import_module(f"{pkg_name}.{mod_name}")
        except ImportError:
            continue

    # Fallback discovery for any additional modules dropped into the package.
    seen = set(BUILTIN_PLUGIN_ORDER)
    if hasattr(pkg, "__path__"):
        for info in sorted(pkgutil.iter_modules(pkg.__path__), key=lambda i: i.name):
            if info.name in seen or info.name.startswith("_"):
                continue
            try:
                importlib.import_module(f"{pkg_name}.{info.name}")
            except ImportError:
                continue


def load_plugin_file(path: str | Path) -> int:
    """Load a single ``.py`` file as a transform plugin.

    Returns the number of operations the file added to the registry.
    """
    p = Path(path)
    if not p.is_file() or p.suffix.lower() != ".py":
        return 0
    before = len(REGISTRY)
    mod_name = f"_hex_xform_plugin_{p.stem}"
    spec = importlib.util.spec_from_file_location(mod_name, str(p))
    if spec is None or spec.loader is None:
        return 0
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(mod_name, None)
        raise
    return len(REGISTRY) - before


def load_plugin_directory(directory: str | Path) -> int:
    """Load every ``.py`` file in *directory* (non-recursive) as a plugin.

    Returns the total number of operations added.
    """
    d = Path(directory)
    if not d.is_dir():
        return 0
    total = 0
    for p in sorted(d.glob("*.py")):
        if p.name.startswith("_"):
            continue
        try:
            total += load_plugin_file(p)
        except Exception:
            # One broken plugin should not kill the rest.
            continue
    return total


# ── Bootstrap ───────────────────────────────────────────────────────

load_builtin_plugins()
