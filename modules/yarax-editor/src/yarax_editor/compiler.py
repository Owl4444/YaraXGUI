"""Authoritative semantic checks using the pinned scanning engine."""
from dataclasses import dataclass, field
from importlib.metadata import version
import yara_x
from .model import Diagnostic
from .text import SourceMap

TARGET_VERSION = "1.20.0"


@dataclass(frozen=True)
class CompileOptions:
    globals: dict = field(default_factory=dict)
    include_dirs: tuple[str, ...] = ()
    allow_includes: bool = False
    relaxed_regex: bool = False
    origin: str | None = None


@dataclass(frozen=True)
class Validation:
    valid: bool
    diagnostics: tuple[Diagnostic, ...]
    rules: object = field(default=None, repr=False, compare=False)


class Compiler:
    def __init__(self, options=CompileOptions()):
        self.options = options
        self.version = version("yara-x")
        if self.version != TARGET_VERSION:
            raise RuntimeError(f"This catalog targets YARA-X {TARGET_VERSION}; installed engine is {self.version}")

    @property
    def modules(self):
        return tuple(yara_x.module_names())

    def validate(self, text):
        source_map = SourceMap(text)
        compiler = yara_x.Compiler(relaxed_re_syntax=self.options.relaxed_regex)
        compiler.enable_includes(self.options.allow_includes)
        for directory in self.options.include_dirs:
            compiler.add_include_dir(str(directory))
        for name, value in self.options.globals.items():
            compiler.define_global(name, value)
        failed = False
        error_text = ""
        rules = None
        try:
            compiler.add_source(text, origin=self.options.origin)
            rules = compiler.build()
        except yara_x.CompileError as exc:
            # Keeping an exception retains its traceback and this compiler in a
            # cycle. PyO3 compilers must be destroyed on their creating thread.
            failed = True
            error_text = str(exc)
        diagnostics = []
        for severity, entries in (("error", compiler.errors()), ("warning", compiler.warnings())):
            for entry in entries:
                labels = entry.get("labels", [])
                label = next((l for l in labels if l.get("level") == severity), labels[0] if labels else {})
                origin = label.get("code_origin")
                raw_span = label.get("span")
                span = None
                if raw_span and (origin is None or origin == self.options.origin):
                    try:
                        span = source_map.byte_span(raw_span["start"], raw_span["end"])
                    except ValueError:
                        pass  # Never put an included-file error at a guessed location.
                message = entry.get("title", "")
                if label.get("text"):
                    message += ": " + label["text"]
                diagnostics.append(Diagnostic(message, severity, entry.get("code", ""), span, origin, entry))
        if failed and not diagnostics:
            diagnostics.append(Diagnostic(error_text, "error", "compile_error"))
        return Validation(not failed, tuple(diagnostics), rules)
