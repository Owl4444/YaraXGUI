"""UI-independent values. All offsets are Python Unicode character offsets."""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Span:
    start: int
    end: int

    def contains(self, offset):
        return self.start <= offset < self.end


@dataclass(frozen=True)
class TextEdit:
    span: Span
    text: str


@dataclass(frozen=True)
class Diagnostic:
    message: str
    severity: str
    code: str
    span: Span | None = None
    origin: str | None = None
    details: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Completion:
    label: str
    kind: str
    edit: TextEdit
    detail: str = ""
    documentation: str = ""
    source: str = ""
    deprecated: bool = False
    snippet: bool = False


@dataclass(frozen=True)
class Symbol:
    name: str
    kind: str
    declaration: Span
    scope: Span
    type: str = ""


@dataclass(frozen=True)
class SignatureHelp:
    signatures: tuple[str, ...]
    active_parameter: int
    documentation: tuple[str, ...] = ()


@dataclass(frozen=True)
class Hover:
    span: Span
    title: str
    documentation: str
    source: str = ""

