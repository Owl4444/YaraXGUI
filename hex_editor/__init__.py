# -*- coding: utf-8 -*-
"""Hex Editor package for YaraXGUI.

Architecture:
- SelectionModel: cursor / selection / marker / region state (Observer)
- HexLayout: column metrics and coordinate mapping (Value Object)
- HexPainter: rendering strategies (Strategy / Template Method)
- ClipboardExporter: copy / YARA export (Registry)
- HexWidget: thin controller wiring input to model (MVC Controller)
- HexEditorWindow: standalone window mediating docks (Mediator)
"""

__all__ = ["HexEditorWindow", "BinaryDiffWindow"]


def __getattr__(name):
    # Analysis subprocesses import this package too. Do not load Qt widgets,
    # disassemblers or plugins just to run a byte-regex worker.
    if name == 'HexEditorWindow':
        from .hex_editor_window import HexEditorWindow
        value = HexEditorWindow
    elif name == 'BinaryDiffWindow':
        from .binary_diff_window import BinaryDiffWindow
        value = BinaryDiffWindow
    else:
        raise AttributeError(name)
    globals()[name] = value
    return value
