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

from .hex_editor_window import HexEditorWindow
from .binary_diff_window import BinaryDiffWindow

__all__ = ["HexEditorWindow", "BinaryDiffWindow"]
