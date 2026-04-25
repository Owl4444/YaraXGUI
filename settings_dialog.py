"""Settings dialog for YaraXGUI editor preferences."""

from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QFontComboBox, QFormLayout,
    QGroupBox, QSpinBox, QVBoxLayout,
)
from PySide6.QtGui import QFont


class SettingsDialog(QDialog):
    """Modal dialog for configuring editor font, size, and tab width."""

    def __init__(
        self,
        current_font_family: str = "Consolas",
        current_font_size: int = 12,
        current_tab_size: int = 4,
        parent=None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Editor Settings")
        self.setMinimumWidth(380)

        layout = QVBoxLayout(self)

        # ── Editor group ─────────────────────────────────────
        editor_group = QGroupBox("Editor")
        form = QFormLayout(editor_group)

        self._font_combo = QFontComboBox()
        self._font_combo.setFontFilters(QFontComboBox.FontFilter.MonospacedFonts)
        self._font_combo.setCurrentFont(QFont(current_font_family))
        form.addRow("Font Family:", self._font_combo)

        self._size_spin = QSpinBox()
        self._size_spin.setRange(6, 72)
        self._size_spin.setValue(current_font_size)
        self._size_spin.setSuffix(" pt")
        form.addRow("Font Size:", self._size_spin)

        self._tab_spin = QSpinBox()
        self._tab_spin.setRange(2, 8)
        self._tab_spin.setValue(current_tab_size)
        self._tab_spin.setSuffix(" spaces")
        form.addRow("Tab Width:", self._tab_spin)

        layout.addWidget(editor_group)

        # ── Buttons ──────────────────────────────────────────
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    # ── Public getters ───────────────────────────────────────

    def font_family(self) -> str:
        return self._font_combo.currentFont().family()

    def font_size(self) -> int:
        return self._size_spin.value()

    def tab_size(self) -> int:
        return self._tab_spin.value()
