# -*- coding: utf-8 -*-
"""Go-to-offset dialog for the hex editor."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                               QLineEdit, QPushButton, QMessageBox)


class GotoDialog(QDialog):
    """Dialog to jump to a specific offset in the hex view."""

    def __init__(self, file_size: int, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Go to Offset")
        self.setMinimumWidth(320)
        self._file_size = file_size
        self._result_offset = -1

        layout = QVBoxLayout(self)

        # Info label
        info = QLabel(f"File size: {file_size:,} bytes (0x{file_size:X})")
        info.setStyleSheet("color: gray;")
        layout.addWidget(info)

        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Offset:"))
        self._input = QLineEdit()
        self._input.setPlaceholderText("Hex (0x1A4) or decimal (420)")
        self._input.returnPressed.connect(self._on_go)
        input_layout.addWidget(self._input)
        layout.addLayout(input_layout)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        go_btn = QPushButton("Go")
        go_btn.setDefault(True)
        go_btn.clicked.connect(self._on_go)
        btn_layout.addWidget(go_btn)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

        self._input.setFocus()

    def _on_go(self):
        text = self._input.text().strip()
        if not text:
            return
        try:
            if text.lower().startswith("0x"):
                offset = int(text, 16)
            else:
                offset = int(text)
        except ValueError:
            QMessageBox.warning(self, "Invalid Input",
                                "Enter a decimal number or hex value (0x...).")
            return

        if offset < 0 or offset >= self._file_size:
            QMessageBox.warning(self, "Out of Range",
                                f"Offset must be between 0 and {self._file_size - 1:,} "
                                f"(0x{self._file_size - 1:X}).")
            return

        self._result_offset = offset
        self.accept()

    def result_offset(self) -> int:
        return self._result_offset
