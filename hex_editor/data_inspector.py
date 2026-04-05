# -*- coding: utf-8 -*-
"""Data inspector widget showing cursor bytes in multiple representations."""

import struct

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QComboBox, QTableWidget, QTableWidgetItem,
                               QHeaderView, QAbstractItemView)

from .hex_data_buffer import HexDataBuffer


class DataInspectorWidget(QWidget):
    """Dock widget content showing the byte(s) at the cursor in multiple formats."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._buffer: HexDataBuffer | None = None
        self._offset = 0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # Endianness selector
        top = QHBoxLayout()
        top.addWidget(QLabel("Endian:"))
        self._endian_combo = QComboBox()
        self._endian_combo.addItems(["Little-endian", "Big-endian"])
        self._endian_combo.currentIndexChanged.connect(self._refresh)
        top.addWidget(self._endian_combo)
        top.addStretch()
        layout.addLayout(top)

        # Table
        self._table = QTableWidget()
        self._table.setColumnCount(2)
        self._table.setHorizontalHeaderLabels(["Type", "Value"])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self._table.setColumnWidth(0, 54)
        self._table.verticalHeader().setVisible(False)
        self._table.verticalHeader().setDefaultSectionSize(20)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        layout.addWidget(self._table)

    def set_buffer(self, buf: HexDataBuffer):
        self._buffer = buf
        self._refresh()

    def update_offset(self, offset: int):
        self._offset = offset
        self._refresh()

    def _is_big_endian(self) -> bool:
        return self._endian_combo.currentIndex() == 1

    def _refresh(self):
        self._table.setRowCount(0)
        if not self._buffer or self._buffer.size() == 0:
            return

        off = self._offset
        be = self._is_big_endian()
        bo = ">" if be else "<"

        # Read up to 8 bytes from cursor
        raw = self._buffer.read(off, 8)
        if not raw:
            return

        rows = []

        # 1-byte
        if len(raw) >= 1:
            b = raw[0]
            rows.append(("uint8", str(b)))
            rows.append(("int8", str(struct.unpack("b", bytes([b]))[0])))
            rows.append(("binary", format(b, "08b")))
            rows.append(("octal", format(b, "03o")))
            ch = chr(b) if 32 <= b <= 126 else "."
            rows.append(("char", repr(ch)))

        # 2-byte
        if len(raw) >= 2:
            val = struct.unpack(f"{bo}H", raw[:2])[0]
            rows.append(("uint16", str(val)))
            val = struct.unpack(f"{bo}h", raw[:2])[0]
            rows.append(("int16", str(val)))
            # UTF-16 char
            try:
                uc = raw[:2].decode("utf-16-le" if not be else "utf-16-be")
                rows.append(("UTF-16", repr(uc)))
            except Exception:
                rows.append(("UTF-16", "?"))

        # 4-byte
        if len(raw) >= 4:
            val = struct.unpack(f"{bo}I", raw[:4])[0]
            rows.append(("uint32", str(val)))
            val = struct.unpack(f"{bo}i", raw[:4])[0]
            rows.append(("int32", str(val)))
            val = struct.unpack(f"{bo}f", raw[:4])[0]
            rows.append(("float32", f"{val:.6g}"))

        # 8-byte
        if len(raw) >= 8:
            val = struct.unpack(f"{bo}Q", raw[:8])[0]
            rows.append(("uint64", str(val)))
            val = struct.unpack(f"{bo}q", raw[:8])[0]
            rows.append(("int64", str(val)))
            val = struct.unpack(f"{bo}d", raw[:8])[0]
            rows.append(("float64", f"{val:.6g}"))

        self._table.setRowCount(len(rows))
        for i, (typ, val) in enumerate(rows):
            ti = QTableWidgetItem(typ)
            ti.setFlags(ti.flags() & ~Qt.ItemFlag.ItemIsEditable)
            vi = QTableWidgetItem(val)
            vi.setFlags(vi.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self._table.setItem(i, 0, ti)
            self._table.setItem(i, 1, vi)
