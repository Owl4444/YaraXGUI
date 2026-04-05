# -*- coding: utf-8 -*-
"""Format viewer dock widget - displays parsed PE/ELF structures in a tree."""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QTreeWidget,
                               QTreeWidgetItem, QLabel)

from .hex_data_buffer import HexDataBuffer
from .pe_parser import PeParser, PeInfo
from .elf_parser import ElfParser, ElfInfo


class FormatViewerWidget(QWidget):
    """Dock widget showing parsed binary format structures."""

    navigate_requested = Signal(int, int)  # offset, length

    def __init__(self, parent=None):
        super().__init__(parent)
        self._buffer: HexDataBuffer | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        self._label = QLabel("No file loaded")
        layout.addWidget(self._label)

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Field", "Value"])
        self._tree.setAlternatingRowColors(True)
        self._tree.setRootIsDecorated(True)
        self._tree.setItemsExpandable(True)
        self._tree.header().setStretchLastSection(True)
        self._tree.itemClicked.connect(self._on_item_clicked)
        layout.addWidget(self._tree)

    def set_buffer(self, buf: HexDataBuffer):
        self._buffer = buf
        self._tree.clear()
        self._label.setText(buf.format_name if buf else "No file loaded")
        if not buf or buf.size() == 0:
            return
        fmt = buf.format_name
        if "PE" in fmt or "MZ" in fmt:
            self._populate_pe()
        elif "ELF" in fmt:
            self._populate_elf()
        else:
            self._label.setText(f"Format: {fmt} (no parser available)")

    # ── PE ──────────────────────────────────────────────────────────

    def _populate_pe(self):
        parser = PeParser(self._buffer)
        info = parser.parse()
        if not info:
            self._label.setText("PE parse failed")
            return

        self._label.setText(f"PE32+ (64-bit)" if info.is_64bit else "PE32 (32-bit)")

        # DOS Header
        dos = self._add("DOS Header", "", info.dos_header_offset, info.dos_header_size)
        self._add("e_magic", "MZ", 0, 2, dos)
        self._add("e_lfanew", f"0x{info.e_lfanew:X}", 0x3C, 4, dos)

        # NT Headers
        nt = self._add("NT Headers", "", info.nt_header_offset, 4)
        self._add("Signature", "PE\\0\\0", info.nt_header_offset, 4, nt)

        # File Header
        fh_off = info.nt_header_offset + 4
        fh = self._add("File Header", "", fh_off, 20, nt)
        self._add("Machine", f"0x{info.machine:04X}", fh_off, 2, fh)
        self._add("NumberOfSections", str(info.number_of_sections), fh_off + 2, 2, fh)
        self._add("TimeDateStamp", f"0x{info.timestamp:08X}", fh_off + 4, 4, fh)
        self._add("Characteristics", f"0x{info.characteristics:04X}", fh_off + 18, 2, fh)

        # Optional Header
        oh = self._add("Optional Header", "PE32+" if info.is_64bit else "PE32",
                        info.optional_header_offset, 0, nt)
        self._add("Magic", f"0x{info.magic:04X}", info.optional_header_offset, 2, oh)
        self._add("AddressOfEntryPoint", f"0x{info.entry_point:X}", info.optional_header_offset + 16, 4, oh)
        self._add("ImageBase", f"0x{info.image_base:X}", 0, 0, oh)
        self._add("SectionAlignment", f"0x{info.section_alignment:X}", 0, 0, oh)
        self._add("FileAlignment", f"0x{info.file_alignment:X}", 0, 0, oh)

        # Data directories
        if info.data_directories:
            dd = self._add("Data Directories", f"{len(info.data_directories)}", 0, 0, oh)
            for d in info.data_directories:
                if d.rva or d.size:
                    self._add(d.name, f"RVA=0x{d.rva:X} Size=0x{d.size:X}", 0, 0, dd)

        # Sections
        if info.sections:
            secs = self._add("Sections", f"{len(info.sections)}", 0, 0)
            for sec in info.sections:
                s = self._add(sec.name, f"VA=0x{sec.virtual_address:X}", sec.file_offset, 40, secs)
                self._add("VirtualSize", f"0x{sec.virtual_size:X}", 0, 0, s)
                self._add("RawSize", f"0x{sec.raw_size:X}", 0, 0, s)
                self._add("RawOffset", f"0x{sec.raw_offset:X}", sec.raw_offset, sec.raw_size, s)
                self._add("Characteristics", f"0x{sec.characteristics:08X}", 0, 0, s)

        # Imports
        if info.imports:
            imps = self._add("Imports", f"{len(info.imports)} DLLs", 0, 0)
            for imp in info.imports:
                dll = self._add(imp.dll_name, f"{len(imp.functions)} functions", imp.file_offset, 20, imps)
                for fn in imp.functions[:200]:  # limit display
                    self._add(fn, "", 0, 0, dll)

        # Exports
        if info.exports:
            exps = self._add("Exports", f"{info.export_dll_name} ({len(info.exports)})", 0, 0)
            for exp in info.exports[:500]:
                self._add(exp.name, f"Ord={exp.ordinal} RVA=0x{exp.rva:X}", 0, 0, exps)

        # Warnings
        if info.warnings:
            w = self._add("Warnings", f"{len(info.warnings)}", 0, 0)
            for msg in info.warnings:
                self._add(msg, "", 0, 0, w)

        self._tree.expandToDepth(0)

    # ── ELF ─────────────────────────────────────────────────────────

    def _populate_elf(self):
        parser = ElfParser(self._buffer)
        info = parser.parse()
        if not info:
            self._label.setText("ELF parse failed")
            return

        self._label.setText(f"ELF{'64' if info.is_64bit else '32'} "
                            f"{'BE' if info.is_big_endian else 'LE'} "
                            f"{info.e_type_name} {info.e_machine_name}")

        # Header
        hdr = self._add("ELF Header", "", 0, info.header_size)
        self._add("Class", "ELF64" if info.is_64bit else "ELF32", 4, 1, hdr)
        self._add("Data", "Big-endian" if info.is_big_endian else "Little-endian", 5, 1, hdr)
        self._add("Type", info.e_type_name, 16, 2, hdr)
        self._add("Machine", info.e_machine_name, 18, 2, hdr)
        self._add("Entry", f"0x{info.e_entry:X}", 0, 0, hdr)
        self._add("Phoff", f"0x{info.e_phoff:X}", 0, 0, hdr)
        self._add("Shoff", f"0x{info.e_shoff:X}", 0, 0, hdr)

        # Program headers
        if info.program_headers:
            ph = self._add("Program Headers", f"{len(info.program_headers)}", int(info.e_phoff), 0)
            for p in info.program_headers:
                flags_str = (("R" if p.flags & 4 else "-") +
                             ("W" if p.flags & 2 else "-") +
                             ("X" if p.flags & 1 else "-"))
                item = self._add(p.type_name, f"Offset=0x{p.offset:X} Vaddr=0x{p.vaddr:X} {flags_str}",
                                 p.header_offset, 0, ph)
                self._add("FileSize", f"0x{p.filesz:X}", 0, 0, item)
                self._add("MemSize", f"0x{p.memsz:X}", 0, 0, item)

        # Sections
        if info.sections:
            secs = self._add("Sections", f"{len(info.sections)}", int(info.e_shoff), 0)
            for sec in info.sections:
                if not sec.name:
                    continue
                s = self._add(sec.name, f"{sec.type_name} Offset=0x{sec.offset:X}",
                              sec.header_offset, 0, secs)
                self._add("Addr", f"0x{sec.addr:X}", 0, 0, s)
                self._add("Size", f"0x{sec.size:X}", sec.offset, sec.size, s)
                self._add("Flags", f"0x{sec.flags:X}", 0, 0, s)

        # Symbols (grouped by table)
        if info.symbols:
            tables = {}
            for sym in info.symbols:
                tables.setdefault(sym.table_name, []).append(sym)
            for tbl_name, syms in tables.items():
                tbl = self._add(f"Symbols ({tbl_name})", f"{len(syms)}", 0, 0)
                for sym in syms[:2000]:
                    self._add(sym.name, f"Value=0x{sym.value:X} Size={sym.size}", 0, 0, tbl)

        # Dynamic
        if info.dynamic:
            dyn = self._add("Dynamic", f"{len(info.dynamic)}", 0, 0)
            for d in info.dynamic:
                self._add(d.tag_name, f"0x{d.value:X}", 0, 0, dyn)

        # Warnings
        if info.warnings:
            w = self._add("Warnings", f"{len(info.warnings)}", 0, 0)
            for msg in info.warnings:
                self._add(msg, "", 0, 0, w)

        self._tree.expandToDepth(0)

    # ── Tree helpers ────────────────────────────────────────────────

    def _add(self, field: str, value: str, offset: int = 0, size: int = 0,
             parent=None) -> QTreeWidgetItem:
        item = QTreeWidgetItem([field, value])
        item.setData(0, Qt.ItemDataRole.UserRole, offset)
        item.setData(1, Qt.ItemDataRole.UserRole, size)
        if parent is None:
            self._tree.addTopLevelItem(item)
        else:
            parent.addChild(item)
        return item

    def _on_item_clicked(self, item, column):
        offset = item.data(0, Qt.ItemDataRole.UserRole)
        size = item.data(1, Qt.ItemDataRole.UserRole)
        if offset is not None and offset > 0:
            self.navigate_requested.emit(int(offset), int(size) if size else 0)
