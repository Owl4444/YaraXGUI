# -*- coding: utf-8 -*-
"""Pure-struct PE format parser."""

import struct
from dataclasses import dataclass, field
from typing import List, Optional

from .hex_data_buffer import HexDataBuffer


@dataclass
class PeSection:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int
    file_offset: int  # offset of the section header itself


@dataclass
class PeImport:
    dll_name: str
    functions: List[str]
    file_offset: int  # offset of the import descriptor


@dataclass
class PeExport:
    name: str
    ordinal: int
    rva: int


@dataclass
class PeDataDirectory:
    name: str
    rva: int
    size: int


@dataclass
class PeInfo:
    # DOS header
    dos_header_offset: int = 0
    dos_header_size: int = 64
    e_lfanew: int = 0

    # NT headers
    nt_header_offset: int = 0
    signature: int = 0
    machine: int = 0
    number_of_sections: int = 0
    timestamp: int = 0
    characteristics: int = 0

    # Optional header
    optional_header_offset: int = 0
    magic: int = 0  # 0x10B=PE32, 0x20B=PE32+
    is_64bit: bool = False
    image_base: int = 0
    entry_point: int = 0
    section_alignment: int = 0
    file_alignment: int = 0

    # Data directories
    data_directories: List[PeDataDirectory] = field(default_factory=list)

    # Sections
    sections: List[PeSection] = field(default_factory=list)

    # Imports
    imports: List[PeImport] = field(default_factory=list)

    # Exports
    exports: List[PeExport] = field(default_factory=list)
    export_dll_name: str = ""

    # Error tracking
    warnings: List[str] = field(default_factory=list)


DATA_DIR_NAMES = [
    "Export", "Import", "Resource", "Exception",
    "Certificate", "Base Relocation", "Debug", "Architecture",
    "Global Ptr", "TLS", "Load Config", "Bound Import",
    "IAT", "Delay Import", "CLR Runtime", "Reserved"
]


class PeParser:
    """Parse PE32/PE32+ executables using struct."""

    def __init__(self, buffer: HexDataBuffer):
        self._buf = buffer

    def parse(self) -> Optional[PeInfo]:
        info = PeInfo()
        try:
            return self._do_parse(info)
        except Exception as e:
            info.warnings.append(f"Parse error: {e}")
            return info

    def _read(self, offset: int, size: int) -> bytes:
        return self._buf.read(offset, size)

    def _u16(self, offset: int) -> int:
        d = self._read(offset, 2)
        return struct.unpack("<H", d)[0] if len(d) == 2 else 0

    def _u32(self, offset: int) -> int:
        d = self._read(offset, 4)
        return struct.unpack("<I", d)[0] if len(d) == 4 else 0

    def _u64(self, offset: int) -> int:
        d = self._read(offset, 8)
        return struct.unpack("<Q", d)[0] if len(d) == 8 else 0

    def _read_cstring(self, offset: int, max_len: int = 256) -> str:
        data = self._read(offset, max_len)
        end = data.find(b"\x00")
        if end >= 0:
            data = data[:end]
        return data.decode("ascii", errors="replace")

    def _rva_to_offset(self, rva: int, sections: List[PeSection]) -> int:
        for sec in sections:
            if sec.virtual_address <= rva < sec.virtual_address + max(sec.virtual_size, sec.raw_size):
                return rva - sec.virtual_address + sec.raw_offset
        return rva  # fallback

    def _do_parse(self, info: PeInfo) -> PeInfo:
        size = self._buf.size()
        if size < 64:
            info.warnings.append("File too small for DOS header")
            return info

        # DOS header
        magic = self._read(0, 2)
        if magic != b"MZ":
            info.warnings.append("Not a valid MZ executable")
            return info

        info.e_lfanew = self._u32(0x3C)
        if info.e_lfanew + 4 > size:
            info.warnings.append("Invalid e_lfanew")
            return info

        # NT signature
        info.nt_header_offset = info.e_lfanew
        sig = self._read(info.nt_header_offset, 4)
        if sig != b"PE\x00\x00":
            info.warnings.append("Invalid PE signature")
            return info
        info.signature = 0x4550

        # File header (COFF)
        fh_off = info.nt_header_offset + 4
        info.machine = self._u16(fh_off)
        info.number_of_sections = self._u16(fh_off + 2)
        info.timestamp = self._u32(fh_off + 4)
        size_of_optional = self._u16(fh_off + 16)
        info.characteristics = self._u16(fh_off + 18)

        # Optional header
        oh_off = fh_off + 20
        info.optional_header_offset = oh_off
        info.magic = self._u16(oh_off)
        info.is_64bit = (info.magic == 0x20B)

        if info.is_64bit:
            info.entry_point = self._u32(oh_off + 16)
            info.image_base = self._u64(oh_off + 24)
            info.section_alignment = self._u32(oh_off + 32)
            info.file_alignment = self._u32(oh_off + 36)
            num_rva_and_sizes = self._u32(oh_off + 108)
            dd_off = oh_off + 112
        else:
            info.entry_point = self._u32(oh_off + 16)
            info.image_base = self._u32(oh_off + 28)
            info.section_alignment = self._u32(oh_off + 32)
            info.file_alignment = self._u32(oh_off + 36)
            num_rva_and_sizes = self._u32(oh_off + 92)
            dd_off = oh_off + 96

        # Data directories
        for i in range(min(num_rva_and_sizes, 16)):
            rva = self._u32(dd_off + i * 8)
            sz = self._u32(dd_off + i * 8 + 4)
            name = DATA_DIR_NAMES[i] if i < len(DATA_DIR_NAMES) else f"Dir[{i}]"
            info.data_directories.append(PeDataDirectory(name=name, rva=rva, size=sz))

        # Section headers
        sections_off = oh_off + size_of_optional
        for i in range(info.number_of_sections):
            sec_off = sections_off + i * 40
            raw_name = self._read(sec_off, 8)
            name = raw_name.split(b"\x00")[0].decode("ascii", errors="replace")
            vs = self._u32(sec_off + 8)
            va = self._u32(sec_off + 12)
            rs = self._u32(sec_off + 16)
            ro = self._u32(sec_off + 20)
            ch = self._u32(sec_off + 36)
            info.sections.append(PeSection(
                name=name, virtual_size=vs, virtual_address=va,
                raw_size=rs, raw_offset=ro, characteristics=ch,
                file_offset=sec_off
            ))

        # Imports
        try:
            self._parse_imports(info)
        except Exception as e:
            info.warnings.append(f"Import parse error: {e}")

        # Exports
        try:
            self._parse_exports(info)
        except Exception as e:
            info.warnings.append(f"Export parse error: {e}")

        return info

    def _parse_imports(self, info: PeInfo):
        if len(info.data_directories) < 2:
            return
        imp_dd = info.data_directories[1]
        if imp_dd.rva == 0 or imp_dd.size == 0:
            return

        imp_off = self._rva_to_offset(imp_dd.rva, info.sections)

        for i in range(1024):  # safety limit
            desc_off = imp_off + i * 20
            if desc_off + 20 > self._buf.size():
                break

            ilt_rva = self._u32(desc_off)
            name_rva = self._u32(desc_off + 12)
            iat_rva = self._u32(desc_off + 16)

            if name_rva == 0:
                break

            dll_name = self._read_cstring(self._rva_to_offset(name_rva, info.sections))

            # Read functions from ILT (or IAT as fallback)
            functions = []
            thunk_rva = ilt_rva if ilt_rva != 0 else iat_rva
            if thunk_rva:
                thunk_off = self._rva_to_offset(thunk_rva, info.sections)
                for j in range(4096):
                    if info.is_64bit:
                        entry = self._u64(thunk_off + j * 8)
                        if entry == 0:
                            break
                        if entry & (1 << 63):  # ordinal
                            functions.append(f"Ordinal {entry & 0xFFFF}")
                        else:
                            hint_off = self._rva_to_offset(entry & 0x7FFFFFFF, info.sections)
                            fname = self._read_cstring(hint_off + 2)
                            functions.append(fname)
                    else:
                        entry = self._u32(thunk_off + j * 4)
                        if entry == 0:
                            break
                        if entry & (1 << 31):
                            functions.append(f"Ordinal {entry & 0xFFFF}")
                        else:
                            hint_off = self._rva_to_offset(entry, info.sections)
                            fname = self._read_cstring(hint_off + 2)
                            functions.append(fname)

            info.imports.append(PeImport(dll_name=dll_name, functions=functions, file_offset=desc_off))

    def _parse_exports(self, info: PeInfo):
        if not info.data_directories:
            return
        exp_dd = info.data_directories[0]
        if exp_dd.rva == 0 or exp_dd.size == 0:
            return

        exp_off = self._rva_to_offset(exp_dd.rva, info.sections)

        name_rva = self._u32(exp_off + 12)
        ordinal_base = self._u32(exp_off + 16)
        num_functions = self._u32(exp_off + 20)
        num_names = self._u32(exp_off + 24)
        addr_table_rva = self._u32(exp_off + 28)
        name_ptr_rva = self._u32(exp_off + 32)
        ordinal_table_rva = self._u32(exp_off + 36)

        info.export_dll_name = self._read_cstring(self._rva_to_offset(name_rva, info.sections))

        name_ptrs_off = self._rva_to_offset(name_ptr_rva, info.sections)
        ordinals_off = self._rva_to_offset(ordinal_table_rva, info.sections)
        addrs_off = self._rva_to_offset(addr_table_rva, info.sections)

        for i in range(min(num_names, 4096)):
            fn_name_rva = self._u32(name_ptrs_off + i * 4)
            ordinal = self._u16(ordinals_off + i * 2)
            fn_rva = self._u32(addrs_off + ordinal * 4)
            fn_name = self._read_cstring(self._rva_to_offset(fn_name_rva, info.sections))
            info.exports.append(PeExport(name=fn_name, ordinal=ordinal + ordinal_base, rva=fn_rva))
