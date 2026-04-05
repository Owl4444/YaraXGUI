# -*- coding: utf-8 -*-
"""Pure-struct ELF format parser."""

import struct
from dataclasses import dataclass, field
from typing import List, Optional

from .hex_data_buffer import HexDataBuffer


@dataclass
class ElfSection:
    name: str
    type_: int
    type_name: str
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    header_offset: int  # offset of section header entry


@dataclass
class ElfProgramHeader:
    type_: int
    type_name: str
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    flags: int
    align: int
    header_offset: int


@dataclass
class ElfSymbol:
    name: str
    value: int
    size: int
    type_: int
    bind: int
    section_index: int
    table_name: str  # ".symtab" or ".dynsym"


@dataclass
class ElfDynamic:
    tag: int
    tag_name: str
    value: int


@dataclass
class ElfInfo:
    # Header
    ei_class: int = 0  # 1=32, 2=64
    is_64bit: bool = False
    ei_data: int = 0   # 1=LE, 2=BE
    is_big_endian: bool = False
    ei_osabi: int = 0
    e_type: int = 0
    e_type_name: str = ""
    e_machine: int = 0
    e_machine_name: str = ""
    e_entry: int = 0
    e_phoff: int = 0
    e_shoff: int = 0
    e_phnum: int = 0
    e_shnum: int = 0
    e_shstrndx: int = 0
    header_size: int = 0

    # Parsed structures
    program_headers: List[ElfProgramHeader] = field(default_factory=list)
    sections: List[ElfSection] = field(default_factory=list)
    symbols: List[ElfSymbol] = field(default_factory=list)
    dynamic: List[ElfDynamic] = field(default_factory=list)

    warnings: List[str] = field(default_factory=list)


ETYPE_NAMES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
MACHINE_NAMES = {
    0: "None", 3: "x86", 8: "MIPS", 0x14: "PowerPC", 0x28: "ARM",
    0x3E: "x86-64", 0xB7: "AArch64", 0xF3: "RISC-V"
}
PHTYPE_NAMES = {
    0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE",
    5: "SHLIB", 6: "PHDR", 7: "TLS"
}
SHTYPE_NAMES = {
    0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
    5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
    11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY"
}
DTAG_NAMES = {
    0: "NULL", 1: "NEEDED", 2: "PLTRELSZ", 3: "PLTGOT", 4: "HASH",
    5: "STRTAB", 6: "SYMTAB", 7: "RELA", 10: "STRSZ", 11: "SYMENT",
    12: "INIT", 13: "FINI", 14: "SONAME", 15: "RPATH", 17: "REL",
    20: "PLTREL", 21: "DEBUG", 23: "JMPREL", 25: "INIT_ARRAY",
    26: "FINI_ARRAY"
}


class ElfParser:
    """Parse ELF32/ELF64 executables using struct."""

    def __init__(self, buffer: HexDataBuffer):
        self._buf = buffer
        self._be = False
        self._64 = False

    def parse(self) -> Optional[ElfInfo]:
        info = ElfInfo()
        try:
            return self._do_parse(info)
        except Exception as e:
            info.warnings.append(f"Parse error: {e}")
            return info

    def _bo(self) -> str:
        return ">" if self._be else "<"

    def _read(self, offset: int, size: int) -> bytes:
        return self._buf.read(offset, size)

    def _u16(self, offset: int) -> int:
        d = self._read(offset, 2)
        return struct.unpack(f"{self._bo()}H", d)[0] if len(d) == 2 else 0

    def _u32(self, offset: int) -> int:
        d = self._read(offset, 4)
        return struct.unpack(f"{self._bo()}I", d)[0] if len(d) == 4 else 0

    def _u64(self, offset: int) -> int:
        d = self._read(offset, 8)
        return struct.unpack(f"{self._bo()}Q", d)[0] if len(d) == 8 else 0

    def _ptr(self, offset: int) -> int:
        return self._u64(offset) if self._64 else self._u32(offset)

    def _read_strtab_entry(self, strtab_off: int, strtab_size: int, index: int) -> str:
        if index >= strtab_size:
            return ""
        data = self._read(strtab_off + index, min(256, strtab_size - index))
        end = data.find(b"\x00")
        if end >= 0:
            data = data[:end]
        return data.decode("utf-8", errors="replace")

    def _do_parse(self, info: ElfInfo) -> ElfInfo:
        size = self._buf.size()
        if size < 16:
            info.warnings.append("File too small")
            return info

        magic = self._read(0, 4)
        if magic != b"\x7fELF":
            info.warnings.append("Not a valid ELF file")
            return info

        info.ei_class = self._buf.read(4, 1)[0]
        info.is_64bit = (info.ei_class == 2)
        self._64 = info.is_64bit

        info.ei_data = self._buf.read(5, 1)[0]
        info.is_big_endian = (info.ei_data == 2)
        self._be = info.is_big_endian

        info.ei_osabi = self._buf.read(7, 1)[0]

        info.e_type = self._u16(16)
        info.e_type_name = ETYPE_NAMES.get(info.e_type, f"0x{info.e_type:X}")
        info.e_machine = self._u16(18)
        info.e_machine_name = MACHINE_NAMES.get(info.e_machine, f"0x{info.e_machine:X}")

        if self._64:
            info.e_entry = self._u64(24)
            info.e_phoff = self._u64(32)
            info.e_shoff = self._u64(40)
            info.e_phnum = self._u16(56)
            info.e_shnum = self._u16(60)
            info.e_shstrndx = self._u16(62)
            info.header_size = 64
        else:
            info.e_entry = self._u32(24)
            info.e_phoff = self._u32(28)
            info.e_shoff = self._u32(32)
            info.e_phnum = self._u16(44)
            info.e_shnum = self._u16(48)
            info.e_shstrndx = self._u16(50)
            info.header_size = 52

        # Program headers
        try:
            self._parse_program_headers(info)
        except Exception as e:
            info.warnings.append(f"Program header error: {e}")

        # Section headers
        try:
            self._parse_sections(info)
        except Exception as e:
            info.warnings.append(f"Section header error: {e}")

        # Symbols
        try:
            self._parse_symbols(info)
        except Exception as e:
            info.warnings.append(f"Symbol parse error: {e}")

        # Dynamic entries
        try:
            self._parse_dynamic(info)
        except Exception as e:
            info.warnings.append(f"Dynamic parse error: {e}")

        return info

    def _parse_program_headers(self, info: ElfInfo):
        ph_size = 56 if self._64 else 32
        for i in range(info.e_phnum):
            off = info.e_phoff + i * ph_size
            if self._64:
                p_type = self._u32(off)
                p_flags = self._u32(off + 4)
                p_offset = self._u64(off + 8)
                p_vaddr = self._u64(off + 16)
                p_paddr = self._u64(off + 24)
                p_filesz = self._u64(off + 32)
                p_memsz = self._u64(off + 40)
                p_align = self._u64(off + 48)
            else:
                p_type = self._u32(off)
                p_offset = self._u32(off + 4)
                p_vaddr = self._u32(off + 8)
                p_paddr = self._u32(off + 12)
                p_filesz = self._u32(off + 16)
                p_memsz = self._u32(off + 20)
                p_flags = self._u32(off + 24)
                p_align = self._u32(off + 28)

            type_name = PHTYPE_NAMES.get(p_type, f"0x{p_type:X}")
            info.program_headers.append(ElfProgramHeader(
                type_=p_type, type_name=type_name, offset=p_offset,
                vaddr=p_vaddr, paddr=p_paddr, filesz=p_filesz,
                memsz=p_memsz, flags=p_flags, align=p_align,
                header_offset=off
            ))

    def _parse_sections(self, info: ElfInfo):
        sh_size = 64 if self._64 else 40
        if info.e_shoff == 0 or info.e_shnum == 0:
            return

        # First load section header string table
        shstrtab_off = 0
        shstrtab_size = 0
        if info.e_shstrndx < info.e_shnum:
            soff = info.e_shoff + info.e_shstrndx * sh_size
            if self._64:
                shstrtab_off = self._u64(soff + 24)
                shstrtab_size = self._u64(soff + 32)
            else:
                shstrtab_off = self._u32(soff + 16)
                shstrtab_size = self._u32(soff + 20)

        for i in range(info.e_shnum):
            off = info.e_shoff + i * sh_size
            sh_name_idx = self._u32(off)
            sh_type = self._u32(off + 4)

            if self._64:
                sh_flags = self._u64(off + 8)
                sh_addr = self._u64(off + 16)
                sh_offset = self._u64(off + 24)
                sh_size_val = self._u64(off + 32)
                sh_link = self._u32(off + 40)
                sh_info = self._u32(off + 44)
            else:
                sh_flags = self._u32(off + 8)
                sh_addr = self._u32(off + 12)
                sh_offset = self._u32(off + 16)
                sh_size_val = self._u32(off + 20)
                sh_link = self._u32(off + 24)
                sh_info = self._u32(off + 28)

            name = self._read_strtab_entry(shstrtab_off, shstrtab_size, sh_name_idx)
            type_name = SHTYPE_NAMES.get(sh_type, f"0x{sh_type:X}")

            info.sections.append(ElfSection(
                name=name, type_=sh_type, type_name=type_name,
                flags=sh_flags, addr=sh_addr, offset=sh_offset,
                size=sh_size_val, link=sh_link, info=sh_info,
                header_offset=off
            ))

    def _parse_symbols(self, info: ElfInfo):
        for sec in info.sections:
            if sec.type_ not in (2, 11):  # SHT_SYMTAB, SHT_DYNSYM
                continue

            table_name = sec.name
            entry_size = 24 if self._64 else 16
            strtab_sec = info.sections[sec.link] if sec.link < len(info.sections) else None
            if not strtab_sec:
                continue

            count = sec.size // entry_size if entry_size > 0 else 0
            for i in range(min(count, 8192)):
                off = sec.offset + i * entry_size
                if self._64:
                    st_name = self._u32(off)
                    st_info = self._buf.read(off + 4, 1)
                    st_info = st_info[0] if st_info else 0
                    st_shndx = self._u16(off + 6)
                    st_value = self._u64(off + 8)
                    st_size = self._u64(off + 16)
                else:
                    st_name = self._u32(off)
                    st_value = self._u32(off + 4)
                    st_size = self._u32(off + 8)
                    st_info = self._buf.read(off + 12, 1)
                    st_info = st_info[0] if st_info else 0
                    st_shndx = self._u16(off + 14)

                name = self._read_strtab_entry(strtab_sec.offset, strtab_sec.size, st_name)
                if not name:
                    continue

                info.symbols.append(ElfSymbol(
                    name=name, value=st_value, size=st_size,
                    type_=st_info & 0xF, bind=(st_info >> 4) & 0xF,
                    section_index=st_shndx, table_name=table_name
                ))

    def _parse_dynamic(self, info: ElfInfo):
        for sec in info.sections:
            if sec.type_ != 6:  # SHT_DYNAMIC
                continue

            entry_size = 16 if self._64 else 8
            count = sec.size // entry_size if entry_size > 0 else 0

            for i in range(min(count, 4096)):
                off = sec.offset + i * entry_size
                if self._64:
                    d_tag = self._u64(off)
                    d_val = self._u64(off + 8)
                else:
                    d_tag = self._u32(off)
                    d_val = self._u32(off + 4)

                if d_tag == 0:  # DT_NULL
                    break

                tag_name = DTAG_NAMES.get(d_tag, f"0x{d_tag:X}")
                info.dynamic.append(ElfDynamic(tag=d_tag, tag_name=tag_name, value=d_val))
