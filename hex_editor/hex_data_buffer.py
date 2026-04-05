# -*- coding: utf-8 -*-
"""Memory-mapped read-only file buffer for the hex editor."""

import mmap
import os
from pathlib import Path


# Threshold above which we use mmap instead of reading the whole file
MMAP_THRESHOLD = 10 * 1024 * 1024  # 10 MB


class HexDataBuffer:
    """Read-only file buffer with mmap support for large files."""

    def __init__(self):
        self._data: bytes | mmap.mmap | None = None
        self._file = None
        self._mmap: mmap.mmap | None = None
        self._size = 0
        self._filepath: str = ""
        self._format: str = ""

    @property
    def filepath(self) -> str:
        return self._filepath

    def open_file(self, filepath: str) -> bool:
        """Open a file for reading. Returns True on success."""
        self.close()
        try:
            path = Path(filepath)
            if not path.exists() or not path.is_file():
                return False

            self._filepath = str(path)
            self._size = path.stat().st_size

            if self._size == 0:
                self._data = b""
                return True

            if self._size > MMAP_THRESHOLD:
                self._file = open(filepath, "rb")
                self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
                self._data = self._mmap
            else:
                with open(filepath, "rb") as f:
                    self._data = f.read()

            self._format = self.detect_format()
            return True

        except Exception as e:
            print(f"Error opening file: {e}")
            self.close()
            return False

    def open_bytes(self, data: bytes, name: str = "<memory>") -> bool:
        """Open raw bytes (e.g. from scan hit file_data)."""
        self.close()
        self._data = data
        self._size = len(data)
        self._filepath = name
        self._format = self.detect_format()
        return True

    def read(self, offset: int, length: int) -> bytes:
        """Read *length* bytes starting at *offset*."""
        if self._data is None or offset < 0 or offset >= self._size:
            return b""
        end = min(offset + length, self._size)
        return bytes(self._data[offset:end])

    def size(self) -> int:
        return self._size

    def close(self):
        if self._mmap is not None:
            try:
                self._mmap.close()
            except Exception:
                pass
            self._mmap = None
        if self._file is not None:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None
        self._data = None
        self._size = 0
        self._filepath = ""
        self._format = ""

    def detect_format(self) -> str:
        """Detect binary format from magic bytes."""
        if self._data is None or self._size < 4:
            return "Unknown"
        magic = bytes(self._data[0:4])
        if magic[:2] == b"MZ":
            # Check for PE
            if self._size >= 64:
                pe_offset_bytes = bytes(self._data[0x3C:0x40])
                if len(pe_offset_bytes) == 4:
                    pe_offset = int.from_bytes(pe_offset_bytes, "little")
                    if pe_offset + 4 <= self._size:
                        pe_sig = bytes(self._data[pe_offset:pe_offset + 4])
                        if pe_sig == b"PE\x00\x00":
                            # Check PE32 vs PE32+
                            opt_hdr_off = pe_offset + 24
                            if opt_hdr_off + 2 <= self._size:
                                opt_magic = int.from_bytes(
                                    bytes(self._data[opt_hdr_off:opt_hdr_off + 2]), "little"
                                )
                                if opt_magic == 0x20B:
                                    return "PE32+ (64-bit)"
                                return "PE32 (32-bit)"
                            return "PE"
            return "MZ/DOS"
        if magic == b"\x7fELF":
            if self._size >= 5:
                ei_class = self._data[4]
                if ei_class == 2:
                    return "ELF64"
                return "ELF32"
            return "ELF"
        if magic[:4] == b"\xCA\xFE\xBA\xBE":
            return "Mach-O Fat"
        if magic[:4] in (b"\xFE\xED\xFA\xCE", b"\xFE\xED\xFA\xCF",
                         b"\xCE\xFA\xED\xFE", b"\xCF\xFA\xED\xFE"):
            return "Mach-O"
        return "Unknown"

    @property
    def format_name(self) -> str:
        return self._format

    def __del__(self):
        self.close()
