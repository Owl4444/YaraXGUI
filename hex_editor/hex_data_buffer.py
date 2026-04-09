# -*- coding: utf-8 -*-
"""Memory-mapped read-only file buffer for the hex editor.

Supports a lazy editable *working copy* for in-place byte transforms.
Until a write happens, reads come straight from mmap/bytes so huge files
have zero overhead.  The first mutation promotes the buffer to an
in-memory ``bytearray`` which then serves all subsequent reads.
"""

import mmap
import os
from pathlib import Path


# Threshold above which we use mmap instead of reading the whole file
MMAP_THRESHOLD = 10 * 1024 * 1024  # 10 MB


class HexDataBuffer:
    """Read/write file buffer with mmap + lazy editable working copy."""

    def __init__(self):
        self._data: bytes | mmap.mmap | None = None
        self._file = None
        self._mmap: mmap.mmap | None = None
        self._size = 0
        self._filepath: str = ""
        self._format: str = ""
        # Lazy editable working copy. While None, reads use self._data.
        self._working: bytearray | None = None

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

    # ── Reads ──────────────────────────────────────────────────────

    def read(self, offset: int, length: int) -> bytes:
        """Read *length* bytes starting at *offset*."""
        if offset < 0 or offset >= self._size:
            return b""
        end = min(offset + length, self._size)
        if self._working is not None:
            return bytes(self._working[offset:end])
        if self._data is None:
            return b""
        return bytes(self._data[offset:end])

    def read_range(self, lo: int, hi: int) -> bytes:
        """Read bytes in the inclusive range ``[lo, hi]``."""
        if hi < lo:
            return b""
        return self.read(lo, hi - lo + 1)

    def size(self) -> int:
        return self._size

    # ── Editable working copy ─────────────────────────────────────

    def is_modified(self) -> bool:
        """True once any write/replace has promoted the buffer."""
        return self._working is not None

    def _promote_to_working(self):
        """Copy current contents to a bytearray and release mmap."""
        if self._working is not None:
            return
        if self._data is None:
            self._working = bytearray()
        else:
            self._working = bytearray(bytes(self._data[0:self._size]))
        # Release mmap / file handles — we no longer need them
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
        # Point _data at the working copy so any stray consumers still work
        self._data = self._working

    def write_bytes(self, offset: int, data: bytes) -> None:
        """Overwrite ``len(data)`` bytes starting at *offset*.

        Length-preserving; the buffer size does not change.  Writes past
        the current end are clamped.
        """
        if offset < 0 or offset > self._size:
            return
        self._promote_to_working()
        end = min(offset + len(data), self._size)
        if end <= offset:
            return
        assert self._working is not None
        self._working[offset:end] = data[: end - offset]

    def replace_range(self, lo: int, hi: int, new_bytes: bytes) -> None:
        """Replace the inclusive range ``[lo, hi]`` with *new_bytes*.

        Supports length changes — the buffer grows or shrinks accordingly.
        """
        if lo < 0 or lo > self._size:
            return
        if hi < lo - 1:  # allow hi == lo - 1 for zero-length range
            return
        hi = min(hi, self._size - 1)
        self._promote_to_working()
        assert self._working is not None
        self._working[lo:hi + 1] = new_bytes
        self._size = len(self._working)

    def save_to(self, filepath: str) -> bool:
        """Write the current buffer contents to *filepath*.

        Writes the working copy if present, else copies the original
        mmap / bytes contents.  Never touches ``self._filepath``.
        """
        try:
            if self._working is not None:
                with open(filepath, "wb") as f:
                    f.write(bytes(self._working))
                return True
            if self._data is None:
                with open(filepath, "wb") as f:
                    pass
                return True
            with open(filepath, "wb") as f:
                f.write(bytes(self._data[0:self._size]))
            return True
        except Exception as e:
            print(f"Error saving file: {e}")
            return False

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
        self._working = None
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
