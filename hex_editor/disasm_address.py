"""Map executable virtual addresses to file offsets for hex navigation."""


class AddressMap:
    def __init__(self, ranges=()):
        self.ranges = list(ranges)  # (file offset, virtual address, file-backed size)

    def virtual_base(self, offset, size):
        for file_start, virtual_start, length in self.ranges:
            if file_start <= offset and offset + size <= file_start + length:
                return virtual_start + offset - file_start
        return None

    def file_offset(self, address):
        for file_start, virtual_start, length in self.ranges:
            if virtual_start <= address < virtual_start + length:
                return file_start + address - virtual_start
        return None


def executable_address_map(buffer):
    if buffer is None:
        return AddressMap()
    magic = buffer.read(0, 4)
    if magic[:2] == b"MZ":
        from .pe_parser import PeParser
        info = PeParser(buffer).parse()
        if info:
            return AddressMap((s.raw_offset, info.image_base + s.virtual_address, s.raw_size)
                              for s in info.sections if s.raw_size)
    elif magic == b"\x7fELF":
        from .elf_parser import ElfParser
        info = ElfParser(buffer).parse()
        if info and info.e_type in (2, 3):
            return AddressMap((p.offset, p.vaddr, p.filesz)
                              for p in info.program_headers if p.type_ == 1 and p.filesz)
    return AddressMap()
