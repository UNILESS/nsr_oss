from typing import Optional


class BinProperty:
    arch: str  # r2=bin.machine
    bits: int  # r2=bin.bits
    format: str  # r2=bin.bintype
    be: bool  # r2=bin.endian
    platform: str  # r2=bin.os
    text_offset: int  # r2: iSj -> vaddr
    text_size: int  # r2: iSj -> vsize

    def __init__(self, arch: str, bits: int, _format: str, be: bool, platform: str, text_offset: int, text_size: int):
        self.arch = arch
        self.bits = bits
        self.format = _format
        self.be = be
        self.platform = platform
        self.text_offset = text_offset
        self.text_size = text_size

    def __getstate__(self):
        return self.__dict__


class FuncProperty:
    name: str
    addr: int
    size: int
    text_offset: int
    raw_bytes: Optional[bytes]
    call_count: int

    def __init__(self, name: str, addr: int, size: int, text_offset: int, raw_bytes: Optional[bytes], call_count: int):
        self.name = name
        self.addr = addr
        self.size = size
        self.text_offset = text_offset
        self.raw_bytes = raw_bytes
        self.call_count = call_count

    def __getstate__(self):
        return self.__dict__
