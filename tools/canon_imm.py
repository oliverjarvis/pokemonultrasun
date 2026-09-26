#!/usr/bin/env python3
"""Re-encode linker-filled ADR immediates the way armcc does.

  canon_imm.py code.elf code.bin

Cross-unit ADRs (`add/sub rd, pc, #imm`) are assembled with R_ARM_ALU_PC_G0
relocations, and ld.lld encodes the resulting immediate with a different (but
equally valid) rotation than armcc, which always uses the smallest rotation
field. The asm marks each such instruction with a local `adrfix_*` label; this
rewrites their rotation/imm8 fields in the flat binary. Values don't change.
"""
import struct
import sys

from elftools.elf.elffile import ELFFile

BASE = 0x100000


def value(w):
    r, i = ((w >> 8) & 0xF) * 2, w & 0xFF
    return ((i >> r) | (i << (32 - r))) & 0xFFFFFFFF if r else i


def smallest_rotation(v):
    for rf in range(16):
        r = rf * 2
        i = ((v << r) | (v >> (32 - r))) & 0xFFFFFFFF if r else v
        if i < 0x100:
            return (rf << 8) | i
    raise ValueError(f"{v:#x} is not an ARM immediate")


def main():
    elf_path, bin_path = sys.argv[1:3]
    with open(elf_path, "rb") as f:
        symtab = ELFFile(f).get_section_by_name(".symtab")
        sites = [s["st_value"] for s in symtab.iter_symbols() if s.name.startswith("adrfix_")]
    data = bytearray(open(bin_path, "rb").read())
    changed = 0
    for a in sites:
        off = a - BASE
        w = struct.unpack_from("<I", data, off)[0]
        nw = (w & ~0xFFF) | smallest_rotation(value(w))
        if nw != w:
            struct.pack_into("<I", data, off, nw)
            changed += 1
    open(bin_path, "wb").write(data)


if __name__ == "__main__":
    main()
