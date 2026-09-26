#!/usr/bin/env python3
"""Wrap the original code.bin in a plain ARM ELF for external analysis tools.

  mkelf.py OUT.elf

Sections .text/.rodata/.data (original bytes) and .bss at their load
addresses, and a symbol table containing only ground truth: the named
exports from static.crs (orig/symbols.tsv), Thumb functions with bit 0 set.
Nothing from this project's own analysis is included, so tools such as
ddisasm give an independent opinion.
"""
import os
import struct
import sys

from analyze import Text

ROOT = os.path.join(os.path.dirname(__file__), "..")


def main():
    t = Text()
    segs = [(".text", t.base, t.blob[: t.size], 6, 1),
            (".rodata", t.ro[0], t.blob[t.ro_off : t.ro_off + t.ro[1] - t.ro[0]], 2, 1),
            (".data", t.data[0], t.blob[t.data_off : t.data_off + t.data[1] - t.data[0]], 3, 1),
            (".bss", t.data[1], b"", 3, 8)]
    bss_size = t.bss_end - t.data[1]

    syms = []
    for line in open(os.path.join(ROOT, "orig", "symbols.tsv")).read().splitlines()[1:]:
        addr, mode, seg, mangled, dm = line.split("\t")
        a = int(addr, 16)
        sec = {"text": 1, "rodata": 2, "data": 3}.get(seg)
        if sec is None:
            continue
        typ = 2 if seg == "text" else 1  # FUNC / OBJECT
        syms.append((mangled, a | (1 if mode == "thumb" else 0), typ, sec))

    strtab = b"\0"
    name_off = []
    for name, *_ in syms:
        name_off.append(len(strtab))
        strtab += name.encode() + b"\0"
    symtab = b"\0" * 16
    for (name, value, typ, sec), no in zip(syms, name_off):
        symtab += struct.pack("<IIIBBH", no, value, 0, (1 << 4) | typ, 0, sec)
    shnames = [b"", b".text", b".rodata", b".data", b".bss", b".symtab", b".strtab", b".shstrtab"]
    shstr = b""
    sh_off = []
    for n in shnames:
        sh_off.append(len(shstr))
        shstr += n + b"\0"

    ehsize, phentsize, shentsize = 52, 32, 40
    phnum = 3
    pos = ehsize + phnum * phentsize
    body = bytearray()
    placed = []
    for name, addr, data, flags, align in segs:
        pos_aligned = (pos + len(body) + 0xFFF) & ~0xFFF if name != ".bss" else pos + len(body)
        body += b"\0" * (pos_aligned - pos - len(body))
        placed.append(pos_aligned)
        body += data
    sym_off = pos + len(body); body += symtab
    str_off = pos + len(body); body += strtab
    shs_off = pos + len(body); body += shstr
    body += b"\0" * (-len(body) % 4)
    sh_table = pos + len(body)

    out = bytearray()
    out += b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\0" * 8
    out += struct.pack("<HHIIIIIHHHHHH", 2, 40, 1, t.base, ehsize, sh_table, 0x05000000,
                       ehsize, phentsize, phnum, shentsize, len(shnames), len(shnames) - 1)
    for (name, addr, data, flags, align), off in list(zip(segs, placed))[:3]:
        memsz = len(data) + (bss_size if name == ".data" else 0)
        out += struct.pack("<IIIIIIII", 1, off, addr, addr, len(data), memsz, [5, 4, 6][segs.index((name, addr, data, flags, align))], 0x1000)
    out += body
    sh = struct.pack("<10I", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    for i, (name, addr, data, flags, align) in enumerate(segs):
        typ = 8 if name == ".bss" else 1
        size = bss_size if name == ".bss" else len(data)
        sh += struct.pack("<10I", sh_off[i + 1], typ, flags, addr, placed[i], size, 0, 0, 4, 0)
    sh += struct.pack("<10I", sh_off[5], 2, 0, 0, sym_off, len(symtab), 6, 1, 4, 16)
    sh += struct.pack("<10I", sh_off[6], 3, 0, 0, str_off, len(strtab), 0, 0, 1, 0)
    sh += struct.pack("<10I", sh_off[7], 3, 0, 0, shs_off, len(shstr), 0, 0, 1, 0)
    with open(sys.argv[1], "wb") as f:
        f.write(out + sh)
    print(f"{sys.argv[1]}: {len(syms)} symbols")


if __name__ == "__main__":
    main()
