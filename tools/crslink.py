#!/usr/bin/env python3
"""Rebuild static.crs, the static module's (code.bin's) CRO-format symbol file.

  crslink.py ORIG.crs OUT.crs [--elf build/code.elf --meta build/codebin_meta.json]

static.crs imports from CRO modules anonymously (raw segment offsets). Each
of those offsets is re-resolved from the target module's linked ELF (see
crolink.target_tag), so they stay correct when a module changes size.

With --elf/--meta it also describes the rebuilt code.bin: the segment table
(.text, .rodata, and .data+.bss, followed by an empty marker segment at the
next page), every named export, and every word modules patch in code.bin
(import relocations), all recomputed from the linked symbols. The four
segment hashes are then recomputed.
"""
import argparse
import json
import struct

from elftools.elf.elffile import ELFFile

from cro import Cro, cstr
from crolink import target_tag


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("orig")
    ap.add_argument("out")
    ap.add_argument("--elf")
    ap.add_argument("--meta")
    args = ap.parse_args()

    c = Cro(open(args.orig, "rb").read(), args.orig)
    d = bytearray(c.data)
    ao, _ = c.tables["anon_imports"]
    for e in c.table("import_modules"):
        name_off, ihead, inum, ahead, anum = struct.unpack("<5I", e)
        target = cstr(c.data, name_off)
        for k in range((ahead - ao) // 8, (ahead - ao) // 8 + anum):
            tag = struct.unpack_from("<I", d, ao + 8 * k)[0]
            struct.pack_into("<I", d, ao + 8 * k, target_tag(target, tag))

    if args.elf:
        meta = json.load(open(args.meta))
        with open(args.elf, "rb") as fh:
            elf = ELFFile(fh)
            sec = {n: elf.get_section_by_name(n) for n in (".text", ".rodata", ".data", ".bss")}
            syms = {s.name: s["st_value"] for s in elf.get_section_by_name(".symtab").iter_symbols() if s.name}
        data_end = sec[".bss"]["sh_addr"] + sec[".bss"]["sh_size"]
        segs = [(sec[".text"]["sh_addr"], sec[".text"]["sh_size"]),
                (sec[".rodata"]["sh_addr"], sec[".rodata"]["sh_size"]),
                (sec[".data"]["sh_addr"], data_end - sec[".data"]["sh_addr"]),
                ((data_end + 0xFFF) & ~0xFFF, 0)]
        so, sn = c.tables["segments"]
        for i, (addr, size) in enumerate(segs):
            kind = struct.unpack_from("<I", d, so + 12 * i + 8)[0]
            struct.pack_into("<III", d, so + 12 * i, addr, size, kind)

        def tag(sym):
            v = syms[sym]
            for i, (addr, size) in enumerate(segs[:3]):
                if addr <= v < addr + size or (v == addr + size and i < 2):
                    return ((v - addr) << 4) | i
            raise ValueError(f"{sym} = {v:#x} is outside code.bin's segments")

        eo, en = c.tables["named_exports"]
        if en != len(meta["exports"]):
            raise SystemExit("export count changed; rerun split.py")
        for i, (name, sym) in enumerate(meta["exports"]):
            struct.pack_into("<I", d, eo + 8 * i + 4, tag(sym))
        ro, rn = c.tables["import_relocs"]
        if rn != len(meta["patches"]):
            raise SystemExit("patch count changed; rerun split.py")
        for i, sym in enumerate(meta["patches"]):
            struct.pack_into("<I", d, ro + 12 * i, tag(sym))

    with open(args.out, "wb") as f:
        f.write(Cro(bytes(d), args.out).rehash())


if __name__ == "__main__":
    main()
