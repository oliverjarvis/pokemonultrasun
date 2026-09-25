#!/usr/bin/env python3
"""Build a symbol table for code.bin from static.crs named exports.

Writes orig/symbols.tsv: address, mode (arm/thumb), segment, mangled, demangled.
Export segment tags are (offset << 4) | segment_index; an odd text offset
marks a Thumb entry point.
"""
import os
import struct
import subprocess
import sys

SEG_NAMES = {0: "text", 1: "rodata", 2: "data", 3: "bss"}


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "orig"
    b = open(os.path.join(root, "romfs", "static.crs"), "rb").read()
    seg_off, seg_num = u32(b, 0xC8), u32(b, 0xCC)
    segs = [struct.unpack_from("<III", b, seg_off + 12 * i) for i in range(seg_num)]

    rows = []
    exp_off, exp_num = u32(b, 0xD0), u32(b, 0xD4)
    for i in range(exp_num):
        name_off, tag = struct.unpack_from("<II", b, exp_off + 8 * i)
        name = b[name_off : b.index(b"\0", name_off)].decode("ascii")
        base, _, kind = segs[tag & 0xF]
        addr = base + (tag >> 4)
        seg = SEG_NAMES.get(kind, str(kind))
        mode = "thumb" if seg == "text" and addr & 1 else ("arm" if seg == "text" else "-")
        rows.append((addr & ~1 if seg == "text" else addr, mode, seg, name))
    rows.sort()

    demangled = subprocess.run(["c++filt"], input="\n".join(r[3] for r in rows),
                               capture_output=True, text=True, check=True).stdout.splitlines()
    with open(os.path.join(root, "symbols.tsv"), "w") as f:
        f.write("addr\tmode\tseg\tmangled\tdemangled\n")
        for (addr, mode, seg, name), dm in zip(rows, demangled):
            f.write(f"{addr:08X}\t{mode}\t{seg}\t{name}\t{dm}\n")
    by = {}
    for r in rows:
        by[(r[2], r[1])] = by.get((r[2], r[1]), 0) + 1
    print(f"{len(rows)} symbols:", ", ".join(f"{s}/{m}={n}" for (s, m), n in sorted(by.items())))


if __name__ == "__main__":
    main()
