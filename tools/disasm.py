#!/usr/bin/env python3
"""Disassemble functions from code.bin using the static.crs symbol table.

  disasm.py <name-substring|0xADDR> [...]   disassemble matching functions
  disasm.py --candidates [max_bytes]        list small, self-contained ARM
                                            functions (compiler-ID candidates)

A function's extent is taken as [addr, next symbol or next LR-saving prologue).
"""
import argparse
import bisect
import json
import os
import struct

import capstone

ROOT = os.path.join(os.path.dirname(__file__), "..", "orig")
RET_WORDS = {0xE12FFF1E}  # bx lr


def load():
    info = json.load(open(os.path.join(ROOT, "info.json")))
    text = info["exheader"]["text"]
    code = open(os.path.join(ROOT, "exefs", "code.bin"), "rb").read()[: text["size"]]
    syms = []
    for line in open(os.path.join(ROOT, "symbols.tsv")).read().splitlines()[1:]:
        addr, mode, seg, mangled, dm = line.split("\t")
        if seg == "text":
            syms.append((int(addr, 16), mode, mangled, dm))
    syms.sort()
    return text["addr"], code, syms


def is_prologue(w):
    return w & 0xFFFF4000 == 0xE92D4000 or w == 0xE52DE004


def is_return(w):
    # bx lr, or pop/ldm sp! {..., pc}
    return w in RET_WORDS or w & 0x0FFF8000 == 0x08BD8000 or w & 0x0FFFFFFF == 0x049DF004


def extent(base, code, syms, i):
    start = syms[i][0]
    limit = syms[i + 1][0] if i + 1 < len(syms) else base + len(code)
    # stop at the first new prologue after an unconditional return
    a, seen_ret = start, False
    while a < limit:
        w = struct.unpack_from("<I", code, a - base)[0]
        if seen_ret and is_prologue(w):
            return a
        if is_return(w) and w >> 28 == 0xE:
            seen_ret = True
        a += 4
    return limit


def disasm(base, code, syms, i, out):
    start, mode, mangled, dm = syms[i]
    end = extent(base, code, syms, i)
    md = capstone.Cs(capstone.CS_ARCH_ARM,
                     capstone.CS_MODE_THUMB if mode == "thumb" else capstone.CS_MODE_ARM)
    addrs = [s[0] for s in syms]
    out.append(f"; {dm}\n; {mangled}\n; {start:#x}-{end:#x} ({end - start} bytes, {mode})")
    blob = code[start - base : end - base]
    pos = 0
    while pos < len(blob):
        insns = list(md.disasm(blob[pos:], start + pos))
        for ins in insns:
            note = ""
            if ins.mnemonic in ("bl", "blx", "b") and ins.op_str.startswith("#"):
                tgt = int(ins.op_str[1:], 16)
                j = bisect.bisect_right(addrs, tgt) - 1
                if j >= 0 and syms[j][0] == tgt:
                    note = f"  ; {syms[j][3]}"
            out.append(f"  {ins.address:08x}: {ins.bytes[::-1].hex()}  {ins.mnemonic:8} {ins.op_str}{note}")
        pos += sum(ins.size for ins in insns)
        if pos < len(blob):  # undecodable word (literal pool data)
            w = struct.unpack_from("<I", blob, pos)[0]
            out.append(f"  {start + pos:08x}: {w:08x}  .word    {w:#x}")
            pos += 4
    return end - start


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("query", nargs="*")
    ap.add_argument("--candidates", type=int, nargs="?", const=160)
    args = ap.parse_args()
    base, code, syms = load()

    if args.candidates:
        for i, (a, mode, mangled, dm) in enumerate(syms):
            if mode != "arm" or dm.startswith(("nn::", "std::", "__", "operator")):
                continue
            size = extent(base, code, syms, i) - a
            if 24 <= size <= args.candidates:
                print(f"{a:08x}\t{size}\t{dm}")
        return

    out = []
    for q in args.query:
        for i, s in enumerate(syms):
            if (q.startswith("0x") and s[0] == int(q, 16)) or (not q.startswith("0x") and q in s[3]):
                disasm(base, code, syms, i, out)
                out.append("")
    print("\n".join(out))


if __name__ == "__main__":
    main()
