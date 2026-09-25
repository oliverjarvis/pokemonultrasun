#!/usr/bin/env python3
"""Compare functions in a compiled ELF object against code.bin.

  objcmp.py file.o [file.o ...] [--verbose]

Functions are matched by mangled name via orig/symbols.tsv. Relocated words
are compared loosely: calls/branches (R_ARM_CALL/JUMP24/PC24) by opcode only,
absolute words (R_ARM_ABS32, literal pools) are skipped. Everything else must
be byte-identical.
"""
import argparse
import struct
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

import disasm

BRANCH_RELOCS = {1, 28, 29}  # R_ARM_PC24, R_ARM_CALL, R_ARM_JUMP24
ABS_RELOCS = {2}  # R_ARM_ABS32


def load_obj(path):
    elf = ELFFile(open(path, "rb"))
    secs = {i: s for i, s in enumerate(elf.iter_sections())}
    relocs = {}
    for s in elf.iter_sections():
        if isinstance(s, RelocationSection):
            tgt = s["sh_info"]
            relocs.setdefault(tgt, {})
            for r in s.iter_relocations():
                relocs[tgt][r["r_offset"]] = r["r_info_type"]
    funcs = {}
    symtab = elf.get_section_by_name(".symtab")
    for sym in symtab.iter_symbols():
        if sym["st_info"]["type"] != "STT_FUNC" or sym["st_shndx"] in ("SHN_UNDEF", "SHN_ABS"):
            continue
        sec = secs[sym["st_shndx"]]
        data = sec.data()
        start = sym["st_value"] & ~1
        # extend over the literal pool: to the next symbol-free end of section/next func
        funcs[sym.name] = (sec, start, sym["st_size"], data, relocs.get(sym["st_shndx"], {}))
    # extend each function to the start of the next function in the same section
    by_sec = {}
    for name, (sec, start, size, data, rel) in funcs.items():
        by_sec.setdefault(sec.name, []).append((start, name))
    for lst in by_sec.values():
        lst.sort()
        for (start, name), nxt in zip(lst, lst[1:] + [(None, None)]):
            sec, _, size, data, rel = funcs[name]
            end = nxt[0] if nxt[0] is not None else len(data)
            funcs[name] = (sec, start, end - start, data, rel)
    return funcs


def compare(obj_bytes, rel, obj_start, orig):
    diffs = 0
    n = max(len(obj_bytes), len(orig)) // 4
    for k in range(n):
        o = obj_bytes[4 * k : 4 * k + 4]
        t = orig[4 * k : 4 * k + 4]
        if len(o) < 4 or len(t) < 4:
            diffs += 1
            continue
        ow, tw = struct.unpack("<I", o)[0], struct.unpack("<I", t)[0]
        rtype = rel.get(obj_start + 4 * k)
        if rtype in ABS_RELOCS:
            continue
        if rtype in BRANCH_RELOCS:
            if ow >> 24 != tw >> 24:
                diffs += 1
            continue
        if ow != tw:
            diffs += 1
    return diffs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("objs", nargs="+")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()
    base, code, syms = disasm.load()
    index = {s[2]: i for i, s in enumerate(syms)}

    total_ok = 0
    for path in args.objs:
        funcs = load_obj(path)
        results = []
        for name, (sec, start, size, data, rel) in sorted(funcs.items()):
            if name not in index:
                continue
            i = index[name]
            a = syms[i][0]
            end = disasm.extent(base, code, syms, i)
            orig = code[a - base : end - base]
            d = compare(data[start : start + size], rel, start, orig)
            results.append((name, d, size, len(orig)))
        ok = sum(1 for r in results if r[1] == 0)
        total_ok += ok
        print(f"{path}: {ok}/{len(results)} match")
        if args.verbose:
            for name, d, size, olen in results:
                status = "MATCH" if d == 0 else f"{d} words differ (size {size} vs {olen})"
                print(f"   {status:32} {name}")
    return 0 if total_ok else 1


if __name__ == "__main__":
    sys.exit(main())
