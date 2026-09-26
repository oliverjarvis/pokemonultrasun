#!/usr/bin/env python3
"""Cross-check code.bin symbolization against ddisasm.

  xcheck.py [--ours build/xcheck/code.elf] [--ddisasm build/ddisasm/code.gtirb] [-n SAMPLES]

Our decisions: every location with an absolute/relative relocation in a
relink of the current build with --emit-relocs (made by this script).
ddisasm's: every symbolic expression in its GTIRB. Reports locations where
only one side sees an address, grouped by segment and target kind; ddisasm-only
entries in data are the likeliest missed pointers.
"""
import argparse
import collections
import os
import struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

import gtirb

ROOT = os.path.join(os.path.dirname(__file__), "..")
SEGS = {"text": (0x100000, 0x5B99F0), "rodata": (0x5BA000, 0x666948), "data": (0x667000, 0x6A3D48)}


def seg_of(a):
    for k, (lo, hi) in SEGS.items():
        if lo <= a < hi:
            return k
    return "other"


def our_relocations(elf_path):
    """{location: kind} for ABS32/REL32-like relocations in our relinked build."""
    out = {}
    with open(elf_path, "rb") as fh:
        elf = ELFFile(fh)
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            base = elf.get_section(sec["sh_info"])
            if base.name not in (".text", ".rodata", ".data"):
                continue
            for r in sec.iter_relocations():
                t = r["r_info_type"]
                if t in (2, 38):
                    out[r["r_offset"]] = "abs"
                elif t in (3, 42):  # REL32, PREL31
                    out[r["r_offset"]] = "rel"
    return out


def ddisasm_symbolic(ir_path):
    """{location: (kind, target)} from ddisasm's symbolic expressions."""
    ir = gtirb.IR.load_protobuf(ir_path)
    out = {}
    for m in ir.modules:
        for bi in m.byte_intervals:
            if bi.address is None:
                continue
            code = [(b.offset, b.offset + b.size) for b in bi.blocks if isinstance(b, gtirb.CodeBlock)]
            code.sort()
            import bisect
            starts = [c[0] for c in code]
            for off, se in bi.symbolic_expressions.items():
                i = bisect.bisect_right(starts, off) - 1
                if i >= 0 and code[i][0] <= off < code[i][1]:
                    continue  # an instruction operand, not a data word
                loc = bi.address + off
                if isinstance(se, gtirb.SymAddrConst):
                    ref = se.symbol.referent
                    tgt = (ref.address if ref is not None and hasattr(ref, "address") and ref.address is not None else None)
                    out[loc] = ("abs", None if tgt is None else tgt + se.offset)
                elif isinstance(se, gtirb.SymAddrAddr):
                    out[loc] = ("rel", None)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ours", default=os.path.join(ROOT, "build", "xcheck", "code.elf"))
    ap.add_argument("--ddisasm", default=os.path.join(ROOT, "build", "ddisasm", "code.gtirb"))
    ap.add_argument("-n", type=int, default=12)
    ap.add_argument("--show", help="print every entry of one group, e.g. 'data,abs,text'")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.ours), exist_ok=True)
    subprocess.run(["ld.lld", "--emit-relocs", "-T", "build/link.ld", "-o", args.ours, "@build/objs.rsp"],
                   cwd=ROOT, check=True, capture_output=True)
    ours = our_relocations(args.ours)
    dd = ddisasm_symbolic(args.ddisasm)
    code = open(os.path.join(ROOT, "orig", "exefs", "code.bin"), "rb").read()
    word = lambda a: struct.unpack_from("<I", code, a - 0x100000)[0]

    only_dd = collections.defaultdict(list)
    only_ours = collections.defaultdict(list)
    for loc, (kind, tgt) in dd.items():
        s = seg_of(loc)
        if s != "other" and loc not in ours:
            only_dd[(s, kind, seg_of(tgt) if tgt is not None else "?")].append((loc, tgt))
    for loc, kind in ours.items():
        if seg_of(loc) != "other" and loc not in dd:
            only_ours[(seg_of(loc), kind, seg_of(word(loc) & ~1))].append(loc)

    from pointers import utf16_like
    for key in list(only_dd):
        only_dd[key] = [(l, t) for l, t in only_dd[key] if not utf16_like(word(l))]
        if not only_dd[key]:
            del only_dd[key]
    if args.show:
        key = tuple(args.show.split(","))
        for loc, tgt in only_dd.get(key, []):
            print(f"{loc:08X} {word(loc):08x}" + (f" -> {tgt:08X}" if tgt is not None else ""))
        return
    both = sum(1 for loc in dd if loc in ours)
    print(f"ours: {len(ours)} symbolic words; ddisasm: {len(dd)}; agree on {both}")
    print("\nddisasm-only data words, excluding UTF-16 look-alikes (possible missed pointers):")
    for key, items in sorted(only_dd.items(), key=lambda kv: -len(kv[1])):
        print(f"  {len(items):6}  in {key[0]:6} {key[1]} -> {key[2]}")
        for loc, tgt in items[: args.n if key[0] != "text" else 3]:
            print(f"            {loc:08X} = {word(loc):08x}" + (f"  -> {tgt:08X}" if tgt is not None else ""))
    print("\nours-only (possible false positives):")
    for key, items in sorted(only_ours.items(), key=lambda kv: -len(kv[1])):
        print(f"  {len(items):6}  in {key[0]:6} {key[1]} -> {key[2]}")
        for loc in items[:3]:
            print(f"            {loc:08X} = {word(loc):08x}")


if __name__ == "__main__":
    main()
