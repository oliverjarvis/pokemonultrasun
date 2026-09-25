#!/usr/bin/env python3
"""Analyze and split every CRO module's .text into per-function assembly.

  cro_split.py [MODULE ...]

For each orig/rom/romfs/<Module>.cro:
  asm/cro/<Module>/<OFF>.s     one unit per function (addresses are file offsets)
  build/cro/<Module>/units.tsv addr, size, symbol
  build/cro/<Module>/layout.ld linker script placing .text at its file offset

Relocated words (internal and import relocations, all R_ARM_ABS32) are zero in
the file; they are emitted as `.word 0` annotated with their target. They also
tell the tracer exactly which words are data. Function seeds: named exports,
the control object / load hooks, import veneers (`ldr pc, [pc, #-4]` + import
word, named veneer_<import>), relocation targets inside .text, call targets
and prologues. Anonymous imports from the static module are named via
static.crs and orig/symbols.tsv.
"""
import os
import struct
import sys

from analyze import Tracer
from asmemit import MACROS, Region
from cro import SEG_TYPES, Cro, u32

ROOT = os.path.join(os.path.dirname(__file__), "..")
ROMFS = os.path.join(ROOT, "orig", "rom", "romfs")
VENEER = 0xE51FF004  # ldr pc, [pc, #-4]


def static_names():
    """code.bin address -> symbol, and static.crs segment bases."""
    names = {}
    for line in open(os.path.join(ROOT, "orig", "symbols.tsv")).read().splitlines()[1:]:
        addr, mode, seg, mangled, dm = line.split("\t")
        names[int(addr, 16)] = mangled
    crs = Cro(open(os.path.join(ROMFS, "static.crs"), "rb").read(), "static.crs")
    return names, [s[0] for s in crs.segments]


def import_map(c, static_syms, static_bases):
    """file offset of each import-relocated word -> import symbol name."""
    relocs = c.import_relocs()
    ro, _ = c.tables["import_relocs"]
    out = {}

    def walk(head_off, name):
        k = (head_off - ro) // 12
        while 0 <= k < len(relocs):
            tag, rtype, last, addend = relocs[k]
            out[c.seg_addr(tag)] = name + (f"+{addend}" if addend else "")
            if last:
                break
            k += 1

    for e in c.table("named_imports"):
        name_off, head = struct.unpack("<II", e)
        walk(head, c.data[name_off : c.data.index(b"\0", name_off)].decode())
    for e in c.table("anon_imports"):
        tag, head = struct.unpack("<II", e)
        addr = static_bases[tag & 0xF] + (tag >> 4)
        walk(head, static_syms.get(addr, f"sub_{addr:08X}"))
    for e in c.table("indexed_imports"):
        idx, head = struct.unpack("<II", e)
        walk(head, f"indexed_{idx}")
    return out


def split_module(path, static_syms, static_bases):
    name = os.path.splitext(os.path.basename(path))[0]
    c = Cro(open(path, "rb").read(), name)
    text = c.text()
    if not text:
        return name, 0, None
    toff, tsize = text
    words = struct.unpack_from(f"<{tsize // 4}I", c.data, toff)
    text_seg = next(i for i, s in enumerate(c.segments) if s[2] == 0 and s[1])

    imports = import_map(c, static_syms, static_bases)
    internal = {}
    for tag, rtype, seg, addend in c.internal_relocs():
        internal[c.seg_addr(tag)] = (seg, addend)
    relocated = set(imports) | set(internal)

    tr = Tracer(words, toff, literals=relocated)
    names = {}

    def add(addr, sym):
        if tr.in_text(addr) and addr % 4 == 0:
            tr.seed(addr, sym)
            if sym and addr not in names:
                names[addr] = sym

    used = set()
    for a in range(toff, toff + tsize - 4, 4):
        if tr.w(a) == VENEER and a + 4 in imports:
            sym = "veneer_" + imports[a + 4].replace("+", "_plus_")
            while sym in used:
                sym += "_"
            used.add(sym)
            add(a, sym)
    for sym, tag in c.named_exports():
        if (tag & 0xF) == text_seg:
            add(c.seg_addr(tag), sym)
    for field in ("control_object", "on_load", "on_exit", "on_unresolved"):
        tag = c.hdr[field]
        if tag != 0xFFFFFFFF and (tag & 0xF) == text_seg:
            add(c.seg_addr(tag), None)
    tr.drain()
    tr.pointer_seeds(toff + addend for seg, addend in internal.values() if seg == text_seg)
    tr.prologue_seeds()

    def describe(seg, addend):
        kind = SEG_TYPES.get(c.segments[seg][2], str(seg))
        if seg == text_seg:
            tgt = toff + addend
            return names.get(tgt) or f"sub_{tgt:08X}" if tgt in tr.funcs else f"text+{addend:#x}"
        return f"{kind}+{addend:#x}"

    def word_ref(a, w):
        if a in imports:
            return ("raw", f"import {imports[a]}")
        if a in internal:
            return ("raw", "-> " + describe(*internal[a]))
        return None

    region = Region(words, toff, c.data[toff : toff + tsize], tr.kind, list(tr.funcs), names, (), word_ref)
    units = region.emit(os.path.join(ROOT, "asm", "cro", name))

    bdir = os.path.join(ROOT, "build", "cro", name)
    os.makedirs(bdir, exist_ok=True)
    with open(os.path.join(bdir, "units.tsv"), "w") as f:
        f.write("addr\tsize\tsymbol\n")
        for s, size, sym in units:
            f.write(f"{s:08X}\t{size}\t{sym}\n")
    with open(os.path.join(bdir, "layout.ld"), "w") as f:
        f.write(f"ENTRY(__text_start)\n__text_start = {toff:#x};\n"
                f"SECTIONS\n{{\n    .text {toff:#x} : {{ *(SORT_BY_NAME(.text.*)) }}\n"
                "    /DISCARD/ : { *(.ARM.attributes) *(.comment) *(.ARM.exidx*) *(.arm_vfe_header) *(.debug*) }\n}\n")
    return name, len(units), tr


def main():
    static_syms, static_bases = static_names()
    os.makedirs(os.path.join(ROOT, "asm", "cro"), exist_ok=True)
    open(os.path.join(ROOT, "asm", "macros.inc"), "w").write(MACROS)
    wanted = set(sys.argv[1:])
    total_units = 0
    code = lit = unk = words = 0
    paths = sorted(p for p in os.listdir(ROMFS) if p.endswith(".cro"))
    for p in paths:
        if wanted and os.path.splitext(p)[0] not in wanted:
            continue
        name, nunits, tr = split_module(os.path.join(ROMFS, p), static_syms, static_bases)
        total_units += nunits
        if tr:
            n = len(tr.words)
            words += n
            code += tr.kind.count(1)
            lit += tr.kind.count(2) + tr.kind.count(3)
            unk += tr.kind.count(0)
    print(f"{len(paths) if not wanted else len(wanted)} modules, {total_units} units; text words {words}: "
          f"code {code / words:.1%}, literal/jump table {lit / words:.1%}, unknown {unk / words:.1%}")


if __name__ == "__main__":
    main()
