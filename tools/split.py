#!/usr/bin/env python3
"""Split code.bin into per-function assembly.

Outputs:
  asm/text/<ADDR>.s   one unit per function start from orig/analysis.json
  asm/data.s          .rodata / .data as .incbin of the original code.bin
  build/units.tsv     addr, size, symbol for every unit
  build/layout.ld     linker script: units sorted by their .text.<ADDR> section
  build/asm_syms.ld   absolute data symbols referenced from asm

Run tools/configure.py afterwards to (re)generate build.ninja.

Words listed in config/force_raw.txt are emitted as `.inst` (exact bytes,
no relocation); tools/check.py adds entries when the assembler's encoding
differs from the original.
"""
import json
import os

from analyze import CODE, JT, LIT, Text
from asmemit import MACROS, Region
from pointers import looks_like_pointer

ROOT = os.path.join(os.path.dirname(__file__), "..")
ORIG = os.path.join(ROOT, "orig")


def load_force_raw():
    path = os.path.join(ROOT, "config", "force_raw.txt")
    if not os.path.exists(path):
        return set()
    return {int(l.split()[0], 16) for l in open(path) if l.strip() and not l.startswith("#")}


def main():
    t = Text()
    an = json.load(open(os.path.join(ORIG, "analysis.json")))
    names = {}
    for line in open(os.path.join(ORIG, "symbols.tsv")).read().splitlines()[1:]:
        addr, mode, seg, mangled, dm = line.split("\t")
        names[int(addr, 16)] = mangled
    force_raw = load_force_raw()

    kind = bytearray(t.size // 4)
    for s, e in an["code"]:
        kind[(s - t.base) >> 2 : (e - t.base) >> 2] = bytes([CODE]) * ((e - s) >> 2)
    for a in an["literals"]:
        kind[(a - t.base) >> 2] = LIT
    for a in an["jumptabs"]:
        kind[(a - t.base) >> 2] = JT

    data_syms = set()
    thumb = an["thumb"]
    in_thumb = lambda a: any(ts <= a < te for ts, te in thumb)

    def word_ref(a, w):
        """Pointer-like literal values become symbols (text labels or data_ADDR)."""
        if not looks_like_pointer(w, t):
            return None
        if t.in_text(w):
            tgt = w & ~1
            if w & 1 and in_thumb(tgt):
                return ("text", tgt, "")  # Thumb function pointer; the label carries bit 0
            return ("text", tgt, " + 1" if w & 1 else "") if tgt % 4 == 0 and not in_thumb(tgt) else None
        data_syms.add(w)
        return ("expr", f"data_{w:08X}")

    region = Region(t.words, t.base, t.blob[: t.size], kind, [a for a, _ in an["funcs"]],
                    names, force_raw, word_ref, thumb=thumb)
    units = region.emit(os.path.join(ROOT, "asm", "text"))
    print(f"merged {getattr(region, 'merged', 0)} function starts into shared-literal-pool units, "
          f"{len(region.thumb_labels)} Thumb labels")

    # ---- data sections, macros, linker script, ninja
    os.makedirs(os.path.join(ROOT, "build"), exist_ok=True)
    open(os.path.join(ROOT, "asm", "macros.inc"), "w").write(MACROS)
    ro_size = t.ro[1] - t.ro[0]
    da_size = t.data[1] - t.data[0]
    open(os.path.join(ROOT, "asm", "data.s"), "w").write(
        f".section .rodata, \"a\"\n.incbin \"orig/exefs/code.bin\", {t.ro_off:#x}, {ro_size:#x}\n"
        f".section .data, \"aw\"\n.incbin \"orig/exefs/code.bin\", {t.data_off:#x}, {da_size:#x}\n")

    with open(os.path.join(ROOT, "build", "units.tsv"), "w") as f:
        f.write("addr\tsize\tsymbol\n")
        for s, size, sym in units:
            f.write(f"{s:08X}\t{size}\t{sym}\n")

    layout = ["SECTIONS", "{", f"    .text {t.base:#x} : {{ *(SORT_BY_NAME(.text.*)) }}",
              f"    .rodata {t.ro[0]:#x} : {{ build/data.o(.rodata) }}",
              f"    .data {t.data[0]:#x} : {{ build/data.o(.data) }}",
              "    /DISCARD/ : { *(.ARM.attributes) *(.comment) *(.ARM.exidx*) *(.arm_vfe_header) *(.debug*) }",
              "}"]
    open(os.path.join(ROOT, "build", "layout.ld"), "w").write("\n".join(layout) + "\n")
    open(os.path.join(ROOT, "build", "asm_syms.ld"), "w").write(
        "".join(f"data_{a:08X} = {a:#x};\n" for a in sorted(data_syms)))

    print(f"{len(units)} units, {len(data_syms)} data symbols, {len(force_raw)} forced raw")


if __name__ == "__main__":
    main()
