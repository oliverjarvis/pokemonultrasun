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
import bisect
import json
import os
import re
import shutil
import struct

import capstone

from analyze import Text, branch, pc_load_targets

ROOT = os.path.join(os.path.dirname(__file__), "..")
ORIG = os.path.join(ROOT, "orig")
PC_REL = re.compile(r"\[pc, #(-?0x[0-9a-f]+|-?\d+)\]")


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

    n = t.size // 4
    CODE, LIT, JT = 1, 2, 3
    kind = bytearray(n)
    for s, e in an["code"]:
        kind[(s - t.base) >> 2 : (e - t.base) >> 2] = bytes([CODE]) * ((e - s) >> 2)
    for a in an["literals"]:
        kind[(a - t.base) >> 2] = LIT
    for a in an["jumptabs"]:
        kind[(a - t.base) >> 2] = JT

    starts = sorted({a for a, _ in an["funcs"]} | {t.base})
    unit_of = lambda a: bisect.bisect_right(starts, a) - 1

    def unit_sym(a):
        return names.get(a) or f"sub_{a:08X}"

    # ---- pass 1: references, to decide which addresses need labels
    local_labels = set()   # referenced only from inside their own unit
    global_labels = set()  # referenced from another unit (mid-unit)
    data_syms = set()

    def text_ref(src, tgt):
        if tgt in starts:
            return
        if unit_of(src) == unit_of(tgt):
            local_labels.add(tgt)
        else:
            global_labels.add(tgt)

    def value_sym_target(v):
        """Target address for a pointer-like value, or None to keep it raw."""
        if t.in_text(v):
            a = v & ~1
            return a if a % 4 == 0 else None
        if t.ro[0] <= v < t.data[1] + 0x40000:  # rodata, data, bss (generous upper bound)
            return v
        return None

    for i in range(n):
        a = t.base + 4 * i
        if a in force_raw:
            continue
        w = t.words[i]
        k = kind[i]
        if k == CODE:
            br = branch(w, a)
            if br and br[0] != "blx" and t.in_text(br[1]):
                text_ref(a, br[1])
            for lt in pc_load_targets(w, a):
                if t.in_text(lt):
                    text_ref(a, lt & ~3)
        elif k in (LIT, JT):
            tgt = value_sym_target(w)
            if tgt is None:
                continue
            if t.in_text(tgt):
                text_ref(a, tgt)
            else:
                data_syms.add(tgt)

    def sym_for(src, tgt):
        """Assembler expression for a reference from src to text address tgt."""
        if tgt in starts:
            return unit_sym(tgt)
        if tgt in global_labels:
            return f"loc_{tgt:08X}"
        return f".L_{tgt:08X}"

    # ---- pass 2: emit units
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    out_dir = os.path.join(ROOT, "asm", "text")
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir)
    units = []
    for ui, s in enumerate(starts):
        e = starts[ui + 1] if ui + 1 < len(starts) else t.end
        blob = t.blob[s - t.base : e - t.base]
        dis = {}
        off = 0
        while off < len(blob):
            last = off
            for addr, size, mnem, op in md.disasm_lite(blob[off:], s + off):
                dis[addr] = (mnem, op)
                off = addr - s + size
            if off == last:  # undecodable word: capstone stops, skip it
                off += 4
        sym = unit_sym(s)
        lines = [".include \"macros.inc\"", f".section .text.{s:08X}, \"ax\", %progbits", "", f"glabel {sym}"]
        for a in range(s, e, 4):
            i = (a - t.base) >> 2
            if a != s and a in names:
                lines.append(f"glabel {names[a]}")
            if a in global_labels:
                lines.append(f"glabel loc_{a:08X}")
            elif a in local_labels:
                lines.append(f".L_{a:08X}:")
            w = t.words[i]
            k = kind[i]
            if a in force_raw:
                lines.append(f"    .inst 0x{w:08x} /* {a:08X} */")
                continue
            if k == CODE and a in dis:
                mnem, op = dis[a]
                br = branch(w, a)
                if br:
                    if br[0] == "blx" or not t.in_text(br[1]):
                        lines.append(f"    .inst 0x{w:08x} /* {a:08X} {mnem} */")
                        continue
                    op = sym_for(a, br[1])
                else:
                    m = PC_REL.search(op)
                    lts = pc_load_targets(w, a)
                    if m and lts:
                        tgt = a + 8 + int(m.group(1), 0)
                        base_w = tgt & ~3
                        if not t.in_text(base_w) or unit_of(base_w) != ui:
                            # pc-relative load across units: keep exact bytes
                            lines.append(f"    .inst 0x{w:08x} /* {a:08X} {mnem} {op} */")
                            continue
                        expr = sym_for(a, base_w) + (f" + {tgt - base_w}" if tgt != base_w else "")
                        op = op[: m.start()] + expr + op[m.end() :]
                lines.append(f"    {mnem} {op} /* {a:08X} */".replace("  /*", " /*"))
                continue
            if k in (LIT, JT):
                tgt = value_sym_target(w)
                if tgt is not None:
                    if t.in_text(tgt):
                        expr = sym_for(a, tgt) + (" + 1" if w & 1 else "")
                    else:
                        expr = f"data_{tgt:08X}"
                    lines.append(f"    .word {expr} /* {a:08X} */")
                    continue
            lines.append(f"    .word 0x{w:08x} /* {a:08X} */")
        lines.append(f"endlabel {sym}")
        open(os.path.join(out_dir, f"{s:08X}.s"), "w").write("\n".join(lines) + "\n")
        units.append((s, e - s, sym))

    # ---- data sections, macros, linker script, ninja
    os.makedirs(os.path.join(ROOT, "build"), exist_ok=True)
    open(os.path.join(ROOT, "asm", "macros.inc"), "w").write(
        ".syntax unified\n.arm\n.text\n"
        ".macro glabel name\n    .global \\name\n    .type \\name, %function\n\\name:\n.endm\n"
        ".macro endlabel name\n    .size \\name, . - \\name\n.endm\n")
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

    print(f"{len(units)} units, {len(global_labels)} mid-unit global labels, "
          f"{len(local_labels)} local labels, {len(data_syms)} data symbols, {len(force_raw)} forced raw")


if __name__ == "__main__":
    main()
