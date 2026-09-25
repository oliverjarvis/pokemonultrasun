#!/usr/bin/env python3
"""Split code.bin into relinkable assembly.

Outputs:
  asm/text/<ADDR>.s     one unit per function start from orig/analysis.json
  asm/data/rodata.s, data.s, bss.s
                        the other segments: original bytes (.incbin) with a label
                        at every pointer target and a symbolic `.4byte` at every
                        pointer (code.bin has no relocations, so pointers are
                        recognised heuristically, see pointers.py)
  build/units.tsv       addr, size, symbol for every .text unit
  build/layout.ld       linker script: .text at its base, .rodata/.data page-aligned
                        after it, .bss after .data
  build/config_syms.ld  config/symbols.txt as symbol aliases (so they move with code)
  build/codebin_meta.json  what crslink.py needs to rebuild static.crs

Run tools/configure.py afterwards to (re)generate build.ninja.

Words listed in config/force_raw.txt are emitted as `.inst` (exact bytes,
no relocation); tools/check.py adds entries when the assembler's encoding
differs from the original.
"""
import json
import os
import struct

from analyze import CODE, JT, LIT, Text
from asmemit import MACROS, Region, emit_segment
from cro import Cro
from pointers import looks_like_pointer

ROOT = os.path.join(os.path.dirname(__file__), "..")
ORIG = os.path.join(ROOT, "orig")
CODE_BIN = "orig/exefs/code.bin"


def load_force_raw():
    path = os.path.join(ROOT, "config", "force_raw.txt")
    if not os.path.exists(path):
        return set()
    return {int(l.split()[0], 16) for l in open(path) if l.strip() and not l.startswith("#")}


def load_config_symbols():
    """config/symbols.txt: `name = 0xADDR;` lines."""
    out = []
    for line in open(os.path.join(ROOT, "config", "symbols.txt")):
        line = line.split("#", 1)[0].strip().rstrip(";")
        if "=" in line:
            name, addr = (x.strip() for x in line.split("=", 1))
            out.append((name, int(addr, 0)))
    return out


def init_array(t, starts):
    """Place-relative static-constructor table(s) in .rodata: {word addr: target}."""
    ro = t.blob[t.ro_off : t.ro_off + (t.ro[1] - t.ro[0]) // 4 * 4]
    out, run = {}, []
    for k, v in enumerate(struct.unpack(f"<{len(ro) // 4}I", ro) + (0,)):
        a = t.ro[0] + 4 * k
        tgt = (a + v) & 0xFFFFFFFF
        if k < len(ro) // 4 and tgt in starts:
            run.append((a, tgt))
            continue
        if len(run) >= 16:
            out.update(run)
        run = []
    return out


def main():
    t = Text()
    an = json.load(open(os.path.join(ORIG, "analysis.json")))
    names = {}
    for line in open(os.path.join(ORIG, "symbols.tsv")).read().splitlines()[1:]:
        addr, mode, seg, mangled, dm = line.split("\t")
        names[int(addr, 16)] = mangled
    text_names = {a: n for a, n in names.items() if t.in_text(a)}
    force_raw = load_force_raw()
    config = load_config_symbols()

    kind = bytearray(t.size // 4)
    for s, e in an["code"]:
        kind[(s - t.base) >> 2 : (e - t.base) >> 2] = bytes([CODE]) * ((e - s) >> 2)
    for a in an["literals"]:
        kind[(a - t.base) >> 2] = LIT
    for a in an["jumptabs"]:
        kind[(a - t.base) >> 2] = JT
    starts = {a for a, _ in an["funcs"]}
    thumb = an["thumb"]
    in_thumb = lambda a: any(ts <= a < te for ts, te in thumb)

    segs = {"rodata": t.ro, "data": t.data, "bss": (t.data[1], t.bss_end)}

    def data_kind(v):
        for k, (lo, hi) in segs.items():
            if lo <= v < hi or (v == hi and k != "bss"):
                return k
        return None

    def text_pointer(w):
        """Target of a pointer-sized text reference, or None if it isn't one."""
        tgt = w & ~1
        if w & 1 and in_thumb(tgt):
            return tgt
        if tgt % 4 or in_thumb(tgt):
            return None
        return tgt

    data_targets = set()

    def word_ref(a, w):
        """Pointer-like literal values in .text become symbols."""
        if not looks_like_pointer(w, t):
            return None
        if t.in_text(w):
            tgt = text_pointer(w)
            if tgt is None:
                return None
            return ("text", tgt, " + 1" if w & 1 and not in_thumb(tgt) else "")
        if data_kind(w) is None:
            return None
        data_targets.add(w)
        return ("expr", f"data_{w:08X}")

    # ---- pointers in .rodata / .data (decided before .text so targets get labels)
    code_words = set()
    for s, e in an["code"]:
        code_words.update(range(s, e, 4))
    ctors = init_array(t, starts)
    data_ptrs = {}   # word addr -> ("text", value) | ("data", value)
    text_labels = set()
    for seg in ("rodata", "data"):
        lo, hi = segs[seg]
        for a in range(lo, hi - 3, 4):
            if a in ctors:
                text_labels.add(ctors[a])
                continue
            v = struct.unpack_from("<I", t.blob, a - t.base)[0]
            if not looks_like_pointer(v, t):
                continue
            if t.in_text(v):
                tgt = text_pointer(v)
                if tgt is None or not (tgt in starts or tgt in code_words or in_thumb(tgt)):
                    continue
                data_ptrs[a] = ("text", v)
                text_labels.add(tgt)
            elif data_kind(v):
                data_ptrs[a] = ("data", v)
                data_targets.add(v)

    # static.crs: exports and the words modules patch in code.bin need stable labels
    crs = Cro(open(os.path.join(ORIG, "rom", "romfs", "static.crs"), "rb").read(), "static.crs")
    crs_base = [s[0] for s in crs.segments]
    patches = [crs_base[tag & 0xF] + (tag >> 4) for tag, *_ in crs.import_relocs()]
    for a in patches:
        (text_labels if t.in_text(a) else data_targets).add(a)
    for name, a in config:
        (text_labels if t.in_text(a) else data_targets).add(a)

    region = Region(t.words, t.base, t.blob[: t.size], kind, sorted(starts), text_names, force_raw, word_ref,
                    labels=text_labels, thumb=thumb)
    units = region.emit(os.path.join(ROOT, "asm", "text"))

    def text_expr(v):
        tgt = text_pointer(v)
        return region.global_name(tgt) + (" + 1" if v & 1 and not in_thumb(tgt) else "")

    def sym_at(a):
        """Global symbol for any address (text or data)."""
        return region.global_name(a) if t.in_text(a) else f"data_{a:08X}"

    # ---- data segments
    labels = {k: {} for k in segs}
    for v in data_targets:
        k = data_kind(v)
        if k:
            labels[k].setdefault(v - segs[k][0], []).append(f"data_{v:08X}")
    for a, n in names.items():  # named data exports
        k = data_kind(a)
        if k and not t.in_text(a):
            labels[k].setdefault(a - segs[k][0], []).append(n)
    os.makedirs(os.path.join(ROOT, "asm", "data"), exist_ok=True)
    for k, (lo, hi) in segs.items():
        words = {}
        if k != "bss":
            for a, (pk, v) in data_ptrs.items():
                if lo <= a < hi:
                    words[a - lo] = text_expr(v) if pk == "text" else f"data_{v:08X}"
            for a, tgt in ctors.items():
                if lo <= a < hi:
                    words[a - lo] = f"{region.global_name(tgt)} - ."
        for o in labels[k]:
            labels[k][o] = sorted(set(labels[k][o]))
        emit_segment(os.path.join(ROOT, "asm", "data", f"{k}.s"), k, CODE_BIN, lo - t.base, hi - lo,
                     labels[k], words)

    os.makedirs(os.path.join(ROOT, "build"), exist_ok=True)
    open(os.path.join(ROOT, "asm", "macros.inc"), "w").write(MACROS)
    with open(os.path.join(ROOT, "build", "units.tsv"), "w") as f:
        f.write("addr\tsize\tsymbol\n")
        for s, size, sym in units:
            f.write(f"{s:08X}\t{size}\t{sym}\n")
    layout = ["SECTIONS", "{",
              f"    .text {t.base:#x} : {{ *(SORT_BY_NAME(.text.*)) }}",
              "    .rodata ALIGN(0x1000) : { build/data/rodata.o(.rodata) }",
              "    .data ALIGN(0x1000) : { build/data/data.o(.data) }",
              "    .bss (NOLOAD) : { build/data/bss.o(.bss) }",
              "    /DISCARD/ : { *(.ARM.attributes) *(.comment) *(.ARM.exidx*) *(.arm_vfe_header) *(.debug*) }",
              "}"]
    open(os.path.join(ROOT, "build", "layout.ld"), "w").write("\n".join(layout) + "\n")
    with open(os.path.join(ROOT, "build", "config_syms.ld"), "w") as f:
        f.write("/* config/symbols.txt, as aliases of labels that move with the code */\n")
        for name, a in config:
            f.write(f'"{name}" = {sym_at(a)};\n')
    exports = []
    for name, tag in crs.named_exports():
        a = crs_base[tag & 0xF] + (tag >> 4)
        if t.in_text(a):
            a &= ~1  # Thumb entry points carry bit 0; their labels do too
        exports.append([name, name if a in names and names[a] == name else sym_at(a)])
    meta = {"exports": exports, "patches": [sym_at(a) for a in patches]}
    with open(os.path.join(ROOT, "build", "codebin_meta.json"), "w") as f:
        json.dump(meta, f)

    print(f"{len(units)} units; merged {getattr(region, 'merged', 0)} shared-pool starts, "
          f"{len(region.thumb_labels)} Thumb labels; data pointers {len(data_ptrs)}, constructors {len(ctors)}, "
          f"data labels {sum(len(v) for v in labels.values())}; {len(force_raw)} forced raw")


if __name__ == "__main__":
    main()
