#!/usr/bin/env python3
"""Analyze and split every CRO module into relinkable assembly.

  cro_split.py [MODULE ...]

For each orig/rom/romfs/<Module>.cro:
  asm/cro/<Module>/<OFF>.s       one .text unit per function (named by file offset)
  asm/cro/<Module>/rodata.s, data.s, bss.s
                                 the other segments: original bytes (.incbin) with a
                                 label at every relocation target and a symbolic
                                 `.4byte` at every relocated word
  build/cro/<Module>/units.tsv   addr, size, symbol of the .text units
  build/cro/<Module>/layout.ld   linker script: each segment at its own base (SEG_BASE)
  build/cro/<Module>/symbols.ld  link addresses for imports (veneer, or a unique fake)
  build/cro/<Module>/meta.json   what crolink.py needs to write the module back
  build/cro/<Module>/incoming.json  original segment tag -> symbol, for every place
                                 another module (or static.crs) imports anonymously

config/cro/<Module>.txt names functions and data: `<symbol> <segment> <offset>`.

All CRO relocations are R_ARM_ABS32; relocated words are zero in the file and
the tables say exactly what they point at, so every pointer is emitted as a
symbol and the module can be relinked after code changes size. Function seeds:
names, exports, load hooks, import veneers (`ldr pc, [pc, #-4]` + import word,
named veneer_<import>), relocation targets in .text, call targets, prologues.
Named imports keep their (mangled) name; anonymous imports, which point into
another module, are named <Module>__<unit or label>.
"""
import json
import os
import struct
import sys

from analyze import Tracer
from asmemit import MACROS, Region
from cro import Cro, cstr

ROOT = os.path.join(os.path.dirname(__file__), "..")
ROMFS = os.path.join(ROOT, "orig", "rom", "romfs")
VENEER = 0xE51FF004  # ldr pc, [pc, #-4]
SEGMENT_NAMES = ("text", "rodata", "data", "bss")
SEG_BASE = {"text": 0x10000000, "rodata": 0x20000000, "data": 0x30000000, "bss": 0x40000000}
IMPORT_BASE, IMPORT_STRIDE = 0xE0000000, 0x10000  # fake link addresses for imports
TEXT_END = "__cro_text_end"  # relocations may point at the end of .text


def load_config(module):
    """config/cro/<Module>.txt: `<symbol> <segment> <offset>` per line."""
    path = os.path.join(ROOT, "config", "cro", module + ".txt")
    out = []
    if os.path.exists(path):
        for line in open(path):
            line = line.split("#", 1)[0].split()
            if not line:
                continue
            if len(line) != 3 or line[1] not in SEGMENT_NAMES:
                sys.exit(f"{path}: expected `<symbol> <segment> <offset>`, got {' '.join(line)}")
            out.append((line[0], line[1], int(line[2], 16)))
    return out


def segments_by_kind(c):
    """kind name -> (segment index, file offset, size), preferring non-empty entries."""
    out = {}
    for i, (off, size, kind) in sorted(enumerate(c.segments), key=lambda e: e[1][1] == 0):
        out.setdefault(SEGMENT_NAMES[kind], (i, off, size))
    return out


_module_cache = {}


def module_header(name):
    if name not in _module_cache:
        path = os.path.join(ROMFS, name + (".crs" if name == "static" else ".cro"))
        _module_cache[name] = Cro(open(path, "rb").read(), name)
    return _module_cache[name]


def anon_import_symbol(target, tag, static_syms):
    """Symbol for an anonymous import of segment tag `tag` in module `target`."""
    t = module_header(target)
    off, _, kind = t.segments[tag & 0xF]
    kind = SEGMENT_NAMES[kind]
    if target == "static":
        addr = off + (tag >> 4)
        return static_syms.get(addr, f"{kind}_{addr:08X}" if kind != "text" else f"sub_{addr:08X}")
    if kind == "text":
        return f"{target}__sub_{off + (tag >> 4):08X}"
    return f"{target}__{kind}_{tag >> 4:08X}"


def read_imports(c, static_syms):
    """Imports in table order, relocated words, and the import-reloc chain order."""
    relocs = c.import_relocs()
    ro, _ = c.tables["import_relocs"]
    ao, _ = c.tables["anon_imports"]
    imports = []  # dicts, in table order: named..., anon...
    heads = {}
    for e in c.table("named_imports"):
        name_off, head = struct.unpack("<II", e)
        name = cstr(c.data, name_off)
        imports.append({"kind": "named", "sym": name})
        heads[(head - ro) // 12] = name
    modules = []
    for e in c.table("import_modules"):
        name_off, ihead, inum, ahead, anum = struct.unpack("<5I", e)
        if inum:
            sys.exit(f"{c.name}: indexed imports are not supported")
        target = cstr(c.data, name_off)
        first = (ahead - ao) // 8 if anum else len(c.table("anon_imports"))
        modules.append({"name": target, "anon_first": first, "anon_count": anum})
    anon = c.table("anon_imports")
    for m in modules:
        for k in range(m["anon_first"], m["anon_first"] + m["anon_count"]):
            tag, head = struct.unpack("<II", anon[k])
            sym = anon_import_symbol(m["name"], tag, static_syms)
            imports.append({"kind": "anon", "sym": sym, "module": m["name"], "tag": tag})
            heads[(head - ro) // 12] = sym
    if len({i["sym"] for i in imports}) != len(imports):
        sys.exit(f"{c.name}: duplicate import symbol names")
    words = {}   # file offset -> (import symbol, addend)
    chains = []  # [symbol, [word file offsets]] in import-reloc table order
    k = 0
    while k < len(relocs):
        sym = heads.get(k)
        if sym is None:
            sys.exit(f"{c.name}: import relocation {k} is not the head of any import chain")
        chain = []
        while True:
            tag, rtype, last, addend = relocs[k]
            if rtype != 2:
                sys.exit(f"{c.name}: import relocation type {rtype} not supported")
            words[c.seg_addr(tag)] = (sym, addend)
            chain.append(c.seg_addr(tag))
            k += 1
            if last:
                break
        chains.append([sym, chain])
    return imports, modules, words, chains


def incoming_references():
    """Module name -> set of segment tags that other modules (and static.crs)
    import anonymously, i.e. by raw offset. These need stable labels."""
    out = {}
    files = [f for f in os.listdir(ROMFS) if f.endswith(".cro")] + ["static.crs"]
    for f in files:
        c = Cro(open(os.path.join(ROMFS, f), "rb").read(), f)
        ao, _ = c.tables["anon_imports"]
        anon = c.table("anon_imports")
        for e in c.table("import_modules"):
            name_off, ihead, inum, ahead, anum = struct.unpack("<5I", e)
            target = cstr(c.data, name_off)
            first = (ahead - ao) // 8
            for k in range(first, first + anum):
                out.setdefault(target, set()).add(struct.unpack("<II", anon[k])[0])
    return out


def data_alignment(c):
    io, n = c.tables["internal_relocs"]
    if c.hdr["data_off"] == io + 12 * n:
        return 4
    a = 4
    while a < 16 and c.hdr["data_off"] % (a * 2) == 0:
        a *= 2
    return a


def expr(sym, addend):
    return sym + (f" + {addend}" if addend > 0 else f" - {-addend}" if addend < 0 else "")


def emit_segment(path, kind, module_file, file_off, size, labels, words):
    """Assembly for a non-text segment: original bytes, labels, symbolic words.

    labels: offset -> [names]; words: offset -> assembler expression."""
    lines = [".include \"macros.inc\"", f".section .{kind}, \"{'aw' if kind != 'rodata' else 'a'}\"" +
             (", %nobits" if kind == "bss" else ""), ""]
    cuts = sorted({0, size} | set(labels) | set(words) | {o + 4 for o in words})
    for a, b in zip(cuts, cuts[1:] + [None]):
        for name in labels.get(a, []):
            lines.append(f"dlabel {name}")
        if b is None:
            break
        if a in words:
            lines.append(f"    .4byte {words[a]} /* {a:08X} */")
        elif kind == "bss":
            lines.append(f"    .space {b - a:#x}")
        else:
            lines.append(f"    .incbin \"{module_file}\", {file_off + a:#x}, {b - a:#x}")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def split_module(path, static_syms, incoming=()):
    name = os.path.splitext(os.path.basename(path))[0]
    c = Cro(open(path, "rb").read(), name)
    segs = segments_by_kind(c)
    seg_kind = {i: SEGMENT_NAMES[kind] for i, (_, _, kind) in enumerate(c.segments)}
    t_idx, toff, tsize = segs["text"]
    if not tsize:
        return name, 0, None
    words = struct.unpack_from(f"<{tsize // 4}I", c.data, toff)

    imports, import_modules, import_words, chains = read_imports(c, static_syms)
    internal = []  # (source kind, source seg offset, target kind, target seg offset) in table order
    for tag, rtype, seg, addend in c.internal_relocs():
        if rtype != 2:
            sys.exit(f"{name}: internal relocation type {rtype} not supported")
        internal.append((seg_kind[tag & 0xF], tag >> 4, seg_kind[seg], addend))
    text_internal = {toff + so: (tk, to) for sk, so, tk, to in internal if sk == "text"}
    relocated = set(import_words) | set(text_internal)

    tr = Tracer(words, toff, literals=relocated)
    names = {}

    def add(addr, sym):
        if tr.in_text(addr) and addr % 4 == 0:
            tr.seed(addr, sym)
            if sym and addr not in names:
                names[addr] = sym

    config = load_config(name)
    for sym, seg, off in config:
        if seg == "text":
            add(toff + off, sym)
    used = set()
    for a in range(toff, toff + tsize - 4, 4):
        if tr.w(a) == VENEER and a + 4 in import_words:
            sym = "veneer_" + import_words[a + 4][0]
            while sym in used:
                sym += "_"
            used.add(sym)
            add(a, sym)
    for sym, tag in c.named_exports():
        if seg_kind[tag & 0xF] == "text":
            add(c.seg_addr(tag), sym)
    hooks = ("control_object", "on_load", "on_exit", "on_unresolved")
    for field in hooks:
        tag = c.hdr[field]
        if tag != 0xFFFFFFFF and seg_kind[tag & 0xF] == "text":
            add(c.seg_addr(tag), None)
    tr.drain()
    tr.pointer_seeds(toff + to for sk, so, tk, to in internal if tk == "text")
    incoming_text = {c.seg_addr(tag) for tag in incoming if seg_kind[tag & 0xF] == "text"}
    tr.pointer_seeds(sorted(incoming_text))
    tr.prologue_seeds()

    # every .text target referenced from a relocation needs a global label
    text_targets = set()
    for sk, so, tk, to in internal:
        if tk == "text":
            if to > tsize:
                sys.exit(f"{name}: relocation target text+{to:#x} is outside .text")
            if to < tsize:
                text_targets.add(toff + (to & ~3))
    for a in incoming_text:
        if a % 4:
            sys.exit(f"{name}: another module imports unaligned text address {a:#x}")
        text_targets.add(a)

    def word_ref(a, w):
        if a in import_words:
            sym, addend = import_words[a]
            return ("expr", expr(sym, addend))
        if a in text_internal:
            tk, to = text_internal[a]
            if tk == "text" and to == tsize:
                return ("expr", TEXT_END)
            if tk == "text":
                return ("text", toff + (to & ~3), f" + {to & 3}" if to & 3 else "")
            return ("expr", f"{tk}_{to:08X}")
        return None

    region = Region(words, toff, c.data[toff : toff + tsize], tr.kind, list(tr.funcs), names, (), word_ref,
                    labels=text_targets)
    units = region.emit(os.path.join(ROOT, "asm", "cro", name))
    starts = set(region.starts)

    def text_sym(addr):
        return region.unit_sym(addr) if addr in starts else f"loc_{addr:08X}"

    def target_expr(tk, to):
        if tk == "text" and to == tsize:
            return TEXT_END
        if tk == "text":
            base = toff + (to & ~3)
            return text_sym(base) + (f" + {to & 3}" if to & 3 else "")
        return f"{tk}_{to:08X}"

    # other segments: labels at relocation targets, exports, hooks and config names
    labels = {k: {} for k in ("rodata", "data", "bss")}
    for sk, so, tk, to in internal:
        if tk in labels:
            labels[tk].setdefault(to, []).append(f"{tk}_{to:08X}")
    sym_of_tag = {}

    def tag_symbol(tag):
        kind, off = seg_kind[tag & 0xF], tag >> 4
        if kind == "text":
            return text_sym(toff + off)
        labels[kind].setdefault(off, []).append(f"{kind}_{off:08X}")
        return f"{kind}_{off:08X}"

    for sym, seg, off in config:
        if seg != "text":
            labels[seg].setdefault(off, []).append(sym)
    incoming_syms = {f"{tag:#x}": tag_symbol(tag) for tag in sorted(incoming)}
    exports = [[sym, tag_symbol(tag)] for sym, tag in c.named_exports()]
    hook_syms = {f: (tag_symbol(c.hdr[f]) if c.hdr[f] != 0xFFFFFFFF else None) for f in hooks}
    module_file = os.path.relpath(path, ROOT)
    for kind in ("rodata", "data", "bss"):
        seg = segs.get(kind)
        size = seg[2] if seg else 0
        off = seg[1] if seg else 0
        seg_words = {so: target_expr(tk, to) for sk, so, tk, to in internal if sk == kind}
        seg_words.update({a - off: expr(*import_words[a]) for a in import_words
                          if kind != "bss" and seg and off <= a < off + size})
        for o, names_ in labels[kind].items():
            labels[kind][o] = sorted(set(names_))
        emit_segment(os.path.join(ROOT, "asm", "cro", name, f"{kind}.s"), kind, module_file, off, size,
                     labels[kind], seg_words)

    # ordering keys so crolink can reproduce the original tables
    unit_starts = sorted(starts)

    def key(kind, off):
        if kind != "text":
            return [kind, off]
        import bisect
        a = toff + off
        s = unit_starts[bisect.bisect_right(unit_starts, a) - 1]
        return ["text", region.unit_sym(s), a - s]

    def file_key(a):
        for kind in ("text", "rodata", "data"):
            seg = segs.get(kind)
            if seg and seg[1] <= a < seg[1] + seg[2]:
                return key(kind, a - seg[1])
        sys.exit(f"{name}: relocated word at file offset {a:#x} is in no segment")

    meta = {
        "module": name,
        "internal_order": [key(sk, so) for sk, so, tk, to in internal],
        "chains": [[sym, [file_key(a) for a in chain]] for sym, chain in chains],
        "imports": imports,
        "import_modules": import_modules,
        "exports": exports,
        "hooks": hook_syms,
        "header_bss_extra": c.hdr["bss_size"] - (segs["bss"][2] if "bss" in segs else 0),
        # .data normally follows the relocation tables directly; a gap means it needed more alignment
        "data_align": data_alignment(c),
    }

    bdir = os.path.join(ROOT, "build", "cro", name)
    os.makedirs(bdir, exist_ok=True)
    with open(os.path.join(bdir, "meta.json"), "w") as f:
        json.dump(meta, f)
    with open(os.path.join(bdir, "incoming.json"), "w") as f:
        json.dump(incoming_syms, f)
    with open(os.path.join(bdir, "units.tsv"), "w") as f:
        f.write("addr\tsize\tsymbol\n")
        for s, size, sym in units:
            f.write(f"{s:08X}\t{size}\t{sym}\n")
    veneers = {}
    for addr, sym in names.items():
        if sym.startswith("veneer_") and addr + 4 in import_words:
            veneers.setdefault(import_words[addr + 4][0], sym)
    ld = ["/* generated by cro_split.py: link addresses for imports */"]
    for k, imp in enumerate(imports):
        target = veneers.get(imp["sym"], f"{IMPORT_BASE + k * IMPORT_STRIDE:#x}")
        ld.append(f'PROVIDE("{imp["sym"]}" = {target});')
    with open(os.path.join(bdir, "symbols.ld"), "w") as f:
        f.write("\n".join(ld) + "\n")
    with open(os.path.join(bdir, "layout.ld"), "w") as f:
        f.write("SECTIONS\n{\n"
                f"    .text {SEG_BASE['text']:#x} : {{ *(SORT_BY_NAME(.text.*)) {TEXT_END} = .; }}\n"
                f"    .rodata {SEG_BASE['rodata']:#x} : {{ *(.rodata) }}\n"
                f"    .data {SEG_BASE['data']:#x} : {{ *(.data) }}\n"
                f"    .bss {SEG_BASE['bss']:#x} (NOLOAD) : {{ *(.bss) }}\n"
                "    /DISCARD/ : { *(.ARM.attributes) *(.comment) *(.ARM.exidx*) *(.arm_vfe_header) *(.debug*) }\n}\n")
    return name, len(units), tr


def main():
    names = {}
    for line in open(os.path.join(ROOT, "orig", "symbols.tsv")).read().splitlines()[1:]:
        addr, mode, seg, mangled, dm = line.split("\t")
        names[int(addr, 16)] = mangled
    os.makedirs(os.path.join(ROOT, "asm", "cro"), exist_ok=True)
    with open(os.path.join(ROOT, "asm", "macros.inc"), "w") as f:
        f.write(MACROS)
    wanted = set(sys.argv[1:])
    incoming = incoming_references()
    total_units = code = lit = unk = words = 0
    paths = sorted(p for p in os.listdir(ROMFS) if p.endswith(".cro"))
    done = 0
    for p in paths:
        if wanted and os.path.splitext(p)[0] not in wanted:
            continue
        _, nunits, tr = split_module(os.path.join(ROMFS, p), names, incoming.get(os.path.splitext(p)[0], set()))
        done += 1
        total_units += nunits
        if tr:
            n = len(tr.words)
            words += n
            code += tr.kind.count(1)
            lit += tr.kind.count(2) + tr.kind.count(3)
            unk += tr.kind.count(0)
    print(f"{done} modules, {total_units} units; text words {words}: "
          f"code {code / words:.1%}, literal/jump table {lit / words:.1%}, unknown {unk / words:.1%}")


if __name__ == "__main__":
    main()
