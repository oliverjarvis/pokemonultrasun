#!/usr/bin/env python3
"""Write a CRO module from a linked ELF (the module linker).

  crolink.py ORIG.cro MODULE.elf META.json OUT.cro

Anonymous imports (raw offsets into another module) are re-resolved from the
target module's linked ELF via build/cro/<Target>/incoming.json, so they stay
correct when the target module changes size.

The ELF comes from linking the module's asm/C++ with its layout.ld (each
segment at its own base, see cro_split.SEG_BASE) and `ld.lld --emit-relocs`.
Every absolute relocation becomes a CRO relocation and its word is zeroed:
references to an import symbol become import relocations (chained per
import), everything else becomes an internal relocation whose target segment
and offset are decoded from the linked value. Segments are laid out like the
original (text at 0x180, rodata and the tables 0x1000-aligned, data after the
tables, 0xCC padding to 0x1000), tables are regenerated, and the four segment
hashes are recomputed.

Entry order follows the original module (META.json records a stable key per
relocation: unit symbol + offset, or segment + offset), with new entries
appended, so an unchanged module is reproduced byte-for-byte. Strings, the
export trie and other non-derivable parts come from ORIG.
"""
import bisect
import json
import struct
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from cro import TABLES, Cro, u32
from cro_split import ROMFS, SEG_BASE, SEGMENT_NAMES, segments_by_kind

TARGETS = "build/cro"


def elf_symbols(path):
    with open(path, "rb") as fh:
        return {s.name: s["st_value"] for s in ELFFile(fh).get_section_by_name(".symtab").iter_symbols() if s.name}


_targets = {}


def target_tag(module, tag):
    """New segment tag for an anonymous import of `tag` in `module`."""
    if module not in _targets:
        import os
        incoming = json.load(open(os.path.join(TARGETS, module, "incoming.json")))
        syms = elf_symbols(os.path.join(TARGETS, module, "module.elf"))
        seg_index = {k: v[0] for k, v in segments_by_kind(
            Cro(open(os.path.join(ROMFS, module + ".cro"), "rb").read(), module)).items()}
        _targets[module] = (incoming, syms, seg_index)
    incoming, syms, seg_index = _targets[module]
    sym = incoming.get(f"{tag:#x}")
    if sym is None or sym not in syms:
        sys.exit(f"anonymous import {module}:{tag:#x}: no symbol in the target module")
    v = syms[sym]
    kind = KIND_OF_BASE[v >> 28]
    if kind == "text":
        v &= ~1
    return ((v - SEG_BASE[kind]) << 4) | seg_index[kind]

ABS_TYPES = {2, 38}  # R_ARM_ABS32, R_ARM_TARGET1
KIND_OF_BASE = {v >> 28: k for k, v in SEG_BASE.items()}


def align(v, a):
    return (v + a - 1) // a * a


def load_elf(path):
    """Segment bytes/sizes, unit symbols in .text, and absolute relocations."""
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        segs = {}
        for kind in SEGMENT_NAMES:
            s = elf.get_section_by_name("." + kind)
            if s is None:
                segs[kind] = (b"", 0)
            elif kind == "bss":
                segs[kind] = (b"", s["sh_size"])
            else:
                segs[kind] = (bytearray(s.data()), s["sh_size"])
            if s is not None and s["sh_size"] and s["sh_addr"] != SEG_BASE[kind]:
                sys.exit(f"{path}: .{kind} at {s['sh_addr']:#x}, expected {SEG_BASE[kind]:#x}")
        symtab = elf.get_section_by_name(".symtab")
        units = sorted((sym["st_value"] & ~1, sym.name) for sym in symtab.iter_symbols()
                       if sym["st_info"]["type"] == "STT_FUNC" and sym["st_size"]
                       and SEG_BASE["text"] <= sym["st_value"] < SEG_BASE["rodata"])
        relocs = []
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            target = elf.get_section(sec["sh_info"]).name.lstrip(".")
            if target not in ("text", "rodata", "data"):
                continue
            syms = elf.get_section(sec["sh_link"])
            for r in sec.iter_relocations():
                if r["r_info_type"] not in ABS_TYPES:
                    continue
                sym = syms.get_symbol(r["r_info_sym"])
                relocs.append((target, r["r_offset"] - SEG_BASE[target], sym.name, sym["st_value"]))
    return segs, units, relocs


def main():
    orig_path, elf_path, meta_path, out_path = sys.argv[1:5]
    orig = Cro(open(orig_path, "rb").read(), orig_path)
    meta = json.load(open(meta_path))
    segs, units, relocs = load_elf(elf_path)
    with open(elf_path, "rb") as fh:
        ds = ELFFile(fh).get_section_by_name(".data")
        data_align = ds["sh_addralign"] if ds is not None else 4
    unit_addrs = [a for a, _ in units]

    def key(kind, off):
        if kind != "text":
            return (kind, off)
        a = SEG_BASE["text"] + off
        i = bisect.bisect_right(unit_addrs, a) - 1
        if i < 0:
            sys.exit(f"text+{off:#x} is before the first unit")
        return ("text", units[i][1], a - unit_addrs[i])

    # segment indices as in the original segment table
    seg_index = {}
    for i, (_, size, kind) in sorted(enumerate(orig.segments), key=lambda e: e[1][1] == 0):
        seg_index.setdefault(SEGMENT_NAMES[kind], i)

    imports = meta["imports"]
    import_syms = {imp["sym"] for imp in imports}
    internal, by_import = [], {}
    for kind, off, sym, symval in relocs:
        data = segs[kind][0]
        value = struct.unpack_from("<I", data, off)[0]
        struct.pack_into("<I", data, off, 0)
        if sym in import_syms:
            by_import.setdefault(sym, []).append((key(kind, off), kind, off, value - symval))
            continue
        tkind = KIND_OF_BASE.get(value >> 28)
        if tkind is None:
            sys.exit(f"{kind}+{off:#x}: relocation to {sym!r} = {value:#x} is outside every segment")
        internal.append((key(kind, off), kind, off, tkind, value - SEG_BASE[tkind]))

    order = {tuple(k): i for i, k in enumerate(meta["internal_order"])}
    internal.sort(key=lambda e: (order.get(e[0], len(order)), SEGMENT_NAMES.index(e[1]), e[2]))
    chain_order = {sym: i for i, (sym, _) in enumerate(meta["chains"])}
    entry_order = {sym: {tuple(k): i for i, k in enumerate(keys)} for sym, keys in meta["chains"]}
    missing = [imp["sym"] for imp in imports if imp["sym"] not in by_import]
    if missing:
        sys.exit(f"imports no longer referenced (not supported yet): {missing[:5]}")
    chains = []
    for sym in sorted(by_import, key=lambda s: chain_order.get(s, len(chain_order))):
        eo = entry_order.get(sym, {})
        chains.append((sym, sorted(by_import[sym], key=lambda e: (eo.get(e[0], len(eo)), e[1], e[2]))))

    def tag(kind, off):
        return (off << 4) | seg_index[kind]

    # ---- layout
    text, text_size = segs["text"]
    ro, ro_size = segs["rodata"]
    data, data_size = segs["data"]
    _, bss_size = segs["bss"]
    code_off = 0x180
    pos = code_off + text_size
    ro_off = align(pos, 0x1000) if ro_size else None
    name_off = align((ro_off + ro_size) if ro_size else pos, 0x1000)

    o = orig.tables
    exp_strings = orig.data[o["export_strings"][0] : o["export_strings"][0] + o["export_strings"][1]]
    imp_strings = orig.data[o["import_strings"][0] : o["import_strings"][0] + o["import_strings"][1]]
    trie = orig.data[o["export_trie"][0] : o["export_trie"][0] + 8 * o["export_trie"][1]]
    name_size = orig.hdr["module_name_size"]

    t = {}
    p = name_off + name_size
    p = align(p, 4)
    t["segments"] = p; p += 12 * len(orig.segments)
    t["named_exports"] = p; p += 8 * len(meta["exports"])
    t["export_trie"] = p; p += len(trie)
    t["indexed_exports"] = p
    t["export_strings"] = p; p += len(exp_strings)
    if meta["imports"] or meta["import_modules"]:  # import tables are only aligned when there are any
        p = align(p, 4)
    t["import_modules"] = p; p += 20 * len(meta["import_modules"])
    n_import_relocs = sum(len(c) for _, c in chains)
    t["import_relocs"] = p; p += 12 * n_import_relocs
    named = [imp for imp in imports if imp["kind"] == "named"]
    anon = [imp for imp in imports if imp["kind"] == "anon"]
    t["named_imports"] = p; p += 8 * len(named)
    t["indexed_imports"] = p
    t["anon_imports"] = p; p += 8 * len(anon)
    p = align(p, 4)  # the strings pool is aligned even when the tables before it are empty
    t["import_strings"] = p; p += len(imp_strings)
    p = align(p, 4)
    t["static_anon_params"] = p
    t["internal_relocs"] = p; p += 12 * len(internal)
    t["static_relocs"] = t["internal_relocs"]
    data_off = align(p, max(meta.get("data_align", 4), data_align))
    end = data_off + data_size
    file_size = align(end, 0x1000)

    out = bytearray(b"\xcc" * file_size)
    out[: code_off] = orig.data[:0x138] + b"\0" * (code_off - 0x138)
    out[code_off : code_off + text_size] = text
    for a in range(code_off + text_size, name_off):
        out[a] = 0
    if ro_size:
        out[ro_off : ro_off + ro_size] = ro
    out[name_off : name_off + name_size] = orig.data[orig.hdr["module_name_off"] : orig.hdr["module_name_off"] + name_size]
    for a in range(name_off + name_size, data_off):
        out[a] = 0

    # segment table
    offs = {"text": code_off, "rodata": ro_off or 0, "data": data_off, "bss": 0}
    sizes = {"text": text_size, "rodata": ro_size, "data": data_size, "bss": bss_size}
    for i, (so, ss, kind) in enumerate(orig.segments):
        k = SEGMENT_NAMES[kind]
        if seg_index.get(k) == i:
            so, ss = offs[k], sizes[k]
            if k == "rodata" and not ro_size:
                so = orig.segments[i][0] and name_off
        struct.pack_into("<III", out, t["segments"] + 12 * i, so, ss, kind)

    # symbol values -> tags (exports, hooks)
    sym_value = {}
    with open(elf_path, "rb") as fh:
        for sym in ELFFile(fh).get_section_by_name(".symtab").iter_symbols():
            if sym.name:
                sym_value[sym.name] = sym["st_value"]

    def sym_tag(sym):
        v = sym_value[sym]
        kind = KIND_OF_BASE[v >> 28]
        if kind == "text":
            v &= ~1  # Thumb bit
        return tag(kind, v - SEG_BASE[kind])

    es = o["export_strings"][0]
    for i, (name, sym) in enumerate(meta["exports"]):
        orig_name_off = u32(orig.table("named_exports")[i], 0)
        struct.pack_into("<II", out, t["named_exports"] + 8 * i, t["export_strings"] + orig_name_off - es, sym_tag(sym))
    out[t["export_trie"] : t["export_trie"] + len(trie)] = trie
    out[t["export_strings"] : t["export_strings"] + len(exp_strings)] = exp_strings

    # imports
    head = {}
    k = 0
    for sym, entries in chains:
        head[sym] = t["import_relocs"] + 12 * k
        for j, (_, kind, off, addend) in enumerate(entries):
            struct.pack_into("<IBBBBi", out, t["import_relocs"] + 12 * k, tag(kind, off), 2,
                             1 if j == len(entries) - 1 else 0, 0, 0, addend)
            k += 1
    istr = o["import_strings"][0]
    for i, imp in enumerate(named):
        orig_name_off = u32(orig.table("named_imports")[i], 0)
        struct.pack_into("<II", out, t["named_imports"] + 8 * i, t["import_strings"] + orig_name_off - istr, head[imp["sym"]])
    for i, imp in enumerate(anon):
        struct.pack_into("<II", out, t["anon_imports"] + 8 * i, target_tag(imp["module"], imp["tag"]),
                         head[imp["sym"]])
    for i, (e, m) in enumerate(zip(orig.table("import_modules"), meta["import_modules"])):
        name_ptr, ihead, inum, ahead, anum = struct.unpack("<5I", e)
        struct.pack_into("<5I", out, t["import_modules"] + 20 * i, t["import_strings"] + name_ptr - istr,
                         t["indexed_imports"], inum, t["anon_imports"] + 8 * m["anon_first"], anum)
    out[t["import_strings"] : t["import_strings"] + len(imp_strings)] = imp_strings

    for i, (_, kind, off, tkind, toff) in enumerate(internal):
        struct.pack_into("<IBBBBi", out, t["internal_relocs"] + 12 * i, tag(kind, off), 2, seg_index[tkind], 0, 0, toff)
    if data_size:
        out[data_off:end] = data

    # header
    h = {"name_off": name_off, "file_size": file_size, "bss_size": bss_size + meta["header_bss_extra"],
         "code_off": code_off, "code_size": name_off - code_off, "data_off": data_off, "data_size": data_size,
         "module_name_off": name_off, "module_name_size": name_size}
    from cro import HDR
    for field, value in h.items():
        struct.pack_into("<I", out, HDR[field], value)
    for field, sym in meta["hooks"].items():
        struct.pack_into("<I", out, HDR[field], 0xFFFFFFFF if sym is None else sym_tag(sym))
    counts = {"segments": len(orig.segments), "named_exports": len(meta["exports"]), "indexed_exports": 0,
              "export_strings": len(exp_strings), "export_trie": len(trie) // 8,
              "import_modules": len(meta["import_modules"]), "import_relocs": n_import_relocs,
              "named_imports": len(named), "indexed_imports": 0, "anon_imports": len(anon),
              "import_strings": len(imp_strings), "static_anon_params": 0, "internal_relocs": len(internal),
              "static_relocs": 0}
    for name, (field, _) in TABLES.items():
        struct.pack_into("<II", out, field, t[name], counts[name])

    with open(out_path, "wb") as f:
        f.write(Cro(bytes(out), out_path).rehash())


if __name__ == "__main__":
    main()
