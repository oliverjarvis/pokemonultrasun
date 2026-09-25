#!/usr/bin/env python3
"""Rebuild a CRO module with newly built .text.

  mkcro.py ORIG.cro TEXT.bin OUT.cro [--elf TEXT.elf --imports IMPORTS.tsv]

Replaces the module's .text segment with TEXT.bin (same size; relocation
tables are taken from ORIG) and recomputes the four segment hashes.

With --elf, absolute relocations (R_ARM_ABS32 / R_ARM_TARGET1) that the link
kept (ld.lld --emit-relocs) come from compiled C++. In a CRO those words are
zero and the loader fills them in from the module's tables, so each one is
zeroed and checked against the original tables: internal relocations must
point at the same segment + offset, import relocations at the same import
(its veneer or fake link address, see cro_split.py). A relocation missing
from the tables is an error, since the module would not match.
"""
import argparse
import struct
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from cro import Cro
from cro_split import BSS_BASE

ABS_TYPES = {2, 38}  # R_ARM_ABS32, R_ARM_TARGET1


def cxx_relocations(elf_path):
    """[(address, linked value)] for absolute relocations in the linked .text."""
    out = []
    with open(elf_path, "rb") as fh:
        elf = ELFFile(fh)
        text = elf.get_section_by_name(".text")
        if text is None:
            return out
        base, data = text["sh_addr"], text.data()
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection) or elf.get_section(sec["sh_info"]).name != ".text":
                continue
            for r in sec.iter_relocations():
                if r["r_info_type"] in ABS_TYPES:
                    a = r["r_offset"]
                    out.append((a, struct.unpack_from("<I", data, a - base)[0]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("orig")
    ap.add_argument("text")
    ap.add_argument("out")
    ap.add_argument("--elf")
    ap.add_argument("--imports")
    args = ap.parse_args()

    c = Cro(open(args.orig, "rb").read(), args.orig)
    off, size = c.text()
    text = bytearray(open(args.text, "rb").read())
    if len(text) != size:
        sys.exit(f"{args.text}: {len(text):#x} bytes, module .text is {size:#x}")

    if args.elf:
        seg_base = [BSS_BASE if kind == 3 else o for o, _, kind in c.segments]
        internal = {c.seg_addr(tag): seg_base[seg] + addend for tag, _, seg, addend in c.internal_relocs()}
        imports = {}
        if args.imports:
            for line in open(args.imports).read().splitlines()[1:]:
                word, name, fake, veneer = line.split("\t")
                imports[int(word, 16)] = (name, {int(fake, 16)} | ({int(veneer, 16)} if veneer else set()))
        errors = []
        for addr, value in cxx_relocations(args.elf):
            if addr in internal:
                if value != internal[addr]:
                    errors.append(f"{addr:08X}: C++ points at {value:#x}, module table says {internal[addr]:#x}")
            elif addr in imports:
                name, ok = imports[addr]
                if value not in ok:
                    errors.append(f"{addr:08X}: C++ points at {value:#x}, module imports {name}")
            else:
                errors.append(f"{addr:08X}: C++ has an address here but the module has no relocation")
            struct.pack_into("<I", text, addr - off, 0)
        if errors:
            sys.exit(f"mkcro: {args.orig}:\n  " + "\n  ".join(errors))

    data = c.data[:off] + bytes(text) + c.data[off + size :]
    with open(args.out, "wb") as f:
        f.write(Cro(data, args.out).rehash())


if __name__ == "__main__":
    main()
