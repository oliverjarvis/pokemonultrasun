#!/usr/bin/env python3
"""Place compiled C++ over asm units and write a linker script + response file.

  linkgen.py --units UNITS.tsv --objdir DIR --layout LAYOUT.ld [--ld FILE ...]
             --out LINK.ld --rsp OBJS.rsp [--extra OBJ ...] [C++ OBJS ...]

Used for code.bin and for each CRO module. Every function armcc emits (one
`i.<symbol>` section each, via --split_sections) replaces the asm unit with
the same symbol. The section is renamed to `.text.<ADDR>` in a copy of the
object (<obj>.lnk.o) so the layout's single `SORT_BY_NAME(.text.*)` places it
at the unit's address. The section must be exactly the unit's size; anything
else is an error, as is a compiled function with no unit or a stray allocated
section. --ld files (symbol definitions) are appended to the linker script;
--extra objects are appended to the response file.
"""
import argparse
import os
import subprocess
import sys

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile

IGNORED = (".ARM.exidx", ".ARM.attributes", ".arm_vfe_header", ".comment", ".debug", ".rel", ".symtab",
           ".strtab", ".shstrtab")


def lnk_path(obj):
    return os.path.splitext(obj)[0] + ".lnk.o"


def compiled_functions(objs):
    funcs, errors = {}, []
    for obj in objs:
        with open(obj, "rb") as fh:
            elf = ELFFile(fh)
            for s in elf.iter_sections():
                if not s.name or s.name.startswith(IGNORED) or not s["sh_flags"] & SH_FLAGS.SHF_ALLOC:
                    continue
                if s.name.startswith("i.") and s["sh_flags"] & SH_FLAGS.SHF_EXECINSTR:
                    sym = s.name[2:]
                    if sym in funcs:
                        errors.append(f"{sym}: defined in {funcs[sym][0]} and {obj}")
                    funcs[sym] = (obj, s.name, s["sh_size"])
                else:
                    errors.append(f"{obj}: section {s.name} has no placement (data in C++ is not supported yet)")
    return funcs, errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--units", required=True)
    ap.add_argument("--objdir", required=True)
    ap.add_argument("--layout", required=True)
    ap.add_argument("--ld", action="append", default=[])
    ap.add_argument("--out", required=True)
    ap.add_argument("--rsp", required=True)
    ap.add_argument("--extra", action="append", default=[])
    ap.add_argument("objs", nargs="*")
    args = ap.parse_args()

    units = {}
    for line in open(args.units).read().splitlines()[1:]:
        addr, size, sym = line.split("\t")
        units[sym] = (int(addr, 16), int(size))
    funcs, errors = compiled_functions(args.objs)

    renames = {obj: [] for obj in args.objs}
    for sym, (obj, sec, fsize) in funcs.items():
        if sym not in units:
            errors.append(f"{sym}: compiled but no asm unit starts with this symbol")
            continue
        addr, size = units[sym]
        if fsize != size:
            errors.append(f"{sym} @ {addr:08X}: compiled {fsize} bytes, unit is {size}")
        renames[obj].append(f"--rename-section={sec}=.text.{addr:08X}")
    if errors:
        sys.exit("linkgen: " + "\n linkgen: ".join(errors))

    for obj, flags in renames.items():
        subprocess.run(["arm-none-eabi-objcopy", *flags, obj, lnk_path(obj)], check=True)

    base = min(a for a, _ in units.values())
    parts = [f"ENTRY(__code_start)\n__code_start = {base:#x};\n", open(args.layout).read()]
    for path in args.ld:
        parts.append(f"/* {path} */\n" + open(path).read())
    with open(args.out, "w") as f:
        f.write("\n".join(parts))

    replaced = {units[s][0] for s in funcs}
    rsp = [os.path.join(args.objdir, f"{a:08X}.o") for a, _ in sorted(units.values()) if a not in replaced]
    rsp += [lnk_path(o) for o in args.objs] + args.extra
    with open(args.rsp, "w") as f:
        f.write(" ".join(rsp) + "\n")
    if funcs:
        print(f"linkgen: {os.path.dirname(args.out)}: {len(funcs)} functions from C++, "
              f"{len(units) - len(funcs)} from asm")


if __name__ == "__main__":
    main()
