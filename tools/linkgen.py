#!/usr/bin/env python3
"""Prepare compiled C++ for linking and write build/link.ld + build/objs.rsp.

  linkgen.py build/src/a.o build/src/b.o ...

Every function armcc emits (one `i.<symbol>` section each, via
--split_sections) replaces the asm unit with the same symbol. The section is
renamed to `.text.<ADDR>` in a copy of the object (build/src/.../a.lnk.o) so
the linker script's single `SORT_BY_NAME(.text.*)` places it at the unit's
address. The section must be exactly the unit's size; anything else is an
error, as is a compiled function with no unit or a stray allocated section.
"""
import os
import subprocess
import sys

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile

ROOT = os.path.join(os.path.dirname(__file__), "..")
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
    objs = sys.argv[1:]
    units = {}
    for line in open(os.path.join(ROOT, "build", "units.tsv")).read().splitlines()[1:]:
        addr, size, sym = line.split("\t")
        units[sym] = (int(addr, 16), int(size))
    funcs, errors = compiled_functions(objs)

    renames = {obj: [] for obj in objs}
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

    for obj, args in renames.items():
        subprocess.run(["arm-none-eabi-objcopy", *args, obj, lnk_path(obj)], check=True)

    base = min(a for a, _ in units.values())
    parts = [f"ENTRY(__code_start)\n__code_start = {base:#x};\n"]
    parts += [open(os.path.join(ROOT, "build", n)).read() for n in ("layout.ld", "asm_syms.ld")]
    parts.append("/* config/symbols.txt */\n" + open(os.path.join(ROOT, "config", "symbols.txt")).read())
    open(os.path.join(ROOT, "build", "link.ld"), "w").write("\n".join(parts))

    replaced = {units[s][0] for s in funcs}
    rsp = [f"build/text/{a:08X}.o" for a, _ in sorted(units.values()) if a not in replaced]
    rsp += [lnk_path(o) for o in objs] + ["build/data.o"]
    open(os.path.join(ROOT, "build", "objs.rsp"), "w").write(" ".join(rsp) + "\n")
    print(f"linkgen: {len(funcs)} functions from C++, {len(units) - len(funcs)} from asm")


if __name__ == "__main__":
    main()
