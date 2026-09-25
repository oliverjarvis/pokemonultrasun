#!/usr/bin/env python3
"""Generate build.ninja. Re-run after adding or removing files in src/.

Build graph:
  asm/text/*.s   --as-->     build/text/*.o
  src/**/*.cpp   --armcc-->  build/src/**/*.o
  (objects)      --linkgen-> build/link.ld, build/objs.rsp, *.lnk.o  (C++ replaces asm units)
  link.ld        --ld-->     build/code.elf --objcopy--> build/code.bin
  orig/rom/romfs --ctr.py--> build/romfs.bin
  code.bin + romfs.bin + orig/rom parts --mkrom--> build/rom.3ds
"""
import glob
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")
ARMCC_DIR = "tools/armcc/4.1/b1454"

CFLAGS = (f"-c --cpu=MPCore --fpmode=fast --apcs=/interwork -I {ARMCC_DIR}/include -I include "
          "-O3 -Otime --cpp --arm --split_sections")


def main():
    os.chdir(ROOT)
    units = [l.split("\t")[0] for l in open("build/units.tsv").read().splitlines()[1:]]
    sources = sorted(glob.glob("src/**/*.cpp", recursive=True))
    headers = sorted(glob.glob("include/**/*.h", recursive=True))
    esc = lambda path: path.replace("$", "$$").replace(" ", "$ ").replace(":", "$:")
    romfs_files = [esc(f) for f in sorted(glob.glob("orig/rom/romfs/**/*", recursive=True)) if os.path.isfile(f)]
    rom_parts = [esc(f) for f in sorted(glob.glob("orig/rom/**/*", recursive=True))
                 if os.path.isfile(f) and not f.startswith("orig/rom/romfs/")]

    nj = [
        f"ARMCC = tools/wibo/wibo {ARMCC_DIR}/bin/armcc.exe",
        f"CFLAGS = {CFLAGS}",
        "ASFLAGS = -mcpu=mpcore -mfpu=vfpv2 -I asm",
        "PYTHON = .venv/bin/python",
        "",
        "rule as",
        "  command = arm-none-eabi-as $ASFLAGS -o $out $in",
        "  description = AS $in",
        "rule cc",
        "  command = $ARMCC $CFLAGS -o $out $in",
        "  description = ARMCC $in",
        "rule linkgen",
        "  command = $PYTHON tools/linkgen.py $in",
        "  description = LINKGEN",
        "rule ld",
        "  command = ld.lld -T build/link.ld -o $out @build/objs.rsp",
        "  description = LD $out",
        "rule bin",
        "  command = arm-none-eabi-objcopy -O binary $in $out && python3 tools/pad.py $out",
        "  description = OBJCOPY $out",
        "rule romfs",
        "  command = $PYTHON tools/ctr.py romfs orig/rom/romfs $out",
        "  description = ROMFS $out",
        "rule rom",
        "  command = $PYTHON tools/mkrom.py --code build/code.bin --romfs build/romfs.bin --out $out",
        "  description = ROM $out",
        "",
        "build build/data.o: as asm/data.s | orig/exefs/code.bin",
    ]
    asm_objs = []
    for a in units:
        o = f"build/text/{a}.o"
        nj.append(f"build {o}: as asm/text/{a}.s | asm/macros.inc")
        asm_objs.append(o)
    src_objs = []
    for src in sources:
        o = "build/" + os.path.splitext(src)[0] + ".o"
        nj.append(f"build {o}: cc {src} | {' '.join(headers)}")
        src_objs.append(o)
    lnk_objs = [os.path.splitext(o)[0] + ".lnk.o" for o in src_objs]
    nj += [
        f"build build/link.ld build/objs.rsp {' '.join(lnk_objs)}: linkgen {' '.join(src_objs)} | build/units.tsv build/layout.ld "
        "build/asm_syms.ld config/symbols.txt tools/linkgen.py",
        f"build build/code.elf: ld build/data.o {' '.join(asm_objs + lnk_objs)} | build/link.ld build/objs.rsp",
        "build build/code.bin: bin build/code.elf",
        f"build build/romfs.bin: romfs | tools/ctr.py {' '.join(romfs_files)}",
        f"build build/rom.3ds: rom build/code.bin build/romfs.bin | tools/mkrom.py tools/ctr.py {' '.join(rom_parts)}",
        "default build/rom.3ds",
    ]
    open("build.ninja", "w").write("\n".join(nj) + "\n")
    print(f"build.ninja: {len(asm_objs)} asm units, {len(sources)} C++ sources")


if __name__ == "__main__":
    main()
