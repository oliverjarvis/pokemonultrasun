#!/usr/bin/env python3
"""Generate build.ninja. Re-run after adding or removing files in src/.

Build graph:
  asm/text/*.s   --as-->     build/text/*.o
  src/**/*.cpp   --armcc-->  build/src/**/*.o   (src/cro/<Module>/ goes into that module)
  (objects)      --linkgen-> build/link.ld, build/objs.rsp, *.lnk.o  (C++ replaces asm units)
  link.ld        --ld-->     build/code.elf --objcopy--> build/code.bin
  asm/cro/<Module>/*.s --as/ld.lld/crolink--> build/romfs_overlay/<Module>.cro (+ .crr/static.crr)
  orig/rom/romfs + overlay --ctr.py--> build/romfs.bin
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
    sources = sorted(f for f in glob.glob("src/**/*.cpp", recursive=True) if not f.startswith("src/cro/"))
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
        "  command = $PYTHON tools/linkgen.py $args $in",
        "  description = LINKGEN",
        "rule ld",
        "  command = ld.lld -T build/link.ld -o $out @build/objs.rsp",
        "  description = LD $out",
        "rule bin",
        "  command = arm-none-eabi-objcopy -O binary $in $out && python3 tools/pad.py $out",
        "  description = OBJCOPY $out",
        "rule ldcro",
        "  command = ld.lld --emit-relocs -T $script -o $out @$rsp",
        "  description = LD $out",
        "rule crolink",
        "  command = $PYTHON tools/crolink.py $orig $in $meta $out",
        "  description = CROLINK $out",
        "rule crr",
        "  command = $PYTHON tools/cro.py crr $orig $out $in",
        "  description = CRR $out",
        "rule romfs",
        "  command = $PYTHON tools/ctr.py romfs orig/rom/romfs $out --overlay build/romfs_overlay",
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
    # CRO modules: assemble, link .text at its file offset, splice into the module
    overlay_cros = []
    module_sources = 0
    for mod in sorted(os.listdir("build/cro")) if os.path.isdir("build/cro") else []:
        units_tsv = f"build/cro/{mod}/units.tsv"
        if not os.path.exists(units_tsv):
            continue
        d = f"build/cro/{mod}"
        objs = []
        for line in open(units_tsv).read().splitlines()[1:]:
            a = line.split("\t")[0]
            o = f"{d}/{a}.o"
            nj.append(f"build {o}: as asm/cro/{mod}/{a}.s | asm/macros.inc")
            objs.append(o)
        mod_srcs = sorted(glob.glob(f"src/cro/{mod}/**/*.cpp", recursive=True))
        module_sources += len(mod_srcs)
        mod_objs = []
        for src in mod_srcs:
            o = "build/" + os.path.splitext(src)[0] + ".o"
            nj.append(f"build {o}: cc {src} | {' '.join(headers)}")
            mod_objs.append(o)
        mod_lnk = [os.path.splitext(o)[0] + ".lnk.o" for o in mod_objs]
        seg_objs = []
        for kind in ("rodata", "data", "bss"):
            o = f"{d}/{kind}.o"
            nj.append(f"build {o}: as asm/cro/{mod}/{kind}.s | asm/macros.inc orig/rom/romfs/{mod}.cro")
            seg_objs.append(o)
        out = f"build/romfs_overlay/{mod}.cro"
        nj += [
            f"build {d}/link.ld {d}/objs.rsp {' '.join(mod_lnk)}: linkgen {' '.join(mod_objs)} | "
            f"{d}/units.tsv {d}/layout.ld {d}/symbols.ld tools/linkgen.py",
            f"  args = --units {d}/units.tsv --objdir {d} --layout {d}/layout.ld --ld {d}/symbols.ld "
            f"--out {d}/link.ld --rsp {d}/objs.rsp " + " ".join(f"--extra {o}" for o in seg_objs),
            f"build {d}/module.elf: ldcro {' '.join(objs + seg_objs + mod_lnk)} | {d}/link.ld {d}/objs.rsp",
            f"  script = {d}/link.ld",
            f"  rsp = {d}/objs.rsp",
            f"build {out}: crolink {d}/module.elf | {d}/meta.json orig/rom/romfs/{mod}.cro "
            "tools/crolink.py tools/cro.py tools/cro_split.py",
            f"  orig = orig/rom/romfs/{mod}.cro",
            f"  meta = {d}/meta.json",
        ]
        overlay_cros.append(out)
    crr = "build/romfs_overlay/.crr/static.crr"
    if overlay_cros:
        nj += [
            f"build {crr}: crr {' '.join(overlay_cros)} | orig/rom/romfs/.crr/static.crr tools/cro.py",
            "  orig = orig/rom/romfs/.crr/static.crr",
        ]
        overlay_cros.append(crr)

    lnk_objs = [os.path.splitext(o)[0] + ".lnk.o" for o in src_objs]
    nj += [
        f"build build/link.ld build/objs.rsp {' '.join(lnk_objs)}: linkgen {' '.join(src_objs)} | build/units.tsv build/layout.ld "
        "build/asm_syms.ld config/symbols.txt tools/linkgen.py",
        "  args = --units build/units.tsv --objdir build/text --layout build/layout.ld --ld build/asm_syms.ld "
        "--ld config/symbols.txt --out build/link.ld --rsp build/objs.rsp --extra build/data.o",
        f"build build/code.elf: ld build/data.o {' '.join(asm_objs + lnk_objs)} | build/link.ld build/objs.rsp",
        "build build/code.bin: bin build/code.elf",
        f"build build/romfs.bin: romfs | tools/ctr.py {' '.join(romfs_files + overlay_cros)}",
        f"build build/rom.3ds: rom build/code.bin build/romfs.bin | tools/mkrom.py tools/ctr.py {' '.join(rom_parts)}",
        "default build/rom.3ds",
    ]
    open("build.ninja", "w").write("\n".join(nj) + "\n")
    print(f"build.ninja: {len(asm_objs)} code.bin units, {len(overlay_cros) - 1 if overlay_cros else 0} CRO modules, "
          f"{len(sources) + module_sources} C++ sources ({module_sources} in modules)")


if __name__ == "__main__":
    main()
