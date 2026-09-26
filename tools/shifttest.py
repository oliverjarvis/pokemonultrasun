#!/usr/bin/env python3
"""Build and boot-test "shifted" ROMs: code.bin with padding inserted, to check
that every reference moves with its target.

  shifttest.py text UNIT COUNT NAME   pad COUNT words (a branch over udf traps)
                                      after the first label of asm/text/UNIT.s
  shifttest.py data SEG ADDR NAME     insert 0x1000 zero bytes into asm/data/SEG.s
                                      before the first item at/after ADDR
  shifttest.py boot NAME [SECS] [RUNS]  boot build/rom_NAME.3ds (tools/boottest.py)

A build writes build/rom_NAME.3ds and build/shift/NAME.elf (for symbolizing a
crash), then restores the tree and rebuilds, so build/rom.3ds stays the matching
ROM. Padding with traps (not nops) makes a stale pointer into moved code fail
loudly instead of sliding into the next function.
"""
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SEG_BASE = {"rodata": 0x5BA000, "data": 0x667000}


def pad_text(path, count):
    lines = open(path).read().splitlines()
    i = next(k for k, l in enumerate(lines) if l.startswith("glabel ")) + 1
    lines[i:i] = ["    b .Lpad_end_0", f"    .rept {count - 1}", "    .inst 0xe7f000f0", "    .endr",
                  ".Lpad_end_0:"]
    open(path, "w").write("\n".join(lines) + "\n")


def pad_data(path, seg, addr):
    base = SEG_BASE[seg]
    lines = open(path).read().splitlines()
    pos = len(lines)
    for i, l in enumerate(lines):
        m = re.search(r'\.incbin "[^"]+", (0x[0-9a-f]+), ', l)
        if m and int(m.group(1), 16) + 0x100000 >= addr:
            pos = i
            break
        m = re.search(r"/\* ([0-9A-F]{8})", l)
        if m and l.strip().startswith(".4byte") and base + int(m.group(1), 16) >= addr:
            pos = i
            break
        m = re.match(r"dlabel data_([0-9A-F]{8})", l)
        if m and int(m.group(1), 16) >= addr:
            pos = i
            break
    while pos > 0 and lines[pos - 1].startswith("dlabel"):
        pos -= 1  # keep labels with the data they name
    lines[pos:pos] = ["    .space 0x1000  /* shift test */"]
    open(path, "w").write("\n".join(lines) + "\n")


def build(kind, args, name):
    path = os.path.join(ROOT, "asm", kind if kind == "text" else "data", (f"{args[0]}.s"))
    backup = open(path).read()
    try:
        if kind == "text":
            pad_text(path, int(args[1]))
        else:
            pad_data(path, args[0], int(args[1], 16))
        r = subprocess.run(["ninja"], cwd=ROOT, capture_output=True, text=True)
        if r.returncode:
            sys.exit("build failed:\n" + r.stdout[-2000:])
        os.makedirs(os.path.join(ROOT, "build", "shift"), exist_ok=True)
        shutil.copy(os.path.join(ROOT, "build", "rom.3ds"), os.path.join(ROOT, "build", f"rom_{name}.3ds"))
        shutil.copy(os.path.join(ROOT, "build", "code.elf"), os.path.join(ROOT, "build", "shift", f"{name}.elf"))
    finally:
        open(path, "w").write(backup)
        subprocess.run(["ninja"], cwd=ROOT, capture_output=True)
    print(f"build/rom_{name}.3ds")


def main():
    cmd = sys.argv[1]
    if cmd == "text":
        build("text", sys.argv[2:4], sys.argv[4])
    elif cmd == "data":
        build("data", sys.argv[2:4], sys.argv[4])
    elif cmd == "boot":
        name = sys.argv[2]
        secs = sys.argv[3] if len(sys.argv) > 3 else "15"
        runs = int(sys.argv[4]) if len(sys.argv) > 4 else 1
        for _ in range(runs):
            subprocess.run([sys.executable, os.path.join(ROOT, "tools", "boottest.py"),
                            os.path.join(ROOT, "build", f"rom_{name}.3ds"), secs])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
