#!/usr/bin/env python3
"""Verify build/code.bin against the original and learn raw-word fallbacks.

  check.py [--learn]

Prints the SHA-1 comparison and the first differing words. With --learn,
addresses of lines the assembler rejected (from build/ninja.log) and text
words whose rebuilt bytes differ are appended to config/force_raw.txt so the
next tools/split.py run emits them as exact `.inst` words.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")
ADDR_COMMENT = re.compile(r"/\* ([0-9A-F]{8})")


def assembler_errors():
    log = os.path.join(ROOT, "build", "ninja.log")
    if not os.path.exists(log):
        return {}
    out = {}
    for m in re.finditer(r"^(asm/text/[0-9A-F]+\.s):(\d+): Error: (.*)$", open(log).read(), re.M):
        path, line, msg = m.group(1), int(m.group(2)), m.group(3)
        text = open(os.path.join(ROOT, path)).read().splitlines()[line - 1]
        a = ADDR_COMMENT.search(text)
        if a:
            out[int(a.group(1), 16)] = "as: " + msg.split(" -- ")[0]
    return out


def check_rom():
    """Compare build/rom.3ds with config/rom.sha1. None if either is missing."""
    want_path = os.path.join(ROOT, "config", "rom.sha1")
    rom = os.path.join(ROOT, "build", "rom.3ds")
    if not (os.path.exists(want_path) and os.path.exists(rom)):
        return None
    want = open(want_path).read().split()[0]
    h = hashlib.sha1()
    with open(rom, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 24), b""):
            h.update(chunk)
    ok = h.hexdigest() == want
    print(f"rom.3ds  {h.hexdigest()}  {'MATCH' if ok else 'DIFFERENT (expected ' + want + ')'}")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--learn", action="store_true")
    args = ap.parse_args()

    info = json.load(open(os.path.join(ROOT, "orig", "info.json")))
    text = info["exheader"]["text"]
    orig = open(os.path.join(ROOT, "orig", "exefs", "code.bin"), "rb").read()
    new = {}
    errs = assembler_errors()
    for a, why in errs.items():
        new[a] = why

    built_path = os.path.join(ROOT, "build", "code.bin")
    ok = False
    if os.path.exists(built_path) and not errs:
        built = open(built_path, "rb").read()
        h_o, h_b = hashlib.sha1(orig).hexdigest(), hashlib.sha1(built).hexdigest()
        ok = h_o == h_b
        print(f"original {h_o}\nbuilt    {h_b}\n{'MATCH' if ok else 'DIFFERENT'}")
        if not ok:
            n = min(len(orig), len(built)) // 4
            ow = struct.unpack(f"<{n}I", orig[: 4 * n])
            bw = struct.unpack(f"<{n}I", built[: 4 * n])
            diffs = [i for i in range(n) if ow[i] != bw[i]]
            print(f"{len(diffs)} differing words; size {len(built):#x} vs {len(orig):#x}")
            for i in diffs[:15]:
                print(f"  {text['addr'] + 4 * i:08X}: orig {ow[i]:08x} built {bw[i]:08x}")
            for i in diffs:
                a = text["addr"] + 4 * i
                if a < text["addr"] + text["size"]:
                    new[a] = f"encoding: orig {ow[i]:08x} built {bw[i]:08x}"
    elif errs:
        print(f"{len(errs)} assembler errors")

    if new and args.learn:
        path = os.path.join(ROOT, "config", "force_raw.txt")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as f:
            for a in sorted(new):
                f.write(f"{a:08X}  {new[a]}\n")
        print(f"learned {len(new)} raw words -> config/force_raw.txt")
    rom_ok = check_rom()
    return 0 if ok and rom_ok is not False else 1


if __name__ == "__main__":
    sys.exit(main())
