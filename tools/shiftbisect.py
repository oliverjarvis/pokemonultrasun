#!/usr/bin/env python3
"""Bisect where padding starts to break a shifted build.

  shiftbisect.py text [LO_UNIT [HI_UNIT]] [--movie build/continue.ctm] [--secs N]
  shiftbisect.py data [--movie ...] [--secs N]

text: pad .text units (tools/shifttest.py text); data: insert 4 KB before a
.rodata/.data label (shifttest.py data). Finds the last point whose moving still
crashes: a stale reference targets what lies between it and the next point.
A failure must repeat to count, and a hang only counts if the matching ROM
boots at that moment (Azahar sometimes stalls on its own).
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PY = os.path.join(ROOT, ".venv", "bin", "python")


def boot(rom, secs, movie):
    cmd = [PY, os.path.join(ROOT, "tools", "boottest.py"), rom, str(secs)] + ([movie] if movie else [])
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT).stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=("text", "data"))
    ap.add_argument("lo", nargs="?")
    ap.add_argument("hi", nargs="?")
    ap.add_argument("--movie")
    ap.add_argument("--secs", type=int, default=15)
    args = ap.parse_args()

    if args.kind == "text":
        pts = [l.split("\t")[0] for l in open(os.path.join(ROOT, "build", "units.tsv")).read().splitlines()[1:]]
        pts = [u for u in pts if "\nglabel " in open(os.path.join(ROOT, "asm", "text", f"{u}.s")).read()]
        make = lambda p: ["text", p, "256"]
    else:
        pts = []
        for seg in ("rodata", "data"):
            for l in open(os.path.join(ROOT, "asm", "data", f"{seg}.s")):
                m = re.match(r"dlabel data_([0-9A-F]{8})", l)
                if m:
                    pts.append((seg, m.group(1)))
        pts = sorted(set(pts), key=lambda x: x[1])
        make = lambda p: ["data", p[0], "0x" + p[1]]

    shutil.copy(os.path.join(ROOT, "build", "rom.3ds"), os.path.join(ROOT, "build", "rom_baseline.3ds"))

    def fails(k):
        r = subprocess.run([PY, os.path.join(ROOT, "tools", "shifttest.py"), *make(pts[k]), "bisect"],
                           capture_output=True, text=True, cwd=ROOT)
        if r.returncode:
            sys.exit(f"build failed at {pts[k]}:\n{r.stdout[-1500:]}{r.stderr[-1500:]}")
        votes = []
        while len(votes) < 3:
            out = boot(os.path.join(ROOT, "build", "rom_bisect.3ds"), args.secs, args.movie)
            if "HANG" in out and "ok" not in boot(os.path.join(ROOT, "build", "rom_baseline.3ds"), args.secs, None):
                print("    (Azahar stalls even on the matching ROM: waiting)", flush=True)
                time.sleep(60)
                continue
            votes.append("CRASH" in out or "HANG" in out)
            if len(votes) == 1 and not votes[0]:
                break
            if len(votes) == 2 and votes[0] == votes[1]:
                break
        bad = sum(votes) * 2 > len(votes)
        print(f"  from {pts[k]}: {'CRASH' if bad else 'ok'} {votes}", flush=True)
        return bad

    index = lambda p: next(i for i, x in enumerate(pts) if (x if isinstance(x, str) else x[1]) == p)
    lo = index(args.lo) if args.lo else 0
    hi = index(args.hi) if args.hi else len(pts) - 1
    if not fails(lo):
        sys.exit("the low end does not fail")
    if not args.hi and fails(hi):
        sys.exit("still fails when only the last point moves")
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if fails(mid):
            lo = mid
        else:
            hi = mid
    print(f"moving from {pts[lo]} fails, from {pts[hi]} is fine")


if __name__ == "__main__":
    main()
