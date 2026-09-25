#!/usr/bin/env python3
"""Report decompilation progress from the last build.

  progress.py [--modules] [--markdown] [--json]

A unit counts as decompiled when the link replaced its asm with compiled C++
(its object is missing from the link's response file). Import veneers in CRO
modules are linker-generated and excluded from the totals.
"""
import argparse
import json
import os
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")


def read_units(path):
    out = []
    for line in open(path).read().splitlines()[1:]:
        addr, size, sym = line.split("\t")
        out.append((int(addr, 16), int(size), sym))
    return out


def target_progress(units_tsv, objdir, rsp):
    units = [u for u in read_units(units_tsv) if not u[2].startswith("veneer_")]
    if not os.path.exists(rsp):
        return None
    linked = set(open(rsp).read().split())
    done = [u for u in units if os.path.join(objdir, f"{u[0]:08X}.o") not in linked]
    return {
        "functions": len(units), "functions_done": len(done),
        "bytes": sum(u[1] for u in units), "bytes_done": sum(u[1] for u in done),
    }


def collect():
    targets = {}
    p = target_progress(os.path.join(ROOT, "build", "units.tsv"), "build/text", os.path.join(ROOT, "build", "objs.rsp"))
    if p:
        targets["code.bin"] = p
    cro = os.path.join(ROOT, "build", "cro")
    for mod in sorted(os.listdir(cro)) if os.path.isdir(cro) else []:
        d = os.path.join(cro, mod)
        if not os.path.isfile(os.path.join(d, "units.tsv")):
            continue
        p = target_progress(os.path.join(d, "units.tsv"), f"build/cro/{mod}", os.path.join(d, "objs.rsp"))
        if p:
            targets[mod] = p
    return targets


def pct(a, b):
    return 100.0 * a / b if b else 0.0


def total(targets):
    keys = ("functions", "functions_done", "bytes", "bytes_done")
    return {k: sum(t[k] for t in targets.values()) for k in keys}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--modules", action="store_true", help="list every module, not just those with progress")
    ap.add_argument("--markdown", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    targets = collect()
    if not targets:
        sys.exit("no build found; run ninja first")
    modules = {k: v for k, v in targets.items() if k != "code.bin"}
    rows = [("code.bin", targets.get("code.bin")), ("CRO modules", total(modules)), ("Total", total(targets))]
    if args.json:
        json.dump({"targets": targets, "total": total(targets)}, sys.stdout, indent=1)
        print()
        return
    shown = [(k, v) for k, v in modules.items() if args.modules or v["functions_done"]]

    if args.markdown:
        print("| | Functions | Code |")
        print("|---|---|---|")
        for name, t in rows + [(f"`{k}`", v) for k, v in shown]:
            print(f"| {name} | {t['functions_done']:,} / {t['functions']:,} ({pct(t['functions_done'], t['functions']):.2f}%) "
                  f"| {t['bytes_done']:,} / {t['bytes']:,} bytes ({pct(t['bytes_done'], t['bytes']):.3f}%) |")
        return
    print(f"{'':16} {'functions':>22} {'code bytes':>30}")
    for name, t in rows + [("  " + k, v) for k, v in shown]:
        print(f"{name:16} {t['functions_done']:>7,} / {t['functions']:>7,} {pct(t['functions_done'], t['functions']):6.2f}%"
              f" {t['bytes_done']:>10,} / {t['bytes']:>10,} {pct(t['bytes_done'], t['bytes']):7.3f}%")


if __name__ == "__main__":
    main()
