#!/usr/bin/env python3
"""Emit relocatable GNU-as ARM assembly for code.bin functions and verify it.

  asmgen.py <name-substring|0xADDR> ... [--out DIR]

For each matching function writes DIR/<mangled>.s where local branches use
labels, pc-relative loads use literal labels, and literal-pool words that point
into the binary become symbol references. Verification assembles the file,
links it at the original address with every referenced symbol defined at its
real address, and requires the bytes to equal code.bin exactly.
"""
import argparse
import os
import re
import struct
import subprocess
import tempfile

import capstone

import disasm

LO, HI = 0x100000, 0x6F0000  # text .. end of bss


def sym_name(addr, by_addr):
    return by_addr.get(addr, f"sub_{addr:08X}" if addr < 0x5BA000 else f"data_{addr:08X}")


def gen(base, code, syms, i, by_addr):
    start, mode, mangled, dm = syms[i]
    end = disasm.extent(base, code, syms, i)
    blob = code[start - base : end - base]
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    md.detail = True

    # pass 1: find literal-pool words (pc-relative load targets) and branch targets
    literals, labels = set(), set()
    for off in range(0, len(blob), 4):
        a = start + off
        if a in literals:
            continue
        ins = next(md.disasm(blob[off : off + 4], a), None)
        if ins is None:
            continue
        m = re.search(r"\[pc, #(-?0x[0-9a-f]+|-?\d+)\]", ins.op_str)
        if m:
            tgt = a + 8 + int(m.group(1), 0)
            literals.add(tgt)
            if ins.mnemonic.startswith("ldrd"):
                literals.add(tgt + 4)
        if ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL):
            if ins.op_str.startswith("#"):
                tgt = int(ins.op_str[1:], 16)
                if start <= tgt < end:
                    labels.add(tgt)

    externs = {}
    lines = [".syntax unified", ".arm", ".text", f".global {mangled}", f".type {mangled}, %function",
             f"{mangled}:"]
    for off in range(0, len(blob), 4):
        a = start + off
        if a in labels or a in literals:
            lines.append(f".L_{a:08X}:")
        w = struct.unpack_from("<I", blob, off)[0]
        ins = None if a in literals else next(md.disasm(blob[off : off + 4], a), None)
        if ins is None:
            if LO <= w < HI:
                s = sym_name(w & ~1 if w < 0x5BA000 else w, by_addr)
                externs[s] = w & ~1 if w < 0x5BA000 else w
                lines.append(f"    .word {s}" + (" + 1" if w < 0x5BA000 and w & 1 else ""))
            else:
                lines.append(f"    .word {w:#010x}")
            continue
        op = ins.op_str
        m = re.search(r"\[pc, #(-?0x[0-9a-f]+|-?\d+)\]", op)
        if m:
            op = op[: m.start()] + f".L_{a + 8 + int(m.group(1), 0):08X}" + op[m.end() :]
        elif (ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL)) and op.startswith("#"):
            tgt = int(op[1:], 16)
            if start <= tgt < end:
                op = f".L_{tgt:08X}"
            else:
                op = sym_name(tgt, by_addr)
                externs[op] = tgt
        lines.append(f"    {ins.mnemonic} {op}")
    lines.append(f".size {mangled}, . - {mangled}")
    return "\n".join(lines) + "\n", externs, blob


def verify(asm, externs, start, blob):
    with tempfile.TemporaryDirectory() as d:
        s, o, e, b = (os.path.join(d, x) for x in ("f.s", "f.o", "f.elf", "f.bin"))
        open(s, "w").write(asm)
        subprocess.run(["arm-none-eabi-as", "-mcpu=mpcore", "-o", o, s], check=True)
        ld = ["arm-none-eabi-ld", f"-Ttext={start:#x}", "-o", e, o]
        for name, addr in externs.items():
            ld.append(f"--defsym={name}={addr:#x}")
        subprocess.run(ld, check=True, capture_output=True)
        subprocess.run(["arm-none-eabi-objcopy", "-O", "binary", "-j", ".text", e, b], check=True)
        got = open(b, "rb").read()
    return got == blob


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("query", nargs="+")
    ap.add_argument("--out", default="asm/funcs")
    args = ap.parse_args()
    base, code, syms = disasm.load()
    by_addr = {s[0]: s[2] for s in syms}
    os.makedirs(args.out, exist_ok=True)
    for q in args.query:
        hits = [i for i, s in enumerate(syms)
                if (q.startswith("0x") and s[0] == int(q, 16)) or (not q.startswith("0x") and q in s[3])]
        for i in hits:
            asm, externs, blob = gen(base, code, syms, i, by_addr)
            ok = verify(asm, externs, syms[i][0], blob)
            path = os.path.join(args.out, syms[i][2] + ".s")
            open(path, "w").write(asm)
            print(f"{'OK  ' if ok else 'FAIL'} {syms[i][0]:08x} {len(blob):4}B  {syms[i][3]}")


if __name__ == "__main__":
    main()
