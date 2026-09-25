#!/usr/bin/env python3
"""Size/function inventory of the extracted code (code.bin + CRO modules).

Function counts are a heuristic: ARM prologues that save LR
(STMFD SP!, {..., LR} / STR LR, [SP, #-4]!) give a lower bound because
leaf functions often have no prologue. `bx lr` counts are shown for scale.
"""
import glob
import json
import os
import struct
import sys

SEG_NAMES = {0: "text", 1: "rodata", 2: "data", 3: "bss"}


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def scan_arm(text):
    prologues = rets = thumb_push = 0
    for (w,) in struct.iter_unpack("<I", text[: len(text) & ~3]):
        if w & 0xFFFF4000 == 0xE92D4000 or w == 0xE52DE004:
            prologues += 1
        elif w == 0xE12FFF1E:
            rets += 1
    for (h,) in struct.iter_unpack("<H", text[: len(text) & ~1]):
        if h & 0xFF00 == 0xB500:  # Thumb PUSH {..., LR}; noisy, only a hint
            thumb_push += 1
    return prologues, rets, thumb_push


def read_cstr(b, o):
    return b[o : b.index(b"\0", o)].decode("ascii", "replace")


def parse_cro(path):
    b = open(path, "rb").read()
    magic = b[0x80:0x84]
    if magic not in (b"CRO0", b"CRS0"):
        return None
    segs = {}
    seg_off, seg_num = u32(b, 0xC8), u32(b, 0xCC)
    for i in range(seg_num):
        off, size, sid = struct.unpack_from("<III", b, seg_off + 12 * i)
        if size:  # trailing entries are empty placeholders
            segs[SEG_NAMES.get(sid, str(sid))] = (off, size)
    exp_off, exp_num = u32(b, 0xD0), u32(b, 0xD4)
    exports = [read_cstr(b, u32(b, exp_off + 8 * i)) for i in range(exp_num)]
    imp_mod_num = u32(b, 0xF4)
    text = b[segs["text"][0] : segs["text"][0] + segs["text"][1]] if "text" in segs else b""
    return {
        "magic": magic.decode(),
        "name": read_cstr(b, u32(b, 0xC0)) if u32(b, 0xC4) else "",
        "segments": {k: v[1] for k, v in segs.items()},
        "named_exports": exports,
        "import_modules": imp_mod_num,
        "text": text,
    }


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "orig"
    info = json.load(open(os.path.join(root, "info.json")))
    ex = info["exheader"]
    code = open(os.path.join(root, "exefs", "code.bin"), "rb").read()
    text = code[: ex["text"]["size"]]

    rows = []
    p, r, t = scan_arm(text)
    rows.append(("code.bin", ex["text"]["size"], ex["rodata"]["size"], ex["data"]["size"], p, r, t, 0))

    all_exports = {}
    for path in sorted(glob.glob(os.path.join(root, "romfs", "**", "*.cr[os]"), recursive=True)):
        c = parse_cro(path)
        if c is None:
            print("skip (bad magic):", path)
            continue
        s = c["segments"]
        p, r, t = scan_arm(c["text"])
        name = os.path.basename(path)
        # static.crs only describes code.bin's segments; don't count them twice
        text_size = 0 if name.endswith(".crs") else s.get("text", 0)
        rows.append((name, text_size, s.get("rodata", 0), s.get("data", 0), p, r, t,
                     len(c["named_exports"])))
        all_exports[name] = c["named_exports"]

    rows.sort(key=lambda x: -x[1])
    hdr = ("module", "text", "rodata", "data", "prologues", "bx_lr", "thumb?", "exports")
    lines = ["\t".join(hdr)] + ["\t".join(map(str, row)) for row in rows]
    open(os.path.join(root, "inventory.tsv"), "w").write("\n".join(lines) + "\n")
    json.dump(all_exports, open(os.path.join(root, "exports.json"), "w"), indent=1)

    tot = [sum(r[i] for r in rows) for i in range(1, 8)]
    print(f"{'module':28} {'text':>10} {'rodata':>9} {'data':>9} {'prolog':>7} {'bx lr':>7} {'exports':>7}")
    for row in rows[:15]:
        print(f"{row[0]:28} {row[1]:>10} {row[2]:>9} {row[3]:>9} {row[4]:>7} {row[5]:>7} {row[7]:>7}")
    print(f"... {len(rows)} modules total")
    print(f"{'TOTAL':28} {tot[0]:>10} {tot[1]:>9} {tot[2]:>9} {tot[3]:>7} {tot[4]:>7} {tot[6]:>7}")
    print(f"thumb push hint total: {tot[5]} (noise floor, compare to prologues)")


if __name__ == "__main__":
    main()
