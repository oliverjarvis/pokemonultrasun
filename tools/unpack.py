#!/usr/bin/env python3
"""Unpack every part of a decrypted .3ds needed to rebuild it (one-time setup).

  unpack.py baserom.3ds [--out orig/rom]

Writes:
  ncsd_header.bin      card header 0x0-0x4000 (RSA signature, card info)
  partitions/<i>.bin   partitions other than the game (manual, DLP child, update)
  ncch/header.bin      game NCCH header (signature, IDs, flags)
  ncch/exheader.bin    extended header + access descriptor (0x800)
  ncch/logo.bin, ncch/plain.bin
  ncch/exefs/<name>.bin  ExeFS files except .code (built from source)
  romfs/...            every RomFS file

Offsets, sizes and hashes in the headers are recomputed by tools/mkrom.py;
only fields that cannot be derived (signatures, IDs, card info) are used from
these files.
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
from extract import copy_range, read_romfs_tree  # noqa: E402

MU = 0x200


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--out", default="orig/rom")
    args = ap.parse_args()
    out = args.out

    def write(rel, data):
        path = os.path.join(out, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "wb").write(data)

    with open(args.image, "rb") as f:
        card = f.read(0x4000)
        if card[0x100:0x104] != b"NCSD":
            sys.exit("not an NCSD image")
        write("ncsd_header.bin", card)
        parts = [struct.unpack_from("<II", card, 0x120 + 8 * i) for i in range(8)]
        for i, (off, size) in enumerate(parts):
            if size and i != 0:
                copy_range(f, off * MU, size * MU, os.path.join(out, "partitions", f"{i}.bin"))

        base = parts[0][0] * MU
        f.seek(base)
        ncch = f.read(0x200)
        if not ncch[0x18F] & 0x04:
            sys.exit("game NCCH is encrypted")
        write("ncch/header.bin", ncch)
        write("ncch/exheader.bin", f.read(0x800))
        for name, o in (("logo", 0x198), ("plain", 0x190)):
            off, size = u32(ncch, o) * MU, u32(ncch, o + 4) * MU
            f.seek(base + off)
            write(f"ncch/{name}.bin", f.read(size))

        exefs = base + u32(ncch, 0x1A0) * MU
        f.seek(exefs)
        hdr = f.read(0x200)
        for i in range(10):
            name = hdr[i * 16 : i * 16 + 8].rstrip(b"\0").decode()
            if not name or name == ".code":
                continue
            off, size = u32(hdr, i * 16 + 8), u32(hdr, i * 16 + 12)
            f.seek(exefs + 0x200 + off)
            write(f"ncch/exefs/{name}.bin", f.read(size))
        order = [hdr[i * 16 : i * 16 + 8].rstrip(b"\0").decode() for i in range(10)]
        write("ncch/exefs/order.txt", ("\n".join(n for n in order if n) + "\n").encode())

        dirs = []
        files = read_romfs_tree(f, base + u32(ncch, 0x1B0) * MU, dirs)
        for d in dirs:
            os.makedirs(os.path.join(out, "romfs", d.lstrip("/")), exist_ok=True)
        for n, (path, off, size) in enumerate(files):
            copy_range(f, off, size, os.path.join(out, "romfs", path.lstrip("/")))
            if n % 100 == 0:
                print(f"  romfs {n}/{len(files)}", end="\r", flush=True)
        print(f"unpacked to {out}: {len(files)} RomFS files in {len(dirs)} dirs, "
              f"{sum(1 for p in parts[1:] if p[1])} extra partitions")


if __name__ == "__main__":
    main()
