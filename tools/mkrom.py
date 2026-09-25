#!/usr/bin/env python3
"""Assemble build/rom.3ds from built and unpacked parts (no base image needed).

  mkrom.py [--code build/code.bin] [--romfs build/romfs.bin] [--parts orig/rom]
           [--out build/rom.3ds] [--trim]

Builds the ExeFS (code.bin + banner + icon), lays out the game NCCH
(exheader, logo, plain region, ExeFS, RomFS) and the NCSD card image
(partitions packed after the 0x4000 card header, 0xFF fill to the card
capacity unless --trim), recomputing every offset, size and SHA-256.

Only non-derivable fields come from the unpacked headers (tools/unpack.py):
RSA signatures, title/program IDs, flags, card info. After a code change the
NCCH/NCSD RSA signatures no longer verify; Luma3DS and emulators don't check.
"""
import argparse
import os
import shutil
import struct

from ctr import MU, build_exefs, ncch_layout, romfs_hash_region


def read(path):
    with open(path, "rb") as f:
        return f.read()


def code_set_info(exheader, elf_path):
    """Exheader with text/rodata/data address, page count and size, and the
    .bss size, taken from the linked code.bin."""
    from elftools.elf.elffile import ELFFile

    ex = bytearray(exheader)
    with open(elf_path, "rb") as fh:
        elf = ELFFile(fh)
        for name, off in ((".text", 0x10), (".rodata", 0x20), (".data", 0x30)):
            sec = elf.get_section_by_name(name)
            size = sec["sh_size"]
            struct.pack_into("<III", ex, off, sec["sh_addr"], (size + 0xFFF) // 0x1000, size)
        struct.pack_into("<I", ex, 0x3C, elf.get_section_by_name(".bss")["sh_size"])
    return bytes(ex)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--code", default="build/code.bin")
    ap.add_argument("--elf", help="linked code.bin ELF: update the exheader's code set info from it")
    ap.add_argument("--romfs", default="build/romfs.bin")
    ap.add_argument("--parts", default="orig/rom")
    ap.add_argument("--out", default="build/rom.3ds")
    ap.add_argument("--trim", action="store_true", help="omit the 0xFF fill after the last partition")
    args = ap.parse_args()
    p = lambda *x: os.path.join(args.parts, *x)

    # ExeFS
    names = read(p("ncch", "exefs", "order.txt")).decode().split()
    files = [(nm, read(args.code) if nm == ".code" else read(p("ncch", "exefs", nm + ".bin"))) for nm in names]
    exefs = build_exefs(files)

    # NCCH
    romfs_size = os.path.getsize(args.romfs)
    hash_size, romfs_hash = romfs_hash_region(args.romfs)
    exheader = read(p("ncch", "exheader.bin"))
    if args.elf:
        exheader = code_set_info(exheader, args.elf)
    ncch_hdr, ncch_parts, ncch_size = ncch_layout(
        read(p("ncch", "header.bin")), exheader, read(p("ncch", "logo.bin")),
        read(p("ncch", "plain.bin")), exefs, romfs_size, hash_size, romfs_hash)

    # NCSD
    card = bytearray(read(p("ncsd_header.bin")))
    capacity = struct.unpack_from("<I", card, 0x104)[0] * MU
    extra = sorted(int(f[:-4]) for f in os.listdir(p("partitions")) if f.endswith(".bin"))
    layout = [(0, None, ncch_size)] + [(i, p("partitions", f"{i}.bin"), os.path.getsize(p("partitions", f"{i}.bin")))
                                       for i in extra]
    struct.pack_into("<16I", card, 0x120, *([0] * 16))
    pos = len(card)
    placed = []
    for idx, path, size in layout:
        struct.pack_into("<II", card, 0x120 + 8 * idx, pos // MU, size // MU)
        placed.append((pos, path, size))
        pos += size
    filled = pos
    struct.pack_into("<I", card, 0x300, filled)
    # The card header keeps a copy of the NCCH header. Its flags describe the
    # retail (encrypted) partition, while a decrypted dump's NCCH says NoCrypto,
    # so keep the copy's own flags and refresh everything else.
    flags = card[0x1188:0x1190]
    card[0x1100:0x1200] = ncch_hdr[0x100:0x200]
    card[0x1188:0x1190] = flags

    with open(args.out, "wb") as o:
        o.write(card)
        base = placed[0][0]
        o.write(ncch_hdr)
        for off, blob in ncch_parts:
            o.seek(base + off)
            if blob is None:
                with open(args.romfs, "rb") as r:
                    shutil.copyfileobj(r, o, 1 << 24)
            else:
                o.write(blob)
        for off, path, size in placed[1:]:
            o.seek(off)
            with open(path, "rb") as r:
                shutil.copyfileobj(r, o, 1 << 24)
        o.seek(filled)
        if not args.trim:
            chunk = b"\xff" * (1 << 24)
            left = capacity - filled
            while left:
                o.write(chunk[: min(left, len(chunk))])
                left -= min(left, len(chunk))
        o.truncate(filled if args.trim else capacity)
    print(f"wrote {args.out}: NCCH {ncch_size:#x}, {len(extra)} extra partitions, "
          f"{'trimmed at' if args.trim else 'filled to'} {filled if args.trim else capacity:#x}")


if __name__ == "__main__":
    main()
