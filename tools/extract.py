#!/usr/bin/env python3
"""Extract code and inventory data from a decrypted 3DS cart image (.3ds / NCSD).

Outputs (under --out, default ./orig):
  exheader.bin        raw extended header
  exefs/<name>.bin    raw ExeFS files (code.bin is BLZ-decompressed)
  romfs_files.tsv     path, offset, size of every RomFS file
  romfs/...           RomFS files matching --romfs-glob (default: code modules)
"""
import argparse
import fnmatch
import hashlib
import json
import os
import struct
import sys

MU = 0x200  # media unit


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def blz_decompress(comp):
    """Backwards-LZ as used for 3DS ExeFS .code (mirrors ctrtool's lzss.c)."""
    size = len(comp)
    top_bottom = u32(comp, size - 8)
    out_size = u32(comp, size - 4) + size
    out = bytearray(out_size)
    out[:size] = comp
    index = size - ((top_bottom >> 24) & 0xFF)
    stop = size - (top_bottom & 0xFFFFFF)
    dst = out_size
    while index > stop:
        index -= 1
        control = comp[index]
        for _ in range(8):
            if index <= stop:
                break
            if control & 0x80:
                index -= 2
                seg = comp[index] | (comp[index + 1] << 8)
                seg_len = ((seg >> 12) & 0xF) + 3
                seg_off = (seg & 0xFFF) + 2
                for _ in range(seg_len):
                    out[dst - 1] = out[dst + seg_off]
                    dst -= 1
            else:
                index -= 1
                dst -= 1
                out[dst] = comp[index]
            control = (control << 1) & 0xFF
    return bytes(out)


def parse_exheader(ex):
    def seg(o):
        return {"addr": u32(ex, o), "pages": u32(ex, o + 4), "size": u32(ex, o + 8)}

    return {
        "title": ex[0:8].rstrip(b"\0").decode("ascii", "replace"),
        "code_compressed": bool(ex[0xD] & 1),
        "text": seg(0x10),
        "stack_size": u32(ex, 0x1C),
        "rodata": seg(0x20),
        "data": seg(0x30),
        "bss_size": u32(ex, 0x3C),
    }


def read_romfs_tree(f, romfs_base, dirs_out=None):
    f.seek(romfs_base)
    ivfc = f.read(0x60)
    if ivfc[:4] != b"IVFC":
        sys.exit("RomFS: missing IVFC magic (is the image decrypted?)")
    master_hash_size = u32(ivfc, 0x08)
    l3_block_log2 = u32(ivfc, 0x4C)
    block = 1 << l3_block_log2
    l3 = romfs_base + ((0x60 + master_hash_size + block - 1) // block) * block

    f.seek(l3)
    hdr = f.read(0x28)
    dir_meta_off, dir_meta_size = u32(hdr, 0x0C), u32(hdr, 0x10)
    file_meta_off, file_meta_size = u32(hdr, 0x1C), u32(hdr, 0x20)
    data_off = u32(hdr, 0x24)
    f.seek(l3 + dir_meta_off)
    dirs = f.read(dir_meta_size)
    f.seek(l3 + file_meta_off)
    files = f.read(file_meta_size)

    def name_at(tbl, o, hdr_len):
        n = u32(tbl, o + hdr_len - 4)
        return tbl[o + hdr_len : o + hdr_len + n].decode("utf-16-le")

    out = []
    NONE = 0xFFFFFFFF

    def walk(d, path):
        if dirs_out is not None:
            dirs_out.append(path)
        fi = u32(dirs, d + 0x0C)
        while fi != NONE:
            name = name_at(files, fi, 0x20)
            out.append((path + name, l3 + data_off + u64(files, fi + 0x08), u64(files, fi + 0x10)))
            fi = u32(files, fi + 0x04)
        ci = u32(dirs, d + 0x08)
        while ci != NONE:
            walk(ci, path + name_at(dirs, ci, 0x18) + "/")
            ci = u32(dirs, ci + 0x04)

    walk(0, "/")
    return out


def copy_range(f, off, size, dest):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    f.seek(off)
    with open(dest, "wb") as o:
        left = size
        while left:
            chunk = f.read(min(left, 1 << 20))
            o.write(chunk)
            left -= len(chunk)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--out", default="orig")
    ap.add_argument("--romfs-glob", action="append", default=None,
                    help="RomFS paths to extract (default: *.cro, *.crs, *.crr)")
    args = ap.parse_args()
    globs = args.romfs_glob or ["*.cro", "*.crs", "*.crr"]
    os.makedirs(args.out, exist_ok=True)

    with open(args.image, "rb") as f:
        ncsd = f.read(0x200)
        if ncsd[0x100:0x104] != b"NCSD":
            sys.exit("not an NCSD (.3ds) image")
        base = u32(ncsd, 0x120) * MU
        f.seek(base)
        ncch = f.read(0x200)
        if ncch[0x100:0x104] != b"NCCH":
            sys.exit("partition 0 is not NCCH")
        if not ncch[0x18F] & 0x04:
            sys.exit("NCCH is encrypted; decrypt it first")

        info = {
            "program_id": "%016X" % u64(ncch, 0x118),
            "product_code": ncch[0x150:0x160].rstrip(b"\0").decode(),
            "ncch_version": struct.unpack_from("<H", ncch, 0x112)[0],
        }

        f.seek(base + 0x200)
        ex = f.read(0x400)
        open(os.path.join(args.out, "exheader.bin"), "wb").write(ex)
        info["exheader"] = parse_exheader(ex)

        exefs_off = base + u32(ncch, 0x1A0) * MU
        f.seek(exefs_off)
        exefs_hdr = f.read(0x200)
        info["exefs"] = {}
        for i in range(10):
            name = exefs_hdr[i * 16 : i * 16 + 8].rstrip(b"\0").decode()
            off, size = u32(exefs_hdr, i * 16 + 8), u32(exefs_hdr, i * 16 + 12)
            if not name:
                continue
            f.seek(exefs_off + 0x200 + off)
            blob = f.read(size)
            if name == ".code" and info["exheader"]["code_compressed"]:
                open(os.path.join(args.out, "code_compressed.bin"), "wb").write(blob)
                blob = blz_decompress(blob)
            fname = "code.bin" if name == ".code" else name + ".bin"
            path = os.path.join(args.out, "exefs", fname)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, "wb").write(blob)
            info["exefs"][name] = {"size": len(blob), "sha1": hashlib.sha1(blob).hexdigest()}

        romfs = read_romfs_tree(f, base + u32(ncch, 0x1B0) * MU)
        with open(os.path.join(args.out, "romfs_files.tsv"), "w") as t:
            t.write("path\toffset\tsize\n")
            for p, o, s in romfs:
                t.write(f"{p}\t{o:#x}\t{s}\n")
        extracted = []
        for p, o, s in romfs:
            if any(fnmatch.fnmatch(p, g) for g in globs):
                copy_range(f, o, s, os.path.join(args.out, "romfs", p.lstrip("/")))
                extracted.append(p)
        info["romfs"] = {"file_count": len(romfs), "total_size": sum(s for _, _, s in romfs),
                         "extracted": extracted}

    with open(os.path.join(args.out, "info.json"), "w") as j:
        json.dump(info, j, indent=2)
    print(json.dumps({k: v for k, v in info.items() if k != "romfs"}, indent=2))
    print(f"romfs: {info['romfs']['file_count']} files, {info['romfs']['total_size'] / 2**30:.2f} GiB; "
          f"extracted {len(extracted)} code modules")


if __name__ == "__main__":
    main()
