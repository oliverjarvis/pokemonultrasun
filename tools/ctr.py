#!/usr/bin/env python3
"""3DS container formats: build RomFS, ExeFS, NCCH and NCSD images from parts.

Layout rules reproduce Nintendo's mastering tool for this title (verified by
byte-identical rebuilds):
  RomFS  a directory's children are allocated together when it is visited
         depth-first; files follow directory pre-order; entries sorted
         case-insensitively; file
         data 16-byte aligned, IVFC levels L3 | L1 | L2 after a 0x1000 header
         block, 4 KiB hash blocks, hash-bucket chains built by prepending.
  ExeFS  files 0x200-aligned, SHA-256 table in reverse entry order.
  NCCH   header, exheader+access desc, logo, plain region, ExeFS, RomFS
         (RomFS 0x1000-aligned).
  NCSD   partitions packed back to back after the 0x4000 card header,
         0xFF fill to the card capacity.

CLI:
  ctr.py romfs SRC_DIR OUT.bin     build a RomFS image from a directory
"""
import hashlib
import os
import struct
import sys

MU = 0x200
BLOCK = 0x1000
NONE = 0xFFFFFFFF


def align(v, a):
    return (v + a - 1) // a * a


# ------------------------------------------------------------------ RomFS

def _hash_bucket_count(n):
    if n < 3:
        return 3
    if n < 19:
        return n | 1
    while any(n % p == 0 for p in (2, 3, 5, 7, 11, 13, 17)):
        n += 1
    return n


def _path_hash(parent_off, name):
    h = parent_off ^ 123456789
    units = name.encode("utf-16-le")
    for i in range(0, len(units), 2):
        h = ((h >> 5) | (h << 27)) & 0xFFFFFFFF
        h ^= units[i] | (units[i + 1] << 8)
    return h


def _sort_key(name):
    return name.upper()


class _Dir:
    def __init__(self, name, path, parent):
        self.name, self.path, self.parent = name, path, parent
        self.dirs, self.files = [], []
        self.off = None


def _scan(root):
    top = _Dir("", root, None)
    queue = [top]
    while queue:
        d = queue.pop(0)
        names = os.listdir(d.path)
        for nm in sorted((n for n in names if os.path.isdir(os.path.join(d.path, n))), key=_sort_key):
            sub = _Dir(nm, os.path.join(d.path, nm), d)
            d.dirs.append(sub)
            queue.append(sub)
        d.files = sorted((n for n in names if os.path.isfile(os.path.join(d.path, n))), key=_sort_key)
    return top


def _dir_table_order(top):
    """Root, then each directory's children are allocated together when it is
    visited, visiting depth-first."""
    out = [top]

    def visit(d):
        out.extend(d.dirs)
        for c in d.dirs:
            visit(c)

    visit(top)
    return out


def _preorder(top):
    out = [top]
    for c in top.dirs:
        out.extend(_preorder(c))
    return out


class _BlockHasher:
    """SHA-256 of each BLOCK-sized block of a byte stream (last block zero-padded)."""

    def __init__(self):
        self.buf = bytearray()
        self.hashes = []
        self.total = 0

    def update(self, data):
        self.total += len(data)
        self.buf += data
        if len(self.buf) >= BLOCK:
            n = len(self.buf) // BLOCK * BLOCK
            mv = memoryview(self.buf)
            for o in range(0, n, BLOCK):
                self.hashes.append(hashlib.sha256(mv[o : o + BLOCK]).digest())
            mv.release()
            del self.buf[:n]

    def finish(self):
        if self.buf:
            self.hashes.append(hashlib.sha256(bytes(self.buf) + b"\0" * (BLOCK - len(self.buf))).digest())
            self.buf = bytearray()
        return b"".join(self.hashes)


def _block_hashes(data):
    h = _BlockHasher()
    h.update(data)
    return h.finish()


def build_romfs(src_dir, out_path):
    """Write a RomFS image for src_dir to out_path. Returns its size."""
    top = _scan(src_dir)
    dirs = _dir_table_order(top)

    # directory metadata
    off = 0
    for d in dirs:
        d.off = off
        off += 0x18 + align(len(d.name.encode("utf-16-le")), 4)
    dir_meta_size = off
    # file metadata: files grouped by directory, directories in pre-order
    files = []
    off = 0
    for d in _preorder(top):
        for nm in d.files:
            files.append([d, nm, off, None, os.path.getsize(os.path.join(d.path, nm))])
            off += 0x20 + align(len(nm.encode("utf-16-le")), 4)
    file_meta_size = off

    dir_buckets = _hash_bucket_count(len(dirs))
    file_buckets = _hash_bucket_count(len(files))
    dir_table = [NONE] * dir_buckets
    file_table = [NONE] * file_buckets

    dir_meta = bytearray(dir_meta_size)
    first_file = {}
    for f in files:
        first_file.setdefault(id(f[0]), f[2])
    for d in dirs:
        parent = d.parent.off if d.parent else 0
        sibs = d.parent.dirs if d.parent else []
        k = sibs.index(d) if d.parent else -1
        nxt = sibs[k + 1].off if d.parent and k + 1 < len(sibs) else NONE
        child = d.dirs[0].off if d.dirs else NONE
        ffile = first_file.get(id(d), NONE)
        b = dir_table[_path_hash(parent, d.name) % dir_buckets]
        dir_table[_path_hash(parent, d.name) % dir_buckets] = d.off
        name = d.name.encode("utf-16-le")
        struct.pack_into("<6I", dir_meta, d.off, parent, nxt, child, ffile, b, len(name))
        dir_meta[d.off + 0x18 : d.off + 0x18 + len(name)] = name

    # file data offsets
    data_off = 0
    for f in files:
        data_off = align(data_off, 0x10)
        f[3] = data_off
        data_off += f[4]
    file_meta = bytearray(file_meta_size)
    for i, (d, nm, moff, doff, size) in enumerate(files):
        nxt = files[i + 1][2] if i + 1 < len(files) and files[i + 1][0] is d else NONE
        bucket = _path_hash(d.off, nm) % file_buckets
        b = file_table[bucket]
        file_table[bucket] = moff
        name = nm.encode("utf-16-le")
        struct.pack_into("<IIQQII", file_meta, moff, d.off, nxt, doff, size, b, len(name))
        file_meta[moff + 0x20 : moff + 0x20 + len(name)] = name

    hdr_len = 0x28
    dir_hash_off = hdr_len
    dir_meta_off = dir_hash_off + 4 * dir_buckets
    file_hash_off = dir_meta_off + dir_meta_size
    file_meta_off = file_hash_off + 4 * file_buckets
    data_base = align(file_meta_off + file_meta_size, 0x10)
    l3_head = bytearray(struct.pack(
        "<10I", hdr_len, dir_hash_off, 4 * dir_buckets, dir_meta_off, dir_meta_size,
        file_hash_off, 4 * file_buckets, file_meta_off, file_meta_size, data_base))
    l3_head += struct.pack(f"<{dir_buckets}I", *dir_table) + dir_meta
    l3_head += struct.pack(f"<{file_buckets}I", *file_table) + file_meta
    l3_head += b"\0" * (data_base - len(l3_head))
    l3_size = data_base + data_off

    # IVFC geometry
    l2_size = (align(l3_size, BLOCK) // BLOCK) * 0x20
    l1_size = (align(l2_size, BLOCK) // BLOCK) * 0x20
    master_size = (align(l1_size, BLOCK) // BLOCK) * 0x20
    l3_phys = align(0x60 + master_size, BLOCK)
    l1_phys = align(l3_phys + l3_size, BLOCK)
    l2_phys = align(l1_phys + l1_size, BLOCK)
    total = align(l2_phys + l2_size, BLOCK)
    l1_log, l2_log = 0, align(l1_size, BLOCK)
    l3_log = align(l2_log + l2_size, BLOCK)

    hasher = _BlockHasher()
    with open(out_path, "wb") as o:
        o.seek(l3_phys)
        o.write(l3_head)
        hasher.update(l3_head)
        pos = len(l3_head) - data_base
        for d, nm, moff, doff, size in files:
            if doff > pos:
                pad = b"\0" * (doff - pos)
                o.write(pad)
                hasher.update(pad)
                pos = doff
            with open(os.path.join(d.path, nm), "rb") as fh:
                while True:
                    chunk = fh.read(1 << 22)
                    if not chunk:
                        break
                    o.write(chunk)
                    hasher.update(chunk)
                    pos += len(chunk)
        l2 = hasher.finish()
        l1 = _block_hashes(l2)
        master = _block_hashes(l1)
        assert len(l2) == l2_size and len(l1) == l1_size and len(master) == master_size
        o.seek(l1_phys)
        o.write(l1)
        o.seek(l2_phys)
        o.write(l2)
        o.truncate(total)
        ivfc = struct.pack("<4sII", b"IVFC", 0x10000, master_size)
        for log, size in ((l1_log, l1_size), (l2_log, l2_size), (l3_log, l3_size)):
            ivfc += struct.pack("<QQII", log, size, 12, 0)
        ivfc += struct.pack("<I", 0x5C) + b"\0" * 8
        o.seek(0)
        o.write(ivfc + master)
    return total


def romfs_hash_region(romfs_path):
    """(hash region size in bytes, SHA-256 of it) for a built RomFS image."""
    with open(romfs_path, "rb") as f:
        head = f.read(0x60)
        master_size = struct.unpack_from("<I", head, 8)[0]
        size = align(0x60 + master_size, MU)
        f.seek(0)
        return size, hashlib.sha256(f.read(size)).digest()


# ------------------------------------------------------------------ ExeFS

def build_exefs(files):
    """files: list of (name, bytes). Returns the ExeFS image (header + data)."""
    hdr = bytearray(0x200)
    data = bytearray()
    for i, (name, blob) in enumerate(files):
        struct.pack_into("<8sII", hdr, i * 16, name.encode(), len(data), len(blob))
        hdr[0x1E0 - 0x20 * i : 0x200 - 0x20 * i] = hashlib.sha256(blob).digest()
        data += blob
        data += b"\0" * (-len(data) % MU)
    return bytes(hdr) + bytes(data)


# ------------------------------------------------------------------ NCCH / NCSD

def ncch_layout(header, exheader, logo, plain, exefs, romfs_size, romfs_hash_size, romfs_hash):
    """Return (header bytes, [(offset, bytes-or-None)]) for an NCCH; None = the RomFS."""
    h = bytearray(header)
    parts = []
    pos = 0x200
    parts.append((pos, exheader))
    struct.pack_into("<I", h, 0x180, 0x400)
    h[0x160:0x180] = hashlib.sha256(exheader[:0x400]).digest()
    pos += len(exheader)
    struct.pack_into("<II", h, 0x198, pos // MU, len(logo) // MU)
    h[0x130:0x150] = hashlib.sha256(logo).digest()
    parts.append((pos, logo))
    pos += len(logo)
    struct.pack_into("<II", h, 0x190, pos // MU, len(plain) // MU)
    parts.append((pos, plain))
    pos += len(plain)
    struct.pack_into("<III", h, 0x1A0, pos // MU, len(exefs) // MU, 1)
    h[0x1C0:0x1E0] = hashlib.sha256(exefs[:MU]).digest()
    parts.append((pos, exefs))
    pos = align(pos + len(exefs), BLOCK)
    struct.pack_into("<III", h, 0x1B0, pos // MU, romfs_size // MU, romfs_hash_size // MU)
    h[0x1E0:0x200] = romfs_hash
    parts.append((pos, None))
    pos += romfs_size
    struct.pack_into("<I", h, 0x104, pos // MU)
    return bytes(h), parts, pos


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "romfs":
        size = build_romfs(sys.argv[2], sys.argv[3])
        print(f"romfs: {sys.argv[3]} {size:#x} bytes")
    else:
        sys.exit(__doc__)
