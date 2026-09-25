#!/usr/bin/env python3
"""CRO0 / CRS (relocatable module) and CRR0 (module hash list) formats.

  cro.py info FILE.cro         header, segments, table sizes, hash check
  cro.py verify DIR            check every module's hashes and static.crr
  cro.py crr ORIG OUT CRO...   rebuild static.crr's hash list for these modules

Segment offsets ("segment tags") encode (offset << 4) | segment_index.
Four SHA-256 hashes at 0x0 cover: [0x80, code), [code, module name),
[module name, data), [data, data + size). static.crr holds the SHA-256 of
each module's 0x80-byte hash table.
"""
import glob
import hashlib
import os
import struct
import sys

SEG_TYPES = {0: "text", 1: "rodata", 2: "data", 3: "bss"}

# header field offsets
HDR = {
    "name_off": 0x84, "file_size": 0x90, "bss_size": 0x94,
    "control_object": 0xA0, "on_load": 0xA4, "on_exit": 0xA8, "on_unresolved": 0xAC,
    "code_off": 0xB0, "code_size": 0xB4, "data_off": 0xB8, "data_size": 0xBC,
    "module_name_off": 0xC0, "module_name_size": 0xC4,
}
# (offset, count) pairs and entry sizes
TABLES = {
    "segments": (0xC8, 12), "named_exports": (0xD0, 8), "indexed_exports": (0xD8, 4),
    "export_strings": (0xE0, 1), "export_trie": (0xE8, 8), "import_modules": (0xF0, 20),
    "import_relocs": (0xF8, 12), "named_imports": (0x100, 8), "indexed_imports": (0x108, 8),
    "anon_imports": (0x110, 8), "import_strings": (0x118, 1), "static_anon_params": (0x120, 8),
    "internal_relocs": (0x128, 12), "static_relocs": (0x130, 12),
}


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def cstr(b, o):
    return b[o : b.index(b"\0", o)].decode("ascii", "replace")


class Cro:
    def __init__(self, data, name=""):
        self.data = data
        self.name = name
        if data[0x80:0x84] not in (b"CRO0", b"FIXD"):
            raise ValueError(f"{name}: not a CRO (magic {data[0x80:0x84]!r})")
        self.hdr = {k: u32(data, o) for k, o in HDR.items()}
        self.tables = {k: (u32(data, o), u32(data, o + 4)) for k, (o, _) in TABLES.items()}
        so, sn = self.tables["segments"]
        self.segments = [struct.unpack_from("<III", data, so + 12 * i) for i in range(sn)]

    def table(self, name):
        off, num = self.tables[name]
        size = TABLES[name][1]
        return [self.data[off + size * i : off + size * (i + 1)] for i in range(num)]

    def seg_addr(self, tag):
        """File offset for a segment tag (segment index in bits 0-3)."""
        if tag == 0xFFFFFFFF:
            return None
        return self.segments[tag & 0xF][0] + (tag >> 4)

    def text(self):
        for off, size, kind in self.segments:
            if kind == 0 and size:
                return off, size
        return None

    def named_exports(self):
        return [(cstr(self.data, u32(e, 0)), u32(e, 4)) for e in self.table("named_exports")]

    def internal_relocs(self):
        """(target tag, type, referred segment, addend)."""
        out = []
        for e in self.table("internal_relocs"):
            tag, rtype, seg, _, _, addend = struct.unpack("<IBBBBi", e)
            out.append((tag, rtype, seg, addend))
        return out

    def import_relocs(self):
        """(target tag, type, is_last, addend)."""
        out = []
        for e in self.table("import_relocs"):
            tag, rtype, last, _, _, addend = struct.unpack("<IBBBBi", e)
            out.append((tag, rtype, last, addend))
        return out

    def named_imports(self):
        """(name, index of first import relocation)."""
        ro, _ = self.tables["import_relocs"]
        out = []
        for e in self.table("named_imports"):
            head = u32(e, 4)
            out.append((cstr(self.data, u32(e, 0)), (head - ro) // 12))
        return out

    def hash_ranges(self):
        h = self.hdr
        return [(0x80, h["code_off"]), (h["code_off"], h["module_name_off"]),
                (h["module_name_off"], h["data_off"]), (h["data_off"], h["data_off"] + h["data_size"])]

    def check_hashes(self):
        return [hashlib.sha256(self.data[a:b]).digest() == self.data[0x20 * i : 0x20 * (i + 1)]
                for i, (a, b) in enumerate(self.hash_ranges())]

    def rehash(self):
        """Return data with the four segment hashes recomputed."""
        d = bytearray(self.data)
        for i, (a, b) in enumerate(self.hash_ranges()):
            d[0x20 * i : 0x20 * (i + 1)] = hashlib.sha256(d[a:b]).digest()
        return bytes(d)


def crr_hashes(data):
    if data[:4] != b"CRR0":
        raise ValueError("not a CRR")
    off, num = u32(data, 0x350), u32(data, 0x354)
    return [data[off + 0x20 * i : off + 0x20 * (i + 1)] for i in range(num)]


def rebuild_crr(crr, cro_datas):
    """Replace the CRR hash list with hashes of the given modules, sorted like the
    original list (ascending byte order)."""
    d = bytearray(crr)
    off, num = u32(d, 0x350), u32(d, 0x354)
    hashes = sorted(hashlib.sha256(c[:0x80]).digest() for c in cro_datas)
    if len(hashes) != num:
        raise ValueError(f"CRR lists {num} modules, got {len(hashes)}")
    d[off : off + 0x20 * num] = b"".join(hashes)
    return bytes(d)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "info":
        c = Cro(open(sys.argv[2], "rb").read(), os.path.basename(sys.argv[2]))
        print(f"{c.name}: module {cstr(c.data, c.hdr['module_name_off'])!r}, file {c.hdr['file_size']:#x}")
        for off, size, kind in c.segments:
            if size:
                print(f"  segment {SEG_TYPES.get(kind, kind):6} file {off:#08x} size {size:#x}")
        for k, (off, num) in c.tables.items():
            print(f"  {k:18} @ {off:#08x} x {num}")
        print("  hashes:", ["ok" if ok else "BAD" for ok in c.check_hashes()])
        return
    if len(sys.argv) == 3 and sys.argv[1] == "verify":
        root = sys.argv[2]
        paths = sorted(glob.glob(os.path.join(root, "*.cro")))
        datas = [open(p, "rb").read() for p in paths]
        bad = [os.path.basename(p) for p, d in zip(paths, datas) if not all(Cro(d, p).check_hashes())]
        crr = open(os.path.join(root, ".crr", "static.crr"), "rb").read()
        listed = crr_hashes(crr)
        mine = {hashlib.sha256(d[:0x80]).digest() for d in datas}
        print(f"{len(paths)} modules, {len(bad)} with bad segment hashes {bad[:5]}")
        print(f"static.crr lists {len(listed)} hashes; {len(mine & set(listed))} match modules; "
              f"sorted: {listed == sorted(listed)}; rebuild identical: {rebuild_crr(crr, datas) == crr}")
        return
    if len(sys.argv) >= 4 and sys.argv[1] == "crr":
        crr = open(sys.argv[2], "rb").read()
        out = sys.argv[3]
        datas = [open(p, "rb").read() for p in sys.argv[4:]]
        open(out, "wb").write(rebuild_crr(crr, datas))
        return
    sys.exit(__doc__)


if __name__ == "__main__":
    main()
