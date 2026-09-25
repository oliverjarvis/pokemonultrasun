#!/usr/bin/env python3
"""Rebuild static.crs, the static module's (code.bin's) CRO-format symbol file.

  crslink.py ORIG.crs OUT.crs

static.crs imports from CRO modules anonymously (raw segment offsets). Each
of those offsets is re-resolved from the target module's linked ELF (see
crolink.target_tag), so they stay correct when a module changes size; the
four segment hashes are then recomputed.
"""
import struct
import sys

from cro import Cro, cstr
from crolink import target_tag


def main():
    orig_path, out_path = sys.argv[1:3]
    c = Cro(open(orig_path, "rb").read(), orig_path)
    d = bytearray(c.data)
    ao, _ = c.tables["anon_imports"]
    for e in c.table("import_modules"):
        name_off, ihead, inum, ahead, anum = struct.unpack("<5I", e)
        target = cstr(c.data, name_off)
        for k in range((ahead - ao) // 8, (ahead - ao) // 8 + anum):
            tag = struct.unpack_from("<I", d, ao + 8 * k)[0]
            struct.pack_into("<I", d, ao + 8 * k, target_tag(target, tag))
    with open(out_path, "wb") as f:
        f.write(Cro(bytes(d), out_path).rehash())


if __name__ == "__main__":
    main()
