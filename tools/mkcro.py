#!/usr/bin/env python3
"""Rebuild a CRO module with newly built .text.

  mkcro.py ORIG.cro TEXT.bin OUT.cro

Replaces the module's .text segment with TEXT.bin (which must have the same
size; relocation tables are taken from ORIG) and recomputes the four segment
hashes in the header.
"""
import sys

from cro import Cro


def main():
    orig_path, text_path, out_path = sys.argv[1:4]
    c = Cro(open(orig_path, "rb").read(), orig_path)
    off, size = c.text()
    text = open(text_path, "rb").read()
    if len(text) != size:
        sys.exit(f"{text_path}: {len(text):#x} bytes, module .text is {size:#x}")
    data = c.data[:off] + text + c.data[off + size :]
    with open(out_path, "wb") as f:
        f.write(Cro(data, out_path).rehash())


if __name__ == "__main__":
    main()
