#!/usr/bin/env python3
"""Zero-pad a built code.bin to the size of the original (page-aligned segments)."""
import os
import sys

ORIG = os.path.join(os.path.dirname(__file__), "..", "orig", "exefs", "code.bin")

path = sys.argv[1]
size = os.path.getsize(path)
want = os.path.getsize(ORIG)
if size > want:
    sys.exit(f"{path}: {size:#x} bytes, larger than original {want:#x}")
with open(path, "ab") as f:
    f.write(b"\0" * (want - size))
