#!/usr/bin/env python3
"""Zero-pad a built code.bin to a whole number of 0x1000-byte pages."""
import os
import sys

path = sys.argv[1]
size = os.path.getsize(path)
with open(path, "ab") as f:
    f.write(b"\0" * (-size % 0x1000))
