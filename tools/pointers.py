#!/usr/bin/env python3
"""Heuristics for recognising pointers in code.bin, which has no relocations.

A word is treated as a pointer when its value lies inside the executable's
memory image (.text through the end of .bss) and it isn't one of the common
look-alikes:
  * UTF-16 text: two ASCII characters stored as UTF-16 (0x00HH00LL) fall in
    the address range, e.g. "_N" = 0x004E005F;
  * round constants (multiples of 0x10000), typically sizes such as 0x200000.
Callers apply further target checks (code pointers must hit a function or a
traced instruction, Thumb pointers must be odd, ...).
"""


def utf16_like(v):
    b = v.to_bytes(4, "little")
    return b[1] == 0 and b[3] == 0 and 0x20 <= b[0] < 0x7F and (0x20 <= b[2] < 0x7F or b[2] == 0)


def looks_like_pointer(v, t):
    """t: analyze.Text (base, ro, data, bss_end)."""
    if not (t.base <= v < t.bss_end):
        return False
    if v % 0x10000 == 0 or utf16_like(v):
        return False
    return True
