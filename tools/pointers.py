#!/usr/bin/env python3
"""Heuristics for recognising pointers in code.bin, which has no relocations.

A word is a pointer candidate when its value lies inside the executable's
memory image (.text through the end of .bss) and isn't a multiple of 0x10000
(typically a size such as 0x200000; in data such a value still counts when it
is a function start next to other code pointers, as in a vtable). Context then
removes look-alikes:

  * UTF-16 text: two ASCII characters stored as UTF-16 (0x00HH00LL) fall in
    the address range ("_N" = 0x004E005F). A UTF-16-like word is text when a
    neighbouring word is UTF-16-like too; an isolated one (e.g. a vtable
    entry that happens to be 0x0036004C) stays a candidate.
  * ASCII string tails: "LYT\\0" = 0x0054594C; three printable bytes and a NUL
    after a word of printable ASCII.
  * tables of small 16-bit pairs (0x00140040): both halves below 0x100 and
    neighbours of the same shape. Code addresses always have a small high
    half, so this only counts against weaker evidence (see classify()).
  * index columns: a struct field whose high half counts up by one from
    entry to entry (0x00110020, 0x00120098, 0x00130000 at a fixed stride).

See classify() for how the evidence is weighed.
"""


def utf16_like(v):
    b = v.to_bytes(4, "little")
    return b[1] == 0 and b[3] == 0 and 0x20 <= b[0] < 0x7F and (0x20 <= b[2] < 0x7F or b[2] == 0)


def printable(b):
    return 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D)


def ascii_word(v):
    return all(printable(b) for b in v.to_bytes(4, "little"))


def ascii_tail(v):
    b = v.to_bytes(4, "little")
    return b[3] == 0 and printable(b[0]) and printable(b[1]) and printable(b[2])


def small_pair(v):
    return (v >> 16) < 0x100 and (v & 0xFFFF) < 0x100


def in_image(v, t, round_ok=False):
    return t.base <= v < t.bss_end and (round_ok or v % 0x10000 != 0)


def looks_like_pointer(v, t):
    """Context-free check, for literal pools in .text (the code loads them, so
    text and number tables don't apply there)."""
    return in_image(v, t)


def classify(words, t, is_func, is_code, in_thumb):
    """Pointer words in a data segment.

    words: {address: value} for every aligned word of .rodata/.data.
    is_func(tgt): tgt is a function start / Thumb function; is_code(tgt): tgt is
    a traced instruction. Returns {address: ("text" | "data", value)}.

    Evidence is tiered: a function-start target is only rejected as text or
    inside a table of small 16-bit pairs (both neighbours);
    a function start at a multiple of 0x10000 (usually a size) and
    a mid-function target also need an accepted code pointer within two
    words and must not look like a small-number table; a data target is
    rejected as text or when both neighbours are small 16-bit pairs.
    """
    def text(a, v):
        prev, nxt = words.get(a - 4, 0), words.get(a + 4, 0)
        return (utf16_like(v) and (utf16_like(prev) or utf16_like(nxt))) or (ascii_tail(v) and ascii_word(prev))

    def pair_table(a, v, both):
        prev, nxt = words.get(a - 4, 0), words.get(a + 4, 0)
        if not small_pair(v):
            return False
        return (small_pair(prev) and small_pair(nxt)) if both else (small_pair(prev) or small_pair(nxt))

    def counter_column(a, v):
        """A struct field counting up by one in its high half (0x00100090,
        0x00110020, 0x00120098 at a fixed stride): an index, not an address."""
        def fits(k, s):
            w = words.get(a + k * s)
            return w is not None and w & 0xFFFF < 0x100 and (w >> 16) == (v >> 16) + k
        if v & 0xFFFF >= 0x100:
            return False
        return any((fits(-1, s) and fits(1, s)) or (fits(1, s) and fits(2, s)) or (fits(-1, s) and fits(-2, s))
                   for s in (4, 8, 12, 16))

    out = {}
    pending = []  # mid-code targets, decided once function pointers are known
    for a, v in words.items():
        if not in_image(v, t, round_ok=True) or text(a, v) or counter_column(a, v):
            continue
        if not in_image(v, t):
            # e.g. a vtable entry for a function at 0x450000
            if t.in_text(v) and is_func(v) and not in_thumb(v):
                pending.append((a, v))
            continue
        if t.in_text(v):
            tgt = v & ~1
            if v & 1:
                if in_thumb(tgt) and is_func(tgt):
                    out[a] = ("text", v)
            elif tgt % 4 == 0 and not in_thumb(tgt):
                if is_func(tgt):
                    if not pair_table(a, v, both=True):
                        out[a] = ("text", v)
                elif is_code(tgt) and not pair_table(a, v, both=False):
                    pending.append((a, v))
        elif not pair_table(a, v, both=True):
            out[a] = ("data", v)
    for a, v in pending:
        if any(out.get(a + 4 * k, ("",))[0] == "text" for k in (-2, -1, 1, 2)):
            out[a] = ("text", v)
    return out
