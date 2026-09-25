#!/usr/bin/env python3
"""Recursive-traversal analysis of code.bin's .text.

Classifies every text word as code / literal / unknown and finds function
starts. Seeds: static.crs named functions, BL targets found while tracing,
text pointers in literal pools, text pointers in .rodata/.data that trace
cleanly (vtables, callback tables), and LR-saving prologues that directly
follow an unconditional return.

Writes orig/analysis.json:
  funcs     sorted list of [addr, name]
  code      sorted list of [start, end) runs of traced instructions
  literals  addresses of words loaded pc-relative (literal pools)
  jumptabs  addresses of words that are jump-table entries (data pointers)
  thumb     [start, end) regions of Thumb code (C library; kept raw)
"""
import json
import os
import struct
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..", "orig")

AL = 0xE


def sext24(v):
    return v - (1 << 24) if v & 0x800000 else v


class Text:
    def __init__(self):
        info = json.load(open(os.path.join(ROOT, "info.json")))
        ex = info["exheader"]
        self.base = ex["text"]["addr"]
        self.size = ex["text"]["size"]
        blob = open(os.path.join(ROOT, "exefs", "code.bin"), "rb").read()
        self.blob = blob
        self.words = struct.unpack_from(f"<{self.size // 4}I", blob, 0)
        self.end = self.base + self.size
        self.ro = (ex["rodata"]["addr"], ex["rodata"]["addr"] + ex["rodata"]["size"])
        self.data = (ex["data"]["addr"], ex["data"]["addr"] + ex["data"]["size"])
        self.ro_off = ex["rodata"]["addr"] - self.base
        self.data_off = ex["data"]["addr"] - self.base

    def w(self, a):
        return self.words[(a - self.base) >> 2]

    def in_text(self, a):
        return self.base <= a < self.end


def pc_load_targets(w, a):
    """Addresses of words read by a pc-relative load at a (list), else []."""
    cond = w >> 28
    if cond == 0xF:
        return []
    rn = (w >> 16) & 0xF
    if rn != 15:
        return []
    up = (w >> 23) & 1
    # LDR/LDRB immediate
    if (w >> 25) & 7 == 0b010 and (w >> 20) & 1:
        off = w & 0xFFF
        return [(a + 8 + (off if up else -off)) & ~3]
    # LDRH/LDRSH/LDRSB/LDRD immediate (extra load/store)
    if (w >> 25) & 7 == 0 and (w >> 22) & 1 and (w >> 7) & 1 and (w >> 4) & 1 and (w >> 5) & 3:
        off = ((w >> 4) & 0xF0) | (w & 0xF)
        t = a + 8 + (off if up else -off)
        sh = (w >> 5) & 3
        if not (w >> 20) & 1:  # L=0: LDRD (sh=2) / STRD (sh=3)
            return [t & ~3, (t & ~3) + 4] if sh == 2 else []
        return [t & ~3]
    # VLDR
    if w & 0x0F300E00 == 0x0D100A00:
        off = (w & 0xFF) * 4
        t = a + 8 + (off if up else -off)
        return [t, t + 4] if (w >> 8) & 1 else [t]
    return []


def branch(w, a):
    """(kind, target) for B/BL/BLX-imm; kind in 'b','bl','blx'."""
    if (w >> 25) & 7 != 0b101:
        return None
    t = a + 8 + (sext24(w & 0xFFFFFF) << 2)
    if w >> 28 == 0xF:
        return ("blx", t | 1 | ((w >> 23) & 2))
    return ("bl" if (w >> 24) & 1 else "b", t)


def writes_pc(w):
    """'ret' for returns / indirect jumps, 'jt_add' / 'jt_ldr' for jump tables."""
    if w >> 28 == 0xF:
        return None
    if w & 0x0FFFFFF0 == 0x012FFF10:  # BX reg
        return "ret"
    if (w >> 25) & 7 == 0b100 and (w >> 20) & 1 and (w >> 15) & 1:  # LDM ..., {..pc}
        return "ret"
    if (w >> 26) & 3 == 0b01 and (w >> 20) & 1 and (w >> 12) & 0xF == 15:  # LDR pc, ...
        if (w >> 16) & 0xF == 15 and (w >> 25) & 1:  # ldr pc, [pc, rX, lsl #2]
            return "jt_ldr"
        return "ret"
    if (w >> 26) & 3 == 0 and (w >> 12) & 0xF == 15:
        op = (w >> 21) & 0xF
        if not (w >> 25) & 1 and (w >> 4) & 9 == 9:  # multiply / extra load-store space
            return None
        if op in (8, 9, 10, 11):  # TST/TEQ/CMP/CMN, or MRS/MSR/CLZ... when S=0
            return None
        if op == 4 and (w >> 16) & 0xF == 15 and not (w >> 25) & 1:  # add pc, pc, rX, lsl #2
            return "jt_add"
        return "ret"
    return None


def cmp_bound(t, a):
    """Find `cmp rX, #imm` shortly before a (jump-table bound)."""
    for back in range(1, 5):
        p = a - 4 * back
        if not t.in_text(p):
            break
        w = t.w(p)
        if w & 0x0FF00000 == 0x03500000:  # CMP imm
            rot = ((w >> 8) & 0xF) * 2
            imm = w & 0xFF
            return ((imm >> rot) | (imm << (32 - rot))) & 0xFFFFFFFF if rot else imm
    return None


def analyze():
    t = Text()
    syms = []
    for line in open(os.path.join(ROOT, "symbols.tsv")).read().splitlines()[1:]:
        addr, mode, seg, mangled, dm = line.split("\t")
        if seg == "text":
            syms.append((int(addr, 16), mode, mangled))
    thumb_starts = sorted(a for a, m, _ in syms if m == "thumb")

    n = t.size // 4
    CODE, LIT, JT = 1, 2, 3
    kind = bytearray(n)
    func_starts = {a: name for a, m, name in syms if m == "arm"}
    thumb = set()

    def idx(a):
        return (a - t.base) >> 2

    # Thumb regions: from each thumb symbol until the next ARM function symbol
    arm_sorted = sorted(func_starts)
    import bisect

    thumb_regions = []
    for s in thumb_starts:
        j = bisect.bisect_right(arm_sorted, s)
        e = arm_sorted[j] if j < len(arm_sorted) else t.end
        if thumb_regions and thumb_regions[-1][1] >= s:
            thumb_regions[-1][1] = max(thumb_regions[-1][1], e)
        else:
            thumb_regions.append([s, e])
    for s, e in thumb_regions:
        for a in range(s, e, 4):
            thumb.add(idx(a))

    work = list(func_starts)
    seen_start = set()

    def trace(start):
        """Trace one entry point; returns False if it hit an invalid spot."""
        stack = [start]
        while stack:
            a = stack.pop()
            while True:
                if not t.in_text(a) or a & 3:
                    break
                i = idx(a)
                if kind[i] == CODE or i in thumb:
                    break
                if kind[i] in (LIT, JT):
                    break
                w = t.w(a)
                kind[i] = CODE
                for lt in pc_load_targets(w, a):
                    if t.in_text(lt) and kind[idx(lt)] != CODE:
                        kind[idx(lt)] = LIT
                br = branch(w, a)
                cond = w >> 28
                if br:
                    k, tgt = br
                    if k == "bl" and t.in_text(tgt):
                        if tgt not in func_starts:
                            func_starts[tgt] = None
                            work.append(tgt)
                    elif k == "b" and t.in_text(tgt):
                        stack.append(tgt)
                        if cond == AL:
                            break
                wp = writes_pc(w)
                if wp == "jt_add":
                    bound = cmp_bound(t, a)
                    count = (bound + 1 if bound is not None else 0) + 1  # default branch + cases
                    for k2 in range(1, count + 1):
                        e = a + 4 * k2
                        if t.in_text(e) and branch(t.w(e), e):
                            stack.append(e)
                    if cond == AL:
                        break
                elif wp == "jt_ldr":
                    bound = cmp_bound(t, a)
                    if bound is not None:
                        # layout: ldrls pc,[pc,rX,lsl#2]; b default; .word case0..caseN
                        stack.append(a + 4)
                        for k2 in range(bound + 1):
                            e = a + 8 + 4 * k2
                            if t.in_text(e):
                                kind[idx(e)] = JT
                                tgt = t.w(e)
                                if t.in_text(tgt):
                                    stack.append(tgt)
                    break
                elif wp == "ret" and cond == AL:
                    break
                a += 4

    def drain():
        while work:
            s = work.pop()
            if s in seen_start:
                continue
            seen_start.add(s)
            trace(s)

    drain()
    traced_seed = len(func_starts)

    # literal-pool / data pointers into text that look like code entry points
    def looks_like_code(a):
        if not t.in_text(a) or a & 3 or idx(a) in thumb or kind[idx(a)] in (LIT, JT):
            return False
        w = t.w(a)
        return w >> 28 == AL and w != 0 and w != 0xFFFFFFFF

    def pointer_seeds(words_iter):
        new = 0
        for v in words_iter:
            if looks_like_code(v) and v not in func_starts:
                if kind[idx(v)] == CODE:
                    continue  # points into middle of traced code: a label, not a function
                func_starts[v] = None
                work.append(v)
                new += 1
        return new

    lit_ptrs = pointer_seeds(t.w(a) for a in range(t.base, t.end, 4) if kind[idx(a)] == LIT)
    drain()
    ro = t.blob[t.ro_off : t.ro_off + (t.ro[1] - t.ro[0]) // 4 * 4]
    da = t.blob[t.data_off : t.data_off + (t.data[1] - t.data[0]) // 4 * 4]
    data_ptrs = pointer_seeds(struct.unpack(f"<{len(ro) // 4}I", ro) + struct.unpack(f"<{len(da) // 4}I", da))
    drain()

    # .init_array: armcc emits static-constructor tables as place-relative
    # offsets. Find long runs of rodata words where (address + word) is code.
    ro_words = struct.unpack(f"<{len(ro) // 4}I", ro)
    rel_targets, run = [], []
    for k, v in enumerate(ro_words + (0,)):
        tgt = (t.ro[0] + 4 * k + v) & 0xFFFFFFFF
        if k < len(ro_words) and looks_like_code(tgt):
            run.append(tgt)
            continue
        if len(run) >= 16:
            rel_targets.extend(run)
        run = []
    init_ptrs = pointer_seeds(rel_targets)
    drain()

    # prologues right after an unconditional return, in untraced space
    prologue_seeds = 0
    for rounds in range(3):
        added = 0
        for i in range(1, n):
            if kind[i] or i in thumb or not kind[i - 1] in (CODE, LIT):
                continue
            w = t.words[i]
            if w & 0xFFFF4000 == 0xE92D4000 or w == 0xE52DE004:
                a = t.base + 4 * i
                if a not in func_starts:
                    func_starts[a] = None
                    work.append(a)
                    added += 1
        drain()
        prologue_seeds += added
        if not added:
            break

    counts = {k: kind.count(k) for k in (0, CODE, LIT, JT)}
    thumb_words = len(thumb)

    def runs(val):
        out, s = [], None
        for i in range(n + 1):
            on = i < n and kind[i] == val and i not in thumb
            if on and s is None:
                s = i
            elif not on and s is not None:
                out.append([t.base + 4 * s, t.base + 4 * i])
                s = None
        return out

    result = {
        "funcs": sorted([a, nm] for a, nm in func_starts.items()),
        "code": runs(CODE),
        "literals": [t.base + 4 * i for i in range(n) if kind[i] == LIT],
        "jumptabs": [t.base + 4 * i for i in range(n) if kind[i] == JT],
        "thumb": thumb_regions,
    }
    json.dump(result, open(os.path.join(ROOT, "analysis.json"), "w"))

    named = sum(1 for _, nm in func_starts.items() if nm)
    print(f"functions: {len(func_starts)} ({named} named; {traced_seed - named} from calls, "
          f"{lit_ptrs} literal ptrs, {data_ptrs} data ptrs, {init_ptrs} init_array, {prologue_seeds} prologues)")
    tot = n
    print(f"text words: {tot}  code {counts[CODE] / tot:.1%}  literal {counts[LIT] / tot:.1%}  "
          f"jumptable {counts[JT] / tot:.1%}  thumb {thumb_words / tot:.1%}  "
          f"unknown {(counts[0] - thumb_words) / tot:.1%}")


if __name__ == "__main__":
    analyze()
