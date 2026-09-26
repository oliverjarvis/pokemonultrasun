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
        self.bss_end = self.data[1] + ex["bss_size"]

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


def sext(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def thumb_call(h1, h2, a):
    """Decode a Thumb-1 BL/BLX pair at a: ("bl"|"blx", target) or None."""
    if h1 & 0xF800 != 0xF000:
        return None
    off = sext(((h1 & 0x7FF) << 12) | ((h2 & 0x7FF) << 1), 23)
    if h2 & 0xF800 == 0xF800:
        return ("bl", a + 4 + off)
    if h2 & 0xF800 == 0xE800:
        return ("blx", (a + 4 + off) & ~3)
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


CODE, LIT, JT = 1, 2, 3


class Tracer:
    """Recursive-traversal classifier for one ARM code region.

    words: the region's 32-bit words; base: address of words[0];
    thumb: word indices to leave alone; literals: addresses known to be data
    (e.g. relocated words), marked before tracing.
    """

    def __init__(self, words, base, thumb=(), literals=()):
        self.words, self.base = words, base
        self.end = base + 4 * len(words)
        self.kind = bytearray(len(words))
        self.thumb = set(thumb)
        self.funcs = {}
        self.work = []
        self.seen = set()
        for a in literals:
            if self.in_text(a):
                self.kind[self.idx(a)] = LIT

    def idx(self, a):
        return (a - self.base) >> 2

    def w(self, a):
        return self.words[(a - self.base) >> 2]

    def in_text(self, a):
        return self.base <= a < self.end

    def seed(self, a, name=None):
        """Add a function start; returns True if it is new."""
        if a in self.funcs:
            if name and not self.funcs[a]:
                self.funcs[a] = name
            return False
        self.funcs[a] = name
        self.work.append(a)
        return True

    def trace(self, start):
        kind = self.kind
        stack = [start]
        while stack:
            a = stack.pop()
            while True:
                if not self.in_text(a) or a & 3:
                    break
                i = self.idx(a)
                if kind[i] == CODE or i in self.thumb:
                    break
                if kind[i] in (LIT, JT):
                    break
                w = self.words[i]
                kind[i] = CODE
                for lt in pc_load_targets(w, a):
                    if self.in_text(lt) and kind[self.idx(lt)] != CODE:
                        kind[self.idx(lt)] = LIT
                br = branch(w, a)
                cond = w >> 28
                if br:
                    k, tgt = br
                    if k == "bl" and self.in_text(tgt):
                        self.seed(tgt)
                    elif k == "b" and self.in_text(tgt):
                        stack.append(tgt)
                        if cond == AL:
                            break
                wp = writes_pc(w)
                # cases 0..bound for `ls` (<=), 0..bound-1 for `lo`/`cc` (<)
                inclusive = cond != 0x3
                if wp == "jt_add":
                    bound = cmp_bound(self, a)
                    cases = (bound + (1 if inclusive else 0)) if bound is not None else 0
                    count = cases + 1  # default branch + cases
                    for k2 in range(1, count + 1):
                        e = a + 4 * k2
                        if self.in_text(e) and branch(self.w(e), e):
                            stack.append(e)
                    if cond == AL:
                        break
                elif wp == "jt_ldr":
                    bound = cmp_bound(self, a)
                    if bound is not None:
                        # layout: ldrls pc,[pc,rX,lsl#2]; b default; .word case0..caseN
                        stack.append(a + 4)
                        for k2 in range(bound + (1 if inclusive else 0)):
                            e = a + 8 + 4 * k2
                            if self.in_text(e):
                                kind[self.idx(e)] = JT
                                tgt = self.w(e)
                                if self.in_text(tgt):
                                    stack.append(tgt)
                    break
                elif wp == "ret" and cond == AL:
                    break
                a += 4

    def drain(self):
        while self.work:
            s = self.work.pop()
            if s in self.seen:
                continue
            self.seen.add(s)
            self.trace(s)

    def looks_like_code(self, a):
        if not self.in_text(a) or a & 3 or self.idx(a) in self.thumb or self.kind[self.idx(a)] in (LIT, JT):
            return False
        w = self.w(a)
        return w >> 28 == AL and w != 0 and w != 0xFFFFFFFF

    def pointer_seeds(self, values):
        """Seed function starts from pointer values that land on untraced code."""
        new = 0
        for v in values:
            if self.looks_like_code(v) and v not in self.funcs:
                if self.kind[self.idx(v)] == CODE:
                    continue  # points into middle of traced code: a label, not a function
                self.seed(v)
                new += 1
        self.drain()
        return new

    def prologue_seeds(self):
        """Seed LR-saving prologues that directly follow code or a literal pool."""
        total = 0
        for _ in range(3):
            added = 0
            for i in range(1, len(self.words)):
                if self.kind[i] or i in self.thumb or self.kind[i - 1] not in (CODE, LIT):
                    continue
                w = self.words[i]
                if w & 0xFFFF4000 == 0xE92D4000 or w == 0xE52DE004:
                    if self.seed(self.base + 4 * i):
                        added += 1
            self.drain()
            total += added
            if not added:
                break
        return total

    def gap_seeds(self, max_len=256):
        """Seed untraced gaps that hold ARM code (see _code_run), at the gap start or
        at an LR-saving prologue inside it. Code that nothing seeds (a function
        after a return, reached only indirectly) would otherwise stay raw words
        with position-dependent branches inside."""
        import capstone

        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        total = 0
        for _ in range(8):
            added = 0
            i, n = 0, len(self.words)
            while i < n:
                if self.kind[i] or i in self.thumb:
                    i += 1
                    continue
                j = i
                while j < n and not self.kind[j] and j not in self.thumb:
                    j += 1
                # candidate starts: the gap start, and any LR-saving prologue inside it
                starts = [i] + [x for x in range(i + 1, j)
                                if self.words[x] & 0xFFFF4000 == 0xE92D4000 or self.words[x] == 0xE52DE004]
                for c in starts:
                    if self._code_run(c, j, md, max_len) and self.seed(self.base + 4 * c):
                        added += 1
                i = j
            self.drain()
            total += added
            if not added:
                break
        return total

    def _code_run(self, i, j, md, max_len):
        """Words from index i decode as plausible ARM code up to an unconditional
        return/branch: unconditional first instruction, no zero or small-number
        words (top byte 0), no LDRD/STRD with an odd register, targets in .text."""
        if self.words[i] >> 28 != AL:
            return False
        k = i
        while k < j and k - i < max_len:
            w = self.words[k]
            a = self.base + 4 * k
            if w >> 24 == 0 or next(md.disasm(struct.pack("<I", w), a), None) is None:
                return False
            if w & 0x0E1000D0 == 0x000000D0 and (w >> 12) & 1:  # LDRD/STRD (L=0, SH=1x) with odd Rt
                return False
            if any(not self.in_text(lt) for lt in pc_load_targets(w, a)):
                return False
            br = branch(w, a)
            if br and not self.in_text(br[1] & ~1):
                return False
            if w >> 28 == AL and (writes_pc(w) == "ret" or (br and br[0] == "b")):
                return True
            k += 1
        return False

    def runs(self, val):
        out, s = [], None
        n = len(self.words)
        for i in range(n + 1):
            on = i < n and self.kind[i] == val and i not in self.thumb
            if on and s is None:
                s = i
            elif not on and s is not None:
                out.append([self.base + 4 * s, self.base + 4 * i])
                s = None
        return out

    def result(self):
        n = len(self.words)
        return {
            "funcs": sorted([a, nm] for a, nm in self.funcs.items()),
            "code": self.runs(CODE),
            "literals": [self.base + 4 * i for i in range(n) if self.kind[i] == LIT],
            "jumptabs": [self.base + 4 * i for i in range(n) if self.kind[i] == JT],
        }

    def summary(self):
        n = len(self.words)
        counts = {k: self.kind.count(k) for k in (0, CODE, LIT, JT)}
        th = len(self.thumb)
        return (f"words: {n}  code {counts[CODE] / n:.1%}  literal {counts[LIT] / n:.1%}  "
                f"jumptable {counts[JT] / n:.1%}  thumb {th / n:.1%}  unknown {(counts[0] - th) / n:.1%}")


def carve_arm_from_thumb(t, tr, regions):
    """ARM code inside the Thumb library regions (ARM-state entry stubs such as
    `add ip, pc, #1; bx ip`, small ARM helpers): every ARM b/bl target and
    Thumb BLX target that lands in a Thumb region is ARM code. Trace each one
    as ARM (the words it reaches stop being Thumb) and repeat until stable."""
    carved = 0
    while True:
        entries = set()
        for i, k in enumerate(tr.kind):
            if k != CODE:
                continue
            a = t.base + 4 * i
            br = branch(t.words[i], a)
            if br and br[0] != "blx" and tr.idx(br[1]) in tr.thumb:
                entries.add(br[1])
        for s, e in regions:
            for a in range(s, e - 2, 2):
                if tr.idx(a) not in tr.thumb:
                    continue
                h1, h2 = (struct.unpack_from("<H", t.blob, x - t.base)[0] for x in (a, a + 2))
                c = thumb_call(h1, h2, a)
                if c and c[0] == "blx" and tr.in_text(c[1]) and tr.idx(c[1]) in tr.thumb:
                    entries.add(c[1])
        if not entries:
            return carved
        for a in sorted(entries):
            # linear ARM walk to find the words this entry covers
            p = a
            while tr.in_text(p) and tr.idx(p) in tr.thumb:
                w = tr.w(p)
                tr.thumb.discard(tr.idx(p))
                for lt in pc_load_targets(w, p):
                    tr.thumb.discard(tr.idx(lt))
                if (writes_pc(w) == "ret" or (branch(w, p) and branch(w, p)[0] == "b")) and w >> 28 == AL:
                    break
                p += 4
            tr.seed(a)
            tr.seen.discard(a)  # it may have been reached before (and stopped at the Thumb boundary)
            tr.work.append(a)
            carved += 1
        tr.drain()


def thumb_runs(tr):
    """Contiguous [start, end) runs of the remaining Thumb words."""
    out = []
    for i in sorted(tr.thumb):
        a = tr.base + 4 * i
        if out and out[-1][1] == a:
            out[-1][1] = a + 4
        else:
            out.append([a, a + 4])
    return out


def analyze():
    import bisect

    t = Text()
    syms = []
    for line in open(os.path.join(ROOT, "symbols.tsv")).read().splitlines()[1:]:
        addr, mode, seg, mangled, dm = line.split("\t")
        if seg == "text":
            syms.append((int(addr, 16), mode, mangled))
    thumb_starts = sorted(a for a, m, _ in syms if m == "thumb")
    arm_sorted = sorted(a for a, m, _ in syms if m == "arm")

    # Thumb regions: from each thumb symbol until the next ARM function symbol
    thumb_regions = []
    for s in thumb_starts:
        j = bisect.bisect_right(arm_sorted, s)
        e = arm_sorted[j] if j < len(arm_sorted) else t.end
        if thumb_regions and thumb_regions[-1][1] >= s:
            thumb_regions[-1][1] = max(thumb_regions[-1][1], e)
        else:
            thumb_regions.append([s, e])
    thumb = {(a - t.base) >> 2 for s, e in thumb_regions for a in range(s, e, 4)}

    tr = Tracer(t.words, t.base, thumb)
    for a, m, name in syms:
        if m == "arm":
            tr.seed(a, name)
    named = len(tr.funcs)
    tr.drain()
    carved = carve_arm_from_thumb(t, tr, thumb_regions)
    traced_seed = len(tr.funcs)

    # literal-pool / data pointers into text that look like code entry points
    lit_ptrs = tr.pointer_seeds(t.w(a) for a in range(t.base, t.end, 4) if tr.kind[tr.idx(a)] == LIT)
    ro = t.blob[t.ro_off : t.ro_off + (t.ro[1] - t.ro[0]) // 4 * 4]
    da = t.blob[t.data_off : t.data_off + (t.data[1] - t.data[0]) // 4 * 4]
    data_ptrs = tr.pointer_seeds(struct.unpack(f"<{len(ro) // 4}I", ro) + struct.unpack(f"<{len(da) // 4}I", da))

    # .init_array: armcc emits static-constructor tables as place-relative
    # offsets. Find long runs of rodata words where (address + word) is code.
    ro_words = struct.unpack(f"<{len(ro) // 4}I", ro)
    rel_targets, run = [], []
    for k, v in enumerate(ro_words + (0,)):
        tgt = (t.ro[0] + 4 * k + v) & 0xFFFFFFFF
        if k < len(ro_words) and tr.looks_like_code(tgt):
            run.append(tgt)
            continue
        if len(run) >= 16:
            rel_targets.extend(run)
        run = []
    init_ptrs = tr.pointer_seeds(rel_targets)
    prologue_seeds = tr.prologue_seeds()
    gap_seeds = tr.gap_seeds()
    prologue_seeds += tr.prologue_seeds()
    carved += carve_arm_from_thumb(t, tr, thumb_regions)  # code found since may branch into Thumb too

    result = tr.result()
    result["thumb"] = thumb_runs(tr)
    json.dump(result, open(os.path.join(ROOT, "analysis.json"), "w"))
    print(f"carved {carved} ARM entry points out of Thumb regions")
    print(f"functions: {len(tr.funcs)} ({named} named; {traced_seed - named} from calls, "
          f"{lit_ptrs} literal ptrs, {data_ptrs} data ptrs, {init_ptrs} init_array, {prologue_seeds} prologues, {gap_seeds} code gaps)")
    print("text " + tr.summary())


if __name__ == "__main__":
    analyze()
