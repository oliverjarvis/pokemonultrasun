#!/usr/bin/env python3
"""Emit per-function GNU-as units for a traced ARM code region.

Used by split.py (code.bin) and cro_split.py (CRO modules). A region is
described by its words, base address, word classification (analyze.CODE /
LIT / JT) and function starts; how data words are symbolized is up to the
caller's `word_ref(addr, word)` callback, which returns one of:
  None                     keep the raw value
  ("text", target, suffix) reference to a text address in this region
  ("expr", text)           an arbitrary assembler expression
  ("rel", target, base)    target - base, both text addresses (offset tables)
  ("raw", comment)         keep the raw value, with a trailing comment
`labels` are addresses that need a global label (referenced from elsewhere).

Units that load literals from each other (code built without per-function
sections shares literal pools) are merged, so every pc-relative load stays
inside its unit; the merged function starts keep their names as global
labels. `thumb` regions ([start, end) of Thumb code) become their own units:
raw halfwords, except BL/BLX calls and literal-pool pointers, which are
symbolic, and Thumb function labels at every entry point used elsewhere.
ARM `blx` calls into them are symbolic too.
"""
import bisect
import os
import re
import shutil
import struct

import capstone

from analyze import CODE, JT, LIT, branch, pc_load_targets, thumb_call

PC_REL = re.compile(r"\[pc, #(-?0x[0-9a-f]+|-?\d+)\]")


def adr_target(w, a):
    """Address formed by `add/sub rd, pc, #imm` (ADR) at a, or None."""
    if (w >> 25) & 7 != 0b001 or (w >> 16) & 0xF != 15 or (w >> 20) & 1 or (w >> 12) & 0xF == 15:
        return None
    op = (w >> 21) & 0xF
    if op not in (2, 4) or w >> 28 == 0xF:  # SUB / ADD
        return None
    rot, imm = ((w >> 8) & 0xF) * 2, w & 0xFF
    v = ((imm >> rot) | (imm << (32 - rot))) & 0xFFFFFFFF if rot else imm
    return (a + 8 + v if op == 4 else a + 8 - v) & 0xFFFFFFFF


class Region:
    def __init__(self, words, base, blob, kind, starts, names=None, force_raw=(), word_ref=None, labels=(),
                 thumb=(), pcrel=None, data_sym=None):
        self.words, self.base, self.blob, self.kind = words, base, blob, kind
        self.extra_labels = set(labels)  # addresses referenced from outside the region
        self.end = base + 4 * len(words)
        self.thumb = sorted((s, e) for s, e in thumb)
        self.names = dict(names or {})
        self.force_raw = set(force_raw)
        self.word_ref = word_ref or (lambda a, w: None)
        # pc-relative literals: {literal addr: (anchor addr, pc bias)} where the code
        # does `ldr rX, =lit; add rX, pc` and the literal is target - (anchor + bias)
        self.pcrel = pcrel or {}
        self.data_sym = data_sym or (lambda a: f"data_{a:08X}")
        starts = set(starts) | {base}
        for s, e in self.thumb:
            starts -= {a for a in starts if s < a < e}
            starts |= {s} | ({e} if e < self.end else set())
        self.starts = sorted(starts)
        self._merge_shared_pools()

    # ---- helpers
    def in_text(self, a):
        return self.base <= a < self.end

    def in_thumb(self, a):
        i = bisect.bisect_right(self.thumb, (a, 1 << 40)) - 1
        return i >= 0 and self.thumb[i][0] <= a < self.thumb[i][1]

    def unit_of(self, a):
        return bisect.bisect_right(self.starts, a) - 1

    def unit_sym(self, a):
        return self.names.get(a) or f"sub_{a:08X}"

    def thumb_sym(self, a):
        return self.names.get(a) or f"thumb_{a:08X}"

    def w(self, a):
        return self.words[(a - self.base) >> 2]

    def hw(self, a):
        return struct.unpack_from("<H", self.blob, a - self.base)[0]

    def _merge_shared_pools(self):
        """Merge runs of units linked by pc-relative loads or ADRs across unit
        boundaries (an ADR into Thumb code keeps a relocation instead)."""
        spans = []
        for i, w in enumerate(self.words):
            a = self.base + 4 * i
            if self.kind[i] != CODE or a in self.force_raw or self.in_thumb(a):
                continue
            targets = [lt & ~3 for lt in pc_load_targets(w, a)]
            t = adr_target(w, a)
            if t is not None:  # ADR: its offset must not change either
                targets.append(t & ~3)
            for lt in targets:
                if self.in_text(lt) and not self.in_thumb(lt):
                    us, ut = self.unit_of(a), self.unit_of(lt)
                    if us != ut:
                        spans.append((min(us, ut), max(us, ut)))
        if not spans:
            return
        drop = set()
        spans.sort()
        cur_s, cur_e = spans[0]
        for s, e in spans[1:] + [(1 << 40, 1 << 40)]:
            if s <= cur_e:
                cur_e = max(cur_e, e)
                continue
            for u in range(cur_s + 1, cur_e + 1):
                drop.add(self.starts[u])
            cur_s, cur_e = s, e
        for a in drop:
            self.names.setdefault(a, f"sub_{a:08X}")  # keep the name as an inner global label
        self.merged = len(drop)
        self.starts = [a for a in self.starts if a not in drop]

    # ---- labels
    def _labels(self):
        local, glob, thumb_labels = set(), set(), set()

        def ref(src, tgt, arm=False):
            if self.in_thumb(tgt):
                if arm:
                    raise ValueError(f"ARM-state reference from {src:#x} into Thumb code at {tgt:#x}")
                thumb_labels.add(tgt)
                return
            if tgt in self.starts or tgt in self.names:
                return
            (local if self.unit_of(src) == self.unit_of(tgt) else glob).add(tgt)

        for i, w in enumerate(self.words):
            a = self.base + 4 * i
            if a in self.force_raw:
                continue
            if self.in_thumb(a):
                continue
            k = self.kind[i]
            if k == CODE:
                br = branch(w, a)
                if br and self.in_text(br[1] & ~1):
                    ref(a, br[1] & ~1, arm=br[0] != "blx")
                for lt in pc_load_targets(w, a):
                    if self.in_text(lt):
                        ref(a, lt & ~3)
                t = self.adr_ok(w, a)
                if t is not None:
                    ref(a, t & ~1 if t & 1 else t & ~3)
            elif k in (LIT, JT) and a not in self.pcrel:
                r = self.word_ref(a, w)
                if r and r[0] == "text":
                    ref(a, r[1])
                elif r and r[0] == "rel":
                    ref(a, r[1])
                    ref(a, r[2])
        for lit, (anchor, bias) in self.pcrel.items():
            tgt = self.pcrel_target(lit)
            if self.in_text(tgt & ~1):
                ref(lit, tgt & ~1)
        for s, e in self.thumb:
            for a in range(s, e - 2, 2):
                c = thumb_call(self.hw(a), self.hw(a + 2), a)
                if c and self.in_text(c[1]):
                    ref(a, c[1], arm=c[0] == "blx")
            for a in self._thumb_literals(s, e) - set(self.pcrel):
                r = self.word_ref(a, self.w(a))
                if r and r[0] == "text":
                    ref(a, r[1])
            thumb_labels |= {a for a in self.names if s <= a < e}
        glob |= {a for a in self.extra_labels if a not in self.starts and self.in_text(a) and not self.in_thumb(a)}
        thumb_labels |= {a for a in self.extra_labels if self.in_thumb(a)}
        local -= glob
        return local, glob, thumb_labels

    def adr_ok(self, w, a):
        """ADR target that can take a symbol: Thumb code (odd) or anything else
        in text outside the Thumb regions (even)."""
        t = adr_target(w, a)
        if t is None or not self.in_text(t & ~1):
            return None
        return t if bool(t & 1) == self.in_thumb(t & ~1) else None

    def _thumb_literals(self, s, e):
        """Addresses of literal-pool words used by Thumb `ldr rX, [pc, #imm]` in [s, e)."""
        out = set()
        for a in range(s, e, 2):
            h = self.hw(a)
            if h & 0xF800 == 0x4800:
                t = ((a + 4) & ~3) + (h & 0xFF) * 4
                if s <= t < e:
                    out.add(t)
        return out

    # ---- emission
    def emit(self, out_dir, include="macros.inc"):
        """Write <out_dir>/<ADDR>.s per unit; returns [(addr, size, symbol)]."""
        local, glob, thumb_labels = self._labels()
        self.thumb_labels = thumb_labels
        self._glob = glob
        self.anchors = {anchor for anchor, _ in self.pcrel.values()}

        def sym_for(tgt):
            if self.in_thumb(tgt):
                return self.thumb_sym(tgt)
            if tgt in self.starts:
                return self.unit_sym(tgt)
            if tgt in self.names:
                return self.names[tgt]
            if tgt in glob:
                return f"loc_{tgt:08X}"
            return f".L_{tgt:08X}"

        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        if os.path.isdir(out_dir):
            shutil.rmtree(out_dir)
        os.makedirs(out_dir)
        units = []
        for ui, s in enumerate(self.starts):
            e = self.starts[ui + 1] if ui + 1 < len(self.starts) else self.end
            if self.in_thumb(s):
                lines, sym = self._emit_thumb(s, e, sym_for, include)
            else:
                lines, sym = self._emit_arm(ui, s, e, md, sym_for, local, glob, include)
            with open(os.path.join(out_dir, f"{s:08X}.s"), "w") as f:
                f.write("\n".join(lines) + "\n")
            units.append((s, e - s, sym))
        return units

    def pcrel_target(self, lit):
        anchor, bias = self.pcrel[lit]
        return (self.w(lit) + anchor + bias) & 0xFFFFFFFF

    def _pcrel_word(self, a, sym_for):
        anchor, bias = self.pcrel[a]
        tgt = self.pcrel_target(a)
        if self.in_text(tgt & ~1):
            t = tgt & ~1
            expr = self.thumb_sym(t) if self.in_thumb(t) else sym_for(t) + (" + 1" if tgt & 1 else "")
        else:
            expr = self.data_sym(tgt)
        return f"    .word {expr} - (pcanchor_{anchor:08X} + {bias}) /* {a:08X} pc-relative */"

    def global_name(self, tgt):
        """Global symbol for a text address (valid after emit); KeyError if it has none."""
        if self.in_thumb(tgt):
            if tgt in self.thumb_labels:
                return self.thumb_sym(tgt)
        elif tgt in self.starts:
            return self.unit_sym(tgt)
        elif tgt in self.names:
            return self.names[tgt]
        elif tgt in self._glob:
            return f"loc_{tgt:08X}"
        raise KeyError(f"no global label at {tgt:#x}")

    def _data_word(self, a, w, sym_for):
        if a in self.pcrel:
            return self._pcrel_word(a, sym_for)
        r = self.word_ref(a, w)
        if r:
            if r[0] == "text":
                if self.in_thumb(r[1]):
                    return f"    .word {self.thumb_sym(r[1])} /* {a:08X} */"  # Thumb symbols carry bit 0
                return f"    .word {sym_for(r[1])}{r[2]} /* {a:08X} */"
            if r[0] == "expr":
                return f"    .word {r[1]} /* {a:08X} */"
            if r[0] == "rel":
                return f"    .word {sym_for(r[1])} - {sym_for(r[2])} /* {a:08X} */"
            if r[0] == "raw":
                return f"    .word 0x{w:08x} /* {a:08X} {r[1]} */"
        return f"    .word 0x{w:08x} /* {a:08X} */"

    def _emit_arm(self, ui, s, e, md, sym_for, local, glob, include):
        blob = self.blob[s - self.base : e - self.base]
        dis = {}
        off = 0
        while off < len(blob):
            last = off
            for addr, size, mnem, op in md.disasm_lite(blob[off:], s + off):
                dis[addr] = (mnem, op)
                off = addr - s + size
            if off == last:  # undecodable word: capstone stops, skip it
                off += 4
        sym = self.unit_sym(s)
        lines = [f".include \"{include}\"", f".section .text.{s:08X}, \"ax\", %progbits", "", f"glabel {sym}"]
        for a in range(s, e, 4):
            i = (a - self.base) >> 2
            if a != s and a in self.names:
                lines.append(f"glabel {self.names[a]}")
            if a in glob:
                lines.append(f"glabel loc_{a:08X}")
            elif a in local:
                lines.append(f".L_{a:08X}:")
            if a in self.anchors:
                lines.append(f"pcanchor_{a:08X}:")
            w = self.words[i]
            k = self.kind[i]
            if a in self.force_raw:
                lines.append(f"    .inst 0x{w:08x} /* {a:08X} */")
                continue
            if k == CODE and a in dis:
                mnem, op = dis[a]
                br = branch(w, a)
                if br:
                    tgt = br[1] & ~1
                    if not self.in_text(tgt) or (br[0] == "blx" and not self.in_thumb(tgt)):
                        lines.append(f"    .inst 0x{w:08x} /* {a:08X} {mnem} */")
                        continue
                    op = sym_for(tgt)
                elif (t := self.adr_ok(w, a)) is not None and self.unit_of(t & ~1) != ui:
                    # ADR into another unit: let the linker fill in the offset
                    rd = op.split(",")[0]
                    tgt = sym_for(t & ~1) if t & 1 else sym_for(t & ~3) + (f" + {t & 3}" if t & 3 else "")
                    # adrfix_*: tools/canon_imm.py re-encodes the linked immediate the
                    # way armcc does (smallest rotation); lld picks another rotation
                    lines.append(f"adrfix_{a:08X}:")
                    lines.append(f"    add{mnem[3:]} {rd}, pc, #:pc_g0:({tgt} - 8) /* {a:08X} {mnem} */")
                    continue
                else:
                    m = PC_REL.search(op)
                    if m and pc_load_targets(w, a):
                        tgt = a + 8 + int(m.group(1), 0)
                        base_w = tgt & ~3
                        if not self.in_text(base_w) or self.unit_of(base_w) != ui:
                            lines.append(f"    .inst 0x{w:08x} /* {a:08X} {mnem} {op} */")
                            continue
                        expr = sym_for(base_w) + (f" + {tgt - base_w}" if tgt != base_w else "")
                        op = op[: m.start()] + expr + op[m.end() :]
                lines.append(f"    {mnem} {op} /* {a:08X} */".replace("  /*", " /*"))
                continue
            if k in (LIT, JT):
                lines.append(self._data_word(a, w, sym_for))
                continue
            lines.append(f"    .word 0x{w:08x} /* {a:08X} */")
        lines.append(f"endlabel {sym}")
        return lines, sym

    def _emit_thumb(self, s, e, sym_for, include):
        sym = self.thumb_sym(s)
        literals = self._thumb_literals(s, e)
        lines = [f".include \"{include}\"", f".section .text.{s:08X}, \"ax\", %progbits", ".thumb", ""]
        a = s
        while a < e:
            if a in self.thumb_labels or a == s:
                name = self.thumb_sym(a)
                lines += [f"    .global {name}", "    .thumb_func", f"{name}:"]
            if a in self.anchors:
                lines.append(f"pcanchor_{a:08X}:")
            if a in literals and a % 4 == 0 and a + 4 <= e:
                lines.append(self._data_word(a, self.w(a), sym_for))
                a += 4
                continue
            if a + 4 <= e and not (a + 2 in self.thumb_labels):
                c = thumb_call(self.hw(a), self.hw(a + 2), a)
                if c and self.in_text(c[1]) and (c[0] == "blx") == (not self.in_thumb(c[1])):
                    lines.append(f"    {c[0]} {sym_for(c[1])} /* {a:08X} */")
                    a += 4
                    continue
            lines.append(f"    .hword 0x{self.hw(a):04x} /* {a:08X} */")
            a += 2
        lines += [".arm", f"    .size {sym}, . - {sym}"]
        return lines, sym


def emit_segment(path, kind, module_file, file_off, size, labels, words):
    """Assembly for a non-text segment: original bytes, labels, symbolic words.

    labels: offset -> [names]; words: offset -> assembler expression. A word
    with a label inside it (a pointer to the middle of a pointer: one of the two
    is a look-alike) is kept as raw bytes."""
    words = {o: e for o, e in words.items() if not any(o + k in labels for k in (1, 2, 3))}
    lines = [".include \"macros.inc\"", f".section .{kind}, \"{'aw' if kind != 'rodata' else 'a'}\"" +
             (", %nobits" if kind == "bss" else ""), ""]
    cuts = sorted({0, size} | set(labels) | set(words) | {o + 4 for o in words})
    for a, b in zip(cuts, cuts[1:] + [None]):
        for name in labels.get(a, []):
            lines.append(f"dlabel {name}")
        if b is None:
            break
        if a in words:
            lines.append(f"    .4byte {words[a]} /* {a:08X} */")
        elif kind == "bss":
            lines.append(f"    .space {b - a:#x}")
        else:
            lines.append(f"    .incbin \"{module_file}\", {file_off + a:#x}, {b - a:#x}")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


MACROS = (".syntax unified\n.arm\n.text\n"
          ".macro glabel name\n    .global \\name\n    .type \\name, %function\n\\name:\n.endm\n"
          ".macro endlabel name\n    .size \\name, . - \\name\n.endm\n"
          ".macro dlabel name\n    .global \\name\n    .type \\name, %object\n\\name:\n.endm\n")
