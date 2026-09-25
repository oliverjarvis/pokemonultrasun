#!/usr/bin/env python3
"""Emit per-function GNU-as units for a traced ARM code region.

Used by split.py (code.bin) and cro_split.py (CRO modules). A region is
described by its words, base address, word classification (analyze.CODE /
LIT / JT) and function starts; how data words are symbolized is up to the
caller's `word_ref(addr, word)` callback, which returns one of:
  None                     keep the raw value
  ("text", target, suffix) reference to a text address in this region
  ("expr", text)           an arbitrary assembler expression
  ("raw", comment)         keep the raw value, with a trailing comment
"""
import bisect
import os
import re
import shutil

import capstone

from analyze import CODE, JT, LIT, branch, pc_load_targets

PC_REL = re.compile(r"\[pc, #(-?0x[0-9a-f]+|-?\d+)\]")


class Region:
    def __init__(self, words, base, blob, kind, starts, names=None, force_raw=(), word_ref=None):
        self.words, self.base, self.blob, self.kind = words, base, blob, kind
        self.end = base + 4 * len(words)
        self.starts = sorted(set(starts) | {base})
        self.names = names or {}
        self.force_raw = set(force_raw)
        self.word_ref = word_ref or (lambda a, w: None)

    def in_text(self, a):
        return self.base <= a < self.end

    def unit_of(self, a):
        return bisect.bisect_right(self.starts, a) - 1

    def unit_sym(self, a):
        return self.names.get(a) or f"sub_{a:08X}"

    def _labels(self):
        local, glob = set(), set()

        def ref(src, tgt):
            if tgt in self.starts:
                return
            (local if self.unit_of(src) == self.unit_of(tgt) else glob).add(tgt)

        for i, w in enumerate(self.words):
            a = self.base + 4 * i
            if a in self.force_raw:
                continue
            k = self.kind[i]
            if k == CODE:
                br = branch(w, a)
                if br and br[0] != "blx" and self.in_text(br[1]):
                    ref(a, br[1])
                for lt in pc_load_targets(w, a):
                    if self.in_text(lt):
                        ref(a, lt & ~3)
            elif k in (LIT, JT):
                r = self.word_ref(a, w)
                if r and r[0] == "text":
                    ref(a, r[1])
        return local, glob

    def emit(self, out_dir, include="macros.inc"):
        """Write <out_dir>/<ADDR>.s per unit; returns [(addr, size, symbol)]."""
        local, glob = self._labels()

        def sym_for(tgt):
            if tgt in self.starts:
                return self.unit_sym(tgt)
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
                w = self.words[i]
                k = self.kind[i]
                if a in self.force_raw:
                    lines.append(f"    .inst 0x{w:08x} /* {a:08X} */")
                    continue
                if k == CODE and a in dis:
                    mnem, op = dis[a]
                    br = branch(w, a)
                    if br:
                        if br[0] == "blx" or not self.in_text(br[1]):
                            lines.append(f"    .inst 0x{w:08x} /* {a:08X} {mnem} */")
                            continue
                        op = sym_for(br[1])
                    else:
                        m = PC_REL.search(op)
                        if m and pc_load_targets(w, a):
                            tgt = a + 8 + int(m.group(1), 0)
                            base_w = tgt & ~3
                            if not self.in_text(base_w) or self.unit_of(base_w) != ui:
                                # pc-relative load across units: keep exact bytes
                                lines.append(f"    .inst 0x{w:08x} /* {a:08X} {mnem} {op} */")
                                continue
                            expr = sym_for(base_w) + (f" + {tgt - base_w}" if tgt != base_w else "")
                            op = op[: m.start()] + expr + op[m.end() :]
                    lines.append(f"    {mnem} {op} /* {a:08X} */".replace("  /*", " /*"))
                    continue
                if k in (LIT, JT):
                    r = self.word_ref(a, w)
                    if r:
                        if r[0] == "text":
                            lines.append(f"    .word {sym_for(r[1])}{r[2]} /* {a:08X} */")
                            continue
                        if r[0] == "expr":
                            lines.append(f"    .word {r[1]} /* {a:08X} */")
                            continue
                        if r[0] == "raw":
                            lines.append(f"    .word 0x{w:08x} /* {a:08X} {r[1]} */")
                            continue
                lines.append(f"    .word 0x{w:08x} /* {a:08X} */")
            lines.append(f"endlabel {sym}")
            with open(os.path.join(out_dir, f"{s:08X}.s"), "w") as f:
                f.write("\n".join(lines) + "\n")
            units.append((s, e - s, sym))
        return units


MACROS = (".syntax unified\n.arm\n.text\n"
          ".macro glabel name\n    .global \\name\n    .type \\name, %function\n\\name:\n.endm\n"
          ".macro endlabel name\n    .size \\name, . - \\name\n.endm\n")
