# Compiler identification — results (2026-09-25)

Target: Pokémon Ultra Sun (USA) v1.0 `code.bin`. Test source: `cases_v2.cpp`
(`cases.cpp` is the first attempt). Compiled on decomp.me (scratch `lO6jQ`,
platform n3ds) via its compile API; objects compared against code.bin with the
in-page equivalent of `tools/objcmp.py` (relocated words masked).

## Result

**armcc 4.1, build 791 or later (not 894), flags `-O3 -Otime --cpp --arm --split_sections`**
(decomp.me always adds `--cpu=MPCore --fpmode=fast --apcs=/interwork`).

Remaining candidates, indistinguishable so far: 791, 844, 921, 1049, 1440, 1454.
Use 1454 provisionally; re-run the matrix as more functions match.

## Evidence

- `--split_sections` is required: without it literal pools are shared at the end
  of `.text`; the ROM has a pool after every function.
- -O3 -Otime is required: the table-search loops are unrolled ×2 (with the first
  iteration peeled for odd counts); -O2 / -Ospace do not unroll.
- armcc 4.0 (771–902), 4.1 561, and 5.04 build 82: loop codegen differs (≤1/9).
- armcc 4.1 713: `ITEM_CheckJewel` differs.
- armcc 4.1 894: `ConvAboutAffinity` / `CalcAffinityAbout` differ.

| function (address) | status with cases_v2.cpp on 4.1 ≥791 (≠894) |
|---|---|
| item::ITEM_GetNutsNo (0x375D90) | match |
| item::ITEM_CheckBeads (0x375EB8) | match |
| item::ITEM_CheckJewel (0x375F04) | match |
| pml::battle::TypeAffinity::ConvAboutAffinity (0x31C3D8) | match |
| pml::battle::TypeAffinity::CalcAffinityAbout (0x31C3B0) | match |
| gfl2::math::Random::Initialize(u32) (0x3616D0) — TinyMT32 | match |
| gfl2::math::SFMTRandom::Next(u32) (0x360F74) — SFMT | match |
| item::ITEM_CheckNuts (0x375CAC) | no — ROM keeps a redundant `!= 0xFF` test after inlining GetNutsNo; source structure unknown |
| item::GetBattlePocketID (0x375F90) | no — ROM loads the 8-byte table init from .rodata (0x5BB6D4); ours emits it in the code section |

Notable source-level findings: loop counters are unsigned (`blo`), the
`ConvAboutAffinity` tests `> TYPEAFF_1` before `== TYPEAFF_1`, and
`SFMTRandom::Next` is the reference `sfmt_genrand_uint32` (pointer to state,
re-read of idx) followed by `% max`.
