# pkmn-comp — Pokémon Ultra Sun decompilation (exploratory)

Target: Pokémon Ultra Sun (USA) v1.0, `00040000001B5000`, decrypted cart image.
You must supply your own dump; nothing derived from the ROM is committed.

## Setup

```sh
python3 -m venv .venv && .venv/bin/pip install capstone pyelftools
brew install arm-none-eabi-binutils ninja lld
```

Compiler (not distributed here): unpack `armcc.zip` (the archive decomp.me
uses) so that `tools/armcc/4.1/b1454/bin/armcc.exe` exists, and put the
`wibo-macos` release of [wibo](https://github.com/decompals/wibo) at
`tools/wibo/wibo` (runs under Rosetta on Apple Silicon).

## Setup from your dump (once)

```sh
ln -s "Pokemon Ultra Sun (USA) (En,Ja,Fr,De,Es,It,Zh,Ko).3ds" baserom.3ds
python3 tools/extract.py baserom.3ds          # code.bin, exheader, CROs -> orig/
python3 tools/unpack.py baserom.3ds           # every ROM part + RomFS files -> orig/rom/
python3 tools/symbols.py                      # static.crs names -> orig/symbols.tsv
.venv/bin/python tools/analyze.py             # trace code, find functions -> orig/analysis.json
.venv/bin/python tools/split.py               # asm/text/*.s (one per function)
```

The dump is only read here. Everything under `orig/` and `asm/` is derived
from it and is not committed.

## Build

```sh
.venv/bin/python tools/configure.py   # build.ninja (re-run after adding src/ files)
ninja                                 # -> build/code.bin, build/romfs.bin, build/rom.3ds
.venv/bin/python tools/check.py       # code.bin + rom.3ds hashes vs the originals
```

- `src/**/*.cpp` is compiled with armcc 4.1 b1454; each compiled function
  replaces the asm unit at its address (`tools/linkgen.py`, sizes must match).
- `asm/text/*.s` is assembled with GNU as; everything is linked with `ld.lld`
  at the original addresses.
- `tools/ctr.py` builds the RomFS (with its IVFC hash tree) from
  `orig/rom/romfs/`, and `tools/mkrom.py` lays out the ExeFS, NCCH and NCSD
  from parts, recomputing all offsets, sizes and SHA-256s. Only
  non-derivable header fields (RSA signatures, IDs, card info) and the
  manual / DLP-child / update partitions come from `orig/rom/` as-is.
- A clean build takes ~75 s (mostly `split.py`); after editing C++ ~3.5 s.

`check.py` prints `MATCH` twice when `build/code.bin` and `build/rom.3ds` are
byte-identical to the dump (`config/rom.sha1`). After code changes the
NCCH/NCSD RSA signatures no longer verify; Luma3DS and emulators don't check.

## Status

- **M1 extract/inventory** — done. ~10.6 MB ARM code: code.bin + 132 CRO modules.
- **M2 asm round-trip (code.bin)** — done. 25,981 function units, text fully
  symbolized (branches, literal pools, jump tables); .rodata/.data are still
  `.incbin`. One word forced raw (`config/force_raw.txt`).
- **M3 compiler ID** — armcc 4.1 build ≥791 (not 894),
  `-O3 -Otime --cpp --arm --split_sections`. See `compiler_id/RESULTS.md`.
- **ROM from files** — done. `ninja` builds a byte-identical `.3ds` from
  `orig/rom/` parts and the compiled code; no base image is read.
- **M4 C++ in the build** — done. `src/**/*.cpp` is compiled with armcc 4.1
  b1454 (`-O3 -Otime --cpp --arm --split_sections`); each compiled function
  replaces its asm unit (`tools/linkgen.py`, sizes must match). 7 functions
  are C++ so far and the ROM is still byte-identical. Symbols C++ uses but
  doesn't define yet go in `config/symbols.txt`.
- CRO modules — not started.

## Tools

| tool | purpose |
|---|---|
| `tools/disasm.py` | labelled disassembly of named functions; `--candidates` lists small ones |
| `tools/asmgen.py` | standalone per-function asm with a byte-exact self-check |
| `tools/objcmp.py` | compare a compiled `.o` against code.bin, reloc-aware |
