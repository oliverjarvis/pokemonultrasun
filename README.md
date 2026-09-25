# Pokémon Ultra Sun — Decompilation

A work-in-progress matching decompilation of **Pokémon Ultra Sun** for the Nintendo 3DS.

The build compiles C++ source with the original compiler and assembles the not-yet-decompiled
remainder from generated assembly, then packs everything into a `.3ds` image that is
**byte-identical** to the retail cartridge.

> [!IMPORTANT]
> This repository contains no game code, assets or other copyrighted data. To build it you need
> your own decrypted dump of the game, and the build extracts everything else from that dump.

## Status

| Component | State |
|---|---|
| `code.bin` (main executable, 4.95 MB of ARM code) | Builds byte-identical |
| Decompiled to C++ | **7 / 81,002** functions (all in `code.bin` so far) |
| CRO modules (132 relocatable modules, 5.6 MB of code) | Build byte-identical from assembly (55,021 functions) |
| `.rodata` / `.data` of `code.bin` | Included as binary; not yet symbolized, so code cannot grow yet |
| RomFS, ExeFS, NCCH, NCSD containers | Rebuilt from files, byte-identical |

## Target

| | |
|---|---|
| Title | Pokémon Ultra Sun (USA) (En, Ja, Fr, De, Es, It, Zh, Ko) |
| Version | 1.0 (cartridge; the 1.2 update is not targeted) |
| Title ID / product code | `00040000001B5000` / `CTR-P-A2AA` |
| `.3ds` SHA-1 (decrypted) | `51957bc32b3e96bda2197496bf0b462dc3da0130` |
| `code.bin` SHA-1 | `d05602171c1854f4c6d33c28589689f52f56c4cd` |

## Requirements

- macOS on Apple Silicon (the only platform tested so far). Linux should work with the Linux build
  of wibo, but hasn't been tried.
- Python 3.9+ with [Capstone](https://www.capstone-engine.org/) and
  [pyelftools](https://github.com/eliben/pyelftools)
- GNU binutils for `arm-none-eabi`, [Ninja](https://ninja-build.org/) and LLVM
  [lld](https://lld.llvm.org/)
- **ARM Compiler armcc 4.1, build 1454**, run through [wibo](https://github.com/decompals/wibo).
  The compiler is proprietary and is not distributed here.
- A **decrypted** `.3ds` dump of the game matching the SHA-1 above

## Setup

```sh
git clone git@github.com:oliverjarvis/pokemonultrasun.git
cd pokemonultrasun

# Toolchain
python3 -m venv .venv && .venv/bin/pip install capstone pyelftools
brew install arm-none-eabi-binutils ninja lld
```

**Compiler.** Place armcc so that `tools/armcc/4.1/b1454/bin/armcc.exe` exists (the directory
layout matches the archive used by [decomp.me](https://decomp.me)). Download the `wibo-macos`
binary from the [wibo releases](https://github.com/decompals/wibo/releases) to `tools/wibo/wibo`
and make it executable. On Apple Silicon it runs under Rosetta 2.

**Game data (one-time).** Link your dump as `baserom.3ds`, then extract and split it:

```sh
ln -s /path/to/your/dump.3ds baserom.3ds
python3 tools/extract.py baserom.3ds      # code.bin, exheader, CRO modules    -> orig/
python3 tools/unpack.py  baserom.3ds      # all container parts, RomFS files   -> orig/rom/
python3 tools/symbols.py                  # names from static.crs              -> orig/symbols.tsv
.venv/bin/python tools/analyze.py         # function and code/data discovery   -> orig/analysis.json
.venv/bin/python tools/split.py           # one assembly file per function     -> asm/text/
.venv/bin/python tools/cro_split.py       # same for every CRO module          -> asm/cro/
```

This is the only step that reads the dump. `orig/`, `asm/` and `build/` are generated locally and
ignored by git.

## Building

```sh
.venv/bin/python tools/configure.py      # writes build.ninja; re-run after adding files to src/
ninja                                    # -> build/code.bin, build/romfs_overlay/*.cro, build/rom.3ds
.venv/bin/python tools/check.py          # verifies code.bin, every module and the ROM
```

A successful build prints:

```
original d05602171c1854f4c6d33c28589689f52f56c4cd
built    d05602171c1854f4c6d33c28589689f52f56c4cd
MATCH
modules  133/133 identical
rom.3ds  51957bc32b3e96bda2197496bf0b462dc3da0130  MATCH
```

A clean `ninja` build (about 81,000 assembly units) takes about 65 seconds on a 15-core Mac, and a
rebuild after a C++ change about 5 seconds. The one-time split steps add about a minute.

`build/rom.3ds` runs in emulators such as Azahar and on consoles running Luma3DS. Once the code
differs from retail, the RSA signatures in the NCCH and NCSD headers no longer verify. Neither
target checks them, and decrypted dumps already fail that check.

## Contributing

Decompilation happens one function at a time. Every function stays byte-identical, so the ROM
always matches. Run the Python tools with `.venv/bin/python`.

1. **Pick a function.** `tools/disasm.py --candidates` lists small, self-contained functions, and
   `tools/disasm.py <name>` shows labelled disassembly. About 4,700 functions keep their original
   C++ names from `static.crs`.
2. **Write the C++** in `src/`, mirroring the original namespaces (for example
   `src/pml/battle/TypeAffinity.cpp`), with declarations in `include/`. Leave a comment with the
   address above each function.
3. **Build and check.** Run `tools/configure.py` if you added a file, then `ninja` and
   `tools/check.py`. For a quicker look at one object, `tools/objcmp.py build/src/<file>.o -v`
   reports each function as `MATCH` or with a count of differing words.
4. **Symbols** that your code references but that aren't decompiled yet (data tables, callees) go
   in `config/symbols.txt` with their addresses.
5. **Near misses** can be committed under `#ifdef NONMATCHING` with a note on what differs.
   Only matching code is linked.

On [decomp.me](https://decomp.me), use the **Nintendo 3DS** platform with **armcc 4.1 build 1454**
and the flags `-O3 -Otime --cpp --arm --split_sections`. `tools/asmgen.py <name>` writes target
assembly for a function to `asm/funcs/`, ready to paste in.

Changes go through pull requests. `tools/check.py` must report `MATCH` for both hashes.

## How it works

```
baserom.3ds ──extract/unpack──▶ orig/            (one time)
orig/exefs/code.bin ──analyze/split──▶ asm/text/<ADDR>.s          25,981 function units
orig/rom/romfs/*.cro ──cro_split────▶ asm/cro/<Module>/<OFF>.s   55,021 function units

asm/text/*.s ──GNU as────▶ build/text/*.o ─┐
src/**/*.cpp ──armcc 4.1─▶ build/src/*.o ──┼─ linkgen ─▶ ld.lld ─▶ build/code.bin
                                           │  (C++ replaces the asm unit at the same address)
asm/cro/<Module>/*.s ──as/ld.lld/mkcro─▶ build/romfs_overlay/<Module>.cro, .crr/static.crr
orig/rom/romfs/ + overlay ──ctr.py──▶ build/romfs.bin
code.bin + romfs.bin + orig/rom/ parts ──mkrom.py──▶ build/rom.3ds
```

- **Analysis** (`tools/analyze.py`) traces the executable from every known entry point: named
  exports, call targets, vtables and other data pointers, and the place-relative `.init_array`.
  It classifies about 90% of `.text` as instructions and 3% as literal pools and jump tables, and
  keeps the remainder as raw words.
- **Splitting** (`tools/split.py`) emits relocatable assembly: branches, literal pools and jump
  tables refer to symbols, and each unit lives in a `.text.<ADDR>` section so that a single
  `SORT_BY_NAME` rule places it at its original address.
- **CRO modules** (`tools/cro.py`, `tools/cro_split.py`, `tools/mkcro.py`) are relocatable
  modules loaded at runtime. All their relocations are `R_ARM_ABS32` and relocated words are zero
  in the file, so the relocation tables say exactly which words are addresses. Calls into
  `code.bin` go through import veneers (`ldr pc, [pc, #-4]`), which are named after the import:
  `bl veneer__ZN3pml8pokepara9CoreParam7SetWazaEh6WazaNo`. Each module's `.text` is linked at its
  file offset and spliced back into the module with its tables. `mkcro.py` then recomputes the
  module's four SHA-256 hashes, and `static.crr` is regenerated from the built modules.
- **Linking** (`tools/linkgen.py`) renames each armcc function section (`i.<symbol>`) to its
  unit's address. A compiled function must be exactly the size of the unit it replaces.
- **Packaging** (`tools/ctr.py`, `tools/mkrom.py`) rebuilds the RomFS (including its IVFC hash
  tree), ExeFS, NCCH and NCSD using the same layout rules as Nintendo's mastering tool, and
  recomputes every offset, size and SHA-256. Only fields that can't be derived (RSA signatures,
  IDs, card info) and the manual, download-play and update partitions come from `orig/rom/`
  unchanged.

The compiler and flags were identified by compiling reconstructed functions with every
candidate armcc build. See [`compiler_id/RESULTS.md`](compiler_id/RESULTS.md) for the method and
results.

## Repository layout

```
compiler_id/   compiler identification experiments and results
config/        symbol addresses, raw-word fallbacks, expected ROM hash
include/       headers for decompiled code
src/           decompiled C++
tools/         extraction, analysis, build and verification scripts
```

| Tool | Purpose |
|---|---|
| `extract.py`, `unpack.py` | Extract code and every container part from a dump |
| `inventory.py`, `symbols.py` | Code size report and CRO exports; `static.crs` symbol table |
| `analyze.py`, `split.py`, `asmemit.py` | Find functions and code/data; generate per-function assembly |
| `cro.py`, `cro_split.py`, `mkcro.py` | CRO/CRR formats; split modules; rebuild modules with new code |
| `configure.py`, `linkgen.py` | Generate `build.ninja`; place compiled C++ at unit addresses |
| `ctr.py`, `mkrom.py`, `pad.py` | Build RomFS / ExeFS / NCCH / NCSD images |
| `check.py`, `objcmp.py` | Verify hashes; compare a compiled object against the original |
| `disasm.py`, `asmgen.py` | Browse disassembly; emit standalone assembly for a function |

## Roadmap

- C++ in CRO modules: generate their relocation and import tables from compiled objects
- Symbolize `.rodata` / `.data` so that modified code can change size
- Grow C++ coverage, starting with the `pml` (Pokémon data and battle rules) and `item` libraries

## Acknowledgements

- [decomp.me](https://decomp.me), whose 3DS compiler setup made compiler identification possible
- [wibo](https://github.com/decompals/wibo) by decompals, for running the compiler natively
- [3dbrew](https://www.3dbrew.org), for documentation of the 3DS container formats
- [pret](https://github.com/pret), whose decompilation projects this workflow follows

## Legal

This project is not affiliated with or endorsed by Nintendo, Game Freak, Creatures Inc. or The
Pokémon Company. Pokémon and all related names are trademarks of their respective owners. No
copyrighted game data is included in this repository. You must use your own legally obtained copy
of the game.
