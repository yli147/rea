# RISC-V ELF analysis through Ghidra

This lane extends native ELF analysis for `EM_RISCV` targets. It does not
execute RISC-V code, emulate a boot sequence, or rehost firmware. It addresses
[#2063](https://github.com/morluto/rea/issues/2063) and follows the same
lane shape as [generic MIPS support](ghidra-mips.md).

## Admission boundary

ELF `EM_RISCV` (243) is retained as the provider-neutral `riscv` family. The
target also retains the raw ELF declarations that decide a lane: class, byte
order, `e_type`, and `e_flags`. Recognition does not mean every provider or
RISC-V variant is supported. Existing PE, managed and Mach-O architecture sets
are unchanged. Headerless inputs use the separate [raw-binary admission
boundary](raw-binary.md); raw RISC-V images are not supported.

The Ghidra lane admits little-endian ELF32 and ELF64 `ET_EXEC` images that
declare `EF_RISCV_FLOAT_ABI_DOUBLE` in `e_flags`, with no `EF_RISCV_RVE`,
`EF_RISCV_TSO`, or any bit outside `EF_RISCV_RVC | EF_RISCV_FLOAT_ABI`. These are
header declarations, not proof that every instruction conforms to that ISA.
It also admits a narrower ELF64 `ET_DYN` PIE lane when the file declares
`DF_1_PIE`, has a verified executable entry in a `PT_LOAD` segment, and its
complete `PT_DYNAMIC` relocation declarations use only the verified RISC-V
`NONE`, `64`, `RELATIVE`, and `JUMP_SLOT` RELA types. A shared object without
`DF_1_PIE`, ELF32 PIE, `REL`/packed `RELR`, text relocations, unsupported
relocation types, or incomplete/ambiguous load ranges remain refused.

Provider selection returns the specific unsupported constraint rather than
guessing a compatible profile:

| Declaration                                      | Outcome                                                                                  |
| ------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| Little-endian ELF64 `ET_EXEC`, double-float ABI  | admitted, `RISCV:LE:64:default` + `gcc`                                                  |
| Little-endian ELF32 `ET_EXEC`, double-float ABI  | admitted, `RISCV:LE:32:default` + `gcc`                                                  |
| Big-endian                                       | refused; Ghidra 12.1.4 ships no big-endian RISC-V language                               |
| `ET_REL`, non-PIE `ET_DYN`, other `e_type`       | refused with the declared value                                                          |
| ELF64 `ET_DYN` with verified `DF_1_PIE` and RELA | admitted as `elf64-dyn-le-double-float-generic-pie-v1`                                   |
| ELF32 `ET_DYN` or missing/incomplete PIE facts   | refused; PIE load declarations are not inferred                                          |
| `EF_RISCV_RVE`                                   | refused; the embedded 16-register profile (x0–x15) needs its own processor specification |
| `EF_RISCV_TSO`                                   | refused; the total-store-order memory model is unverified here                           |
| Soft, single, or quad float ABI                  | refused; the pinned generic compiler specification models double-float                   |
| Reserved or newer `e_flags` bits                 | refused with the offending bits named                                                    |

`e_type` is the only load-shape declaration this lane reads. A fixed-address
`ET_EXEC` declaration does **not** establish static linkage: `PT_INTERP` and
dynamic dependencies are not inspected, and the session records that boundary as
a limitation rather than inferring a load model.

## Why the language is pinned

Ghidra's header-based selection is not reliable for RV32. The 12.1.4
`riscv.opinion` pins `variant="default"` for the 64-bit constraint and leaves the
32-bit constraint unpinned with the comment that the loader "must choose between
'default' and 'AndeStar' variants". Measured against the installed release tree:

| Fixture                                         | Ghidra auto-selection         |
| ----------------------------------------------- | ----------------------------- |
| RV64 ELF, `e_flags 0x5` (RVC, double-float ABI) | `RISCV:LE:64:default:gcc`     |
| RV32 ELF, `e_flags 0x5`, no Andes declaration   | `RISCV:LE:32:AndeStar_v5:gcc` |

So an ordinary RV32 image lands on an Andes processor model unless the language
is stated. REA therefore pins `RISCV:LE:32:default` or `RISCV:LE:64:default`
with the `gcc` compiler specification per class, records
`language_selection: provider-pinned-v1`, and refuses a caller-selected
`REA_GHIDRA_LANGUAGE_ID` or `REA_GHIDRA_COMPILER_SPEC_ID` that disagrees with the
pin without changing the requested override. An override that matches the pin is
accepted and recorded as `configured-v1`.

## PIE mapping and relocations

The PIE inspector reads the ELF64 program-header table and bounded dynamic
records directly from the source file. It checks non-overlapping `PT_LOAD`
memory ranges, the file-backed `PT_DYNAMIC` mapping, the executable entry
mapping, optional `PT_INTERP`, `DF_1_PIE`, and all declared `DT_RELA` and
`DT_JMPREL` records. `DT_JMPREL` may be wholly contained in `DT_RELA`; it is
counted once. Ambiguous table overlap, invalid destinations, text relocations,
or relocation forms outside `R_RISCV_NONE`, `R_RISCV_64`, `R_RISCV_RELATIVE`,
and `R_RISCV_JUMP_SLOT` keep the PIE lane unavailable.

Ghidra's chosen image base and addresses are analysis coordinates, not the
runtime ASLR base. The dynamic loader is not executed and dependency images are
not loaded; symbol-bearing relocations can therefore remain externally
unresolved. `inspect_native_load_image` retains Ghidra's relocation statuses
and source/loaded bytes for the analyst to inspect. These facts establish a
bounded static import, not runtime relocation success.

## Evidence

The `ET_EXEC` lane identity is `elf32-exec-le-double-float-generic-v1` or
`elf64-exec-le-double-float-generic-v1`; the PIE lane uses
`elf64-dyn-le-double-float-generic-pie-v1`. `riscv_elf` retains `elf_class`,
`byte_order`, `type`, and the raw `flags` alongside the read-only booleans
`float_abi_double`, `rvc_declared`, `rve_declared`, and `tso_declared`. Those
fields report declarations the header makes; none of them is evidence of the
original compiler, of instruction conformance, or of a floating-point calling
convention beyond the ABI the pinned language models.
For PIE, `riscv_pie` additionally records the observed PIE flag, interpreter
presence, executable-entry mapping, dependency count, and relocation coverage.

## Verification and limits

Ghidra 12.1.4 PUBLIC with a 64-bit JDK 21+ is required, and on macOS the release
tree ships no host decompiler binary, so `Decompiler/os/<platform>/decompile` and
`sleigh` must come from your own build; see
[installation](installation.md#ghidra).

Run `npm run verify:ghidra:riscv` with an existing Ghidra 12.1.4 installation,
JDK 21+, and a RISC-V-capable Clang, LLD and LLVM readelf. The verifier acquires
no tools and never executes target code. Select installed tools explicitly when
they are not on `PATH`:

```sh
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC \
JAVA_HOME=/path/to/jdk-21 \
REA_RISCV_CLANG=/path/to/llvm/bin/clang \
REA_RISCV_LLD=/path/to/lld/bin/ld.lld \
REA_RISCV_READELF=/path/to/llvm/bin/llvm-readelf \
npm run verify:ghidra:riscv
```

The lane builds the committed freestanding C and assembly sources into RV32 and
RV64 `ET_EXEC` fixtures. Independent LLVM readelf observations establish ELF
declarations and symbol addresses. Public CLI and stdio MCP workflows verify
function enumeration, decompilation, pinned language/compiler identity, decoded
probe bytes, global data, and direct calls. It validates advertised MCP output
schemas and both JSON representations, saves and reopens snapshots, rejects
header-mutated soft-float and unsupported high-bit declarations, and checks
unchanged source bytes and owned cleanup. Failures retain the diagnostic
workspace; successful runs remove it and report the observed process lineage.

Module tests cover admission, ELF64 PIE dynamic tables, relocation boundaries,
and malformed headers. Call-graph completeness,
string inventories, dynamic linkage, Andes or RVE/TSO images, and big-endian
targets are **not** established by this lane. `.riscv.attributes` ISA extensions
are not inspected; the generic language pin remains an analysis convention.
