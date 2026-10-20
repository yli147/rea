import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { GhidraLanguageOverride } from "../config/ghidraLanguageOverride.js";

/**
 * Ghidra's generic RISC-V languages model the double-float ABI: the shipped
 * `riscv.ldefs` maps `RISCV:LE:{32,64}:default` to the `riscv{32,64}-fp.cspec`
 * compiler specification. Soft, single and quad ABI declarations therefore need
 * their own verification rather than inheriting this lane.
 */
const EF_RISCV_RVC = 0x0001;
const EF_RISCV_FLOAT_ABI = 0x0006;
const EF_RISCV_FLOAT_ABI_DOUBLE = 0x0004;
const EF_RISCV_RVE = 0x0008;
const EF_RISCV_TSO = 0x0010;

const ET_REL = 1;
const ET_EXEC = 2;
const ET_DYN = 3;
const RISCV_PIE_RELOCATION_TYPES = new Set([0, 2, 3, 5]);

/**
 * Bits this lane reads. Anything else in `e_flags` — reserved today or defined by
 * a newer psABI — is refused rather than assumed compatible.
 */
const EF_RISCV_DECLARED_BITS = EF_RISCV_RVC | EF_RISCV_FLOAT_ABI;

/** Header declarations outside the verified generic-language lane. */
const riscvUnsupportedFloatAbi = (abi: number): string =>
  abi === 0
    ? "unspecified (soft-float convention)"
    : abi === 0x0002
      ? "single-float"
      : "quad-float";

/**
 * Keep family recognition separate from the deliberately bounded Ghidra lane.
 *
 * Ghidra 12.1.4 selects `RISCV:LE:32:AndeStar_v5` for an ordinary RV32 ELF: its
 * `riscv.opinion` pins `variant="default"` for the 64-bit constraint and leaves
 * the 32-bit one with the comment that the loader "must choose between 'default'
 * and 'AndeStar' variants". The lane therefore pins the language instead of
 * accepting the header-based guess.
 */
export const ghidraRiscvUnsupportedReason = (
  target: BinaryTarget,
): string | null => {
  if (target.kind !== "executable" || target.architecture !== "riscv")
    return null;
  const metadata = target.riscv;
  if (target.format !== "elf")
    return "RISC-V analysis requires ELF header metadata; a family name alone does not select an ISA or ABI.";
  if (metadata.byteOrder !== "little")
    return "This Ghidra RISC-V lane supports little-endian images only; Ghidra 12.1.4 ships no big-endian RISC-V language.";
  if (metadata.elfClass !== 32 && metadata.elfClass !== 64)
    return "This Ghidra RISC-V lane requires ELF32 or ELF64; the class decides which generic language is pinned.";
  if ((metadata.flags & EF_RISCV_RVE) !== 0)
    return "EF_RISCV_RVE declares the embedded 15-register ABI, which needs its own processor specification and compiler verification.";
  if ((metadata.flags & EF_RISCV_TSO) !== 0)
    return "EF_RISCV_TSO declares the total-store-order memory model; this lane verifies the baseline model only.";
  if (metadata.type !== ET_EXEC && metadata.type !== ET_DYN)
    return `This Ghidra RISC-V lane supports ET_EXEC and verified ELF64 PIE only; ${
      metadata.type === ET_REL ? "relocatable" : `e_type ${metadata.type}`
    } images need separate load verification.`;
  if (metadata.type === ET_DYN) {
    if (metadata.elfClass !== 64)
      return "This Ghidra RISC-V PIE lane supports ELF64 only; ELF32 PIE needs separate load verification.";
    const load = metadata.pieLoad;
    if (load === undefined || load.status !== "complete")
      return `RISC-V ET_DYN requires complete PT_LOAD, PT_DYNAMIC and RELA inspection. ${load?.reason ?? "The source declarations have not been inspected."}`;
    if (!load.pieFlag)
      return "RISC-V ET_DYN does not declare DF_1_PIE; shared objects are outside this executable PIE lane.";
    if (!load.executableEntry)
      return "RISC-V PIE entry point is not verified in an executable PT_LOAD range.";
    if (
      load.relocationTypes.some((type) => !RISCV_PIE_RELOCATION_TYPES.has(type))
    )
      return "RISC-V PIE dynamic relocations include types outside the verified R_RISCV_NONE, R_RISCV_64, R_RISCV_RELATIVE and R_RISCV_JUMP_SLOT set.";
  }
  const abi = metadata.flags & EF_RISCV_FLOAT_ABI;
  if (abi !== EF_RISCV_FLOAT_ABI_DOUBLE)
    return `This Ghidra RISC-V lane requires the EF_RISCV_FLOAT_ABI_DOUBLE declaration (${riscvUnsupportedFloatAbi(
      abi,
    )} observed); the pinned generic language uses the double-float compiler specification.`;
  const unsupportedFlags = (metadata.flags & ~EF_RISCV_DECLARED_BITS) >>> 0;
  if (unsupportedFlags !== 0)
    return `RISC-V e_flags declares bits outside the verified lane (0x${unsupportedFlags.toString(16)}); reserved or newer declarations are not treated as compatible with this profile.`;
  return null;
};

/** Pin a language only for declarations admitted by the same lane boundary. */
export const ghidraRiscvLanguageOverride = (
  target: BinaryTarget,
): GhidraLanguageOverride | undefined =>
  target.kind === "executable" &&
  target.architecture === "riscv" &&
  ghidraRiscvUnsupportedReason(target) === null
    ? {
        languageId: `RISCV:LE:${target.riscv.elfClass}:default`,
        compilerSpecId: "gcc",
      }
    : undefined;

/** Commit source ELF interpretation without confusing target ISA with host CPU. */
export const ghidraRiscvProfileParameters = (
  target: BinaryTarget,
): Readonly<Record<string, JsonValue>> =>
  target.kind === "executable" &&
  target.architecture === "riscv" &&
  target.riscv !== undefined
    ? {
        riscv_elf: {
          elf_class: target.riscv.elfClass,
          byte_order: target.riscv.byteOrder,
          type: target.riscv.type,
          flags: target.riscv.flags,
          float_abi_double:
            (target.riscv.flags & EF_RISCV_FLOAT_ABI) ===
            EF_RISCV_FLOAT_ABI_DOUBLE,
          rvc_declared: (target.riscv.flags & EF_RISCV_RVC) !== 0,
          rve_declared: (target.riscv.flags & EF_RISCV_RVE) !== 0,
          tso_declared: (target.riscv.flags & EF_RISCV_TSO) !== 0,
        },
        riscv_support_lane:
          target.riscv.type === ET_DYN
            ? "elf64-dyn-le-double-float-generic-pie-v1"
            : target.riscv.elfClass === 32
              ? "elf32-exec-le-double-float-generic-v1"
              : "elf64-exec-le-double-float-generic-v1",
        ...(target.riscv.type === ET_DYN &&
        target.riscv.pieLoad?.status === "complete"
          ? {
              riscv_pie: {
                pie_flag: target.riscv.pieLoad.pieFlag,
                interpreter: target.riscv.pieLoad.interpreter,
                executable_entry: target.riscv.pieLoad.executableEntry,
                needed_library_count: target.riscv.pieLoad.neededLibraryCount,
                relocation_count: target.riscv.pieLoad.relocationCount,
                relocation_types: [...target.riscv.pieLoad.relocationTypes],
                symbol_relocation_count:
                  target.riscv.pieLoad.symbolRelocationCount,
              },
            }
          : {}),
      }
    : {};

/** The pinned language is an analysis convention, not proof of the producer. */
export const ghidraRiscvLimitations = (
  target: BinaryTarget,
): readonly string[] =>
  target.kind === "executable" && target.architecture === "riscv"
    ? [
        `RISC-V ELF: REA pins Ghidra's generic \`RISCV:LE:${target.riscv.elfClass}:default\` language with the \`gcc\` compiler specification instead of accepting the loader's header-based choice, which selects \`RISCV:LE:32:AndeStar_v5\` for ordinary RV32 images on Ghidra 12.1.4.`,
        "The pinned generic language models the double-float ABI declared by `e_flags`; the declaration is recorded as an ELF fact and is not evidence of the original compiler or of verified instruction semantics.",
        ...(target.riscv.type === ET_DYN
          ? [
              "RISC-V PIE: Ghidra's image base and returned addresses are analysis coordinates, not the runtime ASLR base. REA verifies the ELF load ranges and the declared dynamic RELA records; it does not execute the dynamic loader.",
              "PIE dependencies are not loaded. Symbol-bearing relocations may depend on external images; inspect_native_load_image retains Ghidra's relocation status, and unresolved external bindings remain unknown.",
            ]
          : [
              "Admission reads `e_type` only: a fixed-address ET_EXEC declaration does not establish static linkage, and program headers (`PT_INTERP`, dynamic dependencies) are not inspected by this lane.",
            ]),
      ]
    : [];
