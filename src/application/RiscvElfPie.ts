import type {
  RiscvElfMetadata,
  RiscvPieLoadInspection,
} from "../domain/binaryTargetTypes.js";
import { readElfFixedHeader } from "../domain/elfFixedHeader.js";
import type { FileHandle } from "node:fs/promises";
import { err, ok, type Result } from "../domain/result.js";

const ELF64_HEADER_BYTES = 64;
const ELF64_PROGRAM_HEADER_BYTES = 56;
const ELF64_DYNAMIC_ENTRY_BYTES = 16;
const ELF64_RELA_ENTRY_BYTES = 24;
const PT_LOAD = 1;
const PT_DYNAMIC = 2;
const PT_INTERP = 3;
const PF_X = 1;
const PF_W = 2;
const DT_NULL = 0n;
const DT_NEEDED = 1n;
const DT_PLTRELSZ = 2n;
const DT_RELA = 7n;
const DT_RELASZ = 8n;
const DT_RELAENT = 9n;
const DT_REL = 17n;
const DT_RELSZ = 18n;
const DT_RELENT = 19n;
const DT_PLTREL = 20n;
const DT_JMPREL = 23n;
const DT_TEXTREL = 22n;
const DT_FLAGS = 30n;
const DT_RELRSZ = 35n;
const DT_RELR = 36n;
const DT_RELRENT = 37n;
const DT_RELACOUNT = 0x6ffffff9n;
const DT_FLAGS_1 = 0x6ffffffbn;
const DF_TEXTREL = 0x4n;
const DF_1_PIE = 0x08000000n;
const RISCV_RELOCATION_TYPES = new Set([0, 2, 3, 5]);
const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);
const UINT64_LIMIT = 1n << 64n;

interface LoadSegment {
  readonly offset: bigint;
  readonly address: bigint;
  readonly fileSize: bigint;
  readonly memorySize: bigint;
  readonly flags: number;
}

interface ProgramHeader {
  readonly type: number;
  readonly flags: number;
  readonly offset: bigint;
  readonly address: bigint;
  readonly fileSize: bigint;
  readonly memorySize: bigint;
  readonly alignment: bigint;
}

type ReadRange = (
  offset: number,
  length: number,
  label: string,
) => Promise<Result<Buffer, string>>;

const readSafeNumber = (value: bigint): number | undefined =>
  value >= 0n && value <= MAX_SAFE_BIGINT ? Number(value) : undefined;

/**
 * Inspect ELF64 RISC-V PIE load declarations without opening an analysis engine.
 * Unsupported or incomplete declarations remain attached as an unavailable fact.
 */
export const inspectRiscvElfPie = async (
  handle: FileHandle,
  metadata: RiscvElfMetadata,
  checkCancelled: () => void,
): Promise<RiscvPieLoadInspection> => {
  const unavailable = (reason: string): RiscvPieLoadInspection => ({
    status: "unavailable",
    reason,
  });
  checkCancelled();
  const fileSize = (await handle.stat()).size;
  checkCancelled();
  if (!Number.isSafeInteger(fileSize) || fileSize < ELF64_HEADER_BYTES)
    return unavailable(
      "RISC-V PIE file size is invalid or exceeds safe inspection bounds",
    );

  const read: ReadRange = async (offset, length, label) => {
    checkCancelled();
    if (
      !Number.isSafeInteger(offset) ||
      !Number.isSafeInteger(length) ||
      offset < 0 ||
      length < 0 ||
      offset > fileSize - length
    )
      return err(`RISC-V PIE ${label} lies outside the file`);
    const bytes = Buffer.alloc(length);
    let total = 0;
    while (total < length) {
      checkCancelled();
      const observed = await handle.read(
        bytes,
        total,
        length - total,
        offset + total,
      );
      checkCancelled();
      if (observed.bytesRead === 0) return err(`truncated RISC-V PIE ${label}`);
      total += observed.bytesRead;
    }
    return ok(bytes);
  };
  const header = await read(0, ELF64_HEADER_BYTES, "ELF64 header");
  if (!header.ok) return unavailable(header.error);
  const fixed = readElfFixedHeader(header.value, fileSize);
  if (!fixed.ok) return unavailable(fixed.error);
  const bytes = header.value;
  if (
    fixed.value.elfClass !== 64 ||
    fixed.value.byteOrder !== "little" ||
    fixed.value.machine !== 243 ||
    metadata.elfClass !== 64 ||
    metadata.byteOrder !== "little" ||
    metadata.type !== 3 ||
    bytes.readUInt16LE(16) !== metadata.type ||
    bytes.readUInt32LE(48) !== metadata.flags
  )
    return unavailable(
      "RISC-V PIE ELF header no longer matches the resolved identity",
    );
  if (fixed.value.headerSize !== ELF64_HEADER_BYTES)
    return unavailable("invalid RISC-V ELF64 header size");

  const entry = bytes.readBigUInt64LE(24);
  const programOffset = readSafeNumber(bytes.readBigUInt64LE(32));
  const programEntrySize = bytes.readUInt16LE(54);
  const programCount = bytes.readUInt16LE(56);
  if (
    programOffset === undefined ||
    programEntrySize !== ELF64_PROGRAM_HEADER_BYTES ||
    programCount === 0 ||
    programCount === 0xffff
  )
    return unavailable("invalid or extended RISC-V ELF64 program header table");
  const programBytes = programEntrySize * programCount;
  if (programOffset > fileSize - programBytes)
    return unavailable("RISC-V program header table extends beyond the file");
  const programTable = await read(
    programOffset,
    programBytes,
    "program header table",
  );
  if (!programTable.ok) return unavailable(programTable.error);

  const loads: LoadSegment[] = [];
  let dynamic: ProgramHeader | undefined;
  let interpreter: ProgramHeader | undefined;
  for (let index = 0; index < programCount; index += 1) {
    checkCancelled();
    const offset = index * programEntrySize;
    const type = programTable.value.readUInt32LE(offset);
    const flags = programTable.value.readUInt32LE(offset + 4);
    const headerValue: ProgramHeader = {
      type,
      flags,
      offset: programTable.value.readBigUInt64LE(offset + 8),
      address: programTable.value.readBigUInt64LE(offset + 16),
      fileSize: programTable.value.readBigUInt64LE(offset + 32),
      memorySize: programTable.value.readBigUInt64LE(offset + 40),
      alignment: programTable.value.readBigUInt64LE(offset + 48),
    };
    if (type === PT_LOAD) {
      if (
        headerValue.offset + headerValue.fileSize > BigInt(fileSize) ||
        headerValue.fileSize > headerValue.memorySize ||
        headerValue.address + headerValue.memorySize >= UINT64_LIMIT ||
        (headerValue.alignment > 1n &&
          ((headerValue.alignment & (headerValue.alignment - 1n)) !== 0n ||
            headerValue.offset % headerValue.alignment !==
              headerValue.address % headerValue.alignment))
      )
        return unavailable("invalid or incomplete RISC-V PT_LOAD range");
      loads.push({
        offset: headerValue.offset,
        address: headerValue.address,
        fileSize: headerValue.fileSize,
        memorySize: headerValue.memorySize,
        flags,
      });
    } else if (type === PT_DYNAMIC) {
      if (dynamic !== undefined)
        return unavailable("duplicate RISC-V PT_DYNAMIC tables");
      dynamic = headerValue;
    } else if (type === PT_INTERP) {
      if (interpreter !== undefined)
        return unavailable("duplicate RISC-V PT_INTERP segments");
      interpreter = headerValue;
    }
  }
  if (loads.length === 0)
    return unavailable("RISC-V PIE has no PT_LOAD segments");
  loads.sort((left, right) =>
    left.address < right.address ? -1 : left.address > right.address ? 1 : 0,
  );
  for (let index = 1; index < loads.length; index += 1) {
    const previous = loads[index - 1]!;
    if (loads[index]!.address < previous.address + previous.memorySize)
      return unavailable(
        "overlapping RISC-V PT_LOAD memory ranges need separate mapping verification",
      );
  }
  const mapped = (
    address: bigint,
    length: bigint,
    fileBacked: boolean,
    requiredFlags = 0,
  ): LoadSegment | undefined => {
    let low = 0;
    let high = loads.length;
    while (low < high) {
      const middle = Math.floor((low + high) / 2);
      if (loads[middle]!.address <= address) low = middle + 1;
      else high = middle;
    }
    const load = loads[low - 1];
    if (load === undefined) return undefined;
    const available = fileBacked ? load.fileSize : load.memorySize;
    return address + length <= load.address + available &&
      (load.flags & requiredFlags) === requiredFlags
      ? load
      : undefined;
  };
  if (mapped(entry, 2n, true, PF_X) === undefined)
    return unavailable(
      "RISC-V PIE entry point is not in an executable PT_LOAD range",
    );
  if (dynamic === undefined || dynamic.fileSize === 0n)
    return unavailable("RISC-V PIE has no non-empty PT_DYNAMIC table");
  if (
    dynamic.fileSize % BigInt(ELF64_DYNAMIC_ENTRY_BYTES) !== 0n ||
    dynamic.offset + dynamic.fileSize > BigInt(fileSize)
  )
    return unavailable("invalid or incomplete RISC-V ELF64 dynamic table");
  const dynamicLoad = mapped(dynamic.address, dynamic.fileSize, true);
  if (
    dynamicLoad === undefined ||
    dynamicLoad.offset + dynamic.address - dynamicLoad.address !==
      dynamic.offset
  )
    return unavailable(
      "RISC-V PT_DYNAMIC has no unique matching file-backed PT_LOAD range",
    );
  if (interpreter !== undefined) {
    if (
      interpreter.fileSize < 2n ||
      interpreter.fileSize > 4096n ||
      interpreter.fileSize !== interpreter.memorySize ||
      interpreter.offset + interpreter.fileSize > BigInt(fileSize)
    )
      return unavailable("invalid or incomplete RISC-V PT_INTERP range");
    const interpreterSize = readSafeNumber(interpreter.fileSize);
    const interpreterOffset = readSafeNumber(interpreter.offset);
    if (interpreterSize === undefined || interpreterOffset === undefined)
      return unavailable(
        "RISC-V PT_INTERP range exceeds safe inspection bounds",
      );
    const name = await read(interpreterOffset, interpreterSize, "PT_INTERP");
    if (!name.ok) return unavailable(name.error);
    const interpreterLoad = mapped(
      interpreter.address,
      interpreter.fileSize,
      true,
    );
    if (
      interpreterLoad === undefined ||
      interpreterLoad.offset + interpreter.address - interpreterLoad.address !==
        interpreter.offset
    )
      return unavailable(
        "RISC-V PT_INTERP has no unique matching file-backed PT_LOAD range",
      );
    if (name.value.at(-1) !== 0 || name.value.subarray(0, -1).includes(0))
      return unavailable(
        "RISC-V PT_INTERP is not a single NUL-terminated path",
      );
  }

  const relevantTags = new Set([
    DT_PLTRELSZ,
    DT_RELA,
    DT_RELASZ,
    DT_RELAENT,
    DT_REL,
    DT_RELSZ,
    DT_RELENT,
    DT_PLTREL,
    DT_JMPREL,
    DT_TEXTREL,
    DT_FLAGS,
    DT_RELRSZ,
    DT_RELR,
    DT_RELRENT,
    DT_RELACOUNT,
    DT_FLAGS_1,
  ]);
  const tags = new Map<bigint, bigint>();
  let neededLibraryCount = 0;
  let terminated = false;
  const dynamicBytes = readSafeNumber(dynamic.fileSize);
  const dynamicOffset = readSafeNumber(dynamic.offset);
  if (dynamicBytes === undefined || dynamicOffset === undefined)
    return unavailable("RISC-V dynamic table exceeds safe inspection bounds");
  const dynamicChunkBytes =
    Math.floor((64 * 1024) / ELF64_DYNAMIC_ENTRY_BYTES) *
    ELF64_DYNAMIC_ENTRY_BYTES;
  for (
    let offset = 0;
    offset < dynamicBytes && !terminated;
    offset += dynamicChunkBytes
  ) {
    const chunk = await read(
      dynamicOffset + offset,
      Math.min(dynamicChunkBytes, dynamicBytes - offset),
      "dynamic table",
    );
    if (!chunk.ok) return unavailable(chunk.error);
    for (
      let position = 0;
      position < chunk.value.length;
      position += ELF64_DYNAMIC_ENTRY_BYTES
    ) {
      checkCancelled();
      const tag = chunk.value.readBigInt64LE(position);
      const value = chunk.value.readBigUInt64LE(position + 8);
      if (tag === DT_NULL) {
        terminated = true;
        break;
      }
      if (tag === DT_NEEDED) {
        neededLibraryCount += 1;
        continue;
      }
      if (!relevantTags.has(tag)) continue;
      if (tags.has(tag))
        return unavailable(`duplicate RISC-V dynamic tag ${tag.toString()}`);
      tags.set(tag, value);
    }
  }
  if (!terminated)
    return unavailable("RISC-V dynamic table has no DT_NULL terminator");
  if (
    (tags.get(DT_REL) ?? 0n) !== 0n ||
    (tags.get(DT_RELSZ) ?? 0n) !== 0n ||
    (tags.get(DT_RELENT) ?? 0n) !== 0n ||
    (tags.get(DT_RELR) ?? 0n) !== 0n ||
    (tags.get(DT_RELRSZ) ?? 0n) !== 0n ||
    (tags.get(DT_RELRENT) ?? 0n) !== 0n
  )
    return unavailable(
      "RISC-V REL or packed RELR relocations need separate verification",
    );
  if (tags.has(DT_TEXTREL) || ((tags.get(DT_FLAGS) ?? 0n) & DF_TEXTREL) !== 0n)
    return unavailable(
      "RISC-V text relocations are outside the verified PIE lane",
    );

  const relocationTables: {
    readonly address: bigint;
    readonly size: bigint;
  }[] = [];
  let relaTable:
    | { readonly address: bigint; readonly size: bigint }
    | undefined;
  const relaAddress = tags.get(DT_RELA);
  const relaSize = tags.get(DT_RELASZ);
  const relaEntrySize = tags.get(DT_RELAENT);
  if (
    relaAddress !== undefined ||
    relaSize !== undefined ||
    relaEntrySize !== undefined
  ) {
    if (
      relaAddress === undefined ||
      relaSize === undefined ||
      relaEntrySize !== BigInt(ELF64_RELA_ENTRY_BYTES) ||
      relaSize % BigInt(ELF64_RELA_ENTRY_BYTES) !== 0n
    )
      return unavailable(
        "incomplete or invalid RISC-V DT_RELA/DT_RELASZ/DT_RELAENT declaration",
      );
    relaTable =
      relaSize > 0n ? { address: relaAddress, size: relaSize } : undefined;
    if (relaTable !== undefined) relocationTables.push(relaTable);
  }
  const jumpAddress = tags.get(DT_JMPREL);
  const jumpSize = tags.get(DT_PLTRELSZ);
  const jumpType = tags.get(DT_PLTREL);
  if (
    jumpAddress !== undefined ||
    jumpSize !== undefined ||
    jumpType !== undefined
  ) {
    if (
      jumpAddress === undefined ||
      jumpSize === undefined ||
      jumpType !== DT_RELA ||
      jumpSize % BigInt(ELF64_RELA_ENTRY_BYTES) !== 0n
    )
      return unavailable(
        "incomplete or invalid RISC-V DT_JMPREL PLT relocation declaration",
      );
    if (jumpSize > 0n) {
      const jumpTable = { address: jumpAddress, size: jumpSize };
      if (relaTable === undefined) {
        relocationTables.push(jumpTable);
      } else {
        const overlaps =
          jumpTable.address < relaTable.address + relaTable.size &&
          relaTable.address < jumpTable.address + jumpTable.size;
        const contained =
          jumpTable.address >= relaTable.address &&
          jumpTable.address + jumpTable.size <=
            relaTable.address + relaTable.size;
        if (overlaps && !contained)
          return unavailable("RISC-V DT_JMPREL partially overlaps DT_RELA");
        if (!contained) relocationTables.push(jumpTable);
      }
    }
  }
  const orderedTables = [...relocationTables].sort((left, right) =>
    left.address < right.address ? -1 : left.address > right.address ? 1 : 0,
  );
  for (let index = 1; index < orderedTables.length; index += 1) {
    const previous = orderedTables[index - 1]!;
    if (orderedTables[index]!.address < previous.address + previous.size)
      return unavailable(
        "overlapping RISC-V dynamic RELA tables are ambiguous",
      );
  }
  const relativeCount = tags.get(DT_RELACOUNT);
  if (
    relativeCount !== undefined &&
    (relaTable === undefined ||
      relativeCount > relaTable.size / BigInt(ELF64_RELA_ENTRY_BYTES))
  )
    return unavailable(
      "RISC-V DT_RELACOUNT exceeds the declared DT_RELA table",
    );

  const relocationTypes = new Set<number>();
  let relocationCount = 0;
  let symbolRelocationCount = 0;
  const relocationChunkBytes =
    Math.floor((64 * 1024) / ELF64_RELA_ENTRY_BYTES) * ELF64_RELA_ENTRY_BYTES;
  for (const table of relocationTables) {
    const mapping = mapped(table.address, table.size, true);
    if (mapping === undefined)
      return unavailable(
        "RISC-V dynamic RELA table has no unique complete PT_LOAD mapping",
      );
    const fileOffset = readSafeNumber(
      mapping.offset + table.address - mapping.address,
    );
    const size = readSafeNumber(table.size);
    if (fileOffset === undefined || size === undefined)
      return unavailable(
        "RISC-V dynamic RELA table exceeds safe inspection bounds",
      );
    let recordIndex = 0n;
    for (let offset = 0; offset < size; offset += relocationChunkBytes) {
      const chunk = await read(
        fileOffset + offset,
        Math.min(relocationChunkBytes, size - offset),
        "dynamic RELA records",
      );
      if (!chunk.ok) return unavailable(chunk.error);
      for (
        let position = 0;
        position < chunk.value.length;
        position += ELF64_RELA_ENTRY_BYTES
      ) {
        checkCancelled();
        const destination = chunk.value.readBigUInt64LE(position);
        const info = chunk.value.readBigUInt64LE(position + 8);
        const type = Number(info & 0xffffffffn);
        const symbol = info >> 32n;
        if (
          relaTable !== undefined &&
          table.address === relaTable.address &&
          table.size === relaTable.size &&
          relativeCount !== undefined &&
          recordIndex < relativeCount &&
          (type !== 3 || symbol !== 0n)
        )
          return unavailable(
            "RISC-V DT_RELACOUNT does not match the leading R_RISCV_RELATIVE records",
          );
        if (!RISCV_RELOCATION_TYPES.has(type))
          return unavailable(
            `R_RISCV relocation type ${type} needs separate Ghidra verification`,
          );
        if (type === 3 && symbol !== 0n)
          return unavailable(
            "R_RISCV_RELATIVE must not reference a dynamic symbol",
          );
        if (type !== 0 && mapped(destination, 8n, false, PF_W) === undefined)
          return unavailable(
            "RISC-V relocation destination is not in a writable PT_LOAD range",
          );
        relocationTypes.add(type);
        relocationCount += 1;
        if (symbol !== 0n) symbolRelocationCount += 1;
        recordIndex += 1n;
      }
    }
  }
  return {
    status: "complete",
    pieFlag: ((tags.get(DT_FLAGS_1) ?? 0n) & DF_1_PIE) !== 0n,
    interpreter: interpreter !== undefined,
    executableEntry: true,
    neededLibraryCount,
    relocationCount,
    relocationTypes: [...relocationTypes].sort((left, right) => left - right),
    symbolRelocationCount,
  };
};
