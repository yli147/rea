import { mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { RiscvElfMetadata } from "../domain/binaryTargetTypes.js";
import { parseBinaryTarget } from "./BinaryTargetResolver.js";
import { inspectRiscvElfPie } from "./RiscvElfPie.js";

const metadata: RiscvElfMetadata = {
  elfClass: 64,
  byteOrder: "little",
  type: 3,
  flags: 5,
};
const temporaryDirectories: string[] = [];

const fixture = (change: (bytes: Buffer) => void = () => {}): Buffer => {
  const bytes = Buffer.alloc(0x400);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  bytes.writeUInt16LE(3, 16);
  bytes.writeUInt16LE(243, 18);
  bytes.writeUInt32LE(1, 20);
  bytes.writeBigUInt64LE(0x220n, 24);
  bytes.writeBigUInt64LE(64n, 32);
  bytes.writeUInt16LE(64, 52);
  bytes.writeUInt16LE(56, 54);
  bytes.writeUInt16LE(3, 56);
  bytes.writeUInt16LE(64, 58);
  bytes.writeUInt16LE(0, 60);
  bytes.writeUInt32LE(5, 48);
  const program = (
    index: number,
    type: number,
    flags: number,
    offset: number,
    address: number,
    size: number,
  ) => {
    const start = 64 + index * 56;
    bytes.writeUInt32LE(type, start);
    bytes.writeUInt32LE(flags, start + 4);
    bytes.writeBigUInt64LE(BigInt(offset), start + 8);
    bytes.writeBigUInt64LE(BigInt(address), start + 16);
    bytes.writeBigUInt64LE(BigInt(size), start + 32);
    bytes.writeBigUInt64LE(BigInt(size), start + 40);
    bytes.writeBigUInt64LE(1n, start + 48);
  };
  program(0, 1, 7, 0, 0, bytes.length);
  program(1, 2, 6, 0x100, 0x100, 144);
  program(2, 3, 4, 0x1a0, 0x1a0, 11);
  bytes.write("/lib/ld.so\0", 0x1a0, "ascii");
  const dynamicEntries = [
    [0x6ffffffbn, 0x08000000n],
    [7n, 0x200n],
    [8n, 48n],
    [9n, 24n],
    [1n, 1n],
    [23n, 0x218n],
    [2n, 24n],
    [20n, 7n],
    [0n, 0n],
  ] as const;
  dynamicEntries.forEach(([tag, value], index) => {
    const offset = 0x100 + index * 16;
    bytes.writeBigInt64LE(tag, offset);
    bytes.writeBigUInt64LE(value, offset + 8);
  });
  const relative = 0x200;
  bytes.writeBigUInt64LE(0x300n, relative);
  bytes.writeBigUInt64LE(3n, relative + 8);
  bytes.writeBigUInt64LE(0x250n, relative + 16);
  bytes.writeBigUInt64LE(0x308n, relative + 24);
  bytes.writeBigUInt64LE((1n << 32n) | 5n, relative + 32);
  bytes.writeBigUInt64LE(0n, relative + 40);
  change(bytes);
  return bytes;
};

const inspect = async (bytes: Buffer) => {
  const directory = await mkdtemp(join(tmpdir(), "rea-riscv-pie-"));
  temporaryDirectories.push(directory);
  const path = join(directory, "fixture.elf");
  const handle = await open(path, "w+");
  try {
    await handle.writeFile(bytes);
    return await inspectRiscvElfPie(handle, metadata, () => {});
  } finally {
    await handle.close();
  }
};

const resolveTarget = async (bytes: Buffer) => {
  const directory = await mkdtemp(join(tmpdir(), "rea-riscv-pie-target-"));
  temporaryDirectories.push(directory);
  const path = join(directory, "fixture.elf");
  await writeFile(path, bytes);
  return await parseBinaryTarget(path);
};

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe("RISC-V ELF64 PIE inspection", () => {
  it("verifies the entry mapping and dynamic RELA declarations", async () => {
    await expect(inspect(fixture())).resolves.toEqual({
      status: "complete",
      pieFlag: true,
      interpreter: true,
      executableEntry: true,
      neededLibraryCount: 1,
      relocationCount: 2,
      relocationTypes: [3, 5],
      symbolRelocationCount: 1,
    });
  });

  it("attaches PIE facts during normal target resolution", async () => {
    const resolved = await resolveTarget(fixture());
    if (!resolved.ok) throw resolved.error;
    expect(resolved.value).toMatchObject({
      architecture: "riscv",
      riscv: {
        type: 3,
        pieLoad: {
          status: "complete",
          pieFlag: true,
          interpreter: true,
          relocationTypes: [3, 5],
        },
      },
    });
  });

  it("does not admit unsupported relocation types", async () => {
    const result = await inspect(
      fixture((bytes) => bytes.writeBigUInt64LE(99n, 0x208)),
    );
    expect(result).toMatchObject({
      status: "unavailable",
      reason: expect.stringContaining("relocation type 99"),
    });
  });

  it("refuses a relocation outside writable load memory", async () => {
    const result = await inspect(
      fixture((bytes) => bytes.writeBigUInt64LE(0x900n, 0x200)),
    );
    expect(result).toMatchObject({
      status: "unavailable",
      reason: expect.stringContaining("not in a writable PT_LOAD"),
    });
  });

  it("records a missing DF_1_PIE flag as a complete non-PIE declaration", async () => {
    const result = await inspect(
      fixture((bytes) => bytes.writeBigUInt64LE(0n, 0x108)),
    );
    expect(result).toMatchObject({ status: "complete", pieFlag: false });
  });
});
