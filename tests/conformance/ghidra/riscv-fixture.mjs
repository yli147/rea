import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execute = promisify(execFile);

/** Build and independently inspect a source-owned ELF; never execute it. */
export async function buildRiscvFixture(directory, bits) {
  assert.ok(bits === 32 || bits === 64);
  const compiler = process.env.REA_RISCV_CLANG ?? "clang";
  const linker = process.env.REA_RISCV_LLD ?? "ld.lld";
  const reader = process.env.REA_RISCV_READELF ?? "llvm-readelf";
  const source = fileURLToPath(new URL("../c/riscv.c", import.meta.url));
  const probe = fileURLToPath(new URL("./riscv-probe.S", import.meta.url));
  const path = join(directory, `rv${bits}.elf`);
  const args = [
    `--target=riscv${bits}-unknown-elf`,
    `-march=rv${bits}imafdc`,
    `-mabi=${bits === 32 ? "ilp32d" : "lp64d"}`,
    `--ld-path=${linker}`,
    "-nostdlib",
    "-static",
    "-fno-pic",
    "-O0",
    "-g",
    "-Wl,-e,rea_riscv_entry",
    "-Wl,--build-id=none",
    source,
    probe,
    "-o",
    path,
  ];
  const options = { timeout: 10000, maxBuffer: 1024 * 1024 };
  const compilerVersion = await execute(compiler, ["--version"], options);
  const linkerVersion = await execute(linker, ["--version"], options);
  const readerVersion = await execute(reader, ["--version"], options);
  await execute(compiler, args, { ...options, timeout: 60000 });
  const { stdout, stderr } = await execute(reader, ["-h", "-s", "-W", path], {
    ...options,
    env: { ...process.env, LC_ALL: "C" },
  });
  assert.equal(stderr.trim(), "", "Unexpected ELF reader diagnostics");
  const field = (expression, label) => {
    const matches = [...stdout.matchAll(expression)];
    assert.equal(matches.length, 1, `Missing or ambiguous readelf ${label}`);
    return matches[0][1].trim();
  };
  assert.equal(field(/^\s*Class:\s*(.+)$/gmu, "class"), `ELF${bits}`);
  assert.match(field(/^\s*Data:\s*(.+)$/gmu, "byte order"), /little endian/u);
  assert.match(field(/^\s*Type:\s*(.+)$/gmu, "type"), /^EXEC\b/u);
  assert.match(field(/^\s*Machine:\s*(.+)$/gmu, "machine"), /^RISC-V\b/u);
  const flags = Number(field(/^\s*Flags:\s*(0x[\da-f]+).*$/gmu, "flags"));
  assert.equal(flags, 5, "Compiler did not declare RVC and double-float ABI");
  const symbols = {};
  for (const name of [
    "rea_riscv_entry",
    "rea_riscv_leaf",
    "rea_riscv_float",
    "rea_riscv_probe",
    "rea_riscv_global",
  ]) {
    const value = field(
      new RegExp(
        `^\\s*\\d+:\\s+([\\da-f]+)\\s+\\d+\\s+(?:FUNC|OBJECT)\\s+GLOBAL\\s+\\S+\\s+\\d+\\s+${name}\\s*$`,
        "gmu",
      ),
      name,
    );
    symbols[name] = `0x${BigInt(`0x${value}`).toString(16)}`;
  }
  return {
    path,
    sha256: createHash("sha256")
      .update(await readFile(path))
      .digest("hex"),
    riscv: { elfClass: bits, byteOrder: "little", type: 2, flags },
    symbols,
    toolchain: {
      compiler: { command: compiler, version: compilerVersion.stdout.trim() },
      linker: { command: linker, version: linkerVersion.stdout.trim() },
      reader: { command: reader, version: readerVersion.stdout.trim() },
      arguments: args,
    },
    sources: await Promise.all(
      [source, probe].map(async (sourcePath) => ({
        path: sourcePath,
        sha256: createHash("sha256")
          .update(await readFile(sourcePath))
          .digest("hex"),
      })),
    ),
  };
}

/** Build a small ELF64 PIE with one source-owned relative data relocation. */
export async function buildRiscvPieFixture(directory) {
  const compiler = process.env.REA_RISCV_CLANG ?? "clang";
  const linker = process.env.REA_RISCV_LLD ?? "ld.lld";
  const reader = process.env.REA_RISCV_READELF ?? "llvm-readelf";
  const source = fileURLToPath(new URL("../c/riscv-pie.c", import.meta.url));
  const path = join(directory, "rv64-pie.elf");
  const args = [
    "--target=riscv64-unknown-linux-gnu",
    "-march=rv64imafdc",
    "-mabi=lp64d",
    `--ld-path=${linker}`,
    "-nostdlib",
    "-fPIE",
    "-pie",
    "-O0",
    "-Wl,-e,rea_riscv_pie_entry",
    "-Wl,--build-id=none",
    source,
    "-o",
    path,
  ];
  const options = { timeout: 10000, maxBuffer: 1024 * 1024 };
  const compilerVersion = await execute(compiler, ["--version"], options);
  const linkerVersion = await execute(linker, ["--version"], options);
  const readerVersion = await execute(reader, ["--version"], options);
  await execute(compiler, args, { ...options, timeout: 60000 });
  const { stdout, stderr } = await execute(
    reader,
    ["-h", "-l", "-d", "-r", "-s", "-W", path],
    {
      ...options,
      env: { ...process.env, LC_ALL: "C" },
    },
  );
  assert.equal(stderr.trim(), "", "Unexpected ELF reader diagnostics");
  const field = (expression, label) => {
    const matches = [...stdout.matchAll(expression)];
    assert.equal(matches.length, 1, `Missing or ambiguous readelf ${label}`);
    return matches[0][1].trim();
  };
  assert.equal(field(/^\s*Class:\s*(.+)$/gmu, "class"), "ELF64");
  assert.match(field(/^\s*Data:\s*(.+)$/gmu, "byte order"), /little endian/u);
  assert.match(field(/^\s*Type:\s*(.+)$/gmu, "type"), /^DYN\b/u);
  assert.match(field(/^\s*Machine:\s*(.+)$/gmu, "machine"), /^RISC-V\b/u);
  assert.equal(
    Number(field(/^\s*Flags:\s*(0x[\da-f]+).*$/gmu, "flags")),
    5,
    "Compiler did not declare RVC and double-float ABI",
  );
  assert.match(stdout, /\(FLAGS_1\).*PIE/u);
  assert.match(stdout, /\bDYNAMIC\b/u);
  assert.match(stdout, /R_RISCV_RELATIVE/u);
  for (const name of ["rea_riscv_pie_entry", "rea_riscv_pie_global"]) {
    assert.match(stdout, new RegExp(`\\b${name}\\b`, "u"));
  }
  return {
    path,
    sha256: createHash("sha256")
      .update(await readFile(path))
      .digest("hex"),
    symbols: {
      rea_riscv_pie_entry: `0x${BigInt(
        `0x${field(
          /^\s*\d+:\s+([\da-f]+)\s+\d+\s+FUNC\s+GLOBAL\s+\S+\s+\d+\s+rea_riscv_pie_entry\s*$/gmu,
          "PIE entry symbol",
        )}`,
      ).toString(16)}`,
      rea_riscv_pie_global: `0x${BigInt(
        `0x${field(
          /^\s*\d+:\s+([\da-f]+)\s+\d+\s+OBJECT\s+GLOBAL\s+\S+\s+\d+\s+rea_riscv_pie_global\s*$/gmu,
          "PIE global symbol",
        )}`,
      ).toString(16)}`,
    },
    toolchain: {
      compiler: { command: compiler, version: compilerVersion.stdout.trim() },
      linker: { command: linker, version: linkerVersion.stdout.trim() },
      reader: { command: reader, version: readerVersion.stdout.trim() },
      arguments: args,
    },
    source: {
      path: source,
      sha256: createHash("sha256")
        .update(await readFile(source))
        .digest("hex"),
    },
  };
}
