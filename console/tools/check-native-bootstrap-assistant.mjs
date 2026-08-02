import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { requireIsolatedExecution } from "./lib/execution-environment.mjs";
import {
  assertSupportedNativeTarget,
  inspectPortableExecutable,
  inspectPreparedNativeAssistant,
} from "./lib/native-bootstrap-assistant.mjs";

const consoleRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const [target, binaryInput, artifactFlag, ...unexpectedArguments] = process.argv.slice(2);
if (
  !target ||
  !binaryInput ||
  (artifactFlag !== undefined && artifactFlag !== "--packaged") ||
  unexpectedArguments.length > 0
) {
  throw new Error(
    "usage: node tools/check-native-bootstrap-assistant.mjs TARGET BINARY [--packaged]",
  );
}

function buildPeFixture({
  normalLibrary = "KERNEL32.dll",
  delayLibrary = "USER32.dll",
  machine = 0x8664,
  optionalHeaderMagic = 0x020b,
  delayAttributes = 1,
} = {}) {
  const contents = Buffer.alloc(0x600);
  const peOffset = 0x80;
  const coffHeader = peOffset + 4;
  const optionalHeader = coffHeader + 20;
  const sectionTable = optionalHeader + 0xf0;
  const importDescriptor = 0x200;
  const delayImportDescriptor = 0x240;
  const normalLibraryOffset = 0x300;
  const delayLibraryOffset = 0x320;

  contents.write("MZ", 0, "ascii");
  contents.writeUInt32LE(peOffset, 0x3c);
  contents.write("PE\0\0", peOffset, "binary");
  contents.writeUInt16LE(machine, coffHeader);
  contents.writeUInt16LE(1, coffHeader + 2);
  contents.writeUInt16LE(0xf0, coffHeader + 16);
  contents.writeUInt16LE(0x22, coffHeader + 18);

  contents.writeUInt16LE(optionalHeaderMagic, optionalHeader);
  contents.writeUInt32LE(0x2000, optionalHeader + 56);
  contents.writeUInt32LE(0x200, optionalHeader + 60);
  contents.writeUInt32LE(16, optionalHeader + 108);
  contents.writeUInt32LE(0x1000, optionalHeader + 120);
  contents.writeUInt32LE(40, optionalHeader + 124);
  contents.writeUInt32LE(0x1040, optionalHeader + 216);
  contents.writeUInt32LE(64, optionalHeader + 220);

  contents.write(".rdata\0\0", sectionTable, "binary");
  contents.writeUInt32LE(0x400, sectionTable + 8);
  contents.writeUInt32LE(0x1000, sectionTable + 12);
  contents.writeUInt32LE(0x400, sectionTable + 16);
  contents.writeUInt32LE(0x200, sectionTable + 20);

  contents.writeUInt32LE(0x1100, importDescriptor + 12);
  contents.writeUInt32LE(0x1180, importDescriptor + 16);
  contents.writeUInt32LE(delayAttributes, delayImportDescriptor);
  contents.writeUInt32LE(0x1120, delayImportDescriptor + 4);
  contents.writeUInt32LE(0x1180, delayImportDescriptor + 12);
  contents.write(normalLibrary, normalLibraryOffset, "ascii");
  contents.write(delayLibrary, delayLibraryOffset, "ascii");
  return contents;
}

function requireRejectedPeFixture(label, contents) {
  try {
    inspectPortableExecutable(contents, label);
  } catch {
    return;
  }
  throw new Error(`${label}: hostile PE fixture was accepted`);
}

function assertPeGateFixtures() {
  const nominal = inspectPortableExecutable(buildPeFixture(), "nominal PE fixture");
  if (
    JSON.stringify(nominal.normal) !== JSON.stringify(["KERNEL32.dll"]) ||
    JSON.stringify(nominal.delay) !== JSON.stringify(["USER32.dll"])
  ) {
    throw new Error("nominal PE fixture did not expose normal and delay imports");
  }

  for (const [label, fixture] of [
    [
      "forbidden WebView normal import",
      buildPeFixture({ normalLibrary: "WebView2Loader.dll" }),
    ],
    [
      "forbidden WebKit delay import",
      buildPeFixture({ delayLibrary: "WebKit2.dll" }),
    ],
    [
      "forbidden JavaScriptCore normal import",
      buildPeFixture({ normalLibrary: "JavaScriptCore.dll" }),
    ],
    ["forbidden WPE delay import", buildPeFixture({ delayLibrary: "WPEBackend.dll" })],
    ["non-AMD64 image", buildPeFixture({ machine: 0x014c })],
    ["PE32 image", buildPeFixture({ optionalHeaderMagic: 0x010b })],
    ["absolute delay-import pointers", buildPeFixture({ delayAttributes: 0 })],
  ]) {
    requireRejectedPeFixture(label, fixture);
  }

  const escapedName = buildPeFixture();
  escapedName.writeUInt32LE(0xffff_fff0, 0x200 + 12);
  requireRejectedPeFixture("escaped import name RVA", escapedName);

  const oversizedDirectory = buildPeFixture();
  oversizedDirectory.writeUInt32LE(2 * 1024 * 1024, 0x98 + 124);
  requireRejectedPeFixture("oversized import directory", oversizedDirectory);

  const unterminatedDirectory = buildPeFixture();
  unterminatedDirectory.writeUInt32LE(0x1100, 0x200 + 20 + 12);
  unterminatedDirectory.writeUInt32LE(0x1180, 0x200 + 20 + 16);
  requireRejectedPeFixture("unterminated import directory", unterminatedDirectory);

  const unterminatedName = buildPeFixture();
  unterminatedName.fill(0x41, 0x300, 0x300 + 260);
  requireRejectedPeFixture("unterminated import library name", unterminatedName);
}

requireIsolatedExecution("native assistant Cargo/ELF gate");
assertSupportedNativeTarget(target);
assertPeGateFixtures();

const inspection = await inspectPreparedNativeAssistant(
  resolve(binaryInput),
  resolve(consoleRoot, "src-tauri", "Cargo.toml"),
  target,
  { artifactKind: artifactFlag === "--packaged" ? "packaged" : "external-bin" },
);
process.stdout.write(`${JSON.stringify(inspection, null, 2)}\n`);
