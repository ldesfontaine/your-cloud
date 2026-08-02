import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { basename, resolve } from "node:path";

export const NATIVE_ASSISTANT_PACKAGE = "your-cloud-native-bootstrap-assistant";
export const NATIVE_ASSISTANT_BINARY = "your-cloud-native-bootstrap-assistant";
export const BOOTSTRAP_PROTOCOL_PACKAGE = "your-cloud-bootstrap-protocol";
export const NATIVE_ASSISTANT_EXTERNAL_BIN = "binaries/your-cloud-native-bootstrap-assistant";

export const SUPPORTED_NATIVE_TARGETS = Object.freeze([
  "x86_64-unknown-linux-gnu",
  "x86_64-pc-windows-msvc",
]);

const FORBIDDEN_ELF_LIBRARY =
  /^lib(?:javascriptcore|webkit|wpe)[A-Za-z0-9_.+-]*\.so(?:\.\d+)*$/iu;
const FORBIDDEN_PE_LIBRARY = /(?:webview|webkit|javascriptcore|wpe)/iu;

const MAX_PE_FILE_BYTES = 64 * 1024 * 1024;
const MAX_PE_SECTIONS = 96;
const MAX_PE_IMPORT_DIRECTORY_BYTES = 1024 * 1024;
const MAX_PE_IMPORT_DESCRIPTORS = 4096;
const MAX_PE_LIBRARY_NAME_BYTES = 260;
const PE_MACHINE_AMD64 = 0x8664;
const PE32_PLUS_MAGIC = 0x020b;
const PE_EXECUTABLE_IMAGE = 0x0002;
const PE_OPTIONAL_HEADER_DATA_DIRECTORIES_OFFSET = 112;
const PE_IMPORT_DIRECTORY_INDEX = 1;
const PE_DELAY_IMPORT_DIRECTORY_INDEX = 13;
const PE_IMPORT_DESCRIPTOR_BYTES = 20;
const PE_DELAY_IMPORT_DESCRIPTOR_BYTES = 32;
const PE_DELAY_IMPORT_USES_RVAS = 1;

export function runBounded(command, args, options = {}) {
  return execFileSync(command, args, {
    cwd: options.cwd,
    encoding: "utf8",
    env: { ...process.env, LC_ALL: "C" },
    maxBuffer: options.maxBuffer ?? 16 * 1024 * 1024,
    stdio: options.stdio ?? ["ignore", "pipe", "pipe"],
    timeout: options.timeout ?? 120_000,
  });
}

export function assertSupportedNativeTarget(target) {
  if (!SUPPORTED_NATIVE_TARGETS.includes(target)) {
    throw new Error(
      `unsupported native assistant target ${JSON.stringify(target)}; expected ${SUPPORTED_NATIVE_TARGETS.join(" or ")}`,
    );
  }
  return target;
}

export function nativeAssistantFileName(target) {
  assertSupportedNativeTarget(target);
  return `${NATIVE_ASSISTANT_BINARY}-${target}${target.endsWith("-windows-msvc") ? ".exe" : ""}`;
}

export function nativeAssistantBuildFileName(target) {
  assertSupportedNativeTarget(target);
  return `${NATIVE_ASSISTANT_BINARY}${target.endsWith("-windows-msvc") ? ".exe" : ""}`;
}

export function nativeAssistantPackagedFileName(target) {
  return nativeAssistantBuildFileName(target);
}

export function resolveNativeTarget(requestedTarget) {
  const hostTarget = runBounded("rustc", ["--print", "host-tuple"], {
    timeout: 30_000,
  }).trim();
  assertSupportedNativeTarget(hostTarget);

  const target = requestedTarget === undefined ? hostTarget : requestedTarget;
  assertSupportedNativeTarget(target);
  if (target !== hostTarget) {
    throw new Error(
      `cross-compilation is refused for the native assistant: host ${hostTarget}, requested ${target}`,
    );
  }
  return target;
}

function cargoPackageName(line) {
  return line.match(/^([A-Za-z0-9_.-]+) v\d/iu)?.[1];
}

export function nativeAssistantCargoPackageIsForbidden(name) {
  const normalized = name.toLowerCase();
  return (
    normalized === "your-cloud-console" ||
    normalized === "tauri" ||
    normalized.startsWith("tauri-") ||
    normalized === "tao" ||
    normalized.startsWith("tao-") ||
    normalized === "wry" ||
    normalized.startsWith("wry-") ||
    normalized.startsWith("webkit") ||
    normalized.startsWith("javascriptcore") ||
    normalized === "wpe" ||
    normalized.startsWith("wpe-")
  );
}

export function nativeAssistantElfLibraryIsForbidden(name) {
  return FORBIDDEN_ELF_LIBRARY.test(name);
}

export function nativeAssistantPeLibraryIsForbidden(name) {
  return FORBIDDEN_PE_LIBRARY.test(name);
}

export function inspectNativeAssistantCargoGraph(cargoManifest, target) {
  assertSupportedNativeTarget(target);
  const graph = runBounded(
    "cargo",
    [
      "tree",
      "--manifest-path",
      resolve(cargoManifest),
      "--package",
      NATIVE_ASSISTANT_PACKAGE,
      "--target",
      target,
      "--edges",
      "normal,build",
      "--prefix",
      "none",
      "--format",
      "{p}",
      "--no-dedupe",
      "--no-default-features",
      "--locked",
      "--offline",
    ],
    { timeout: 180_000 },
  );
  const packages = [
    ...new Set(graph.split(/\r?\n/u).map(cargoPackageName).filter(Boolean)),
  ].sort();
  const forbidden = packages.filter(nativeAssistantCargoPackageIsForbidden);

  if (!packages.includes(NATIVE_ASSISTANT_PACKAGE)) {
    throw new Error(`Cargo graph does not contain ${NATIVE_ASSISTANT_PACKAGE}`);
  }
  if (!packages.includes(BOOTSTRAP_PROTOCOL_PACKAGE)) {
    throw new Error(`Cargo graph does not contain ${BOOTSTRAP_PROTOCOL_PACKAGE}`);
  }
  if (forbidden.length > 0) {
    throw new Error(
      `native assistant Cargo graph contains forbidden packages: ${forbidden.join(", ")}`,
    );
  }

  return {
    packages,
    sha256: createHash("sha256").update(graph, "utf8").digest("hex"),
  };
}

export async function inspectDirectElfDependencies(binary) {
  const contents = await readFile(binary);
  if (!contents.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) {
    throw new Error(`${binary}: expected an ELF executable`);
  }

  const dynamicSection = runBounded("readelf", ["-dW", resolve(binary)], {
    timeout: 30_000,
  });
  const needed = [
    ...new Set(
      [...dynamicSection.matchAll(/\(NEEDED\).*Shared library: \[([^\]]+)\]/gu)].map(
        (match) => match[1],
      ),
    ),
  ].sort();
  const forbidden = needed.filter(nativeAssistantElfLibraryIsForbidden);

  if (needed.length === 0) {
    throw new Error(`${binary}: no ELF DT_NEEDED entry was found for the GNU target`);
  }
  if (forbidden.length > 0) {
    throw new Error(
      `native assistant ELF links forbidden WebKit/JavaScriptCore/WPE libraries: ${forbidden.join(", ")}`,
    );
  }
  return needed;
}

function requirePeRange(contents, offset, length, context) {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(length) ||
    offset < 0 ||
    length < 0 ||
    offset > contents.length - length
  ) {
    throw new Error(`${context}: range escapes the PE file`);
  }
  return offset;
}

function readPeUint16(contents, offset, context) {
  return contents.readUInt16LE(requirePeRange(contents, offset, 2, context));
}

function readPeUint32(contents, offset, context) {
  return contents.readUInt32LE(requirePeRange(contents, offset, 4, context));
}

function parsePeHeaders(contents, binaryLabel) {
  if (!Buffer.isBuffer(contents)) {
    throw new Error(`${binaryLabel}: PE inspection requires a Buffer`);
  }
  if (contents.length === 0 || contents.length > MAX_PE_FILE_BYTES) {
    throw new Error(
      `${binaryLabel}: PE file size must be between 1 and ${MAX_PE_FILE_BYTES} bytes`,
    );
  }
  requirePeRange(contents, 0, 0x40, `${binaryLabel}: DOS header`);
  if (contents.subarray(0, 2).toString("ascii") !== "MZ") {
    throw new Error(`${binaryLabel}: expected an MZ executable`);
  }

  const peOffset = readPeUint32(contents, 0x3c, `${binaryLabel}: PE offset`);
  requirePeRange(contents, peOffset, 24, `${binaryLabel}: PE and COFF headers`);
  if (!contents.subarray(peOffset, peOffset + 4).equals(Buffer.from("PE\0\0", "binary"))) {
    throw new Error(`${binaryLabel}: expected a PE signature`);
  }

  const coffHeader = peOffset + 4;
  const machine = readPeUint16(contents, coffHeader, `${binaryLabel}: COFF machine`);
  if (machine !== PE_MACHINE_AMD64) {
    throw new Error(
      `${binaryLabel}: expected the AMD64 COFF machine 0x${PE_MACHINE_AMD64.toString(16)}`,
    );
  }
  const sectionCount = readPeUint16(
    contents,
    coffHeader + 2,
    `${binaryLabel}: COFF section count`,
  );
  if (sectionCount === 0 || sectionCount > MAX_PE_SECTIONS) {
    throw new Error(
      `${binaryLabel}: PE section count must be between 1 and ${MAX_PE_SECTIONS}`,
    );
  }
  const optionalHeaderBytes = readPeUint16(
    contents,
    coffHeader + 16,
    `${binaryLabel}: optional header size`,
  );
  const characteristics = readPeUint16(
    contents,
    coffHeader + 18,
    `${binaryLabel}: COFF characteristics`,
  );
  if ((characteristics & PE_EXECUTABLE_IMAGE) === 0) {
    throw new Error(`${binaryLabel}: COFF image is not executable`);
  }
  const optionalHeader = coffHeader + 20;
  requirePeRange(
    contents,
    optionalHeader,
    optionalHeaderBytes,
    `${binaryLabel}: optional header`,
  );
  if (
    readPeUint16(contents, optionalHeader, `${binaryLabel}: optional header magic`) !==
    PE32_PLUS_MAGIC
  ) {
    throw new Error(`${binaryLabel}: expected a PE32+ optional header`);
  }
  if (optionalHeaderBytes < PE_OPTIONAL_HEADER_DATA_DIRECTORIES_OFFSET) {
    throw new Error(`${binaryLabel}: truncated PE32+ optional header`);
  }

  const directoryCount = readPeUint32(
    contents,
    optionalHeader + 108,
    `${binaryLabel}: data directory count`,
  );
  const availableDirectoryCount = Math.floor(
    (optionalHeaderBytes - PE_OPTIONAL_HEADER_DATA_DIRECTORIES_OFFSET) / 8,
  );
  if (
    directoryCount <= PE_DELAY_IMPORT_DIRECTORY_INDEX ||
    directoryCount > availableDirectoryCount
  ) {
    throw new Error(
      `${binaryLabel}: optional header does not expose bounded import and delay-import directories`,
    );
  }

  const sizeOfHeaders = readPeUint32(
    contents,
    optionalHeader + 60,
    `${binaryLabel}: SizeOfHeaders`,
  );
  const sectionTable = optionalHeader + optionalHeaderBytes;
  const sectionTableBytes = sectionCount * 40;
  requirePeRange(
    contents,
    sectionTable,
    sectionTableBytes,
    `${binaryLabel}: section table`,
  );
  if (
    sizeOfHeaders < sectionTable + sectionTableBytes ||
    sizeOfHeaders > contents.length
  ) {
    throw new Error(`${binaryLabel}: invalid SizeOfHeaders`);
  }

  const sections = [];
  for (let index = 0; index < sectionCount; index += 1) {
    const section = sectionTable + index * 40;
    const virtualSize = readPeUint32(
      contents,
      section + 8,
      `${binaryLabel}: section ${index} virtual size`,
    );
    const virtualAddress = readPeUint32(
      contents,
      section + 12,
      `${binaryLabel}: section ${index} virtual address`,
    );
    const rawSize = readPeUint32(
      contents,
      section + 16,
      `${binaryLabel}: section ${index} raw size`,
    );
    const rawOffset = readPeUint32(
      contents,
      section + 20,
      `${binaryLabel}: section ${index} raw offset`,
    );
    if (rawSize > 0) {
      requirePeRange(
        contents,
        rawOffset,
        rawSize,
        `${binaryLabel}: section ${index} raw data`,
      );
    }
    if (virtualAddress + Math.max(virtualSize, rawSize) > 0x1_0000_0000) {
      throw new Error(`${binaryLabel}: section ${index} virtual range overflows an RVA`);
    }
    sections.push({ virtualSize, virtualAddress, rawSize, rawOffset });
  }

  function rvaToFileOffset(rva, length, context) {
    if (!Number.isSafeInteger(rva) || rva <= 0 || rva > 0xffff_ffff) {
      throw new Error(`${context}: invalid RVA`);
    }
    if (!Number.isSafeInteger(length) || length <= 0 || rva + length > 0x1_0000_0000) {
      throw new Error(`${context}: invalid RVA length`);
    }

    const matches = [];
    if (rva < sizeOfHeaders && rva + length <= sizeOfHeaders) {
      matches.push(requirePeRange(contents, rva, length, context));
    }
    for (const section of sections) {
      const mappedSize = Math.max(section.virtualSize, section.rawSize);
      if (rva < section.virtualAddress || rva >= section.virtualAddress + mappedSize) {
        continue;
      }
      const sectionOffset = rva - section.virtualAddress;
      if (sectionOffset + length > section.rawSize) {
        throw new Error(`${context}: RVA is not fully backed by section bytes`);
      }
      matches.push(
        requirePeRange(contents, section.rawOffset + sectionOffset, length, context),
      );
    }
    if (matches.length !== 1) {
      throw new Error(`${context}: RVA must map to exactly one file range`);
    }
    return matches[0];
  }

  function dataDirectory(index, name) {
    const directory =
      optionalHeader + PE_OPTIONAL_HEADER_DATA_DIRECTORIES_OFFSET + index * 8;
    const rva = readPeUint32(contents, directory, `${binaryLabel}: ${name} RVA`);
    const size = readPeUint32(contents, directory + 4, `${binaryLabel}: ${name} size`);
    if (rva === 0 && size === 0) return null;
    if (rva === 0 || size === 0) {
      throw new Error(`${binaryLabel}: ${name} must have both an RVA and a size`);
    }
    if (size > MAX_PE_IMPORT_DIRECTORY_BYTES) {
      throw new Error(
        `${binaryLabel}: ${name} exceeds ${MAX_PE_IMPORT_DIRECTORY_BYTES} bytes`,
      );
    }
    return {
      offset: rvaToFileOffset(rva, size, `${binaryLabel}: ${name}`),
      size,
    };
  }

  return { binaryLabel, contents, dataDirectory, rvaToFileOffset };
}

function readPeLibraryName(headers, nameRva, context) {
  const bytes = [];
  for (let index = 0; index < MAX_PE_LIBRARY_NAME_BYTES; index += 1) {
    const offset = headers.rvaToFileOffset(nameRva + index, 1, context);
    const value = headers.contents[offset];
    if (value === 0) {
      if (bytes.length === 0) throw new Error(`${context}: empty library name`);
      const library = Buffer.from(bytes).toString("ascii");
      if (!library.toLowerCase().endsWith(".dll")) {
        throw new Error(`${context}: imported library must use a .dll basename`);
      }
      return library;
    }
    if (value < 0x21 || value > 0x7e || value === 0x2f || value === 0x3a || value === 0x5c) {
      throw new Error(`${context}: imported library is not a printable ASCII basename`);
    }
    bytes.push(value);
  }
  throw new Error(
    `${context}: imported library exceeds ${MAX_PE_LIBRARY_NAME_BYTES - 1} bytes`,
  );
}

function readPeImportDirectory(headers) {
  const directory = headers.dataDirectory(PE_IMPORT_DIRECTORY_INDEX, "import directory");
  if (directory === null) return [];
  if (
    directory.size % PE_IMPORT_DESCRIPTOR_BYTES !== 0 ||
    directory.size / PE_IMPORT_DESCRIPTOR_BYTES > MAX_PE_IMPORT_DESCRIPTORS
  ) {
    throw new Error(`${headers.binaryLabel}: invalid import directory size`);
  }

  const libraries = [];
  let terminated = false;
  for (let offset = 0; offset < directory.size; offset += PE_IMPORT_DESCRIPTOR_BYTES) {
    const descriptor = directory.offset + offset;
    const fields = Array.from({ length: 5 }, (_, index) =>
      readPeUint32(
        headers.contents,
        descriptor + index * 4,
        `${headers.binaryLabel}: import descriptor`,
      ),
    );
    if (fields.every((value) => value === 0)) {
      terminated = true;
      break;
    }
    libraries.push(
      readPeLibraryName(
        headers,
        fields[3],
        `${headers.binaryLabel}: import descriptor library`,
      ),
    );
  }
  if (!terminated) {
    throw new Error(`${headers.binaryLabel}: unterminated import directory`);
  }
  return libraries;
}

function readPeDelayImportDirectory(headers) {
  const directory = headers.dataDirectory(
    PE_DELAY_IMPORT_DIRECTORY_INDEX,
    "delay-import directory",
  );
  if (directory === null) return [];
  if (
    directory.size % PE_DELAY_IMPORT_DESCRIPTOR_BYTES !== 0 ||
    directory.size / PE_DELAY_IMPORT_DESCRIPTOR_BYTES > MAX_PE_IMPORT_DESCRIPTORS
  ) {
    throw new Error(`${headers.binaryLabel}: invalid delay-import directory size`);
  }

  const libraries = [];
  let terminated = false;
  for (
    let offset = 0;
    offset < directory.size;
    offset += PE_DELAY_IMPORT_DESCRIPTOR_BYTES
  ) {
    const descriptor = directory.offset + offset;
    const fields = Array.from({ length: 8 }, (_, index) =>
      readPeUint32(
        headers.contents,
        descriptor + index * 4,
        `${headers.binaryLabel}: delay-import descriptor`,
      ),
    );
    if (fields.every((value) => value === 0)) {
      terminated = true;
      break;
    }
    if (fields[0] !== PE_DELAY_IMPORT_USES_RVAS) {
      throw new Error(
        `${headers.binaryLabel}: delay-import descriptor must use PE32+ RVAs`,
      );
    }
    libraries.push(
      readPeLibraryName(
        headers,
        fields[1],
        `${headers.binaryLabel}: delay-import descriptor library`,
      ),
    );
  }
  if (!terminated) {
    throw new Error(`${headers.binaryLabel}: unterminated delay-import directory`);
  }
  return libraries;
}

function sortedUniquePeLibraries(libraries) {
  const byNormalizedName = new Map();
  for (const library of libraries) {
    const normalized = library.toLowerCase();
    if (!byNormalizedName.has(normalized)) byNormalizedName.set(normalized, library);
  }
  return [...byNormalizedName.values()].sort((left, right) => {
    const normalizedLeft = left.toLowerCase();
    const normalizedRight = right.toLowerCase();
    if (normalizedLeft < normalizedRight) return -1;
    if (normalizedLeft > normalizedRight) return 1;
    return left < right ? -1 : left > right ? 1 : 0;
  });
}

export function inspectPortableExecutable(contents, binaryLabel = "PE fixture") {
  const headers = parsePeHeaders(contents, binaryLabel);
  const normal = sortedUniquePeLibraries(readPeImportDirectory(headers));
  const delay = sortedUniquePeLibraries(readPeDelayImportDirectory(headers));
  const all = sortedUniquePeLibraries([...normal, ...delay]);
  if (normal.length === 0) {
    throw new Error(`${binaryLabel}: no direct PE import was found for the MSVC target`);
  }
  const forbidden = all.filter(nativeAssistantPeLibraryIsForbidden);
  if (forbidden.length > 0) {
    throw new Error(
      `native assistant PE imports forbidden WebView/WebKit/JavaScriptCore/WPE libraries: ${forbidden.join(", ")}`,
    );
  }
  return { format: "PE32+", machine: "AMD64", normal, delay, all };
}

export async function inspectPreparedNativeAssistant(
  binary,
  cargoManifest,
  target,
  options = {},
) {
  assertSupportedNativeTarget(target);
  const artifactKind = options.artifactKind ?? "external-bin";
  if (!new Set(["external-bin", "packaged"]).has(artifactKind)) {
    throw new Error(`unsupported native assistant artifact kind ${JSON.stringify(artifactKind)}`);
  }
  const expectedName =
    artifactKind === "packaged"
      ? nativeAssistantPackagedFileName(target)
      : nativeAssistantFileName(target);
  if (basename(binary) !== expectedName) {
    throw new Error(`${binary}: expected the exact ${artifactKind} filename ${expectedName}`);
  }

  const metadata = await stat(binary);
  if (!metadata.isFile() || metadata.size === 0) {
    throw new Error(`${binary}: native assistant must be a non-empty regular file`);
  }
  if (target === "x86_64-unknown-linux-gnu" && (metadata.mode & 0o111) === 0) {
    throw new Error(`${binary}: native assistant is not executable`);
  }
  if (target === "x86_64-pc-windows-msvc" && metadata.size > MAX_PE_FILE_BYTES) {
    throw new Error(`${binary}: native assistant exceeds the bounded PE gate size`);
  }

  const cargo = inspectNativeAssistantCargoGraph(cargoManifest, target);
  const contents = await readFile(binary);
  const elf =
    target === "x86_64-unknown-linux-gnu"
      ? await inspectDirectElfDependencies(binary)
      : null;
  const pe =
    target === "x86_64-pc-windows-msvc"
      ? inspectPortableExecutable(contents, binary)
      : null;
  return {
    target,
    size: metadata.size,
    sha256: createHash("sha256").update(contents).digest("hex"),
    cargo,
    elf_direct_needed: elf,
    pe_imports: pe,
  };
}
