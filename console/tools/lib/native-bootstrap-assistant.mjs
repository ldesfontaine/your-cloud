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

export async function inspectPreparedNativeAssistant(binary, cargoManifest, target) {
  assertSupportedNativeTarget(target);
  const expectedName = nativeAssistantFileName(target);
  if (basename(binary) !== expectedName) {
    throw new Error(`${binary}: expected the exact externalBin filename ${expectedName}`);
  }

  const metadata = await stat(binary);
  if (!metadata.isFile() || metadata.size === 0) {
    throw new Error(`${binary}: native assistant must be a non-empty regular file`);
  }
  if (target === "x86_64-unknown-linux-gnu" && (metadata.mode & 0o111) === 0) {
    throw new Error(`${binary}: native assistant is not executable`);
  }

  const cargo = inspectNativeAssistantCargoGraph(cargoManifest, target);
  const elf =
    target === "x86_64-unknown-linux-gnu"
      ? await inspectDirectElfDependencies(binary)
      : null;
  return {
    target,
    size: metadata.size,
    sha256: createHash("sha256").update(await readFile(binary)).digest("hex"),
    cargo,
    elf_direct_needed: elf,
  };
}
