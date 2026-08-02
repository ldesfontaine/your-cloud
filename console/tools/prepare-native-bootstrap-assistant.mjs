import { createHash, randomUUID } from "node:crypto";
import { chmod, copyFile, mkdir, readFile, rename, rm, stat } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { requireIsolatedExecution } from "./lib/execution-environment.mjs";
import {
  NATIVE_ASSISTANT_PACKAGE,
  inspectPreparedNativeAssistant,
  nativeAssistantBuildFileName,
  nativeAssistantFileName,
  resolveNativeTarget,
  runBounded,
} from "./lib/native-bootstrap-assistant.mjs";

const consoleRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const tauriRoot = resolve(consoleRoot, "src-tauri");
const cargoManifest = resolve(tauriRoot, "Cargo.toml");
const targetDirectory = resolve(
  tauriRoot,
  process.env.CARGO_TARGET_DIR ?? resolve(tauriRoot, "target"),
);
const externalBinDirectory = resolve(tauriRoot, "binaries");

const [profile, ...unexpectedArguments] = process.argv.slice(2);
if (!new Set(["debug", "release"]).has(profile) || unexpectedArguments.length > 0) {
  throw new Error(
    "usage: node tools/prepare-native-bootstrap-assistant.mjs <debug|release>",
  );
}

const executionEnvironment = requireIsolatedExecution("native assistant build");
const target = resolveNativeTarget(process.env.YOUR_CLOUD_NATIVE_TARGET);
const destination = resolve(externalBinDirectory, nativeAssistantFileName(target));
if (relative(externalBinDirectory, destination).startsWith("..")) {
  throw new Error("native assistant destination escapes src-tauri/binaries");
}

const cargoArguments = [
  "build",
  "--manifest-path",
  cargoManifest,
  "--package",
  NATIVE_ASSISTANT_PACKAGE,
  "--bin",
  NATIVE_ASSISTANT_PACKAGE,
  "--target",
  target,
  "--target-dir",
  targetDirectory,
  "--locked",
  "--offline",
];
if (profile === "release") cargoArguments.push("--release");

runBounded("cargo", cargoArguments, {
  cwd: tauriRoot,
  stdio: "inherit",
  timeout: 20 * 60_000,
});

const builtBinary = resolve(
  targetDirectory,
  target,
  profile,
  nativeAssistantBuildFileName(target),
);
const builtMetadata = await stat(builtBinary);
if (!builtMetadata.isFile() || builtMetadata.size === 0) {
  throw new Error(`${builtBinary}: Cargo did not produce a non-empty native assistant`);
}

await mkdir(externalBinDirectory, { recursive: true, mode: 0o755 });
const stagingDirectory = resolve(externalBinDirectory, `.prepare-${randomUUID()}`);
const stagedBinary = resolve(stagingDirectory, nativeAssistantFileName(target));
await mkdir(stagingDirectory, { mode: 0o700 });

try {
  await copyFile(builtBinary, stagedBinary);
  if (target === "x86_64-unknown-linux-gnu") await chmod(stagedBinary, 0o755);

  const inspection = await inspectPreparedNativeAssistant(stagedBinary, cargoManifest, target);
  await rm(destination, { force: true });
  await rename(stagedBinary, destination);

  const installedDigest = await readFile(destination);
  const destinationMetadata = await stat(destination);
  const installedSha256 = createHash("sha256").update(installedDigest).digest("hex");
  if (
    destinationMetadata.size !== inspection.size ||
    installedSha256 !== inspection.sha256
  ) {
    throw new Error(`${destination}: copied native assistant differs from the inspected file`);
  }

  process.stdout.write(
    `${JSON.stringify({
      kind: "your-cloud-native-bootstrap-assistant",
      environment: executionEnvironment,
      profile,
      ...inspection,
      external_bin: relative(tauriRoot, destination),
    })}\n`,
  );
} finally {
  await rm(stagingDirectory, { recursive: true, force: true });
}
