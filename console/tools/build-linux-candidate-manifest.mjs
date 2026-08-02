import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { requireIsolatedExecution } from "./lib/execution-environment.mjs";
import {
  BOOTSTRAP_PROTOCOL_PACKAGE,
  NATIVE_ASSISTANT_BINARY,
  NATIVE_ASSISTANT_PACKAGE,
  inspectDirectElfDependencies,
  nativeAssistantFileName,
  nativeAssistantCargoPackageIsForbidden,
} from "./lib/native-bootstrap-assistant.mjs";

const consoleRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const [
  artifactInput,
  consoleSbomInput,
  helperSbomInput,
  outputInput,
  signerFingerprint,
  gitHead,
  ...unexpectedArguments
] = process.argv.slice(2);
const packageDocument = JSON.parse(
  await readFile(resolve(consoleRoot, "package.json"), "utf8"),
);
const target = "x86_64-unknown-linux-gnu";

if (
  !artifactInput ||
  !consoleSbomInput ||
  !helperSbomInput ||
  !outputInput ||
  !signerFingerprint ||
  !gitHead ||
  unexpectedArguments.length > 0
) {
  throw new Error(
    "usage: node tools/build-linux-candidate-manifest.mjs ARTIFACT CONSOLE_SBOM HELPER_SBOM OUTPUT SIGNER_FINGERPRINT GIT_HEAD",
  );
}
if (!/^[A-F0-9]{40}$/u.test(signerFingerprint)) {
  throw new Error("the OpenPGP signer fingerprint must contain 40 uppercase hexadecimal characters");
}
if (!/^[a-f0-9]{40}$/u.test(gitHead)) {
  throw new Error("the Git head must contain 40 lowercase hexadecimal characters");
}

const executionEnvironment = requireIsolatedExecution("Linux candidate manifest generation");
const artifact = resolve(artifactInput);
const consoleSbom = resolve(consoleSbomInput);
const helperSbom = resolve(helperSbomInput);
const output = resolve(outputInput);
if (consoleSbom === helperSbom) {
  throw new Error("the Console and native assistant must use two distinct SBOM files");
}

function command(commandName, args, options = {}) {
  return execFileSync(commandName, args, {
    cwd: consoleRoot,
    encoding: "utf8",
    env: { ...process.env, LC_ALL: "C" },
    maxBuffer: options.maxBuffer ?? 16 * 1024 * 1024,
    timeout: options.timeout ?? 120_000,
  }).trim();
}

const actualGitHead = command("git", ["rev-parse", "HEAD"]);
if (actualGitHead !== gitHead) {
  throw new Error(`the declared Git head does not match the runner checkout: ${actualGitHead}`);
}
if (command("git", ["status", "--porcelain"]) !== "") {
  throw new Error("the Linux candidate manifest requires a clean Git worktree");
}

async function digest(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

async function regularFile(path, label) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.size === 0) {
    throw new Error(`${label} must be a non-empty regular file: ${path}`);
  }
  return metadata;
}

async function collectFiles(path, collected = []) {
  const metadata = await lstat(path);
  if (metadata.isSymbolicLink()) {
    throw new Error(`source provenance refuses symbolic links: ${relative(consoleRoot, path)}`);
  }
  if (metadata.isFile()) {
    collected.push(path);
    return collected;
  }
  if (!metadata.isDirectory()) {
    throw new Error(`source provenance refuses special files: ${relative(consoleRoot, path)}`);
  }
  for (const entry of (await readdir(path)).sort()) {
    await collectFiles(resolve(path, entry), collected);
  }
  return collected;
}

async function treeDigest(files) {
  const tree = createHash("sha256");
  for (const path of [...files].sort((left, right) => left.localeCompare(right))) {
    tree.update(`${relative(consoleRoot, path)}\0${await digest(path)}\n`, "utf8");
  }
  return tree.digest("hex");
}

function sbomProperty(document, name) {
  return document.metadata?.component?.properties?.find((entry) => entry.name === name)?.value;
}

async function inspectSbom(path, expectedComponent, expectedArtifact) {
  const metadata = await regularFile(path, `${expectedArtifact} SBOM`);
  const document = JSON.parse(await readFile(path, "utf8"));
  if (document.bomFormat !== "CycloneDX" || document.specVersion !== "1.6") {
    throw new Error(`${expectedArtifact} SBOM must be a CycloneDX 1.6 document`);
  }
  if (document.metadata?.component?.name !== expectedComponent) {
    throw new Error(`${expectedArtifact} SBOM describes the wrong root component`);
  }
  if (sbomProperty(document, "your-cloud:artifact") !== expectedArtifact) {
    throw new Error(`${expectedArtifact} SBOM does not identify its artifact closure`);
  }
  if (sbomProperty(document, "your-cloud:target") !== target) {
    throw new Error(`${expectedArtifact} SBOM does not describe target ${target}`);
  }
  if (!Array.isArray(document.components) || !Array.isArray(document.dependencies)) {
    throw new Error(`${expectedArtifact} SBOM must contain components and dependency closure edges`);
  }
  if (!document.dependencies.some((entry) => entry.ref === document.metadata.component["bom-ref"])) {
    throw new Error(`${expectedArtifact} SBOM does not root its dependency closure`);
  }
  return {
    document,
    evidence: {
      role: expectedArtifact,
      file: basename(path),
      format: "CycloneDX",
      specification: "1.6",
      components: document.components.length,
      size: metadata.size,
      sha256: await digest(path),
    },
  };
}

const sourceRoots = [
  "package.json",
  "package-lock.json",
  "tsconfig.json",
  "vite.config.ts",
  "src",
  "tests",
  "tools",
  "src-tauri/Cargo.toml",
  "src-tauri/Cargo.lock",
  "src-tauri/build.rs",
  "src-tauri/capabilities",
  "src-tauri/crates",
  "src-tauri/icons",
  "src-tauri/src",
  "src-tauri/tauri.conf.json",
];
const sourceFiles = [];
for (const sourceRoot of sourceRoots) {
  await collectFiles(resolve(consoleRoot, sourceRoot), sourceFiles);
}
const helperSourceFiles = [];
for (const helperSourceRoot of [
  "src-tauri/crates/bootstrap-protocol",
  "src-tauri/crates/native-bootstrap-assistant",
]) {
  await collectFiles(resolve(consoleRoot, helperSourceRoot), helperSourceFiles);
}

const osRelease = Object.fromEntries(
  (await readFile("/etc/os-release", "utf8"))
    .split("\n")
    .filter((line) => line.includes("="))
    .map((line) => {
      const separator = line.indexOf("=");
      return [line.slice(0, separator), line.slice(separator + 1).replace(/^"|"$/gu, "")];
    }),
);
const artifactStat = await regularFile(artifact, "Linux installer");
if (basename(artifact).split(".").pop() !== "deb") {
  throw new Error("the Linux candidate artifact must be a .deb installer");
}
if (command("dpkg-deb", ["--field", artifact, "Architecture"]) !== "amd64") {
  throw new Error("the Linux candidate installer must target Debian amd64");
}
if (command("dpkg-deb", ["--field", artifact, "Version"]) !== packageDocument.version) {
  throw new Error("the Linux candidate installer version differs from package.json");
}

const inspectedConsoleSbom = await inspectSbom(
  consoleSbom,
  "your-cloud-console",
  "console",
);
const inspectedHelperSbom = await inspectSbom(
  helperSbom,
  NATIVE_ASSISTANT_PACKAGE,
  "native-bootstrap-assistant",
);
const helperComponents = inspectedHelperSbom.document.components.map((entry) => entry.name);
const helperForbiddenComponents = helperComponents.filter(
  nativeAssistantCargoPackageIsForbidden,
);
if (!helperComponents.includes(BOOTSTRAP_PROTOCOL_PACKAGE)) {
  throw new Error(`helper SBOM does not contain ${BOOTSTRAP_PROTOCOL_PACKAGE}`);
}
if (helperForbiddenComponents.length > 0) {
  throw new Error(
    `helper SBOM contains forbidden Console/WebKit components: ${helperForbiddenComponents.join(", ")}`,
  );
}

const preparedHelper = resolve(
  consoleRoot,
  "src-tauri",
  "binaries",
  nativeAssistantFileName(target),
);
const preparedHelperStat = await regularFile(preparedHelper, "prepared native assistant");
if ((preparedHelperStat.mode & 0o111) === 0) {
  throw new Error("the prepared native assistant is not executable");
}

const extractionRoot = await mkdtemp(join(tmpdir(), "your-cloud-candidate-"));
let helperEvidence;
try {
  command("dpkg-deb", ["--extract", artifact, extractionRoot], {
    timeout: 180_000,
    maxBuffer: 32 * 1024 * 1024,
  });
  const embeddedHelper = resolve(extractionRoot, "usr", "bin", NATIVE_ASSISTANT_BINARY);
  const embeddedHelperStat = await regularFile(embeddedHelper, "packaged native assistant");
  if ((embeddedHelperStat.mode & 0o111) === 0) {
    throw new Error("the packaged native assistant is not executable");
  }

  const preparedSha256 = await digest(preparedHelper);
  const embeddedSha256 = await digest(embeddedHelper);
  if (preparedSha256 !== embeddedSha256 || preparedHelperStat.size !== embeddedHelperStat.size) {
    throw new Error("the packaged native assistant differs from the inspected externalBin source");
  }
  helperEvidence = {
    role: "native-bootstrap-assistant",
    package_path: `/usr/bin/${NATIVE_ASSISTANT_BINARY}`,
    source_external_bin: relative(consoleRoot, preparedHelper),
    target,
    format: "elf",
    size: embeddedHelperStat.size,
    sha256: embeddedSha256,
    elf_direct_needed: await inspectDirectElfDependencies(embeddedHelper),
  };
} finally {
  await rm(extractionRoot, { recursive: true, force: true });
}

const manifest = {
  schema_version: 2,
  kind: "your-cloud-console-linux-candidate",
  version: packageDocument.version,
  release_status: "candidate-exact-commit",
  generated_at: new Date().toISOString(),
  source: {
    git_head: gitHead,
    worktree_clean: true,
    provenance_limit:
      "This LAB candidate is tied to an exact clean Git commit. Its synthetic signer proves the signing mechanism, not a public release identity.",
    source_roots: sourceRoots,
    repository_source_file_count: sourceFiles.length,
    repository_source_tree_sha256: await treeDigest(sourceFiles),
    helper_source_file_count: helperSourceFiles.length,
    helper_source_tree_sha256: await treeDigest(helperSourceFiles),
    package_lock_sha256: await digest(resolve(consoleRoot, "package-lock.json")),
    cargo_lock_sha256: await digest(resolve(consoleRoot, "src-tauri/Cargo.lock")),
  },
  artifacts: [
    {
      role: "linux-installer",
      file: basename(artifact),
      target,
      format: "deb",
      size: artifactStat.size,
      sha256: await digest(artifact),
      embedded: [helperEvidence],
    },
  ],
  sboms: [inspectedConsoleSbom.evidence, inspectedHelperSbom.evidence],
  signing: {
    scheme: "OpenPGP Ed25519 detached signature",
    signer_fingerprint: signerFingerprint,
    identity_scope: "synthetic LAB key; no public identity claim",
  },
  runner: {
    execution_environment: executionEnvironment,
    hostname: command("hostname", []),
    operating_system: osRelease.PRETTY_NAME,
    architecture: command("uname", ["-m"]),
  },
  tools: {
    node: command("node", ["--version"]),
    npm: command("npm", ["--version"]),
    rustc: command("rustc", ["--version"]),
    cargo: command("cargo", ["--version"]),
    tauri_cli: command(resolve(consoleRoot, "node_modules/.bin/tauri"), ["--version"]),
    dpkg_deb: command("dpkg-deb", ["--version"]).split("\n")[0],
    readelf: command("readelf", ["--version"]).split("\n")[0],
  },
  deferred: {
    windows_x86_64: "requires its separate native build, signature and execution proof",
  },
};

await mkdir(dirname(output), { recursive: true });
await writeFile(output, `${JSON.stringify(manifest, null, 2)}\n`, {
  encoding: "utf8",
  mode: 0o644,
});
process.stdout.write(
  `manifest: ${manifest.artifacts.length} installer, ${manifest.sboms.length} artifact closures\n`,
);
