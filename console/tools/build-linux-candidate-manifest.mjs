import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { basename, dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const consoleRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const [artifactInput, sbomInput, outputInput, signerFingerprint, gitHead] = process.argv.slice(2);

if (!artifactInput || !sbomInput || !outputInput || !signerFingerprint || !gitHead) {
  throw new Error(
    "usage: node tools/build-linux-candidate-manifest.mjs ARTIFACT SBOM OUTPUT SIGNER_FINGERPRINT GIT_HEAD",
  );
}
if (!/^[A-F0-9]{40}$/u.test(signerFingerprint)) {
  throw new Error("the OpenPGP signer fingerprint must contain 40 uppercase hexadecimal characters");
}
if (!/^[a-f0-9]{40}$/u.test(gitHead)) {
  throw new Error("the Git head must contain 40 lowercase hexadecimal characters");
}

const artifact = resolve(artifactInput);
const sbom = resolve(sbomInput);
const output = resolve(outputInput);

function command(commandName, args) {
  return execFileSync(commandName, args, {
    cwd: consoleRoot,
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  }).trim();
}

async function digest(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

async function collectFiles(path, collected = []) {
  const metadata = await stat(path);
  if (metadata.isFile()) {
    collected.push(path);
    return collected;
  }
  for (const entry of (await readdir(path)).sort()) {
    await collectFiles(resolve(path, entry), collected);
  }
  return collected;
}

const sourceRoots = [
  "package.json",
  "package-lock.json",
  "tsconfig.json",
  "vite.config.ts",
  "src",
  "src-tauri/Cargo.toml",
  "src-tauri/Cargo.lock",
  "src-tauri/build.rs",
  "src-tauri/capabilities",
  "src-tauri/icons",
  "src-tauri/src",
  "src-tauri/tauri.conf.json",
];
const sourceFiles = [];
for (const sourceRoot of sourceRoots) {
  await collectFiles(resolve(consoleRoot, sourceRoot), sourceFiles);
}
sourceFiles.sort((left, right) => left.localeCompare(right));

const sourceTree = createHash("sha256");
for (const path of sourceFiles) {
  const name = relative(consoleRoot, path);
  const contentDigest = await digest(path);
  sourceTree.update(`${name}\0${contentDigest}\n`, "utf8");
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
const artifactStat = await stat(artifact);
const sbomStat = await stat(sbom);
const sbomDocument = JSON.parse(await readFile(sbom, "utf8"));
if (sbomDocument.bomFormat !== "CycloneDX" || sbomDocument.specVersion !== "1.6") {
  throw new Error("the SBOM must be a CycloneDX 1.6 document");
}

const manifest = {
  schema_version: 1,
  kind: "your-cloud-console-linux-candidate",
  version: "0.0.3",
  release_status: "candidate-uncommitted",
  generated_at: new Date().toISOString(),
  source: {
    git_head: gitHead,
    git_branch: "console-controller",
    worktree_clean: false,
    provenance_limit:
      "This candidate contains uncommitted v0.0.3 changes. It is suitable for LAB proof only and is not a release artifact tied to an exact Git commit.",
    console_source_file_count: sourceFiles.length,
    console_source_tree_sha256: sourceTree.digest("hex"),
    package_lock_sha256: await digest(resolve(consoleRoot, "package-lock.json")),
    cargo_lock_sha256: await digest(resolve(consoleRoot, "src-tauri/Cargo.lock")),
  },
  artifacts: [
    {
      role: "linux-installer",
      file: basename(artifact),
      target: "x86_64-unknown-linux-gnu",
      format: "deb",
      size: artifactStat.size,
      sha256: await digest(artifact),
    },
  ],
  sbom: {
    file: basename(sbom),
    format: "CycloneDX",
    specification: "1.6",
    components: sbomDocument.components.length,
    size: sbomStat.size,
    sha256: await digest(sbom),
  },
  signing: {
    scheme: "OpenPGP Ed25519 detached signature",
    signer_fingerprint: signerFingerprint,
    identity_scope: "synthetic LAB key; no public identity claim",
  },
  runner: {
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
  },
  deferred: {
    windows_x86_64: "deferred by the user until the Linux gate is stable",
  },
};

await mkdir(dirname(output), { recursive: true });
await writeFile(output, `${JSON.stringify(manifest, null, 2)}\n`, {
  encoding: "utf8",
  mode: 0o644,
});
process.stdout.write(
  `manifest: ${manifest.artifacts.length} artifact, ${manifest.sbom.components} components\n`,
);
