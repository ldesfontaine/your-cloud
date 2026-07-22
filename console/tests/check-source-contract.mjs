import { readFile, readdir } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const consoleRoot = fileURLToPath(new URL("..", import.meta.url));
const failures = [];
const releaseCoupledIdentifier =
  /\bv\d+\.\d+\.\d+\b|\bv\d+-\d+-\d+\b|\/v\d+\.\d+\.\d+\b/iu;

for (const hostile of [
  "https://controller.example.v0-0-3.your-cloud.test",
  "urn:your-cloud:v0.0.3:device",
  "/v0.0.3/session",
]) {
  if (!releaseCoupledIdentifier.test(hostile)) {
    failures.push(`garde interne: identifiant de livraison non détecté (${hostile})`);
  }
}
for (const stable of ["/v0/session", "your-cloud/human-session.v1", "controller.example.your-cloud.test"]) {
  if (releaseCoupledIdentifier.test(stable)) {
    failures.push(`garde interne: identifiant de protocole stable refusé (${stable})`);
  }
}

const packageDocument = JSON.parse(await readFile(join(consoleRoot, "package.json"), "utf8"));
const packageLock = JSON.parse(await readFile(join(consoleRoot, "package-lock.json"), "utf8"));
const tauriConfig = JSON.parse(
  await readFile(join(consoleRoot, "src-tauri", "tauri.conf.json"), "utf8"),
);
const cargoManifest = await readFile(join(consoleRoot, "src-tauri", "Cargo.toml"), "utf8");
const cargoVersion = cargoManifest.match(/^version\s*=\s*"([^"]+)"$/mu)?.[1];

if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(packageDocument.version)) {
  failures.push("package.json: version semver invalide");
}
if (packageLock.version !== packageDocument.version) {
  failures.push("package-lock.json: version racine différente de package.json");
}
if (packageLock.packages?.[""]?.version !== packageDocument.version) {
  failures.push("package-lock.json: version du paquet différente de package.json");
}
if (cargoVersion !== packageDocument.version) {
  failures.push("src-tauri/Cargo.toml: version différente de package.json");
}
if (tauriConfig.version !== "../package.json") {
  failures.push("src-tauri/tauri.conf.json: la version doit provenir de package.json");
}

async function filesBelow(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await filesBelow(path)));
    else files.push(path);
  }
  return files;
}

const runtimeRoots = [join(consoleRoot, "src"), join(consoleRoot, "src-tauri", "src")];
for (const runtimeRoot of runtimeRoots) {
  for (const path of await filesBelow(runtimeRoot)) {
    if (![".rs", ".ts", ".tsx"].includes(extname(path))) continue;
    const contents = await readFile(path, "utf8");
    const name = relative(consoleRoot, path);
    if (releaseCoupledIdentifier.test(contents)) {
      failures.push(`${name}: identifiant d'exécution couplé à une version de livraison`);
    }
  }
}

if (failures.length > 0) {
  for (const failure of failures) process.stderr.write(`source-contract: ${failure}\n`);
  process.exit(1);
}

process.stdout.write(`source-contract: PASS (version ${packageDocument.version})\n`);
