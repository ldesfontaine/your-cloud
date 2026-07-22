import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const consoleRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const output = process.argv[2];
if (!output) {
  throw new Error("usage: node tools/build-sbom.mjs OUTPUT.json");
}

const packageDocument = JSON.parse(
  await readFile(resolve(consoleRoot, "package.json"), "utf8"),
);

const cargo = JSON.parse(
  execFileSync(
    "cargo",
    ["metadata", "--format-version", "1", "--locked", "--offline"],
    {
      cwd: resolve(consoleRoot, "src-tauri"),
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    },
  ),
);
const npmLock = JSON.parse(
  await readFile(resolve(consoleRoot, "package-lock.json"), "utf8"),
);

const components = [];
for (const entry of cargo.packages) {
  if (cargo.workspace_members.includes(entry.id)) continue;
  const purl = `pkg:cargo/${encodeURIComponent(entry.name)}@${encodeURIComponent(entry.version)}`;
  components.push({
    type: "library",
    "bom-ref": purl,
    name: entry.name,
    version: entry.version,
    purl,
    properties: [{ name: "your-cloud:source", value: entry.source ?? "workspace" }],
  });
}

for (const [path, entry] of Object.entries(npmLock.packages ?? {})) {
  if (!path || !entry?.version) continue;
  const fallback = path.replace(/^.*node_modules\//u, "");
  const name = entry.name ?? fallback;
  const normalized = name.startsWith("@")
    ? `${encodeURIComponent(name.split("/")[0])}/${encodeURIComponent(name.split("/").slice(1).join("/"))}`
    : encodeURIComponent(name);
  const purl = `pkg:npm/${normalized}@${encodeURIComponent(entry.version)}`;
  const properties = [{ name: "your-cloud:lock-path", value: path }];
  if (entry.integrity) properties.push({ name: "your-cloud:npm-integrity", value: entry.integrity });
  components.push({
    type: "library",
    "bom-ref": `${purl}?path=${encodeURIComponent(path)}`,
    name,
    version: entry.version,
    purl,
    properties,
  });
}

components.sort((left, right) => left["bom-ref"].localeCompare(right["bom-ref"]));
const document = {
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  serialNumber: `urn:uuid:${randomUUID()}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    tools: {
      components: [
        {
          type: "application",
          name: "your-cloud-sbom-builder",
          version: packageDocument.version,
        },
      ],
    },
    component: {
      type: "application",
      "bom-ref": `pkg:generic/your-cloud-console@${encodeURIComponent(packageDocument.version)}?os=linux&arch=x86_64`,
      name: "your-cloud-console",
      version: packageDocument.version,
    },
  },
  components,
};

await mkdir(dirname(resolve(output)), { recursive: true });
await writeFile(resolve(output), `${JSON.stringify(document, null, 2)}\n`, {
  encoding: "utf8",
  mode: 0o644,
});
process.stdout.write(`sbom: ${components.length} locked components\n`);
