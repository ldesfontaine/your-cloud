import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { requireIsolatedExecution } from "./lib/execution-environment.mjs";
import {
  NATIVE_ASSISTANT_PACKAGE,
  assertSupportedNativeTarget,
  nativeAssistantCargoPackageIsForbidden,
} from "./lib/native-bootstrap-assistant.mjs";

const consoleRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const [
  outputInput,
  artifactName = "console",
  target = "x86_64-unknown-linux-gnu",
  ...unexpectedArguments
] = process.argv.slice(2);
const artifacts = new Map([
  ["console", { cargoPackage: "your-cloud-console", includeNpm: true }],
  [
    "native-bootstrap-assistant",
    { cargoPackage: NATIVE_ASSISTANT_PACKAGE, includeNpm: false },
  ],
]);

if (!outputInput || unexpectedArguments.length > 0) {
  throw new Error("usage: node tools/build-sbom.mjs OUTPUT.json [ARTIFACT TARGET]");
}
const artifact = artifacts.get(artifactName);
if (!artifact) {
  throw new Error(
    `unknown SBOM artifact ${JSON.stringify(artifactName)}; expected ${[...artifacts.keys()].join(" or ")}`,
  );
}
assertSupportedNativeTarget(target);
requireIsolatedExecution(`${artifactName} SBOM generation`);

const packageDocument = JSON.parse(
  await readFile(resolve(consoleRoot, "package.json"), "utf8"),
);
const cargo = JSON.parse(
  execFileSync(
    "cargo",
    [
      "metadata",
      "--format-version",
      "1",
      "--filter-platform",
      target,
      "--locked",
      "--offline",
    ],
    {
      cwd: resolve(consoleRoot, "src-tauri"),
      encoding: "utf8",
      env: { ...process.env, LC_ALL: "C" },
      maxBuffer: 32 * 1024 * 1024,
      timeout: 180_000,
    },
  ),
);

const packagesById = new Map(cargo.packages.map((entry) => [entry.id, entry]));
const nodesById = new Map((cargo.resolve?.nodes ?? []).map((entry) => [entry.id, entry]));
const roots = cargo.packages.filter((entry) => entry.name === artifact.cargoPackage);
if (roots.length !== 1) {
  throw new Error(
    `expected one Cargo package named ${artifact.cargoPackage}; found ${roots.length}`,
  );
}
const rootPackage = roots[0];

function productionDependencies(node) {
  return (node?.deps ?? []).filter((dependency) =>
    dependency.dep_kinds.some((kind) => kind.kind !== "dev"),
  );
}

function cargoClosure(rootId) {
  const closure = new Set();
  const pending = [rootId];
  while (pending.length > 0) {
    const current = pending.pop();
    if (closure.has(current)) continue;
    if (!packagesById.has(current) || !nodesById.has(current)) {
      throw new Error(`Cargo metadata closure contains an unresolved package ${current}`);
    }
    closure.add(current);
    for (const dependency of productionDependencies(nodesById.get(current))) {
      pending.push(dependency.pkg);
    }
  }
  return closure;
}

function cargoPurl(entry) {
  return `pkg:cargo/${encodeURIComponent(entry.name)}@${encodeURIComponent(entry.version)}`;
}

function cargoComponent(entry) {
  const purl = cargoPurl(entry);
  return {
    type: "library",
    "bom-ref": purl,
    name: entry.name,
    version: entry.version,
    purl,
    properties: [{ name: "your-cloud:source", value: entry.source ?? "workspace" }],
  };
}

const closure = cargoClosure(rootPackage.id);
const rootPurl = cargoPurl(rootPackage);
const targetPlatform = target === "x86_64-unknown-linux-gnu" ? "linux" : "windows";
const rootRef = `${rootPurl}?arch=x86_64&os=${targetPlatform}`;
const components = [...closure]
  .filter((packageId) => packageId !== rootPackage.id)
  .map((packageId) => cargoComponent(packagesById.get(packageId)));
const dependencyGraph = [...closure].map((packageId) => {
  const reference = packageId === rootPackage.id ? rootRef : cargoPurl(packagesById.get(packageId));
  const dependsOn = productionDependencies(nodesById.get(packageId))
    .map((dependency) => dependency.pkg)
    .filter((dependencyId) => closure.has(dependencyId))
    .map((dependencyId) => cargoPurl(packagesById.get(dependencyId)))
    .sort();
  return { ref: reference, dependsOn: [...new Set(dependsOn)] };
});

if (artifactName === "native-bootstrap-assistant") {
  const forbidden = [...closure]
    .map((packageId) => packagesById.get(packageId).name)
    .filter(nativeAssistantCargoPackageIsForbidden);
  if (forbidden.length > 0) {
    throw new Error(`helper SBOM closure contains forbidden packages: ${forbidden.join(", ")}`);
  }
}

if (artifact.includeNpm) {
  const npmLock = JSON.parse(
    await readFile(resolve(consoleRoot, "package-lock.json"), "utf8"),
  );
  const npmRefs = [];
  for (const [path, entry] of Object.entries(npmLock.packages ?? {})) {
    if (!path || !entry?.version) continue;
    const fallback = path.replace(/^.*node_modules\//u, "");
    const name = entry.name ?? fallback;
    const normalized = name.startsWith("@")
      ? `${encodeURIComponent(name.split("/")[0])}/${encodeURIComponent(name.split("/").slice(1).join("/"))}`
      : encodeURIComponent(name);
    const purl = `pkg:npm/${normalized}@${encodeURIComponent(entry.version)}`;
    const reference = `${purl}?path=${encodeURIComponent(path)}`;
    const properties = [{ name: "your-cloud:lock-path", value: path }];
    if (entry.integrity) {
      properties.push({ name: "your-cloud:npm-integrity", value: entry.integrity });
    }
    components.push({
      type: "library",
      "bom-ref": reference,
      name,
      version: entry.version,
      purl,
      properties,
    });
    npmRefs.push(reference);
  }
  dependencyGraph.find((entry) => entry.ref === rootRef).dependsOn.push(...npmRefs.sort());
}

components.sort((left, right) => left["bom-ref"].localeCompare(right["bom-ref"]));
dependencyGraph.sort((left, right) => left.ref.localeCompare(right.ref));
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
      "bom-ref": rootRef,
      name: rootPackage.name,
      version: rootPackage.version,
      purl: rootPurl,
      properties: [
        { name: "your-cloud:artifact", value: artifactName },
        { name: "your-cloud:target", value: target },
        { name: "your-cloud:dependency-scope", value: "cargo-non-dev-closure" },
      ],
    },
  },
  components,
  dependencies: dependencyGraph,
};

const output = resolve(outputInput);
await mkdir(dirname(output), { recursive: true });
await writeFile(output, `${JSON.stringify(document, null, 2)}\n`, {
  encoding: "utf8",
  mode: 0o644,
});
process.stdout.write(
  `sbom: ${artifactName} ${target}, ${components.length} closure components\n`,
);
