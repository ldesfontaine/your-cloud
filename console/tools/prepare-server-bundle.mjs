// Prépare le lot serveur que le paquet Debian de la Console embarque, et
// refuse d'en préparer un autre que celui que le mainteneur a signé.
//
// Le dépôt ne committe jamais le `.deb` : il committe le manifeste signé et la
// signature détachée, et chaque build **reconstruit** le lot puis refuse si
// l'empreinte ne correspond pas à ce que la signature couvre. Une porte qui
// vérifie vaut mieux qu'une porte qui fait confiance. La construction exige
// l'outillage épinglé de `packaging/server-bundle/toolchain.lock` ; un
// environnement qui ne le porte pas — le poste de développement, un runner
// Ubuntu — reçoit un refus nommé, jamais un lot différent. La porte hébergée
// construit donc le lot dans un conteneur `debian:13` épinglé et le dépose ici
// avant le build de la Console, qui le re-vérifie au lieu de le croire.
//
// Les contrôles de ce script sont un écho de build de la porte du produit,
// jamais son remplacement : l'autorité finale reste `bundle::verify` contre
// l'ancre scellée dans l'Assistant installé. Échouer ici épargne seulement à
// un mainteneur de découvrir au premier amorçage ce qu'un build pouvait dire.
//
// Sous Windows, rien n'est préparé et c'est une décision : seul le paquet
// Debian de la Console livre le lot (`bundle.linux.deb.files`), et le `.msi`
// n'a rien à transporter tant que la distribution Windows publique reste
// bloquée.

import { createHash, createPublicKey, verify as verifyDetached } from "node:crypto";
import { copyFile, mkdir, readFile, rm, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import { requireIsolatedExecution } from "./lib/execution-environment.mjs";
import { runBounded } from "./lib/native-bootstrap-assistant.mjs";

const consoleRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = resolve(consoleRoot, "..");
const stagedDirectory = resolve(consoleRoot, "src-tauri", "server-bundle");
const committedDirectory = resolve(repositoryRoot, "packaging", "server-bundle", "manifest");
const anchorPath = resolve(
  consoleRoot,
  "src-tauri",
  "crates",
  "native-bootstrap-assistant",
  "anchor",
  "release-anchor.pub",
);

// Les trois noms fixes, exactement ceux que `installation::embedded` résout
// depuis la position attestée de l'Assistant.
const STAGED_ARTIFACT = "your-cloud-server.deb";
const STAGED_MANIFEST = "bundle-manifest.json";
const STAGED_SIGNATURE = "bundle-manifest.sig";

// L'enveloppe SPKI DER d'une clé publique Ed25519 est constante : ces douze
// octets devant les trente-deux de l'ancre donnent exactement ce que
// `crypto.createPublicKey` lit. L'ancre committée reste brute, comme le
// binaire la scelle.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

if (process.argv.length > 2) {
  throw new Error("usage: node tools/prepare-server-bundle.mjs");
}

if (process.platform === "win32") {
  process.stdout.write(
    `${JSON.stringify({
      kind: "your-cloud-server-bundle-preparation",
      skipped: "windows-carries-no-server-bundle",
    })}\n`,
  );
  process.exit(0);
}

const executionEnvironment = requireIsolatedExecution("server bundle preparation");

const packageDocument = JSON.parse(
  await readFile(resolve(consoleRoot, "package.json"), "utf8"),
);
const releaseVersion = packageDocument.version;

// Le manifeste signé et sa signature, tels que committés. Leur absence est un
// refus, pas un lot de secours : un paquet de Console sans lot signé serait un
// paquet qui promet un lot qu'il ne porte pas.
const manifestBytes = await readFile(join(committedDirectory, STAGED_MANIFEST)).catch(() => {
  throw new Error(
    `no signed manifest under ${committedDirectory}; the maintainer's signing gesture is documented in docs/contribution/RELEASE.md`,
  );
});
const signatureBytes = await readFile(join(committedDirectory, STAGED_SIGNATURE)).catch(() => {
  throw new Error(
    `no detached signature under ${committedDirectory}; the maintainer's signing gesture is documented in docs/contribution/RELEASE.md`,
  );
});
if (signatureBytes.length !== 64) {
  throw new Error(
    `${STAGED_SIGNATURE}: a detached Ed25519 signature is 64 bytes, not ${signatureBytes.length}`,
  );
}

const anchorBytes = await readFile(anchorPath);
if (anchorBytes.length !== 32) {
  throw new Error(`release anchor is ${anchorBytes.length} bytes; the sealed anchor holds 32`);
}
const anchorKey = createPublicKey({
  key: Buffer.concat([ED25519_SPKI_PREFIX, anchorBytes]),
  format: "der",
  type: "spki",
});
if (!verifyDetached(null, manifestBytes, anchorKey, signatureBytes)) {
  throw new Error(
    "the committed manifest is not signed by the sealed anchor; the Assistant would refuse this bundle as SignatureNotByAnchor",
  );
}

// Les octets sont authentifiés ; leur sens peut être lu. La version liée doit
// être celle de la release en cours : un produit, une révision.
const manifest = JSON.parse(manifestBytes.toString("utf8"));
if (manifest.version !== releaseVersion) {
  throw new Error(
    `the signed manifest binds version ${JSON.stringify(manifest.version)} but the release is ${JSON.stringify(releaseVersion)}; reproduce and re-sign the bundle for this release`,
  );
}

const stagedArtifactPath = join(stagedDirectory, STAGED_ARTIFACT);

async function stagedArtifactMatches() {
  const metadata = await stat(stagedArtifactPath).catch(() => null);
  if (metadata === null || !metadata.isFile()) return false;
  if (metadata.size !== manifest.size) {
    throw new Error(
      `${stagedArtifactPath}: a staged bundle is present but its size ${metadata.size} is not the signed ${manifest.size}; refusing to keep it`,
    );
  }
  const digest = createHash("sha256").update(await readFile(stagedArtifactPath)).digest("hex");
  if (digest !== manifest.sha256) {
    throw new Error(
      `${stagedArtifactPath}: a staged bundle is present but its digest is not the signed one; refusing to keep it`,
    );
  }
  return true;
}

let origin;
if (await stagedArtifactMatches()) {
  // Le lot déposé — par la porte hébergée, ou par une préparation précédente —
  // est exactement celui que la signature couvre. Le garder n'est pas une
  // confiance : il vient d'être confronté au manifeste signé.
  origin = "verified-preexisting";
} else {
  // Reconstruire, puis confronter octet pour octet le manifeste produit au
  // manifeste signé. La reproductibilité est la propriété qui rend cette
  // égalité possible ; sa dérive s'arrête ici, nommée par l'outil de
  // construction lui-même quand l'outillage n'est pas celui du verrou.
  const buildDirectory = join(tmpdir(), `your-cloud-server-bundle-${process.pid}`);
  await rm(buildDirectory, { recursive: true, force: true });
  await mkdir(buildDirectory, { recursive: true, mode: 0o700 });
  try {
    runBounded(
      join(repositoryRoot, "tools", "build-server-bundle"),
      [releaseVersion, repositoryRoot, buildDirectory],
      { stdio: "inherit", timeout: 10 * 60_000 },
    );
    const rebuiltManifest = await readFile(join(buildDirectory, STAGED_MANIFEST));
    if (!rebuiltManifest.equals(manifestBytes)) {
      throw new Error(
        "the rebuilt bundle manifest differs from the signed one: the sources, the toolchain or the version moved since the maintainer signed; reproduce and re-sign deliberately",
      );
    }
    await mkdir(stagedDirectory, { recursive: true, mode: 0o755 });
    await rm(stagedArtifactPath, { force: true });
    // Copie plutôt que `rename` : le répertoire de construction vit dans le
    // tmpfs de la machine et le dépôt sur son disque, deux systèmes de
    // fichiers entre lesquels un déplacement atomique n'existe pas.
    await copyFile(
      join(buildDirectory, `your-cloud-server_${releaseVersion}_amd64.deb`),
      stagedArtifactPath,
    );
    origin = "rebuilt";
  } finally {
    await rm(buildDirectory, { recursive: true, force: true });
  }
  if (!(await stagedArtifactMatches())) {
    throw new Error(`${stagedArtifactPath}: the rebuilt bundle does not match the signed manifest`);
  }
}

// Le manifeste et la signature embarqués sont recopiés depuis les fichiers
// committés — jamais depuis la reconstruction, même quand elle vient de rendre
// des octets égaux : ce que l'Assistant jugera est ce que le mainteneur a
// signé, sans intermédiaire.
await mkdir(stagedDirectory, { recursive: true, mode: 0o755 });
await copyFile(join(committedDirectory, STAGED_MANIFEST), join(stagedDirectory, STAGED_MANIFEST));
await copyFile(join(committedDirectory, STAGED_SIGNATURE), join(stagedDirectory, STAGED_SIGNATURE));

process.stdout.write(
  `${JSON.stringify({
    kind: "your-cloud-server-bundle-preparation",
    environment: executionEnvironment,
    origin,
    version: manifest.version,
    target: manifest.target,
    size: manifest.size,
    sha256: manifest.sha256,
  })}\n`,
);
