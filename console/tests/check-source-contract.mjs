import { readFile, readdir } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import {
  nativeAssistantCargoPackageIsForbidden,
  nativeAssistantElfLibraryIsForbidden,
} from "../tools/lib/native-bootstrap-assistant.mjs";

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

for (const forbiddenPackage of [
  "tauri",
  "tauri-runtime-wry",
  "tao",
  "wry",
  "webkit2gtk-sys",
  "javascriptcore-rs-sys",
  "wpe-webkit",
  "your-cloud-console",
]) {
  if (!nativeAssistantCargoPackageIsForbidden(forbiddenPackage)) {
    failures.push(`garde interne: paquet helper interdit non détecté (${forbiddenPackage})`);
  }
}
for (const allowedPackage of ["gtk", "gdk", "libadwaita", "your-cloud-bootstrap-protocol"]) {
  if (nativeAssistantCargoPackageIsForbidden(allowedPackage)) {
    failures.push(`garde interne: paquet UI natif légitime refusé (${allowedPackage})`);
  }
}
for (const forbiddenLibrary of [
  "libwebkit2gtk-4.1.so.0",
  "libjavascriptcoregtk-4.1.so.0",
  "libWPEWebKit-2.0.so.1",
]) {
  if (!nativeAssistantElfLibraryIsForbidden(forbiddenLibrary)) {
    failures.push(`garde interne: bibliothèque ELF interdite non détectée (${forbiddenLibrary})`);
  }
}
for (const allowedLibrary of ["libgtk-3.so.0", "libgdk-3.so.0", "libadwaita-1.so.0"]) {
  if (nativeAssistantElfLibraryIsForbidden(allowedLibrary)) {
    failures.push(`garde interne: bibliothèque GTK légitime refusée (${allowedLibrary})`);
  }
}
const packageDocument = JSON.parse(await readFile(join(consoleRoot, "package.json"), "utf8"));
const packageLock = JSON.parse(await readFile(join(consoleRoot, "package-lock.json"), "utf8"));
const tauriConfig = JSON.parse(
  await readFile(join(consoleRoot, "src-tauri", "tauri.conf.json"), "utf8"),
);
const cargoManifest = await readFile(join(consoleRoot, "src-tauri", "Cargo.toml"), "utf8");
const cargoLock = await readFile(join(consoleRoot, "src-tauri", "Cargo.lock"), "utf8");
const bootstrapRuntime = await readFile(
  join(consoleRoot, "src-tauri", "src", "bootstrap.rs"),
  "utf8",
);
const nativeAssistantRuntime = await readFile(
  join(consoleRoot, "src-tauri", "src", "native_assistant.rs"),
  "utf8",
);
const nativeAssistantPrompt = await readFile(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "src",
    "native_prompt.rs",
  ),
  "utf8",
);
const bootstrapProtocol = await readFile(
  join(consoleRoot, "src-tauri", "crates", "bootstrap-protocol", "src", "lib.rs"),
  "utf8",
);
const bootstrapProtocolManifest = await readFile(
  join(consoleRoot, "src-tauri", "crates", "bootstrap-protocol", "Cargo.toml"),
  "utf8",
);
const nativeAssistantManifest = await readFile(
  join(consoleRoot, "src-tauri", "crates", "native-bootstrap-assistant", "Cargo.toml"),
  "utf8",
);
const nativeAssistantBuild = await readFile(
  join(consoleRoot, "tools", "prepare-native-bootstrap-assistant.mjs"),
  "utf8",
);
const nativeAssistantGate = await readFile(
  join(consoleRoot, "tools", "lib", "native-bootstrap-assistant.mjs"),
  "utf8",
);
const sbomBuilder = await readFile(join(consoleRoot, "tools", "build-sbom.mjs"), "utf8");
const candidateManifestBuilder = await readFile(
  join(consoleRoot, "tools", "build-linux-candidate-manifest.mjs"),
  "utf8",
);
const continuousIntegration = await readFile(
  join(consoleRoot, "..", ".github", "workflows", "ci.yml"),
  "utf8",
);
const consoleRuntime = await readFile(join(consoleRoot, "src-tauri", "src", "lib.rs"), "utf8");
const productModels = await readFile(join(consoleRoot, "src", "product", "models.ts"), "utf8");
const nativeOperations = await readFile(join(consoleRoot, "src", "product", "native.ts"), "utf8");
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
if (
  JSON.stringify(tauriConfig.bundle?.externalBin) !==
  JSON.stringify(["binaries/your-cloud-native-bootstrap-assistant"])
) {
  failures.push("tauri.conf.json: externalBin doit nommer uniquement le helper natif fixe");
}
if (
  tauriConfig.build?.beforeBuildCommand !==
    "npm run build:native-assistant && npm run build" ||
  tauriConfig.build?.beforeDevCommand !==
    "npm run build:native-assistant:dev && npm run dev"
) {
  failures.push("tauri.conf.json: le helper natif doit être préparé avant Tauri build et dev");
}
if (
  packageDocument.scripts?.["build:native-assistant"] !==
    "node tools/prepare-native-bootstrap-assistant.mjs release" ||
  packageDocument.scripts?.["build:native-assistant:dev"] !==
    "node tools/prepare-native-bootstrap-assistant.mjs debug"
) {
  failures.push("package.json: scripts de préparation bornée du helper absents");
}
if (
  !continuousIntegration.includes(
    "cargo +1.94.1 fetch --manifest-path src-tauri/Cargo.toml --locked",
  ) ||
  !continuousIntegration.includes("npm run build:native-assistant") ||
  !continuousIntegration.includes("xvfb-run -a env NO_AT_BRIDGE=1") ||
  !continuousIntegration.includes(
    "native_prompt::tests::gtk_dialog_maps_consent_without_collecting_a_secret",
  ) ||
  !continuousIntegration.includes(
    "console_parent_keeps_the_gtk_helper_bounded_until_cancelled",
  ) ||
  continuousIntegration.indexOf("npm run build:native-assistant") >
    continuousIntegration.indexOf("cargo +1.94.1 test --release --locked --workspace")
) {
  failures.push("ci.yml: le helper natif doit être préparé avant les tests de tout le workspace");
}

const npmDocuments = JSON.stringify({
  dependencies: packageDocument.dependencies,
  devDependencies: packageDocument.devDependencies,
  lock: packageLock.packages,
});
if (npmDocuments.includes("@tauri-apps/plugin-shell")) {
  failures.push("dépendances npm: @tauri-apps/plugin-shell est interdit");
}
if (Object.hasOwn(tauriConfig.plugins ?? {}, "shell")) {
  failures.push("tauri.conf.json: le plugin shell est interdit");
}
for (const [name, source] of [
  ["Cargo.toml Console", cargoManifest],
  ["Cargo.toml protocole", bootstrapProtocolManifest],
  ["Cargo.toml helper", nativeAssistantManifest],
]) {
  if (/tauri[-_]plugin[-_]shell/iu.test(source)) {
    failures.push(`${name}: tauri-plugin-shell est interdit`);
  }
}
if (/^name\s*=\s*"tauri-plugin-shell"$/mu.test(cargoLock)) {
  failures.push("Cargo.lock: tauri-plugin-shell est interdit");
}

for (const expectedWorkspaceEntry of [
  '"crates/bootstrap-protocol"',
  '"crates/native-bootstrap-assistant"',
]) {
  if (!cargoManifest.includes(expectedWorkspaceEntry)) {
    failures.push(`Cargo.toml Console: membre workspace absent (${expectedWorkspaceEntry})`);
  }
}
if (
  !cargoManifest.includes("your-cloud-bootstrap-protocol") ||
  !bootstrapRuntime.includes("pub use your_cloud_bootstrap_protocol::{")
) {
  failures.push("protocole amorçage: la Console doit consommer et réexporter le crate partagé");
}
if (
  !/^name\s*=\s*"your-cloud-native-bootstrap-assistant"$/mu.test(nativeAssistantManifest) ||
  !/\[\[bin\]\][\s\S]*?^name\s*=\s*"your-cloud-native-bootstrap-assistant"$/mu.test(
    nativeAssistantManifest,
  ) ||
  !nativeAssistantManifest.includes('path = "../bootstrap-protocol"')
) {
  failures.push("Cargo.toml helper: paquet, binaire ou dépendance protocole non bornés");
}
if (
  /\b(?:tauri(?:-[\w-]+)?|wry(?:-[\w-]+)?|tao(?:-[\w-]+)?|webkit[\w-]*|javascriptcore[\w-]*|wpe(?:-[\w-]+)?)\b/iu.test(
    nativeAssistantManifest,
  )
) {
  failures.push("Cargo.toml helper: graphe Tauri, WebView ou WebKit interdit");
}

for (const [source, expected] of [
  [nativeAssistantBuild, "inspectPreparedNativeAssistant"],
  [nativeAssistantBuild, '"--locked"'],
  [nativeAssistantBuild, '"--offline"'],
  [nativeAssistantGate, '"x86_64-unknown-linux-gnu"'],
  [nativeAssistantGate, '"x86_64-pc-windows-msvc"'],
  [nativeAssistantGate, '"readelf"'],
  [sbomBuilder, "cargoClosure"],
  [candidateManifestBuilder, "helper_source_tree_sha256"],
]) {
  if (!source.includes(expected)) {
    failures.push(`outillage helper: garde attendue absente (${expected})`);
  }
}

const bootstrapStartInput = productModels.match(
  /export type BootstrapStartInput = \{(?<body>[\s\S]*?)\n\};/u,
)?.groups?.body;
if (!bootstrapStartInput) {
  failures.push("models.ts: contrat public BootstrapStartInput absent");
} else {
  const inputFields = [...bootstrapStartInput.matchAll(/^\s+(\w+):/gmu)].map((match) => match[1]);
  if (inputFields.join(",") !== "mode,target") {
    failures.push("models.ts: BootstrapStartInput doit seulement exposer mode et target");
  }
}

const bootstrapTarget = productModels.match(
  /export type BootstrapTarget = \{(?<body>[\s\S]*?)\n\};/u,
)?.groups?.body;
if (!bootstrapTarget) {
  failures.push("models.ts: contrat public BootstrapTarget absent");
} else {
  const targetFields = [...bootstrapTarget.matchAll(/^\s+(\w+):/gmu)].map((match) => match[1]);
  if (targetFields.join(",") !== "host,port,username,host_key_sha256,access_kind") {
    failures.push("models.ts: la cible d’amorçage sort du schéma positif décidé");
  }
}

const bootstrapSessionView = productModels.match(
  /export type BootstrapSessionView = \{(?<body>[\s\S]*?)\n\};/u,
)?.groups?.body;
if (!bootstrapSessionView) {
  failures.push("models.ts: contrat public BootstrapSessionView absent");
} else {
  const outputFields = [...bootstrapSessionView.matchAll(/^\s+(\w+):/gmu)].map(
    (match) => match[1],
  );
  if (
    outputFields.join(",") !==
    "schema_version,request_id,mode,target,step,actions,lifecycle,expires_in_seconds"
  ) {
    failures.push("models.ts: BootstrapSessionView doit rester un schéma positif exact");
  }
}

const rustSessionView = bootstrapProtocol.match(
  /pub struct BootstrapSessionView \{(?<body>[\s\S]*?)\n\}/u,
)?.groups?.body;
if (!rustSessionView) {
  failures.push("bootstrap-protocol: sortie sérialisée BootstrapSessionView absente");
} else {
  const outputFields = [...rustSessionView.matchAll(/^\s+pub (\w+):/gmu)].map(
    (match) => match[1],
  );
  if (
    outputFields.join(",") !==
    "schema_version,request_id,mode,target,step,actions,lifecycle,expires_in_seconds"
  ) {
    failures.push("bootstrap-protocol: BootstrapSessionView doit rester un schéma positif exact");
  }
}

const rustBootstrapTarget = bootstrapProtocol.match(
  /pub struct BootstrapTarget \{(?<body>[\s\S]*?)\n\}/u,
)?.groups?.body;
if (!rustBootstrapTarget) {
  failures.push("bootstrap-protocol: cible sérialisée BootstrapTarget absente");
} else {
  const targetFields = [...rustBootstrapTarget.matchAll(/^\s+pub (\w+):/gmu)].map(
    (match) => match[1],
  );
  if (targetFields.join(",") !== "host,port,username,host_key_sha256,access_kind") {
    failures.push("bootstrap-protocol: BootstrapTarget doit rester un schéma positif exact");
  }
}

for (const [source, body] of [
  ["models.ts BootstrapStartInput", bootstrapStartInput],
  ["models.ts BootstrapTarget", bootstrapTarget],
  ["models.ts BootstrapSessionView", bootstrapSessionView],
  ["bootstrap-protocol BootstrapTarget", rustBootstrapTarget],
  ["bootstrap-protocol BootstrapSessionView", rustSessionView],
]) {
  if (/\b(?:password|passphrase|private_key|secret|consent)\b/iu.test(body ?? "")) {
    failures.push(`${source}: un champ sensible traverse le contrat IPC`);
  }
}

for (const expected of [
  'export type BootstrapMode = "create" | "replace";',
  'step: "personal_access";',
  'actions: readonly ["audit_target_read_only"];',
  'lifecycle: "awaiting_native_assistant";',
]) {
  if (!productModels.includes(expected)) {
    failures.push(`models.ts: contrat d’amorçage manquant (${expected})`);
  }
}

for (const command of ["start_bootstrap", "bootstrap_status", "cancel_bootstrap"]) {
  if (!nativeOperations.includes(`"${command}"`) || !consoleRuntime.includes(command)) {
    failures.push(`IPC amorçage: commande nommée absente (${command})`);
  }
}

const invokeHandler = consoleRuntime.match(
  /tauri::generate_handler!\[(?<body>[\s\S]*?)\n\s*\]/u,
)?.groups?.body;
if (!invokeHandler) {
  failures.push("lib.rs: registre des commandes Tauri introuvable");
} else if (/\b(?:ssh\w*|\w*agent\w*|sign(?:ature)?\w*)\b/iu.test(invokeHandler)) {
  failures.push("lib.rs: une primitive SSH, agent ou signature générale est enregistrée");
}

for (const forbidden of ["request_id", "step", "actions", "ttl_seconds", "expires_in_seconds"]) {
  if (bootstrapStartInput?.includes(`${forbidden}:`)) {
    failures.push(`models.ts: le frontend ne doit pas fixer ${forbidden}`);
  }
}

for (const required of [
  "struct BootstrapStartEnvelope",
  "struct BootstrapRequestEnvelope",
  'exact_object(value, &["input"])',
  'exact_object(value, &["requestId"])',
]) {
  if (!bootstrapRuntime.includes(required)) {
    failures.push(`bootstrap.rs: enveloppe IPC hostile incomplète (${required})`);
  }
}
const rawRequestCommands = ["start_bootstrap", "bootstrap_status", "cancel_bootstrap"].filter(
  (command) => {
    const commandBody = consoleRuntime.match(
      new RegExp(
        `#\\[tauri::command\\]\\nfn ${command}\\((?<body>[\\s\\S]*?)\\n\\}`,
        "u",
      ),
    )?.groups?.body;
    return !commandBody?.includes("request: Request<'_>");
  },
);
if (rawRequestCommands.length > 0 || !consoleRuntime.includes("InvokeBody::Raw(_)")) {
  failures.push(
    `lib.rs: les commandes d’amorçage doivent fermer le corps Tauri complet (${rawRequestCommands.join(",")})`,
  );
}
if (!bootstrapRuntime.includes("const BOOTSTRAP_TTL: Duration = Duration::from_secs(300);")) {
  failures.push("bootstrap.rs: le TTL monotone fixe de 300 secondes est absent");
}
if (
  !consoleRuntime.includes("tauri::WindowEvent::CloseRequested") ||
  !consoleRuntime.includes("tauri::WindowEvent::Destroyed") ||
  !consoleRuntime.includes("bootstrap.close()")
) {
  failures.push("lib.rs: la fermeture native ne rend pas l’état d’amorçage terminal");
}
if (
  !consoleRuntime.includes("struct ConsoleLocalState") ||
  !consoleRuntime.includes("core: ConsoleCore") ||
  !consoleRuntime.includes("bootstrap: BootstrapState") ||
  !consoleRuntime.includes("native_assistant: NativeAssistantSupervisor")
) {
  failures.push(
    "lib.rs: coffre, amorçage et helper doivent partager la même transition atomique",
  );
}
const lockCommand = consoleRuntime.match(
  /#\[tauri::command\]\nfn lock_console\((?<body>[\s\S]*?)\n\}/u,
)?.groups?.body;
const localLockIndex = lockCommand?.search(/state\.local\.lock\(\)/u) ?? -1;
const networkLockIndex = lockCommand?.search(/state\s*\.network\s*\.lock\(\)/u) ?? -1;
if (
  !lockCommand ||
  localLockIndex < 0 ||
  networkLockIndex < 0 ||
  localLockIndex > networkLockIndex ||
  networkLockIndex > lockCommand.indexOf("local_result?;")
) {
  failures.push(
    "lib.rs: le verrouillage local doit précéder le nettoyage réseau, exécuté avant tout retour d’erreur",
  );
}
if (/\b(?:russh|ssh2|sudo|Command::new|std::process|sign(?:ature)?)\b/iu.test(bootstrapRuntime)) {
  failures.push("bootstrap.rs: une primitive d’exécution ou de signature est exposée trop tôt");
}
for (const expected of [
  'const NATIVE_ASSISTANT_BINARY: &str = "your-cloud-native-bootstrap-assistant";',
  'const REQUIRED_MODE_ARGUMENT: &str = "--native-bootstrap-assistant";',
  "Command::new(path)",
  ".env_clear()",
  ".stdin(Stdio::piped())",
  ".stdout(Stdio::piped())",
  ".stderr(Stdio::null())",
  "MAX_ASSISTANT_SCOPE_FRAME_BYTES",
  "MAX_ASSISTANT_EVENT_FRAME_BYTES",
  "configure_nonblocking_stdout",
  "command.process_group(0)",
  "const KILL_REAP_GRACE: Duration",
  "cleanup_worker: Option<CleanupWorker>",
  "cleanup_unproven: bool",
  "terminate_running_and_reap_bounded",
  "reap_until_terminal",
]) {
  if (!nativeAssistantRuntime.includes(expected)) {
    failures.push(`native_assistant.rs: garde de lancement parent absente (${expected})`);
  }
}
if (/\.wait\s*\(/u.test(nativeAssistantRuntime)) {
  failures.push(
    "native_assistant.rs: la recolte du helper ne doit jamais attendre sans echeance",
  );
}
for (const allowedEnvironmentName of [
  "DISPLAY",
  "XAUTHORITY",
  "WAYLAND_DISPLAY",
  "XDG_RUNTIME_DIR",
]) {
  if (!nativeAssistantRuntime.includes(`"${allowedEnvironmentName}"`)) {
    failures.push(
      `native_assistant.rs: variable graphique publique absente (${allowedEnvironmentName})`,
    );
  }
}
for (const forbiddenEnvironmentName of [
  "LD_PRELOAD",
  "LD_LIBRARY_PATH",
  "GTK_MODULES",
  "GTK_PATH",
  "SSH_AUTH_SOCK",
]) {
  if (nativeAssistantRuntime.includes(`"${forbiddenEnvironmentName}"`)) {
    failures.push(
      `native_assistant.rs: variable non autorisée transmise trop tôt (${forbiddenEnvironmentName})`,
    );
  }
}
if (
  !nativeAssistantPrompt.includes("Dialog::with_buttons") ||
  !nativeAssistantPrompt.includes("SessionTerminal::Refused") ||
  !nativeAssistantPrompt.includes("SessionTerminal::Expired") ||
  /\b(?:Entry|PasswordEntry|SSH_AUTH_SOCK|passphrase|password|secret)\b/u.test(
    nativeAssistantPrompt.replaceAll("without_collecting_a_secret", ""),
  )
) {
  failures.push(
    "native_prompt.rs: le palier GTK doit rester un consentement terminal sans collecte secrète",
  );
}
if (/Command::new|std::process::Command/iu.test(consoleRuntime)) {
  failures.push("lib.rs: le lancement du helper doit rester isolé dans native_assistant.rs");
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

for (const path of await filesBelow(join(consoleRoot, "src-tauri", "capabilities"))) {
  const contents = await readFile(path, "utf8");
  if (/tauri[-_]plugin[-_]shell|["']shell:/iu.test(contents)) {
    failures.push(`${relative(consoleRoot, path)}: permission shell interdite`);
  }
}

const runtimeRoots = [
  join(consoleRoot, "src"),
  join(consoleRoot, "src-tauri", "src"),
  join(consoleRoot, "src-tauri", "crates"),
];
for (const runtimeRoot of runtimeRoots) {
  for (const path of await filesBelow(runtimeRoot)) {
    if (![".rs", ".ts", ".tsx"].includes(extname(path))) continue;
    const contents = await readFile(path, "utf8");
    const name = relative(consoleRoot, path);
    if (/tauri[-_]plugin[-_]shell|@tauri-apps\/plugin-shell/iu.test(contents)) {
      failures.push(`${name}: appel au plugin shell interdit`);
    }
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
