import { readFile, readdir } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import {
  nativeAssistantCargoPackageIsForbidden,
  nativeAssistantElfLibraryIsForbidden,
  nativeAssistantPeLibraryIsForbidden,
} from "../tools/lib/native-bootstrap-assistant.mjs";

const consoleRoot = fileURLToPath(new URL("..", import.meta.url));
const failures = [];
const normalizeSourceText = (source) => source.replace(/\r\n?/gu, "\n");
const readSourceText = async (path) =>
  normalizeSourceText(await readFile(path, "utf8"));
const releaseCoupledIdentifier =
  /\bv\d+\.\d+\.\d+\b|\bv\d+-\d+-\d+\b|\/v\d+\.\d+\.\d+\b/iu;
const forbiddenProtectedSecretDerive =
  /#\[derive\([^\]]*(?:Clone|Serialize|Deserialize)[^\]]*\)\]\s*pub\(crate\) struct ProtectedSecret/u;

if (normalizeSourceText("ligne 1\r\nligne 2\rligne 3\n") !== "ligne 1\nligne 2\nligne 3\n") {
  failures.push("garde interne: normalisation LF, CRLF et CR invalide");
}
if (
  !forbiddenProtectedSecretDerive.test(
    "#[derive(Debug, Clone)]\npub(crate) struct ProtectedSecret { value: Vec<u8> }",
  )
) {
  failures.push("garde interne: derive interdit du secret protégé non détecté");
}

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
for (const forbiddenLibrary of [
  "WebView2Loader.dll",
  "WebKit2.dll",
  "JavaScriptCore.dll",
  "WPEBackend.dll",
]) {
  if (!nativeAssistantPeLibraryIsForbidden(forbiddenLibrary)) {
    failures.push(`garde interne: bibliothèque PE interdite non détectée (${forbiddenLibrary})`);
  }
}
for (const allowedLibrary of ["KERNEL32.dll", "USER32.dll", "ADVAPI32.dll"]) {
  if (nativeAssistantPeLibraryIsForbidden(allowedLibrary)) {
    failures.push(`garde interne: bibliothèque Win32 légitime refusée (${allowedLibrary})`);
  }
}
const packageDocument = JSON.parse(await readFile(join(consoleRoot, "package.json"), "utf8"));
const packageLock = JSON.parse(await readFile(join(consoleRoot, "package-lock.json"), "utf8"));
const tauriConfig = JSON.parse(
  await readFile(join(consoleRoot, "src-tauri", "tauri.conf.json"), "utf8"),
);
const cargoManifest = await readSourceText(join(consoleRoot, "src-tauri", "Cargo.toml"));
const cargoLock = await readSourceText(join(consoleRoot, "src-tauri", "Cargo.lock"));
const bootstrapRuntime = await readSourceText(
  join(consoleRoot, "src-tauri", "src", "bootstrap.rs"),
);
const nativeAssistantRuntime = await readSourceText(
  join(consoleRoot, "src-tauri", "src", "native_assistant.rs"),
);
const nativeAssistantWindows = await readSourceText(
  join(consoleRoot, "src-tauri", "src", "native_assistant", "windows.rs"),
);
const nativeAssistantHardening = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "src",
    "hardening.rs",
  ),
);
const nativeAssistantHelperRuntime = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "src",
    "lib.rs",
  ),
);
const nativeAssistantWatchdog = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "src",
    "watchdog.rs",
  ),
);
const bootstrapProtocolMonotonic = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "bootstrap-protocol",
    "src",
    "monotonic.rs",
  ),
);
const nativeAssistantWindowsJobContract = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "tests",
    "windows_job_contract.rs",
  ),
);
const nativeAssistantPrompt = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "src",
    "native_prompt.rs",
  ),
);
const nativeAssistantWindowsPrompt = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "src",
    "native_prompt_windows.rs",
  ),
);
const nativeAssistantLease = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "src",
    "lease.rs",
  ),
);
const nativeAssistantParent = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "src",
    "parent.rs",
  ),
);
const nativeAssistantSecret = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "src",
    "secret.rs",
  ),
);
const nativeAssistantCrashFixture = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "src",
    "secret_crash_fixture.rs",
  ),
);
const nativeAssistantCrashContract = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "tests",
    "secret_crash_contract.rs",
  ),
);
const nativeAssistantParentSpoofFixture = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "src",
    "parent_spoof_fixture.rs",
  ),
);
const nativeAssistantParentSpoofContract = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "tests",
    "windows_parent_spoof_contract.rs",
  ),
);
// Les aides bornées du contrat processus vivent désormais dans un module
// partagé, inclus par `#[path]` à la fois par ce contrat et par celui de
// l'accès personnel. La preuve est donc lue sur les deux fichiers réunis :
// exiger les jetons dans le seul fichier de tests reviendrait à interdire de
// partager ces bornes, alors que les dupliquer est précisément ce qui les fait
// diverger.
const nativeAssistantBoundedProcess = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "tests",
    "support",
    "bounded_process.rs",
  ),
);
const nativeAssistantLinuxProcessContract = `${await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "tests",
    "process_contract.rs",
  ),
)}\n${nativeAssistantBoundedProcess}`;
const nativeAssistantWindowsLivePromptContract = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "tests",
    "windows_live_prompt_contract.rs",
  ),
);
const nativeAssistantPersonalAccessContract = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "tests",
    "personal_access_contract.rs",
  ),
);
const nativeAssistantAgentEndpoint = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "src",
    "personal_access",
    "agent_endpoint.rs",
  ),
);
const nativeAssistantAgentPipe = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "src",
    "personal_access",
    "agent_pipe.rs",
  ),
);
const nativeAssistantLocalAddresses = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "src",
    "personal_access",
    "local_addresses.rs",
  ),
);
const nativeAssistantPersonalAccess = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "src",
    "personal_access.rs",
  ),
);
const nativeAssistantDelayedStartFixture = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "src",
    "delayed_start_fixture.rs",
  ),
);
const nativeAssistantDelayedStartContract = await readSourceText(
  join(
    consoleRoot,
    "src-tauri",
    "crates",
    "native-bootstrap-assistant",
    "tests",
    "delayed_start_contract.rs",
  ),
);
const bootstrapProtocol = await readSourceText(
  join(consoleRoot, "src-tauri", "crates", "bootstrap-protocol", "src", "lib.rs"),
);
const approvalProtocol = await readSourceText(
  join(consoleRoot, "src-tauri", "crates", "bootstrap-protocol", "src", "approval.rs"),
);
const planProtocol = await readSourceText(
  join(consoleRoot, "src-tauri", "crates", "bootstrap-protocol", "src", "plan.rs"),
);
const approvalRuntime = await readSourceText(join(consoleRoot, "src-tauri", "src", "approval.rs"));
const planV2Protocol = await readSourceText(
  join(consoleRoot, "src-tauri", "crates", "bootstrap-protocol", "src", "plan_v2.rs"),
);
const probePlanRuntime = await readSourceText(
  join(consoleRoot, "src-tauri", "src", "probe_plan.rs"),
);
const publicationPlanRuntime = await readSourceText(
  join(consoleRoot, "src-tauri", "src", "publication_plan.rs"),
);
const planV3Protocol = await readSourceText(
  join(consoleRoot, "src-tauri", "crates", "bootstrap-protocol", "src", "plan_v3.rs"),
);
const linkPlanRuntime = await readSourceText(join(consoleRoot, "src-tauri", "src", "link_plan.rs"));
const bootstrapProtocolManifest = await readSourceText(
  join(consoleRoot, "src-tauri", "crates", "bootstrap-protocol", "Cargo.toml"),
);
const nativeAssistantManifest = await readSourceText(
  join(consoleRoot, "src-tauri", "crates", "native-bootstrap-assistant", "Cargo.toml"),
);
const nativeAssistantBuild = await readSourceText(
  join(consoleRoot, "tools", "prepare-native-bootstrap-assistant.mjs"),
);
const nativeAssistantGate = await readSourceText(
  join(consoleRoot, "tools", "lib", "native-bootstrap-assistant.mjs"),
);
const sbomBuilder = await readSourceText(join(consoleRoot, "tools", "build-sbom.mjs"));
const candidateManifestBuilder = await readSourceText(
  join(consoleRoot, "tools", "build-linux-candidate-manifest.mjs"),
);
const continuousIntegration = await readSourceText(
  join(consoleRoot, "..", ".github", "workflows", "ci.yml"),
);
const linuxInstalledProof = await readSourceText(
  join(consoleRoot, "..", "tests", "checks", "console-linux-ci"),
);
const windowsInstalledProof = await readSourceText(
  join(consoleRoot, "..", "tests", "checks", "console-windows-ci.ps1"),
);
const installedUiProof = await readSourceText(
  join(consoleRoot, "..", "tests", "checks", "console-windows-ui-proof.py"),
);
const installedUiRasterContract = await readSourceText(
  join(consoleRoot, "..", "tests", "checks", "test-console-ui-raster.py"),
);
const genericSourceGate = await readSourceText(
  join(consoleRoot, "..", "tests", "checks", "source-v0.0.1"),
);
const consoleRuntime = await readSourceText(join(consoleRoot, "src-tauri", "src", "lib.rs"));
const networkRuntime = await readSourceText(join(consoleRoot, "src-tauri", "src", "network.rs"));
const productModels = await readSourceText(join(consoleRoot, "src", "product", "models.ts"));
const nativeOperations = await readSourceText(join(consoleRoot, "src", "product", "native.ts"));
const infrastructureViews = await readSourceText(
  join(consoleRoot, "src", "product", "infrastructure-views.tsx"),
);
const productScreens = await readSourceText(join(consoleRoot, "src", "product", "screens.css"));
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
for (const forbiddenShippingFeature of [
  "native-prompt-contract-test",
  "secret-crash-contract-test",
  "windows-parent-spoof-contract-test",
  "windows-live-prompt-contract-test",
  "delayed-start-contract-test",
  "windows-agent-pipe-contract-test",
]) {
  if (nativeAssistantBuild.includes(forbiddenShippingFeature)) {
    failures.push(
      `outillage helper: une feature de fixture entre dans le build livré (${forbiddenShippingFeature})`,
    );
  }
}
if (
  !continuousIntegration.includes(
    "cargo +1.94.1 fetch --manifest-path src-tauri/Cargo.toml --locked",
  ) ||
  !continuousIntegration.includes("npm run build:native-assistant") ||
  !continuousIntegration.includes(
    'xvfb-run -a -s "-screen 0 1280x1024x24 -noreset" env NO_AT_BRIDGE=1',
  ) ||
  !continuousIntegration.includes(
    "native_prompt::tests::gtk_dialog_handles_consent_secret_and_lease_states",
  ) ||
  !continuousIntegration.includes(
    "native_prompt_windows::tests::win32_dialog_handles_consent_secret_tamper_and_lease_states",
  ) ||
  !continuousIntegration.includes(
    "console_parent_keeps_the_gtk_helper_bounded_until_cancelled",
  ) ||
  !continuousIntegration.includes(
    "helper_closes_every_inherited_descriptor_outside_stdio",
  ) ||
  !continuousIntegration.includes(
    "live_prompt_refuses_target_step_action_and_expiration_mutations",
  ) ||
  !continuousIntegration.includes("--features windows-contract-test") ||
  !continuousIntegration.includes("--features native-prompt-contract-test") ||
  !continuousIntegration.includes("--features secret-crash-contract-test") ||
  !continuousIntegration.includes("--features windows-parent-spoof-contract-test") ||
  !continuousIntegration.includes("--features windows-live-prompt-contract-test") ||
  !continuousIntegration.includes("--features delayed-start-contract-test") ||
  !continuousIntegration.includes("--test process-contract") ||
  !continuousIntegration.includes("--test parent-contract") ||
  !continuousIntegration.includes("--test windows-job-contract") ||
  !continuousIntegration.includes("--test secret-crash-contract") ||
  !continuousIntegration.includes("--test windows-parent-spoof-contract") ||
  !continuousIntegration.includes("--test windows-live-prompt-contract") ||
  !continuousIntegration.includes("--test delayed-start-contract") ||
  !continuousIntegration.includes("declared_parent_cannot_authorize_an_attacker_owned_pipe") ||
  !continuousIntegration.includes(
    "live_prompt_refuses_target_step_action_and_expiration_mutations",
  ) ||
  !continuousIntegration.includes(
    "delay_before_process_main_cannot_renew_the_transmitted_ttl",
  ) ||
  !continuousIntegration.includes("\n          gdb\n") ||
  !continuousIntegration.includes("webkit2gtk-driver") ||
  !continuousIntegration.includes("xdotool") ||
  !continuousIntegration.includes("imagemagick") ||
  !continuousIntegration.includes("console-linux-webkitgtk-smoke") ||
  !continuousIntegration.includes(
    'dbus-run-session -- xvfb-run -a -s "-screen 0 1280x1024x24 -noreset" env NO_AT_BRIDGE=1',
  ) ||
  continuousIntegration.indexOf("npm run build:native-assistant") >
    continuousIntegration.indexOf("cargo +1.94.1 test --release --locked --workspace")
) {
  failures.push("ci.yml: le helper natif doit être préparé avant les tests de tout le workspace");
}
for (const [name, source, fragments] of [
  [
    "preuve Linux installée",
    linuxInstalledProof,
    [
      "/usr/bin/your-cloud-native-bootstrap-assistant",
      "installed native helper accepted a direct non-Console parent",
      "--native-driver /usr/bin/WebKitWebDriver",
      "--native-port 4445",
      "--platform linux",
      "linux-webkitgtk-smoke.json",
      "linux-native-personal-consent.png",
      "installed Linux proof artifact contains an unexpected entry",
      "Linux WebDriver, Console, helper or loopback listeners remained after cleanup",
    ],
  ],
  [
    "preuve Windows installée",
    windowsInstalledProof,
    [
      "direct native helper parent refusal",
      "-AllowedExitCodes @(70)",
      "refused native helper invocation emitted public output",
      "windows-native-personal-consent.png",
      "$proofNameDifferences",
    ],
  ],
  [
    "preuve UI installée",
    installedUiProof,
    [
      "phase: 'capture_ready'",
      "phase: 'finished'",
      "create_helper_running_after_native_capture: true",
      "replace_helper_running_after_millis: 1000",
      'driver.execute_async(BOOTSTRAP_IPC_PROOF_SCRIPT, ["start"])',
      '["finish", create_request_id]',
      "if create_request_id in serialized_proof",
      "capture_linux_native_prompt",
      "capture_windows_native_prompt",
      "SendMessageTimeoutW",
      "native-personal-consent.png",
      '"public_scope_machine_inspected": False',
      '"secret_control_machine_inspected": False',
      "frontend-consent-must-not-be-accepted",
      "authority_fields: authorityRejections",
      "active_target_mutation: targetMutationCode",
      "sensitive_input_included_in_public_error_or_proof_artifact: false",
      "MAX_SCREENSHOT_ATTEMPTS = 5",
      "MIN_SCREENSHOT_DISTINCT_RGB = 256",
      "MAX_SCREENSHOT_DOMINANT_RGB_RATIO = 0.995",
      "MAX_SCREENSHOT_EXACT_BLACK_RATIO = 0.10",
      "def inspect_png_raster(",
      "zlib.decompressobj()",
      "document.fonts?.ready",
      "requestAnimationFrame",
      "capture_attempts",
      "def set_script_timeout(",
      "self.set_script_timeout(timeout_seconds)",
      "capture raster has too few distinct RGB colors",
      "capture raster is dominated by one RGB color",
      "capture raster contains too much exact black",
      'desktop["raster"] = driver.screenshot(',
      'compact["raster"] = driver.screenshot(',
      'zoomed["raster"] = driver.screenshot(',
    ],
  ],
]) {
  for (const fragment of fragments) {
    if (!source.includes(fragment)) {
      failures.push(`${name}: contrat absent (${fragment})`);
    }
  }
}

for (const fragment of [
  "black_damage",
  "dominant_pixel",
  "transparent",
  "corrupt_crc",
  "dimensions differ",
  "exercise_screenshot_retry",
  "exercise_async_retry_boundary",
  '"not-base64!"',
  "synthetic timeout disconnect",
  "synthetic mutating disconnect",
  "only the idempotent script timeout may be retried",
  "a mutating async request was retried after disconnection",
  "remained invalid after 5 attempts",
  "target.exists()",
  "for filter_type in range(1, 5)",
  "unknown_filter",
  "unknown_critical",
]) {
  if (!installedUiRasterContract.includes(fragment)) {
    failures.push(`preuve hostile du raster UI absente (${fragment})`);
  }
}
if (
  [...installedUiRasterContract.matchAll(/\bexercise_async_retry_boundary\(\)/gu)].length !== 2
) {
  failures.push("preuve UI installée: la frontière async doit être définie puis exécutée");
}
if (
  !genericSourceGate.includes("tests/checks/test-console-ui-raster.py") ||
  !genericSourceGate.includes("python3 -B tests/checks/test-console-ui-raster.py")
) {
  failures.push("source-v0.0.1: le contrat hostile du raster UI doit être exécuté");
}

const resizeMethodStart = installedUiProof.indexOf("    def resize(");
const screenshotMethodStart = installedUiProof.indexOf("    def screenshot(");
const screenshotMethodEnd = installedUiProof.indexOf("    def press_tab(", screenshotMethodStart);
const resizeMethod =
  resizeMethodStart >= 0 && screenshotMethodStart > resizeMethodStart
    ? installedUiProof.slice(resizeMethodStart, screenshotMethodStart)
    : "";
const screenshotMethod =
  screenshotMethodStart >= 0 && screenshotMethodEnd > screenshotMethodStart
    ? installedUiProof.slice(screenshotMethodStart, screenshotMethodEnd)
    : "";
const screenshotOrder = [
  "for attempt in range(",
  "self.wait_for_paint()",
  'f"/session/{self.session_id}/screenshot"',
  "base64.b64decode(encoded, validate=True)",
  "inspect_png_raster(payload, expected_width, expected_height)",
  "path.write_bytes(payload)",
  'return {**raster, "capture_attempts": attempt}',
].map((fragment) => screenshotMethod.indexOf(fragment));
if (
  !resizeMethod.includes("self.wait(") ||
  resizeMethod.includes("time.sleep(0.25)") ||
  screenshotOrder.some((position) => position < 0) ||
  screenshotOrder.some((position, index) => index > 0 && position <= screenshotOrder[index - 1])
) {
  failures.push(
    "preuve UI installée: resize et capture doivent attendre, valider puis écrire le raster dans cet ordre",
  );
}

const linuxPidTerminatorStart = linuxInstalledProof.indexOf("terminate_child_pid() {");
const linuxPidTerminatorEnd = linuxInstalledProof.indexOf(
  "terminate_driver_group() {",
  linuxPidTerminatorStart,
);
const linuxPidTerminator =
  linuxPidTerminatorStart >= 0 && linuxPidTerminatorEnd > linuxPidTerminatorStart
    ? linuxInstalledProof.slice(linuxPidTerminatorStart, linuxPidTerminatorEnd)
    : "";
const linuxPidTerminationOrder = [
  'validate_process_id "$process_id"',
  'kill -TERM "$process_id"',
  'wait_for_child_stop_bounded "$process_id"',
  'kill -KILL "$process_id"',
  'reap_stopped_child "$process_id"',
].map((fragment) => linuxPidTerminator.indexOf(fragment));
if (
  linuxPidTerminationOrder.some((index) => index < 0) ||
  linuxPidTerminationOrder.some(
    (index, position) => position > 0 && index <= linuxPidTerminationOrder[position - 1],
  )
) {
  failures.push(
    "preuve Linux installée: le launcher doit suivre PID validé, TERM, borne, KILL puis reap",
  );
}

const linuxDriverTerminatorStart = linuxInstalledProof.indexOf(
  "terminate_driver_group() {",
);
const linuxDriverTerminatorEnd = linuxInstalledProof.indexOf(
  "cleanup() {",
  linuxDriverTerminatorStart,
);
const linuxDriverTerminator =
  linuxDriverTerminatorStart >= 0 && linuxDriverTerminatorEnd > linuxDriverTerminatorStart
    ? linuxInstalledProof.slice(linuxDriverTerminatorStart, linuxDriverTerminatorEnd)
    : "";
for (const expected of [
  'validate_process_id "$process_id" "tauri-driver PID"',
  'validate_process_id "$process_group_id" "tauri-driver PGID"',
  '[[ "$process_id" != "$process_group_id" ]]',
  'kill -TERM -- "-$process_group_id"',
  'child_is_stopped_or_zombie "$process_id"',
  'reap_stopped_child "$process_id"',
  'kill -KILL -- "-$process_group_id"',
  'kill -0 -- "-$process_group_id"',
  '[[ "$group_disappeared" != true ]]',
]) {
  if (!linuxDriverTerminator.includes(expected)) {
    failures.push(`preuve Linux installée: arrêt borné du driver absent (${expected})`);
  }
}
const driverTermIndex = linuxDriverTerminator.indexOf(
  'kill -TERM -- "-$process_group_id"',
);
const driverEarlyReapIndex = linuxDriverTerminator.indexOf(
  'reap_stopped_child "$process_id"',
);
const driverKillIndex = linuxDriverTerminator.indexOf(
  'kill -KILL -- "-$process_group_id"',
);
if (
  driverTermIndex < 0 ||
  driverEarlyReapIndex <= driverTermIndex ||
  driverKillIndex <= driverEarlyReapIndex
) {
  failures.push(
    "preuve Linux installée: le leader driver doit être reapé sous borne entre TERM et KILL éventuel",
  );
}

const driverLaunchOrder = [
  "setsid tauri-driver",
  "driver_pid=$!",
  'validate_process_id "$driver_pid" "tauri-driver PID"',
  'ps -o pgid= -p "$driver_pid"',
  '[[ "$observed_driver_pgid" == "$driver_pid" ]]',
  "driver_pgid=$observed_driver_pgid",
].map((fragment) => linuxInstalledProof.indexOf(fragment));
driverLaunchOrder.push(
  linuxInstalledProof.indexOf(
    'terminate_driver_group "$driver_pid" "$driver_pgid"',
    driverLaunchOrder.at(-1) + 1,
  ),
);
if (
  driverLaunchOrder.some((index) => index < 0) ||
  driverLaunchOrder.some(
    (index, position) => position > 0 && index <= driverLaunchOrder[position - 1],
  )
) {
  failures.push(
    "preuve Linux installée: le PGID setsid doit être résolu, égal au PID puis utilisé au nominal",
  );
}
if (
  /\bwait\s+"\$(?:driver_pid|launcher_pid)"/u.test(linuxInstalledProof) ||
  /kill\s+-(?:TERM|KILL)\s+--\s+"-\$driver_pid"/u.test(linuxInstalledProof) ||
  (linuxInstalledProof.match(/\bwait\s+"\$process_id"/gu) ?? []).length !== 1 ||
  !linuxInstalledProof.includes('if wait "$process_id"; then') ||
  !linuxInstalledProof.includes('[[ "$wait_status" -eq 127 ]]')
) {
  failures.push(
    "preuve Linux installée: wait direct ou cible driver non validée hors primitive bornée",
  );
}

const startHandshakeIndex = installedUiProof.indexOf(
  'driver.execute_async(BOOTSTRAP_IPC_PROOF_SCRIPT, ["start"])',
);
const synchronousCaptureIndex = installedUiProof.indexOf("capture_facts = (");
const finishHandshakeIndex = installedUiProof.indexOf('["finish", create_request_id]');
if (
  installedUiProof.includes("threading.Thread") ||
  startHandshakeIndex < 0 ||
  synchronousCaptureIndex <= startHandshakeIndex ||
  finishHandshakeIndex <= synchronousCaptureIndex
) {
  failures.push(
    "preuve UI installée: la capture native doit rester synchrone entre les handshakes start et finish",
  );
}

const nativeVaultScriptMatch = installedUiProof.match(
  /NATIVE_VAULT_INITIALIZATION_SCRIPT = r"""(?<body>[\s\S]*?)"""/u,
);
const nativeVaultScript = nativeVaultScriptMatch?.groups?.body;
const nativeVaultInitializer = installedUiProof.match(
  /def initialize_real_native_vault\(driver: Driver\) -> None:\n(?<body>[\s\S]*?)\n\nBOOTSTRAP_IPC_PROOF_SCRIPT/u,
)?.groups?.body;
for (const forbidden of [
  "def fill_fields(",
  "driver.fill_fields(",
  "secrets = driver.execute(",
  "phrase, recovery = secrets",
  "return [...document.querySelectorAll('.yc-secret')].map((e)=>e.textContent.trim())",
]) {
  if (installedUiProof.includes(forbidden)) {
    failures.push(`preuve UI installée: secret sorti de la WebView (${forbidden})`);
  }
}
if (!nativeVaultScript || !nativeVaultInitializer) {
  failures.push("preuve UI installée: initialisation encapsulée du coffre absente");
} else {
  for (const expected of [
    "const secrets = await waitFor(() => {",
    "const candidates = [...document.querySelectorAll('.yc-secret')]",
    "/^[^ ]+(?: [^ ]+){5}$/u.test(phrase)",
    "new TextEncoder().encode(phrase).length <= 96",
    "/^(?:[A-Z2-7]{6}-){8}[A-Z2-7]{6}$/u.test(recovery)",
    "setInputValue('#confirm-unlock-phrase', phrase)",
    "setInputValue('#confirm-recovery-code', recovery)",
    "checkbox.click()",
    "secrets.fill('')",
    "phrase = ''",
    "recovery = ''",
    "confirmButton.click()",
    "document.querySelectorAll('.yc-secret').length === 0",
    "Object.keys(localStorage).length === 0",
    "Object.keys(sessionStorage).length === 0",
    "done({ ok: true, facts })",
    "done({ ok: false, failure: phase })",
  ]) {
    if (!nativeVaultScript.includes(expected)) {
      failures.push(`preuve UI installée: coffre WebView expurgé incomplet (${expected})`);
    }
  }
  const nativeVaultDoneCalls = [...nativeVaultScript.matchAll(/\bdone\((?<body>[\s\S]*?)\)/gu)]
    .map((match) => match.groups?.body.trim());
  if (
    JSON.stringify(nativeVaultDoneCalls) !==
    JSON.stringify(["{ ok: true, facts }", "{ ok: false, failure: phase }"])
  ) {
    failures.push(
      "preuve UI installée: le script coffre doit exposer exactement les deux résultats expurgés",
    );
  }
  if (
    nativeVaultDoneCalls.some((call) => /\b(?:secrets|phrase|recovery)\b/u.test(call ?? ""))
  ) {
    failures.push("preuve UI installée: un résultat WebDriver référence une valeur secrète");
  }
  const installedUiProofOutsideVaultScript = installedUiProof.replace(
    nativeVaultScriptMatch[0],
    "",
  );
  if (
    installedUiProofOutsideVaultScript.includes(".yc-secret") ||
    installedUiProofOutsideVaultScript.includes("#confirm-unlock-phrase") ||
    installedUiProofOutsideVaultScript.includes("#confirm-recovery-code")
  ) {
    failures.push(
      "preuve UI installée: sélecteur secret présent hors du script WebView encapsulé",
    );
  }
  for (const expected of [
    "driver.execute_async(NATIVE_VAULT_INITIALIZATION_SCRIPT, timeout_seconds=90)",
    'outcome.get("facts") == {',
    'driver.wait("return document.querySelector(\'h1\')?.textContent ?? null;", "Infrastructures", 60)',
  ]) {
    if (!nativeVaultInitializer.includes(expected)) {
      failures.push(`preuve UI installée: oracle coffre expurgé incomplet (${expected})`);
    }
  }
  if (
    /driver\.(?:execute|fill_fields)\(/u.test(nativeVaultInitializer) ||
    /\b(?:phrase|recovery)\b/u.test(nativeVaultInitializer)
  ) {
    failures.push(
      "preuve UI installée: l’orchestrateur Python ne doit lire ou réinjecter aucun secret du coffre",
    );
  }
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
for (const expected of [
  "native-prompt-contract-test = []",
  'required-features = ["native-prompt-contract-test"]',
]) {
  if (!nativeAssistantManifest.includes(expected)) {
    failures.push(`Cargo.toml helper: fixture de prompt non bornée (${expected})`);
  }
}
if (
  !nativeAssistantManifest.includes("secret-crash-contract-test = []") ||
  !/\[\[bin\]\][\s\S]*?name\s*=\s*"your-cloud-secret-crash-fixture"[\s\S]*?path\s*=\s*"src\/secret_crash_fixture\.rs"[\s\S]*?required-features\s*=\s*\["secret-crash-contract-test"\]/u.test(
    nativeAssistantManifest,
  ) ||
  !/\[\[test\]\][\s\S]*?name\s*=\s*"secret-crash-contract"[\s\S]*?path\s*=\s*"tests\/secret_crash_contract\.rs"[\s\S]*?required-features\s*=\s*\["secret-crash-contract-test"\]/u.test(
    nativeAssistantManifest,
  )
) {
  failures.push("Cargo.toml helper: fixture crash/dump test-only absente ou non bornée");
}
if (
  !nativeAssistantManifest.includes(
    'windows-parent-spoof-contract-test = ["native-prompt-contract-test"]',
  ) ||
  !/\[\[bin\]\][\s\S]*?name\s*=\s*"your-cloud-parent-spoof-fixture"[\s\S]*?path\s*=\s*"src\/parent_spoof_fixture\.rs"[\s\S]*?required-features\s*=\s*\["windows-parent-spoof-contract-test"\]/u.test(
    nativeAssistantManifest,
  ) ||
  !/\[\[test\]\][\s\S]*?name\s*=\s*"windows-parent-spoof-contract"[\s\S]*?path\s*=\s*"tests\/windows_parent_spoof_contract\.rs"[\s\S]*?required-features\s*=\s*\["windows-parent-spoof-contract-test"\]/u.test(
    nativeAssistantManifest,
  )
) {
  failures.push("Cargo.toml helper: fixture hostile parent Windows absente ou non bornée");
}
if (
  !nativeAssistantManifest.includes(
    'windows-live-prompt-contract-test = ["native-prompt-contract-test"]',
  ) ||
  !/\[\[test\]\][\s\S]*?name\s*=\s*"windows-live-prompt-contract"[\s\S]*?path\s*=\s*"tests\/windows_live_prompt_contract\.rs"[\s\S]*?required-features\s*=\s*\["windows-live-prompt-contract-test"\]/u.test(
    nativeAssistantManifest,
  )
) {
  failures.push("Cargo.toml helper: preuve Win32 vivante absente ou non bornée");
}
if (
  !nativeAssistantManifest.includes(
    'delayed-start-contract-test = ["native-prompt-contract-test"]',
  ) ||
  !/\[\[bin\]\][\s\S]*?name\s*=\s*"your-cloud-delayed-start-fixture"[\s\S]*?path\s*=\s*"src\/delayed_start_fixture\.rs"[\s\S]*?required-features\s*=\s*\["delayed-start-contract-test"\]/u.test(
    nativeAssistantManifest,
  ) ||
  !/\[\[test\]\][\s\S]*?name\s*=\s*"delayed-start-contract"[\s\S]*?path\s*=\s*"tests\/delayed_start_contract\.rs"[\s\S]*?required-features\s*=\s*\["delayed-start-contract-test"\]/u.test(
    nativeAssistantManifest,
  )
) {
  failures.push("Cargo.toml helper: preuve delayed-start absente ou non bornée");
}
if (
  !nativeAssistantManifest.includes("windows-agent-pipe-contract-test = []") ||
  !/\[\[bin\]\][\s\S]*?name\s*=\s*"your-cloud-agent-pipe-fixture"[\s\S]*?path\s*=\s*"src\/agent_pipe_fixture\.rs"[\s\S]*?required-features\s*=\s*\["windows-agent-pipe-contract-test"\]/u.test(
    nativeAssistantManifest,
  ) ||
  !/\[\[test\]\][\s\S]*?name\s*=\s*"windows-agent-pipe-contract"[\s\S]*?path\s*=\s*"tests\/windows_agent_pipe_contract\.rs"[\s\S]*?required-features\s*=\s*\["windows-agent-pipe-contract-test"\]/u.test(
    nativeAssistantManifest,
  )
) {
  failures.push("Cargo.toml helper: fixture hostile de pipe agent absente ou non bornée");
}
// L'attestation du serveur de pipe ne vaut que par ce qu'elle interroge : sans
// ces primitives elle retomberait sur une comparaison de nom, que n'importe
// quel processus peut satisfaire en prenant le nom le premier.
for (const expected of [
  '"Win32_Security_Authorization"',
  '"Win32_System_SystemInformation"',
]) {
  if (!nativeAssistantManifest.includes(expected)) {
    failures.push(`Cargo.toml helper: primitive d’attestation du pipe absente (${expected})`);
  }
}
for (const expected of [
  "GetNamedPipeServerProcessId",
  "QueryFullProcessImageNameW",
  "GetFinalPathNameByHandleW",
  "ConvertSidToStringSidW",
  "GetSystemDirectoryW",
  // Le propriétaire de l’objet pipe est le seul fait qu’un compte sans droit
  // administrateur peut lire ; sans lui l’attestation redevient inutilisable
  // pour l’utilisateur normal de `ssh-agent`, donc fermée pour rien.
  "GetSecurityInfo",
  "OWNER_SECURITY_INFORMATION",
  "READ_CONTROL",
]) {
  if (!nativeAssistantAgentPipe.includes(expected)) {
    failures.push(`agent_pipe.rs: attestation du serveur de pipe incomplète (${expected})`);
  }
}
if (
  !nativeAssistantAgentEndpoint.includes('pub const WINDOWS_AGENT_ACCOUNT: &str = "S-1-5-18"') ||
  !nativeAssistantAgentEndpoint.includes(
    'pub const WINDOWS_AGENT_IMAGE: &str = r"OpenSSH\\ssh-agent.exe"',
  ) ||
  !nativeAssistantAgentEndpoint.includes("EndpointRefusal::ForeignPipeOwner") ||
  !nativeAssistantAgentEndpoint.includes("EndpointRefusal::ForeignPipeServer") ||
  !nativeAssistantAgentEndpoint.includes("EndpointRefusal::ForeignServerAccount") ||
  !nativeAssistantAgentEndpoint.includes("EndpointRefusal::ServerNotAttestable")
) {
  failures.push(
    "agent_endpoint.rs: le pipe Windows doit rester jugé sur son serveur, pas sur son nom",
  );
}
// Le propriétaire n’est jamais facultatif : c’est le seul contrôle que tout
// compte peut faire. Le chemin d’image, lui, l’est — Windows ne prête pas de
// descripteur sur un processus `SYSTEM` à un utilisateur ordinaire — et c’est
// cette asymétrie que le type doit porter, sinon elle se perdrait en une
// comparaison de nom déguisée.
if (
  !nativeAssistantAgentEndpoint.includes("pub server_object_owner_sid: &'a str") ||
  !nativeAssistantAgentEndpoint.includes("pub server_process: Option<ObservedServerProcess<'a>>")
) {
  failures.push(
    "agent_endpoint.rs: le propriétaire du pipe doit être obligatoire et le processus facultatif",
  );
}
// Le refus de composer une adresse que le poste détient déjà ne vaut que par
// l’énumération qui l’alimente. Les deux systèmes doivent réellement énumérer :
// une plateforme qui retomberait sur `Unsupported` rendrait tout le transport
// personnel inatteignable, et une plateforme qui rendrait un ensemble vide
// désarmerait le garde sans le dire.
for (const expected of ["getifaddrs", "GetAdaptersAddresses", "IP_ADAPTER_ADDRESSES_LH"]) {
  if (!nativeAssistantLocalAddresses.includes(expected)) {
    failures.push(`local_addresses.rs: énumération réelle absente (${expected})`);
  }
}
if (
  !nativeAssistantLocalAddresses.includes(
    '#[cfg(any(target_os = "linux", target_os = "windows"))]\n    pub fn observe()',
  ) ||
  !nativeAssistantLocalAddresses.includes("LocalAddressRefusal::EnumerationFailed") ||
  !nativeAssistantLocalAddresses.includes("LocalAddressRefusal::NothingObserved")
) {
  failures.push(
    "local_addresses.rs: le témoin doit rester produit par une énumération qui a eu lieu",
  );
}
for (const expected of ['"Win32_NetworkManagement_IpHelper"', '"Win32_Networking_WinSock"']) {
  if (!nativeAssistantManifest.includes(expected)) {
    failures.push(`Cargo.toml helper: primitive d’énumération locale absente (${expected})`);
  }
}
// Le chemin commun est un seul chemin : le module de session est compilé des
// deux côtés, et c’est l’endpoint d’agent — socket ou pipe attesté — qui seul
// diffère.
if (
  !nativeAssistantPersonalAccess.includes(
    '#[cfg(any(target_os = "linux", target_os = "windows"))]\npub mod session;',
  )
) {
  failures.push("personal_access.rs: la session doit être compilée sous Linux comme sous Windows");
}
if (
  !nativeAssistantManifest.includes("windows-personal-transport-contract-test = []") ||
  !/\[\[test\]\][\s\S]*?name\s*=\s*"windows-personal-transport-contract"[\s\S]*?path\s*=\s*"tests\/windows_personal_transport_contract\.rs"[\s\S]*?required-features\s*=\s*\["windows-personal-transport-contract-test"\]/u.test(
    nativeAssistantManifest,
  )
) {
  failures.push("Cargo.toml helper: preuve du transport personnel Windows absente ou non bornée");
}
if (
  !bootstrapProtocol.includes("pub issued_at_monotonic_nanos: u64") ||
  /#\[serde\(default\)\][\s\S]{0,120}issued_at_monotonic_nanos/u.test(bootstrapProtocol) ||
  !bootstrapProtocol.includes('.remove("issued_at_monotonic_nanos")')
) {
  failures.push("bootstrap-protocol: estampille monotone obligatoire absente ou optionnelle");
}
for (const expected of [
  "clock_gettime",
  "CLOCK_MONOTONIC",
  "QueryPerformanceCounter",
  "QueryPerformanceFrequency",
  "u128::try_from(counter)",
  "u128::try_from(frequency)",
  ".checked_mul(NANOS_PER_SECOND)",
  ".checked_div(frequency)",
  "normalized_seconds_nanos(0, 0), Some(0)",
  "normalized_counter_nanos(0, 10), Some(0)",
]) {
  if (!bootstrapProtocolMonotonic.includes(expected)) {
    failures.push(`horloge monotone partagée: garde absente (${expected})`);
  }
}
if (
  !bootstrapProtocolManifest.includes("libc = \"=0.2.183\"") ||
  !bootstrapProtocolManifest.includes('"Win32_System_Performance"') ||
  !/name = "your-cloud-bootstrap-protocol"[\s\S]*?"libc"[\s\S]*?"windows-sys 0\.61\.2"/u.test(
    cargoLock,
  )
) {
  failures.push("horloge monotone partagée: dépendances Linux/Windows ou lock absents");
}
for (const expected of [
  "ProtectedSecret::new()",
  "secret.raw_mut()",
  "std::process::id()",
  "std::ptr::write_volatile",
  "libc::PR_SET_DUMPABLE",
  "libc::PR_SET_PTRACER",
  "libc::PR_GET_DUMPABLE",
  "libc::RLIMIT_CORE",
  "RaiseFailFastException",
  "FAIL_FAST_GENERATE_EXCEPTION_ADDRESS",
  "SEM_NOGPFAULTERRORBOX",
]) {
  if (!nativeAssistantCrashFixture.includes(expected)) {
    failures.push(`fixture crash/dump: protection synthétique absente (${expected})`);
  }
}
for (const expected of [
  "CREATE_DEFAULT_ERROR_MODE",
  'Command::new("gcore")',
  'file_contains(&core_path, &dump_control)',
  'file_contains(&core_path, &protected_canary)',
  "status.core_dumped()",
  "LocalDumps",
  'registration.add_dword("DumpType", "0")',
  'registration.add_dword("CustomDumpFlags", WER_CUSTOM_DUMP_FLAGS)',
  'const WER_CUSTOM_DUMP_FLAGS: &str = "801"',
  'registration.add_dword("DumpCount", "1")',
  'assert_eq!(&signature, b"MDMP"',
  "administrator_local_dump_is_outside_the_wer_exclusion_contract",
  "panic::catch_unwind",
  "protected_canary_present",
  "stable_since",
  "remove_and_prove_absent",
]) {
  if (!nativeAssistantCrashContract.includes(expected)) {
    failures.push(`contrat crash/dump: preuve synthétique absente (${expected})`);
  }
}
if (
  !/assert!\(\s*protected_canary_present\s*,/u.test(nativeAssistantCrashContract) ||
  /assert!\(\s*!\s*protected_canary_present\s*,/u.test(nativeAssistantCrashContract)
) {
  failures.push(
    "contrat crash/dump: la frontière LocalDumps administrateur doit rester une présence explicite du canari",
  );
}
if (!/scratch\s*\.remove_and_prove_absent\(\)/u.test(nativeAssistantCrashContract)) {
  failures.push(
    "contrat crash/dump: le répertoire LocalDumps doit être supprimé et prouvé absent avant verdict",
  );
}
if (/\.arg\(\s*"-a"\s*\)/u.test(nativeAssistantCrashContract)) {
  failures.push("contrat crash/dump: gcore ne doit pas forcer les mappings VM_DONTDUMP");
}
for (const expected of [
  "command.process_group(0);",
  "libc::kill(-process_group, libc::SIGKILL)",
  "libc::kill(-process_group, 0)",
  "Some(libc::ESRCH)",
  "REG_TIMEOUT",
  "try_wait_bounded(REG_TIMEOUT)",
]) {
  if (!nativeAssistantCrashContract.includes(expected)) {
    failures.push(`contrat crash/dump: nettoyage processus borné absent (${expected})`);
  }
}
const boundedRegStart = nativeAssistantCrashContract.indexOf(
  "fn try_run_reg<const N: usize>",
);
const boundedRegBody =
  boundedRegStart >= 0 ? nativeAssistantCrashContract.slice(boundedRegStart) : "";
if (
  !boundedRegBody.includes('Command::new("reg.exe")') ||
  !boundedRegBody.includes(".spawn()?") ||
  !boundedRegBody.includes("GuardedChild::new(child).try_wait_bounded(REG_TIMEOUT)") ||
  /\.(?:status|output)\s*\(/u.test(boundedRegBody)
) {
  failures.push(
    "contrat crash/dump: reg.exe doit rester lancé, attendu et nettoyé avec une borne explicite",
  );
}
if (
  !nativeAssistantParentSpoofFixture.includes("transport_parent_contract_main()") ||
  !nativeAssistantHelperRuntime.includes(
    '#[cfg(feature = "windows-parent-spoof-contract-test")]',
  ) ||
  !nativeAssistantHelperRuntime.includes("pub fn transport_parent_contract_main() -> u8")
) {
  failures.push("fixture parent Windows: entrée transport test-only absente");
}
for (const expected of [
  "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
  "PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
  "DuplicateHandle",
  "duplicate_into_declared_parent",
  "GetNamedPipeClientProcessId",
  "GetCurrentProcessId",
  "observed_parent_pid",
  "EXIT_INTERNAL_FAILURE",
  "stdout_bytes.is_empty()",
  "stderr_bytes.is_empty()",
  "TerminateJobObject",
  "wait_bounded",
]) {
  if (!nativeAssistantParentSpoofContract.includes(expected)) {
    failures.push(`contrat parent Windows hostile: preuve absente (${expected})`);
  }
}
const hostileVerifierExitIndex = nativeAssistantParentSpoofContract.indexOf(
  "process.wait_bounded(CONTRACT_TIMEOUT)",
);
const hostileParentCleanupIndex = nativeAssistantParentSpoofContract.indexOf(
  'job.terminate().expect("cleanup job terminated")',
);
const hostileOutputReadIndex = nativeAssistantParentSpoofContract.indexOf(
  "stdout.read_to_end(&mut stdout_bytes)",
);
if (
  hostileVerifierExitIndex < 0 ||
  hostileParentCleanupIndex < 0 ||
  hostileOutputReadIndex < 0 ||
  !(hostileVerifierExitIndex < hostileParentCleanupIndex &&
    hostileParentCleanupIndex < hostileOutputReadIndex)
) {
  failures.push(
    "contrat parent Windows hostile: C doit terminer puis A être fermé avant la lecture des pipes",
  );
}
for (const expected of [
  'Command::new("xdotool")',
  '"--sync"',
  '"--onlyvisible"',
  '"--pid"',
  '"getwindowpid"',
  "collect_output_bounded(search.spawn()?, timeout)?",
  "collect_output_bounded(owner.spawn()?, timeout)?",
  "observed_process_id != child.id()",
  "terminate_and_reap_bounded",
  "child.try_wait()?",
  "child.kill()",
  "libc::O_NONBLOCK",
  "PIPE_EOF_TIMEOUT",
  "MAX_CAPTURED_OUTPUT",
]) {
  if (!nativeAssistantLinuxProcessContract.includes(expected)) {
    failures.push(`contrat prompt GTK vivant: preuve bornée absente (${expected})`);
  }
}
if (
  /\.(?:wait_with_output|wait|output)\s*\(/u.test(nativeAssistantLinuxProcessContract) ||
  nativeAssistantLinuxProcessContract.includes("thread::sleep(Duration::from_millis(250))")
) {
  failures.push(
    "contrat prompt GTK vivant: attente implicite ou oracle temporel non borné présent",
  );
}
const linuxLivePromptStart = nativeAssistantLinuxProcessContract.indexOf(
  "fn live_prompt_refuses_target_step_action_and_expiration_mutations()",
);
const linuxLivePromptEnd = nativeAssistantLinuxProcessContract.indexOf(
  "fn mutation_frame",
  linuxLivePromptStart,
);
const linuxLivePromptBody =
  linuxLivePromptStart >= 0 && linuxLivePromptEnd > linuxLivePromptStart
    ? nativeAssistantLinuxProcessContract.slice(linuxLivePromptStart, linuxLivePromptEnd)
    : "";
const linuxLivePromptOrder = [
  "for mutation_kind in [",
  "let initial = scope(INITIAL_REMAINING_MILLIS)",
  ".write_all(&frame(&initial))",
  "wait_for_visible_x11_window(&mut child, WINDOW_TIMEOUT)",
  ".write_all(&mutation)",
  "collect_output_bounded(child, PROCESS_TIMEOUT)",
].map((fragment) => linuxLivePromptBody.indexOf(fragment));
if (
  linuxLivePromptOrder.some((index) => index < 0) ||
  linuxLivePromptOrder.some(
    (index, position) => position > 0 && index <= linuxLivePromptOrder[position - 1],
  )
) {
  failures.push(
    "contrat prompt GTK vivant: scope fraîche, fenêtre, mutation, attente et sorties doivent rester ordonnées",
  );
}
for (const expected of [
  "wait_for_prompt_window(process_id, WINDOW_TIMEOUT)",
  "EnumWindows",
  "GetWindowThreadProcessId",
  "IsWindowVisible",
  "GetClassNameW",
  "DIALOG_CLASS_NAME",
  "const ALL: [Self; 4] = [Self::Target, Self::Step, Self::Action, Self::Expiration]",
  '.target.host = "other-controller.example.test"',
  "step.step = BootstrapStep::UnlockPersonalKey",
  'action["actions"] = serde_json::json!(["install_controller"])',
  "expiration.remaining_millis = INITIAL_REMAINING_MILLIS - 1_000",
  "EXIT_PROTOCOL_REFUSED",
  "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
  "TerminateJobObject",
  "wait_bounded",
  "terminate_and_reap",
  "stdout_bytes.is_empty()",
  "stderr_bytes.is_empty()",
]) {
  if (!nativeAssistantWindowsLivePromptContract.includes(expected)) {
    failures.push(`contrat prompt Win32 vivant: preuve absente (${expected})`);
  }
}
const windowsLivePromptStart = nativeAssistantWindowsLivePromptContract.indexOf(
  "fn live_prompt_refuses_target_step_action_and_expiration_mutations()",
);
const windowsLivePromptEnd = nativeAssistantWindowsLivePromptContract.indexOf(
  "struct Mutation",
  windowsLivePromptStart,
);
const windowsLivePromptBody =
  windowsLivePromptStart >= 0 && windowsLivePromptEnd > windowsLivePromptStart
    ? nativeAssistantWindowsLivePromptContract.slice(
        windowsLivePromptStart,
        windowsLivePromptEnd,
      )
    : "";
const windowsLivePromptOrder = [
  "for mutation_kind in MutationKind::ALL",
  "let initial_scope = scope(INITIAL_REMAINING_MILLIS)",
  "let initial_frame = frame(&initial_scope)",
  "let mutation = mutation_kind.derive_from(&initial_scope)",
  ".write_all(&initial_frame)",
  "wait_for_prompt_window(process_id, WINDOW_TIMEOUT)",
  ".write_all(&mutation.frame)",
  "process.wait_bounded(PROCESS_TIMEOUT)",
  "process.read_output()",
].map((fragment) => windowsLivePromptBody.indexOf(fragment));
if (
  windowsLivePromptBody.length === 0 ||
  windowsLivePromptOrder.some((index) => index < 0) ||
  windowsLivePromptOrder.some(
    (index, position) => position > 0 && index <= windowsLivePromptOrder[position - 1],
  )
) {
  failures.push(
    "contrat prompt Win32 vivant: scope fraîche, frame, mutation dérivée, HWND, attente et sorties doivent rester ordonnés",
  );
}
// Le cas homologue de l'accès personnel. Sans cet ordre, une régression pourrait
// envoyer la mutation avant que la fenêtre existe : le helper la refuserait pour
// n'avoir pas encore ouvert de dialogue, et le cas passerait au vert pour la
// mauvaise raison. Le corps est découpé sur l'accolade fermante de la fonction
// elle-même — la première en colonne zéro, les fermetures internes étant toutes
// indentées — et non sur l'élément suivant : rien de ce qui vient après ne peut
// donc satisfaire un fragment que le cas aurait perdu. Ce découpage n'exige la
// présence d'aucune aide dans ce fichier, donc il n'interdit pas de les
// partager avec l'autre suite.
const personalAccessLivePromptStart = nativeAssistantPersonalAccessContract.indexOf(
  "fn a_live_personal_access_window_refuses_target_step_action_and_expiration_mutations()",
);
const personalAccessLivePromptEnd =
  personalAccessLivePromptStart < 0
    ? -1
    : nativeAssistantPersonalAccessContract.indexOf("\n}\n", personalAccessLivePromptStart);
const personalAccessLivePromptBody =
  personalAccessLivePromptStart >= 0 &&
  personalAccessLivePromptEnd > personalAccessLivePromptStart
    ? nativeAssistantPersonalAccessContract.slice(
        personalAccessLivePromptStart,
        personalAccessLivePromptEnd,
      )
    : "";
const personalAccessLivePromptOrder = [
  "for mutation_kind in MutationKind::ALL",
  "let initial = direct_personal_access_scope(LIVE_WINDOW_LEASE_MILLIS)",
  "let mutation = mutation_frame(&initial, mutation_kind)",
  ".write_all(&scope_frame(&initial))",
  "await_live_window_of(&mut child, WINDOW_TIMEOUT)",
  "PERSONAL_ACCESS_TITLE",
  ".write_all(&mutation)",
  "collect_output_bounded(child, PROCESS_TIMEOUT)",
  "output.status.code()",
  "output.stdout.is_empty()",
  "output.stderr.is_empty()",
].map((fragment) => personalAccessLivePromptBody.indexOf(fragment));
if (
  personalAccessLivePromptBody.length === 0 ||
  personalAccessLivePromptOrder.some((index) => index < 0) ||
  personalAccessLivePromptOrder.some(
    (index, position) => position > 0 && index <= personalAccessLivePromptOrder[position - 1],
  )
) {
  failures.push(
    "contrat fenêtre d'accès personnel vivante: scope fraîche, fenêtre observée vivante et titrée, mutation, attente bornée et sorties doivent rester ordonnées",
  );
}
for (const expected of [
  "READY_PATH_ENV",
  "RELEASE_PATH_ENV",
  "MAX_FIXTURE_WAIT",
  ".create_new(true)",
  "release_path.try_exists()",
  "process_main()",
]) {
  if (!nativeAssistantDelayedStartFixture.includes(expected)) {
    failures.push(`fixture delayed-start: synchronisation bornée absente (${expected})`);
  }
}
const delayedFixtureOrder = [
  ".create_new(true)",
  "release_path.try_exists()",
  "process_main()",
].map((fragment) => nativeAssistantDelayedStartFixture.indexOf(fragment));
if (
  delayedFixtureOrder.some((index) => index < 0) ||
  delayedFixtureOrder.some(
    (index, position) => position > 0 && index <= delayedFixtureOrder[position - 1],
  )
) {
  failures.push(
    "fixture delayed-start: ready, attente de release et process_main doivent rester ordonnés",
  );
}
for (const expected of [
  "monotonic_nanos()",
  "UnixStream::pair()",
  "GetNamedPipeClientProcessId",
  "GetCurrentProcessId",
  ".process_group(0)",
  "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
  "TerminateJobObject",
  "terminate_and_reap",
  "wait_bounded",
  "EXIT_WATCHDOG_EXPIRED",
  "AssistantEventKind::Expired",
  "stderr_bytes.is_empty()",
]) {
  if (!nativeAssistantDelayedStartContract.includes(expected)) {
    failures.push(`contrat delayed-start: preuve processus absente (${expected})`);
  }
}
const delayedContractOrder = [
  ".write_all(&frame(&scope(issued_at_monotonic_nanos)))",
  "wait_for_path(&synchronization.ready, READY_TIMEOUT)",
  "process.is_running()",
  "wait_until_monotonic(",
  "synchronization.release()",
  "process.wait_bounded(POST_RELEASE_TIMEOUT)",
  "process.read_output()",
].map((fragment) => nativeAssistantDelayedStartContract.indexOf(fragment));
if (
  delayedContractOrder.some((index) => index < 0) ||
  delayedContractOrder.some(
    (index, position) => position > 0 && index <= delayedContractOrder[position - 1],
  )
) {
  failures.push(
    "contrat delayed-start: frame, blocage, dépassement TTL, release et événement doivent rester ordonnés",
  );
}
for (const shippingSource of [nativeAssistantHelperRuntime, nativeAssistantBuild]) {
  if (
    shippingSource.includes("YOUR_CLOUD_DELAYED_START_READY_PATH") ||
    shippingSource.includes("YOUR_CLOUD_DELAYED_START_RELEASE_PATH")
  ) {
    failures.push("contrat delayed-start: la synchronisation de fixture entre dans le runtime livré");
  }
}
const transportFixtureEntryStart = nativeAssistantHelperRuntime.indexOf(
  "pub fn transport_parent_contract_main() -> u8",
);
const processMainStart = nativeAssistantHelperRuntime.indexOf("pub fn process_main() -> u8");
if (transportFixtureEntryStart < 0 || processMainStart <= transportFixtureEntryStart) {
  failures.push("lib.rs helper: entrée fixture transport ou process_main introuvable");
} else {
  const transportFixtureEntry = nativeAssistantHelperRuntime.slice(
    transportFixtureEntryStart,
    processMainStart,
  );
  if (
    !transportFixtureEntry.includes("UnbufferedStandardInput::open()") ||
    !transportFixtureEntry.includes("parent::verify(&stdin)") ||
    /framing::read_scope|show_prompt|Watchdog::start_at/u.test(transportFixtureEntry)
  ) {
    failures.push(
      "lib.rs helper: la fixture transport doit seulement ouvrir stdin et attester son parent",
    );
  }
}
const processMainEnd = nativeAssistantHelperRuntime.indexOf("\nfn valid_arguments", processMainStart);
const processMainBody =
  processMainStart >= 0 && processMainEnd > processMainStart
    ? nativeAssistantHelperRuntime.slice(processMainStart, processMainEnd)
    : "";
const processMainOrder = [
  "let session_started_at = Instant::now();",
  "hardening::apply()",
  "Watchdog::start_at(session_started_at)",
  "UnbufferedStandardInput::open()",
  "parent::verify(&stdin)",
  "framing::read_scope(&mut stdin)",
].map((fragment) => processMainBody.indexOf(fragment));
if (
  processMainBody.length === 0 ||
  processMainOrder.some((index) => index < 0) ||
  processMainOrder.some((index, position) => position > 0 && index <= processMainOrder[position - 1])
) {
  failures.push(
    "lib.rs helper: origine TTL, hardening, watchdog, transport, parent et scope sont mal ordonnés",
  );
}
const parentStampIndices = [
  ...nativeAssistantRuntime.matchAll(/scope\.issued_at_monotonic_nanos\s*=/gu),
].map((match) => match.index);
const parentRemainingIndices = [
  ...nativeAssistantRuntime.matchAll(
    /scope\.remaining_millis\s*=\s*remaining_millis\(expires_at, Instant::now\(\)\)\?;/gu,
  ),
].map((match) => match.index);
const encodedScopeIndex = nativeAssistantRuntime.indexOf("let frame = encode_scope(&scope)?;");
const writtenScopeIndex = nativeAssistantRuntime.indexOf(".write_all(&frame)", encodedScopeIndex);
if (
  parentStampIndices.length !== 2 ||
  parentRemainingIndices.length !== 2 ||
  parentStampIndices.some((stampIndex, position) => {
    const remainingIndex = parentRemainingIndices[position];
    const pair = nativeAssistantRuntime.slice(stampIndex, remainingIndex);
    return stampIndex >= remainingIndex || !pair.includes("monotonic_nanos()");
  }) ||
  encodedScopeIndex <= parentRemainingIndices[1] ||
  writtenScopeIndex <= encodedScopeIndex
) {
  failures.push(
    "native_assistant.rs: chaque remaining doit être précédé de son estampille OS, dont la paire finale avant encodage et écriture",
  );
}
const serveScopeStart = nativeAssistantHelperRuntime.indexOf("fn serve_scope(");
const serveScopeEnd = nativeAssistantHelperRuntime.indexOf(
  "\nfn terminal_from_prompt",
  serveScopeStart,
);
const serveScopeBody =
  serveScopeStart >= 0 && serveScopeEnd > serveScopeStart
    ? nativeAssistantHelperRuntime.slice(serveScopeStart, serveScopeEnd)
    : "";
const overriddenSecretDropIndex = serveScopeBody.indexOf("drop(outcome);");
const overriddenTerminalWriteIndex = serveScopeBody.lastIndexOf(
  "write_terminal(writer, &scope, terminal)",
);
if (
  serveScopeBody.length === 0 ||
  !serveScopeBody.includes("Some(SessionTerminal::Expired)") ||
  !serveScopeBody.includes("Some(SessionTerminal::Cancelled)") ||
  overriddenSecretDropIndex < 0 ||
  overriddenTerminalWriteIndex <= overriddenSecretDropIndex
) {
  failures.push(
    "lib.rs helper: un secret supplanté par expiration ou annulation doit être détruit avant la frame terminale",
  );
}
const helperTtlOrder = [
  "let local_before = Instant::now();",
  "let observed_at_monotonic_nanos = monotonic_nanos()",
  "deadline_from_observation(",
  "watchdog\n        .tighten_to(deadline)",
  "return write_terminal(writer, &scope, SessionTerminal::Expired);",
  "let outcome = show_prompt(",
].map((fragment) => serveScopeBody.indexOf(fragment));
if (
  helperTtlOrder.some((index) => index < 0) ||
  helperTtlOrder.some(
    (index, position) => position > 0 && index <= helperTtlOrder[position - 1],
  )
) {
  failures.push(
    "lib.rs helper: observation locale/OS, reliquat, watchdog, expiration et prompt sont mal ordonnés",
  );
}
const deadlineObservationStart = nativeAssistantHelperRuntime.indexOf(
  "fn deadline_from_observation(",
);
const deadlineObservationEnd = nativeAssistantHelperRuntime.indexOf(
  "\nfn map_read_error",
  deadlineObservationStart,
);
const deadlineObservationBody =
  deadlineObservationStart >= 0 && deadlineObservationEnd > deadlineObservationStart
    ? nativeAssistantHelperRuntime.slice(deadlineObservationStart, deadlineObservationEnd)
    : "";
for (const expected of [
  "observed_at_monotonic_nanos.checked_sub(issued_at_monotonic_nanos)?",
  "remaining_millis.checked_mul(1_000_000)?",
  "transmitted_nanos.saturating_sub(elapsed_nanos)",
  "local_before.checked_add(Duration::from_nanos(remaining_nanos))",
]) {
  if (!deadlineObservationBody.includes(expected)) {
    failures.push(`lib.rs helper: calcul TTL hostile absent (${expected})`);
  }
}
for (const expected of [
  "a future parent stamp must fail closed",
  "millisecond-to-nanosecond overflow must fail closed",
]) {
  if (!nativeAssistantHelperRuntime.includes(expected)) {
    failures.push(`lib.rs helper: test TTL hostile absent (${expected})`);
  }
}
if (
  !serveScopeBody.includes("monotonic_nanos().map_err(|_| SessionError::Internal)?") ||
  !serveScopeBody.includes(".ok_or(SessionError::Protocol)?")
) {
  failures.push("lib.rs helper: erreur horloge, futur ou overflow doivent échouer fermés");
}
const delayedPromptOverrideStart = nativeAssistantHelperRuntime.indexOf(
  '#[cfg(feature = "delayed-start-contract-test")]',
);
const linuxPromptStart = nativeAssistantHelperRuntime.indexOf(
  '#[cfg(all(not(feature = "delayed-start-contract-test"), target_os = "linux"))]',
  delayedPromptOverrideStart,
);
const delayedPromptOverride =
  delayedPromptOverrideStart >= 0 && linuxPromptStart > delayedPromptOverrideStart
    ? nativeAssistantHelperRuntime.slice(delayedPromptOverrideStart, linuxPromptStart)
    : "";
if (
  !delayedPromptOverride.includes("fn show_prompt(") ||
  !delayedPromptOverride.includes("PromptOutcome::Unavailable") ||
  /native_prompt(?:_windows)?::prompt/u.test(delayedPromptOverride) ||
  !nativeAssistantHelperRuntime.includes(
    '#[cfg(all(not(feature = "delayed-start-contract-test"), target_os = "windows"))]',
  )
) {
  failures.push(
    "lib.rs helper: la preuve delayed-start doit distinguer la frontière prompt par Unavailable",
  );
}
const watchdogStartAtStart = nativeAssistantWatchdog.indexOf(
  "pub(crate) fn start_at(session_started_at: Instant)",
);
const watchdogStartAtEnd = nativeAssistantWatchdog.indexOf(
  "\n    pub(crate) fn tighten_to",
  watchdogStartAtStart,
);
const watchdogStartAtBody =
  watchdogStartAtStart >= 0 && watchdogStartAtEnd > watchdogStartAtStart
    ? nativeAssistantWatchdog.slice(watchdogStartAtStart, watchdogStartAtEnd)
    : "";
if (
  !watchdogStartAtBody.includes("let deadline = session_started_at") ||
  !watchdogStartAtBody.includes(
    ".checked_add(Duration::from_millis(MAX_ASSISTANT_REMAINING_MILLIS))",
  ) ||
  !watchdogStartAtBody.includes(".spawn(move || run(receiver, deadline, worker_expired))") ||
  watchdogStartAtBody.includes("Instant::now()")
) {
  failures.push("watchdog.rs: la borne maximale doit dériver sans renouvellement de l’origine TTL");
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
  [nativeAssistantBuild, '"--no-default-features"'],
  [nativeAssistantBuild, '"--locked"'],
  [nativeAssistantBuild, '"--offline"'],
  [nativeAssistantGate, '"x86_64-unknown-linux-gnu"'],
  [nativeAssistantGate, '"x86_64-pc-windows-msvc"'],
  [nativeAssistantGate, '"readelf"'],
  [nativeAssistantGate, '"--no-default-features"'],
  [nativeAssistantGate, "inspectPortableExecutable"],
  [nativeAssistantGate, 'format: "PE32+"'],
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
  'step: "personal_access" | "root_access";',
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
} else if (/\b\w*approv\w*\b/iu.test(invokeHandler)) {
  failures.push("lib.rs: une commande d’approbation est exposée sans sa fenêtre de confirmation");
}

// Ce qui est géré, ce qui est externe, ce qui est ancien.
//
// Un élément externe est une chose que ce produit n'a pas posée : la Console la
// montre, ne la gère pas, et le dit. Les gardes qui suivent tiennent les quatre
// propriétés dont dépend cette phrase — le vocabulaire fermé de l'état, les
// quatre absences sues et non lues, l'inertie de tout octet venu d'un tiers, et
// le fait qu'un retrait ne retire que la déclaration.
const externalWireFields =
  "element_id,machine_id,label,kind,probe_port,declared_at,state,reason,observed_at,observation_status";
const externalElementView = networkRuntime.match(
  /#\[serde\(deny_unknown_fields\)\]\npub\(crate\) struct ExternalElementView \{(?<body>[\s\S]*?)\n\}/u,
)?.groups?.body;
if (!externalElementView) {
  failures.push("network.rs: la vue d’un élément externe est absente ou ouverte aux champs inconnus");
} else {
  const wireFields = [...externalElementView.matchAll(/^\s+pub (\w+):/gmu)].map((match) => match[1]);
  if (wireFields.join(",") !== externalWireFields) {
    failures.push("network.rs: ExternalElementView doit rester le schéma positif exact du fil");
  }
}
for (const view of ["ExternalElementsView", "ExternalElementView", "ExternalWithdrawalView"]) {
  if (
    !new RegExp(`#\\[serde\\(deny_unknown_fields\\)\\]\\npub\\(crate\\) struct ${view} \\{`, "u").test(
      networkRuntime,
    )
  ) {
    failures.push(`network.rs: la vue externe ${view} accepterait un champ inconnu`);
  }
}
// Aucune capacité ne traverse le fil : les quatre absences sont des propriétés
// de ce qu'est un élément externe, et une Console qui les lirait offrirait une
// action de gestion le jour où un Controller compromis dirait oui.
const externalWireStructs = ["ExternalElementsView", "ExternalElementView", "ExternalWithdrawalView"]
  .map(
    (view) =>
      networkRuntime.match(
        new RegExp(`pub\\(crate\\) struct ${view} \\{(?<body>[\\s\\S]*?)\\n\\}`, "u"),
      )?.groups?.body ?? "",
  )
  .join("\n");
for (const [name, source] of [
  ["network.rs", externalWireStructs],
  ["models.ts", productModels],
]) {
  if (/\b(?:can_update|can_restore|can_delete|can_guarantee|guaranteed|capabilit\w*)\b/iu.test(source)) {
    failures.push(`${name}: une capacité d’élément externe traverse le fil`);
  }
}
// Un mot que cette Console ne connaît pas est un refus, jamais un rendu de
// repli : l'état et le motif sont des listes fermées, la date accompagne tout
// constat, et l'ancienneté reste une dimension séparée de l'état. La garde est
// lue hors des tests, sinon un vocabulaire disparu du décodage passerait encore
// pour être cité par la preuve qui devait le tenir.
const externalContract = networkRuntime.replace(/#\[cfg\(test\)\][\s\S]*$/u, "");
for (const bound of [
  "fn validate_external_elements(",
  "view.elements.len() > MAX_EXTERNAL_ELEMENTS",
  "fn validate_external_element(element: &ExternalElementView) -> Result<(), NetworkError> {",
  '("declared" | "verified" | "contradicted", None)',
  '"nothing_listening"',
  '"response_too_large"',
  '"machine_unreachable"',
  '"port_is_managed"',
  "let read = element.state != \"declared\";",
  "read != element.observed_at.is_some()",
  '(false, "absent") | (true, "recent") | (true, "old")',
  "fn valid_external_label(value: &str) -> bool {",
  "(1..=MAX_EXTERNAL_LABEL_BYTES).contains(&value.len())",
  "value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))",
]) {
  if (!externalContract.includes(bound)) {
    failures.push(`network.rs: garde de l’inventaire déclaré absente (${bound})`);
  }
}
// Le corpus hostile est exécuté là où le refus vit. Un libellé de balisage est
// un libellé légitime — c'est à l'affichage qu'il devient inerte — tandis qu'un
// renversement du sens de lecture, un octet de contrôle ou un octet de trop ne
// peuvent pas être un libellé du tout.
for (const expected of [
  "fn external_labels_are_bytes_and_never_the_managed_profile()",
  'valid_external_label("<script>alert(\\"x\\")</script>")',
  'valid_external_label("facture\\u{202e}exe.gnp")',
  'valid_external_label("vault\\u{7}rouge")',
  'valid_external_label("vault\\u{1b}[31mrouge")',
  'valid_external_label(&"<".repeat(MAX_EXTERNAL_LABEL_BYTES))',
  '&"<".repeat(MAX_EXTERNAL_LABEL_BYTES + 1)',
  "fn external_readings_refuse_a_word_this_console_does_not_know()",
  "fn a_capability_on_the_wire_is_an_unknown_field()",
]) {
  if (!networkRuntime.includes(expected)) {
    failures.push(`network.rs: preuve hostile de l’inventaire déclaré absente (${expected})`);
  }
}
// Le retrait est un POST sur sa propre route, et le chemin d'un élément n'existe
// sous aucune méthode : le produit ne possède rien ici, donc il n'a aucune
// ressource à supprimer.
if (!networkRuntime.includes("/v0/external-element-withdrawals")) {
  failures.push("network.rs: le retrait n’emprunte plus sa route nommée");
}
if (networkRuntime.includes("/v0/external-elements/")) {
  failures.push("network.rs: le chemin d’un élément déclaré ne doit exister sous aucune méthode");
}
if (/"DELETE"[\s\S]{0,240}?external/u.test(networkRuntime)) {
  failures.push("network.rs: aucun DELETE ne vise l’inventaire déclaré");
}
const externalCommands = [
  ...consoleRuntime.matchAll(/#\[tauri::command\]\nfn (?<name>\w*external\w*)\(/gu),
].map((match) => match.groups.name);
if (externalCommands.join(",") !== "read_external_elements,withdraw_external_element") {
  failures.push(
    `lib.rs: les seuls actes offerts sur une déclaration sont la lire et la retirer (${externalCommands.join(",")})`,
  );
}
for (const command of ["read_external_elements", "withdraw_external_element"]) {
  if (!nativeOperations.includes(`"${command}"`) || !consoleRuntime.includes(command)) {
    failures.push(`IPC externe: commande nommée absente (${command})`);
  }
}
// Le type dit ce que le contrat dit : « déclaré » est l'état d'un élément que
// personne n'a lu, donc il n'a ni date ni ancienneté ; un invérifiable nomme
// toujours son motif ; et le mot d'ancienneté est celui de l'inventaire géré,
// pour qu'« ancien » n'ait qu'un seul sens sur un même écran.
for (const expected of [
  'export type ExternalState = "declared" | "verified" | "contradicted" | "unverifiable";',
  'export type ExternalReason =\n  | "nothing_listening"\n  | "response_too_large"\n  | "machine_unreachable"\n  | "port_is_managed";',
  'export type ExternalObservationStatus = Exclude<ObservationStatus, "untrusted" | null>;',
  '      state: Extract<ExternalState, "declared">;\n      reason: null;\n      observed_at: null;\n      observation_status: Extract<ExternalObservationStatus, "absent">;',
  '      state: Extract<ExternalState, "verified" | "contradicted">;\n      reason: null;\n      observed_at: string;',
  '      state: Extract<ExternalState, "unverifiable">;\n      reason: ExternalReason;\n      observed_at: string;',
]) {
  if (!productModels.includes(expected)) {
    failures.push(`models.ts: contrat d’élément externe manquant (${expected.split("\n")[0]})`);
  }
}
// Les quatre absences sont annoncées mot pour mot depuis le contexte de la
// route, et elles ne peuvent pas venir d'ailleurs : rien ne les projette.
for (const absence of [
  '{ capability: "Mettre à jour", refusal: "non — aucun plan ne décrit cet élément" },',
  '{ capability: "Restaurer", refusal: "non — le produit ne détient aucune de ses données" },',
  '{ capability: "Supprimer", refusal: "non — retirer la déclaration ne retire pas la chose" },',
  '{ capability: "Garantir l’état", refusal: "non — seule une lecture datée est offerte" },',
]) {
  if (!infrastructureViews.includes(absence)) {
    failures.push(`infrastructure-views.tsx: absence annoncée manquante (${absence})`);
  }
}
const externalViewStart = infrastructureViews.indexOf("export function ExternalView(");
const externalViewEnd = infrastructureViews.indexOf("function PageHeader(");
const externalRegion =
  externalViewStart >= 0 && externalViewStart < externalViewEnd
    ? infrastructureViews.slice(externalViewStart, externalViewEnd)
    : "";
const externalProse = externalRegion.replace(/\s+/gu, " ");
if (!externalRegion) {
  failures.push("infrastructure-views.tsx: la vue des éléments externes est introuvable");
}
// Aucune action de gestion n'est offerte pour un élément externe. Le seul acte
// que cette vue propose porte sur la déclaration, jamais sur la chose.
const externalActions = [
  ...externalRegion.matchAll(/<Button[^>]*>(?<label>[\s\S]*?)<\/Button>/gu),
].map((match) => match.groups.label.trim());
if (
  externalActions.length === 0 ||
  externalActions.some(
    (label) => !["Retirer la déclaration", "Conserver la déclaration"].includes(label),
  )
) {
  failures.push(
    `infrastructure-views.tsx: un élément externe ne doit offrir aucune action de gestion (${externalActions.join("|")})`,
  );
}
// Chaque motif d'invérifiable a sa propre phrase, et ce sont bien quatre
// phrases : « rien n'écoute » et « la machine n'est pas joignable » sont des
// faits différents, et un rendu qui les confondrait passerait une garde de
// simple présence.
const externalReasonSentences = [
  "nothing_listening",
  "response_too_large",
  "machine_unreachable",
  "port_is_managed",
].map(
  (reason) =>
    externalRegion.match(new RegExp(`case "${reason}":\\n\\s+return "(?<sentence>[^"]+)";`, "u"))
      ?.groups?.sentence,
);
if (
  externalReasonSentences.some((sentence) => !sentence) ||
  new Set(externalReasonSentences).size !== 4
) {
  failures.push("infrastructure-views.tsx: chaque motif d’invérifiable doit avoir sa propre phrase");
}
if (
  !externalReasonSentences[3]?.includes("ce port est tenu par un service que ce produit gère")
) {
  failures.push("infrastructure-views.tsx: le port déjà géré doit dire pourquoi rien ne s’y connecte");
}
// « Contredit » veut dire ce que le contrat lui fait dire : un port qui
// répondait n'accepte plus. Jamais que la chose aurait disparu.
if (
  !externalProse.includes(
    "Contredit : le port qu’une lecture datée avait trouvé répondant n’accepte plus aucune connexion.",
  )
) {
  failures.push("infrastructure-views.tsx: « contredit » ne dit plus ce que le contrat lui fait dire");
}
if (/(?:le service|la chose|l’élément|il)\s+(?:a disparu|n’existe plus|est supprimé|est parti)/iu.test(
  infrastructureViews,
)) {
  failures.push("infrastructure-views.tsx: « contredit » ne doit jamais dire que la chose a disparu");
}
// Un constat vérifié dépassé continue de dire vérifié et cesse d'être présenté
// comme actuel, et le retrait dit en propres termes ce qu'il ne retire pas.
if (
  !externalProse.includes(
    "Il reste vérifié à sa date et cesse d’être présenté comme actuel.",
  ) ||
  !externalProse.includes(
    "Le retrait retire la déclaration, et rien d’autre : la chose déclarée continue d’exister",
  )
) {
  failures.push(
    "infrastructure-views.tsx: l’ancienneté d’un constat ou la portée d’un retrait n’est plus dite",
  );
}
// Le libellé est la parole d'un tiers : il n'est rendu que comme du texte,
// jamais dans un attribut, et son cadre est ce qui l'empêche d'élargir la page.
if (!externalRegion.includes("{element.label}")) {
  failures.push("infrastructure-views.tsx: le libellé déclaré n’est plus affiché comme du texte");
}
if (/(?:href|src|style|title|alt|dangerouslySetInnerHTML)=\{[^}]*element\.label/u.test(
  externalRegion,
)) {
  failures.push("infrastructure-views.tsx: le libellé déclaré atteint un attribut actif");
}
const externalLabelFrame = productScreens.match(
  /\.yc-external__label,\n\.yc-external__origin \{(?<body>[\s\S]*?)\n\}/u,
)?.groups?.body;
if (
  !externalLabelFrame ||
  !["max-width: 100%;", "overflow-wrap: anywhere;", "unicode-bidi: isolate;"].every((bound) =>
    externalLabelFrame.includes(bound),
  )
) {
  failures.push("screens.css: le cadre inerte du libellé déclaré n’est plus borné ni isolé");
}
// L'âge affiché est celui que le Controller a calculé contre l'unique limite
// annoncée : la Console n'a pas d'horloge d'autorité et n'en invente pas une.
if (/Date\.now\(\)|new Date\(/u.test(infrastructureViews)) {
  failures.push("infrastructure-views.tsx: l’ancienneté doit rester celle que le Controller calcule");
}

// L’approbation humaine ne doit jamais devenir un oracle de signature. La seule
// entrée décrit une approbation par ses champs typés ; elle ne reçoit ni octets
// à signer, ni transcription déjà construite, ni privilège choisi par l’appelant.
if (
  !approvalRuntime.includes("pub fn sign_approval(") ||
  !approvalRuntime.includes("association: &AssociationRecord,") ||
  !approvalRuntime.includes("request: ApprovalRequest<'_>,") ||
  !approvalRuntime.includes(
    "infrastructure_id: association.summary.infrastructure_id.clone(),",
  ) ||
  !approvalRuntime.includes("privileges: request.operation.required_privileges().to_vec(),") ||
  !approvalRuntime.includes("plan_sha256: hex::encode(Sha256::digest(request.plan)),") ||
  !approvalRuntime.includes(
    "rollback_sha256: hex::encode(Sha256::digest(request.rollback)),",
  )
) {
  failures.push("approval.rs: l’unique signature n’est plus dérivée d’une demande typée");
}
if (/fn\s+\w*sign\w*\s*(?:<[^>]*>)?\s*\([^)]*(?:&\[u8\]|Vec<u8>|transcript|digest)/u.test(
  approvalRuntime.replace(/\n/gu, " "),
)) {
  failures.push("approval.rs: une primitive de signature libre est exposée");
}
if (
  !/pub\s+struct\s+ApprovalRequest<'a>\s*\{[\s\S]*?\n\}/u
    .exec(approvalRuntime)?.[0]
    ?.includes("operation: ApprovalOperation") ||
  /pub\s+struct\s+ApprovalRequest<'a>\s*\{[\s\S]*?\n\}/u
    .exec(approvalRuntime)?.[0]
    ?.match(/\b(privileges|infrastructure_id|approval_public_key|signature|transcript)\b/u)
) {
  failures.push("approval.rs: la demande d’approbation laisse choisir un champ dérivé");
}

// L’enveloppe canonique lie tout ce qu’une approbation signifie. Chaque champ
// est écrit sous sa propre longueur, dans cet ordre exact, et le côté Auxiliaire
// écrit la même table dans internal/approval/envelope.go.
for (const bound of [
  'pub const APPROVAL_TRANSCRIPT_DOMAIN: &[u8] = b"your-cloud/approval-envelope.v1\\0";',
  "append_field(&mut transcript, self.infrastructure_id.as_bytes())?;",
  "append_field(&mut transcript, self.machine_id.as_bytes())?;",
  "transcript.extend_from_slice(&self.approval_epoch.to_be_bytes());",
  "transcript.extend_from_slice(&self.sequence.to_be_bytes());",
  "append_field(&mut transcript, self.operation.as_str().as_bytes())?;",
  "append_field(&mut transcript, &plan)?;",
  "append_field(&mut transcript, &rollback)?;",
  "append_field(&mut transcript, privilege.as_str().as_bytes())?;",
  "transcript.extend_from_slice(&self.issued_at_unix_seconds.to_be_bytes());",
  "transcript.extend_from_slice(&self.expires_at_unix_seconds.to_be_bytes());",
  "append_field(&mut transcript, &public_key)?;",
  "self.privileges != self.operation.required_privileges()",
]) {
  if (!approvalProtocol.includes(bound)) {
    failures.push(`approval.rs (protocole): lien signé absent (${bound})`);
  }
}
// Le protocole partagé construit des octets et ne signe jamais : il n’a ni
// primitive, ni type de clé, ni dépendance de signature. Une transcription est
// sans valeur pour qui ne peut pas la signer, et c’est ce qui autorise ce
// contrat à être public des deux côtés.
for (const forbidden of ["SigningKey", "signing_key", "private_key", "secret", "Signer"]) {
  if (approvalProtocol.includes(forbidden)) {
    failures.push(`approval.rs (protocole): une notion de clé privée y apparaît (${forbidden})`);
  }
}
for (const forbidden of ["ed25519", "signature ="]) {
  if (bootstrapProtocolManifest.includes(forbidden)) {
    failures.push(`bootstrap-protocol: dépendance de signature interdite (${forbidden})`);
  }
}

// Le plan est ce que les deux hachages de l’enveloppe recouvrent. Sa
// transcription est écrite champ par champ, sous sa propre longueur, dans cet
// ordre exact, et le côté Auxiliaire écrit la même table dans internal/plan.
for (const bound of [
  'pub const PLAN_TRANSCRIPT_DOMAIN: &[u8] = b"your-cloud/oci-plan.v1\\0";',
  "transcript.extend_from_slice(&self.schema_version.to_be_bytes());",
  "append_field(&mut transcript, self.infrastructure_id.as_bytes())?;",
  "append_field(&mut transcript, self.machine_id.as_bytes())?;",
  "append_field(&mut transcript, self.operation.as_str().as_bytes())?;",
  "append_field(&mut transcript, self.image_reference.as_bytes())?;",
  "append_field(&mut transcript, &image)?;",
  "transcript.extend_from_slice(&self.local_port.to_be_bytes());",
  // La liste des champs est fermée, et l’image est comparée à l’égalité : un
  // plan qui nommerait un autre registre, un autre dépôt ou un autre digest
  // n’est pas un plan plus étroit, c’est un plan que ce palier ne connaît pas.
  "#[serde(deny_unknown_fields)]\npub struct PlanDocumentV1 {",
  "self.image_reference != PROBE_IMAGE_REFERENCE",
  "self.image_digest != PROBE_IMAGE_DIGEST",
  'pub const PROBE_IMAGE_REFERENCE: &str = "docker.io/traefik/whoami";',
  'pub const PROBE_LOCAL_ADDRESS: &str = "127.0.0.1";',
]) {
  if (!planProtocol.includes(bound)) {
    failures.push(`plan.rs (protocole): lien haché absent (${bound})`);
  }
}
// Le plan ne porte aucun champ exécutable : ni commande, ni chemin, ni volume,
// ni réseau, ni privilège conteneur, ni variable. Un document qui en porterait
// un est un champ inconnu, refusé avant lecture de sa valeur — encore faut-il
// qu’aucun de ces champs n’existe dans le schéma.
for (const forbidden of [
  "pub tag:",
  "pub volumes:",
  "pub network:",
  "pub privileged:",
  "pub command:",
  "pub environment:",
]) {
  if (planProtocol.includes(forbidden)) {
    failures.push(`plan.rs (protocole): le schéma déclare un champ exécutable (${forbidden})`);
  }
}
// La Console ne possède pas de ré-encodeur canonique faisant autorité : elle
// vérifie les octets reçus. Ce qu’elle affiche est donc vérifié avant d’être
// affiché, et signé sur les mêmes octets.
for (const bound of [
  "pub fn verify(view: &ProbePlanView) -> Result<Self, ProbePlanError>",
  "verify_plan_document(view.plan_document.as_bytes(), &view.plan_sha256)",
  "verify_plan_document(view.rollback_document.as_bytes(), &view.rollback_sha256)",
  "if !plan.is_undone_by(&rollback) {",
  "pub fn confirmation_lines(&self) -> Vec<String> {",
  "if Self::verify(documents)? != *self {",
  "if self.plan.infrastructure_id != association.summary.infrastructure_id {",
  "operation: approval_operation(self.plan.operation),",
]) {
  if (!probePlanRuntime.includes(bound)) {
    failures.push(`probe_plan.rs: garde du plan présenté absente (${bound})`);
  }
}
for (const forbidden of ["SigningKey", "signing_key", "human_private_seed", "Signer"]) {
  if (probePlanRuntime.replace(/#\[cfg\(test\)\][\s\S]*$/u, "").includes(forbidden)) {
    failures.push(`probe_plan.rs: une notion de clé privée y apparaît (${forbidden})`);
  }
}

// Le schéma 2 ajoute six opérations en trois paires inverses sans rouvrir le
// schéma 1 : son domaine diffère d'un octet, chaque groupe écrit sa propre
// queue de transcription champ par champ sous sa propre longueur, et le côté
// Auxiliaire écrit la même table dans internal/plan/schema2.go.
for (const bound of [
  'pub const PLAN_V2_TRANSCRIPT_DOMAIN: &[u8] = b"your-cloud/oci-plan.v2\\0";',
  "pub const PLAN_V2_SCHEMA_VERSION: u8 = 2;",
  "transcript.extend_from_slice(PLAN_V2_TRANSCRIPT_DOMAIN);",
  "transcript.extend_from_slice(&schema_version.to_be_bytes());",
  "append_field(&mut transcript, infrastructure_id.as_bytes())?;",
  "append_field(&mut transcript, machine_id.as_bytes())?;",
  "append_field(&mut transcript, operation.as_str().as_bytes())?;",
  "append_field(&mut transcript, self.service_profile.as_bytes())?;",
  "append_field(&mut transcript, self.image_reference.as_bytes())?;",
  "append_field(&mut transcript, &image)?;",
  "transcript.extend_from_slice(&self.local_port.to_be_bytes());",
  "append_field(&mut transcript, self.route_host.as_bytes())?;",
  "transcript.extend_from_slice(&self.backend_port.to_be_bytes());",
  // L'opération est le discriminant : elle est lue d'abord, et seule, puis le
  // document est tenu contre exactement la liste fermée qu'elle déclare.
  "fn declared_operation(document: &[u8]) -> Result<PlanV2Operation, ProtocolError> {",
  "let parsed = match declared_operation(document)?.group() {",
  "#[serde(deny_unknown_fields)]\npub struct WebServicePlanDocumentV2 {",
  "#[serde(deny_unknown_fields)]\npub struct EntrypointPlanDocumentV2 {",
  "#[serde(deny_unknown_fields)]\npub struct RoutePlanDocumentV2 {",
  // Profil fermé, images épinglées par digest seul, bornes du contrat.
  'pub const SERVICE_PROFILE_BENTOPDF: &str = "bentopdf";',
  "SERVICE_PROFILE_BENTOPDF => Some(PinnedImage {",
  'pub const BENTOPDF_IMAGE_REFERENCE: &str = "ghcr.io/alam00000/bentopdf";',
  '"sha256:a4ed090f29823da5e296e2c2f8603664da71676156ea47c3f186cc73eec38db0"',
  'pub const ENTRYPOINT_IMAGE_REFERENCE: &str = "docker.io/library/traefik";',
  '"sha256:9c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab2614cbaf410dcb2ac"',
  "reference == pinned.reference",
  "&& decode_image_digest(digest).is_some()",
  "&& digest == pinned.digest",
  "!pinned_image_matches(&self.image_reference, &self.image_digest, image)",
  "!pinned_image_matches(&self.image_reference, &self.image_digest, ENTRYPOINT_IMAGE)",
  "!(MIN_PLAN_LOCAL_PORT..=MAX_PLAN_LOCAL_PORT).contains(&self.local_port)",
  "!(MIN_PLAN_BACKEND_PORT..=MAX_PLAN_BACKEND_PORT).contains(&self.backend_port)",
  "!canonical_route_host(&self.route_host)",
  "bytes.len() < MIN_ROUTE_HOST_BYTES || bytes.len() > MAX_ROUTE_HOST_BYTES",
  '!alphanumeric(bytes[0]) || !alphanumeric(bytes[bytes.len() - 1]) || host.contains("..")',
  // Constantes du contrat : affichées, jamais approuvées comme valeurs.
  'pub const SERVICE_LOCAL_ADDRESS: &str = "127.0.0.1";',
  "pub const ENTRYPOINT_PUBLIC_HTTPS_PORT: u32 = 443;",
  "pub const ENTRYPOINT_PUBLIC_HTTP_PORT: u32 = 80;",
  'pub const ENTRYPOINT_UNPRIVILEGED_PORT_SYSCTL: &str = "net.ipv4.ip_unprivileged_port_start=80";',
  '"Cross-Origin-Opener-Policy: same-origin",',
  '"Cross-Origin-Embedder-Policy: require-corp",',
  // Le profil privé : sa propre porte, sa propre liste fermée, sa propre image
  // épinglée par digest seul. La liste de manifestes est ce que le contrat
  // épingle ; l'image résolue par architecture n'est pas une seconde vérité.
  'pub const SERVICE_PROFILE_VAULTWARDEN: &str = "vaultwarden";',
  "SERVICE_PROFILE_VAULTWARDEN => Some(PinnedImage {",
  'pub const VAULTWARDEN_IMAGE_REFERENCE: &str = "docker.io/vaultwarden/server";',
  // La déclaration entière, et pas seulement le digest : celui-ci apparaît
  // aussi dans les vecteurs, si bien qu'une garde de simple présence passerait
  // encore avec une constante déplacée sur l'image résolue d'une architecture.
  'pub const VAULTWARDEN_IMAGE_DIGEST: &str =\n    "sha256:ebdfe70701c60ac0c28c697e787cea767d7972940b786037b29fe0d507f821e8";',
  "fn private_profile_image(service_profile: &str) -> Option<PinnedImage> {",
  "#[serde(deny_unknown_fields)]\npub struct PrivateServicePlanDocumentV2 {",
  "#[serde(deny_unknown_fields)]\npub struct LinkRoutePlanDocumentV2 {",
  "#[serde(deny_unknown_fields)]\npub struct SnapshotPlanDocumentV2 {",
  "#[serde(deny_unknown_fields)]\npub struct RestorePlanDocumentV2 {",
  // La troisième porte : une forme fermée de plus, qui nomme une définition là
  // où les deux autres nomment un profil livré. Le slug et le dépôt sont tenus
  // par la grammaire du module des définitions plutôt que par une seconde
  // écrite ici, et la révision est lue par le lecteur de digest de l'enveloppe
  // — jamais par celui d'un digest OCI, qui porte son algorithme.
  "#[serde(deny_unknown_fields)]\npub struct UserServicePlanDocumentV2 {",
  "!canonical_definition_slug(&self.definition_slug)",
  "decode_digest(&self.definition_digest).is_none()",
  "!canonical_image_repository(&self.image_reference)",
  "append_field(&mut transcript, self.definition_slug.as_bytes())?;",
  "append_field(&mut transcript, &definition)?;",
  // L'origine du service utilisateur est écrite même absente : une longueur de
  // zéro, jamais un champ que le lecteur peut ne pas trouver.
  "fn canonical_user_service_origin(origin: &str) -> bool {",
  "origin.is_empty() || canonical_route_host(origin)",
  "!canonical_user_service_origin(&self.origin_host)",
  // Les archives partagent un champ avec la troisième porte, et la réservation
  // des quatre noms du produit est ce qui garde une lecture unique : un nom est
  // dans la liste fermée, ou c'est un slug, jamais les deux.
  "fn archives_data(service_profile: &str) -> bool {",
  "private_profile_image(service_profile).is_some() || canonical_definition_slug(service_profile)",
  "Self::DeployUserService | Self::RemoveUserService => PlanV2Group::UserService,",
  "Self::DeployUserService => Self::RemoveUserService,",
  "Self::RemoveUserService => Self::DeployUserService,",
  'Self::DeployUserService => "deploy_user_service",',
  'Self::RemoveUserService => "remove_user_service",',
  // Les queues de transcription des quatre groupes : l'origine ajoutée après le
  // port, l'emplacement après le profil.
  "append_field(&mut transcript, self.origin_host.as_bytes())?;",
  "append_field(&mut transcript, self.snapshot_slot.as_bytes())?;",
  // L'origine reprend la borne des hôtes plutôt qu'une seconde expression, et
  // l'emplacement a la sienne, fermée sur ce qu'une entrée de répertoire peut
  // être : ni séparateur, ni point, ni majuscule, donc rien qui grimpe.
  "!canonical_route_host(&self.origin_host)",
  "!canonical_snapshot_slot(&self.snapshot_slot)",
  "bytes.len() < MIN_SNAPSHOT_SLOT_BYTES || bytes.len() > MAX_SNAPSHOT_SLOT_BYTES",
  "pub const MIN_SNAPSHOT_SLOT_BYTES: usize = 1;",
  "pub const MAX_SNAPSHOT_SLOT_BYTES: usize = 32;",
  // L'emplacement réservé appartient au mécanisme de retour : refusé dans une
  // sauvegarde et dans une destruction, accepté dans un retour — c'est le
  // rollback signé d'un `restore_service`, seul document du produit à le nommer.
  'pub const RESERVED_SNAPSHOT_SLOT: &str = "previous";',
  "self.snapshot_slot == RESERVED_SNAPSHOT_SLOT",
  // L'inverse qui déplace un champ au lieu de l'opération. Les deux lignes vont
  // ensemble : l'opération d'un retour est elle-même, et ce qui change entre lui
  // et son annulation est l'emplacement.
  "Self::RestoreService => Self::RestoreService,",
  "snapshot_slot: RESERVED_SNAPSHOT_SLOT.to_owned(),",
  // Constantes du profil privé : affichées, portées par aucun champ.
  'pub const PRIVATE_SERVICE_DATA_VOLUME: &str = "/var/lib/your-cloud-svc-vaultwarden/data";',
  '"SIGNUPS_ALLOWED=false",',
  '"INVITATIONS_ALLOWED=false",',
  '"SHOW_PASSWORD_HINT=false",',
  'pub const PRIVATE_SERVICE_ORIGIN_VARIABLE: &str = "DOMAIN";',
  'pub const PRIVATE_SERVICE_ORIGIN_SCHEME: &str = "https";',
  'pub const PRIVATE_SERVICE_EGRESS_TABLE: &str = "inet your-cloud-egress";',
]) {
  if (!planV2Protocol.includes(bound)) {
    failures.push(`plan_v2.rs (protocole): lien haché absent (${bound})`);
  }
}
// Les deux groupes qui nomment une image l'écrivent chacun dans sa propre
// transcription, et les deux seuls. C'est compté plutôt que constaté présent :
// une garde de présence passerait encore si l'un des deux groupes cessait de
// hacher son image.
for (const [fragment, expected] of [
  ["append_field(&mut transcript, self.image_reference.as_bytes())?;", 4],
  ["append_field(&mut transcript, &image)?;", 4],
  // Les deux formes qui nomment un emplacement le hachent chacune, et les deux
  // seules ; les deux qui archivent tiennent chacune la liste privée des
  // profils, parce qu'un profil sans volume n'a rien à archiver.
  ["append_field(&mut transcript, self.snapshot_slot.as_bytes())?;", 2],
  // Les deux formes qui portent une origine la hachent chacune en fin de queue,
  // et les deux seules ; celle de la troisième porte l'écrit même vide.
  ["append_field(&mut transcript, self.origin_host.as_bytes())?;", 2],
  ["!archives_data(&self.service_profile)", 2],
  ["!canonical_snapshot_slot(&self.snapshot_slot)", 2],
  // Le refus de l'emplacement réservé est écrit une fois et une seule : dans la
  // forme des archives. L'écrire aussi dans le retour interdirait le rollback
  // signé d'un `restore_service` ; ne l'écrire nulle part laisserait une
  // sauvegarde écraser ce que le mécanisme de retour détient.
  ["self.snapshot_slot == RESERVED_SNAPSHOT_SLOT", 1],
]) {
  const occurrences = planV2Protocol.split(fragment).length - 1;
  if (occurrences !== expected) {
    failures.push(
      `plan_v2.rs (protocole): ${fragment} est écrit ${occurrences} fois au lieu de ${expected}`,
    );
  }
}
// Aucun des trois documents ne porte de champ exécutable, et aucun ne porte le
// champ d'un autre groupe : un document qui en porterait un est un champ
// inconnu, refusé avant lecture de sa valeur — encore faut-il qu'aucun de ces
// champs n'existe dans les schémas.
for (const forbidden of [
  "pub tag:",
  "pub volumes:",
  "pub network:",
  "pub privileged:",
  "pub command:",
  "pub environment:",
  "pub headers:",
  "pub tls_certificate:",
  // Le profil privé n'ouvre aucun de ces champs non plus : le volume, la table
  // de sortie, le chemin et le digest d'une archive, l'adresse du pair du
  // tunnel et la direction d'un retour sont des constantes ou des faits, jamais
  // des valeurs qu'une requête pourrait déplacer.
  "pub volume:",
  "pub data_volume:",
  "pub egress:",
  "pub snapshot_path:",
  "pub archive_digest:",
  "pub backend_address:",
  "pub peer_address:",
]) {
  if (planV2Protocol.includes(forbidden)) {
    failures.push(`plan_v2.rs (protocole): un schéma déclare un champ interdit (${forbidden})`);
  }
}
// Les six opérations du profil public existent dans l'enveloppe et y demandent
// exactement la paire mutante. Nommer une opération est tout ce qu'une
// enveloppe fait pour demander un pouvoir : il n'y a pas de second champ par
// lequel en demander plus, et le diagnostic en lecture seule reste seul à
// refuser la mutation.
for (const bound of [
  'Self::DeployWebService => "deploy_web_service",',
  'Self::RemoveWebService => "remove_web_service",',
  'Self::DeployEntrypoint => "deploy_entrypoint",',
  'Self::RemoveEntrypoint => "remove_entrypoint",',
  'Self::PublishRoute => "publish_route",',
  'Self::RetireRoute => "retire_route",',
  "Self::DiagnoseProtocolReadOnly => &[ApprovalPrivilege::ReadLocalState],",
  "| Self::DeployWebService\n            | Self::RemoveWebService\n            | Self::DeployEntrypoint\n            | Self::RemoveEntrypoint\n            | Self::PublishRoute\n            | Self::RetireRoute\n            | Self::PrepareLink\n            | Self::WithdrawLink\n            | Self::AttachLinkPeer\n            | Self::DetachLinkPeer\n            | Self::JoinLinkPeer\n            | Self::LeaveLinkPeer\n            | Self::DeployPrivateService\n            | Self::RemovePrivateService\n            | Self::PublishLinkRoute\n            | Self::RetireLinkRoute\n            | Self::SnapshotService\n            | Self::DiscardSnapshot\n            | Self::RestoreService\n            | Self::DeployUserService\n            | Self::RemoveUserService => &[\n                ApprovalPrivilege::MutateLocalState,\n                ApprovalPrivilege::ReadLocalState,\n            ],",
]) {
  if (!approvalProtocol.includes(bound)) {
    failures.push(`approval.rs (protocole): opération du profil public absente (${bound})`);
  }
}
// Les six opérations du passage privé existent dans la même enveloppe et y
// demandent la même paire mutante : préparer un lien lit la machine pour refuser
// de régénérer une clé existante, et retirer ou quitter lit la machine pour
// trouver ce qu'il s'apprête à défaire.
for (const bound of [
  'Self::PrepareLink => "prepare_link",',
  'Self::WithdrawLink => "withdraw_link",',
  'Self::AttachLinkPeer => "attach_link_peer",',
  'Self::DetachLinkPeer => "detach_link_peer",',
  'Self::JoinLinkPeer => "join_link_peer",',
  'Self::LeaveLinkPeer => "leave_link_peer",',
]) {
  if (!approvalProtocol.includes(bound)) {
    failures.push(`approval.rs (protocole): opération du passage privé absente (${bound})`);
  }
}
// Les sept opérations du profil privé existent dans la même enveloppe et y
// demandent la même paire mutante. La sauvegarde est celle qu'il faut nommer :
// elle arrête le service, écrit une archive et le redémarre, donc elle mute la
// machine autant qu'un déploiement, quoi que le mot « sauvegarde » suggère.
for (const bound of [
  'Self::DeployPrivateService => "deploy_private_service",',
  'Self::RemovePrivateService => "remove_private_service",',
  'Self::PublishLinkRoute => "publish_link_route",',
  'Self::RetireLinkRoute => "retire_link_route",',
  'Self::SnapshotService => "snapshot_service",',
  'Self::DiscardSnapshot => "discard_snapshot",',
  'Self::RestoreService => "restore_service",',
  "| Self::SnapshotService\n            | Self::DiscardSnapshot\n            | Self::RestoreService\n            | Self::DeployUserService\n            | Self::RemoveUserService => &[\n                ApprovalPrivilege::MutateLocalState,\n                ApprovalPrivilege::ReadLocalState,\n            ],",
]) {
  if (!approvalProtocol.includes(bound)) {
    failures.push(`approval.rs (protocole): opération du profil privé absente (${bound})`);
  }
}
// Les deux opérations de la troisième porte existent dans la même enveloppe et y
// demandent la même paire mutante. Les nommer ne les rend pas applicables :
// l'enveloppe décide qu'un humain a approuvé deux empreintes pour une opération,
// et elle n'a jamais su ce que ces empreintes couvrent.
for (const bound of [
  'Self::DeployUserService => "deploy_user_service",',
  'Self::RemoveUserService => "remove_user_service",',
]) {
  if (!approvalProtocol.includes(bound)) {
    failures.push(`approval.rs (protocole): opération de la troisième porte absente (${bound})`);
  }
}
// La Console ne possède pas plus de ré-encodeur canonique au schéma 2 qu'au
// schéma 1 : elle vérifie les octets reçus contre leurs digests avant de rien
// afficher, elle revérifie avant de signer, et ce que l'humain doit lire est
// nommé ligne par ligne — le profil, l'image et son digest, le port du service ;
// l'image et les constantes du point d'entrée, effet sysctl compris ; le nom, le
// port joint et les en-têtes d'isolation d'une route.
for (const bound of [
  "pub fn verify(view: &PlanPairView) -> Result<Self, PublicationPlanError>",
  "verify_plan_v2_document(view.plan_document.as_bytes(), &view.plan_sha256)",
  "verify_plan_v2_document(view.rollback_document.as_bytes(), &view.rollback_sha256)",
  "pub fn confirmation_lines(&self) -> Vec<String> {",
  "if Self::verify(documents)? != *self {",
  "if self.plan.infrastructure_id() != association.summary.infrastructure_id.as_str() {",
  "operation: approval_operation(self.plan.operation()),",
  'format!("Profil de service : {}", document.service_profile)',
  'format!("Image : {}", document.image_reference)',
  'format!("Digest de l’image : {}", document.image_digest)',
  '"Port local : {SERVICE_LOCAL_ADDRESS}:{}"',
  '"Ports publics : {ENTRYPOINT_PUBLIC_HTTPS_PORT} en HTTPS,',
  "{ENTRYPOINT_PUBLIC_HTTP_PORT} limité à la redirection",
  '"Effet sur l’hôte : sysctl {ENTRYPOINT_UNPRIVILEGED_PORT_SYSCTL},',
  'format!("Nom publié : {}", document.route_host)',
  '"Service joint : {SERVICE_LOCAL_ADDRESS}:{}"',
  "for header in ROUTE_ISOLATION_HEADERS {",
  'format!("En-tête d’isolation : {header}")',
  'format!("Empreinte du plan : {}", self.plan_sha256)',
  'format!("Empreinte du rollback : {}", self.rollback_sha256)',
  // Une paire dont les deux documents sont un seul document n'est pas une
  // paire : un retour nommant déjà l'emplacement réservé s'annule lui-même, et
  // l'humain approuverait le même plan comme son propre rollback. Le refus
  // porte sur les documents, donc il vaut pour tous les groupes.
  "if !plan.is_undone_by(&rollback) || plan == rollback {",
  // Ce que la porte privée ajoute, ligne par ligne : l'origine exacte, le seul
  // chemin d'écriture durable, les quatre lignes d'environnement — trois
  // constantes de durcissement et la seule valeur approuvée — et la table qui
  // refuse au service toute sortie.
  '"Origine : {PRIVATE_SERVICE_ORIGIN_SCHEME}://{}"',
  'format!("Volume persistant : {PRIVATE_SERVICE_DATA_VOLUME}")',
  "for hardening in PRIVATE_SERVICE_ENVIRONMENT_HARDENING {",
  'format!("Ligne d’environnement : {hardening}")',
  '"Ligne d’environnement : {PRIVATE_SERVICE_ORIGIN_VARIABLE}=\\',
  '"Confinement de sortie : table {PRIVATE_SERVICE_EGRESS_TABLE}, le service ne \\',
  "parle à personne : sortie refusée hors loopback et réponses",
  // La route de lien nomme le pair du tunnel, jamais le loopback de la machine,
  // et dit à quoi ressemble une panne du passage.
  '"Service joint : {LINK_INITIATOR_TUNNEL_ADDRESS}:{}, publié par le seul \\',
  "Panne du passage : le nom rend l’erreur de passerelle du point d’entrée, \\",
  // Les archives : l'immuabilité d'un côté, et de l'autre la phrase que le
  // contrat exige — le rollback d'une destruction recrée une archive de l'état
  // courant, jamais l'archive détruite.
  'format!("Emplacement : {}", document.snapshot_slot)',
  "Immuabilité : un emplacement existant est refusé",
  "Ce que le rollback fait vraiment : il recrée une archive de l’état \\",
  "courant sous ce nom, jamais l’archive détruite, que rien ne ramène",
  // Le retour dit d'où vient son propre retour.
  'format!("Emplacement restauré : {}", document.snapshot_slot)',
  '"Retour : le rollback restaure ce que « {RESERVED_SNAPSHOT_SLOT} » détient, \\',
  "écrit avant que la moindre donnée ne soit touchée",
  // La troisième porte : ce qu'un humain approuve vraiment est la définition et
  // sa révision, parce que le compte, le foyer, les volumes, l'environnement et
  // les noms de secrets en viennent et d'aucun champ du plan. L'origine est le
  // seul champ du schéma qu'un document peut porter ou non, donc les deux formes
  // sont écrites : une fenêtre qui omettrait la ligne rendrait deux états
  // presque identiques.
  'format!("Service défini : {}", document.definition_slug)',
  '"Révision de la définition : {}",',
  "if document.origin_host.is_empty() {",
  '"Origine : aucune, aucune ligne de la définition gelée ne nomme \\',
  '"Origine : {}, portée par les lignes de la définition qui nomment \\',
  "{ORIGIN_HOST_PLACEHOLDER}",
  '"Ce que la révision décide : le compte, le foyer, les volumes, \\',
  "cette empreinte, et d’aucun champ de ce plan",
]) {
  if (!publicationPlanRuntime.includes(bound)) {
    failures.push(`publication_plan.rs: garde du plan présenté absente (${bound})`);
  }
}
// Les deux genres de plan qui nomment une image la montrent chacun avec son
// digest. Comme au-dessus, c'est compté : un service dont l'image aurait
// disparu de ses lignes passerait une garde de simple présence.
for (const [fragment, expected] of [
  ['format!("Image : {}", document.image_reference)', 4],
  ['format!("Digest de l’image : {}", document.image_digest)', 4],
  // Les quatre genres de plan qui nomment un profil le montrent. Un service
  // privé, une archive ou un retour dont le profil aurait disparu des lignes
  // passerait une garde de simple présence, puisque le service sans état, lui,
  // le montre toujours.
  ['format!("Profil de service : {}", document.service_profile)', 4],
]) {
  const occurrences = publicationPlanRuntime.split(fragment).length - 1;
  if (occurrences !== expected) {
    failures.push(
      `publication_plan.rs: ${fragment} est affiché ${occurrences} fois au lieu de ${expected}`,
    );
  }
}
for (const forbidden of ["SigningKey", "signing_key", "human_private_seed", "Signer"]) {
  if (publicationPlanRuntime.replace(/#\[cfg\(test\)\][\s\S]*$/u, "").includes(forbidden)) {
    failures.push(`publication_plan.rs: une notion de clé privée y apparaît (${forbidden})`);
  }
}

// Le schéma 3 ajoute six opérations en trois paires inverses sans rouvrir les
// deux schémas plus anciens : son domaine diffère d'un octet, chaque groupe
// écrit sa propre queue de transcription champ par champ sous sa propre
// longueur, et le côté Auxiliaire écrit la même table dans
// internal/plan/schema3.go.
for (const bound of [
  'pub const PLAN_V3_TRANSCRIPT_DOMAIN: &[u8] = b"your-cloud/oci-plan.v3\\0";',
  "pub const PLAN_V3_SCHEMA_VERSION: u8 = 3;",
  "transcript.extend_from_slice(PLAN_V3_TRANSCRIPT_DOMAIN);",
  "transcript.extend_from_slice(&schema_version.to_be_bytes());",
  "append_field(&mut transcript, infrastructure_id.as_bytes())?;",
  "append_field(&mut transcript, machine_id.as_bytes())?;",
  "append_field(&mut transcript, operation.as_str().as_bytes())?;",
  "append_field(&mut transcript, self.link_role.as_str().as_bytes())?;",
  "append_field(&mut transcript, &key)?;",
  "append_field(&mut transcript, self.peer_endpoint_host.as_bytes())?;",
  "transcript.extend_from_slice(&self.service_port.to_be_bytes());",
  // L'opération est le discriminant : elle est lue d'abord, et seule, puis le
  // document est tenu contre exactement la liste fermée qu'elle déclare.
  "fn declared_operation(document: &[u8]) -> Result<PlanV3Operation, ProtocolError> {",
  "let parsed = match declared_operation(document)?.group() {",
  "#[serde(deny_unknown_fields)]\npub struct LinkPlanDocumentV3 {",
  "#[serde(deny_unknown_fields)]\npub struct ListenerPeerPlanDocumentV3 {",
  "#[serde(deny_unknown_fields)]\npub struct InitiatorPeerPlanDocumentV3 {",
  // La clé du pair est lue avec indulgence et ré-écrite avec rigueur : c'est le
  // ré-encodage qui refuse une seconde orthographe des mêmes trente-deux
  // octets, donc il doit rester la règle plutôt qu'une précaution.
  "const PEER_PUBLIC_KEY_BASE64: GeneralPurpose = GeneralPurpose::new(\n    &alphabet::STANDARD,\n    GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),\n);",
  "pub const PEER_PUBLIC_KEY_BYTES: usize = 32;",
  "pub const PEER_PUBLIC_KEY_ENCODED_BYTES: usize = 44;",
  "if value.len() != PEER_PUBLIC_KEY_ENCODED_BYTES || !value.is_ascii() {",
  "let decoded = PEER_PUBLIC_KEY_BASE64.decode(value.as_bytes()).ok()?;",
  "if decoded.len() != PEER_PUBLIC_KEY_BYTES || PEER_PUBLIC_KEY_BASE64.encode(&decoded) != value {",
  "decode_peer_public_key(&self.peer_public_key).is_none()",
  "!canonical_peer_endpoint_host(&self.peer_endpoint_host)",
  "!(MIN_PLAN_SERVICE_PORT..=MAX_PLAN_SERVICE_PORT).contains(&self.service_port)",
  // L'endpoint reprend la borne de route_host, jusqu'aux deux nombres qu'il lit
  // dans le module du schéma 2 plutôt que de les redire.
  "bytes.len() < MIN_ROUTE_HOST_BYTES || bytes.len() > MAX_ROUTE_HOST_BYTES",
  '!alphanumeric(bytes[0]) || !alphanumeric(bytes[bytes.len() - 1]) || host.contains("..")',
  // Constantes du scénario : affichées, jamais approuvées comme valeurs.
  'pub const LINK_INTERFACE_NAME: &str = "yc-link0";',
  'pub const LINK_LISTENER_TUNNEL_ADDRESS: &str = "10.66.66.1";',
  'pub const LINK_INITIATOR_TUNNEL_ADDRESS: &str = "10.66.66.2";',
  "pub const LINK_LISTEN_PORT: u32 = 51_820;",
  "pub const LINK_KEEPALIVE_SECONDS: u32 = 25;",
  'pub const LINK_NFTABLES_TABLE: &str = "inet your-cloud-link";',
]) {
  if (!planV3Protocol.includes(bound)) {
    failures.push(`plan_v3.rs (protocole): lien haché absent (${bound})`);
  }
}
// Les deux groupes de jonction hachent chacun la clé décodée et le port dans
// leur propre transcription, et les deux seuls. C'est compté plutôt que constaté
// présent : une garde de présence passerait encore si l'un des deux groupes
// cessait de hacher la sienne.
for (const [fragment, expected] of [
  ["append_field(&mut transcript, &key)?;", 2],
  ["decode_peer_public_key(&self.peer_public_key).is_none()", 2],
  ["transcript.extend_from_slice(&self.service_port.to_be_bytes());", 2],
]) {
  const occurrences = planV3Protocol.split(fragment).length - 1;
  if (occurrences !== expected) {
    failures.push(
      `plan_v3.rs (protocole): ${fragment} est écrit ${occurrences} fois au lieu de ${expected}`,
    );
  }
}
// La clé du pair voyage décodée, comme un digest d'image : trente-deux octets
// sous leur propre longueur. Hacher la chaîne base64 donnerait une empreinte à
// une orthographe plutôt qu'à une clé, donc la chaîne n'entre nulle part dans
// une transcription.
if (planV3Protocol.includes("self.peer_public_key.as_bytes()")) {
  failures.push("plan_v3.rs (protocole): la clé du pair serait hachée sous sa forme encodée");
}
// Aucun des trois documents ne porte de champ exécutable, et aucun ne porte une
// constante du contrat : le sous-réseau, les deux adresses, l'interface, le port
// d'écoute, le keepalive, les règles et surtout une clé privée n'ont pas de
// champ à occuper.
for (const forbidden of [
  "pub private_key:",
  "pub interface:",
  "pub listen_port:",
  "pub keepalive_seconds:",
  "pub allowed_ips:",
  "pub address:",
  "pub subnet:",
  "pub peer_endpoint_port:",
  "pub nftables:",
  "pub command:",
]) {
  if (planV3Protocol.includes(forbidden)) {
    failures.push(`plan_v3.rs (protocole): un schéma déclare un champ interdit (${forbidden})`);
  }
}
// La Console ne possède pas plus de ré-encodeur canonique au schéma 3 qu'aux
// deux précédents : elle vérifie les octets reçus contre leurs digests avant de
// rien afficher, elle revérifie avant de signer, et ce que l'humain doit lire
// est nommé ligne par ligne — le rôle et ce que ce rôle décide sans qu'aucun
// champ ne le porte ; la clé publique du pair entière, le port que les règles
// borneront et le seul couple qui passera ; l'endpoint et le port d'écoute du
// contrat qu'il est joint dessus.
for (const bound of [
  "pub fn verify(view: &LinkPlanPairView) -> Result<Self, LinkPlanError>",
  "verify_plan_v3_document(view.plan_document.as_bytes(), &view.plan_sha256)",
  "verify_plan_v3_document(view.rollback_document.as_bytes(), &view.rollback_sha256)",
  "if !plan.is_undone_by(&rollback) {",
  "pub fn confirmation_lines(&self) -> Vec<String> {",
  "if Self::verify(documents)? != *self {",
  "if self.plan.infrastructure_id() != association.summary.infrastructure_id.as_str() {",
  "operation: approval_operation(self.plan.operation()),",
  'format!("Rôle du lien : {}", role_text(document.link_role))',
  '"Adresse de tunnel : {}/32 sur l’interface {LINK_INTERFACE_NAME}"',
  '"Port d’écoute (UDP) : {LINK_LISTEN_PORT}, sur l’écouteur seulement"',
  '"Keepalive : {LINK_KEEPALIVE_SECONDS} s, sur l’initiateur seulement"',
  '"Clés : générées sur cette machine, la moitié privée n’en sort jamais"',
  '"Clé publique du pair : {}"',
  'format!("Port du service : {}", document.service_port)',
  '"Seul flux autorisé : TCP vers {LINK_INITIATOR_TUNNEL_ADDRESS}:{}, \\',
  '"Seul flux autorisé : TCP depuis {LINK_LISTENER_TUNNEL_ADDRESS} vers \\',
  '"Table de règles : {LINK_NFTABLES_TABLE}, posée avec ce plan \\',
  '"Endpoint joint : {}:{LINK_LISTEN_PORT}"',
  'format!("Empreinte du plan : {}", self.plan_sha256)',
  'format!("Empreinte du rollback : {}", self.rollback_sha256)',
]) {
  if (!linkPlanRuntime.includes(bound)) {
    failures.push(`link_plan.rs: garde du plan présenté absente (${bound})`);
  }
}
// Les deux genres de jonction montrent chacun la clé qu'ils acceptent, le port
// qu'ils bornent et la table qu'ils posent. Comme au-dessus, c'est compté : une
// jonction dont la clé aurait disparu des lignes passerait une garde de simple
// présence.
for (const [fragment, expected] of [
  ['"Clé publique du pair : {}"', 2],
  ['format!("Port du service : {}", document.service_port)', 2],
  ['"Table de règles : {LINK_NFTABLES_TABLE}, posée avec ce plan \\', 2],
]) {
  const occurrences = linkPlanRuntime.split(fragment).length - 1;
  if (occurrences !== expected) {
    failures.push(
      `link_plan.rs: ${fragment} est affiché ${occurrences} fois au lieu de ${expected}`,
    );
  }
}
for (const forbidden of [
  "SigningKey",
  "signing_key",
  "human_private_seed",
  "Signer",
  "private_key",
]) {
  if (linkPlanRuntime.replace(/#\[cfg\(test\)\][\s\S]*$/u, "").includes(forbidden)) {
    failures.push(`link_plan.rs: une notion de clé privée y apparaît (${forbidden})`);
  }
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
  "UnixStream::pair()",
  "Stdio::from(OwnedFd::from(child_input))",
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
for (const expected of [
  "CreateProcessW",
  "PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
  "CREATE_SUSPENDED",
  "CREATE_UNICODE_ENVIRONMENT",
  "EXTENDED_STARTUPINFO_PRESENT",
  "CREATE_NO_WINDOW",
  "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
  "AssignProcessToJobObject",
  "IsProcessInJob",
  "ResumeThread",
  "TerminateJobObject",
  "QueryInformationJobObject",
  "ActiveProcesses",
  "WINDOWS_CLEANUP_UNPROVEN",
]) {
  if (!nativeAssistantWindows.includes(expected)) {
    failures.push(`native_assistant/windows.rs: garde Win32 absente (${expected})`);
  }
}
for (const expected of [
  "active_processes()",
  "terminate_tree()",
  "root and its descendant must both belong to the private Job",
  "Job termination must leave no descendant",
  "hostile inheritable handle must be absent from the helper",
  "must no longer be inheritable",
  "WindowsSpawnFault::AfterCreate",
  "every later launch must remain refused after cleanup is unproven",
]) {
  if (!nativeAssistantWindowsJobContract.includes(expected)) {
    failures.push(`windows_job_contract.rs: preuve Job hostile absente (${expected})`);
  }
}
const assignToJobIndex = nativeAssistantWindows.indexOf("AssignProcessToJobObject(");
const verifyJobIndex = nativeAssistantWindows.indexOf("IsProcessInJob(");
const resumeThreadIndex = nativeAssistantWindows.indexOf("ResumeThread(");
if (
  assignToJobIndex < 0 ||
  verifyJobIndex < 0 ||
  resumeThreadIndex < 0 ||
  !(assignToJobIndex < verifyJobIndex && verifyJobIndex < resumeThreadIndex)
) {
  failures.push(
    "native_assistant/windows.rs: l’ordre assignation Job, vérification puis reprise doit rester explicite",
  );
}
if (nativeAssistantWindows.includes("CREATE_BREAKAWAY_FROM_JOB")) {
  failures.push("native_assistant/windows.rs: CREATE_BREAKAWAY_FROM_JOB est interdit");
}
for (const expected of [
  "GetStdHandle",
  "SetHandleInformation",
  "HANDLE_FLAG_INHERIT",
  "STD_INPUT_HANDLE",
  "STD_OUTPUT_HANDLE",
  "STD_ERROR_HANDLE",
]) {
  if (!nativeAssistantHardening.includes(expected)) {
    failures.push(`hardening.rs: garde des handles standard Windows absente (${expected})`);
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
]) {
  if (
    nativeAssistantRuntime.includes(`"${forbiddenEnvironmentName}"`) ||
    nativeAssistantWindows.includes(`"${forbiddenEnvironmentName}"`)
  ) {
    failures.push(
      `native_assistant.rs: variable non autorisée transmise trop tôt (${forbiddenEnvironmentName})`,
    );
  }
}
// L'endpoint de l'agent personnel est transmis, mais c'est un oracle de
// signature : il n'est dû qu'à la fenêtre d'accès personnel. Le garde doit
// donc rester dans la même fonction que la variable, et la variable ne doit
// jamais apparaître du côté Windows, où l'endpoint est un pipe fixe.
if (!nativeAssistantRuntime.includes('"SSH_AUTH_SOCK"')) {
  failures.push(
    "native_assistant.rs: l’endpoint de l’agent personnel n’est plus transmis au helper",
  );
}
if (nativeAssistantWindows.includes('"SSH_AUTH_SOCK"')) {
  failures.push(
    "native_assistant/windows.rs: l’endpoint d’agent Linux n’a rien à y faire",
  );
}
if (
  !/prompt != NativePromptKind::ConfirmPersonalAccess \{\s*return;\s*\}[\s\S]{0,400}?"SSH_AUTH_SOCK"/u.test(
    nativeAssistantRuntime,
  )
) {
  failures.push(
    "native_assistant.rs: SSH_AUTH_SOCK doit rester réservé au prompt d’accès personnel",
  );
}
for (const expected of [
  "Dialog::with_buttons",
  "Entry::new()",
  "set_visibility(false)",
  "InputPurpose::Password",
  "gtk_entry_get_text",
  "ProtectedSecret::new()",
  "entry.set_text(\"\")",
  "ConfirmRootAccess",
]) {
  if (!nativeAssistantPrompt.includes(expected)) {
    failures.push(`native_prompt.rs: garde GTK secrète absente (${expected})`);
  }
}
for (const expected of [
  "DialogBoxIndirectParamW",
  "CreateWindowExW",
  "ES_PASSWORD",
  "EM_SETLIMITTEXT",
  "GetWindowTextW",
  "ProtectedSecret::new()",
  "SetWindowTextW(edit",
  "ConfirmRootAccess",
]) {
  if (!nativeAssistantWindowsPrompt.includes(expected)) {
    failures.push(`native_prompt_windows.rs: garde Win32 secrète absente (${expected})`);
  }
}
for (const expected of [
  "mmap",
  "mlock",
  "MADV_DONTDUMP",
  "VirtualAlloc",
  "VirtualLock",
  "WerRegisterExcludedMemoryBlock",
  "volatile_zero",
]) {
  if (!nativeAssistantSecret.includes(expected)) {
    failures.push(`secret.rs: protection mémoire absente (${expected})`);
  }
}
if (
  forbiddenProtectedSecretDerive.test(nativeAssistantSecret) ||
  !nativeAssistantSecret.includes('formatter.write_str("ProtectedSecret([REDACTED])")')
) {
  failures.push("secret.rs: le secret protégé devient clonable, sérialisable ou non expurgé");
}
for (const expected of [
  "watch_standard_input",
  "Ok(0) => return CANCELLED",
  "Ok(_) => return PROTOCOL_INVALID",
  "SO_PEERCRED",
  "GetFileType",
  "FILE_TYPE_PIPE",
  "GetNamedPipeClientProcessId",
  "authenticate_parent_process",
  "transport_peer_rejects_clone_parent_spoof",
]) {
  if (!nativeAssistantLease.includes(expected)) {
    failures.push(`lease.rs: bail d’annulation fermé absent (${expected})`);
  }
}
if (
  !nativeAssistantRuntime.includes("stdin: Option<NativeChildStdin>") ||
  !nativeAssistantRuntime.includes("active.stdin.take()")
) {
  failures.push("native_assistant.rs: stdin doit rester le bail puis fermer coopérativement");
}
for (const expected of [
  "/usr/bin/your-cloud-console",
  "pidfd_open",
  "QueryFullProcessImageNameW",
  "FOLDERID_ProgramFiles",
  "PROCESS_QUERY_LIMITED_INFORMATION",
  "verify(input: &UnbufferedStandardInput)",
  "input.authenticate_parent_process",
]) {
  if (!nativeAssistantParent.includes(expected)) {
    failures.push(`parent.rs: attestation du parent installée absente (${expected})`);
  }
}
if (!nativeAssistantManifest.includes('"Win32_System_Pipes"')) {
  failures.push("Cargo.toml: primitive Win32 d’authentification du pipe absente");
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
