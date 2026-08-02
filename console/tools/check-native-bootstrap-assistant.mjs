import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { requireIsolatedExecution } from "./lib/execution-environment.mjs";
import {
  assertSupportedNativeTarget,
  inspectPreparedNativeAssistant,
} from "./lib/native-bootstrap-assistant.mjs";

const consoleRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const [target, binaryInput, ...unexpectedArguments] = process.argv.slice(2);
if (!target || !binaryInput || unexpectedArguments.length > 0) {
  throw new Error(
    "usage: node tools/check-native-bootstrap-assistant.mjs TARGET EXTERNAL_BIN_FILE",
  );
}

requireIsolatedExecution("native assistant Cargo/ELF gate");
assertSupportedNativeTarget(target);

const inspection = await inspectPreparedNativeAssistant(
  resolve(binaryInput),
  resolve(consoleRoot, "src-tauri", "Cargo.toml"),
  target,
);
process.stdout.write(`${JSON.stringify(inspection, null, 2)}\n`);
