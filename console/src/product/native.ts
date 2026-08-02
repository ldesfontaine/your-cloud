import { invoke } from "@tauri-apps/api/core";
import type {
  AssociationSummary,
  BootstrapSessionView,
  BootstrapStartInput,
  ConsoleStatus,
  GeneratedLocalSecrets,
  InfrastructureView,
  MachineMutationView,
  MachinesView,
  PairingInput,
  PreparedPhraseChange,
  PreparedRecoveryRotation,
  RecoveryRotationProgress,
} from "./models";

export type NativeErrorCode =
  | "console_unavailable"
  | "console_locked"
  | "invalid_input"
  | "authentication_failed"
  | "association_failed"
  | "session_expired"
  | "controller_unavailable"
  | "response_refused"
  | "bootstrap_busy"
  | "bootstrap_expired"
  | "bootstrap_request_refused"
  | "native_assistant_unavailable";

export class NativeOperationError extends Error {
  readonly code: NativeErrorCode;

  constructor(code: NativeErrorCode) {
    super(code);
    this.name = "NativeOperationError";
    this.code = code;
  }
}

const knownErrorCodes = new Set<NativeErrorCode>([
  "console_unavailable",
  "console_locked",
  "invalid_input",
  "authentication_failed",
  "association_failed",
  "session_expired",
  "controller_unavailable",
  "response_refused",
  "bootstrap_busy",
  "bootstrap_expired",
  "bootstrap_request_refused",
  "native_assistant_unavailable",
]);

function toNativeError(value: unknown): NativeOperationError {
  if (
    typeof value === "object" &&
    value !== null &&
    "code" in value &&
    typeof value.code === "string" &&
    knownErrorCodes.has(value.code as NativeErrorCode)
  ) {
    return new NativeOperationError(value.code as NativeErrorCode);
  }
  return new NativeOperationError("console_unavailable");
}

async function namedOperation<T>(command: string, arguments_: Record<string, unknown> = {}): Promise<T> {
  try {
    return await invoke<T>(command, arguments_);
  } catch (error: unknown) {
    throw toNativeError(error);
  }
}

export const nativeConsole = {
  status: () => namedOperation<ConsoleStatus>("console_status"),
  prepare: () => namedOperation<GeneratedLocalSecrets>("prepare_console"),
  discardPreparation: (generationId: string) =>
    namedOperation<void>("discard_console_preparation", { generationId }),
  confirmInitialization: (
    generationId: string,
    unlockPhrase: string,
    recoveryCode: string,
    confirmedCopies: boolean,
  ) =>
    namedOperation<ConsoleStatus>("confirm_console_initialization", {
      generationId,
      unlockPhrase,
      recoveryCode,
      confirmedCopies,
    }),
  unlock: (phrase: string) => namedOperation<ConsoleStatus>("unlock_console", { phrase }),
  preparePhraseChange: () => namedOperation<PreparedPhraseChange>("prepare_phrase_change"),
  confirmPhraseChange: (generationId: string, currentPhrase: string, newPhrase: string) =>
    namedOperation<void>("confirm_phrase_change", {
      generationId,
      currentPhrase,
      newPhrase,
    }),
  startBootstrap: (input: BootstrapStartInput) =>
    namedOperation<BootstrapSessionView>("start_bootstrap", { input }),
  bootstrapStatus: (requestId: string) =>
    namedOperation<BootstrapSessionView>("bootstrap_status", { requestId }),
  cancelBootstrap: (requestId: string) =>
    namedOperation<void>("cancel_bootstrap", { requestId }),
  lock: () => namedOperation<void>("lock_console"),
  cancelPendingRequests: () => namedOperation<void>("cancel_pending_requests"),
  pair: (input: PairingInput) => namedOperation<AssociationSummary>("pair_controller", { input }),
  readInfrastructure: (infrastructureId: string) =>
    namedOperation<InfrastructureView>("read_infrastructure", { infrastructureId }),
  readMachines: (infrastructureId: string) =>
    namedOperation<MachinesView>("read_machines", { infrastructureId }),
  putInfrastructure: (infrastructureId: string, label: string) =>
    namedOperation<InfrastructureView>("put_infrastructure", { infrastructureId, label }),
  putMachine: (infrastructureId: string, machineId: string, label: string) =>
    namedOperation<MachineMutationView>("put_machine", { infrastructureId, machineId, label }),
  rotateDevice: (infrastructureId: string) =>
    namedOperation<AssociationSummary>("rotate_device", { infrastructureId }),
  prepareRecoveryKeyRotation: () =>
    namedOperation<PreparedRecoveryRotation>("prepare_recovery_key_rotation"),
  confirmRecoveryKeyRotation: (
    generationId: string,
    newRecoveryCode: string,
    confirmedCopies: boolean,
  ) =>
    namedOperation<RecoveryRotationProgress>("confirm_recovery_key_rotation", {
      generationId,
      newRecoveryCode,
      confirmedCopies,
    }),
  resumeRecoveryKeyRotation: (oldRecoveryCode: string, newRecoveryCode: string) =>
    namedOperation<RecoveryRotationProgress>("resume_recovery_key_rotation", {
      oldRecoveryCode,
      newRecoveryCode,
    }),
  completeRecoveryKeyRotation: () =>
    namedOperation<void>("complete_recovery_key_rotation"),
  logout: (infrastructureId: string) =>
    namedOperation<void>("logout_session", { infrastructureId }),
};

export function localErrorMessage(code: NativeErrorCode): string {
  switch (code) {
    case "console_locked":
      return "Déverrouillez la Console pour continuer.";
    case "invalid_input":
      return "Les informations saisies ne respectent pas le format attendu.";
    case "authentication_failed":
      return "L’authentification a été refusée.";
    case "association_failed":
      return "L’association n’a pas pu être terminée. Vérifiez la fenêtre locale.";
    case "session_expired":
      return "La session a expiré. Une nouvelle preuve humaine est nécessaire.";
    case "controller_unavailable":
      return "La liaison privée avec cette infrastructure est indisponible.";
    case "response_refused":
      return "La réponse reçue ne respecte pas le contrat de sécurité.";
    case "bootstrap_busy":
      return "Un parcours d’amorçage est déjà actif.";
    case "bootstrap_expired":
      return "Le parcours d’amorçage a expiré et doit être recommencé.";
    case "bootstrap_request_refused":
      return "Le parcours d’amorçage demandé n’est plus utilisable.";
    case "native_assistant_unavailable":
      return "L’assistant natif d’amorçage est indisponible.";
    case "console_unavailable":
      return "La Console ne peut pas terminer cette opération.";
  }
}
