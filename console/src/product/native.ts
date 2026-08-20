import { invoke } from "@tauri-apps/api/core";
import type {
  AssociationSummary,
  BootstrapSessionView,
  BootstrapStartInput,
  ConsoleStatus,
  ExternalElementsView,
  ExternalWithdrawalView,
  GeneratedLocalSecrets,
  InfrastructureView,
  MachineMutationView,
  MachinesView,
  PairingInput,
  FrozenDefinitionView,
  PreparedPhraseChange,
  PreparedRecoveryRotation,
  RecoveryRotationProgress,
  ServiceDefinitionDraft,
  ServiceDefinitionPaste,
  ServiceDefinitionReview,
  ServiceDefinitionsProjection,
  PlanPairPresentation,
  PlanConsentSessionView,
  PlanDispatchAcceptedView,
  PlanDispatchesView,
} from "./models";

/// Le vocabulaire fermé des refus, en **une** liste.
///
/// Le type, la garde d’exécution et la table des phrases en dérivent tous les
/// trois. Ils ont été trois listes tenues à la main, et elles ont divergé : la
/// garde s’était arrêtée à un palier antérieur, si bien que huit codes que le
/// cœur émettait réellement étaient rendus à l’humain comme « la Console ne
/// peut pas terminer cette opération », alors que leur phrase existait, écrite,
/// juste à côté. Une seule source rend cette divergence impossible à écrire.
const nativeErrorCodes = [
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
  "bootstrap_entry_too_narrow",
  "native_assistant_unavailable",
  "plan_absent",
  "definition_absent",
  "plan_consent_request_refused",
  "plan_consent_expired",
  "plan_consent_unavailable",
  "unverified_plan",
  "unconfirmed_plan",
  "foreign_infrastructure",
  // Les six refus de `POST /v0/plan-approvals` — la seule route dont l’effet
  // sort de cette machine. Chacun nomme une suite différente, et c’est
  // exactement ce qu’aucun d’eux ne pouvait dire tant que la Console ne les
  // connaissait pas.
  "approval_signature_invalid",
  "approval_expired",
  "approval_pair_mismatch",
  "approval_definition_mismatch",
  "approval_sequence_invalid",
  "approval_already_dispatched",
] as const;

export type NativeErrorCode = (typeof nativeErrorCodes)[number];

export class NativeOperationError extends Error {
  readonly code: NativeErrorCode;
  /// Quel contrôle a refusé, quand le code seul ne suffit pas à agir. Le cœur
  /// ne le renseigne que là où sa phrase ne dit rien de la suite ; c’est une
  /// chaîne que le produit a choisie, jamais un écho de ce qui a été reçu.
  readonly detail: string | null;

  constructor(code: NativeErrorCode, detail: string | null = null) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = "NativeOperationError";
    this.code = code;
    this.detail = detail;
  }
}

const knownErrorCodes: ReadonlySet<NativeErrorCode> = new Set(nativeErrorCodes);

function toNativeError(value: unknown): NativeOperationError {
  if (
    typeof value === "object" &&
    value !== null &&
    "code" in value &&
    typeof value.code === "string" &&
    knownErrorCodes.has(value.code as NativeErrorCode)
  ) {
    const detail =
      "detail" in value && typeof value.detail === "string" ? value.detail : null;
    return new NativeOperationError(value.code as NativeErrorCode, detail);
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
  readExternalElements: (infrastructureId: string) =>
    namedOperation<ExternalElementsView>("read_external_elements", { infrastructureId }),
  withdrawExternalElement: (infrastructureId: string, elementId: string) =>
    namedOperation<ExternalWithdrawalView>("withdraw_external_element", {
      infrastructureId,
      elementId,
    }),
  // La validation d’un brouillon n’est jamais écrite ici : elle traverse le
  // miroir Rust, qui est la même grammaire que celle du Controller. Une Console
  // qui bornerait ses champs elle-même dériverait du document qui est gelé.
  reviewServiceDefinition: (draft: ServiceDefinitionDraft) =>
    namedOperation<ServiceDefinitionReview>("review_service_definition", { draft }),
  // Un collage ne peut que préremplir. La commande n’a pas d’infrastructure dans
  // sa signature parce qu’elle ne soumet rien : ce qu’elle rend repasse par la
  // relecture ci-dessus et par un humain.
  parseServiceDefinitionPaste: (pasted: string) =>
    namedOperation<ServiceDefinitionPaste>("parse_service_definition_paste", { pasted }),
  // Lire une paire gelée. La Console n’assemble rien : elle nomme une machine,
  // une révision déjà gelée et les trois valeurs qu’un déploiement choisit
  // réellement, et ce qui revient sont des phrases.
  readPlanPair: (
    infrastructureId: string,
    machineId: string,
    operation: string,
    definitionSlug: string,
    definitionDigest: string,
    imageDigest: string,
    localPort: number,
    originHost: string,
  ) =>
    namedOperation<PlanPairPresentation>("read_plan_pair", {
      infrastructureId,
      machineId,
      operation,
      definitionSlug,
      definitionDigest,
      imageDigest,
      localPort,
      originHost,
    }),
  // Ouvrir la fenêtre native sur la paire en cours d’examen. Le frontend ne
  // choisit pas l’identifiant de la demande : il le reçoit.
  openPlanConsent: (infrastructureId: string) =>
    namedOperation<PlanConsentSessionView>("open_plan_consent", { infrastructureId }),
  planConsentStatus: (requestId: string) =>
    namedOperation<PlanConsentSessionView>("plan_consent_status", { requestId }),
  cancelPlanConsent: (requestId: string) =>
    namedOperation<void>("cancel_plan_consent", { requestId }),
  // Signer et soumettre. La position et l’époque viennent de ce que la machine
  // a elle-même rapporté ; le Controller et la machine les revérifient.
  submitPlanDecision: (
    infrastructureId: string,
    requestId: string,
    approvalEpoch: number,
    sequence: number,
  ) =>
    namedOperation<PlanDispatchAcceptedView>("submit_plan_decision", {
      infrastructureId,
      requestId,
      approvalEpoch,
      sequence,
    }),
  // L'histoire bornée des lancements, telle que le Controller la tient : rien
  // n'y est filtré à l'entrée.
  readPlanDispatches: (infrastructureId: string) =>
    namedOperation<PlanDispatchesView>("read_plan_dispatches", { infrastructureId }),
  readServiceDefinitions: (infrastructureId: string) =>
    namedOperation<ServiceDefinitionsProjection>("read_service_definitions", { infrastructureId }),
  // Les deux arguments sont exactement ce que la relecture a produit : les
  // octets affichés et l’empreinte affichée à côté d’eux.
  freezeServiceDefinition: (
    infrastructureId: string,
    definitionDocument: string,
    definitionSha256: string,
  ) =>
    namedOperation<FrozenDefinitionView>("freeze_service_definition", {
      infrastructureId,
      definitionDocument,
      definitionSha256,
    }),
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
    case "bootstrap_entry_too_narrow":
      // Le refus du constat n°10 : il tombe avant toute fenêtre, il nomme ce
      // que l'action exige et les deux issues — et le détail à côté nomme ce
      // que l'entrée permet aujourd'hui. Personne n'est contraint d'élargir :
      // c'est un choix nommé.
      // Le conseil dit REMPLACER, et hors du groupe : ajouter une entrée
      // `ALL` à un compte qui appartient déjà au groupe `sudo` en fabrique
      // deux, et le produit refuse un listing ambigu — le conseil produisait
      // donc le refus suivant (mesuré le 20 août 2026, n°149 / n°157).
      return (
        "L’entrée sudoers du compte prêté ne permet pas cette action : installer exige " +
        "d’autoriser toute commande (ALL). Deux issues : remplacer son entrée par une " +
        "entrée unique autorisant ALL — le compte doit alors être hors du groupe sudo, " +
        "sans quoi il en porterait deux — ou prêter un accès root direct. Ce que " +
        "l’entrée permet aujourd’hui est nommé ci-dessous."
      );
    case "native_assistant_unavailable":
      return "L’assistant natif d’amorçage est indisponible.";
    case "plan_absent":
      return "Aucun plan n’est en cours d’examen. Relisez une paire avant d’ouvrir la fenêtre.";
    case "definition_absent":
      return "Ce Controller ne détient aucune révision gelée sous ce nom et cette empreinte.";
    case "plan_consent_request_refused":
      return "Cette demande d’approbation n’est plus ouverte. Relisez le plan et rouvrez la fenêtre.";
    case "plan_consent_expired":
      return "La fenêtre d’approbation a expiré. Rien n’a été signé ; rouvrez-la pour décider.";
    case "plan_consent_unavailable":
      return "La fenêtre d’approbation n’a pas pu s’ouvrir. Aucun plan n’a été approuvé.";
    case "unverified_plan":
      return "Cette paire ne rend pas les empreintes qu’elle annonce. Elle n’est pas affichable.";
    case "unconfirmed_plan":
      return "Ce plan n’a pas été confirmé dans la fenêtre native. Rien ne peut être signé.";
    case "foreign_infrastructure":
      return "Ce plan nomme une autre infrastructure que celle à laquelle cette Console est associée.";
    // Les six refus du trajet de commande. Chacun dit la même chose sur l’effet
    // — le Controller a refusé avant tout lancement — puis nomme une suite
    // différente, parce que ce qui doit être repris n’est pas le même.
    case "approval_signature_invalid":
      return "Le Controller n’a pas reconnu la signature de cette approbation. Rien n’a été lancé. Approuvez de nouveau ; si le refus se répète, l’identité de cette Console doit être renouvelée.";
    case "approval_expired":
      return "L’autorité de cette approbation avait expiré en arrivant au Controller. Rien n’a été lancé. Rouvrez la fenêtre et approuvez de nouveau.";
    case "approval_pair_mismatch":
      return "La paire soumise n’est pas celle que cette approbation nomme. Rien n’a été lancé. Relisez la paire, puis approuvez de nouveau.";
    case "approval_definition_mismatch":
      return "La définition soumise n’est pas la révision gelée que ce plan épingle. Rien n’a été lancé. Relisez la paire depuis la révision attendue.";
    case "approval_sequence_invalid":
      return "La position de cette machine a bougé depuis la lecture de ce plan : l’approbation vise une position déjà dépassée. Rien n’a été lancé. Le plan doit être reconstruit depuis la position actuelle, puis approuvé de nouveau.";
    case "approval_already_dispatched":
      return "Cette approbation a déjà été lancée : ses octets signés ne valent qu’une fois. Rien de nouveau n’a été lancé. Consultez les lancements avant de reconstruire un plan.";
    case "console_unavailable":
      return "La Console ne peut pas terminer cette opération.";
  }
}
