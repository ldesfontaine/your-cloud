export type ConsoleLockState = "uninitialized" | "locked" | "unlocked";
export type RelayStatus = "available" | "unavailable" | "clock_untrusted";
export type EnrollmentStatus = "active" | "revoked" | null;
export type ObservationStatus = "absent" | "recent" | "old" | "untrusted" | null;
export type Continuity = "complete" | "gapped";
export type HealthStatus = "ok" | "error";

export type ExternalKind = "external_service" | "external_passage";
export type ExternalState = "declared" | "verified" | "contradicted" | "unverifiable";
export type ExternalReason =
  | "nothing_listening"
  | "response_too_large"
  | "machine_unreachable"
  | "port_is_managed";

// L’ancienneté d’un constat externe emprunte les mots de l’inventaire géré et
// jamais des synonymes : « ancien » ne doit avoir qu’un seul sens sur un écran
// où les machines gérées et les éléments externes s’affichent côte à côte. Un
// élément externe n’a pas d’état de transport, donc pas de « untrusted ».
export type ExternalObservationStatus = Exclude<ObservationStatus, "untrusted" | null>;

export type ViewName =
  | "local-access"
  | "infrastructures"
  | "association"
  | "create-infrastructure"
  | "summary"
  | "fleet"
  | "observations"
  | "external"
  | "services"
  | "plans"
  | "profile";

export type AssociationSummary = {
  controller_id: string;
  infrastructure_id: string;
  infrastructure_label: string | null;
  origin: string;
  device_status: "candidate" | "active" | "revoked";
  certificate_expires_at: string | null;
};

export type ConsoleStatus = {
  schema_version: 1;
  lock_state: ConsoleLockState;
  associations: AssociationSummary[];
  recovery_rotation: RecoveryRotationProgress | null;
};

export type RecoveryControllerProgress = {
  controller_id: string;
  infrastructure_id: string;
  operation_id: string;
  target_recovery_epoch: number;
  status: "pending" | "failed" | "completed";
};

export type RecoveryRotationProgress = {
  schema_version: 1;
  new_code_sha256: string;
  controllers: RecoveryControllerProgress[];
};

export type PreparedRecoveryRotation = {
  generation_id: string;
  new_recovery_code: string;
  target_count: number;
};

export type PreparedPhraseChange = {
  generation_id: string;
  new_unlock_phrase: string;
};

export type InfrastructureView = {
  schema_version: 1;
  controller_id: string;
  infrastructure_id: string;
  initialized: boolean;
  label: string | null;
  inventory_revision: number;
};

export type GapSummary = {
  range_count: number;
  dropped_count: number;
  first_sequence: number;
  last_sequence: number;
};

export type ScalarHealth = {
  status: HealthStatus;
  uptime_seconds: number | null;
  error: "source_unavailable" | "source_invalid" | null;
};

export type CapacityHealth = {
  status: HealthStatus;
  total_bytes: number | null;
  available_bytes: number | null;
  error: "source_unavailable" | "source_invalid" | null;
};

export type MachineObservation = {
  profile: "host-health.v1";
  sequence: number;
  observed_at: string;
  received_at: string;
  observed_time_warning: boolean;
  continuity: Continuity;
  gap_summary: GapSummary | null;
  health: {
    uptime: ScalarHealth;
    memory: CapacityHealth;
    rootfs: CapacityHealth;
  };
};

/// La position que le Controller peut attester pour une machine, et si elle est
/// certaine. `last_reported_sequence` à zéro veut dire que ce Controller
/// n’atteste rien — ce qui n’est pas la même chose qu’une machine qui n’a rien
/// consommé, et l’écran ne confond jamais les deux. `certain` est faux dès
/// qu’un lancement n’a pas été rapporté.
export type CommandPosition = {
  last_reported_sequence: number;
  certain: boolean;
};

export type MachineView = {
  machine_id: string;
  label: string;
  enrollment_status: EnrollmentStatus;
  observation_status: ObservationStatus;
  observation: MachineObservation | null;
  /// Ce que la Console doit signer : le successeur exact de cette position.
  /// Elle vient de ce que la machine a elle-même rapporté, jamais d’une
  /// supposition de cette Console.
  command_position: CommandPosition;
};

export type MachinesView = {
  schema_version: 1;
  controller_id: string;
  infrastructure_id: string;
  inventory_revision: number;
  relay_status: RelayStatus;
  relay_snapshot_at: string | null;
  machines: MachineView[];
};

// Une déclaration externe ne porte aucune capacité, et le type le dit : les
// quatre absences annoncées sont des propriétés de ce qu’est un élément externe,
// identiques pour toutes les lignes, et la Console les tient du contexte de la
// route. Aucun champ ci-dessous ne peut donc les contredire.
type ExternalElementDeclaration = {
  element_id: string;
  machine_id: string;
  label: string;
  kind: ExternalKind;
  probe_port: number;
  declared_at: string;
};

// Les trois états du contrat, et jamais un quatrième déguisé. « Déclaré » est
// l’état d’un élément que personne n’a lu : il n’a ni date, ni ancienneté, et
// c’est le type qui le tient plutôt qu’une garde d’affichage. Un constat porte
// toujours sa date, et son ancienneté reste une dimension séparée de son état.
export type ExternalElementView =
  | (ExternalElementDeclaration & {
      state: Extract<ExternalState, "declared">;
      reason: null;
      observed_at: null;
      observation_status: Extract<ExternalObservationStatus, "absent">;
    })
  | (ExternalElementDeclaration & {
      state: Extract<ExternalState, "verified" | "contradicted">;
      reason: null;
      observed_at: string;
      observation_status: Exclude<ExternalObservationStatus, "absent">;
    })
  | (ExternalElementDeclaration & {
      state: Extract<ExternalState, "unverifiable">;
      reason: ExternalReason;
      observed_at: string;
      observation_status: Exclude<ExternalObservationStatus, "absent">;
    });

export type ExternalElementsView = {
  schema_version: 1;
  controller_id: string;
  infrastructure_id: string;
  external_revision: number;
  elements: ExternalElementView[];
};

export type ExternalWithdrawalView = {
  schema_version: 1;
  external_revision: number;
  element_id: string;
};

export type MachineMutationView = {
  schema_version: 1;
  inventory_revision: number;
  machine_id: string;
  label: string;
};

// La définition de service utilisateur est le seul document de ce produit qu’un
// humain écrit. Rien de ce qui suit ne décrit un effet : ni compte, ni chemin
// hôte, ni valeur de secret, ni machine. Tout cela est dérivé du slug par la
// machine qui agit, et aucun champ ci-dessous ne peut le déplacer.
export type ServiceDefinitionDocument = {
  schema_version: 1;
  slug: string;
  image_repository: string;
  container_port: number;
  volumes: string[];
  tmpfs: string[];
  environment: string[];
  secret_keys: string[];
};

// Ce que l’humain remplit, avant que ce soit une définition. Il n’y a pas de
// `schema_version` : la Console écrit la seule version qu’elle connaît, et un
// brouillon qui pourrait en nommer une autre demanderait un document que ce
// palier ne lit pas.
export type ServiceDefinitionDraft = Omit<ServiceDefinitionDocument, "schema_version">;

// Le champ d’un refus, et jamais un champ d’écran : « document » nomme le cas où
// tous les champs tiennent leurs bornes et où le document dépasse la sienne.
export type ServiceDefinitionFieldName =
  | "schema_version"
  | "slug"
  | "image_repository"
  | "container_port"
  | "volumes"
  | "tmpfs"
  | "environment"
  | "secret_keys"
  | "document";

// La liste fermée des refus que le miroir Rust nomme. Une entrée ajoutée ici
// sans sa phrase est un trou que le contrat de source rougit : la Console ne
// rend jamais un refus sans le dire en français.
export type ServiceDefinitionRefusalName =
  | "unknown_schema_version"
  | "slug_grammar"
  | "slug_reserved"
  | "image_repository_pinned"
  | "image_repository_grammar"
  | "container_port_range"
  | "list_too_long"
  | "container_path_grammar"
  | "mounts_overlap"
  | "environment_line_shape"
  | "key_grammar"
  | "value_grammar"
  | "key_already_declared"
  | "document_too_large";

export type ServiceDefinitionFieldRefusal = {
  field: ServiceDefinitionFieldName;
  entry: number | null;
  refusal: ServiceDefinitionRefusalName;
};

// Les deux états d’un brouillon, et le type interdit le troisième : un brouillon
// refusé ne porte ni octets, ni empreinte, ni ligne de conséquence, donc rien
// que la vue puisse soumettre. Le bouton qui gèle n’existe que dans la branche
// « ready ».
export type ServiceDefinitionReview =
  | {
      state: "refused";
      schema_version: 1;
      refusals: ServiceDefinitionFieldRefusal[];
    }
  | {
      state: "ready";
      schema_version: 1;
      slug: string;
      definition_document: string;
      definition_sha256: string;
      interpolates_origin_host: boolean;
      confirmation_lines: string[];
    };

export type FrozenDefinitionView = {
  slug: string;
  definition_sha256: string;
  frozen_at: string;
  definition_document: string;
  document: ServiceDefinitionDocument;
  interpolates_origin_host: boolean;
};

// Aucune instance n’apparaît ici, et l’absence est l’état du produit plutôt
// qu’un oubli de cette projection : rien entre le Controller et la Console ne
// projette quelle machine exécute quelle révision.
export type ServiceDefinitionsProjection = {
  schema_version: 1;
  definition_revision: number;
  definitions: FrozenDefinitionView[];
};

export type PasteSource = "container_command" | "compose_document" | "unrecognised";

export type PasteNoteName =
  | "nothing_recognised"
  | "paste_too_large"
  | "single_service_only"
  | "image_pin_dropped"
  | "host_side_dropped"
  | "unsupported_directive_dropped"
  | "environment_entry_dropped"
  | "no_image_found";

export type PasteNote = {
  note: PasteNoteName;
  subjects: string[];
};

// Un collage rend un brouillon et rien d’autre : ni document canonique, ni
// empreinte, ni quoi que ce soit qui puisse être soumis.
export type ServiceDefinitionPaste = {
  schema_version: 1;
  source: PasteSource;
  draft: ServiceDefinitionDraft;
  notes: PasteNote[];
};

export type PairingInput = {
  mode: "enrollment" | "recovery";
  origin: string;
  temporary_origin: string;
  controller_id: string;
  infrastructure_id: string;
  server_ca_pem: string;
  server_spki_sha256: string;
  window_id: string;
  window_code: string;
  recovery_code: string;
};

export type GeneratedLocalSecrets = {
  generation_id: string;
  unlock_phrase: string;
  recovery_code: string;
};

export type BootstrapMode = "create" | "replace";
export type BootstrapAccessKind = "administrator" | "root";

export type BootstrapTarget = {
  host: string;
  port: number;
  username: string;
  host_key_sha256: string;
  access_kind: BootstrapAccessKind;
};

export type BootstrapStartInput = {
  mode: BootstrapMode;
  target: BootstrapTarget;
  // L'action que l'humain veut approuver, et ce qu'elle exige. Absents : la
  // demande d'audit d'hier, inchangée. La cohérence — quelle action exige
  // quoi — est jugée par la validation du scope côté natif, jamais ici.
  action?: BootstrapActionName;
  declared_target?: { private: boolean; normally_on: boolean };
  machine_configuration?: {
    listen: string;
    allowed_source: string;
    relay_endpoint: string;
  };
};

export type BootstrapActionName =
  | "audit_target_read_only"
  | "install_server_bundle"
  | "activate_approved_controller";

export type BootstrapSessionView = {
  schema_version: 1;
  request_id: string;
  mode: BootstrapMode;
  target: BootstrapTarget;
  step: "personal_access" | "root_access";
  actions: readonly [BootstrapActionName];
  lifecycle:
    | "awaiting_native_assistant"
    // Les issues terminales que la clôture d'affaires nomme : la vue en fait
    // des phrases, et l'état partiel n'est jamais annoncé comme succès — le
    // terminal dit ce qui s'est conclu, l'action de la session dit ce que cela
    // couvre.
    | "access_verified"
    | "refused"
    | "cancelled"
    | "unavailable";
  expires_in_seconds: number;
};

/// La présentation d’une paire gelée : les phrases qu’un humain lit, et les deux
/// empreintes qui terminent les deux dernières. Aucun document ne traverse — les
/// octets canoniques restent dans le cœur, atteignables derrière un geste
/// explicite et jamais comme forme par défaut.
export type PlanPairPresentation = {
  schema_version: 1;
  machine_id: string;
  plan_sha256: string;
  rollback_sha256: string;
  confirmation_lines: readonly string[];
};

/// Ce que le frontend lit d’une session de consentement : quelle demande, et
/// combien de temps il reste. Ni empreinte ni phrase : la fenêtre les a
/// montrées, et les répéter ici serait un second endroit où elles pourraient
/// différer de ce qui a été affiché.
export type PlanConsentSessionView = {
  schema_version: 1;
  request_id: string;
  remaining_millis: number;
  state: "open" | "answered";
  confirmed: boolean;
};

/// Un dispatch tel que la Console le relit. Les états sont ceux du contrat, et
/// `launched_unreported` en est un à part entière : il n’est ni un succès ni un
/// échec, et la vue le rend comme tel.
export type PlanDispatchState =
  | "in_flight"
  | "not_launched"
  | "machine_refused"
  | "reported"
  | "launched_unreported";

export type PlanDispatchEntryView = {
  approval_sha256: string;
  machine_id: string;
  operation: string;
  approval_epoch: number;
  sequence: number;
  plan_sha256: string;
  rollback_sha256: string;
  state: PlanDispatchState;
  accepted_at_unix: number;
  finished_at_unix: number;
  expires_at_unix: number;
  machine_sentence: string;
  controller_observation: string;
  /// La révision que le plan approuvé épinglait. Elle vient du plan, jamais du
  /// rapport, et elle a été tenue deux fois avant d'être enregistrée.
  definition_slug: string;
  definition_sha256: string;
  reported_changed: boolean;
  reported_outcome: string;
};

export type PlanDispatchAcceptedView = {
  schema_version: 1;
  dispatch: PlanDispatchEntryView;
};

export type PlanDispatchesView = {
  schema_version: 1;
  dispatches: readonly PlanDispatchEntryView[];
};
