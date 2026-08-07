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
  | "summary"
  | "fleet"
  | "observations"
  | "external"
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

export type MachineView = {
  machine_id: string;
  label: string;
  enrollment_status: EnrollmentStatus;
  observation_status: ObservationStatus;
  observation: MachineObservation | null;
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
};

export type BootstrapSessionView = {
  schema_version: 1;
  request_id: string;
  mode: BootstrapMode;
  target: BootstrapTarget;
  step: "personal_access" | "root_access";
  actions: readonly ["audit_target_read_only"];
  lifecycle: "awaiting_native_assistant";
  expires_in_seconds: number;
};
