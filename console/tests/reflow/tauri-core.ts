// A stand-in for the Tauri IPC bridge, and nothing else.
//
// The reflow proof measures the frontend's geometry. Everything above this file
// is the product's own code: `src/product/native.ts` keeps its command names and
// its error mapping, `App.tsx` keeps its view machine, and the stylesheets under
// `src/design` are the thing under test. Only `invoke` is replaced, because the
// installed Console reaches its seven views through a Controller and a vault
// that a layout measurement has no business standing up.
//
// The payloads are deliberately hostile: labels without a single space, mixed
// scripts, bidirectional overrides and combining marks, at the length the API
// contract allows. A layout that survives them survives the ones a Controller
// will really send.

type Payload = Record<string, unknown>;

// 236 characters, one of them a run of 118 without a space. A frame that cannot
// break inside a word is a frame this token widens until the page scrolls.
const HOSTILE_INFRASTRUCTURE_LABEL =
  "Infrastructure de sauvegarde du site principal — " +
  "grappe-de-stockage-froid-hors-site-redondee-chiffree-verifiee-et-journalisee " +
  "‮noisivér‬ مخزن احتياطي " +
  "é́́́́ — dernier libellé";

const HOSTILE_MACHINE_LABEL =
  "Serveur de fichiers du premier étage — " +
  "hyperviseur-de-secours-avec-un-nom-que-personne-na-jamais-abrégé-et-qui-ne-se-coupe-nulle-part " +
  "مثال — dernier libellé";

const HOSTILE_EXTERNAL_LABEL =
  "Routeur du fournisseur d’accès — " +
  "boitier-pose-par-quelquun-dautre-que-your-cloud-na-jamais-installe-et-ne-gere-pas " +
  "‮tnallievélam‬ — dernier libellé";

const CONTROLLER_ID = "01J8Z9QK7C4X2M6V0T3B5N8W1D";
const INFRASTRUCTURE_ID = "01J8Z9QK7C4X2M6V0T3B5N8W2E";
const SECOND_INFRASTRUCTURE_ID = "01J8Z9QK7C4X2M6V0T3B5N8W3F";
const ORIGIN = "https://controller-principal.interne.example.invalid:8443";

function machine(index: number, status: string, gapped: boolean): Payload {
  return {
    machine_id: `machine-${index}-nom-technique-qui-ne-se-coupe-nulle-part-non-plus`,
    label: `${index}. ${HOSTILE_MACHINE_LABEL}`,
    enrollment_status: "active",
    observation_status: status,
    observation:
      status === "absent"
        ? null
        : {
            profile: "host-health.v1",
            sequence: 4096 + index,
            observed_at: "2026-08-07T04:12:44.512837Z",
            received_at: "2026-08-07T04:12:45.004311Z",
            observed_time_warning: index === 2,
            continuity: gapped ? "gapped" : "complete",
            gap_summary: gapped
              ? { range_count: 2, dropped_count: 17, first_sequence: 4001, last_sequence: 4090 }
              : null,
            health: {
              uptime: { status: "ok", uptime_seconds: 864_213, error: null },
              memory: { status: "ok", total_bytes: 16_777_216_000, available_bytes: 4_194_304_000, error: null },
              rootfs: { status: "error", total_bytes: null, available_bytes: null, error: "source_unavailable" },
            },
          },
  };
}

function externalElement(index: number, state: string, reason: string | null, status: string): Payload {
  return {
    element_id: `externe-${index}-identifiant-long-sans-espace-ni-coupure-possible`,
    machine_id: `machine-1-nom-technique-qui-ne-se-coupe-nulle-part-non-plus`,
    label: `${index}. ${HOSTILE_EXTERNAL_LABEL}`,
    kind: index % 2 === 0 ? "external_service" : "external_passage",
    probe_port: 8443 + index,
    declared_at: "2026-07-30T09:00:00.000000Z",
    state,
    reason,
    observed_at: state === "declared" ? null : "2026-08-06T22:41:03.998217Z",
    observation_status: status,
  };
}

function association(infrastructureId: string, label: string | null): Payload {
  return {
    controller_id: CONTROLLER_ID,
    infrastructure_id: infrastructureId,
    infrastructure_label: label,
    origin: ORIGIN,
    device_status: "active",
    certificate_expires_at: "2026-08-19T06:00:00Z",
  };
}

function requestedState(): string {
  return new URLSearchParams(location.search).get("state") ?? "unlocked";
}

function lockState(): string {
  const state = requestedState();
  if (state === "uninitialized" || state === "locked") return state;
  return "unlocked";
}

const recoveryRotation: Payload = {
  schema_version: 1,
  new_code_sha256: "9f2c1b7e4a6d8035c1e7f4a29b0d6c85173e4f9a2b8c0d6e5f4a3b2c1d0e9f80",
  controllers: [
    {
      controller_id: CONTROLLER_ID,
      infrastructure_id: INFRASTRUCTURE_ID,
      operation_id: "01J8Z9QK7C4X2M6V0T3B5N8W9Z",
      target_recovery_epoch: 4,
      status: "pending",
    },
    {
      controller_id: `${CONTROLLER_ID}B`,
      infrastructure_id: SECOND_INFRASTRUCTURE_ID,
      operation_id: "01J8Z9QK7C4X2M6V0T3B5N8WA0",
      target_recovery_epoch: 4,
      status: "failed",
    },
  ],
};

function consoleStatus(): Payload {
  return {
    schema_version: 1,
    lock_state: lockState(),
    associations: [
      association(INFRASTRUCTURE_ID, HOSTILE_INFRASTRUCTURE_LABEL),
      association(SECOND_INFRASTRUCTURE_ID, null),
    ],
    recovery_rotation: lockState() === "unlocked" ? recoveryRotation : null,
  };
}

const answers: Record<string, () => unknown> = {
  console_status: consoleStatus,
  prepare_console: () => ({
    generation_id: "01J8Z9QK7C4X2M6V0T3B5N8WB1",
    unlock_phrase: "chataigne bourrasque velours enclume phosphore tourbillon",
    recovery_code: "K7QW-2M4X-9ZFA-3TPD-6RHN-8YCE-5JVB-1SLU",
  }),
  discard_console_preparation: () => null,
  confirm_console_initialization: consoleStatus,
  unlock_console: consoleStatus,
  prepare_phrase_change: () => ({
    generation_id: "01J8Z9QK7C4X2M6V0T3B5N8WC2",
    new_unlock_phrase: "meridien coquelicot sarabande falaise grenadine ossature",
  }),
  confirm_phrase_change: () => null,
  lock_console: () => null,
  cancel_pending_requests: () => null,
  pair_controller: () => association(INFRASTRUCTURE_ID, HOSTILE_INFRASTRUCTURE_LABEL),
  read_infrastructure: () => ({
    schema_version: 1,
    controller_id: CONTROLLER_ID,
    infrastructure_id: INFRASTRUCTURE_ID,
    initialized: true,
    label: HOSTILE_INFRASTRUCTURE_LABEL,
    inventory_revision: 42,
  }),
  read_machines: () => ({
    schema_version: 1,
    controller_id: CONTROLLER_ID,
    infrastructure_id: INFRASTRUCTURE_ID,
    inventory_revision: 42,
    relay_status: "clock_untrusted",
    relay_snapshot_at: "2026-08-07T04:12:45.004311Z",
    machines: [
      machine(1, "recent", false),
      machine(2, "old", true),
      machine(3, "absent", false),
      machine(4, "untrusted", true),
    ],
  }),
  read_external_elements: () => ({
    schema_version: 1,
    controller_id: CONTROLLER_ID,
    infrastructure_id: INFRASTRUCTURE_ID,
    external_revision: 7,
    elements: [
      externalElement(1, "verified", null, "old"),
      externalElement(2, "unverifiable", "port_is_managed", "recent"),
      externalElement(3, "declared", null, "absent"),
      externalElement(4, "contradicted", null, "recent"),
    ],
  }),
  withdraw_external_element: () => ({ schema_version: 1, external_revision: 8, element_id: "externe-1" }),
  put_infrastructure: () => ({
    schema_version: 1,
    controller_id: CONTROLLER_ID,
    infrastructure_id: INFRASTRUCTURE_ID,
    initialized: true,
    label: HOSTILE_INFRASTRUCTURE_LABEL,
    inventory_revision: 43,
  }),
  put_machine: () => ({ schema_version: 1, inventory_revision: 43, machine_id: "machine-1", label: "x" }),
  rotate_device: () => association(INFRASTRUCTURE_ID, HOSTILE_INFRASTRUCTURE_LABEL),
  prepare_recovery_key_rotation: () => ({
    generation_id: "01J8Z9QK7C4X2M6V0T3B5N8WD3",
    new_recovery_code: "T4NB-8XQK-2WFH-6ZDC-9JRM-5PVS-1YLA-7EGU",
    target_count: 2,
  }),
  confirm_recovery_key_rotation: () => recoveryRotation,
  resume_recovery_key_rotation: () => recoveryRotation,
  complete_recovery_key_rotation: () => null,
  logout_session: () => null,
};

export async function invoke<T>(command: string, _arguments?: Payload): Promise<T> {
  const answer = answers[command];
  if (!answer) throw { code: "console_unavailable" };
  return answer() as T;
}
