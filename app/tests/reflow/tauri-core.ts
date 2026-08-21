// A stand-in for the Tauri IPC bridge, and nothing else.
//
// The reflow proof measures the frontend's geometry. Everything above this file
// is the product's own code: `src/product/native.ts` keeps its command names and
// its error mapping, `App.tsx` keeps its view machine, and the stylesheets under
// `src/design` are the thing under test. Only `invoke` is replaced, because the
// installed App reaches its views through a Controller and a vault that a
// layout measurement has no business standing up.
//
// The payloads are deliberately hostile: labels without a single space, mixed
// scripts, bidirectional overrides and combining marks, at the length the API
// contract allows. A layout that survives them survives the ones a Controller
// will really send.
//
// The definitions of the Services view are hostile in the other direction. Their
// grammar admits no bidirectional override and no combining mark, so the worst
// case is not a strange byte but a document at the maximum of what the contract
// accepts: the longest slug, the longest repository, the deepest container paths
// and the longest inert value. Those are the lengths that widen a card, a
// consequence panel and a two-column diff.

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

// Une définition est bornée par sa grammaire, donc le pire cas de sa vue n'est
// pas un octet hostile mais un document au maximum de ce que le contrat admet :
// le plus long slug, le plus long dépôt, la plus longue valeur d'environnement
// et les chemins les plus profonds. Ce sont ces longueurs-là qui élargissent une
// carte, un panneau de conséquences et un diff à deux colonnes.
const LONGEST_SLUG = "definition-notes";
const LONG_IMAGE_REPOSITORY =
  "registry.interne.exemple.invalid:5000/equipe-plateforme/applications-metier/" +
  "service-de-notes-de-laboratoire-sans-abreviation";
const LONG_ENVIRONMENT_VALUE = `NOTES_BANNIERE=${"contenu-sans-espace-que-rien-ne-coupe-".repeat(6)}fin`;
const LONG_CONTAINER_PATH = "/srv/donnees/equipe-plateforme/service-de-notes/archives-quotidiennes";
const PLAN_DIGEST = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809";
const ROLLBACK_DIGEST = "4f1c9d0a7b6e5d4c3b2a19087f6e5d4c3b2a19087f6e5d4c3b2a19087f6e5d4c";
// Un hôte à la largeur que la grammaire des plans autorise : la phrase
// d'origine est la plus large que ce produit sache écrire.
const LONG_ORIGIN_HOST = `${"notes-de-lequipe-plateforme.".repeat(7)}exemple.test`;
// Une phrase que ce produit n'a pas écrite : elle est citée telle quelle, et
// elle est mesurée à la largeur qu'une machine peut réellement rendre.
const HOSTILE_MACHINE_SENTENCE =
  "approval sequence 12 is not the exact successor of 9: this machine consumed nothing and is unchanged";

let dispatchOrdinal = 0;
function dispatchEntry(state: string) {
  dispatchOrdinal += 1;
  return {
    approval_sha256: `${dispatchOrdinal}`.padStart(64, "a"),
    machine_id: "machine-1",
    operation: "deploy_user_service",
    approval_epoch: 3,
    sequence: 12 - dispatchOrdinal,
    plan_sha256: PLAN_DIGEST,
    rollback_sha256: ROLLBACK_DIGEST,
    state,
    accepted_at_unix: 1786000000 + dispatchOrdinal,
    finished_at_unix: state === "in_flight" ? 0 : 1786000060 + dispatchOrdinal,
    expires_at_unix: 1786000900 + dispatchOrdinal,
    machine_sentence: state === "machine_refused" ? HOSTILE_MACHINE_SENTENCE : "",
    controller_observation:
      state === "launched_unreported"
        ? "the channel closed before this Controller could read an answer"
        : state === "not_launched"
          ? "the connection failed before the first byte of the wrapper; the machine is unchanged"
          : "",
    definition_slug: "service-de-notes",
    definition_sha256: PLAN_DIGEST,
    reported_changed: state === "reported",
    reported_outcome: state === "reported" ? "applied" : "",
  };
}

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

function appStatus(): Payload {
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

function definitionDocument(volumes: string[], environment: string[]): string {
  return JSON.stringify({
    schema_version: 1,
    slug: LONGEST_SLUG,
    image_repository: LONG_IMAGE_REPOSITORY,
    container_port: 8080,
    volumes,
    tmpfs: ["/tmp"],
    environment,
    secret_keys: ["NOTES_JETON_ADMINISTRATION"],
  });
}

function frozenDefinition(
  digest: string,
  frozenAt: string,
  volumes: string[],
  environment: string[],
): Payload {
  const document = definitionDocument(volumes, environment);
  return {
    slug: LONGEST_SLUG,
    definition_sha256: digest,
    frozen_at: frozenAt,
    definition_document: document,
    document: JSON.parse(document),
    interpolates_origin_host: true,
  };
}

// Le panneau de conséquences est la seule chose qu'un humain lit avant de geler,
// donc c'est lui qui doit tenir : des phrases entières, les plus longues que la
// dérivation produise, et jamais une abréviation qui ne rendrait le cadre
// mesurable qu'en cachant ce qu'il doit dire.
const CONSEQUENCE_LINES: string[] = [
  `Service défini : ${LONGEST_SLUG}`,
  "Révision à geler : 4f1c9d0a7b6e5d4c3b2a19087f6e5d4c3b2a19087f6e5d4c3b2a19087f6e5d4c",
  "Ce que geler fait : le Controller garde ces octets sous cette empreinte. Aucun compte, aucun répertoire, aucune fiche et aucun plan ne naît de ce gel, et aucune machine n’est contactée.",
  `Compte dérivé sur la machine : your-cloud-user-${LONGEST_SLUG}, créé le jour où un plan de déploiement approuvé pose ce service`,
  `Foyer dérivé : /var/lib/your-cloud-user-${LONGEST_SLUG}/`,
  `Dépôt d’image : ${LONG_IMAGE_REPOSITORY}`,
  `Image exécutée : ${LONG_IMAGE_REPOSITORY}@<empreinte choisie par un plan> — une définition dit d’où les images viennent, jamais laquelle`,
  `Volume durable : ${LONG_CONTAINER_PATH} dans le conteneur, tenu sur la machine dans /var/lib/your-cloud-user-${LONGEST_SLUG}/volumes${LONG_CONTAINER_PATH}`,
  "Ligne de la fiche : PublishPort=127.0.0.1:<port local choisi par un plan>:8080 — le service n’écoute que sur la boucle locale de sa machine",
  "Ligne de la fiche : ReadOnly=true",
  `Ligne de la fiche : Environment=${LONG_ENVIRONMENT_VALUE}`,
  `Ligne de la fiche : EnvironmentFile=/var/lib/your-cloud-user-${LONGEST_SLUG}/secrets.env`,
  "Confinement de sortie : le compte rejoint la table inet your-cloud-egress. Ce service ne parle à personne : sortie refusée hors boucle locale et réponses établies, et aucun champ d’aucun document ne peut y percer un trou.",
  "Révision suivante : renommer un chemin conteneur monte un répertoire neuf et vide. L’ancien sous-arbre survit sous le foyer ; le déplacer vous appartient, et ce produit ne l’infère jamais.",
];

const answers: Record<string, () => unknown> = {
  app_status: appStatus,
  prepare_app: () => ({
    generation_id: "01J8Z9QK7C4X2M6V0T3B5N8WB1",
    unlock_phrase: "chataigne bourrasque velours enclume phosphore tourbillon",
    recovery_code: "K7QW-2M4X-9ZFA-3TPD-6RHN-8YCE-5JVB-1SLU",
  }),
  discard_app_preparation: () => null,
  confirm_app_initialization: appStatus,
  unlock_app: appStatus,
  prepare_phrase_change: () => ({
    generation_id: "01J8Z9QK7C4X2M6V0T3B5N8WC2",
    new_unlock_phrase: "meridien coquelicot sarabande falaise grenadine ossature",
  }),
  confirm_phrase_change: () => null,
  lock_app: () => null,
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
  // La relecture rend toujours un brouillon prêt : la géométrie mesurée est
  // celle du panneau de conséquences, qui n'est atteignable qu'ainsi. Le
  // formulaire refusé se mesure par ses phrases de refus, que la même page
  // affiche sous les champs quand le miroir en nomme.
  review_service_definition: () => ({
    state: "ready",
    schema_version: 1,
    slug: LONGEST_SLUG,
    definition_document: definitionDocument(
      [LONG_CONTAINER_PATH, "/var/lib/notes"],
      [LONG_ENVIRONMENT_VALUE, "NOTES_ORIGINE={origin_host}"],
    ),
    definition_sha256: "4f1c9d0a7b6e5d4c3b2a19087f6e5d4c3b2a19087f6e5d4c3b2a19087f6e5d4c",
    interpolates_origin_host: true,
    confirmation_lines: CONSEQUENCE_LINES,
  }),
  parse_service_definition_paste: () => ({
    schema_version: 1,
    source: "compose_document",
    draft: {
      slug: LONGEST_SLUG,
      image_repository: LONG_IMAGE_REPOSITORY,
      container_port: 8080,
      volumes: [LONG_CONTAINER_PATH],
      tmpfs: ["/tmp"],
      environment: [LONG_ENVIRONMENT_VALUE],
      secret_keys: [],
    },
    notes: [
      { note: "single_service_only", subjects: ["web", "base-de-donnees-de-notes", "cache"] },
      { note: "image_pin_dropped", subjects: [`${LONG_IMAGE_REPOSITORY}:2026.08.1-stable`] },
      { note: "unsupported_directive_dropped", subjects: ["networks", "deploy", "cap_add"] },
    ],
  }),
  read_service_definitions: () => ({
    schema_version: 1,
    definition_revision: 3,
    definitions: [
      frozenDefinition(
        "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809",
        "2026-08-01T09:14:02.118374Z",
        [LONG_CONTAINER_PATH],
        [LONG_ENVIRONMENT_VALUE],
      ),
      frozenDefinition(
        "4f1c9d0a7b6e5d4c3b2a19087f6e5d4c3b2a19087f6e5d4c3b2a19087f6e5d4c",
        "2026-08-06T18:41:55.902611Z",
        [LONG_CONTAINER_PATH, "/var/lib/notes"],
        [LONG_ENVIRONMENT_VALUE, "NOTES_ORIGINE={origin_host}"],
      ),
    ],
  }),
  freeze_service_definition: () =>
    frozenDefinition(
      "4f1c9d0a7b6e5d4c3b2a19087f6e5d4c3b2a19087f6e5d4c3b2a19087f6e5d4c",
      "2026-08-06T18:41:55.902611Z",
      [LONG_CONTAINER_PATH, "/var/lib/notes"],
      [LONG_ENVIRONMENT_VALUE, "NOTES_ORIGINE={origin_host}"],
    ),
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
  // Le trajet de commande. Les valeurs sont hostiles par construction : une
  // phrase d'origine à sa largeur maximale, une phrase de machine que ce
  // produit n'a pas écrite, et une histoire portant les quatre états qu'un
  // humain doit pouvoir distinguer — dont « lancé, non rapporté », qui n'est ni
  // un succès ni un échec.
  read_plan_pair: () => ({
    schema_version: 1,
    machine_id: "machine-1",
    plan_sha256: PLAN_DIGEST,
    rollback_sha256: ROLLBACK_DIGEST,
    confirmation_lines: [
      "Machine : machine-1",
      "Opération : déployer le service utilisateur",
      "Service défini : service-de-notes",
      `Révision de la définition : ${PLAN_DIGEST}`,
      `Image : ${LONG_IMAGE_REPOSITORY}@sha256:${PLAN_DIGEST}`,
      `Digest de l’image : sha256:${PLAN_DIGEST}`,
      "Port local : 127.0.0.1:8443",
      `Origine : ${LONG_ORIGIN_HOST}, portée par les lignes de la définition qui nomment {origin_host}`,
      "Ce que la révision décide : le compte, le foyer, les volumes, l’environnement et les noms de secrets viennent de la définition gelée sous cette empreinte, et d’aucun champ de ce plan",
      "Rollback : retirer le service utilisateur, sur la même machine et le même slug",
      `Empreinte du plan : ${PLAN_DIGEST}`,
      `Empreinte du rollback : ${ROLLBACK_DIGEST}`,
    ],
  }),
  open_plan_consent: () => ({
    schema_version: 1,
    request_id: "00112233445566778899aabbccddeeff",
    remaining_millis: 300000,
    state: "open",
    confirmed: false,
  }),
  plan_consent_status: () => ({
    schema_version: 1,
    request_id: "00112233445566778899aabbccddeeff",
    remaining_millis: 240000,
    state: "open",
    confirmed: false,
  }),
  cancel_plan_consent: () => null,
  submit_plan_decision: () => ({ schema_version: 1, dispatch: dispatchEntry("reported") }),
  read_plan_dispatches: () => ({
    schema_version: 1,
    dispatches: [
      dispatchEntry("reported"),
      dispatchEntry("launched_unreported"),
      dispatchEntry("machine_refused"),
      dispatchEntry("not_launched"),
    ],
  }),
  logout_session: () => null,
};

export async function invoke<T>(command: string, _arguments?: Payload): Promise<T> {
  const answer = answers[command];
  if (!answer) throw { code: "app_unavailable" };
  return answer() as T;
}
