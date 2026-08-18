mod approval;
mod approval_consent;
mod monotonic;
mod plan;
mod plan_v2;
mod plan_v3;
mod service_definition;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

pub use approval::{
    ApprovalEnvelopeV1, ApprovalOperation, ApprovalPrivilege, SignedApprovalV1,
    APPROVAL_DIGEST_BYTES, APPROVAL_DIGEST_ENCODED_BYTES, APPROVAL_INFRASTRUCTURE_BYTES,
    APPROVAL_PUBLIC_KEY_BYTES, APPROVAL_SCHEMA_VERSION, APPROVAL_SIGNATURE_BYTES,
    APPROVAL_TRANSCRIPT_DOMAIN, MAX_APPROVAL_LIFETIME_SECONDS, MAX_APPROVAL_MACHINE_BYTES,
    MAX_APPROVAL_PRIVILEGES, MAX_SIGNED_APPROVAL_BYTES,
};
pub use approval_consent::{
    folded_line_count, ApprovalConsentDecision, ApprovalConsentOutcomeKind,
    ApprovalConsentOutcomeV1, ApprovalConsentV1, APPROVAL_CONSENT_FOLD_COLUMNS,
    APPROVAL_CONSENT_SCHEMA_VERSION, MAX_APPROVAL_CONSENT_FOLDED_LINES,
    MAX_APPROVAL_CONSENT_FRAME_BYTES, MAX_APPROVAL_CONSENT_LINES, MAX_APPROVAL_CONSENT_LINE_BYTES,
    MAX_APPROVAL_CONSENT_OUTCOME_FRAME_BYTES,
};
pub use monotonic::{monotonic_nanos, MonotonicClockError};
pub use plan::{
    decode_plan_document, verify_plan_document, PlanDocumentV1, PlanOperation,
    MAX_PLAN_DOCUMENT_BYTES, MAX_PLAN_LOCAL_PORT, MIN_PLAN_LOCAL_PORT, PLAN_DIGEST_BYTES,
    PLAN_SCHEMA_VERSION, PLAN_TRANSCRIPT_DOMAIN, PROBE_IMAGE_DIGEST, PROBE_IMAGE_REFERENCE,
    PROBE_LOCAL_ADDRESS,
};
pub use plan_v2::{
    decode_plan_v2_document, verify_plan_v2_document, EntrypointPlanDocumentV2,
    LinkRoutePlanDocumentV2, PlanDocumentV2, PlanV2Group, PlanV2Operation,
    PrivateServicePlanDocumentV2, RestorePlanDocumentV2, RoutePlanDocumentV2,
    SnapshotPlanDocumentV2, UserServicePlanDocumentV2, WebServicePlanDocumentV2,
    BENTOPDF_IMAGE_DIGEST, BENTOPDF_IMAGE_REFERENCE, ENTRYPOINT_IMAGE_DIGEST,
    ENTRYPOINT_IMAGE_REFERENCE, ENTRYPOINT_PUBLIC_HTTPS_PORT, ENTRYPOINT_PUBLIC_HTTP_PORT,
    ENTRYPOINT_UNPRIVILEGED_PORT_SYSCTL, MAX_PLAN_BACKEND_PORT, MAX_ROUTE_HOST_BYTES,
    MAX_SNAPSHOT_SLOT_BYTES, MIN_PLAN_BACKEND_PORT, MIN_ROUTE_HOST_BYTES, MIN_SNAPSHOT_SLOT_BYTES,
    PLAN_V2_SCHEMA_VERSION, PLAN_V2_TRANSCRIPT_DOMAIN, PRIVATE_SERVICE_DATA_VOLUME,
    PRIVATE_SERVICE_EGRESS_TABLE, PRIVATE_SERVICE_ENVIRONMENT_HARDENING,
    PRIVATE_SERVICE_ORIGIN_SCHEME, PRIVATE_SERVICE_ORIGIN_VARIABLE, RESERVED_SNAPSHOT_SLOT,
    ROUTE_ISOLATION_HEADERS, SERVICE_LOCAL_ADDRESS, SERVICE_PROFILE_BENTOPDF,
    SERVICE_PROFILE_VAULTWARDEN, VAULTWARDEN_IMAGE_DIGEST, VAULTWARDEN_IMAGE_REFERENCE,
};
pub use plan_v3::{
    decode_plan_v3_document, verify_plan_v3_document, InitiatorPeerPlanDocumentV3,
    LinkPlanDocumentV3, LinkRole, ListenerPeerPlanDocumentV3, PlanDocumentV3, PlanV3Group,
    PlanV3Operation, LINK_INITIATOR_TUNNEL_ADDRESS, LINK_INTERFACE_NAME, LINK_KEEPALIVE_SECONDS,
    LINK_LISTENER_TUNNEL_ADDRESS, LINK_LISTEN_PORT, LINK_NFTABLES_TABLE, MAX_PLAN_SERVICE_PORT,
    MIN_PLAN_SERVICE_PORT, PEER_PUBLIC_KEY_BYTES, PEER_PUBLIC_KEY_ENCODED_BYTES,
    PLAN_V3_SCHEMA_VERSION, PLAN_V3_TRANSCRIPT_DOMAIN,
};
pub use service_definition::{
    decode_service_definition_document, verify_service_definition_document,
    ServiceDefinitionDocument, ServiceDefinitionField, ServiceDefinitionFieldRefusal,
    ServiceDefinitionRefusal, MAX_CONTAINER_PATH_BYTES, MAX_CONTAINER_PORT,
    MAX_ENVIRONMENT_KEY_CHARS, MAX_ENVIRONMENT_VALUE_BYTES, MAX_IMAGE_REPOSITORY_BYTES,
    MAX_SERVICE_DEFINITION_BYTES, MAX_SERVICE_ENVIRONMENT_LINES, MAX_SERVICE_SECRET_KEYS,
    MAX_SERVICE_SLUG_CHARS, MAX_SERVICE_TMPFS, MAX_SERVICE_VOLUMES, MIN_CONTAINER_PORT,
    ORIGIN_HOST_PLACEHOLDER, RESERVED_SERVICE_SLUGS, SERVICE_DEFINITION_DIGEST_BYTES,
    SERVICE_DEFINITION_SCHEMA_VERSION, SERVICE_DEFINITION_TRANSCRIPT_DOMAIN,
};

pub const REQUEST_ID_BYTES: usize = 16;
pub const MAX_HOST_BYTES: usize = 253;
pub const MAX_USERNAME_BYTES: usize = 32;
pub const HOST_KEY_BYTES: usize = 32;
pub const HOST_KEY_ENCODED_BYTES: usize = 43;
pub const MAX_ASSISTANT_REMAINING_MILLIS: u64 = 300_000;
/// Largest frozen address set a scope may carry. A name is resolved exactly
/// once, and what that resolution froze is displayed before consent.
pub const MAX_ASSISTANT_TARGET_ADDRESSES: usize = 8;
pub const MAX_ASSISTANT_SCOPE_FRAME_BYTES: usize = 4_096;
pub const MAX_ASSISTANT_EVENT_FRAME_BYTES: usize = 1_024;
/// The one code a proven access may answer, and the only code any terminal
/// event of this protocol maps onto zero. It is declared beside the refusals it
/// is the counterpart of, so the whole terminal table is read in one place.
pub const ASSISTANT_EXIT_ACCESS_VERIFIED: u8 = 0;
pub const ASSISTANT_EXIT_INVALID_INVOCATION: u8 = 64;
pub const ASSISTANT_EXIT_PROTOCOL_REFUSED: u8 = 65;
pub const ASSISTANT_EXIT_REFUSED: u8 = 66;
pub const ASSISTANT_EXIT_CANCELLED: u8 = 67;
pub const ASSISTANT_EXIT_UNAVAILABLE: u8 = 69;
pub const ASSISTANT_EXIT_INTERNAL_FAILURE: u8 = 70;
pub const ASSISTANT_EXIT_IO_FAILURE: u8 = 74;
pub const ASSISTANT_EXIT_WATCHDOG_EXPIRED: u8 = 124;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidInput,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid public bootstrap protocol input")
    }
}

impl std::error::Error for ProtocolError {}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapMode {
    Create,
    Replace,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapAccessKind {
    Administrator,
    // This selects the requested route. Only the separate native consent flow may authorize it.
    Root,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapTarget {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub host_key_sha256: String,
    pub access_kind: BootstrapAccessKind,
}

/// Ce que le frontend demande au lanceur, et rien de plus.
///
/// **Amendement du 18 août 2026 — la demande nomme son action.** Le lanceur
/// n'ouvrait que l'audit ; le parcours de création demande aussi les deux
/// actions d'installation, chacune avec ce qu'elle exige : la déclaration de
/// la cible pour les deux, les trois valeurs de configuration pour la pose
/// seule. Les règles de cohérence sont celles du scope — c'est lui qui les
/// tient, à la validation, et les dupliquer ici donnerait à chaque règle deux
/// maisons. Ce que ce type garde en propre est la forme : des champs
/// conditionnels absents par défaut, pour que la demande d'audit d'hier reste
/// lisible telle quelle.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapStartInput {
    pub mode: BootstrapMode,
    pub target: BootstrapTarget,
    /// L'action que l'humain veut approuver. Absente : l'audit — la demande
    /// d'hier, inchangée.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<BootstrapAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_target: Option<DeclaredTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_configuration: Option<MachineConfigurationValues>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapStep {
    PersonalAccess,
    UnlockPersonalKey,
    PrivilegeEscalation,
    RootAccess,
}

/// Ce que l'humain approuve, jamais comment l'Assistant s'y prend.
///
/// Le vocabulaire est clos et une session en porte exactement une : un
/// document qui annoncerait une action inconnue est refusé à la
/// désérialisation, avant toute fenêtre. Les deux actions d'installation
/// séparent ce qui doit l'être — poser des fichiers inertes et mettre un
/// service en écoute sont deux natures d'actes, sous deux approbations — et
/// la tranche du plan que chacune couvre est fixée par le module
/// d'installation de l'Assistant, pas par l'appelant.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapAction {
    AuditTargetReadOnly,
    /// Poser le lot vérifié, inerte : le paquet par `dpkg`, la configuration
    /// de cette machine, l'état privé, les sources de credentials. Rien
    /// n'écoute à la fin de cette action.
    InstallServerBundle,
    /// Mettre en écoute ce qui a été posé : la seule unité que le plan nomme,
    /// l'association de cette Console, le prévol depuis le Controller.
    ActivateApprovedController,
}

/// Où en est une session d'amorçage, dans le vocabulaire que la vue traduit
/// en phrases.
///
/// **Amendement du 18 août 2026 — les issues terminales sont nommées.** Ce
/// cycle de vie n'avait qu'un état : la Console effaçait le succès sitôt lu
/// (« naming that outcome to the frontend belongs to the business closure of
/// the palier »), et un refus du produit remontait indistinct d'une demande
/// malformée. La clôture d'affaires est ce palier-ci : chaque issue terminale
/// de l'Assistant a désormais son nom, la vue en fera une phrase, et l'état
/// partiel n'est jamais annoncé comme succès — le terminal dit ce qui s'est
/// conclu, l'action de la session dit ce que cela couvre.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapLifecycle {
    AwaitingNativeAssistant,
    /// L'Assistant a prouvé l'accès sur la session consentie — et, pour une
    /// action d'installation, joué sa séquence jusqu'au bout. Ce que cela
    /// couvre exactement se lit à côté, dans l'action de la session.
    AccessVerified,
    /// Refusé — par l'humain à la fenêtre, ou par un juge du produit. La
    /// machine reste dans l'état que le registre nomme.
    Refused,
    Cancelled,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BootstrapSessionView {
    pub schema_version: u8,
    pub request_id: String,
    pub mode: BootstrapMode,
    pub target: BootstrapTarget,
    pub step: BootstrapStep,
    pub actions: [BootstrapAction; 1],
    pub lifecycle: BootstrapLifecycle,
    pub expires_in_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativePromptKind {
    ConfirmPersonalAccess,
    KeyPassphrase,
    SudoPassword,
    ConfirmRootAccess,
}

/// Ce que l'utilisateur a déclaré de la cible, et que l'Assistant rejugera.
///
/// Deux natures se séparent ici, et la séparation est celle de la porte du
/// placement : une **déclaration** est un dire de l'utilisateur — cette machine
/// est privée, elle est normalement allumée — et peut donc voyager ; un **fait**
/// est ce que la machine répond, et l'Assistant l'observe lui-même dans sa
/// propre session, jamais depuis un champ. Un scope qui porterait les faits
/// ferait fonder le jugement du placement sur ce qu'une Console affirme d'une
/// machine qu'elle ne voit pas.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredTarget {
    /// L'exposition déclarée. Un Controller sur un endpoint exposé est refusé
    /// par la porte du placement, quoi que la machine ait répondu.
    pub private: bool,
    /// La disponibilité déclarée. Un Controller sur une machine intermittente
    /// est refusé pour la même raison : la continuité du plan de contrôle.
    pub normally_on: bool,
}

/// Les trois adresses que l'unité du Controller lit, et les seules.
///
/// Elles voyagent **comme valeurs, jamais comme fichier** : l'Assistant compose
/// lui-même les octets de `controller.env` et en calcule l'empreinte, de sorte
/// que le contenu que le privilège déplacera n'a qu'une seule définition, du
/// côté qui le produit. Envoyer le fichier tout fait ferait entrer ici des
/// octets choisis ailleurs — précisément ce que le module de configuration de
/// l'Assistant existe pour refuser.
///
/// Ce que ce protocole en dit s'arrête à leur forme : trois chaînes bornées,
/// non vides, sans caractère de contrôle. Leur **sens** — une adresse d'écoute,
/// une source autorisée, un point de rendez-vous — appartient au Controller et
/// à personne d'autre ici ; ce qui les refuserait mal formées est la porte de
/// composition de l'Assistant, qui refuse plutôt qu'elle n'échappe.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineConfigurationValues {
    pub listen: String,
    pub allowed_source: String,
    pub relay_endpoint: String,
}

/// Longueur maximale d'une des trois valeurs de configuration.
///
/// Une adresse, un CIDR ou un point de rendez-vous s'écrivent court. La borne
/// est là pour que la trame de scope reste très en deçà de
/// [`MAX_ASSISTANT_SCOPE_FRAME_BYTES`], et non pour juger d'un format : trois
/// valeurs de cette taille laissent la trame à moins du quart de sa borne.
pub const MAX_CONFIGURATION_VALUE_BYTES: usize = 253;

impl MachineConfigurationValues {
    /// La forme, et rien que la forme.
    ///
    /// Chaque valeur est non vide, bornée, et exempte de caractère de contrôle.
    /// Le `=` n'est **pas** refusé ici bien qu'un fichier d'environnement ne
    /// puisse pas le porter : ce refus-là appartient à la composition, qui est
    /// le seul endroit sachant dans quel format ces valeurs vont s'écrire. Le
    /// dupliquer donnerait deux règles pour une propriété, et un jour deux
    /// réponses.
    fn valid(&self) -> bool {
        [&self.listen, &self.allowed_source, &self.relay_endpoint]
            .into_iter()
            .all(|value| {
                !value.is_empty()
                    && value.len() <= MAX_CONFIGURATION_VALUE_BYTES
                    && !value.chars().any(char::is_control)
            })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssistantScopeV1 {
    pub schema_version: u8,
    pub request_id: String,
    pub mode: BootstrapMode,
    pub target: BootstrapTarget,
    pub step: BootstrapStep,
    pub actions: [BootstrapAction; 1],
    pub prompt: NativePromptKind,
    /// The numeric addresses the single name resolution froze, in resolution
    /// order. The launcher never freezes anything and always emits this empty:
    /// only the assistant's own resolution fills it, and only before the
    /// consent window renders it beside the name.
    pub target_addresses: Vec<String>,
    /// Les trois adresses dont l'Assistant composera `controller.env`, présentes
    /// **exactement** quand l'action est de poser le lot.
    ///
    /// C'est le patron d'`origin_host` de `#118` : approuver une conséquence,
    /// pas une intention. Une session d'audit ou d'activation qui les porterait
    /// annoncerait une écriture qu'elle ne fera pas ; une session qui pose et
    /// ne les porte pas n'aurait rien à composer, donc rien à montrer à
    /// l'humain — et l'empreinte qu'il approuve serait celle de rien.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_configuration: Option<MachineConfigurationValues>,
    /// La déclaration de la cible, présente **exactement** quand l'action
    /// installe — poser ou activer, les deux jugent un placement. L'audit n'en
    /// juge aucun et n'en porte pas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_target: Option<DeclaredTarget>,
    pub issued_at_monotonic_nanos: u64,
    pub remaining_millis: u64,
}

impl AssistantScopeV1 {
    pub fn validate(mut self) -> Result<Self, ProtocolError> {
        if self.schema_version != 1
            || !canonical_request_id(&self.request_id)
            || !(1..=MAX_ASSISTANT_REMAINING_MILLIS).contains(&self.remaining_millis)
            || !prompt_matches_scope(self.prompt, self.step, self.target.access_kind)
            || !valid_target_addresses(&self.target_addresses)
            || !configuration_matches_action(self.machine_configuration.as_ref(), self.actions[0])
            || !declaration_matches_action(self.declared_target, self.actions[0])
        {
            return Err(ProtocolError::InvalidInput);
        }
        self.target = validate_target(self.target)?;
        Ok(self)
    }
}

/// Bounds the frozen address set: at most eight entries, each a canonical
/// numeric address of a reachability class a remote host may actually hold,
/// and no repetition. An empty set means the resolution has not happened yet.
fn valid_target_addresses(addresses: &[String]) -> bool {
    if addresses.len() > MAX_ASSISTANT_TARGET_ADDRESSES {
        return false;
    }
    let mut seen: Vec<IpAddr> = Vec::with_capacity(addresses.len());
    for entry in addresses {
        let Ok(address) = IpAddr::from_str(entry) else {
            return false;
        };
        // An IPv4-mapped form is the same host spelled twice. Refusing it here
        // keeps the displayed set free of two names for one peer.
        if matches!(address, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some()) {
            return false;
        }
        // Rendering back to text refuses every non-canonical spelling of the
        // same address, so what is displayed is what is dialled.
        if address.to_string() != *entry
            || !valid_target_address(address)
            || seen.contains(&address)
        {
            return false;
        }
        seen.push(address);
    }
    true
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssistantEventKind {
    PromptOpen,
    /// The elevation was proven on the exact session that was consented to.
    /// It is the only event of this protocol that means an access succeeded,
    /// and the only one whose exit code is zero.
    AccessVerified,
    Refused,
    Cancelled,
    Expired,
    Unavailable,
}

impl AssistantEventKind {
    /// The one exit code this event may ever be read beside.
    ///
    /// There is a single table, on the surface both processes share, so that
    /// the pair cannot come apart: the assistant derives the code it exits
    /// with from the event it wrote, and the Console refuses any frame whose
    /// code is not the one named here. A divergent combination — `zero`
    /// without [`Self::AccessVerified`], or [`Self::AccessVerified`] with
    /// anything but zero — is therefore not a case anyone has to remember to
    /// handle: it has no entry at all.
    ///
    /// [`Self::PromptOpen`] is not terminal and names no code.
    pub fn terminal_exit_code(self) -> Option<u8> {
        match self {
            Self::PromptOpen => None,
            Self::AccessVerified => Some(ASSISTANT_EXIT_ACCESS_VERIFIED),
            Self::Refused => Some(ASSISTANT_EXIT_REFUSED),
            Self::Cancelled => Some(ASSISTANT_EXIT_CANCELLED),
            Self::Expired => Some(ASSISTANT_EXIT_WATCHDOG_EXPIRED),
            Self::Unavailable => Some(ASSISTANT_EXIT_UNAVAILABLE),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssistantEventV1 {
    pub schema_version: u8,
    pub request_id: String,
    pub event: AssistantEventKind,
}

impl AssistantEventV1 {
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if self.schema_version != 1 || !canonical_request_id(&self.request_id) {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(self)
    }
}

pub fn validate_target(mut target: BootstrapTarget) -> Result<BootstrapTarget, ProtocolError> {
    target.host = canonical_host(&target.host)?;
    if target.port == 0 || !valid_username(&target.username, target.access_kind) {
        return Err(ProtocolError::InvalidInput);
    }
    validate_host_key(&target.host_key_sha256)?;
    Ok(target)
}

pub fn canonical_request_id(request_id: &str) -> bool {
    request_id.len() == REQUEST_ID_BYTES * 2
        && request_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// La configuration voyage **exactement** avec l'action qui l'écrit.
///
/// Les deux sens comptent, et c'est ce qui fait de cette règle autre chose
/// qu'une commodité de sérialisation. Absente d'une pose, l'Assistant n'aurait
/// rien à composer et l'humain approuverait l'empreinte de rien. Présente à
/// côté d'un audit ou d'une activation, elle annoncerait une écriture que la
/// tranche du plan ne contient pas — un document qui promet plus que ce que
/// l'action fera.
/// La déclaration voyage **exactement** avec les actions qui jugent un
/// placement — les deux actions d'installation. Même règle à deux sens que la
/// configuration : absente, l'Assistant n'aurait rien à rejuger et le
/// consentement couvrirait une déclaration que personne n'a faite ; présente à
/// côté d'un audit, elle annoncerait un jugement que l'action ne rend pas.
fn declaration_matches_action(
    declaration: Option<DeclaredTarget>,
    action: BootstrapAction,
) -> bool {
    match (declaration, action) {
        (Some(_), BootstrapAction::InstallServerBundle)
        | (Some(_), BootstrapAction::ActivateApprovedController)
        | (None, BootstrapAction::AuditTargetReadOnly) => true,
        _ => false,
    }
}

fn configuration_matches_action(
    configuration: Option<&MachineConfigurationValues>,
    action: BootstrapAction,
) -> bool {
    match (configuration, action) {
        (Some(values), BootstrapAction::InstallServerBundle) => values.valid(),
        (None, BootstrapAction::AuditTargetReadOnly)
        | (None, BootstrapAction::ActivateApprovedController) => true,
        _ => false,
    }
}

fn prompt_matches_scope(
    prompt: NativePromptKind,
    step: BootstrapStep,
    access_kind: BootstrapAccessKind,
) -> bool {
    matches!(
        (prompt, step, access_kind),
        (
            NativePromptKind::ConfirmPersonalAccess,
            BootstrapStep::PersonalAccess,
            BootstrapAccessKind::Administrator
        ) | (
            NativePromptKind::KeyPassphrase,
            BootstrapStep::UnlockPersonalKey,
            BootstrapAccessKind::Administrator | BootstrapAccessKind::Root
        ) | (
            NativePromptKind::SudoPassword,
            BootstrapStep::PrivilegeEscalation,
            BootstrapAccessKind::Administrator
        ) | (
            NativePromptKind::ConfirmRootAccess,
            BootstrapStep::RootAccess,
            BootstrapAccessKind::Root
        )
    )
}

fn canonical_host(host: &str) -> Result<String, ProtocolError> {
    if host.is_empty() || host.len() > MAX_HOST_BYTES || host.trim() != host || !host.is_ascii() {
        return Err(ProtocolError::InvalidInput);
    }
    if let Ok(address) = IpAddr::from_str(host) {
        if !valid_target_address(address) {
            return Err(ProtocolError::InvalidInput);
        }
        return Ok(address.to_string());
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err(ProtocolError::InvalidInput);
    }
    if host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || host.ends_with('.')
        || host
            .split('.')
            .any(|label| !valid_dns_label(label.as_bytes()))
    {
        return Err(ProtocolError::InvalidInput);
    }
    Ok(host.to_ascii_lowercase())
}

fn valid_target_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => valid_target_ipv4(address),
        IpAddr::V6(address) => valid_target_ipv6(address),
    }
}

fn valid_target_ipv4(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_multicast()
        && !address.is_broadcast()
}

fn valid_target_ipv6(address: Ipv6Addr) -> bool {
    if let Some(address) = address.to_ipv4_mapped() {
        return valid_target_ipv4(address);
    }
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_unicast_link_local()
        && !address.is_multicast()
}

fn valid_dns_label(label: &[u8]) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }
    let is_alphanumeric = |byte: u8| byte.is_ascii_alphanumeric();
    is_alphanumeric(label[0])
        && is_alphanumeric(label[label.len() - 1])
        && label
            .iter()
            .all(|byte| is_alphanumeric(*byte) || *byte == b'-')
}

fn valid_username(username: &str, access_kind: BootstrapAccessKind) -> bool {
    let bytes = username.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_USERNAME_BYTES || !username.is_ascii() {
        return false;
    }
    let first = bytes[0];
    if !(first.is_ascii_lowercase() || first == b'_')
        || !bytes.iter().skip(1).all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'_' | b'-')
        })
    {
        return false;
    }
    match access_kind {
        BootstrapAccessKind::Administrator => username != "root",
        BootstrapAccessKind::Root => username == "root",
    }
}

fn validate_host_key(host_key_sha256: &str) -> Result<(), ProtocolError> {
    let encoded = host_key_sha256
        .strip_prefix("SHA256:")
        .ok_or(ProtocolError::InvalidInput)?;
    if encoded.len() != HOST_KEY_ENCODED_BYTES || !encoded.is_ascii() {
        return Err(ProtocolError::InvalidInput);
    }
    let mut decoded = [0_u8; HOST_KEY_BYTES];
    let decoded_bytes = STANDARD_NO_PAD
        .decode_slice(encoded, &mut decoded)
        .map_err(|_| ProtocolError::InvalidInput)?;
    if decoded_bytes != HOST_KEY_BYTES || STANDARD_NO_PAD.encode(decoded) != encoded {
        return Err(ProtocolError::InvalidInput);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_ID: &str = "00112233445566778899aabbccddeeff";
    const HOST_KEY: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn target(access_kind: BootstrapAccessKind) -> BootstrapTarget {
        BootstrapTarget {
            host: "Controller.Example.test".into(),
            port: 22,
            username: match access_kind {
                BootstrapAccessKind::Administrator => "infra_admin".into(),
                BootstrapAccessKind::Root => "root".into(),
            },
            host_key_sha256: HOST_KEY.into(),
            access_kind,
        }
    }

    fn scope(prompt: NativePromptKind, access_kind: BootstrapAccessKind) -> AssistantScopeV1 {
        let step = match prompt {
            NativePromptKind::ConfirmPersonalAccess => BootstrapStep::PersonalAccess,
            NativePromptKind::KeyPassphrase => BootstrapStep::UnlockPersonalKey,
            NativePromptKind::SudoPassword => BootstrapStep::PrivilegeEscalation,
            NativePromptKind::ConfirmRootAccess => BootstrapStep::RootAccess,
        };
        AssistantScopeV1 {
            schema_version: 1,
            request_id: REQUEST_ID.into(),
            mode: BootstrapMode::Create,
            target: target(access_kind),
            step,
            actions: [BootstrapAction::AuditTargetReadOnly],
            prompt,
            target_addresses: Vec::new(),
            machine_configuration: None,
            declared_target: None,
            issued_at_monotonic_nanos: 1,
            remaining_millis: MAX_ASSISTANT_REMAINING_MILLIS,
        }
    }

    /// Les trois valeurs telles qu'une pose licite les porte.
    fn configuration_values() -> MachineConfigurationValues {
        MachineConfigurationValues {
            listen: "192.168.240.115:9443".into(),
            allowed_source: "192.168.240.0/24".into(),
            relay_endpoint: "192.168.240.9:9444".into(),
        }
    }

    /// Un scope de pose, complet et licite.
    fn install_scope() -> AssistantScopeV1 {
        AssistantScopeV1 {
            actions: [BootstrapAction::InstallServerBundle],
            machine_configuration: Some(configuration_values()),
            declared_target: Some(DeclaredTarget {
                private: true,
                normally_on: true,
            }),
            ..scope(
                NativePromptKind::ConfirmPersonalAccess,
                BootstrapAccessKind::Administrator,
            )
        }
    }

    /// **La configuration voyage exactement avec l'action qui l'écrit**, dans
    /// les deux sens.
    ///
    /// Le contrôle positif d'abord : une pose la porte et passe. Puis les deux
    /// manières de mentir — une pose sans elle, qui n'aurait rien à composer et
    /// ferait approuver l'empreinte de rien ; une action qui n'écrit pas et la
    /// porte quand même, ce qui annoncerait une écriture que sa tranche du plan
    /// ne contient pas.
    #[test]
    fn the_machine_configuration_travels_exactly_with_the_action_that_writes_it() {
        install_scope()
            .validate()
            .expect("une pose qui porte ses trois valeurs doit passer");

        // Poser sans savoir quoi écrire.
        let orphan = AssistantScopeV1 {
            machine_configuration: None,
            ..install_scope()
        };
        assert_eq!(orphan.validate().unwrap_err(), ProtocolError::InvalidInput);

        // Annoncer une écriture que l'action ne fera pas.
        for action in [
            BootstrapAction::AuditTargetReadOnly,
            BootstrapAction::ActivateApprovedController,
        ] {
            let overreaching = AssistantScopeV1 {
                actions: [action],
                machine_configuration: Some(configuration_values()),
                ..scope(
                    NativePromptKind::ConfirmPersonalAccess,
                    BootstrapAccessKind::Administrator,
                )
            };
            assert_eq!(
                overreaching.validate().unwrap_err(),
                ProtocolError::InvalidInput,
                "{action:?} porte une configuration qu'elle n'écrira jamais"
            );
        }
    }

    /// **La déclaration voyage exactement avec les actions qui jugent un
    /// placement**, dans les deux sens.
    ///
    /// Les deux actions d'installation la portent — poser et activer jugent
    /// chacune un placement — et l'audit n'en porte pas : il n'en juge aucun.
    /// Une déclaration absente d'une installation laisserait l'Assistant sans
    /// rien à rejuger, et le consentement couvrirait une déclaration que
    /// personne n'a faite.
    #[test]
    fn the_declaration_travels_exactly_with_the_actions_that_judge_a_placement() {
        // Les deux contrôles positifs : la pose (déjà couverte par
        // `install_scope`) et l'activation, qui porte la déclaration sans la
        // configuration.
        AssistantScopeV1 {
            actions: [BootstrapAction::ActivateApprovedController],
            machine_configuration: None,
            declared_target: Some(DeclaredTarget {
                private: true,
                normally_on: true,
            }),
            ..scope(
                NativePromptKind::ConfirmPersonalAccess,
                BootstrapAccessKind::Administrator,
            )
        }
        .validate()
        .expect("une activation qui porte sa déclaration doit passer");

        // Installer sans déclaration : rien à rejuger.
        for action in [
            BootstrapAction::InstallServerBundle,
            BootstrapAction::ActivateApprovedController,
        ] {
            let undeclared = AssistantScopeV1 {
                actions: [action],
                machine_configuration: match action {
                    BootstrapAction::InstallServerBundle => Some(configuration_values()),
                    _ => None,
                },
                declared_target: None,
                ..scope(
                    NativePromptKind::ConfirmPersonalAccess,
                    BootstrapAccessKind::Administrator,
                )
            };
            assert_eq!(
                undeclared.validate().unwrap_err(),
                ProtocolError::InvalidInput,
                "{action:?} passe sans déclaration"
            );
        }

        // Auditer avec une déclaration : un jugement annoncé que l'action ne
        // rend pas.
        let overreaching = AssistantScopeV1 {
            declared_target: Some(DeclaredTarget {
                private: true,
                normally_on: true,
            }),
            ..scope(
                NativePromptKind::ConfirmPersonalAccess,
                BootstrapAccessKind::Administrator,
            )
        };
        assert_eq!(
            overreaching.validate().unwrap_err(),
            ProtocolError::InvalidInput
        );

        // Et la déclaration est un dire, pas un jugement : un scope déclarant
        // une cible exposée ou intermittente RESTE licite ici — c'est la porte
        // du placement, dans l'Assistant, qui le refusera. La refuser dans le
        // protocole donnerait à la règle deux maisons.
        AssistantScopeV1 {
            declared_target: Some(DeclaredTarget {
                private: false,
                normally_on: false,
            }),
            ..install_scope()
        }
        .validate()
        .expect("le protocole transporte la déclaration, il ne la juge pas");
    }

    /// Chaque valeur mal formée est refusée **avant toute fenêtre**.
    ///
    /// Ce que ce protocole juge est la forme, et rien qu'elle : non vide,
    /// bornée, sans caractère de contrôle. Le saut de ligne compte double — il
    /// est un caractère de contrôle ici, et il serait une seconde variable dans
    /// un fichier d'environnement — mais c'est la composition qui porte cette
    /// seconde raison, et elle refuse aussi le `=` que cette porte-ci laisse
    /// passer.
    #[test]
    fn a_malformed_configuration_value_is_refused_before_any_window() {
        let hostile = [
            "",
            "192.168.1.1\nCONTROLLER_ALLOWED_SOURCE=0.0.0.0/0",
            "192.168.1.1\r",
            "192.168.1.1\u{0}",
            &"a".repeat(MAX_CONFIGURATION_VALUE_BYTES + 1),
        ];

        for value in hostile {
            for position in 0..3 {
                let mut values = configuration_values();
                match position {
                    0 => values.listen = value.into(),
                    1 => values.allowed_source = value.into(),
                    _ => values.relay_endpoint = value.into(),
                }
                let scope = AssistantScopeV1 {
                    machine_configuration: Some(values),
                    ..install_scope()
                };
                assert_eq!(
                    scope.validate().unwrap_err(),
                    ProtocolError::InvalidInput,
                    "valeur acceptée en position {position} : {value:?}"
                );
            }
        }

        // La borne est un plafond, pas un piège : la plus longue valeur licite
        // passe.
        let mut values = configuration_values();
        values.listen = "a".repeat(MAX_CONFIGURATION_VALUE_BYTES);
        AssistantScopeV1 {
            machine_configuration: Some(values),
            ..install_scope()
        }
        .validate()
        .expect("la valeur la plus longue admissible doit passer");
    }

    /// Les trois valeurs tiennent très en deçà de la trame de scope.
    ///
    /// La borne par valeur n'a pas été choisie pour juger d'un format mais pour
    /// que ce champ ne puisse jamais rapprocher une trame de sa limite. Le test
    /// le mesure sur le pire cas plutôt que de le supposer.
    #[test]
    fn the_widest_configuration_stays_far_below_the_scope_frame() {
        let mut values = configuration_values();
        values.listen = "a".repeat(MAX_CONFIGURATION_VALUE_BYTES);
        values.allowed_source = "b".repeat(MAX_CONFIGURATION_VALUE_BYTES);
        values.relay_endpoint = "c".repeat(MAX_CONFIGURATION_VALUE_BYTES);
        let widest = AssistantScopeV1 {
            machine_configuration: Some(values),
            ..install_scope()
        };

        let encoded = serde_json::to_vec(&widest).expect("un scope se sérialise");
        assert!(
            encoded.len() < MAX_ASSISTANT_SCOPE_FRAME_BYTES / 2,
            "la trame la plus large fait {} octets sur {MAX_ASSISTANT_SCOPE_FRAME_BYTES}",
            encoded.len()
        );
    }

    /// Un scope qui n'a jamais entendu parler de configuration reste lisible.
    ///
    /// Le champ est absent des documents que l'audit produit, et son absence
    /// n'est pas une erreur de désérialisation : `deny_unknown_fields` refuse ce
    /// qui est en trop, jamais ce qui manque légitimement.
    #[test]
    fn a_scope_without_the_field_is_still_read() {
        let audit = scope(
            NativePromptKind::ConfirmPersonalAccess,
            BootstrapAccessKind::Administrator,
        );
        let encoded = serde_json::to_string(&audit).expect("un scope se sérialise");
        assert!(
            !encoded.contains("machine_configuration"),
            "l'absence doit rester absente du document : {encoded}"
        );
        let decoded: AssistantScopeV1 =
            serde_json::from_str(&encoded).expect("un scope sans le champ se relit");
        assert_eq!(decoded.machine_configuration, None);
        decoded.validate().expect("et reste licite");
    }

    #[test]
    fn target_validation_canonicalizes_the_public_scope() {
        let target = validate_target(target(BootstrapAccessKind::Administrator)).unwrap();
        assert_eq!(target.host, "controller.example.test");
    }

    #[test]
    fn target_validation_refuses_local_and_mapped_addresses() {
        for host in [
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.1.1",
            "::ffff:224.0.0.1",
            "localhost",
            "machine.localhost",
        ] {
            assert_eq!(
                validate_target(BootstrapTarget {
                    host: host.into(),
                    ..target(BootstrapAccessKind::Administrator)
                }),
                Err(ProtocolError::InvalidInput)
            );
        }
    }

    #[test]
    fn request_id_is_exact_and_canonical() {
        assert!(canonical_request_id(REQUEST_ID));
        assert!(!canonical_request_id("00112233445566778899AABBCCDDEEFF"));
        assert!(!canonical_request_id("../../forged"));
    }

    /// Le vocabulaire des actions est clos et ses noms de fil sont exacts :
    /// chacune voyage sous son nom `snake_case` et revient identique. Un nom
    /// que ce vocabulaire ne définit pas est refusé à la désérialisation —
    /// avant toute fenêtre, avant tout acte.
    #[test]
    fn the_action_vocabulary_is_closed_and_its_wire_names_are_exact() {
        for (action, wire_name) in [
            (
                BootstrapAction::AuditTargetReadOnly,
                "\"audit_target_read_only\"",
            ),
            (
                BootstrapAction::InstallServerBundle,
                "\"install_server_bundle\"",
            ),
            (
                BootstrapAction::ActivateApprovedController,
                "\"activate_approved_controller\"",
            ),
        ] {
            assert_eq!(serde_json::to_string(&action).unwrap(), wire_name);
            assert_eq!(
                serde_json::from_str::<BootstrapAction>(wire_name).unwrap(),
                action
            );
        }

        for unknown in [
            "\"install_and_activate\"",
            "\"transfer_authority\"",
            "\"InstallServerBundle\"",
        ] {
            assert!(serde_json::from_str::<BootstrapAction>(unknown).is_err());
        }
    }

    #[test]
    fn assistant_scope_accepts_only_positive_bounded_combinations() {
        for (prompt, access_kind) in [
            (
                NativePromptKind::ConfirmPersonalAccess,
                BootstrapAccessKind::Administrator,
            ),
            (
                NativePromptKind::KeyPassphrase,
                BootstrapAccessKind::Administrator,
            ),
            (NativePromptKind::KeyPassphrase, BootstrapAccessKind::Root),
            (
                NativePromptKind::SudoPassword,
                BootstrapAccessKind::Administrator,
            ),
            (
                NativePromptKind::ConfirmRootAccess,
                BootstrapAccessKind::Root,
            ),
        ] {
            assert!(scope(prompt, access_kind).validate().is_ok());
        }

        for (prompt, access_kind) in [
            (
                NativePromptKind::ConfirmPersonalAccess,
                BootstrapAccessKind::Root,
            ),
            (NativePromptKind::SudoPassword, BootstrapAccessKind::Root),
            (
                NativePromptKind::ConfirmRootAccess,
                BootstrapAccessKind::Administrator,
            ),
        ] {
            assert_eq!(
                scope(prompt, access_kind).validate(),
                Err(ProtocolError::InvalidInput)
            );
        }

        let mut mismatched_step = scope(
            NativePromptKind::SudoPassword,
            BootstrapAccessKind::Administrator,
        );
        mismatched_step.step = BootstrapStep::PersonalAccess;
        assert_eq!(mismatched_step.validate(), Err(ProtocolError::InvalidInput));
    }

    #[test]
    fn assistant_wire_variants_are_fixed() {
        for (step, wire_name) in [
            (BootstrapStep::PersonalAccess, "personal_access"),
            (BootstrapStep::UnlockPersonalKey, "unlock_personal_key"),
            (BootstrapStep::PrivilegeEscalation, "privilege_escalation"),
            (BootstrapStep::RootAccess, "root_access"),
        ] {
            assert_eq!(
                serde_json::to_value(step).unwrap(),
                serde_json::json!(wire_name)
            );
        }

        for (prompt, wire_name) in [
            (
                NativePromptKind::ConfirmPersonalAccess,
                "confirm_personal_access",
            ),
            (NativePromptKind::KeyPassphrase, "key_passphrase"),
            (NativePromptKind::SudoPassword, "sudo_password"),
            (NativePromptKind::ConfirmRootAccess, "confirm_root_access"),
        ] {
            assert_eq!(
                serde_json::to_value(prompt).unwrap(),
                serde_json::json!(wire_name)
            );
        }

        for (event, wire_name) in [
            (AssistantEventKind::PromptOpen, "prompt_open"),
            (AssistantEventKind::AccessVerified, "access_verified"),
            (AssistantEventKind::Refused, "refused"),
            (AssistantEventKind::Cancelled, "cancelled"),
            (AssistantEventKind::Expired, "expired"),
            (AssistantEventKind::Unavailable, "unavailable"),
        ] {
            assert_eq!(
                serde_json::to_value(event).unwrap(),
                serde_json::json!(wire_name)
            );
        }
    }

    /// The pair both processes read the same table for.
    ///
    /// Zero belongs to `access_verified` and to nothing else, every other
    /// terminal event names a distinct non-zero code, and the only event
    /// without a code is the one that terminates nothing.
    #[test]
    fn exactly_one_terminal_event_carries_the_successful_exit_code() {
        const TERMINALS: [AssistantEventKind; 5] = [
            AssistantEventKind::AccessVerified,
            AssistantEventKind::Refused,
            AssistantEventKind::Cancelled,
            AssistantEventKind::Expired,
            AssistantEventKind::Unavailable,
        ];

        assert_eq!(AssistantEventKind::PromptOpen.terminal_exit_code(), None);
        assert_eq!(
            AssistantEventKind::AccessVerified.terminal_exit_code(),
            Some(ASSISTANT_EXIT_ACCESS_VERIFIED)
        );
        assert_eq!(ASSISTANT_EXIT_ACCESS_VERIFIED, 0);

        let mut codes: Vec<u8> = Vec::new();
        for event in TERMINALS {
            let code = event
                .terminal_exit_code()
                .expect("every terminal event names its own code");
            assert_eq!(
                code == 0,
                event == AssistantEventKind::AccessVerified,
                "{event:?} must not share the successful code"
            );
            assert!(!codes.contains(&code), "{event:?} reuses the code {code}");
            codes.push(code);
        }
    }

    #[test]
    fn assistant_scope_refuses_wrong_schema_identifier_or_expiration() {
        let mut wrong_schema = scope(
            NativePromptKind::ConfirmPersonalAccess,
            BootstrapAccessKind::Administrator,
        );
        wrong_schema.schema_version = 2;
        assert_eq!(wrong_schema.validate(), Err(ProtocolError::InvalidInput));

        let mut wrong_request = scope(
            NativePromptKind::ConfirmPersonalAccess,
            BootstrapAccessKind::Administrator,
        );
        wrong_request.request_id = "forged".into();
        assert_eq!(wrong_request.validate(), Err(ProtocolError::InvalidInput));

        for remaining_millis in [0, MAX_ASSISTANT_REMAINING_MILLIS + 1] {
            let mut invalid = scope(
                NativePromptKind::ConfirmPersonalAccess,
                BootstrapAccessKind::Administrator,
            );
            invalid.remaining_millis = remaining_millis;
            assert_eq!(invalid.validate(), Err(ProtocolError::InvalidInput));
        }
    }

    #[test]
    fn assistant_event_is_closed_and_correlated() {
        let event = AssistantEventV1 {
            schema_version: 1,
            request_id: REQUEST_ID.into(),
            event: AssistantEventKind::PromptOpen,
        };
        assert!(event.clone().validate().is_ok());

        let hostile = serde_json::json!({
            "schema_version": 1,
            "request_id": REQUEST_ID,
            "event": "prompt_open",
            "secret": "forbidden"
        });
        assert!(serde_json::from_value::<AssistantEventV1>(hostile).is_err());

        let mut wrong_request = event;
        wrong_request.request_id = "forged".into();
        assert_eq!(wrong_request.validate(), Err(ProtocolError::InvalidInput));

        let wrong_schema = AssistantEventV1 {
            schema_version: 2,
            request_id: REQUEST_ID.into(),
            event: AssistantEventKind::Unavailable,
        };
        assert_eq!(wrong_schema.validate(), Err(ProtocolError::InvalidInput));
    }

    /// The scope is what the native window renders, so the address set it
    /// carries is bounded, canonical and free of anything that does not mean a
    /// remote host. An empty set is the launcher's own state: nothing frozen yet.
    #[test]
    fn assistant_scope_bounds_the_frozen_address_set() {
        let base = scope(
            NativePromptKind::ConfirmPersonalAccess,
            BootstrapAccessKind::Administrator,
        );
        assert!(
            base.clone().validate().is_ok(),
            "an unresolved scope carries no address"
        );

        let mut frozen = base.clone();
        frozen.target_addresses = vec!["192.168.1.10".into(), "2001:db8::1".into()];
        assert_eq!(
            frozen.clone().validate().unwrap().target_addresses,
            frozen.target_addresses,
            "validation canonicalises the host, never the frozen addresses"
        );

        let mut maximal = base.clone();
        maximal.target_addresses = (1..=MAX_ASSISTANT_TARGET_ADDRESSES)
            .map(|last| format!("192.168.1.{last}"))
            .collect();
        assert!(maximal.validate().is_ok());

        let mut too_many = base.clone();
        too_many.target_addresses = (1..=MAX_ASSISTANT_TARGET_ADDRESSES + 1)
            .map(|last| format!("192.168.1.{last}"))
            .collect();
        assert_eq!(too_many.validate(), Err(ProtocolError::InvalidInput));

        for hostile in [
            vec!["controller.example.test".to_string()],
            vec!["127.0.0.1".to_string()],
            vec!["::1".to_string()],
            vec!["169.254.169.254".to_string()],
            vec!["0.0.0.0".to_string()],
            vec!["224.0.0.1".to_string()],
            vec!["255.255.255.255".to_string()],
            vec!["::ffff:192.168.1.10".to_string()],
            vec!["192.168.001.010".to_string()],
            vec!["2001:DB8::1".to_string()],
            vec!["192.168.1.10".to_string(), "192.168.1.10".to_string()],
            vec![" 192.168.1.10".to_string()],
            vec![String::new()],
        ] {
            let mut invalid = base.clone();
            invalid.target_addresses = hostile.clone();
            assert_eq!(
                invalid.validate(),
                Err(ProtocolError::InvalidInput),
                "{hostile:?} must never reach the consent window"
            );
        }
    }

    #[test]
    fn assistant_scope_serde_refuses_unknown_fields() {
        let mut document = serde_json::to_value(scope(
            NativePromptKind::ConfirmPersonalAccess,
            BootstrapAccessKind::Administrator,
        ))
        .unwrap();
        document["secret"] = serde_json::json!("forbidden");
        assert!(serde_json::from_value::<AssistantScopeV1>(document).is_err());

        let mut missing_stamp = serde_json::to_value(scope(
            NativePromptKind::ConfirmPersonalAccess,
            BootstrapAccessKind::Administrator,
        ))
        .unwrap();
        missing_stamp
            .as_object_mut()
            .unwrap()
            .remove("issued_at_monotonic_nanos");
        assert!(serde_json::from_value::<AssistantScopeV1>(missing_stamp).is_err());
    }
}
