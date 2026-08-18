use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use std::time::{Duration, Instant};
pub use your_cloud_bootstrap_protocol::{
    canonical_request_id, validate_target, AssistantScopeV1, BootstrapAction, BootstrapLifecycle,
    BootstrapMode, BootstrapSessionView, BootstrapStartInput, BootstrapStep, BootstrapTarget,
    DeclaredTarget, MachineConfigurationValues, NativePromptKind, HOST_KEY_ENCODED_BYTES,
    MAX_CONFIGURATION_VALUE_BYTES, MAX_HOST_BYTES, MAX_USERNAME_BYTES, REQUEST_ID_BYTES,
};

// The WebView can observe this native deadline but cannot choose or extend it.
const BOOTSTRAP_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("invalid public bootstrap input")]
    InvalidInput,
    #[error("another bootstrap request is active")]
    Busy,
    #[error("the bootstrap request expired")]
    Expired,
    #[error("the bootstrap request was refused")]
    RequestRefused,
}

impl BootstrapError {
    pub fn public_code(&self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::Busy => "bootstrap_busy",
            Self::Expired => "bootstrap_expired",
            Self::RequestRefused => "bootstrap_request_refused",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapStartEnvelope {
    input: BootstrapStartInput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BootstrapRequestEnvelope {
    request_id: String,
}

pub fn parse_start_envelope(
    value: &serde_json::Value,
) -> Result<BootstrapStartInput, BootstrapError> {
    // Bound every attacker-controlled string before serde creates owned copies.
    let envelope = exact_object(value, &["input"]).ok_or(BootstrapError::InvalidInput)?;
    let input = object_with(
        envelope.get("input").ok_or(BootstrapError::InvalidInput)?,
        &["mode", "target"],
        &["action", "declared_target", "machine_configuration"],
    )
    .ok_or(BootstrapError::InvalidInput)?;
    bounded_string(input.get("mode"), 7).ok_or(BootstrapError::InvalidInput)?;
    // Les champs conditionnels sont bornés AVANT que serde possède quoi que ce
    // soit, comme le reste : l'action est un mot du vocabulaire clos, la
    // déclaration deux booléens, et chaque valeur de configuration tient sous
    // la borne que le protocole publie. La COHÉRENCE (quelle action exige
    // quoi) n'est pas jugée ici : elle a une seule maison, la validation du
    // scope, que le lancement du helper impose.
    if let Some(action) = input.get("action") {
        bounded_string(Some(action), "activate_approved_controller".len())
            .ok_or(BootstrapError::InvalidInput)?;
    }
    if let Some(declared) = input.get("declared_target") {
        let declared = exact_object(declared, &["private", "normally_on"])
            .ok_or(BootstrapError::InvalidInput)?;
        if !declared.values().all(serde_json::Value::is_boolean) {
            return Err(BootstrapError::InvalidInput);
        }
    }
    if let Some(configuration) = input.get("machine_configuration") {
        let configuration = exact_object(
            configuration,
            &["listen", "allowed_source", "relay_endpoint"],
        )
        .ok_or(BootstrapError::InvalidInput)?;
        for field in ["listen", "allowed_source", "relay_endpoint"] {
            bounded_string(configuration.get(field), MAX_CONFIGURATION_VALUE_BYTES)
                .ok_or(BootstrapError::InvalidInput)?;
        }
    }
    let target = exact_object(
        input.get("target").ok_or(BootstrapError::InvalidInput)?,
        &["host", "port", "username", "host_key_sha256", "access_kind"],
    )
    .ok_or(BootstrapError::InvalidInput)?;
    bounded_string(target.get("host"), MAX_HOST_BYTES).ok_or(BootstrapError::InvalidInput)?;
    bounded_string(target.get("username"), MAX_USERNAME_BYTES)
        .ok_or(BootstrapError::InvalidInput)?;
    bounded_string(
        target.get("host_key_sha256"),
        "SHA256:".len() + HOST_KEY_ENCODED_BYTES,
    )
    .ok_or(BootstrapError::InvalidInput)?;
    bounded_string(target.get("access_kind"), "administrator".len())
        .ok_or(BootstrapError::InvalidInput)?;

    BootstrapStartEnvelope::deserialize(value)
        .map(|envelope| envelope.input)
        .map_err(|_| BootstrapError::InvalidInput)
}

pub fn parse_request_envelope(value: &serde_json::Value) -> Result<String, BootstrapError> {
    let envelope = exact_object(value, &["requestId"]).ok_or(BootstrapError::RequestRefused)?;
    let request_id = bounded_string(envelope.get("requestId"), REQUEST_ID_BYTES * 2)
        .ok_or(BootstrapError::RequestRefused)?;
    if request_id.len() != REQUEST_ID_BYTES * 2 || !canonical_request_id(request_id) {
        return Err(BootstrapError::RequestRefused);
    }
    BootstrapRequestEnvelope::deserialize(value)
        .map(|envelope| envelope.request_id)
        .map_err(|_| BootstrapError::RequestRefused)
}

/// Un objet dont les clés requises sont toutes là, et dont chaque clé restante
/// appartient à la liste optionnelle. La forme d'`exact_object`, ouverte aux
/// champs conditionnels.
///
/// Le refus des clés inconnues est ici une défense en profondeur, et c'est
/// mesuré : la mutation qui l'y retire laisse la suite verte, parce que
/// `deny_unknown_fields` les refuse une couche plus bas. Ce que cette couche
/// tient en PROPRE — et que sa mutation fait rougir — ce sont les tailles :
/// chaque chaîne est bornée avant que serde en possède une copie.
fn object_with<'a>(
    value: &'a serde_json::Value,
    required: &[&str],
    optional: &[&str],
) -> Option<&'a serde_json::Map<String, serde_json::Value>> {
    let object = value.as_object()?;
    (required.iter().all(|field| object.contains_key(*field))
        && object
            .keys()
            .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str())))
    .then_some(object)
}

fn exact_object<'a>(
    value: &'a serde_json::Value,
    expected: &[&str],
) -> Option<&'a serde_json::Map<String, serde_json::Value>> {
    let object = value.as_object()?;
    (object.len() == expected.len() && expected.iter().all(|field| object.contains_key(*field)))
        .then_some(object)
}

fn bounded_string(value: Option<&serde_json::Value>, max_bytes: usize) -> Option<&str> {
    value?.as_str().filter(|value| value.len() <= max_bytes)
}

struct BootstrapSession {
    request_id: String,
    mode: BootstrapMode,
    target: BootstrapTarget,
    expires_at: Instant,
    /// L'action que l'humain a demandée — l'audit quand la demande n'en nomme
    /// aucune, la forme d'hier restant la forme par défaut.
    action: BootstrapAction,
    declared_target: Option<DeclaredTarget>,
    machine_configuration: Option<MachineConfigurationValues>,
    /// L'issue terminale, une fois l'Assistant parti. `None` tant qu'il court.
    ///
    /// Elle est RETENUE plutôt qu'effacée — c'est la clôture d'affaires que
    /// `bootstrap_status` différait : un frontend qui ne peut pas relire
    /// l'issue ne peut pas la nommer, et un succès effacé se raconte comme un
    /// silence. La session conclue reste lisible jusqu'à son échéance ou
    /// jusqu'au démarrage suivant, qui la remplace.
    concluded: Option<BootstrapLifecycle>,
}

/// Une demande de démarrage validée en forme, prête à devenir une session.
struct PreparedStart {
    mode: BootstrapMode,
    target: BootstrapTarget,
    action: BootstrapAction,
    declared_target: Option<DeclaredTarget>,
    machine_configuration: Option<MachineConfigurationValues>,
}

pub(crate) struct NativeAssistantLaunch {
    pub(crate) scope: AssistantScopeV1,
    pub(crate) expires_at: Instant,
}

#[derive(Default)]
pub struct BootstrapState {
    active: Option<BootstrapSession>,
    closed: bool,
}

impl BootstrapState {
    pub fn start(
        &mut self,
        input: BootstrapStartInput,
    ) -> Result<BootstrapSessionView, BootstrapError> {
        let now = Instant::now();
        let prepared = self.prepare_start(input, now)?;
        self.activate(prepared, now, random_request_id()?)
    }

    pub fn status(&mut self, request_id: &str) -> Result<BootstrapSessionView, BootstrapError> {
        self.status_at(request_id, Instant::now())
    }

    pub fn cancel(&mut self, request_id: &str) -> Result<(), BootstrapError> {
        self.cancel_at(request_id, Instant::now())
    }

    pub fn assistant_scope(
        &mut self,
        request_id: &str,
    ) -> Result<NativeAssistantLaunch, BootstrapError> {
        self.assistant_scope_at(request_id, Instant::now())
    }

    fn assistant_scope_at(
        &mut self,
        request_id: &str,
        now: Instant,
    ) -> Result<NativeAssistantLaunch, BootstrapError> {
        self.require_active_request(request_id, now)?;
        let (active_request_id, mode, target, expires_at, remaining_millis) = {
            let active = self.active.as_ref().ok_or(BootstrapError::RequestRefused)?;
            let remaining_millis = u64::try_from(
                active
                    .expires_at
                    .checked_duration_since(now)
                    .ok_or(BootstrapError::Expired)?
                    .as_millis(),
            )
            .map_err(|_| BootstrapError::RequestRefused)?;
            (
                active.request_id.clone(),
                active.mode,
                active.target.clone(),
                active.expires_at,
                remaining_millis,
            )
        };
        let active = self.active.as_ref().ok_or(BootstrapError::RequestRefused)?;
        if remaining_millis == 0 {
            self.clear();
            return Err(BootstrapError::Expired);
        }
        let (step, prompt) = initial_native_step(target.access_kind);
        Ok(NativeAssistantLaunch {
            scope: AssistantScopeV1 {
                schema_version: 1,
                request_id: active_request_id,
                mode,
                target,
                step,
                // L'action que l'humain a demandée, et ce qu'elle exige. La
                // cohérence a une seule maison — la validation du scope, que le
                // lancement impose — et ce lanceur ne fait que porter ce que la
                // session a retenu.
                actions: [active.action],
                prompt,
                // The launcher never resolves a name and therefore never freezes an
                // address. Only the assistant's single resolution fills this, and only
                // before its own consent window renders it.
                target_addresses: Vec::new(),
                machine_configuration: active.machine_configuration.clone(),
                declared_target: active.declared_target.clone(),
                // The launcher replaces this safe placeholder immediately before transport.
                issued_at_monotonic_nanos: 0,
                remaining_millis,
            },
            expires_at,
        })
    }

    pub fn clear(&mut self) {
        self.active = None;
    }

    pub fn close(&mut self) {
        self.closed = true;
        self.clear();
    }

    #[cfg(test)]
    fn start_at(
        &mut self,
        input: BootstrapStartInput,
        now: Instant,
        request_id: String,
    ) -> Result<BootstrapSessionView, BootstrapError> {
        if !canonical_request_id(&request_id) {
            return Err(BootstrapError::RequestRefused);
        }
        let prepared = self.prepare_start(input, now)?;
        self.activate(prepared, now, request_id)
    }

    fn prepare_start(
        &mut self,
        input: BootstrapStartInput,
        now: Instant,
    ) -> Result<PreparedStart, BootstrapError> {
        if self.closed {
            return Err(BootstrapError::RequestRefused);
        }
        self.clear_if_expired(now);
        // Une session CONCLUE ne travaille plus : elle reste lisible pour que
        // la vue nomme son issue, mais elle ne retient aucun helper et ne doit
        // pas bloquer le parcours suivant. Seule une session encore en attente
        // est occupée.
        if self
            .active
            .as_ref()
            .is_some_and(|active| active.concluded.is_none())
        {
            return Err(BootstrapError::Busy);
        }
        let target = validate_target(input.target).map_err(|_| BootstrapError::InvalidInput)?;
        Ok(PreparedStart {
            mode: input.mode,
            target,
            action: input.action.unwrap_or(BootstrapAction::AuditTargetReadOnly),
            declared_target: input.declared_target,
            machine_configuration: input.machine_configuration,
        })
    }

    fn activate(
        &mut self,
        prepared: PreparedStart,
        now: Instant,
        request_id: String,
    ) -> Result<BootstrapSessionView, BootstrapError> {
        let expires_at = now
            .checked_add(BOOTSTRAP_TTL)
            .ok_or(BootstrapError::RequestRefused)?;
        self.active = Some(BootstrapSession {
            request_id,
            mode: prepared.mode,
            target: prepared.target,
            expires_at,
            action: prepared.action,
            declared_target: prepared.declared_target,
            machine_configuration: prepared.machine_configuration,
            concluded: None,
        });
        self.active_view(now)
    }

    fn status_at(
        &mut self,
        request_id: &str,
        now: Instant,
    ) -> Result<BootstrapSessionView, BootstrapError> {
        self.require_active_request(request_id, now)?;
        self.active_view(now)
    }

    fn cancel_at(&mut self, request_id: &str, now: Instant) -> Result<(), BootstrapError> {
        self.require_active_request(request_id, now)?;
        self.clear();
        Ok(())
    }

    fn require_active_request(
        &mut self,
        request_id: &str,
        now: Instant,
    ) -> Result<(), BootstrapError> {
        if !canonical_request_id(request_id) {
            return Err(BootstrapError::RequestRefused);
        }
        if self.is_expired(now) {
            self.clear();
            return Err(BootstrapError::Expired);
        }
        let active = self.active.as_ref().ok_or(BootstrapError::RequestRefused)?;
        if active.request_id != request_id {
            return Err(BootstrapError::RequestRefused);
        }
        Ok(())
    }

    fn active_view(&self, now: Instant) -> Result<BootstrapSessionView, BootstrapError> {
        let active = self.active.as_ref().ok_or(BootstrapError::RequestRefused)?;
        let remaining = active
            .expires_at
            .checked_duration_since(now)
            .ok_or(BootstrapError::Expired)?;
        let expires_in_seconds = remaining
            .as_secs()
            .saturating_add(u64::from(remaining.subsec_nanos() > 0));
        Ok(BootstrapSessionView {
            schema_version: 1,
            request_id: active.request_id.clone(),
            mode: active.mode,
            target: active.target.clone(),
            step: initial_native_step(active.target.access_kind).0,
            actions: [active.action],
            lifecycle: active
                .concluded
                .unwrap_or(BootstrapLifecycle::AwaitingNativeAssistant),
            expires_in_seconds,
        })
    }

    /// Retient l'issue terminale que le superviseur du helper vient de lire.
    ///
    /// Une conclusion ne s'écrit qu'une fois : la première issue est LA
    /// conclusion de la session, et un helper dont le cadavre serait relu ne
    /// peut pas la réécrire. Elle ne s'écrit que sur la session active — une
    /// issue arrivée pour une session déjà remplacée est refusée plutôt que
    /// posée sur la mauvaise.
    pub fn conclude(
        &mut self,
        request_id: &str,
        outcome: BootstrapLifecycle,
    ) -> Result<(), BootstrapError> {
        if outcome == BootstrapLifecycle::AwaitingNativeAssistant {
            // « En attente » n'est pas une issue : conclure dessus rendrait la
            // session éternellement re-concluable.
            return Err(BootstrapError::RequestRefused);
        }
        let active = self.active.as_mut().ok_or(BootstrapError::RequestRefused)?;
        if active.request_id != request_id || active.concluded.is_some() {
            return Err(BootstrapError::RequestRefused);
        }
        active.concluded = Some(outcome);
        Ok(())
    }

    fn clear_if_expired(&mut self, now: Instant) {
        if self.is_expired(now) {
            self.clear();
        }
    }

    fn is_expired(&self, now: Instant) -> bool {
        self.active
            .as_ref()
            .is_some_and(|active| now >= active.expires_at)
    }
}

fn initial_native_step(
    access_kind: your_cloud_bootstrap_protocol::BootstrapAccessKind,
) -> (BootstrapStep, NativePromptKind) {
    match access_kind {
        your_cloud_bootstrap_protocol::BootstrapAccessKind::Administrator => (
            BootstrapStep::PersonalAccess,
            NativePromptKind::ConfirmPersonalAccess,
        ),
        your_cloud_bootstrap_protocol::BootstrapAccessKind::Root => (
            BootstrapStep::RootAccess,
            NativePromptKind::ConfirmRootAccess,
        ),
    }
}

fn random_request_id() -> Result<String, BootstrapError> {
    let mut raw = [0_u8; REQUEST_ID_BYTES];
    OsRng
        .try_fill_bytes(&mut raw)
        .map_err(|_| BootstrapError::RequestRefused)?;
    Ok(hex::encode(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use your_cloud_bootstrap_protocol::BootstrapAccessKind;

    const REQUEST_ONE: &str = "00112233445566778899aabbccddeeff";
    const REQUEST_TWO: &str = "ffeeddccbbaa99887766554433221100";
    const HOST_KEY: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn target() -> BootstrapTarget {
        BootstrapTarget {
            host: "Controller.Example.test".into(),
            port: 22,
            username: "infra_admin".into(),
            host_key_sha256: HOST_KEY.into(),
            access_kind: BootstrapAccessKind::Administrator,
        }
    }

    fn input(mode: BootstrapMode) -> BootstrapStartInput {
        BootstrapStartInput {
            mode,
            target: target(),
            action: None,
            declared_target: None,
            machine_configuration: None,
        }
    }

    /// **La conclusion est retenue, relisible, et ne s'écrit qu'une fois.**
    ///
    /// C'est la clôture d'affaires : un frontend qui ne peut pas relire
    /// l'issue ne peut pas la nommer, et un succès effacé se raconte comme un
    /// silence. Le test tient les trois moitiés — l'issue se relit autant de
    /// fois qu'on veut, la première écriture est la seule, et « en attente »
    /// n'est pas une issue.
    #[test]
    fn a_concluded_session_is_readable_and_concludes_only_once() {
        let mut state = BootstrapState::default();
        let now = Instant::now();
        let view = state
            .prepare_start(input(BootstrapMode::Create), now)
            .and_then(|prepared| state.activate(prepared, now, REQUEST_ONE.into()))
            .expect("la session démarre");
        assert_eq!(view.lifecycle, BootstrapLifecycle::AwaitingNativeAssistant);

        state
            .conclude(REQUEST_ONE, BootstrapLifecycle::AccessVerified)
            .expect("la première conclusion s'écrit");
        for _ in 0..3 {
            let read = state.status_at(REQUEST_ONE, now).expect("l'issue se relit");
            assert_eq!(read.lifecycle, BootstrapLifecycle::AccessVerified);
        }

        // La conclusion ne se réécrit pas — ni par une autre issue, ni par la
        // même.
        for outcome in [
            BootstrapLifecycle::Refused,
            BootstrapLifecycle::AccessVerified,
        ] {
            assert!(matches!(
                state.conclude(REQUEST_ONE, outcome),
                Err(BootstrapError::RequestRefused)
            ));
        }

        // « En attente » n'est jamais une issue.
        let mut fresh = BootstrapState::default();
        fresh
            .prepare_start(input(BootstrapMode::Create), now)
            .and_then(|prepared| fresh.activate(prepared, now, REQUEST_TWO.into()))
            .expect("la session démarre");
        assert!(matches!(
            fresh.conclude(REQUEST_TWO, BootstrapLifecycle::AwaitingNativeAssistant),
            Err(BootstrapError::RequestRefused)
        ));
    }

    /// Une session conclue ne bloque pas le parcours suivant, et une issue ne
    /// se pose jamais sur la session qui l'a remplacée.
    #[test]
    fn a_concluded_session_yields_to_the_next_start_and_never_receives_its_outcome() {
        let mut state = BootstrapState::default();
        let now = Instant::now();
        state
            .prepare_start(input(BootstrapMode::Create), now)
            .and_then(|prepared| state.activate(prepared, now, REQUEST_ONE.into()))
            .expect("la première session démarre");

        // En attente : le démarrage suivant est occupé — l'invariant existant.
        assert!(matches!(
            state.prepare_start(input(BootstrapMode::Create), now),
            Err(BootstrapError::Busy)
        ));

        state
            .conclude(REQUEST_ONE, BootstrapLifecycle::Refused)
            .expect("la session se conclut");
        // Conclue : elle cède la place.
        state
            .prepare_start(input(BootstrapMode::Create), now)
            .and_then(|prepared| state.activate(prepared, now, REQUEST_TWO.into()))
            .expect("le parcours suivant démarre");

        // Une issue tardive du helper de la PREMIÈRE session ne se pose pas
        // sur la seconde.
        assert!(matches!(
            state.conclude(REQUEST_ONE, BootstrapLifecycle::AccessVerified),
            Err(BootstrapError::RequestRefused)
        ));
        let read = state.status_at(REQUEST_TWO, now).expect("la seconde vit");
        assert_eq!(read.lifecycle, BootstrapLifecycle::AwaitingNativeAssistant);
    }

    /// **La demande nomme son action, et le lanceur la porte jusqu'au scope**
    /// — avec la déclaration et la configuration qu'elle exige.
    ///
    /// C'est le fil que cette tranche câble : ce que le frontend demande est ce
    /// que la session retient, ce que la vue rend, et ce que le helper recevra.
    /// Un lanceur qui figerait l'audit — ce qu'il a fait jusqu'ici — ouvrirait
    /// une fenêtre d'audit pour une demande de pose, et l'humain approuverait
    /// autre chose que ce qu'il a demandé.
    #[test]
    fn the_requested_action_travels_from_the_start_input_to_the_scope() {
        let mut state = BootstrapState::default();
        let now = Instant::now();
        let request = BootstrapStartInput {
            action: Some(BootstrapAction::InstallServerBundle),
            declared_target: Some(DeclaredTarget {
                private: true,
                normally_on: true,
            }),
            machine_configuration: Some(MachineConfigurationValues {
                listen: "192.168.240.115:9443".into(),
                allowed_source: "192.168.240.0/24".into(),
                relay_endpoint: "192.168.240.9:9444".into(),
            }),
            ..input(BootstrapMode::Create)
        };

        let view = state
            .start_at(request, now, REQUEST_ONE.into())
            .expect("une demande de pose démarre");
        assert_eq!(view.actions, [BootstrapAction::InstallServerBundle]);

        let launch = state
            .assistant_scope_at(REQUEST_ONE, now + Duration::from_secs(1))
            .expect("le scope se construit");
        assert_eq!(launch.scope.actions, [BootstrapAction::InstallServerBundle]);
        assert_eq!(
            launch.scope.declared_target,
            Some(DeclaredTarget {
                private: true,
                normally_on: true,
            })
        );
        let configuration = launch
            .scope
            .machine_configuration
            .as_ref()
            .expect("la pose porte sa configuration");
        assert_eq!(configuration.listen, "192.168.240.115:9443");
        // Et le scope entier reste licite aux yeux du protocole : la cohérence
        // action/déclaration/configuration a une seule maison, sa validation.
        let mut stamped = launch.scope.clone();
        stamped.issued_at_monotonic_nanos = 1;
        stamped.validate().expect("le scope de pose est licite");
    }

    /// La demande d'hier — sans action — reste exactement l'audit d'hier.
    #[test]
    fn a_request_naming_no_action_stays_the_audit_it_always_was() {
        let mut state = BootstrapState::default();
        let now = Instant::now();
        let view = state
            .start_at(input(BootstrapMode::Create), now, REQUEST_ONE.into())
            .expect("la demande d'hier démarre");
        assert_eq!(view.actions, [BootstrapAction::AuditTargetReadOnly]);

        let launch = state
            .assistant_scope_at(REQUEST_ONE, now + Duration::from_secs(1))
            .expect("le scope se construit");
        assert_eq!(launch.scope.actions, [BootstrapAction::AuditTargetReadOnly]);
        assert_eq!(launch.scope.declared_target, None);
        assert_eq!(launch.scope.machine_configuration, None);
    }

    /// Le parseur borné accepte la demande complète et refuse ce qui déborde,
    /// AVANT que serde possède la moindre copie.
    #[test]
    fn the_bounded_parser_accepts_the_full_request_and_refuses_what_overflows() {
        let full = serde_json::json!({
            "input": {
                "mode": "create",
                "target": {
                    "host": "controller.example.test",
                    "port": 22,
                    "username": "infra_admin",
                    "host_key_sha256": HOST_KEY,
                    "access_kind": "administrator",
                },
                "action": "install_server_bundle",
                "declared_target": { "private": true, "normally_on": true },
                "machine_configuration": {
                    "listen": "192.168.240.115:9443",
                    "allowed_source": "192.168.240.0/24",
                    "relay_endpoint": "192.168.240.9:9444",
                },
            }
        });
        let parsed = parse_start_envelope(&full).expect("la demande complète se lit");
        assert_eq!(parsed.action, Some(BootstrapAction::InstallServerBundle));

        // Une valeur de configuration au-delà de la borne du protocole est
        // refusée ici, avant serde.
        let mut oversized = full.clone();
        oversized["input"]["machine_configuration"]["listen"] =
            serde_json::Value::String("a".repeat(MAX_CONFIGURATION_VALUE_BYTES + 1));
        assert!(matches!(
            parse_start_envelope(&oversized),
            Err(BootstrapError::InvalidInput)
        ));

        // Une clé inconnue dans la demande est refusée — la liste est close.
        let mut foreign = full.clone();
        foreign["input"]["forwarding"] = serde_json::Value::Bool(true);
        assert!(matches!(
            parse_start_envelope(&foreign),
            Err(BootstrapError::InvalidInput)
        ));

        // Une déclaration qui n'est pas deux booléens est refusée.
        let mut stringly = full;
        stringly["input"]["declared_target"]["private"] = serde_json::Value::String("oui".into());
        assert!(matches!(
            parse_start_envelope(&stringly),
            Err(BootstrapError::InvalidInput)
        ));
    }

    fn root_input(mode: BootstrapMode) -> BootstrapStartInput {
        BootstrapStartInput {
            mode,
            target: BootstrapTarget {
                username: "root".into(),
                access_kind: BootstrapAccessKind::Root,
                ..target()
            },
            action: None,
            declared_target: None,
            machine_configuration: None,
        }
    }

    fn start_envelope() -> serde_json::Value {
        serde_json::json!({
            "input": {
                "mode": "create",
                "target": {
                    "host": "host.test",
                    "port": 22,
                    "username": "admin",
                    "host_key_sha256": HOST_KEY,
                    "access_kind": "administrator"
                }
            }
        })
    }

    #[test]
    fn starts_one_immutable_public_scope() {
        let now = Instant::now();
        let mut state = BootstrapState::default();

        let started = state
            .start_at(input(BootstrapMode::Create), now, REQUEST_ONE.into())
            .unwrap();
        let status = state
            .status_at(REQUEST_ONE, now + Duration::from_secs(1))
            .unwrap();

        assert_eq!(started.request_id, REQUEST_ONE);
        assert_eq!(started.target.host, "controller.example.test");
        assert_eq!(started.step, BootstrapStep::PersonalAccess);
        assert_eq!(started.actions, [BootstrapAction::AuditTargetReadOnly]);
        assert_eq!(started.expires_in_seconds, 300);
        assert_eq!(status.mode, started.mode);
        assert_eq!(status.target, started.target);
        assert_eq!(status.step, started.step);
        assert_eq!(status.actions, started.actions);
        assert_eq!(status.expires_in_seconds, 299);
    }

    #[test]
    fn derives_the_helper_scope_from_the_active_native_session() {
        let now = Instant::now();
        let mut state = BootstrapState::default();
        let started = state
            .start_at(input(BootstrapMode::Replace), now, REQUEST_ONE.into())
            .unwrap();

        let launch = state
            .assistant_scope_at(REQUEST_ONE, now + Duration::from_secs(1))
            .unwrap();
        let scope = launch.scope;

        assert_eq!(scope.request_id, started.request_id);
        assert_eq!(scope.mode, started.mode);
        assert_eq!(scope.target, started.target);
        assert_eq!(scope.step, BootstrapStep::PersonalAccess);
        assert_eq!(scope.actions, [BootstrapAction::AuditTargetReadOnly]);
        assert_eq!(scope.prompt, NativePromptKind::ConfirmPersonalAccess);
        assert_eq!(scope.issued_at_monotonic_nanos, 0);
        assert_eq!(scope.remaining_millis, 299_000);
        assert_eq!(launch.expires_at, now + BOOTSTRAP_TTL);
    }

    #[test]
    fn root_route_requires_its_dedicated_native_confirmation() {
        let now = Instant::now();
        let mut state = BootstrapState::default();
        let started = state
            .start_at(root_input(BootstrapMode::Create), now, REQUEST_ONE.into())
            .unwrap();
        let launch = state.assistant_scope_at(REQUEST_ONE, now).unwrap();

        assert_eq!(started.step, BootstrapStep::RootAccess);
        assert_eq!(launch.scope.step, BootstrapStep::RootAccess);
        assert_eq!(launch.scope.prompt, NativePromptKind::ConfirmRootAccess);
        assert_eq!(launch.scope.target.access_kind, BootstrapAccessKind::Root);
    }

    #[test]
    fn refuses_concurrent_and_forged_requests_without_changing_scope() {
        let now = Instant::now();
        let mut state = BootstrapState::default();
        state
            .start_at(input(BootstrapMode::Create), now, REQUEST_ONE.into())
            .unwrap();

        assert!(matches!(
            state.start_at(input(BootstrapMode::Replace), now, REQUEST_TWO.into()),
            Err(BootstrapError::Busy)
        ));
        assert!(matches!(
            state.status_at(REQUEST_TWO, now),
            Err(BootstrapError::RequestRefused)
        ));
        assert!(matches!(
            state.cancel_at("../../forged", now),
            Err(BootstrapError::RequestRefused)
        ));
        assert_eq!(
            state.status_at(REQUEST_ONE, now).unwrap().mode,
            BootstrapMode::Create
        );
    }

    #[test]
    fn cancellation_makes_the_request_unusable() {
        let now = Instant::now();
        let mut state = BootstrapState::default();
        state
            .start_at(input(BootstrapMode::Replace), now, REQUEST_ONE.into())
            .unwrap();

        state.cancel_at(REQUEST_ONE, now).unwrap();

        assert!(matches!(
            state.status_at(REQUEST_ONE, now),
            Err(BootstrapError::RequestRefused)
        ));
        assert!(matches!(
            state.cancel_at(REQUEST_ONE, now),
            Err(BootstrapError::RequestRefused)
        ));
    }

    #[test]
    fn expiration_clears_the_request_and_allows_a_new_one() {
        let now = Instant::now();
        let mut state = BootstrapState::default();
        state
            .start_at(input(BootstrapMode::Create), now, REQUEST_ONE.into())
            .unwrap();

        assert!(matches!(
            state.status_at(REQUEST_ONE, now + BOOTSTRAP_TTL),
            Err(BootstrapError::Expired)
        ));
        assert!(matches!(
            state.status_at(REQUEST_ONE, now + BOOTSTRAP_TTL),
            Err(BootstrapError::RequestRefused)
        ));
        let next = state
            .start_at(
                input(BootstrapMode::Replace),
                now + BOOTSTRAP_TTL,
                REQUEST_TWO.into(),
            )
            .unwrap();
        assert_eq!(next.request_id, REQUEST_TWO);
    }

    #[test]
    fn clear_makes_the_request_unusable() {
        let now = Instant::now();
        let mut state = BootstrapState::default();
        state
            .start_at(input(BootstrapMode::Create), now, REQUEST_ONE.into())
            .unwrap();

        state.clear();

        assert!(matches!(
            state.status_at(REQUEST_ONE, now),
            Err(BootstrapError::RequestRefused)
        ));
    }

    #[test]
    fn close_is_terminal_and_destroys_the_active_request() {
        let now = Instant::now();
        let mut state = BootstrapState::default();
        state
            .start_at(input(BootstrapMode::Create), now, REQUEST_ONE.into())
            .unwrap();

        state.close();

        assert!(matches!(
            state.status_at(REQUEST_ONE, now),
            Err(BootstrapError::RequestRefused)
        ));
        assert!(matches!(
            state.start_at(input(BootstrapMode::Replace), now, REQUEST_TWO.into()),
            Err(BootstrapError::RequestRefused)
        ));
    }

    #[test]
    fn rejects_unknown_or_authoritative_envelope_fields() {
        for field in ["request_id", "step", "actions", "ttl_seconds", "password"] {
            let mut document = start_envelope();
            document
                .as_object_mut()
                .unwrap()
                .insert(field.into(), serde_json::json!("forbidden"));
            assert!(matches!(
                parse_start_envelope(&document),
                Err(BootstrapError::InvalidInput)
            ));
        }

        let mut nested_unknown = start_envelope();
        nested_unknown["input"]["target"]["command"] = serde_json::json!("forbidden");
        assert!(matches!(
            parse_start_envelope(&nested_unknown),
            Err(BootstrapError::InvalidInput)
        ));

        let mut authoritative = start_envelope();
        authoritative["input"]["step"] = serde_json::json!("personal_access");
        assert!(matches!(
            parse_start_envelope(&authoritative),
            Err(BootstrapError::InvalidInput)
        ));

        assert!(parse_start_envelope(&start_envelope()).is_ok());
    }

    #[test]
    fn request_envelope_returns_only_closed_errors() {
        assert_eq!(
            parse_request_envelope(&serde_json::json!({ "requestId": REQUEST_ONE })).unwrap(),
            REQUEST_ONE
        );
        for forged in [
            serde_json::Value::Null,
            serde_json::json!({ "requestId": "00112233445566778899AABBCCDDEEFF" }),
            serde_json::json!({ "request_id": REQUEST_ONE }),
            serde_json::json!({ "requestId": REQUEST_ONE, "approve": true }),
        ] {
            assert!(matches!(
                parse_request_envelope(&forged),
                Err(BootstrapError::RequestRefused)
            ));
        }
    }

    #[test]
    fn rejects_oversized_host_key_before_decoding() {
        let mut document = start_envelope();
        document["input"]["target"]["host_key_sha256"] =
            serde_json::Value::String(format!("SHA256:{}", "A".repeat(1024 * 1024)));

        assert!(matches!(
            parse_start_envelope(&document),
            Err(BootstrapError::InvalidInput)
        ));
    }

    #[test]
    fn rejects_targets_outside_the_positive_schema() {
        let now = Instant::now();
        let invalid_targets = [
            BootstrapTarget {
                host: "https://host.test/path".into(),
                ..target()
            },
            BootstrapTarget {
                host: " host.test".into(),
                ..target()
            },
            BootstrapTarget {
                host: "127.000.000.001".into(),
                ..target()
            },
            BootstrapTarget {
                host: "127.0.0.1".into(),
                ..target()
            },
            BootstrapTarget {
                host: "0.0.0.0".into(),
                ..target()
            },
            BootstrapTarget {
                host: "169.254.1.1".into(),
                ..target()
            },
            BootstrapTarget {
                host: "224.0.0.1".into(),
                ..target()
            },
            BootstrapTarget {
                host: "::1".into(),
                ..target()
            },
            BootstrapTarget {
                host: "fe80::1".into(),
                ..target()
            },
            BootstrapTarget {
                host: "ff02::1".into(),
                ..target()
            },
            BootstrapTarget {
                host: "::ffff:127.0.0.1".into(),
                ..target()
            },
            BootstrapTarget {
                host: "::ffff:169.254.169.254".into(),
                ..target()
            },
            BootstrapTarget {
                host: "::ffff:224.0.0.1".into(),
                ..target()
            },
            BootstrapTarget {
                host: "localhost".into(),
                ..target()
            },
            BootstrapTarget {
                host: "machine.localhost".into(),
                ..target()
            },
            BootstrapTarget {
                port: 0,
                ..target()
            },
            BootstrapTarget {
                username: "Root".into(),
                ..target()
            },
            BootstrapTarget {
                username: "root".into(),
                ..target()
            },
            BootstrapTarget {
                host_key_sha256: "SHA256:not-canonical".into(),
                ..target()
            },
            BootstrapTarget {
                username: "admin".into(),
                access_kind: BootstrapAccessKind::Root,
                ..target()
            },
        ];

        for invalid in invalid_targets {
            let mut state = BootstrapState::default();
            assert!(matches!(
                state.start_at(
                    BootstrapStartInput {
                        mode: BootstrapMode::Create,
                        target: invalid,
                        action: None,
                        declared_target: None,
                        machine_configuration: None,
                    },
                    now,
                    REQUEST_ONE.into(),
                ),
                Err(BootstrapError::InvalidInput)
            ));
        }
        let mut state = BootstrapState::default();
        assert!(state
            .start_at(
                BootstrapStartInput {
                    mode: BootstrapMode::Create,
                    target: BootstrapTarget {
                        host: "2001:db8::1".into(),
                        username: "root".into(),
                        access_kind: BootstrapAccessKind::Root,
                        ..target()
                    },
                    action: None,
                    declared_target: None,
                    machine_configuration: None,
                },
                now,
                REQUEST_ONE.into(),
            )
            .is_ok());
    }

    #[test]
    fn production_request_id_is_native_and_canonical() {
        let mut state = BootstrapState::default();
        let started = state.start(input(BootstrapMode::Create)).unwrap();

        assert!(canonical_request_id(&started.request_id));
        assert_ne!(started.request_id, REQUEST_ONE);
    }
}
