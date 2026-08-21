// The approval path is signed here and verified by the Auxiliary end to end.
// This module also holds the two halves of the consent that must precede a
// signature: the document a native window is given, and the reading of the
// document it answers with. What is still missing is the window itself and the
// command that opens it, and both belong to the palier that adds them. Nothing
// in the command surface below reaches this module, which is exactly what "no
// free signature is exposed to the frontend" means for now.
#[allow(dead_code)]
mod approval;
mod bootstrap;
// The six plans of the private passage are verified, displayed and signed here,
// for the same reason `approval` above and the two plan modules below are not
// reachable from a command: the window that must render a plan before it is
// approved belongs to the palier that adds the command, and the source contract
// holds the command surface against that.
#[allow(dead_code)]
mod link_plan;
mod native_helper;
mod network;
// The probe plan is verified, displayed and signed here for the same reason the
// module above is not reachable from a command: the window that must render a
// plan before it is approved belongs to the palier that adds the command, and
// the source contract holds the command surface against that.
#[allow(dead_code)]
mod probe_plan;
// The three plans of the public profile are verified, displayed and signed
// here, for the same reason the three modules above are not reachable from a
// command: the window that must render a plan before it is approved belongs to
// the palier that adds the command, and the source contract holds the command
// surface against that.
#[allow(dead_code)]
mod plan_consent;
mod publication_plan;
// The third door on the side that writes its one document. Unlike the plan
// modules above, this one *is* reachable from a command, and it may be: freezing
// a definition mints no envelope, signs nothing and reaches no native window —
// the document is inert, and the route that freezes it is a business route like
// the others.
mod service_definition;
mod vault;
#[cfg(windows)]
mod windows_security;

use bootstrap::BootstrapState;
use native_helper::{HelperInvocation, NativeHelperPoll, NativeHelperSupervisor};
use network::{
    ExternalElementsView, ExternalWithdrawalView, InfrastructureView, MachineMutationView,
    MachinesView, NetworkState, PairingInput, PlanDispatchAcceptedView, PlanDispatchesView,
};
use plan_consent::{PlanConsentError, PlanConsentSessionView, PlanConsentState};
use publication_plan::{
    PlanPairView, PresentedPublicationPlan, PublicationApprovalRequest,
    PublicationPlanConfirmation, PublicationPlanError,
};
use serde::Serialize;
use service_definition::{
    FrozenDefinitionView, ServiceDefinitionDraft, ServiceDefinitionPaste, ServiceDefinitionReview,
    ServiceDefinitionsProjection,
};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};
use tauri::{
    ipc::{InvokeBody, Request},
    Manager, State,
};
use vault::{
    AppCore, AppStatus, AssociationSummary, GeneratedLocalSecrets, PreparedPhraseChange,
    PreparedRecoveryRotation, RecoveryRotationProgress,
};
use your_cloud_bootstrap_protocol::{
    BootstrapSessionView, BootstrapStartInput, MAX_APPROVAL_LIFETIME_SECONDS,
};
use zeroize::Zeroizing;

/// What a refused command tells the surface above it.
///
/// `code` is the closed vocabulary a human sentence is chosen from, and it does
/// not grow here. `detail` is the second half of a refusal that could not
/// otherwise be acted on: it names **which** check refused, for the one code
/// whose sentence — « la réponse reçue ne respecte pas le contrat de
/// sécurité » — tells a reader nothing about what to do.
///
/// Il est presque toujours une chaîne fixe choisie par ce produit, jamais un
/// écho du reçu — avec UNE exception, écrite ici parce qu'elle contredit la
/// règle d'hier : le refus « entrée trop étroite » porte ce que l'entrée
/// sudoers permet aujourd'hui. C'est bien un écho de la machine, mais un écho
/// **attesté** — parsé par le juge du produit, borné et ASCII par le
/// protocole — et le contrat l'exige nommé : sans lui, l'humain devine au
/// lieu de choisir entre ses deux issues.
#[derive(Debug, Serialize)]
struct CommandError {
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

impl From<vault::VaultError> for CommandError {
    fn from(value: vault::VaultError) -> Self {
        Self {
            code: value.public_code(),
            // Ces refus se nomment déjà par leur code : rien à ajouter, et un
            // champ vide vaut mieux qu'un détail qui ne dirait rien de plus.
            detail: None,
        }
    }
}

impl From<network::NetworkError> for CommandError {
    fn from(value: network::NetworkError) -> Self {
        Self {
            code: value.public_code(),
            detail: value.detail().map(str::to_owned),
        }
    }
}

impl From<bootstrap::BootstrapError> for CommandError {
    fn from(value: bootstrap::BootstrapError) -> Self {
        Self {
            code: value.public_code(),
            // Un seul refus a une seconde moitié : l'entrée trop étroite porte
            // ce qu'elle permet. Les autres se nomment déjà par leur code.
            detail: value.detail(),
        }
    }
}

impl From<native_helper::NativeHelperError> for CommandError {
    fn from(value: native_helper::NativeHelperError) -> Self {
        Self {
            code: value.public_code(),
            // Ces refus se nomment déjà par leur code : rien à ajouter, et un
            // champ vide vaut mieux qu'un détail qui ne dirait rien de plus.
            detail: None,
        }
    }
}

struct AppLocalState {
    core: AppCore,
    bootstrap: BootstrapState,
    native_helper: NativeHelperSupervisor,
    /// The one pair currently under consideration, verified, with the exact
    /// bytes the Controller froze.
    ///
    /// It is one rather than a collection for the same reason a single helper
    /// runs at a time: a human considers one plan, and an App holding two
    /// would have to say which of them a window answered for. Keeping the exact
    /// bytes matters more than keeping them at all — asking again would build a
    /// second pair, and approving one while submitting the other is the whole
    /// class of failure the two digests exist to make impossible.
    plan_pair: Option<HeldPlanPair>,
    plan_consent: PlanConsentState,
}

/// The pair under consideration, kept twice over: verified, and as the exact
/// bytes that were verified.
///
/// The bytes are kept because the signature is taken over them: re-verifying at
/// signing time from documents that had been rebuilt would prove that a pair is
/// well formed, not that it is *this* one.
struct HeldPlanPair {
    presented: PresentedPublicationPlan,
    documents: PlanPairView,
    /// The frozen revision this plan pins, read back from the Controller rather
    /// than supplied by a caller: a definition assembled elsewhere would be a
    /// definition whose consequences nobody read. Empty for the doors that pin
    /// none — the Controller refuses one that travelled beside them.
    definition_document: String,
}

impl AppLocalState {
    fn start_bootstrap(
        &mut self,
        input: BootstrapStartInput,
    ) -> Result<BootstrapSessionView, CommandError> {
        if self.core.status()?.lock_state != "unlocked" {
            return Err(vault::VaultError::Locked.into());
        }
        let started = self.bootstrap.start(input)?;
        if let Err(error) = self.native_helper.stop_active() {
            self.bootstrap.clear();
            return Err(error.into());
        }
        let launch = match self.bootstrap.assistant_scope(&started.request_id) {
            Ok(launch) => launch,
            Err(error) => {
                self.bootstrap.clear();
                return Err(error.into());
            }
        };
        if let Err(error) = self
            .native_helper
            .start(HelperInvocation::Bootstrap(launch.scope), launch.expires_at)
        {
            self.bootstrap.clear();
            return Err(error.into());
        }
        Ok(started)
    }

    #[cfg(test)]
    fn start_bootstrap_state_only(
        &mut self,
        input: BootstrapStartInput,
    ) -> Result<BootstrapSessionView, CommandError> {
        if self.core.status()?.lock_state != "unlocked" {
            return Err(vault::VaultError::Locked.into());
        }
        self.bootstrap.start(input).map_err(Into::into)
    }

    fn lock(&mut self) -> Result<(), native_helper::NativeHelperError> {
        self.core.lock();
        let stopped = self.native_helper.stop_active();
        self.bootstrap.clear();
        stopped
    }

    fn close(&mut self) {
        let _ = self.native_helper.stop_active();
        self.bootstrap.close();
    }
}

struct AppRuntime {
    local: Mutex<AppLocalState>,
    network: Mutex<NetworkState>,
    request_generation: AtomicU64,
}

fn with_core<T>(
    state: &State<'_, AppRuntime>,
    operation: impl FnOnce(&mut AppCore) -> Result<T, vault::VaultError>,
) -> Result<T, CommandError> {
    let mut local = state.local.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    operation(&mut local.core).map_err(Into::into)
}

impl From<PlanConsentError> for CommandError {
    fn from(error: PlanConsentError) -> Self {
        Self {
            code: error.public_code(),
            // Ces refus se nomment déjà par leur code : rien à ajouter, et un
            // champ vide vaut mieux qu'un détail qui ne dirait rien de plus.
            detail: None,
        }
    }
}

impl From<PublicationPlanError> for CommandError {
    fn from(error: PublicationPlanError) -> Self {
        Self {
            code: error.public_code(),
            // Ces refus se nomment déjà par leur code : rien à ajouter, et un
            // champ vide vaut mieux qu'un détail qui ne dirait rien de plus.
            detail: None,
        }
    }
}

fn json_request_body<'a>(request: &'a Request<'_>) -> Result<&'a serde_json::Value, CommandError> {
    match request.body() {
        InvokeBody::Json(value) => Ok(value),
        InvokeBody::Raw(_) => Err(CommandError {
            code: "bootstrap_request_refused",
            detail: None,
        }),
    }
}

#[tauri::command]
fn app_status(state: State<'_, AppRuntime>) -> Result<AppStatus, CommandError> {
    with_core(&state, AppCore::status)
}

#[tauri::command]
fn prepare_app(state: State<'_, AppRuntime>) -> Result<GeneratedLocalSecrets, CommandError> {
    with_core(&state, AppCore::prepare)
}

#[tauri::command]
fn discard_app_preparation(
    generation_id: String,
    state: State<'_, AppRuntime>,
) -> Result<(), CommandError> {
    with_core(&state, |core| core.discard_preparation(&generation_id))
}

#[tauri::command]
fn confirm_app_initialization(
    generation_id: String,
    unlock_phrase: String,
    recovery_code: String,
    confirmed_copies: bool,
    state: State<'_, AppRuntime>,
) -> Result<AppStatus, CommandError> {
    with_core(&state, |core| {
        core.confirm_initialization(
            &generation_id,
            unlock_phrase,
            recovery_code,
            confirmed_copies,
        )
    })
}

#[tauri::command]
fn unlock_app(phrase: String, state: State<'_, AppRuntime>) -> Result<AppStatus, CommandError> {
    with_core(&state, |core| core.unlock(phrase))
}

#[tauri::command]
fn prepare_phrase_change(
    state: State<'_, AppRuntime>,
) -> Result<PreparedPhraseChange, CommandError> {
    with_core(&state, AppCore::prepare_phrase_change)
}

#[tauri::command]
fn confirm_phrase_change(
    generation_id: String,
    current_phrase: String,
    new_phrase: String,
    state: State<'_, AppRuntime>,
) -> Result<(), CommandError> {
    with_core(&state, |core| {
        core.confirm_phrase_change(&generation_id, current_phrase, new_phrase)
    })
}

#[tauri::command]
fn start_bootstrap(
    request: Request<'_>,
    state: State<'_, AppRuntime>,
) -> Result<BootstrapSessionView, CommandError> {
    let input = bootstrap::parse_start_envelope(json_request_body(&request)?)?;
    let mut local = state.local.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    local.start_bootstrap(input)
}

#[tauri::command]
fn bootstrap_status(
    request: Request<'_>,
    state: State<'_, AppRuntime>,
) -> Result<BootstrapSessionView, CommandError> {
    let request_id = bootstrap::parse_request_envelope(json_request_body(&request)?)?;
    let mut local = state.local.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    let view = match local.bootstrap.status(&request_id) {
        Ok(view) => view,
        Err(error @ bootstrap::BootstrapError::Expired) => {
            local.native_helper.stop_active()?;
            return Err(error.into());
        }
        Err(error) => return Err(error.into()),
    };
    // Une session déjà conclue n'a plus de helper à interroger : son issue est
    // retenue, la vue la relit autant de fois qu'elle veut, et c'est tout le
    // point de la clôture — un frontend qui ne peut relire une issue ne peut
    // pas la nommer.
    if view.lifecycle != your_cloud_bootstrap_protocol::BootstrapLifecycle::AwaitingNativeAssistant
    {
        return Ok(view);
    }
    // La conclusion est RETENUE plutôt qu'effacée, puis la vue est relue pour
    // que ce que le frontend reçoit soit ce que l'état a réellement retenu —
    // jamais une vue d'avant la conclusion.
    let mut conclude = |local: &mut AppLocalState,
                        outcome: your_cloud_bootstrap_protocol::BootstrapLifecycle|
     -> Result<BootstrapSessionView, CommandError> {
        local.bootstrap.conclude(&request_id, outcome)?;
        local.bootstrap.status(&request_id).map_err(Into::into)
    };
    match local.native_helper.poll(&request_id) {
        Ok(NativeHelperPoll::Running) => Ok(view),
        // Le helper a prouvé son accès — et, pour une action d'installation,
        // joué sa séquence — puis s'en est allé. L'issue est nommée au
        // frontend : c'est la clôture d'affaires que ce palier devait. La
        // portée d'installation qu'il a exportée est retenue AVANT de
        // conclure : c'est elle qui fera tomber le refus d'une pose suivante
        // avant toute session, et elle qui lève la rétention quand l'entrée a
        // été élargie.
        Ok(NativeHelperPoll::AccessVerified {
            installation_scope,
            install_ledger,
        }) => {
            local
                .bootstrap
                .retain_attested_scope(&request_id, installation_scope);
            local
                .bootstrap
                .record_install_ledger(&request_id, install_ledger);
            conclude(
                &mut *local,
                your_cloud_bootstrap_protocol::BootstrapLifecycle::AccessVerified,
            )
        }
        Ok(NativeHelperPoll::Refused {
            installation_scope,
            install_ledger,
            refusal,
        }) => {
            local
                .bootstrap
                .retain_attested_scope(&request_id, installation_scope);
            // Le déroulé du refus d'abord, la conclusion ensuite : c'est lui
            // qui permet à la vue de nommer ce qui était posé quand le refus
            // est tombé, au lieu de renvoyer à un registre illisible.
            local
                .bootstrap
                .record_install_ledger(&request_id, install_ledger);
            // La cause avant la conclusion, pour la même raison : la vue rend
            // une phrase qui nomme, au lieu de « n'a pas pu conclure » (#157).
            local.bootstrap.record_refusal(&request_id, refusal);
            conclude(
                &mut *local,
                your_cloud_bootstrap_protocol::BootstrapLifecycle::Refused,
            )
        }
        Ok(NativeHelperPoll::Cancelled) => conclude(
            &mut *local,
            your_cloud_bootstrap_protocol::BootstrapLifecycle::Cancelled,
        ),
        Ok(NativeHelperPoll::Unavailable) => conclude(
            &mut *local,
            your_cloud_bootstrap_protocol::BootstrapLifecycle::Unavailable,
        ),
        // An approval outcome read on a bootstrap session is not a weaker
        // bootstrap verdict; it is an answer to something else. The session is
        // cleared and refused rather than interpreted — the supervisor already
        // reads the frame its own invocation writes, so reaching here would
        // mean the two had been crossed, and this is the second place that
        // cannot happen.
        Ok(NativeHelperPoll::ApprovalDecided(_)) => {
            let _ = local.native_helper.stop_active();
            local.bootstrap.clear();
            Err(native_helper::NativeHelperError::RequestRefused.into())
        }
        Err(error) => {
            let _ = local.native_helper.stop_active();
            local.bootstrap.clear();
            Err(error.into())
        }
    }
}

#[tauri::command]
fn cancel_bootstrap(
    request: Request<'_>,
    state: State<'_, AppRuntime>,
) -> Result<(), CommandError> {
    let request_id = bootstrap::parse_request_envelope(json_request_body(&request)?)?;
    let mut local = state.local.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    let view = match local.bootstrap.status(&request_id) {
        Ok(view) => view,
        Err(error @ bootstrap::BootstrapError::Expired) => {
            local.native_helper.stop_active()?;
            return Err(error.into());
        }
        Err(error) => return Err(error.into()),
    };
    // Une session conclue n'a plus de helper : l'annuler retire seulement ce
    // que l'état retient encore, et exiger un processus à tuer refuserait un
    // geste parfaitement licite.
    if view.lifecycle == your_cloud_bootstrap_protocol::BootstrapLifecycle::AwaitingNativeAssistant
    {
        local.native_helper.cancel(&request_id)?;
    }
    local.bootstrap.cancel(&request_id).map_err(Into::into)
}

#[tauri::command]
fn lock_app(state: State<'_, AppRuntime>) -> Result<(), CommandError> {
    state.request_generation.fetch_add(1, Ordering::SeqCst);
    let local_result = match state.local.lock() {
        Ok(mut local) => local.lock().map_err(CommandError::from),
        Err(_) => Err(CommandError {
            code: "app_unavailable",
            detail: None,
        }),
    };
    let network_result = state
        .network
        .lock()
        .map_err(|_| CommandError {
            code: "app_unavailable",
            detail: None,
        })
        .map(|mut network| network.clear_sessions());
    local_result?;
    network_result
}

#[tauri::command]
fn cancel_pending_requests(state: State<'_, AppRuntime>) {
    state.request_generation.fetch_add(1, Ordering::SeqCst);
}

#[tauri::command]
fn pair_controller(
    input: PairingInput,
    state: State<'_, AppRuntime>,
) -> Result<AssociationSummary, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let replacing = input.mode == "recovery";
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    let active = network.pair(input, generation, &state.request_generation, |candidate| {
        if state.request_generation.load(Ordering::SeqCst) != generation {
            return Err(network::NetworkError::Cancelled);
        }
        let mut local = state
            .local
            .lock()
            .map_err(|_| network::NetworkError::AppUnavailable)?;
        local
            .core
            .store_association(candidate, replacing)
            .map(|_| ())
            .map_err(|_| network::NetworkError::AppUnavailable)
    })?;
    if state.request_generation.load(Ordering::SeqCst) != generation {
        return Err(network::NetworkError::Cancelled.into());
    }
    let mut local = state.local.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    local
        .core
        .store_association(active, true)
        .map_err(Into::into)
}

#[tauri::command]
fn read_infrastructure(
    infrastructure_id: String,
    state: State<'_, AppRuntime>,
) -> Result<InfrastructureView, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    let view = network
        .read_infrastructure(&association, generation, &state.request_generation)
        .map_err(CommandError::from)?;
    drop(network);
    if let Some(label) = &view.label {
        if association.summary.infrastructure_label.as_ref() != Some(label) {
            with_core(&state, |core| {
                core.update_association_label(&infrastructure_id, label.clone())
                    .map(|_| ())
            })?;
        }
    }
    Ok(view)
}

#[tauri::command]
fn read_machines(
    infrastructure_id: String,
    state: State<'_, AppRuntime>,
) -> Result<MachinesView, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    network
        .read_machines(&association, generation, &state.request_generation)
        .map_err(Into::into)
}

// The declared inventory is read beside the managed one, by the same session
// and against the same association. No command below it mutates an external
// element, because there is no such command to write: the only act this palier
// offers on a declaration is withdrawing the declaration.
#[tauri::command]
fn read_external_elements(
    infrastructure_id: String,
    state: State<'_, AppRuntime>,
) -> Result<ExternalElementsView, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    network
        .read_external_elements(&association, generation, &state.request_generation)
        .map_err(Into::into)
}

#[tauri::command]
fn withdraw_external_element(
    infrastructure_id: String,
    element_id: String,
    state: State<'_, AppRuntime>,
) -> Result<ExternalWithdrawalView, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    network
        .withdraw_external_element(
            &association,
            &element_id,
            generation,
            &state.request_generation,
        )
        .map_err(Into::into)
}

/// Reads one draft against the mirror, and says what freezing it would mean.
///
/// It is local and pure: no session, no network, no state of this App is
/// touched, and calling it is exactly as consequential as typing. It is also the
/// only door to a freeze — the command below can be given nothing this one did
/// not produce — so the panel of consequences is not something a frontend may
/// choose to display: it is what the answer carries beside the bytes.
#[tauri::command]
fn review_service_definition(draft: ServiceDefinitionDraft) -> ServiceDefinitionReview {
    service_definition::review_service_definition(&draft)
}

/// Reads one pasted `docker run` or `docker-compose.yml` into a draft.
///
/// It prefills and does nothing else. There is no infrastructure in the
/// signature and no session behind it, because nothing is submitted: what comes
/// back has to go through the review above and through a human before any of it
/// reaches a Controller.
#[tauri::command]
fn parse_service_definition_paste(pasted: String) -> ServiceDefinitionPaste {
    service_definition::parse_service_definition_paste(&pasted)
}

/// Reads every definition this infrastructure has frozen, rehashed one by one.
/// Reads back the frozen pair of one deployment, and renders it as sentences.
///
/// The App assembles nothing. It names a machine, a revision this
/// Controller already froze, and the three values a deployment really chooses —
/// which image revision, which local port, which public name — and the
/// Controller answers with two documents and two digests it froze itself.
///
/// What is returned is the **presentation**: the sentences a human reads and
/// the two digests that end the last two of them. The canonical bytes stay on
/// this side, reachable behind an explicit gesture and never as the default
/// form, because a human reads phrases and not documents.
///
/// The verification is not a formality on the way to a display. Both documents
/// are strict-decoded, both digests are rebuilt from the parsed fields rather
/// than believed, and the rollback is required to be the complete undoing of
/// the plan. A pair that fails any of it is refused whole: there is no
/// partially verified plan a window could render most of.
#[tauri::command]
fn read_plan_pair(
    infrastructure_id: String,
    machine_id: String,
    operation: String,
    definition_slug: String,
    definition_digest: String,
    image_digest: String,
    local_port: u16,
    origin_host: String,
    state: State<'_, AppRuntime>,
) -> Result<PlanPairPresentation, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    let view = network.build_user_service_plan(
        &association,
        &machine_id,
        &operation,
        &definition_slug,
        &definition_digest,
        &image_digest,
        local_port,
        &origin_host,
        generation,
        &state.request_generation,
    )?;
    // The revision this plan pins is read back from the Controller now, while
    // the association is in hand: the submission that follows carries it, and
    // carrying one a caller supplied would be carrying one nobody read.
    let definitions =
        network.read_service_definitions(&association, generation, &state.request_generation)?;
    drop(network);
    let definition_document = definitions
        .definitions
        .iter()
        .find(|entry| entry.slug == definition_slug && entry.definition_sha256 == definition_digest)
        .map(|entry| entry.definition_document.clone())
        .ok_or(CommandError {
            code: "definition_absent",
            detail: None,
        })?;

    let presented = PresentedPublicationPlan::verify(&view)?;
    let presentation = PlanPairPresentation {
        schema_version: 1,
        machine_id: presented.machine_id().to_owned(),
        plan_sha256: presented.plan_sha256().to_owned(),
        rollback_sha256: presented.rollback_sha256().to_owned(),
        confirmation_lines: presented.confirmation_lines(),
    };
    // The verified pair is kept whole, with the bytes that were verified, so the
    // window and the submission that follow answer for these documents and not
    // for a second pair built from the same request.
    let mut local = state.local.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    local.plan_pair = Some(HeldPlanPair {
        presented,
        documents: view,
        definition_document,
    });
    // A new pair ends any window still open on the previous one: an answer
    // about a plan nobody is considering any more is an answer about nothing.
    local.plan_consent.clear();
    let _ = local.native_helper.stop_active();
    Ok(presentation)
}

/// Opens the native window on the pair currently under consideration.
///
/// The App does not ask a human to approve *a plan it describes*: it hands
/// the separate window the sentences it derived from the two documents it
/// verified, and that window is drawn by a process the WebView cannot reach.
/// The identifier of the session is drawn here and never accepted from the
/// caller — a frontend naming its own request could name one whose answer it
/// had already seen.
///
/// One window at a time, and that exclusion is the helper's own: a bootstrap in
/// progress refuses this just as this refuses a bootstrap.
#[tauri::command]
fn open_plan_consent(
    infrastructure_id: String,
    state: State<'_, AppRuntime>,
) -> Result<PlanConsentSessionView, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut local = state.local.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    if local.core.status()?.lock_state != "unlocked" {
        return Err(vault::VaultError::Locked.into());
    }
    let Some(held) = local.plan_pair.as_ref() else {
        return Err(PlanConsentError::NoPlan.into());
    };
    let presented = held.presented.clone();
    let (view, consent, expires_at) = local.plan_consent.start(|request_id, remaining| {
        presented.consent(&association, request_id, remaining).ok()
    })?;
    if let Err(error) = local
        .native_helper
        .start(HelperInvocation::ApprovalConsent(consent), expires_at)
    {
        local.plan_consent.clear();
        return Err(error.into());
    }
    Ok(view)
}

/// Reads what the window is doing, and holds its answer against the pair.
///
/// The answer is never read as a decision on its own. It is held against the
/// consent this session sent — the very document the window was opened on — and
/// against the presentation that produced it, so an answer to a window opened
/// on another pair cannot be laundered through this one. Everything that is not
/// a confirmation is a refusal, whatever ended the window.
#[tauri::command]
fn plan_consent_status(
    request_id: String,
    state: State<'_, AppRuntime>,
) -> Result<PlanConsentSessionView, CommandError> {
    let mut local = state.local.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    let view = local.plan_consent.status(&request_id)?;
    if view.state == "answered" {
        return Ok(view);
    }
    let consent = local.plan_consent.consent(&request_id)?;
    match local.native_helper.poll(&request_id) {
        Ok(NativeHelperPoll::Running) => Ok(view),
        Ok(NativeHelperPoll::ApprovalDecided(outcome)) => {
            let Some(held) = local.plan_pair.as_ref() else {
                local.plan_consent.clear();
                return Err(PlanConsentError::NoPlan.into());
            };
            let confirmed = matches!(
                held.presented.confirmed_by(&consent, &outcome),
                PublicationPlanConfirmation::Confirmed { .. }
            );
            local
                .plan_consent
                .answer(&request_id, confirmed)
                .map_err(Into::into)
        }
        // A bootstrap verdict on this session, or a helper that could not run,
        // ends it without producing an answer: this App does not know what
        // a human decided, and it says so rather than deciding for him.
        Ok(NativeHelperPoll::AccessVerified { .. })
        | Ok(NativeHelperPoll::Refused { .. })
        | Ok(NativeHelperPoll::Cancelled)
        | Ok(NativeHelperPoll::Unavailable) => {
            let _ = local.native_helper.stop_active();
            local.plan_consent.clear();
            Err(PlanConsentError::Unavailable.into())
        }
        Err(error) => {
            let _ = local.native_helper.stop_active();
            local.plan_consent.clear();
            Err(error.into())
        }
    }
}

/// Reads the bounded history of what was launched in this human's name.
///
/// It shows what happened rather than what was asked: `lancé, non rapporté` is
/// a state of its own, neither a success nor a failure, and nothing here turns
/// it into either. What the machine answered is carried as the machine wrote
/// it; what this Controller observed is carried apart, because a reader must be
/// able to tell which he is reading.
#[tauri::command]
fn read_plan_dispatches(
    infrastructure_id: String,
    state: State<'_, AppRuntime>,
) -> Result<PlanDispatchesView, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    network
        .read_plan_dispatches(&association, generation, &state.request_generation)
        .map_err(Into::into)
}

/// Signs the confirmed plan and submits it, which is the one act of this App
/// whose effect leaves the Controller's machine.
///
/// Nothing here re-decides anything. The signature happens only for a session
/// whose window answered a confirmation, over the exact bytes that were
/// verified and displayed; `publication_plan` re-verifies them from those bytes
/// before signing, so a transport that altered either document between the
/// window and this call produces another pair and no signature at all.
///
/// The position and the epoch are named by the caller because they are read
/// from the machine's own reported position, and they are re-verified by the
/// Controller and again by the machine: this App is trusted for neither.
/// What it *is* trusted for is that the human saw these two digests, and that
/// is what the envelope binds.
///
/// The session is closed whatever happens. An approval is a one-shot authority
/// on this side too: a confirmation that could be submitted twice would be a
/// confirmation that authorised two dispatches.
#[tauri::command]
fn submit_plan_decision(
    infrastructure_id: String,
    request_id: String,
    approval_epoch: u64,
    sequence: u64,
    state: State<'_, AppRuntime>,
) -> Result<PlanDispatchAcceptedView, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut local = state.local.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    // La borne mord ici, et c'est le seul endroit où elle compte : une autorité
    // confirmée dont l'échéance a couru refuse de signer, et le dit par le refus
    // qui nomme la suite — rouvrir la fenêtre — plutôt que par celui d'une
    // demande qui n'a jamais existé (`#133`).
    local.plan_consent.confirmed(&request_id)?;
    let Some(held) = local.plan_pair.as_ref() else {
        return Err(PlanConsentError::NoPlan.into());
    };
    let signed = held.presented.sign(
        &association,
        &held.documents,
        &held.presented.confirmed(),
        PublicationApprovalRequest {
            approval_epoch,
            sequence,
            issued_at_unix_seconds: unix_seconds()?,
            lifetime_seconds: MAX_APPROVAL_LIFETIME_SECONDS,
        },
    )?;
    let documents = held.documents.clone();
    let definition_document = held.definition_document.clone();
    // The session is spent before a byte leaves, and it is spent whatever the
    // submission answers.
    local.plan_consent.clear();
    drop(local);

    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    network
        .submit_plan_approval(
            &association,
            &signed,
            &documents,
            &definition_document,
            generation,
            &state.request_generation,
        )
        .map_err(Into::into)
}

/// The instant an envelope is issued at, read from the wall clock because that
/// is what an expiry is compared against on the other side.
fn unix_seconds() -> Result<u64, CommandError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| CommandError {
            code: "app_unavailable",
            detail: None,
        })
}

/// Closes the window without an answer.
///
/// A cancellation is not a refusal recorded on the human's behalf: the session
/// ends holding nothing, and the pair stays where it was. Reopening is a new
/// window, a new identifier and a new consent.
#[tauri::command]
fn cancel_plan_consent(
    request_id: String,
    state: State<'_, AppRuntime>,
) -> Result<(), CommandError> {
    let mut local = state.local.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    local.plan_consent.status(&request_id)?;
    local.native_helper.cancel(&request_id)?;
    local.plan_consent.cancel(&request_id).map_err(Into::into)
}

/// What a human is shown of a pair before any window opens.
///
/// It carries no document. The last two sentences end with the two digests, so
/// the values a signature will bind are values the human read at the end of a
/// phrase rather than values handed to him beside one.
#[derive(Serialize)]
struct PlanPairPresentation {
    schema_version: u8,
    machine_id: String,
    plan_sha256: String,
    rollback_sha256: String,
    confirmation_lines: Vec<String>,
}

#[tauri::command]
fn read_service_definitions(
    infrastructure_id: String,
    state: State<'_, AppRuntime>,
) -> Result<ServiceDefinitionsProjection, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    let view =
        network.read_service_definitions(&association, generation, &state.request_generation)?;
    drop(network);
    project_service_definitions(view)
}

/// Freezes one definition the human read the consequences of.
///
/// The two arguments are the two the review produced, and they are held against
/// one another again here — by the mirror, not by a comparison written here — so
/// bytes that are not the definition of the displayed digest never leave. A
/// freeze creates nothing, contacts no machine and signs nothing: it is the one
/// act of this palier that a human performs without approving a plan, because
/// there is no effect for a plan to describe.
#[tauri::command]
fn freeze_service_definition(
    infrastructure_id: String,
    definition_document: String,
    definition_sha256: String,
    state: State<'_, AppRuntime>,
) -> Result<FrozenDefinitionView, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    let view = network.freeze_service_definition(
        &association,
        &definition_document,
        &definition_sha256,
        generation,
        &state.request_generation,
    )?;
    drop(network);
    service_definition::frozen_definition_view(
        &view.definition.slug,
        &view.definition.definition_document,
        &view.definition.definition_sha256,
        &view.definition.frozen_at,
    )
    .ok_or(CommandError {
        code: "response_refused",
        detail: None,
    })
}

/// Turns the frozen bytes into the fields a view renders, entry by entry.
///
/// A listing with one entry this App cannot verify is refused whole rather
/// than shortened, exactly as the transport already refuses it: a human reading
/// a shorter list would believe a revision was never frozen.
fn project_service_definitions(
    view: network::ServiceDefinitionsView,
) -> Result<ServiceDefinitionsProjection, CommandError> {
    let mut definitions = Vec::with_capacity(view.definitions.len());
    for entry in &view.definitions {
        definitions.push(
            service_definition::frozen_definition_view(
                &entry.slug,
                &entry.definition_document,
                &entry.definition_sha256,
                &entry.frozen_at,
            )
            .ok_or(CommandError {
                code: "response_refused",
                detail: None,
            })?,
        );
    }
    Ok(ServiceDefinitionsProjection {
        schema_version: 1,
        definition_revision: view.definition_revision,
        definitions,
    })
}

#[tauri::command]
fn logout_session(
    infrastructure_id: String,
    state: State<'_, AppRuntime>,
) -> Result<(), CommandError> {
    let association = with_core(&state, |core| core.association(&infrastructure_id))?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    network.logout(&association).map_err(Into::into)
}

#[tauri::command]
fn rotate_device(
    infrastructure_id: String,
    state: State<'_, AppRuntime>,
) -> Result<AssociationSummary, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    let active = network.rotate_device(
        association,
        generation,
        &state.request_generation,
        |candidate| {
            if state.request_generation.load(Ordering::SeqCst) != generation {
                return Err(network::NetworkError::Cancelled);
            }
            let mut local = state
                .local
                .lock()
                .map_err(|_| network::NetworkError::AppUnavailable)?;
            local
                .core
                .store_association(candidate, true)
                .map(|_| ())
                .map_err(|_| network::NetworkError::AppUnavailable)
        },
    )?;
    drop(network);
    if state.request_generation.load(Ordering::SeqCst) != generation {
        return Err(network::NetworkError::Cancelled.into());
    }
    with_core(&state, |core| core.store_association(active, true)).map_err(Into::into)
}

#[tauri::command]
fn prepare_recovery_key_rotation(
    state: State<'_, AppRuntime>,
) -> Result<PreparedRecoveryRotation, CommandError> {
    with_core(&state, AppCore::prepare_recovery_rotation)
}

#[tauri::command]
fn confirm_recovery_key_rotation(
    generation_id: String,
    new_recovery_code: String,
    confirmed_copies: bool,
    state: State<'_, AppRuntime>,
) -> Result<RecoveryRotationProgress, CommandError> {
    with_core(&state, |core| {
        core.confirm_recovery_rotation(&generation_id, new_recovery_code, confirmed_copies)
    })
}

#[tauri::command]
fn resume_recovery_key_rotation(
    old_recovery_code: String,
    new_recovery_code: String,
    state: State<'_, AppRuntime>,
) -> Result<RecoveryRotationProgress, CommandError> {
    let old_recovery_code = Zeroizing::new(old_recovery_code);
    let new_recovery_code = Zeroizing::new(new_recovery_code);
    let generation = state.request_generation.load(Ordering::SeqCst);
    let (mut progress, associations) = with_core(&state, |core| {
        core.recovery_rotation(&old_recovery_code, &new_recovery_code)
    })?;
    for target in progress.controllers.clone() {
        if target.status == "completed" {
            continue;
        }
        if state.request_generation.load(Ordering::SeqCst) != generation {
            return Err(network::NetworkError::Cancelled.into());
        }
        let association = associations
            .iter()
            .find(|association| {
                association.summary.infrastructure_id == target.infrastructure_id
                    && association.summary.controller_id == target.controller_id
            })
            .cloned()
            .ok_or(CommandError {
                code: "app_unavailable",
                detail: None,
            })?;
        let result = {
            let mut network = state.network.lock().map_err(|_| CommandError {
                code: "app_unavailable",
                detail: None,
            })?;
            network.rotate_recovery_key(
                association,
                &target,
                &old_recovery_code,
                &new_recovery_code,
                generation,
                &state.request_generation,
            )
        };
        let completed = result.is_ok();
        progress = with_core(&state, |core| {
            core.record_recovery_rotation_result(result.ok(), &target.infrastructure_id, completed)
        })?;
    }
    Ok(progress)
}

#[tauri::command]
fn complete_recovery_key_rotation(state: State<'_, AppRuntime>) -> Result<(), CommandError> {
    with_core(&state, AppCore::complete_recovery_rotation)
}

#[tauri::command]
fn put_infrastructure(
    infrastructure_id: String,
    label: String,
    state: State<'_, AppRuntime>,
) -> Result<InfrastructureView, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    let view =
        network.put_infrastructure(&association, &label, generation, &state.request_generation)?;
    drop(network);
    let persisted_label = view.label.clone().ok_or(CommandError {
        code: "response_refused",
        detail: None,
    })?;
    with_core(&state, |core| {
        core.update_association_label(&infrastructure_id, persisted_label)
            .map(|_| ())
    })?;
    Ok(view)
}

#[tauri::command]
fn put_machine(
    infrastructure_id: String,
    machine_id: String,
    label: String,
    state: State<'_, AppRuntime>,
) -> Result<MachineMutationView, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    network
        .put_machine(
            &association,
            &machine_id,
            &label,
            generation,
            &state.request_generation,
        )
        .map_err(Into::into)
}

fn active_association(
    state: &State<'_, AppRuntime>,
    infrastructure_id: &str,
    generation: u64,
) -> Result<vault::AssociationRecord, CommandError> {
    let association = with_core(state, |core| core.association(infrastructure_id))?;
    if association.summary.device_status == "active" && association.pending_mode.is_none() {
        return Ok(association);
    }
    if association.summary.device_status != "candidate"
        && association.pending_mode.as_deref() != Some("rotation")
    {
        return Err(network::NetworkError::SessionExpired.into());
    }
    let active = {
        let mut network = state.network.lock().map_err(|_| CommandError {
            code: "app_unavailable",
            detail: None,
        })?;
        network.activate_pending(association, generation, &state.request_generation)?
    };
    if state.request_generation.load(Ordering::SeqCst) != generation {
        return Err(network::NetworkError::Cancelled.into());
    }
    let mut local = state.local.lock().map_err(|_| CommandError {
        code: "app_unavailable",
        detail: None,
    })?;
    local.core.store_association(active.clone(), true)?;
    Ok(active)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let state_directory = app.path().app_data_dir()?.join("native-vault");
            app.manage(AppRuntime {
                local: Mutex::new(AppLocalState {
                    core: AppCore::new(state_directory),
                    bootstrap: BootstrapState::default(),
                    native_helper: NativeHelperSupervisor::default(),
                    plan_pair: None,
                    plan_consent: PlanConsentState::default(),
                }),
                network: Mutex::new(NetworkState::new()),
                request_generation: AtomicU64::new(0),
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() != "main"
                || !matches!(
                    event,
                    tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed
                )
            {
                return;
            }
            if let Some(state) = window.try_state::<AppRuntime>() {
                if let Ok(mut local) = state.local.lock() {
                    local.close();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            app_status,
            prepare_app,
            discard_app_preparation,
            confirm_app_initialization,
            unlock_app,
            prepare_phrase_change,
            confirm_phrase_change,
            start_bootstrap,
            bootstrap_status,
            cancel_bootstrap,
            lock_app,
            cancel_pending_requests,
            pair_controller,
            read_infrastructure,
            read_machines,
            read_external_elements,
            withdraw_external_element,
            review_service_definition,
            parse_service_definition_paste,
            read_service_definitions,
            freeze_service_definition,
            read_plan_pair,
            open_plan_consent,
            plan_consent_status,
            cancel_plan_consent,
            submit_plan_decision,
            read_plan_dispatches,
            put_infrastructure,
            put_machine,
            rotate_device,
            prepare_recovery_key_rotation,
            confirm_recovery_key_rotation,
            resume_recovery_key_rotation,
            complete_recovery_key_rotation,
            logout_session,
        ])
        .run(tauri::generate_context!())
        .expect("Your Cloud App runtime failed");
}

#[cfg(test)]
mod bootstrap_lifecycle_tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use your_cloud_bootstrap_protocol::{BootstrapAccessKind, BootstrapMode, BootstrapTarget};

    const HOST_KEY: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn input() -> BootstrapStartInput {
        BootstrapStartInput {
            mode: BootstrapMode::Create,
            target: BootstrapTarget {
                host: "controller.example.test".into(),
                port: 22,
                username: "infra_admin".into(),
                host_key_sha256: HOST_KEY.into(),
                access_kind: BootstrapAccessKind::Administrator,
            },
            action: None,
            declared_target: None,
            machine_configuration: None,
        }
    }

    fn unlocked_local_state() -> (tempfile::TempDir, AppLocalState) {
        let directory = tempfile::tempdir().unwrap();
        let mut core = AppCore::new(directory.path().join("vault"));
        let generated = core.prepare().unwrap();
        core.confirm_initialization(
            &generated.generation_id,
            generated.unlock_phrase,
            generated.recovery_code,
            true,
        )
        .unwrap();
        (
            directory,
            AppLocalState {
                core,
                bootstrap: BootstrapState::default(),
                native_helper: NativeHelperSupervisor::default(),
                plan_pair: None,
                plan_consent: PlanConsentState::default(),
            },
        )
    }

    #[test]
    fn concurrent_lock_and_start_leave_no_bootstrap_request() {
        let (_directory, local) = unlocked_local_state();
        let local = Arc::new(Mutex::new(local));
        let barrier = Arc::new(Barrier::new(2));

        let start_local = Arc::clone(&local);
        let start_barrier = Arc::clone(&barrier);
        let start = std::thread::spawn(move || {
            start_barrier.wait();
            start_local
                .lock()
                .unwrap()
                .start_bootstrap_state_only(input())
                .ok()
        });
        let lock_local = Arc::clone(&local);
        let lock_barrier = Arc::clone(&barrier);
        let lock = std::thread::spawn(move || {
            lock_barrier.wait();
            lock_local.lock().unwrap().lock().unwrap();
        });

        let started = start.join().unwrap();
        lock.join().unwrap();
        let mut local = local.lock().unwrap();
        assert_eq!(local.core.status().unwrap().lock_state, "locked");
        if let Some(started) = started {
            assert!(local.bootstrap.status(&started.request_id).is_err());
        }
        assert_eq!(
            local.start_bootstrap_state_only(input()).unwrap_err().code,
            "app_locked"
        );
    }

    #[test]
    fn concurrent_close_and_start_leave_a_terminal_bootstrap_state() {
        let (_directory, local) = unlocked_local_state();
        let local = Arc::new(Mutex::new(local));
        let barrier = Arc::new(Barrier::new(2));

        let start_local = Arc::clone(&local);
        let start_barrier = Arc::clone(&barrier);
        let start = std::thread::spawn(move || {
            start_barrier.wait();
            start_local
                .lock()
                .unwrap()
                .start_bootstrap_state_only(input())
                .ok()
        });
        let close_local = Arc::clone(&local);
        let close_barrier = Arc::clone(&barrier);
        let close = std::thread::spawn(move || {
            close_barrier.wait();
            close_local.lock().unwrap().close();
        });

        let started = start.join().unwrap();
        close.join().unwrap();
        let mut local = local.lock().unwrap();
        if let Some(started) = started {
            assert!(local.bootstrap.status(&started.request_id).is_err());
        }
        assert_eq!(
            local.start_bootstrap_state_only(input()).unwrap_err().code,
            "bootstrap_request_refused"
        );
    }
}
