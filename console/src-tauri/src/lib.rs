// The approval path is signed here and verified by the Auxiliary end to end,
// but the native window that must display and confirm a plan before it is
// emitted belongs to the palier that adds the command. Nothing in the command
// surface below reaches this module, which is exactly what "no free signature
// is exposed to the frontend" means for now.
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
mod native_assistant;
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
use native_assistant::{NativeAssistantPoll, NativeAssistantSupervisor};
use network::{
    ExternalElementsView, ExternalWithdrawalView, InfrastructureView, MachineMutationView,
    MachinesView, NetworkState, PairingInput,
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
    AssociationSummary, ConsoleCore, ConsoleStatus, GeneratedLocalSecrets, PreparedPhraseChange,
    PreparedRecoveryRotation, RecoveryRotationProgress,
};
use your_cloud_bootstrap_protocol::{BootstrapSessionView, BootstrapStartInput};
use zeroize::Zeroizing;

#[derive(Debug, Serialize)]
struct CommandError {
    code: &'static str,
}

impl From<vault::VaultError> for CommandError {
    fn from(value: vault::VaultError) -> Self {
        Self {
            code: value.public_code(),
        }
    }
}

impl From<network::NetworkError> for CommandError {
    fn from(value: network::NetworkError) -> Self {
        Self {
            code: value.public_code(),
        }
    }
}

impl From<bootstrap::BootstrapError> for CommandError {
    fn from(value: bootstrap::BootstrapError) -> Self {
        Self {
            code: value.public_code(),
        }
    }
}

impl From<native_assistant::NativeAssistantError> for CommandError {
    fn from(value: native_assistant::NativeAssistantError) -> Self {
        Self {
            code: value.public_code(),
        }
    }
}

struct ConsoleLocalState {
    core: ConsoleCore,
    bootstrap: BootstrapState,
    native_assistant: NativeAssistantSupervisor,
}

impl ConsoleLocalState {
    fn start_bootstrap(
        &mut self,
        input: BootstrapStartInput,
    ) -> Result<BootstrapSessionView, CommandError> {
        if self.core.status()?.lock_state != "unlocked" {
            return Err(vault::VaultError::Locked.into());
        }
        let started = self.bootstrap.start(input)?;
        if let Err(error) = self.native_assistant.stop_active() {
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
        if let Err(error) = self.native_assistant.start(launch.scope, launch.expires_at) {
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

    fn lock(&mut self) -> Result<(), native_assistant::NativeAssistantError> {
        self.core.lock();
        let stopped = self.native_assistant.stop_active();
        self.bootstrap.clear();
        stopped
    }

    fn close(&mut self) {
        let _ = self.native_assistant.stop_active();
        self.bootstrap.close();
    }
}

struct ConsoleRuntime {
    local: Mutex<ConsoleLocalState>,
    network: Mutex<NetworkState>,
    request_generation: AtomicU64,
}

fn with_core<T>(
    state: &State<'_, ConsoleRuntime>,
    operation: impl FnOnce(&mut ConsoleCore) -> Result<T, vault::VaultError>,
) -> Result<T, CommandError> {
    let mut local = state.local.lock().map_err(|_| CommandError {
        code: "console_unavailable",
    })?;
    operation(&mut local.core).map_err(Into::into)
}

fn json_request_body<'a>(request: &'a Request<'_>) -> Result<&'a serde_json::Value, CommandError> {
    match request.body() {
        InvokeBody::Json(value) => Ok(value),
        InvokeBody::Raw(_) => Err(CommandError {
            code: "bootstrap_request_refused",
        }),
    }
}

#[tauri::command]
fn console_status(state: State<'_, ConsoleRuntime>) -> Result<ConsoleStatus, CommandError> {
    with_core(&state, ConsoleCore::status)
}

#[tauri::command]
fn prepare_console(
    state: State<'_, ConsoleRuntime>,
) -> Result<GeneratedLocalSecrets, CommandError> {
    with_core(&state, ConsoleCore::prepare)
}

#[tauri::command]
fn discard_console_preparation(
    generation_id: String,
    state: State<'_, ConsoleRuntime>,
) -> Result<(), CommandError> {
    with_core(&state, |core| core.discard_preparation(&generation_id))
}

#[tauri::command]
fn confirm_console_initialization(
    generation_id: String,
    unlock_phrase: String,
    recovery_code: String,
    confirmed_copies: bool,
    state: State<'_, ConsoleRuntime>,
) -> Result<ConsoleStatus, CommandError> {
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
fn unlock_console(
    phrase: String,
    state: State<'_, ConsoleRuntime>,
) -> Result<ConsoleStatus, CommandError> {
    with_core(&state, |core| core.unlock(phrase))
}

#[tauri::command]
fn prepare_phrase_change(
    state: State<'_, ConsoleRuntime>,
) -> Result<PreparedPhraseChange, CommandError> {
    with_core(&state, ConsoleCore::prepare_phrase_change)
}

#[tauri::command]
fn confirm_phrase_change(
    generation_id: String,
    current_phrase: String,
    new_phrase: String,
    state: State<'_, ConsoleRuntime>,
) -> Result<(), CommandError> {
    with_core(&state, |core| {
        core.confirm_phrase_change(&generation_id, current_phrase, new_phrase)
    })
}

#[tauri::command]
fn start_bootstrap(
    request: Request<'_>,
    state: State<'_, ConsoleRuntime>,
) -> Result<BootstrapSessionView, CommandError> {
    let input = bootstrap::parse_start_envelope(json_request_body(&request)?)?;
    let mut local = state.local.lock().map_err(|_| CommandError {
        code: "console_unavailable",
    })?;
    local.start_bootstrap(input)
}

#[tauri::command]
fn bootstrap_status(
    request: Request<'_>,
    state: State<'_, ConsoleRuntime>,
) -> Result<BootstrapSessionView, CommandError> {
    let request_id = bootstrap::parse_request_envelope(json_request_body(&request)?)?;
    let mut local = state.local.lock().map_err(|_| CommandError {
        code: "console_unavailable",
    })?;
    let view = match local.bootstrap.status(&request_id) {
        Ok(view) => view,
        Err(error @ bootstrap::BootstrapError::Expired) => {
            local.native_assistant.stop_active()?;
            return Err(error.into());
        }
        Err(error) => return Err(error.into()),
    };
    match local.native_assistant.poll(&request_id) {
        Ok(NativeAssistantPoll::Running) => Ok(view),
        // The helper proved its access and is gone. The session is cleared here
        // because it is over; naming that outcome to the frontend belongs to
        // the business closure of the palier, not to this one. The frontend
        // therefore cannot read `access_verified`, and — having no way to write
        // an event either — cannot produce one.
        Ok(NativeAssistantPoll::AccessVerified) => {
            local.bootstrap.clear();
            Ok(view)
        }
        Ok(NativeAssistantPoll::Unavailable) => {
            local.bootstrap.clear();
            Err(native_assistant::NativeAssistantError::Unavailable.into())
        }
        Err(error) => {
            let _ = local.native_assistant.stop_active();
            local.bootstrap.clear();
            Err(error.into())
        }
    }
}

#[tauri::command]
fn cancel_bootstrap(
    request: Request<'_>,
    state: State<'_, ConsoleRuntime>,
) -> Result<(), CommandError> {
    let request_id = bootstrap::parse_request_envelope(json_request_body(&request)?)?;
    let mut local = state.local.lock().map_err(|_| CommandError {
        code: "console_unavailable",
    })?;
    match local.bootstrap.status(&request_id) {
        Ok(_) => {}
        Err(error @ bootstrap::BootstrapError::Expired) => {
            local.native_assistant.stop_active()?;
            return Err(error.into());
        }
        Err(error) => return Err(error.into()),
    }
    local.native_assistant.cancel(&request_id)?;
    local.bootstrap.cancel(&request_id).map_err(Into::into)
}

#[tauri::command]
fn lock_console(state: State<'_, ConsoleRuntime>) -> Result<(), CommandError> {
    state.request_generation.fetch_add(1, Ordering::SeqCst);
    let local_result = match state.local.lock() {
        Ok(mut local) => local.lock().map_err(CommandError::from),
        Err(_) => Err(CommandError {
            code: "console_unavailable",
        }),
    };
    let network_result = state
        .network
        .lock()
        .map_err(|_| CommandError {
            code: "console_unavailable",
        })
        .map(|mut network| network.clear_sessions());
    local_result?;
    network_result
}

#[tauri::command]
fn cancel_pending_requests(state: State<'_, ConsoleRuntime>) {
    state.request_generation.fetch_add(1, Ordering::SeqCst);
}

#[tauri::command]
fn pair_controller(
    input: PairingInput,
    state: State<'_, ConsoleRuntime>,
) -> Result<AssociationSummary, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let replacing = input.mode == "recovery";
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "console_unavailable",
    })?;
    let active = network.pair(input, generation, &state.request_generation, |candidate| {
        if state.request_generation.load(Ordering::SeqCst) != generation {
            return Err(network::NetworkError::Cancelled);
        }
        let mut local = state
            .local
            .lock()
            .map_err(|_| network::NetworkError::ConsoleUnavailable)?;
        local
            .core
            .store_association(candidate, replacing)
            .map(|_| ())
            .map_err(|_| network::NetworkError::ConsoleUnavailable)
    })?;
    if state.request_generation.load(Ordering::SeqCst) != generation {
        return Err(network::NetworkError::Cancelled.into());
    }
    let mut local = state.local.lock().map_err(|_| CommandError {
        code: "console_unavailable",
    })?;
    local
        .core
        .store_association(active, true)
        .map_err(Into::into)
}

#[tauri::command]
fn read_infrastructure(
    infrastructure_id: String,
    state: State<'_, ConsoleRuntime>,
) -> Result<InfrastructureView, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "console_unavailable",
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
    state: State<'_, ConsoleRuntime>,
) -> Result<MachinesView, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "console_unavailable",
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
    state: State<'_, ConsoleRuntime>,
) -> Result<ExternalElementsView, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "console_unavailable",
    })?;
    network
        .read_external_elements(&association, generation, &state.request_generation)
        .map_err(Into::into)
}

#[tauri::command]
fn withdraw_external_element(
    infrastructure_id: String,
    element_id: String,
    state: State<'_, ConsoleRuntime>,
) -> Result<ExternalWithdrawalView, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "console_unavailable",
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
/// It is local and pure: no session, no network, no state of this Console is
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
#[tauri::command]
fn read_service_definitions(
    infrastructure_id: String,
    state: State<'_, ConsoleRuntime>,
) -> Result<ServiceDefinitionsProjection, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "console_unavailable",
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
    state: State<'_, ConsoleRuntime>,
) -> Result<FrozenDefinitionView, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "console_unavailable",
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
    })
}

/// Turns the frozen bytes into the fields a view renders, entry by entry.
///
/// A listing with one entry this Console cannot verify is refused whole rather
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
    state: State<'_, ConsoleRuntime>,
) -> Result<(), CommandError> {
    let association = with_core(&state, |core| core.association(&infrastructure_id))?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "console_unavailable",
    })?;
    network.logout(&association).map_err(Into::into)
}

#[tauri::command]
fn rotate_device(
    infrastructure_id: String,
    state: State<'_, ConsoleRuntime>,
) -> Result<AssociationSummary, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "console_unavailable",
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
                .map_err(|_| network::NetworkError::ConsoleUnavailable)?;
            local
                .core
                .store_association(candidate, true)
                .map(|_| ())
                .map_err(|_| network::NetworkError::ConsoleUnavailable)
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
    state: State<'_, ConsoleRuntime>,
) -> Result<PreparedRecoveryRotation, CommandError> {
    with_core(&state, ConsoleCore::prepare_recovery_rotation)
}

#[tauri::command]
fn confirm_recovery_key_rotation(
    generation_id: String,
    new_recovery_code: String,
    confirmed_copies: bool,
    state: State<'_, ConsoleRuntime>,
) -> Result<RecoveryRotationProgress, CommandError> {
    with_core(&state, |core| {
        core.confirm_recovery_rotation(&generation_id, new_recovery_code, confirmed_copies)
    })
}

#[tauri::command]
fn resume_recovery_key_rotation(
    old_recovery_code: String,
    new_recovery_code: String,
    state: State<'_, ConsoleRuntime>,
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
                code: "console_unavailable",
            })?;
        let result = {
            let mut network = state.network.lock().map_err(|_| CommandError {
                code: "console_unavailable",
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
fn complete_recovery_key_rotation(state: State<'_, ConsoleRuntime>) -> Result<(), CommandError> {
    with_core(&state, ConsoleCore::complete_recovery_rotation)
}

#[tauri::command]
fn put_infrastructure(
    infrastructure_id: String,
    label: String,
    state: State<'_, ConsoleRuntime>,
) -> Result<InfrastructureView, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "console_unavailable",
    })?;
    let view =
        network.put_infrastructure(&association, &label, generation, &state.request_generation)?;
    drop(network);
    let persisted_label = view.label.clone().ok_or(CommandError {
        code: "response_refused",
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
    state: State<'_, ConsoleRuntime>,
) -> Result<MachineMutationView, CommandError> {
    let generation = state.request_generation.load(Ordering::SeqCst);
    let association = active_association(&state, &infrastructure_id, generation)?;
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "console_unavailable",
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
    state: &State<'_, ConsoleRuntime>,
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
            code: "console_unavailable",
        })?;
        network.activate_pending(association, generation, &state.request_generation)?
    };
    if state.request_generation.load(Ordering::SeqCst) != generation {
        return Err(network::NetworkError::Cancelled.into());
    }
    let mut local = state.local.lock().map_err(|_| CommandError {
        code: "console_unavailable",
    })?;
    local.core.store_association(active.clone(), true)?;
    Ok(active)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let state_directory = app.path().app_data_dir()?.join("native-vault");
            app.manage(ConsoleRuntime {
                local: Mutex::new(ConsoleLocalState {
                    core: ConsoleCore::new(state_directory),
                    bootstrap: BootstrapState::default(),
                    native_assistant: NativeAssistantSupervisor::default(),
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
            if let Some(state) = window.try_state::<ConsoleRuntime>() {
                if let Ok(mut local) = state.local.lock() {
                    local.close();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            console_status,
            prepare_console,
            discard_console_preparation,
            confirm_console_initialization,
            unlock_console,
            prepare_phrase_change,
            confirm_phrase_change,
            start_bootstrap,
            bootstrap_status,
            cancel_bootstrap,
            lock_console,
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
        .expect("Your Cloud Console runtime failed");
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
        }
    }

    fn unlocked_local_state() -> (tempfile::TempDir, ConsoleLocalState) {
        let directory = tempfile::tempdir().unwrap();
        let mut core = ConsoleCore::new(directory.path().join("vault"));
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
            ConsoleLocalState {
                core,
                bootstrap: BootstrapState::default(),
                native_assistant: NativeAssistantSupervisor::default(),
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
            "console_locked"
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
