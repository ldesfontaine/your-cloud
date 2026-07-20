mod network;
mod vault;
#[cfg(windows)]
mod windows_security;

use network::{InfrastructureView, MachineMutationView, MachinesView, NetworkState, PairingInput};
use serde::Serialize;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};
use tauri::{Manager, State};
use vault::{
    AssociationSummary, ConsoleCore, ConsoleStatus, GeneratedLocalSecrets, PreparedPhraseChange,
    PreparedRecoveryRotation, RecoveryRotationProgress,
};
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

struct ConsoleRuntime {
    core: Mutex<ConsoleCore>,
    network: Mutex<NetworkState>,
    request_generation: AtomicU64,
}

fn with_core<T>(
    state: &State<'_, ConsoleRuntime>,
    operation: impl FnOnce(&mut ConsoleCore) -> Result<T, vault::VaultError>,
) -> Result<T, CommandError> {
    let mut core = state.core.lock().map_err(|_| CommandError {
        code: "console_unavailable",
    })?;
    operation(&mut core).map_err(Into::into)
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
fn lock_console(state: State<'_, ConsoleRuntime>) -> Result<(), CommandError> {
    state.request_generation.fetch_add(1, Ordering::SeqCst);
    let mut network = state.network.lock().map_err(|_| CommandError {
        code: "console_unavailable",
    })?;
    network.clear_sessions();
    with_core(&state, |core| {
        core.lock();
        Ok(())
    })
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
        let mut core = state
            .core
            .lock()
            .map_err(|_| network::NetworkError::ConsoleUnavailable)?;
        core.store_association(candidate, replacing)
            .map(|_| ())
            .map_err(|_| network::NetworkError::ConsoleUnavailable)
    })?;
    if state.request_generation.load(Ordering::SeqCst) != generation {
        return Err(network::NetworkError::Cancelled.into());
    }
    let mut core = state.core.lock().map_err(|_| CommandError {
        code: "console_unavailable",
    })?;
    core.store_association(active, true).map_err(Into::into)
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
            let mut core = state
                .core
                .lock()
                .map_err(|_| network::NetworkError::ConsoleUnavailable)?;
            core.store_association(candidate, true)
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
    let mut core = state.core.lock().map_err(|_| CommandError {
        code: "console_unavailable",
    })?;
    core.store_association(active.clone(), true)?;
    Ok(active)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let state_directory = app.path().app_data_dir()?.join("native-vault");
            app.manage(ConsoleRuntime {
                core: Mutex::new(ConsoleCore::new(state_directory)),
                network: Mutex::new(NetworkState::new()),
                request_generation: AtomicU64::new(0),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            console_status,
            prepare_console,
            discard_console_preparation,
            confirm_console_initialization,
            unlock_console,
            prepare_phrase_change,
            confirm_phrase_change,
            lock_console,
            cancel_pending_requests,
            pair_controller,
            read_infrastructure,
            read_machines,
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
