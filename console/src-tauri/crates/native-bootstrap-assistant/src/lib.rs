mod framing;
mod hardening;
mod lease;
#[cfg(target_os = "linux")]
mod native_prompt;
#[cfg(target_os = "windows")]
mod native_prompt_windows;
mod parent;
pub mod personal_access;
mod secret;
mod watchdog;

use std::{
    ffi::{OsStr, OsString},
    io,
    time::{Duration, Instant},
};

use framing::ReadFrameError;
use lease::{LeaseResolution, LeaseState, UnbufferedStandardInput};
use your_cloud_bootstrap_protocol::{
    monotonic_nanos, AssistantEventKind, AssistantEventV1, AssistantScopeV1,
    ASSISTANT_EXIT_CANCELLED, ASSISTANT_EXIT_INTERNAL_FAILURE, ASSISTANT_EXIT_INVALID_INVOCATION,
    ASSISTANT_EXIT_IO_FAILURE, ASSISTANT_EXIT_PROTOCOL_REFUSED, ASSISTANT_EXIT_REFUSED,
    ASSISTANT_EXIT_UNAVAILABLE, ASSISTANT_EXIT_WATCHDOG_EXPIRED,
};

pub const REQUIRED_MODE_ARGUMENT: &str = "--native-bootstrap-assistant";
pub const EXIT_INVALID_INVOCATION: u8 = ASSISTANT_EXIT_INVALID_INVOCATION;
pub const EXIT_PROTOCOL_REFUSED: u8 = ASSISTANT_EXIT_PROTOCOL_REFUSED;
pub const EXIT_REFUSED: u8 = ASSISTANT_EXIT_REFUSED;
pub const EXIT_CANCELLED: u8 = ASSISTANT_EXIT_CANCELLED;
pub const EXIT_UNAVAILABLE: u8 = ASSISTANT_EXIT_UNAVAILABLE;
pub const EXIT_INTERNAL_FAILURE: u8 = ASSISTANT_EXIT_INTERNAL_FAILURE;
pub const EXIT_IO_FAILURE: u8 = ASSISTANT_EXIT_IO_FAILURE;
pub const EXIT_WATCHDOG_EXPIRED: u8 = ASSISTANT_EXIT_WATCHDOG_EXPIRED;

/// Feature-only entry point for the hostile declared-parent process contract.
/// It deliberately performs no prompt or protocol read: the only observable
/// decision is whether the inherited transport belongs to the declared parent.
#[cfg(feature = "windows-parent-spoof-contract-test")]
#[doc(hidden)]
pub fn transport_parent_contract_main() -> u8 {
    let stdin = match UnbufferedStandardInput::open() {
        Ok(stdin) => stdin,
        Err(()) => return EXIT_INTERNAL_FAILURE,
    };
    match parent::verify(&stdin) {
        Ok(_parent) => 0,
        Err(()) => EXIT_INTERNAL_FAILURE,
    }
}

pub fn process_main() -> u8 {
    // This origin precedes every local operation: hardening, parent attestation and
    // protocol reading all consume, and can never renew, the Console-provided TTL.
    let session_started_at = Instant::now();
    if hardening::apply().is_err() {
        return EXIT_INTERNAL_FAILURE;
    }
    std::panic::set_hook(Box::new(|_| {}));

    let watchdog = match watchdog::Watchdog::start_at(session_started_at) {
        Ok(watchdog) => watchdog,
        Err(()) => return EXIT_INTERNAL_FAILURE,
    };

    if !valid_arguments(std::env::args_os()) {
        return EXIT_INVALID_INVOCATION;
    }

    let mut stdin = match UnbufferedStandardInput::open() {
        Ok(stdin) => stdin,
        Err(()) => return EXIT_INTERNAL_FAILURE,
    };
    let _parent = match parent::verify(&stdin) {
        Ok(parent) => parent,
        Err(()) => return EXIT_INTERNAL_FAILURE,
    };

    let stdout = io::stdout();
    let scope = match framing::read_scope(&mut stdin).map_err(map_read_error) {
        Ok(scope) => scope,
        Err(SessionError::Protocol) => return EXIT_PROTOCOL_REFUSED,
        Err(SessionError::Io) => return EXIT_IO_FAILURE,
        Err(SessionError::Internal) => return EXIT_INTERNAL_FAILURE,
    };
    let lease = match LeaseState::watch_standard_input(stdin) {
        Ok(lease) => lease,
        Err(()) => return EXIT_INTERNAL_FAILURE,
    };
    let mut writer = stdout.lock();

    match serve_scope(scope, &mut writer, &watchdog, lease) {
        Ok(terminal) => terminal.exit_code(),
        Err(SessionError::Protocol) => EXIT_PROTOCOL_REFUSED,
        Err(SessionError::Io) => EXIT_IO_FAILURE,
        Err(SessionError::Internal) => EXIT_INTERNAL_FAILURE,
    }
}

fn valid_arguments(arguments: impl IntoIterator<Item = OsString>) -> bool {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    arguments.next().as_deref() == Some(OsStr::new(REQUIRED_MODE_ARGUMENT))
        && arguments.next().is_none()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionError {
    Protocol,
    Io,
    Internal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionTerminal {
    Refused,
    Cancelled,
    Expired,
    Unavailable,
}

pub(crate) enum PromptOutcome {
    Consent,
    /// Consent that also names the single agent identity the user selected.
    /// The fingerprint is public material; it is never a secret.
    ConsentWithIdentity(String),
    Secret(secret::ProtectedSecret),
    Refused,
    Cancelled,
    Expired,
    Unavailable,
}

impl SessionTerminal {
    fn event(self) -> AssistantEventKind {
        match self {
            Self::Refused => AssistantEventKind::Refused,
            Self::Cancelled => AssistantEventKind::Cancelled,
            Self::Expired => AssistantEventKind::Expired,
            Self::Unavailable => AssistantEventKind::Unavailable,
        }
    }

    fn exit_code(self) -> u8 {
        match self {
            Self::Refused => EXIT_REFUSED,
            Self::Cancelled => EXIT_CANCELLED,
            Self::Expired => EXIT_WATCHDOG_EXPIRED,
            Self::Unavailable => EXIT_UNAVAILABLE,
        }
    }
}

fn serve_scope(
    scope: AssistantScopeV1,
    writer: &mut impl io::Write,
    watchdog: &watchdog::Watchdog,
    lease: LeaseState,
) -> Result<SessionTerminal, SessionError> {
    // Map the parent's boot-relative issuance onto this process's Instant. Sampling the local
    // Instant first makes any time until the OS observation conservative rather than renewable.
    let local_before = Instant::now();
    let observed_at_monotonic_nanos = monotonic_nanos().map_err(|_| SessionError::Internal)?;
    let deadline = deadline_from_observation(
        local_before,
        observed_at_monotonic_nanos,
        scope.issued_at_monotonic_nanos,
        scope.remaining_millis,
    )
    .ok_or(SessionError::Protocol)?;
    watchdog
        .tighten_to(deadline)
        .map_err(|_| SessionError::Internal)?;
    if Instant::now() >= deadline {
        return write_terminal(writer, &scope, SessionTerminal::Expired);
    }

    let outcome = show_prompt(&scope, deadline, watchdog.expiration_flag(), lease.clone());
    let lease_resolution = lease.close_and_resolve();
    if lease_resolution == LeaseResolution::ProtocolInvalid {
        return Err(SessionError::Protocol);
    }
    let overriding_terminal = if Instant::now() >= deadline {
        Some(SessionTerminal::Expired)
    } else if lease_resolution == LeaseResolution::Cancelled {
        Some(SessionTerminal::Cancelled)
    } else {
        None
    };
    let terminal = match overriding_terminal {
        Some(terminal) => {
            // A secret accepted just before the deadline or parent lease wins must be
            // zeroized before even the expurgated Expired/Cancelled frame is written.
            drop(outcome);
            terminal
        }
        None => terminal_from_prompt(outcome),
    };
    write_terminal(writer, &scope, terminal)
}

fn terminal_from_prompt(outcome: PromptOutcome) -> SessionTerminal {
    match outcome {
        // A verified personal access is deliberately indistinguishable from an
        // unavailable one on the public surface: announcing it belongs to a
        // later issue, not to this one.
        PromptOutcome::Consent | PromptOutcome::ConsentWithIdentity(_) => {
            SessionTerminal::Unavailable
        }
        PromptOutcome::Secret(secret) => {
            drop(secret);
            SessionTerminal::Unavailable
        }
        PromptOutcome::Refused => SessionTerminal::Refused,
        PromptOutcome::Cancelled => SessionTerminal::Cancelled,
        PromptOutcome::Expired => SessionTerminal::Expired,
        PromptOutcome::Unavailable => SessionTerminal::Unavailable,
    }
}

fn write_terminal(
    writer: &mut impl io::Write,
    scope: &AssistantScopeV1,
    terminal: SessionTerminal,
) -> Result<SessionTerminal, SessionError> {
    let event = AssistantEventV1 {
        schema_version: 1,
        request_id: scope.request_id.clone(),
        event: terminal.event(),
    }
    .validate()
    .map_err(|_| SessionError::Internal)?;
    framing::write_event(writer, &event).map_err(|_| SessionError::Io)?;
    Ok(terminal)
}

/// The delayed-start process proof needs a non-graphical marker for crossing
/// the prompt boundary: reaching this function returns Unavailable, whereas
/// consuming the transmitted TTL correctly returns Expired before this point.
#[cfg(feature = "delayed-start-contract-test")]
fn show_prompt(
    _scope: &AssistantScopeV1,
    _deadline: Instant,
    _expired: std::sync::Arc<std::sync::atomic::AtomicBool>,
    _lease: LeaseState,
) -> PromptOutcome {
    PromptOutcome::Unavailable
}

#[cfg(all(not(feature = "delayed-start-contract-test"), target_os = "linux"))]
fn show_prompt(
    scope: &AssistantScopeV1,
    deadline: Instant,
    expired: std::sync::Arc<std::sync::atomic::AtomicBool>,
    lease: LeaseState,
) -> PromptOutcome {
    if scope.prompt == your_cloud_bootstrap_protocol::NativePromptKind::ConfirmPersonalAccess {
        return serve_personal_access(scope, deadline, expired, lease);
    }
    native_prompt::prompt(scope, deadline, expired, lease)
}

/// The whole personal access, in the order the perimeter fixes.
///
/// Every observation happens before the window opens, so what the user reads
/// — the frozen addresses beside the name, the identities the agent really
/// holds — is exactly what the transport will use afterwards. Nothing is
/// re-derived after consent, and every refusal is expurgated into the same
/// Unavailable outcome, because no public surface of this palier may reveal
/// whether an access was verified.
#[cfg(all(not(feature = "delayed-start-contract-test"), target_os = "linux"))]
fn serve_personal_access(
    scope: &AssistantScopeV1,
    deadline: Instant,
    expired: std::sync::Arc<std::sync::atomic::AtomicBool>,
    lease: LeaseState,
) -> PromptOutcome {
    use personal_access::session::{AuthenticationRequest, GuardVerdict, Prepared};
    use std::sync::atomic::Ordering;

    let Ok(prepared) = Prepared::open(&scope.target.host, scope.target.port, deadline) else {
        return PromptOutcome::Unavailable;
    };

    // The scope shown is the received one plus the addresses this process just
    // froze; revalidating it keeps that augmentation inside the same bounds the
    // parent's scope had to satisfy.
    let mut resolved = scope.clone();
    resolved.target_addresses = prepared
        .target()
        .addresses()
        .iter()
        .map(|address| address.to_string())
        .collect();
    let Ok(resolved) = resolved.validate() else {
        return PromptOutcome::Unavailable;
    };

    let outcome = native_prompt::prompt_with_identities(
        &resolved,
        prepared.identities(),
        deadline,
        std::sync::Arc::clone(&expired),
        lease.clone(),
    );
    let PromptOutcome::ConsentWithIdentity(selected) = outcome else {
        return outcome;
    };

    let guard_expired = std::sync::Arc::clone(&expired);
    let guard_lease = lease.clone();
    let guard = move || {
        if guard_expired.load(Ordering::SeqCst) || Instant::now() >= deadline {
            GuardVerdict::Expired
        } else if guard_lease.is_cancelled() || guard_lease.is_protocol_invalid() {
            GuardVerdict::Cancelled
        } else {
            GuardVerdict::Continue
        }
    };
    let request = AuthenticationRequest {
        username: &scope.target.username,
        approved_host_key_fingerprint: &scope.target.host_key_sha256,
        selected_fingerprint: &selected,
    };
    match prepared.run(&request, deadline, &guard) {
        Ok(report) => {
            // The probe result stays internal at this palier: it is dropped
            // here rather than travelling to any public event.
            drop(report);
            PromptOutcome::ConsentWithIdentity(selected)
        }
        Err(_refused) => PromptOutcome::Unavailable,
    }
}

#[cfg(all(not(feature = "delayed-start-contract-test"), target_os = "windows"))]
fn show_prompt(
    scope: &AssistantScopeV1,
    deadline: Instant,
    expired: std::sync::Arc<std::sync::atomic::AtomicBool>,
    lease: LeaseState,
) -> PromptOutcome {
    native_prompt_windows::prompt(scope, deadline, expired, lease)
}

#[cfg(all(
    not(feature = "delayed-start-contract-test"),
    not(any(target_os = "linux", target_os = "windows"))
))]
fn show_prompt(
    _scope: &AssistantScopeV1,
    _deadline: Instant,
    _expired: std::sync::Arc<std::sync::atomic::AtomicBool>,
    _lease: LeaseState,
) -> PromptOutcome {
    PromptOutcome::Unavailable
}

fn deadline_from_observation(
    local_before: Instant,
    observed_at_monotonic_nanos: u64,
    issued_at_monotonic_nanos: u64,
    remaining_millis: u64,
) -> Option<Instant> {
    let elapsed_nanos = observed_at_monotonic_nanos.checked_sub(issued_at_monotonic_nanos)?;
    let transmitted_nanos = remaining_millis.checked_mul(1_000_000)?;
    let remaining_nanos = transmitted_nanos.saturating_sub(elapsed_nanos);
    local_before.checked_add(Duration::from_nanos(remaining_nanos))
}

fn map_read_error(error: ReadFrameError) -> SessionError {
    match error {
        ReadFrameError::Invalid => SessionError::Protocol,
        ReadFrameError::Io => SessionError::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_requires_exactly_one_fixed_argument() {
        assert!(valid_arguments([
            OsString::from("assistant"),
            OsString::from(REQUIRED_MODE_ARGUMENT),
        ]));
        for arguments in [
            vec![OsString::from("assistant")],
            vec![OsString::from("assistant"), OsString::from("--other")],
            vec![
                OsString::from("assistant"),
                OsString::from(REQUIRED_MODE_ARGUMENT),
                OsString::from("extra"),
            ],
        ] {
            assert!(!valid_arguments(arguments));
        }
    }

    #[test]
    fn shared_monotonic_stamp_deducts_delay_and_rejects_hostile_values() {
        let local_before = Instant::now();
        let issued = 10_000_000_000;

        assert_eq!(
            deadline_from_observation(local_before, issued + 40_000_000, issued, 100),
            Some(local_before + Duration::from_millis(60))
        );
        assert_eq!(
            deadline_from_observation(local_before, issued + 100_000_000, issued, 100),
            Some(local_before)
        );
        assert_eq!(
            deadline_from_observation(local_before, issued - 1, issued, 100),
            None,
            "a future parent stamp must fail closed"
        );
        assert_eq!(
            deadline_from_observation(local_before, issued, issued, u64::MAX),
            None,
            "millisecond-to-nanosecond overflow must fail closed"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn a_protected_secret_can_only_produce_an_expurgated_terminal_kind() {
        let mut secret = secret::ProtectedSecret::new().expect("protected allocation");
        secret
            .copy_from(b"synthetic-canary")
            .expect("bounded synthetic input");

        let terminal = terminal_from_prompt(PromptOutcome::Secret(secret));
        assert_eq!(terminal, SessionTerminal::Unavailable);
        let event = AssistantEventV1 {
            schema_version: 1,
            request_id: "00112233445566778899aabbccddeeff".into(),
            event: terminal.event(),
        };
        let payload = serde_json::to_vec(&event).expect("expurgated event");
        assert!(!payload
            .windows(b"synthetic-canary".len())
            .any(|window| window == b"synthetic-canary"));
    }
}
