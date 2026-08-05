mod framing;
mod hardening;
/// Installing one Controller from the embedded bundle. It is compiled on the
/// two platforms the palier targets, exactly like the audit, the elevation and
/// the placement whose witnesses it requires.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod installation;
mod lease;
/// Enrolling one approved machine with an SSH identity bounded to it. It is
/// compiled on the two platforms the palier targets, like the installation it
/// continues and like the witnesses it requires.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod machine_identity;
#[cfg(target_os = "linux")]
mod native_prompt;
#[cfg(target_os = "windows")]
mod native_prompt_windows;
mod parent;
pub mod personal_access;
/// Replacing one Controller explicitly, and leaving the old one no exposed
/// authority. It is compiled on the two platforms the palier targets, like the
/// installation and the enrolment whose witnesses it requires.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod replacement;
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
    ASSISTANT_EXIT_ACCESS_VERIFIED, ASSISTANT_EXIT_CANCELLED, ASSISTANT_EXIT_INTERNAL_FAILURE,
    ASSISTANT_EXIT_INVALID_INVOCATION, ASSISTANT_EXIT_IO_FAILURE, ASSISTANT_EXIT_PROTOCOL_REFUSED,
    ASSISTANT_EXIT_REFUSED, ASSISTANT_EXIT_UNAVAILABLE, ASSISTANT_EXIT_WATCHDOG_EXPIRED,
};

pub const REQUIRED_MODE_ARGUMENT: &str = "--native-bootstrap-assistant";
pub const EXIT_ACCESS_VERIFIED: u8 = ASSISTANT_EXIT_ACCESS_VERIFIED;
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

/// Names the personal access contract fixture and its suite agree on.
///
/// The perimeter is read entirely from the environment: this crate carries no
/// lab address, no account name and no key material, and the harness that sets
/// these variables is documented with the run itself.
#[cfg(all(feature = "personal-access-contract-test", target_os = "linux"))]
pub mod personal_access_contract {
    /// Name or numeric address of the machine running the synthetic `sshd`.
    pub const TARGET: &str = "YOUR_CLOUD_LAB_TARGET";
    /// Port that `sshd` listens on, decimal.
    pub const PORT: &str = "YOUR_CLOUD_LAB_PORT";
    /// Synthetic account the fixture authenticates as.
    pub const USERNAME: &str = "YOUR_CLOUD_LAB_USERNAME";
    /// `SHA256:…` fingerprint of that machine's real Ed25519 host key.
    pub const HOST_KEY: &str = "YOUR_CLOUD_LAB_HOST_KEY";
    /// Fingerprint of the agent identity the server accepts.
    pub const AUTHORIZED: &str = "YOUR_CLOUD_LAB_AUTHORIZED";

    /// File created once a `linger` session has completed, so the suite knows
    /// the process it is about to search really finished a session. It is a
    /// file rather than a line on standard output for the same reason the
    /// delayed start fixture uses one: a readiness signal must be observable
    /// without a blocking read that has no deadline of its own.
    pub const READY_PATH: &str = "YOUR_CLOUD_LAB_READY_PATH";

    /// Absolute path of the synthetic encrypted key file the fallback opens.
    ///
    /// It is what selects the credential: present, the fixture authenticates
    /// with the key file of #53; absent, with the agent of #52. Both modes
    /// above work either way, so the teardown and the canary search are taken
    /// on the same fixture rather than on a second one.
    ///
    /// Only the *path* travels through the environment. The passphrase never
    /// does: the fixture reads it from its own standard input, precisely so
    /// that the canary search of this suite can look at `environ` and at the
    /// command line and find nothing.
    pub const KEY_PATH: &str = "YOUR_CLOUD_LAB_KEY_PATH";

    /// Stay inside a session the server holds open, until something kills us.
    pub const MODE_HOLD: &str = "hold";
    /// Finish one nominal session, then stay alive to be searched.
    pub const MODE_LINGER: &str = "linger";

    /// Stop at the state the fallback is in while the passphrase is being
    /// typed: the file opened, validated and still held, and not one byte of a
    /// passphrase in this process. It opens no transport at all, because the
    /// product has none open at that moment either.
    pub const MODE_SELECTED: &str = "selected";
    /// Stop *inside* the derivation: the passphrase in the protected
    /// allocation, the file still held, and the derivation thread paying for
    /// the rounds the envelope declared. It too opens no transport: the
    /// product opens its own only once this state has produced a key.
    pub const MODE_DERIVING: &str = "deriving";

    /// Name of the thread the derivation runs on, taken from the module that
    /// spawns it rather than repeated: a suite that looked for a name written
    /// twice would stop observing anything the day one of the two changed.
    pub const DERIVATION_THREAD: &str = crate::personal_access::key_unlock::DERIVATION_THREAD_NAME;
    /// How much of that name `/proc/<pid>/task/<tid>/comm` really answers.
    ///
    /// Linux stores fifteen characters and a terminator, and the standard
    /// library truncates to exactly that before asking, so a suite comparing
    /// the whole name against `comm` would never match and would conclude the
    /// derivation had not started.
    pub const DERIVATION_THREAD_COMM_BYTES: usize = 15;

    /// Longest a fixture session may last before its own lease cuts it.
    pub const LEASE_SECONDS: u64 = 100;
}

/// Feature-only entry point for the personal access process contract.
///
/// This is the helper's own hardened process — parent death signal, no core,
/// non-dumpable, every inherited descriptor above stdio closed — wrapped
/// around one real personal access session and nothing else. Killing it
/// therefore proves what killing the helper mid-session proves, and what
/// cannot be found in its memory afterwards is what the helper never holds
/// either.
#[cfg(all(feature = "personal-access-contract-test", target_os = "linux"))]
#[doc(hidden)]
pub fn personal_access_contract_main() -> u8 {
    use personal_access::session::{AuthenticationRequest, GuardVerdict, Prepared};
    use personal_access_contract as names;

    // Hardened first, exactly as `process_main` does, and before anything is
    // read: a fixture that hardened itself late would prove a weaker claim.
    if hardening::apply().is_err() {
        return EXIT_INTERNAL_FAILURE;
    }

    let read = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    // The two state modes stop *inside* the fallback rather than around a
    // whole session, and they open no transport at all: at the moment each of
    // them describes, the product has none open either. They are therefore
    // decided before a single name of the perimeter's server is read, so that
    // what they hold is only what the fallback itself holds.
    if let Some(mode) = std::env::args().nth(1) {
        if mode == names::MODE_SELECTED || mode == names::MODE_DERIVING {
            return hold_fallback_state(&mode);
        }
    }

    let (Some(mode), Some(target), Some(username), Some(host_key), Some(authorized)) = (
        std::env::args().nth(1),
        read(names::TARGET),
        read(names::USERNAME),
        read(names::HOST_KEY),
        read(names::AUTHORIZED),
    ) else {
        return EXIT_INVALID_INVOCATION;
    };
    let Some(port) = read(names::PORT).and_then(|port| port.parse::<u16>().ok()) else {
        return EXIT_INVALID_INVOCATION;
    };
    if mode != names::MODE_HOLD && mode != names::MODE_LINGER {
        return EXIT_INVALID_INVOCATION;
    }

    let deadline = Instant::now() + Duration::from_secs(names::LEASE_SECONDS);
    let Ok(prepared) = Prepared::open(&target, port, deadline) else {
        return EXIT_UNAVAILABLE;
    };
    // The key path opens its file and derives *before* the transport, exactly
    // as the product does, so what a debugger finds in this process afterwards
    // is what it would find in the helper.
    let opened = match read(names::KEY_PATH) {
        Some(key_path) => match open_contract_key(std::path::Path::new(&key_path), deadline) {
            Ok(key) => Some(key),
            Err(code) => return code,
        },
        None => None,
    };
    let selected = match opened.as_ref() {
        Some(key) => key.fingerprint().to_owned(),
        None => authorized,
    };
    let request = AuthenticationRequest {
        username: &username,
        approved_host_key_fingerprint: &host_key,
        selected_fingerprint: &selected,
    };
    // A `hold` session never returns from here: the server holds the probe
    // open and only the deadline, or being killed, ends it.
    let observation = match opened {
        Some(key) => prepared.run_with_key(key, &request, deadline, &|| GuardVerdict::Continue),
        None => prepared.run(&request, deadline, &|| GuardVerdict::Continue),
    };
    let Ok(report) = observation.outcome else {
        return EXIT_UNAVAILABLE;
    };
    // The probe result stays a value here too; only the fact that a session
    // completed is announced, so the suite knows what it is searching.
    drop(report);
    if mode == names::MODE_LINGER {
        let Some(ready_path) = read(names::READY_PATH) else {
            return EXIT_INVALID_INVOCATION;
        };
        if announce(std::path::Path::new(&ready_path), b"session complete").is_err() {
            return EXIT_IO_FAILURE;
        }
        // Stay alive, holding whatever this process accumulated, until the
        // suite has finished searching it and kills us.
        std::thread::sleep(Duration::from_secs(names::LEASE_SECONDS));
    }
    0
}

/// Stops at one clean state of the encrypted key fallback and stays there.
///
/// Neither state opens a transport, and neither is a session: they are the two
/// moments at which the product itself is holding something and doing nothing
/// else — waiting for a passphrase, and paying for the rounds. Whatever ends
/// this process while it sits in one of them is what a suite is measuring, so
/// nothing else may be running beside it.
///
/// Readiness is a file, announced at the exact instant the state is entered and
/// never before: a suite that killed this process on a guess would prove
/// nothing about a state it had not observed.
#[cfg(all(feature = "personal-access-contract-test", target_os = "linux"))]
fn hold_fallback_state(mode: &str) -> u8 {
    use personal_access::{key_file, key_unlock};
    use personal_access_contract as names;

    let read = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    let (Some(key_path), Some(ready_path)) = (read(names::KEY_PATH), read(names::READY_PATH))
    else {
        return EXIT_INVALID_INVOCATION;
    };
    let ready_path = std::path::PathBuf::from(ready_path);
    let Ok(selected) = key_file::open_and_validate(std::path::Path::new(&key_path)) else {
        return EXIT_UNAVAILABLE;
    };

    if mode == names::MODE_SELECTED {
        // The file is open, validated and still held; not one byte of a
        // passphrase exists in this process. It is the state the product is in
        // while its passphrase window is up, and the standard input read below
        // is that window: an end of file on it is the user letting go before
        // ever typing, and it must leave nothing behind.
        if announce(&ready_path, b"file selected").is_err() {
            return EXIT_IO_FAILURE;
        }
        return match read_contract_passphrase() {
            Ok(passphrase) => {
                // Nothing in this mode derives. Both values are dropped here,
                // and wiped by that drop.
                drop(passphrase);
                drop(selected);
                EXIT_REFUSED
            }
            Err(code) => code,
        };
    }

    let passphrase = match read_contract_passphrase() {
        Ok(passphrase) => passphrase,
        Err(code) => return code,
    };
    // Everything the derivation needs is in hand, and nothing has been paid for
    // yet. Announced here rather than after the call, which never returns in
    // time to announce anything.
    if announce(&ready_path, b"deriving").is_err() {
        return EXIT_IO_FAILURE;
    }
    let deadline = Instant::now() + Duration::from_secs(names::LEASE_SECONDS);
    match key_unlock::unlock(selected, passphrase, deadline) {
        // A derivation nothing interrupted is the control of every case that
        // interrupts one: it says the file really does derive, and how long the
        // state under observation lasts.
        Ok(key) => {
            drop(key);
            0
        }
        Err(_) => EXIT_UNAVAILABLE,
    }
}

/// Writes a readiness marker exactly once, or fails.
///
/// `create_new` is what makes it once: a marker that could be rewritten would
/// let a second state announce itself under the first one's name.
#[cfg(all(feature = "personal-access-contract-test", target_os = "linux"))]
fn announce(path: &std::path::Path, content: &[u8]) -> io::Result<()> {
    use std::io::Write as _;

    let mut ready = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    ready.write_all(content)?;
    ready.flush()
}

/// Opens the contract's synthetic key file with a passphrase read from this
/// process's own standard input.
#[cfg(all(feature = "personal-access-contract-test", target_os = "linux"))]
fn open_contract_key(
    path: &std::path::Path,
    deadline: Instant,
) -> Result<personal_access::key_unlock::PersonalKey, u8> {
    use personal_access::{key_file, key_unlock};

    let Ok(selected) = key_file::open_and_validate(path) else {
        return Err(EXIT_UNAVAILABLE);
    };
    let passphrase = read_contract_passphrase()?;
    key_unlock::unlock(selected, passphrase, deadline).map_err(|_| EXIT_UNAVAILABLE)
}

/// Reads the contract's synthetic passphrase from this process's own standard
/// input, straight into the protected allocation.
///
/// Standard input is used rather than an argument or an environment entry
/// because both of those are exactly what the canary search reads back from
/// `/proc`. It is read through the *unbuffered* descriptor rather than through
/// `io::stdin`, which keeps an eight kibibyte buffer of its own on the heap and
/// never wipes it — the passphrase would land there before reaching the
/// protected allocation, and the search of this suite finds it. The product
/// never has that problem, because its passphrase comes from the native window
/// straight into the protected allocation; the fixture must not weaken what it
/// is used to prove.
///
/// An end of file before a single byte is the caller letting go: it answers the
/// invalid-invocation code, having built nothing to keep.
#[cfg(all(feature = "personal-access-contract-test", target_os = "linux"))]
fn read_contract_passphrase() -> Result<secret::ProtectedSecret, u8> {
    use std::io::Read as _;

    let Ok(mut passphrase) = secret::ProtectedSecret::new() else {
        return Err(EXIT_INTERNAL_FAILURE);
    };
    let Ok(mut stdin) = UnbufferedStandardInput::open() else {
        return Err(EXIT_INTERNAL_FAILURE);
    };
    let buffer = passphrase.raw_mut();
    let mut filled = 0;
    loop {
        match stdin.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(_) => return Err(EXIT_IO_FAILURE),
        }
        if filled == buffer.len() {
            break;
        }
    }
    // A trailing newline belongs to the pipe, not to the passphrase.
    while filled > 0 && (buffer[filled - 1] == b'\n' || buffer[filled - 1] == b'\r') {
        filled -= 1;
    }
    if passphrase.set_len(filled).is_err() || passphrase.is_empty() {
        return Err(EXIT_INVALID_INVOCATION);
    }
    Ok(passphrase)
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
    /// The elevation was proven on the exact session that was consented to.
    /// It is the only terminal that is not a refusal, and the only one this
    /// process may exit zero on.
    AccessVerified,
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
    /// Consent that names an encrypted key file instead of an agent identity.
    /// It carries a path and nothing else: the file is not opened by the
    /// window, and the path came from the helper's own native selector.
    ConsentWithKeyFile(std::path::PathBuf),
    Secret(secret::ProtectedSecret),
    /// The elevation was proven. It carries the witness `elevation` produced
    /// and nothing else: the only way to reach this variant is to hold one, and
    /// the only way to hold one is to have read an exit status of zero beside
    /// root's uid on the session that was consented to.
    #[cfg(all(
        not(feature = "delayed-start-contract-test"),
        any(target_os = "linux", target_os = "windows")
    ))]
    Verified(personal_access::elevation::Elevation),
    Refused,
    Cancelled,
    Expired,
    Unavailable,
}

impl SessionTerminal {
    fn event(self) -> AssistantEventKind {
        match self {
            Self::AccessVerified => AssistantEventKind::AccessVerified,
            Self::Refused => AssistantEventKind::Refused,
            Self::Cancelled => AssistantEventKind::Cancelled,
            Self::Expired => AssistantEventKind::Expired,
            Self::Unavailable => AssistantEventKind::Unavailable,
        }
    }

    /// The code this process exits with is *derived from the event it wrote*,
    /// never chosen beside it, and the table it is derived through is the
    /// protocol's own — the very one the Console reads the pair back with.
    ///
    /// That is what makes "exit code zero" and `access_verified` indissociable
    /// rather than merely consistent: there is no second list to keep in step,
    /// and no way to answer one without the other. An event that terminates
    /// nothing names no code and is refused here, which cannot happen from any
    /// variant above and is written down so it never silently can.
    fn exit_code(self) -> u8 {
        self.event()
            .terminal_exit_code()
            .unwrap_or(EXIT_INTERNAL_FAILURE)
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
        // A consent is not an access. It says the user agreed to a session,
        // never that the session proved anything, and it stays expurgated into
        // the same Unavailable every refusal ends in.
        PromptOutcome::Consent
        | PromptOutcome::ConsentWithIdentity(_)
        | PromptOutcome::ConsentWithKeyFile(_) => SessionTerminal::Unavailable,
        // The one path to the one terminal that is not a refusal. It is
        // reachable only from a witness, so this line cannot be reached by
        // anything that did not prove an elevation.
        #[cfg(all(
            not(feature = "delayed-start-contract-test"),
            any(target_os = "linux", target_os = "windows")
        ))]
        PromptOutcome::Verified(_witness) => SessionTerminal::AccessVerified,
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

/// The native window of this process, whichever system it runs on.
///
/// The two implementations are separate because the surfaces are — a GTK dialog
/// and a Win32 one share no type — but they answer the same two calls with the
/// same meaning, which is what lets the personal access step below be one path
/// rather than two.
#[cfg(all(not(feature = "delayed-start-contract-test"), target_os = "linux"))]
use native_prompt as native_window;
#[cfg(all(not(feature = "delayed-start-contract-test"), target_os = "windows"))]
use native_prompt_windows as native_window;

#[cfg(all(
    not(feature = "delayed-start-contract-test"),
    any(target_os = "linux", target_os = "windows")
))]
fn show_prompt(
    scope: &AssistantScopeV1,
    deadline: Instant,
    expired: std::sync::Arc<std::sync::atomic::AtomicBool>,
    lease: LeaseState,
) -> PromptOutcome {
    match scope.prompt {
        your_cloud_bootstrap_protocol::NativePromptKind::ConfirmPersonalAccess => {
            serve_personal_access(scope, deadline, expired, lease)
        }
        // The root route is its own entry, and it is entered only through the
        // scope the protocol reserves for it: `ConfirmRootAccess` is refused
        // beside an administrator target, and `ConfirmPersonalAccess` beside a
        // root one, so neither route can be arrived at through the other's
        // consent.
        your_cloud_bootstrap_protocol::NativePromptKind::ConfirmRootAccess => {
            serve_root_access(scope, deadline, expired, lease)
        }
        _ => native_window::prompt(scope, deadline, expired, lease),
    }
}

/// The whole personal access, in the order the perimeter fixes.
///
/// Every observation happens before the window opens, so what the user reads
/// — the frozen addresses beside the name, the identities the agent really
/// holds — is exactly what the transport will use afterwards. Nothing is
/// re-derived after consent, and every refusal is expurgated into the same
/// Unavailable outcome: the public surface distinguishes a proven access from
/// everything else, and never one refusal from another.
///
/// The step is one path on both systems. Only the agent endpoint differs, and
/// that difference lives inside `Prepared::open`: a Unix socket judged by its
/// own rule, or the attested OpenSSH pipe. Everything after it — the frozen
/// addresses shown, the identity named, the single signature spent, the probe
/// — is literally the same code here.
#[cfg(all(
    not(feature = "delayed-start-contract-test"),
    any(target_os = "linux", target_os = "windows")
))]
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

    // An agent that holds nothing is no longer the end of the step on Linux:
    // it is exactly the state in which the encrypted key file of #53 is the way
    // in, and the window below offers it. Windows has no such fallback at this
    // palier — the selector belongs to the GTK window — so there, an agent that
    // holds nothing still ends the step before anything is displayed, which is
    // the behaviour that palier was proved with.
    #[cfg(target_os = "windows")]
    if prepared.identities().is_empty() {
        return PromptOutcome::Unavailable;
    }

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

    let outcome = native_window::prompt_with_identities(
        &resolved,
        prepared.identities(),
        deadline,
        std::sync::Arc::clone(&expired),
        lease.clone(),
    );
    // Exactly one credential leaves the window: an agent identity, or a key
    // file. Both continue into the *same* session below.
    let credential = match outcome {
        PromptOutcome::ConsentWithIdentity(selected) => Credential::AgentIdentity(selected),
        #[cfg(target_os = "linux")]
        PromptOutcome::ConsentWithKeyFile(path) => {
            match open_personal_key(&resolved, &path, deadline, &expired, &lease) {
                Ok(key) => Credential::Key(key),
                Err(outcome) => return outcome,
            }
        }
        other => return other,
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
    let selected = credential.fingerprint().to_owned();
    let request = AuthenticationRequest {
        username: &scope.target.username,
        approved_host_key_fingerprint: &scope.target.host_key_sha256,
        selected_fingerprint: &selected,
    };
    // Only the outcome is consulted here: how much of the signature budget the
    // session left is a contract observation, not a decision this path makes.
    let established = match credential {
        Credential::AgentIdentity(_) => prepared.establish(&request, deadline, &guard),
        #[cfg(target_os = "linux")]
        Credential::Key(key) => prepared.establish_with_key(key, &request, deadline, &guard),
    };
    let Ok(mut live) = established.outcome else {
        return PromptOutcome::Unavailable;
    };
    let proven =
        prove_administrator_elevation(&mut live, &resolved, deadline, &expired, &lease, &guard);
    // The transport is closed before anything is announced, on every path —
    // including the one that is about to announce a verified access. Nothing of
    // this session is still open when its terminal is written.
    live.close();
    match proven {
        Ok(witness) => PromptOutcome::Verified(witness),
        // Every refusal of the elevation is already expurgated into an outcome
        // by the function above; a cancelled or expired window keeps its own.
        Err(outcome) => outcome,
    }
}

/// The administrator route, in the three channels it is allowed and no more.
///
/// The order is the perimeter's. The identity first, because an account that is
/// already `root` must never reach root privileges under the personal access
/// consent alone. The policy next, judged by #51 before a password exists at
/// all. The single elevation last, and only in the one form that policy chose:
/// a passwordless `sudo -n` when the entry waives authentication, or the one
/// `sudo -S` when it does not — never both, never twice, never retried.
///
/// The password window is a *new* native consent for a new privileged step. It
/// is derived from the scope already agreed and revalidated, so the escalation
/// it names is the escalation of the machine the user consented to.
#[cfg(all(
    not(feature = "delayed-start-contract-test"),
    any(target_os = "linux", target_os = "windows")
))]
fn prove_administrator_elevation(
    live: &mut personal_access::session::LiveSession,
    resolved: &AssistantScopeV1,
    deadline: Instant,
    expired: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    lease: &LeaseState,
    guard: &(dyn Fn() -> personal_access::session::GuardVerdict + Sync),
) -> Result<personal_access::elevation::Elevation, PromptOutcome> {
    use personal_access::elevation::{self, AccessRoute};

    let probe = live
        .probe(deadline, guard)
        .map_err(|_| PromptOutcome::Unavailable)?;
    elevation::attest_identity(
        AccessRoute::Administrator,
        probe.exit_status,
        &probe.stdout,
        &probe.stderr,
    )
    .map_err(|_| PromptOutcome::Unavailable)?;

    let preflight = live
        .run_channel(elevation::PREFLIGHT, None, deadline, guard)
        .map_err(|_| PromptOutcome::Unavailable)?;
    // A listing that succeeded is on the standard output; the reason a listing
    // failed — a password required, a terminal required — is on the standard
    // error. Whichever stream carries the answer is the stream #51 judges, and
    // handing it the empty one would turn an explicit refusal into a shrug.
    let succeeded = preflight.exit_status == 0;
    let capture = if succeeded {
        &preflight.stdout
    } else {
        &preflight.stderr
    };
    let attested = elevation::attest_policy(succeeded, capture, false)
        .map_err(|_| PromptOutcome::Unavailable)?;

    let elevated = if attested.password_required {
        let password = ask_sudo_password(resolved, deadline, expired, lease)?;
        let report = live.run_channel(attested.command, Some(password.bytes()), deadline, guard);
        // Wiped here, whatever the channel answered. There is no retry, so
        // there is nothing that could ever need it a second time.
        drop(password);
        report
    } else {
        live.run_channel(attested.command, None, deadline, guard)
    }
    .map_err(|_| PromptOutcome::Unavailable)?;

    elevation::elevated(elevated.exit_status, &elevated.stdout, &elevated.stderr)
        .map_err(|_| PromptOutcome::Unavailable)
}

/// Opens the escalation window of #45 for the step it belongs to.
///
/// The scope is derived from the one already agreed and revalidated, exactly as
/// the passphrase window is, so the augmentation stays inside the very bounds
/// the parent's scope had to satisfy. The protocol refuses this couple beside a
/// root target, which is what keeps a `sudo` password window off the root route
/// without a check anyone has to remember.
#[cfg(all(
    not(feature = "delayed-start-contract-test"),
    any(target_os = "linux", target_os = "windows")
))]
fn ask_sudo_password(
    resolved: &AssistantScopeV1,
    deadline: Instant,
    expired: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    lease: &LeaseState,
) -> Result<secret::ProtectedSecret, PromptOutcome> {
    let mut escalation = resolved.clone();
    escalation.step = your_cloud_bootstrap_protocol::BootstrapStep::PrivilegeEscalation;
    escalation.prompt = your_cloud_bootstrap_protocol::NativePromptKind::SudoPassword;
    let Ok(escalation) = escalation.validate() else {
        return Err(PromptOutcome::Unavailable);
    };

    let outcome = native_window::prompt(
        &escalation,
        deadline,
        std::sync::Arc::clone(expired),
        lease.clone(),
    );
    let PromptOutcome::Secret(password) = outcome else {
        return Err(outcome);
    };
    Ok(password)
}

/// The root route, which shares no step with the one above beyond the transport
/// itself.
///
/// Nothing here elevates: an access lent as `root` is already `root`, and the
/// only thing left to establish is that the session really reached it. What
/// makes it an access rather than an assumption is the window: a dedicated
/// consent, on the scope the protocol reserves for this route, answered with
/// the one identity the session will authenticate with. No other outcome of
/// that window continues, so there is no implicit root attempt to make.
#[cfg(all(
    not(feature = "delayed-start-contract-test"),
    any(target_os = "linux", target_os = "windows")
))]
fn serve_root_access(
    scope: &AssistantScopeV1,
    deadline: Instant,
    expired: std::sync::Arc<std::sync::atomic::AtomicBool>,
    lease: LeaseState,
) -> PromptOutcome {
    use personal_access::{
        elevation,
        session::{AuthenticationRequest, GuardVerdict, Prepared},
    };
    use std::sync::atomic::Ordering;

    let Ok(prepared) = Prepared::open(&scope.target.host, scope.target.port, deadline) else {
        return PromptOutcome::Unavailable;
    };
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

    let outcome = native_window::prompt_with_identities(
        &resolved,
        prepared.identities(),
        deadline,
        std::sync::Arc::clone(&expired),
        lease.clone(),
    );
    // The dedicated consent, and nothing weaker. A window that answered a bare
    // consent named no identity, which is not something this route completes
    // for the user.
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
        username: &resolved.target.username,
        approved_host_key_fingerprint: &resolved.target.host_key_sha256,
        selected_fingerprint: &selected,
    };
    let established = prepared.establish(&request, deadline, &guard);
    let Ok(mut live) = established.outcome else {
        return PromptOutcome::Unavailable;
    };
    let probe = live.probe(deadline, &guard);
    live.close();
    let Ok(probe) = probe else {
        return PromptOutcome::Unavailable;
    };
    // `true` is reachable from this line alone, and this line is reachable only
    // from the dedicated consent above.
    match elevation::root_access(true, probe.exit_status, &probe.stdout, &probe.stderr) {
        Ok(witness) => PromptOutcome::Verified(witness),
        Err(_refused) => PromptOutcome::Unavailable,
    }
}

/// The one credential a consent carries into the session.
#[cfg(all(
    not(feature = "delayed-start-contract-test"),
    any(target_os = "linux", target_os = "windows")
))]
enum Credential {
    /// A fingerprint the agent holds, named by the user.
    AgentIdentity(String),
    /// A key opened from the user's own file, held only in this process.
    #[cfg(target_os = "linux")]
    Key(personal_access::key_unlock::PersonalKey),
}

#[cfg(all(
    not(feature = "delayed-start-contract-test"),
    any(target_os = "linux", target_os = "windows")
))]
impl Credential {
    /// What the signature budget will be bound to, whichever it is.
    fn fingerprint(&self) -> &str {
        match self {
            Self::AgentIdentity(fingerprint) => fingerprint,
            #[cfg(target_os = "linux")]
            Self::Key(key) => key.fingerprint(),
        }
    }
}

/// Opens the selected key file, then asks for its passphrase, then derives.
///
/// The order is the perimeter's, not a convenience. The envelope — format,
/// cipher, KDF, rounds, key type and key size — is validated first, on a file
/// opened once without following a link, so a file that can never be used never
/// asks the user for a passphrase and never spends a single round of the lease.
/// Only then does the passphrase window of #45 open, and only then is the
/// derivation paid for, under the same deadline as everything else.
///
/// Every refusal is expurgated into `Unavailable`, exactly like the agent path:
/// no public surface of this palier may say whether a key was opened, let alone
/// why one was not.
#[cfg(all(not(feature = "delayed-start-contract-test"), target_os = "linux"))]
fn open_personal_key(
    resolved: &AssistantScopeV1,
    path: &std::path::Path,
    deadline: Instant,
    expired: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    lease: &LeaseState,
) -> Result<personal_access::key_unlock::PersonalKey, PromptOutcome> {
    use personal_access::{key_file, key_unlock};

    let Ok(selected) = key_file::open_and_validate(path) else {
        return Err(PromptOutcome::Unavailable);
    };

    // The passphrase window of #45, for the step it belongs to. It is derived
    // from the scope already agreed and revalidated, so the augmentation stays
    // inside the very bounds the parent's scope had to satisfy.
    let mut passphrase_scope = resolved.clone();
    passphrase_scope.step = your_cloud_bootstrap_protocol::BootstrapStep::UnlockPersonalKey;
    passphrase_scope.prompt = your_cloud_bootstrap_protocol::NativePromptKind::KeyPassphrase;
    let Ok(passphrase_scope) = passphrase_scope.validate() else {
        return Err(PromptOutcome::Unavailable);
    };

    let outcome = native_window::prompt(
        &passphrase_scope,
        deadline,
        std::sync::Arc::clone(expired),
        lease.clone(),
    );
    let PromptOutcome::Secret(passphrase) = outcome else {
        return Err(outcome);
    };

    // Both the file and the passphrase are consumed here. A wrong passphrase
    // leaves nothing behind: no retry, no kept state, no second window.
    key_unlock::unlock(selected, passphrase, deadline).map_err(|_| PromptOutcome::Unavailable)
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

    /// The pair, inside this process. Whatever a session ends as, the code it
    /// exits with is the one the protocol pairs with the event it just wrote,
    /// and zero belongs to the proven access alone.
    #[test]
    fn the_exit_code_is_always_the_one_the_written_event_names() {
        for terminal in [
            SessionTerminal::AccessVerified,
            SessionTerminal::Refused,
            SessionTerminal::Cancelled,
            SessionTerminal::Expired,
            SessionTerminal::Unavailable,
        ] {
            assert_eq!(
                Some(terminal.exit_code()),
                terminal.event().terminal_exit_code(),
                "{terminal:?} exits with a code its own event does not name"
            );
            assert_eq!(
                terminal.exit_code() == EXIT_ACCESS_VERIFIED,
                terminal == SessionTerminal::AccessVerified,
                "{terminal:?} must not share the successful exit code"
            );
        }
        assert_eq!(
            SessionTerminal::AccessVerified.event(),
            AssistantEventKind::AccessVerified
        );
    }

    /// A consent is not an access, and neither is a secret. Nothing a window
    /// can answer on its own reaches the verified terminal: only the witness
    /// does, and only `personal_access::elevation` builds one.
    #[test]
    fn nothing_a_window_alone_answers_ever_becomes_a_verified_access() {
        let mut outcomes = vec![
            PromptOutcome::Consent,
            PromptOutcome::ConsentWithIdentity("SHA256:synthetic".into()),
            PromptOutcome::ConsentWithKeyFile(std::path::PathBuf::from("/nonexistent/key")),
            PromptOutcome::Refused,
            PromptOutcome::Cancelled,
            PromptOutcome::Expired,
            PromptOutcome::Unavailable,
        ];
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        if let Ok(mut secret) = secret::ProtectedSecret::new() {
            if secret.copy_from(b"synthetic-canary").is_ok() {
                outcomes.push(PromptOutcome::Secret(secret));
            }
        }
        for outcome in outcomes {
            assert_ne!(
                terminal_from_prompt(outcome),
                SessionTerminal::AccessVerified,
                "a window answer alone must never announce a verified access"
            );
        }
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
