/// The approval consent window. It is compiled on the two platforms the palier
/// targets, like the bootstrap window it sits beside.
#[cfg(target_os = "linux")]
mod approval_window;
#[cfg(target_os = "windows")]
mod approval_window_windows;
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
    AttestedInstallationScopeV1, ASSISTANT_EXIT_ACCESS_VERIFIED, ASSISTANT_EXIT_CANCELLED,
    ASSISTANT_EXIT_INTERNAL_FAILURE, ASSISTANT_EXIT_INVALID_INVOCATION, ASSISTANT_EXIT_IO_FAILURE,
    ASSISTANT_EXIT_PROTOCOL_REFUSED, ASSISTANT_EXIT_REFUSED, ASSISTANT_EXIT_UNAVAILABLE,
    ASSISTANT_EXIT_WATCHDOG_EXPIRED,
};

pub const REQUIRED_MODE_ARGUMENT: &str = "--native-bootstrap-assistant";

/// The second, and only other, mode this process answers to.
///
/// It is a distinct argument rather than a field inside the bootstrap scope
/// because the two modes read two different documents, on two differently
/// bounded frames, and answer two different closed vocabularies. A mode chosen
/// by a field of the document would be a process whose behaviour the document
/// decides; a mode chosen by the invocation is a process whose behaviour the
/// parent decides, and the parent is attested.
pub const REQUIRED_APPROVAL_MODE_ARGUMENT: &str = "--native-approval-consent";
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
    // protocol reading all consume, and can never renew, the App-provided TTL.
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

/// The approval consent session: read one consent, show it whole, answer once.
///
/// It shares the hardening, the parent attestation, the watchdog and the lease
/// of the bootstrap session, because the properties those give are exactly the
/// ones a window that collects a signature needs: a process that dies with its
/// parent, a transport that belongs to the declared parent, a session that
/// cannot outlive the time the App granted it, and a cancellation the
/// App can always reach.
///
/// What it does **not** share is everything that touches a credential. No agent
/// endpoint, no key file, no passphrase and no elevation are reachable from
/// here — this function calls into `approval_window` and `framing` and into
/// nothing else, and a test of this crate holds that structurally rather than
/// by intention.
pub fn approval_consent_main() -> u8 {
    let session_started_at = Instant::now();
    if hardening::apply().is_err() {
        return EXIT_INTERNAL_FAILURE;
    }
    std::panic::set_hook(Box::new(|_| {}));

    let watchdog = match watchdog::Watchdog::start_at(session_started_at) {
        Ok(watchdog) => watchdog,
        Err(()) => return EXIT_INTERNAL_FAILURE,
    };

    if !valid_approval_arguments(std::env::args_os()) {
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
    let consent = match framing::read_approval_consent(&mut stdin).map_err(map_read_error) {
        Ok(consent) => consent,
        Err(SessionError::Protocol) => return EXIT_PROTOCOL_REFUSED,
        Err(SessionError::Io) => return EXIT_IO_FAILURE,
        Err(SessionError::Internal) => return EXIT_INTERNAL_FAILURE,
    };
    let lease = match LeaseState::watch_standard_input(stdin) {
        Ok(lease) => lease,
        Err(()) => return EXIT_INTERNAL_FAILURE,
    };
    let mut writer = stdout.lock();

    // The deadline is mapped from the parent's own boot-relative issuance onto
    // this process's clock, exactly as the bootstrap session maps it, so the
    // time the App granted cannot be renewed by a document that arrived
    // late or by a window that opened slowly. Sampling the local instant before
    // the observation makes any drift conservative rather than generous.
    let local_before = Instant::now();
    let Ok(observed_at_monotonic_nanos) = monotonic_nanos() else {
        return EXIT_INTERNAL_FAILURE;
    };
    let Some(deadline) = deadline_from_observation(
        local_before,
        observed_at_monotonic_nanos,
        consent.issued_at_monotonic_nanos,
        consent.remaining_millis,
    ) else {
        return EXIT_PROTOCOL_REFUSED;
    };
    if watchdog.tighten_to(deadline).is_err() {
        return EXIT_INTERNAL_FAILURE;
    }
    if Instant::now() >= deadline {
        // The window is never opened past its own deadline: a human asked after
        // the authority expired is a human asked for nothing.
        let expired = your_cloud_bootstrap_protocol::ApprovalConsentOutcomeV1::without_confirmation(
            &consent.request_id,
            your_cloud_bootstrap_protocol::ApprovalConsentOutcomeKind::Expired,
        );
        let code = expired.exit_code();
        if framing::write_approval_outcome(&mut writer, &expired).is_err() {
            return EXIT_IO_FAILURE;
        }
        return code;
    }
    let outcome = approval_window_ask(&consent, deadline, watchdog.expiration_flag(), lease);
    let code = outcome.exit_code();
    if framing::write_approval_outcome(&mut writer, &outcome).is_err() {
        return EXIT_IO_FAILURE;
    }
    code
}

#[cfg(target_os = "linux")]
fn approval_window_ask(
    consent: &your_cloud_bootstrap_protocol::ApprovalConsentV1,
    deadline: Instant,
    expired: std::sync::Arc<std::sync::atomic::AtomicBool>,
    lease: LeaseState,
) -> your_cloud_bootstrap_protocol::ApprovalConsentOutcomeV1 {
    approval_window::ask(consent, deadline, expired, lease)
}

#[cfg(target_os = "windows")]
fn approval_window_ask(
    consent: &your_cloud_bootstrap_protocol::ApprovalConsentV1,
    deadline: Instant,
    expired: std::sync::Arc<std::sync::atomic::AtomicBool>,
    lease: LeaseState,
) -> your_cloud_bootstrap_protocol::ApprovalConsentOutcomeV1 {
    approval_window_windows::ask(consent, deadline, expired, lease)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn approval_window_ask(
    consent: &your_cloud_bootstrap_protocol::ApprovalConsentV1,
    _deadline: Instant,
    _expired: std::sync::Arc<std::sync::atomic::AtomicBool>,
    _lease: LeaseState,
) -> your_cloud_bootstrap_protocol::ApprovalConsentOutcomeV1 {
    // Unsupported targets never reach a prepared release artifact, and they say
    // `unavailable` rather than pretending a human was asked.
    your_cloud_bootstrap_protocol::ApprovalConsentOutcomeV1::without_confirmation(
        &consent.request_id,
        your_cloud_bootstrap_protocol::ApprovalConsentOutcomeKind::Unavailable,
    )
}

fn valid_approval_arguments(arguments: impl IntoIterator<Item = OsString>) -> bool {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    arguments.next().as_deref() == Some(OsStr::new(REQUIRED_APPROVAL_MODE_ARGUMENT))
        && arguments.next().is_none()
}

/// Le troisième mode, et le seul qui ne dialogue pas : dire ce que vaut le lot
/// serveur que le paquet installé porte, puis se taire.
///
/// Il ne lit aucune trame et n'atteste aucun parent, et c'est une décision :
/// ce mode ne tient aucun secret, ne dépense aucun privilège et n'ouvre aucune
/// fenêtre — il lit trois fichiers que le paquet installe lisibles par tous et
/// prononce un fait public. Ce qui remplace l'attestation du parent est celle
/// de la **position** : la résolution dérive de `/proc/self/exe`, donc un
/// binaire recopié hors de sa position installée ne trouve rien et le dit.
/// L'autorité sur le verdict reste entière : `bundle::verify` contre l'ancre
/// scellée, la même porte que le trajet d'installation emprunte.
pub const REQUIRED_VERIFY_EMBEDDED_MODE_ARGUMENT: &str = "--verify-embedded-server-bundle";

/// La seule version de lot que ce binaire accepte d'installer : la sienne.
/// C'est le modèle de version unifié — un produit, une révision — scellé à la
/// compilation comme l'ancre l'est, et pour la même raison : une version que
/// quelque chose pourrait fournir après coup serait une version choisie par ce
/// quelque chose.
#[cfg(any(target_os = "linux", target_os = "windows"))]
const EMBEDDED_EXPECTED_VERSION: &str = env!("CARGO_PKG_VERSION");

/// La session du troisième mode : borner, résoudre, lire, juger, prononcer.
///
/// Chaque verdict s'imprime par son nom — `VERIFIED …` ou `REFUSED …` — parce
/// que la preuve LAB asserte des noms, jamais des codes de sortie. La sortie
/// tient sur une ligne et il n'y en a qu'une.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn verify_embedded_main() -> u8 {
    use installation::{anchor, bundle, embedded};

    let session_started_at = Instant::now();
    if hardening::apply().is_err() {
        return EXIT_INTERNAL_FAILURE;
    }
    std::panic::set_hook(Box::new(|_| {}));

    let _watchdog = match watchdog::Watchdog::start_at(session_started_at) {
        Ok(watchdog) => watchdog,
        Err(()) => return EXIT_INTERNAL_FAILURE,
    };

    if !valid_verify_embedded_arguments(std::env::args_os()) {
        return EXIT_INVALID_INVOCATION;
    }

    let carried =
        match embedded::from_attested_position().and_then(|location| embedded::read(&location)) {
            Ok(carried) => carried,
            Err(refusal) => {
                println!("REFUSED {refusal:?}");
                return EXIT_REFUSED;
            }
        };
    match bundle::verify(
        anchor::RELEASE_ANCHOR,
        &carried.manifest,
        &carried.signature,
        EMBEDDED_EXPECTED_VERSION,
        &carried.artifact,
    ) {
        Ok(verified) => {
            println!(
                "VERIFIED version={} target={} size={} sha256={}",
                verified.version(),
                verified.target(),
                verified.size(),
                verified.sha256(),
            );
            0
        }
        Err(refusal) => {
            println!("REFUSED {refusal:?}");
            EXIT_REFUSED
        }
    }
}

/// Les cibles jamais livrées disent « indisponible » plutôt que d'imiter un
/// verdict que rien n'a rendu.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn verify_embedded_main() -> u8 {
    EXIT_UNAVAILABLE
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn valid_verify_embedded_arguments(arguments: impl IntoIterator<Item = OsString>) -> bool {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    arguments.next().as_deref() == Some(OsStr::new(REQUIRED_VERIFY_EMBEDDED_MODE_ARGUMENT))
        && arguments.next().is_none()
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
    /// protocol's own — the very one the App reads the pair back with.
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
        return write_terminal(
            writer,
            &scope,
            SessionTerminal::Expired,
            SessionExports::default(),
        );
    }

    let (outcome, exports) =
        show_prompt(&scope, deadline, watchdog.expiration_flag(), lease.clone());
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
            // Les exports tombent avec lui : un terminal qui n'a rien jugé
            // n'affirme rien, et le protocole le refuse de toute façon.
            drop(outcome);
            drop(exports);
            return write_terminal(writer, &scope, terminal, SessionExports::default());
        }
        None => terminal_from_prompt(outcome),
    };
    write_terminal(writer, &scope, terminal, exports)
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
    exports: SessionExports,
) -> Result<SessionTerminal, SessionError> {
    // Seuls les deux terminaux d'une session qui a jugé portent les exports :
    // un accès vérifié — la route d'audit exporte la portée, une pose réussie
    // exporte son déroulé — et un refus, dont la portée est parfois la cause
    // et dont le déroulé dit ce qui restait quand il est tombé. Tout autre
    // terminal les laisse tomber ici plutôt que d'affirmer, et le protocole
    // refuse de toute façon la combinaison.
    let (installation_scope, install_ledger) = match terminal {
        SessionTerminal::AccessVerified | SessionTerminal::Refused => (
            exports
                .installation_scope
                .map(|scope| AttestedInstallationScopeV1 {
                    suffices: scope.suffices,
                    permits: scope.permits,
                }),
            exports.install_ledger,
        ),
        _ => (None, None),
    };
    // La cause n'a qu'un porteur : le refus. Un accès vérifié n'a rien refusé,
    // et un terminal qui n'a pas jugé n'a rien à nommer — le protocole refuse
    // de toute façon la combinaison (#157).
    let refusal = match terminal {
        SessionTerminal::Refused => exports.refusal,
        _ => None,
    };
    let event = AssistantEventV1 {
        schema_version: 1,
        request_id: scope.request_id.clone(),
        event: terminal.event(),
        installation_scope,
        install_ledger,
        refusal,
    }
    .validate()
    .map_err(|_| SessionError::Internal)?;
    framing::write_event(writer, &event).map_err(|_| SessionError::Io)?;
    Ok(terminal)
}

/// Ce qu'une session exporte au-delà de son verdict : la portée attestée de
/// l'entrée sudoers, et le déroulé du registre quand une séquence a couru.
/// Rassemblés parce qu'ils voyagent ensemble, sur les deux mêmes terminaux
/// porteurs, et qu'un troisième export rejoindrait cette structure plutôt que
/// d'allonger chaque signature du chemin.
#[derive(Default)]
struct SessionExports {
    installation_scope: Option<personal_access::elevation::InstallationScope>,
    install_ledger: Option<Vec<your_cloud_bootstrap_protocol::LedgerItemV1>>,
    /// La cause, quand un contrôle a jugé plutôt que renoncé (#157).
    refusal: Option<your_cloud_bootstrap_protocol::AssistantRefusalV1>,
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
) -> (PromptOutcome, SessionExports) {
    (PromptOutcome::Unavailable, SessionExports::default())
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
) -> (PromptOutcome, SessionExports) {
    // Les exports voyagent À CÔTÉ de l'issue, jamais dedans : la portée
    // n'existe que si un listing a été attesté sous ce consentement, le
    // déroulé que si une séquence a couru — et la seule route qui fait l'un
    // ou l'autre est celle de l'accès personnel. Les faire porter par chaque
    // variante d'issue laisserait une fenêtre affirmer un jugement qu'aucun
    // listing n'a rendu.
    match scope.prompt {
        your_cloud_bootstrap_protocol::NativePromptKind::ConfirmPersonalAccess => {
            let mut exports = SessionExports::default();
            let outcome = serve_personal_access(scope, deadline, expired, lease, &mut exports);
            (outcome, exports)
        }
        // The root route is its own entry, and it is entered only through the
        // scope the protocol reserves for it: `ConfirmRootAccess` is refused
        // beside an administrator target, and `ConfirmPersonalAccess` beside a
        // root one, so neither route can be arrived at through the other's
        // consent. `root` n'a pas de listing à attester : sa portée n'existe
        // pas, plutôt que de valoir « tout ».
        your_cloud_bootstrap_protocol::NativePromptKind::ConfirmRootAccess => (
            serve_root_access(scope, deadline, expired, lease),
            SessionExports::default(),
        ),
        _ => (
            native_window::prompt(scope, deadline, expired, lease),
            SessionExports::default(),
        ),
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
    exports: &mut SessionExports,
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
    // Le budget de la session est dérivé de l'action que l'humain a approuvée,
    // et adopté **ici** : avant la sonde d'identité, donc avant le premier
    // canal, ce qui est le seul instant où la garde de #54 l'accepte. Plus tard
    // — après l'élévation, par exemple — elle refuserait, et une séquence
    // d'installation branchée sur cette session n'aurait pas un canal à
    // dépenser.
    //
    // Une action qui n'installe rien rend zéro, et zéro veut dire « rien à
    // substituer » : la session garde alors la conversation que #54 lui donne,
    // intacte. C'est le cas de l'audit, qui n'ouvre aucune étape.
    let session_budget = installation::acts::channel_budget(resolved.actions[0]);
    if session_budget != 0 && live.adopt_derived_budget(session_budget).is_err() {
        live.close();
        return PromptOutcome::Unavailable;
    }
    let proven = prove_administrator_elevation(
        &mut live, &resolved, deadline, &expired, &lease, &guard, exports,
    );
    let outcome = match proven {
        Ok(proof) => match resolved.actions[0] {
            // L'audit s'arrête à l'accès prouvé : c'est toute sa conversation.
            your_cloud_bootstrap_protocol::BootstrapAction::AuditTargetReadOnly => {
                let ProvenElevation {
                    witness, secret, ..
                } = proof;
                let mut secret = secret;
                secret.destroy();
                PromptOutcome::Verified(witness)
            }
            // Les deux actions d'installation continuent dans la même session :
            // c'est elle qui a prouvé l'élévation, et une seconde connexion
            // serait une seconde authentification, une seconde attestation de
            // clé d'hôte, une seconde signature.
            your_cloud_bootstrap_protocol::BootstrapAction::InstallServerBundle
            | your_cloud_bootstrap_protocol::BootstrapAction::ActivateApprovedController => {
                let ledger = &mut exports.install_ledger;
                run_installation(&mut live, &resolved, proof, deadline, &guard, ledger)
            }
        },
        // Every refusal of the elevation is already expurgated into an outcome
        // by the function above; a cancelled or expired window keeps its own.
        Err(outcome) => outcome,
    };
    // The transport is closed before anything is announced, on every path —
    // including the one that is about to announce a verified access. Nothing of
    // this session is still open when its terminal is written.
    live.close();
    outcome
}

/// Ce que l'élévation prouvée laisse à la suite de la session.
///
/// Le témoin d'abord ; puis le secret **retenu** plutôt que détruit — c'est la
/// décision du contrat d'amorçage : sur la route d'installation, il vit dans la
/// même allocation protégée le temps de la séquence que l'humain vient
/// d'approuver, et meurt sur toute sortie de cette séquence. La route d'audit
/// le détruit sans délai ; aucune route ne le rend à un appelant.
#[cfg(all(
    not(feature = "delayed-start-contract-test"),
    any(target_os = "linux", target_os = "windows")
))]
struct ProvenElevation {
    witness: personal_access::elevation::Elevation,
    secret: installation::sequence::SpentSecret<secret::ProtectedSecret>,
    /// Vient de l'attestation de politique, et d'elle seule : c'est elle qui a
    /// lu le listing distant, et chaque acte de la séquence choisira sa forme
    /// — `-n` ou `-S` — d'après elle.
    password_required: bool,
}

/// La route d'installation : ce que la session fait, une fois l'élévation
/// prouvée, quand l'action approuvée installe.
///
/// **Chaque témoin naît ici, dans cette session, ou d'une constante scellée.**
/// Les faits de la machine sont observés par les canaux de cette session ; la
/// déclaration et l'approbation dérivent du scope que l'humain vient de
/// consentir à l'écran ; le lot vient de la position attestée et de l'ancre de
/// release ; la configuration est composée des valeurs que le scope porte et
/// dont la fenêtre a montré l'empreinte. Rien n'est affirmé par l'App,
/// rien ne traverse d'une autre session.
///
/// **La provenance est la création.** Le remplacement d'un Controller existant
/// a sa propre route (`machine_identity`, `replacement`) et ses propres
/// témoins ; un scope de remplacement qui arriverait ici est refusé plutôt que
/// traité comme une création qui n'ose pas dire son nom.
#[cfg(all(
    not(feature = "delayed-start-contract-test"),
    any(target_os = "linux", target_os = "windows")
))]
fn run_installation(
    live: &mut personal_access::session::LiveSession,
    resolved: &AssistantScopeV1,
    proof: ProvenElevation,
    deadline: Instant,
    guard: &(dyn Fn() -> personal_access::session::GuardVerdict + Sync),
    exported_ledger: &mut Option<Vec<your_cloud_bootstrap_protocol::LedgerItemV1>>,
) -> PromptOutcome {
    use installation::{anchor, bundle, configuration, embedded, plan, sequence, transport};
    use personal_access::{audit, placement};

    let ProvenElevation {
        witness,
        mut secret,
        password_required,
    } = proof;

    if resolved.mode == your_cloud_bootstrap_protocol::BootstrapMode::Replace {
        secret.destroy();
        return PromptOutcome::Unavailable;
    }

    // Les faits, observés par cette session et par personne d'autre. Un canal
    // qui refuse rend des faits inconnus avec leur raison, et c'est la porte
    // du placement qui en tirera le refus nommé.
    let machine = audit::observe(live, deadline, guard);

    // La déclaration et l'approbation, dérivées du scope consenti. La fenêtre
    // vient de montrer la cible, l'action et les empreintes : ce consentement
    // est l'approbation du placement que ce scope déclare.
    let Some((endpoint, approval)) = declared_placement_claim(resolved) else {
        secret.destroy();
        return PromptOutcome::Unavailable;
    };
    let placement = match placement::propose(
        personal_access::audit::Role::Controller,
        &endpoint,
        &machine,
    )
    .and_then(|proposal| placement::approve(&proposal, &approval))
    {
        Ok(placement) => placement,
        Err(_) => {
            secret.destroy();
            return PromptOutcome::Refused;
        }
    };

    // Le lot, depuis la position attestée et l'ancre scellée — la même chaîne
    // que le mode `--verify-embedded-server-bundle`, jusqu'aux mêmes refus.
    let carried =
        match embedded::from_attested_position().and_then(|location| embedded::read(&location)) {
            Ok(carried) => carried,
            Err(_) => {
                secret.destroy();
                return PromptOutcome::Unavailable;
            }
        };
    let verified = match bundle::verify(
        anchor::RELEASE_ANCHOR,
        &carried.manifest,
        &carried.signature,
        EMBEDDED_EXPECTED_VERSION,
        &carried.artifact,
    ) {
        Ok(verified) => verified,
        Err(_) => {
            secret.destroy();
            return PromptOutcome::Refused;
        }
    };

    // La configuration : composée des valeurs que le scope porte, exactement
    // celles dont la fenêtre a montré l'empreinte. La pose la porte toujours —
    // le protocole le tient — et l'activation jamais.
    let composed = match resolved.machine_configuration.as_ref() {
        Some(values) => {
            match configuration::compose(
                &values.listen,
                &values.allowed_source,
                &values.relay_endpoint,
            ) {
                Ok(composed) => Some(composed),
                Err(_) => {
                    secret.destroy();
                    return PromptOutcome::Refused;
                }
            }
        }
        None => None,
    };

    let authorised = match plan::authorize(&verified, &placement, &witness, plan::Origin::Creation)
    {
        Ok(authorised) => authorised,
        Err(_) => {
            secret.destroy();
            return PromptOutcome::Refused;
        }
    };

    let payload = sequence::InstallPayload {
        bundle: &verified,
        artifact: &carried.artifact,
        configuration: composed.as_ref(),
    };
    let mut channel = transport::SessionChannel::new(live, deadline, guard);
    let outcome = sequence::Sequence::new(&mut channel, resolved.actions[0], password_required)
        .run(
            &authorised,
            &payload,
            &mut secret,
            |held: &secret::ProtectedSecret| held.bytes(),
        );
    // Le déroulé est EXPORTÉ dans les deux cas, succès comme arrêt : c'est
    // l'arbitrage du 19 août 2026 — le registre calculé puis abandonné
    // laissait les constats n°6 et n°7 sans surface, et la phrase de la vue
    // renvoyait à un registre que personne ne pouvait lire.
    *exported_ledger = Some(outcome.ledger.to_protocol());

    // Le registre est rendu dans les deux cas ; sa consommation — nommer à
    // l'humain ce qui a été posé et ce qui reste — appartient à la clôture
    // d'affaires de `bootstrap_status`, pas à cette session. Ce qu'elle doit
    // dire ici tient en un terminal : prouvé et joué, ou arrêté.
    match outcome.stopped {
        None => PromptOutcome::Verified(witness),
        // Un juge a refusé, ou un acte s'est plaint : le produit refuse, et la
        // machine reste dans l'état que le registre nomme.
        Some(sequence::SequenceStop::Refused { .. })
        | Some(sequence::SequenceStop::ActFailed { .. }) => PromptOutcome::Refused,
        // Pas de verdict : budget refusé ou canal muet. Rien n'affirme quoi que
        // ce soit de la machine.
        Some(sequence::SequenceStop::BudgetRefused)
        | Some(sequence::SequenceStop::Unanswered { .. }) => PromptOutcome::Unavailable,
    }
}

/// La déclaration d'endpoint et l'approbation que le scope consenti porte.
///
/// Pure, et déclarée hors de la route pour la raison de `#151` : la règle
/// « l'approbation dérive du scope que l'humain a vu, et de rien d'autre »
/// doit être exerçable par une suite sans session ni fenêtre. Le nom déclaré
/// est l'hôte que la fenêtre a montré ; l'exposition et la disponibilité sont
/// les dires que le scope transporte ; rien ici n'est un fait de machine.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn declared_placement_claim(
    scope: &AssistantScopeV1,
) -> Option<(
    personal_access::placement::DeclaredEndpoint,
    personal_access::placement::Approval,
)> {
    use personal_access::audit::Role;
    use personal_access::placement::{Approval, Availability, DeclaredEndpoint, Exposure};

    let declared = scope.declared_target.as_ref()?;
    let endpoint = DeclaredEndpoint {
        name: scope.target.host.clone(),
        port: scope.target.port,
        exposure: if declared.private {
            Exposure::Private
        } else {
            Exposure::Exposed
        },
        availability: if declared.normally_on {
            Availability::NormallyOn
        } else {
            Availability::Intermittent
        },
        // Poser un Controller n'a jamais déclaré de candidat Relay : le champ
        // dit « non déclaré », ce qui est exactement l'état.
        relay_candidate: false,
    };
    let approval = Approval {
        role: Role::Controller,
        endpoint: scope.target.host.clone(),
    };
    Some((endpoint, approval))
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
    exports: &mut SessionExports,
) -> Result<ProvenElevation, PromptOutcome> {
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

    // La portée exigée suit l'action que l'humain a approuvée : auditer ne
    // demande que la sonde, installer exige toute commande.
    let scope = elevation::RequiredScope::for_action(resolved.actions[0]);
    // La politique, et le secret qu'elle a coûté — zéro sur une machine qui se
    // laisse lire, un sur le compte que Debian crée à son installation.
    let (attested, mut retained) = attested_policy(
        live, resolved, deadline, expired, lease, guard, exports, scope,
    )?;

    // Le secret est RETENU plutôt qu'effacé à la commande, et c'est la
    // décision que le contrat d'amorçage porte (amendement du 16 août 2026) :
    // sur la route de l'élévation seule, il meurt sans délai — l'appelant de
    // l'audit le détruit sitôt le témoin rendu ; sur la route d'installation,
    // il vit dans la même allocation protégée le temps de la séquence que
    // l'humain vient d'approuver, et meurt sur *toute* sortie de cette
    // séquence — succès, refus, annulation, expiration — ou à l'échéance de
    // session, le premier des deux. Chaque chemin d'erreur ci-dessous le
    // détruit par la même sortie : `SpentSecret` ne quitte cette fonction que
    // détruit ou remis à l'appelant, jamais oublié.
    //
    // Un compte `root` direct ou une politique sans mot de passe ne retient
    // rien du tout : le cas strict reste le meilleur cas, il cesse simplement
    // d'être le seul.
    let elevated = if attested.password_required {
        // Le secret est déjà là : c'est lui qui a payé le listing. Le
        // redemander serait une seconde fenêtre pour une seule permission.
        match retained.bytes(secret::ProtectedSecret::bytes) {
            // Le mot de passe est une RÉPONSE de terminal : `sudo -S` le lit
            // jusqu'à la fin de ligne, et cette fin de ligne fait partie de la
            // réponse — c'est sa nature, nommée ici où le secret est écrit.
            Some(password) => live.run_channel(
                attested.command,
                Some(personal_access::session::ChannelInput::TerminalAnswer(
                    password,
                )),
                deadline,
                guard,
            ),
            // Impossible par construction : `attested_policy` ne rend un
            // secret détruit qu'avec une politique qui n'en veut pas. La
            // branche existe quand même, et elle détruit — la borne du secret
            // ne dépend d'aucune sortie de portée, sur aucun chemin.
            None => {
                retained.destroy();
                return Err(PromptOutcome::Unavailable);
            }
        }
    } else {
        live.run_channel(attested.command, None, deadline, guard)
    };
    let elevated = match elevated {
        Ok(elevated) => elevated,
        Err(_) => {
            retained.destroy();
            return Err(PromptOutcome::Unavailable);
        }
    };

    match elevation::elevated(elevated.exit_status, &elevated.stdout, &elevated.stderr) {
        Ok(witness) => Ok(ProvenElevation {
            witness,
            secret: retained,
            password_required: attested.password_required,
        }),
        Err(_) => {
            retained.destroy();
            Err(PromptOutcome::Unavailable)
        }
    }
}

/// Établit la politique distante, et rend le secret que cela a coûté.
///
/// Deux chemins, et le second est ce que #218 ajoute.
///
/// Le prévol **non secret** d'abord, toujours : une machine qui se laisse lire
/// est attestée sans qu'aucun secret n'existe, et c'est le meilleur cas. Il ne
/// cesse pas d'être le premier parce qu'un second existe.
///
/// Quand ce prévol répond que **lire coûte le secret** — la réponse du compte
/// que Debian crée à son installation — l'Assistant demande le mot de passe,
/// puis relit la politique avec lui. Le contrat d'amorçage autorise ce pas
/// explicitement, et sa justification de sécurité y est écrite : l'identité de
/// la machine est **déjà** établie par l'empreinte de clé d'hôte relevée hors
/// bande, si bien que ce qui restait inconnu n'était pas *à qui l'on parle*
/// mais *quel privilège possède le compte prêté* — et le secret partait de
/// toute façon vers cette même machine à l'acte suivant.
///
/// **Le secret ne repart pas d'une seconde fenêtre.** Il est rendu à
/// l'appelant, qui le dépense pour l'élévation. Une seconde fenêtre pour une
/// seule permission serait un consentement de plus sans une décision de plus.
///
/// Tout chemin d'erreur détruit ce qu'il détient avant de rendre la main.
#[cfg(all(
    not(feature = "delayed-start-contract-test"),
    any(target_os = "linux", target_os = "windows")
))]
#[allow(clippy::too_many_arguments)]
fn attested_policy(
    live: &mut personal_access::session::LiveSession,
    resolved: &AssistantScopeV1,
    deadline: Instant,
    expired: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    lease: &LeaseState,
    guard: &(dyn Fn() -> personal_access::session::GuardVerdict + Sync),
    exports: &mut SessionExports,
    scope: personal_access::elevation::RequiredScope,
) -> Result<
    (
        personal_access::elevation::AttestedPolicy,
        installation::sequence::SpentSecret<secret::ProtectedSecret>,
    ),
    PromptOutcome,
> {
    use personal_access::elevation::{self, PreflightVerdict};

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

    // L'attestation juge aussi, sur le même listing, ce que l'entrée
    // permettrait à une INSTALLATION — et cette portée est EXPORTÉE, réussite
    // comme refus étroit : c'est elle que la route d'audit rapporte pour qu'un
    // refus de pose ultérieur tombe avant toute fenêtre, et elle que le refus
    // d'une pose sans audit nomme au lieu de se taire (arbitrage du 19 août
    // 2026 — le refus expurgé en Unavailable laissait l'humain deviner, et
    // l'écran disait « n'a pas pu conclure » là où un contrôle avait jugé).
    match elevation::read_policy(succeeded, capture, false, scope) {
        PreflightVerdict::Attested(attested) => {
            exports.installation_scope = Some(attested.installation.clone());
            return Ok((attested, installation::sequence::SpentSecret::none()));
        }
        PreflightVerdict::Refused(refusal) => return Err(policy_refusal(refusal, exports)),
        // Le seul verdict qui continue : la lecture a un prix, et le contrat
        // autorise à le payer dans la séquence déjà consentie.
        PreflightVerdict::CostsTheSecret => {}
    }

    let password = ask_sudo_password(resolved, deadline, expired, lease)?;
    let read = live.run_channel(
        elevation::PREFLIGHT_WITH_PASSWORD,
        Some(personal_access::session::ChannelInput::TerminalAnswer(
            password.bytes(),
        )),
        deadline,
        guard,
    );
    let mut retained = installation::sequence::SpentSecret::holding(password);
    let Ok(read) = read else {
        retained.destroy();
        return Err(PromptOutcome::Unavailable);
    };

    match elevation::attest_policy_after_secret(
        read.exit_status == 0,
        &read.stdout,
        &read.stderr,
        false,
        scope,
    ) {
        Ok(attested) => {
            exports.installation_scope = Some(attested.installation.clone());
            // Une entrée qui renonce à l'authentification alors que la LISTER
            // coûtait un mot de passe est possible — `listpw` et l'entrée sont
            // deux réglages. Le secret devient alors inutile : il meurt ici
            // plutôt qu'à la fin de la séquence. Le cas strict reste le
            // meilleur cas partout où il est atteignable.
            if !attested.password_required {
                retained.destroy();
            }
            Ok((attested, retained))
        }
        Err(refusal) => {
            retained.destroy();
            Err(policy_refusal(refusal, exports))
        }
    }
}

/// La décision rendue sur le verdict de l'attestation de politique — pure,
/// exprès, pour être exerçable sans session ni fenêtre.
///
/// Le refus étroit devient un REFUS qui exporte son nom : l'humain a deux
/// issues à lire — élargir l'entrée à `ALL`, ou prêter un accès `root` direct
/// — et un refus qui se taisait le laissait deviner (mesuré le 19 août 2026 :
/// l'écran disait « n'a pas pu conclure » là où un contrôle avait jugé). Tout
/// autre refus reste une indisponibilité muette, parce qu'aucun autre ne parle
/// d'un choix qui appartient à l'humain. La réussite exporte aussi : c'est la
/// portée que la route d'audit rapporte, celle qui permet à un refus de pose
/// ultérieur de tomber avant toute fenêtre.
#[cfg(all(
    not(feature = "delayed-start-contract-test"),
    any(target_os = "linux", target_os = "windows")
))]
fn policy_refusal(
    refusal: personal_access::elevation::ElevationRefusal,
    exports: &mut SessionExports,
) -> PromptOutcome {
    use personal_access::elevation::{ElevationRefusal, InstallationScope};
    use personal_access::sudo_policy::SudoRefusal;
    use your_cloud_bootstrap_protocol::{AssistantRefusalCauseV1, AssistantRefusalV1};

    // Ce que le protocole accepte de porter, borné ici plutôt qu'espéré : un
    // listing plus long que la borne rendrait la frame invalide, et le refus
    // deviendrait le silence qu'il vient de remplacer.
    fn borne(detail: String) -> String {
        let mut detail: String = detail
            .chars()
            .filter(|caractere| caractere.is_ascii() && !caractere.is_ascii_control())
            .collect();
        detail.truncate(your_cloud_bootstrap_protocol::MAX_ATTESTED_PERMITS_BYTES);
        detail
    }

    let mut named = |cause| {
        exports.refusal = Some(AssistantRefusalV1 {
            cause,
            detail: String::new(),
        });
        PromptOutcome::Refused
    };

    match refusal {
        ElevationRefusal::NarrowerThanTheActionRequires { permits } => {
            exports.installation_scope = Some(InstallationScope {
                suffices: false,
                permits,
            });
            PromptOutcome::Refused
        }
        // Les refus qui JUGENT, et qui s'expurgeaient en « indisponible » : la
        // phrase disait « je n'ai pas pu conclure » là où un contrôle avait
        // décidé, et l'humain n'avait ni la cause ni le geste suivant. Mesuré
        // par le parcours d'un inconnu (#149), corrigé par #157 sur le patron
        // du refus d'entrée trop étroite.
        //
        // Celui-ci dit désormais autre chose qu'en #157 : le secret est
        // **parti**, et la politique refuse toujours de se dire. C'est la fin
        // du parcours, sans troisième tour.
        ElevationRefusal::Policy(SudoRefusal::AuthenticationRequired) => {
            named(AssistantRefusalCauseV1::PolicyUnreadableWithoutSecret)
        }
        // Le voisin qui ne tombe pas avec le premier, et qui doit rester
        // **nommé** : jusqu'au 22 août 2026 il empruntait la cause ci-dessus,
        // les deux partageant une table de marqueurs. Les séparer sans nommer
        // celui-ci l'aurait rendu muet — une régression déguisée en nettoyage.
        // Les deux étages qui le constatent — le listing, puis l'erreur de
        // l'élévation — rendent le même fait, donc la même phrase.
        ElevationRefusal::Policy(SudoRefusal::TerminalRequired)
        | ElevationRefusal::TerminalRequired => named(AssistantRefusalCauseV1::PolicyNeedsTerminal),
        // Le seul refus dont le geste correcteur n'appartient qu'à l'humain et
        // ne touche à aucune configuration : retaper. Il naît avec le chemin
        // devenu nominal — c'est la faute la plus probable d'un compte à mot
        // de passe, et un « indisponible » muet la lui cacherait.
        ElevationRefusal::IncorrectPassword => named(AssistantRefusalCauseV1::SudoPasswordRefused),
        ElevationRefusal::AmbiguousPolicy { entries } => {
            exports.refusal = Some(AssistantRefusalV1 {
                cause: AssistantRefusalCauseV1::PolicyAmbiguous,
                detail: borne(entries),
            });
            PromptOutcome::Refused
        }
        _ => PromptOutcome::Unavailable,
    }
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

    /// **L'approbation du placement dérive du scope que l'humain a vu, et de
    /// rien d'autre.**
    ///
    /// La règle est pure et exerçable sans session ni fenêtre — la raison de
    /// `#151`. Trois choses sont tenues : le nom approuvé est l'hôte montré à
    /// l'écran, les dires du scope passent tels quels sans être promus en
    /// faits, et un scope sans déclaration ne produit aucune revendication —
    /// jamais une revendication par défaut.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn the_placement_claim_derives_from_the_consented_scope_and_nothing_else() {
        use personal_access::audit::Role;
        use personal_access::placement::{Availability, Exposure};
        use your_cloud_bootstrap_protocol::{
            AssistantScopeV1, BootstrapAccessKind, BootstrapAction, BootstrapMode, BootstrapStep,
            BootstrapTarget, DeclaredTarget, NativePromptKind,
        };

        let scope = |declared: Option<DeclaredTarget>| AssistantScopeV1 {
            schema_version: 1,
            request_id: "00112233445566778899aabbccddeeff".into(),
            mode: BootstrapMode::Create,
            target: BootstrapTarget {
                host: "controller.example.test".into(),
                port: 22,
                username: "infra_admin".into(),
                host_key_sha256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                access_kind: BootstrapAccessKind::Administrator,
            },
            step: BootstrapStep::PersonalAccess,
            actions: [BootstrapAction::InstallServerBundle],
            prompt: NativePromptKind::ConfirmPersonalAccess,
            target_addresses: Vec::new(),
            machine_configuration: None,
            declared_target: declared,
            issued_at_monotonic_nanos: 1,
            remaining_millis: 5_000,
        };

        // Le contrôle positif : la déclaration passe telle quelle, le nom et
        // le rôle approuvés sont ceux de l'écran.
        let (endpoint, approval) = declared_placement_claim(&scope(Some(DeclaredTarget {
            private: true,
            normally_on: true,
        })))
        .expect("un scope déclaré produit une revendication");
        assert_eq!(endpoint.name, "controller.example.test");
        assert_eq!(endpoint.port, 22);
        assert_eq!(endpoint.exposure, Exposure::Private);
        assert_eq!(endpoint.availability, Availability::NormallyOn);
        assert!(
            !endpoint.relay_candidate,
            "poser n'a rien déclaré d'un Relay"
        );
        assert_eq!(approval.role, Role::Controller);
        assert_eq!(approval.endpoint, "controller.example.test");

        // Les dires hostiles passent AUSSI tels quels : c'est la porte du
        // placement qui refusera un Controller sur un endpoint exposé ou
        // intermittent, et adoucir la déclaration ici la lui cacherait.
        let (endpoint, _) = declared_placement_claim(&scope(Some(DeclaredTarget {
            private: false,
            normally_on: false,
        })))
        .expect("une déclaration hostile est transportée, pas corrigée");
        assert_eq!(endpoint.exposure, Exposure::Exposed);
        assert_eq!(endpoint.availability, Availability::Intermittent);

        // Aucune déclaration, aucune revendication — jamais un défaut.
        assert!(declared_placement_claim(&scope(None)).is_none());
    }

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

    /// Le refus étroit est un REFUS qui exporte son nom, et chaque verdict de
    /// politique exporte la portée — jamais l'expurgation muette d'avant.
    ///
    /// C'est la garde du remplacement de `.map_err(|_| Unavailable)` : une
    /// mutation qui remettrait « tout refus vaut Unavailable » rougit ici, en
    /// CI, plutôt qu'à la seule passe LAB. Les autres refus restent muets —
    /// aucun ne parle d'un choix qui appartient à l'humain.
    #[cfg(all(
        not(feature = "delayed-start-contract-test"),
        any(target_os = "linux", target_os = "windows")
    ))]
    #[test]
    fn every_refusal_that_judged_is_named_under_its_own_cause() {
        use personal_access::elevation::{ElevationRefusal, InstallationScope};

        use personal_access::sudo_policy::SudoRefusal;
        use your_cloud_bootstrap_protocol::AssistantRefusalCauseV1 as Cause;

        // La portée qu'une réussite exporte est jugée par `read_policy`, dont
        // le succès porte l'attestation ; ici on n'exerce que les refus.
        let judged = InstallationScope {
            suffices: false,
            permits: "/usr/bin/id".into(),
        };

        // Le refus étroit : REFUSÉ, et la portée exportée nomme ce que
        // l'entrée permet.
        let mut exports = SessionExports::default();
        let refused = policy_refusal(
            ElevationRefusal::NarrowerThanTheActionRequires {
                permits: "/usr/bin/id".into(),
            },
            &mut exports,
        );
        assert!(matches!(refused, PromptOutcome::Refused));
        assert_eq!(exports.installation_scope, Some(judged));

        // **Les quatre refus qui JUGENT, chacun sous SON nom.** Ce tableau est
        // la garde du « voisin » : `TerminalRequired` et `AuthenticationRequired`
        // partageaient une cause jusqu'au 22 août 2026, et une mutation qui les
        // recollerait — ou qui replierait l'un d'eux sur `Unavailable` — rougit
        // ici plutôt qu'à la passe LAB.
        for (refusal, expected) in [
            (
                ElevationRefusal::Policy(SudoRefusal::AuthenticationRequired),
                Cause::PolicyUnreadableWithoutSecret,
            ),
            (
                ElevationRefusal::Policy(SudoRefusal::TerminalRequired),
                Cause::PolicyNeedsTerminal,
            ),
            (
                // Le même fait, constaté à l'étage de l'élévation : même
                // phrase, parce que c'est la même machine qui le dit.
                ElevationRefusal::TerminalRequired,
                Cause::PolicyNeedsTerminal,
            ),
            (
                ElevationRefusal::IncorrectPassword,
                Cause::SudoPasswordRefused,
            ),
        ] {
            let mut exports = SessionExports::default();
            let outcome = policy_refusal(refusal.clone(), &mut exports);
            assert!(
                matches!(outcome, PromptOutcome::Refused),
                "{refusal:?} a jugé : il refuse, il ne renonce pas"
            );
            assert_eq!(
                exports.refusal,
                Some(your_cloud_bootstrap_protocol::AssistantRefusalV1 {
                    cause: expected,
                    detail: String::new(),
                }),
                "{refusal:?} doit nommer sa propre cause"
            );
        }

        let mut exports = SessionExports::default();
        let ambiguous = policy_refusal(
            ElevationRefusal::AmbiguousPolicy {
                entries: "Sudoers entry: /etc/sudoers ; Sudoers entry: /etc/sudoers.d/90-x".into(),
            },
            &mut exports,
        );
        assert!(matches!(ambiguous, PromptOutcome::Refused));
        let carried = exports.refusal.expect("la cause voyage");
        assert_eq!(carried.cause, Cause::PolicyAmbiguous);
        assert!(carried.detail.contains("/etc/sudoers.d/90-x"));

        // Un refus qui n'a pas jugé — le listing illisible pour une autre
        // raison — reste une indisponibilité muette : il ne parle pas du choix
        // de l'humain.
        let mut exports = SessionExports::default();
        let mute = policy_refusal(ElevationRefusal::DivergentCommand, &mut exports);
        assert!(matches!(mute, PromptOutcome::Unavailable));
        assert!(exports.refusal.is_none());
        assert_eq!(exports.installation_scope, None);
    }

    /// **Le prix d'une lecture n'est pas un refus, et le voisin reste un
    /// refus.** Les trois issues du prévol non secret, exercées sur les octets
    /// que `sudo 1.9.16p2` écrit réellement (mesurés sur `lab-machine-1` le
    /// 22 août 2026).
    ///
    /// C'est le cœur de #218 : la première ligne était une fin de parcours, et
    /// elle rendait inatteignable le compte que Debian crée à son
    /// installation. La deuxième ne bouge pas — aucun secret ne fabrique un
    /// terminal — et c'est elle qui échouerait si le refus voisin tombait avec
    /// le premier.
    #[cfg(all(
        not(feature = "delayed-start-contract-test"),
        any(target_os = "linux", target_os = "windows")
    ))]
    #[test]
    fn the_price_of_a_reading_is_not_a_refusal_and_the_neighbour_stays_one() {
        use personal_access::elevation::{
            read_policy, ElevationRefusal, PreflightVerdict, RequiredScope,
        };
        use personal_access::sudo_policy::SudoRefusal;

        let verdict =
            |answer: &[u8]| read_policy(false, answer, false, RequiredScope::IdentityProbe);

        assert!(
            matches!(
                verdict(b"sudo: a password is required\n"),
                PreflightVerdict::CostsTheSecret
            ),
            "la posture Debian par défaut n'est plus une fin de parcours"
        );
        for terminal in [
            &b"sudo: sorry, you must have a tty to run sudo\n"[..],
            b"sudo: no tty present and no askpass program specified\n",
        ] {
            assert!(
                matches!(
                    verdict(terminal),
                    PreflightVerdict::Refused(ElevationRefusal::Policy(
                        SudoRefusal::TerminalRequired
                    ))
                ),
                "{:?} reste un refus — aucun secret ne fabrique un terminal",
                String::from_utf8_lossy(terminal)
            );
        }
        assert!(
            matches!(
                verdict(b"quelque chose que personne ne reconnait\n"),
                PreflightVerdict::Refused(ElevationRefusal::Policy(SudoRefusal::Unattestable))
            ),
            "un listing non reconnu reste illisible"
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
            installation_scope: None,
            install_ledger: None,
            refusal: None,
        };
        let payload = serde_json::to_vec(&event).expect("expurgated event");
        assert!(!payload
            .windows(b"synthetic-canary".len())
            .any(|window| window == b"synthetic-canary"));
    }

    /// La garde de la tranche registre côté frame : le déroulé exporté part
    /// avec les DEUX terminaux d'une session qui a jugé — le refus surtout,
    /// c'est lui qui doit dire ce qui restait — et avec aucun autre. Un
    /// terminal qui n'a pas jugé écrit une frame sans déroulé, et la même
    /// fonction refuserait de l'affirmer.
    #[test]
    fn the_terminal_frame_carries_the_deroule_exactly_when_the_session_judged() {
        use your_cloud_bootstrap_protocol::{
            AssistantScopeV1, BootstrapAccessKind, BootstrapAction, BootstrapMode, BootstrapStep,
            BootstrapTarget, LedgerItemKind, LedgerItemV1, LedgerProvenance, NativePromptKind,
        };

        let scope = AssistantScopeV1 {
            schema_version: 1,
            request_id: "00112233445566778899aabbccddeeff".into(),
            mode: BootstrapMode::Create,
            target: BootstrapTarget {
                host: "controller.example.test".into(),
                port: 22,
                username: "infra_admin".into(),
                host_key_sha256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                access_kind: BootstrapAccessKind::Administrator,
            },
            step: BootstrapStep::PersonalAccess,
            actions: [BootstrapAction::InstallServerBundle],
            prompt: NativePromptKind::ConfirmPersonalAccess,
            target_addresses: Vec::new(),
            machine_configuration: None,
            declared_target: None,
            issued_at_monotonic_nanos: 1,
            remaining_millis: 5_000,
        };
        let deroule = || SessionExports {
            installation_scope: None,
            install_ledger: Some(vec![LedgerItemV1 {
                kind: LedgerItemKind::Package,
                name: "your-cloud-server".into(),
                provenance: LedgerProvenance::Created,
            }]),
            refusal: None,
        };
        let written = |terminal: SessionTerminal| {
            let mut output = Vec::new();
            write_terminal(&mut output, &scope, terminal, deroule())
                .expect("un terminal licite s'écrit");
            serde_json::from_slice::<AssistantEventV1>(&output[4..])
                .expect("la frame écrite se relit")
        };

        // Les deux porteurs : le déroulé voyage tel quel.
        for terminal in [SessionTerminal::AccessVerified, SessionTerminal::Refused] {
            let event = written(terminal);
            let carried = event.install_ledger.expect("le déroulé exporté voyage");
            assert_eq!(carried.len(), 1);
            assert_eq!(carried[0].name, "your-cloud-server");
        }

        // Tout autre terminal le laisse tomber plutôt que d'affirmer.
        for terminal in [
            SessionTerminal::Cancelled,
            SessionTerminal::Expired,
            SessionTerminal::Unavailable,
        ] {
            assert!(written(terminal).install_ledger.is_none());
        }
    }
}
