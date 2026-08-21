use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitStatus,
    sync::mpsc::{self, Receiver, Sender, TryRecvError},
    thread,
    time::{Duration, Instant},
};

#[cfg(not(target_os = "windows"))]
use std::process::{Child, ChildStdout, Command, Stdio};

#[cfg(all(not(target_os = "windows"), not(target_os = "linux")))]
use std::process::ChildStdin;

#[cfg(target_os = "linux")]
use std::os::unix::{
    io::{AsRawFd, OwnedFd},
    net::UnixStream,
    process::CommandExt,
};

// The exit codes are deliberately not imported one by one any more: the pair an
// event may be read beside is `AssistantEventKind::terminal_exit_code`, and
// naming the constants here again would be a second table to keep in step.
use your_cloud_bootstrap_protocol::{
    monotonic_nanos, ApprovalConsentOutcomeV1, ApprovalConsentV1, AssistantEventKind,
    AssistantEventV1, AssistantRefusalV1, AssistantScopeV1, AttestedInstallationScopeV1,
    LedgerItemV1, MAX_APPROVAL_CONSENT_FRAME_BYTES, MAX_APPROVAL_CONSENT_OUTCOME_FRAME_BYTES,
    MAX_ASSISTANT_EVENT_FRAME_BYTES, MAX_ASSISTANT_SCOPE_FRAME_BYTES,
};

// The launch-time environment allowlist is decided per prompt, so the kind of
// window about to open is part of what the spawn path reads. Windows builds
// their command line elsewhere and never consult it.
#[cfg(not(target_os = "windows"))]
use your_cloud_bootstrap_protocol::NativePromptKind;

#[cfg(target_os = "windows")]
#[path = "native_helper/windows.rs"]
mod windows;

#[cfg(target_os = "windows")]
use windows::{WindowsChild as NativeChild, WindowsChildStdout as NativeChildStdout};

#[cfg(not(target_os = "windows"))]
type NativeChild = Child;
#[cfg(target_os = "linux")]
type NativeChildStdin = UnixStream;
#[cfg(all(not(target_os = "windows"), not(target_os = "linux")))]
type NativeChildStdin = ChildStdin;
#[cfg(not(target_os = "windows"))]
type NativeChildStdout = ChildStdout;
#[cfg(target_os = "windows")]
type NativeChildStdin = std::fs::File;

const NATIVE_ASSISTANT_BINARY: &str = "your-cloud-native-bootstrap-assistant";
const REQUIRED_MODE_ARGUMENT: &str = "--native-bootstrap-assistant";
const REQUIRED_APPROVAL_MODE_ARGUMENT: &str = "--native-approval-consent";
const FRAME_HEADER_BYTES: usize = 4;
const STOP_GRACE: Duration = Duration::from_millis(500);
const KILL_REAP_GRACE: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeHelperError {
    Busy,
    Expired,
    RequestRefused,
    Unavailable,
}

impl NativeHelperError {
    pub(crate) fn public_code(self) -> &'static str {
        match self {
            Self::Busy => "bootstrap_busy",
            Self::Expired => "bootstrap_expired",
            Self::RequestRefused => "bootstrap_request_refused",
            Self::Unavailable => "native_assistant_unavailable",
        }
    }
}

/// The two invocations this product may spawn a native helper for, and the only
/// two.
///
/// It is an enumeration rather than a pair of free arguments — a mode string
/// beside a frame — because a mode and a document that could be named
/// separately could be crossed: a consent written on the bootstrap frame, or a
/// scope handed to the approval window. **Each variant carries the one document
/// its own mode reads**, so the crossing is not refused at runtime, it cannot
/// be spelled. A third invocation cannot be added by passing a different
/// string; it would have to be a third variant, and every `match` below would
/// stop compiling until it was answered.
pub(crate) enum HelperInvocation {
    /// The bootstrap window: one public scope in, one terminal event out.
    Bootstrap(AssistantScopeV1),
    /// The approval consent window: one consent in, one closed outcome out.
    ApprovalConsent(ApprovalConsentV1),
}

/// Which of the two a running session is, kept beside it so the frame read back
/// is the one that invocation writes and never the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HelperKind {
    Bootstrap,
    ApprovalConsent,
}

impl HelperInvocation {
    fn kind(&self) -> HelperKind {
        match self {
            Self::Bootstrap(_) => HelperKind::Bootstrap,
            Self::ApprovalConsent(_) => HelperKind::ApprovalConsent,
        }
    }

    /// The one argument this invocation is spawned with. The helper holds each
    /// mode to exactly one argument and refuses everything else, so these two
    /// strings and the two the helper reads are the same two facts written on
    /// both sides of one boundary.
    fn mode_argument(&self) -> &'static str {
        match self {
            Self::Bootstrap(_) => REQUIRED_MODE_ARGUMENT,
            Self::ApprovalConsent(_) => REQUIRED_APPROVAL_MODE_ARGUMENT,
        }
    }

    /// Whether this invocation is the one step that cannot work without the
    /// user's personal signing agent.
    ///
    /// An agent is a signing oracle, and the allowlist stays a per-step grant
    /// rather than an environment every helper inherits. The approval window
    /// has no `NativePromptKind` at all: it is not that it declines the grant,
    /// it is that there is no value it could carry that would ask for one.
    #[cfg(target_os = "linux")]
    fn agent_endpoint_prompt(&self) -> Option<NativePromptKind> {
        match self {
            Self::Bootstrap(scope) => Some(scope.prompt),
            Self::ApprovalConsent(_) => None,
        }
    }

    /// Refuses a launch before any process exists.
    ///
    /// It stamps a copy of the document and validates it: a lease already spent,
    /// or a document that no longer fits its own grammar once stamped, is
    /// refused here rather than spawned and then killed. Spawning first would
    /// mean a process created for an authority that was already gone, and the
    /// bounded termination that followed would be cleaning up after a decision
    /// this side could have taken without it.
    fn preflight(&self, expires_at: Instant, now: Instant) -> Result<(), NativeHelperError> {
        let issued_at = monotonic_nanos().map_err(|_| NativeHelperError::Unavailable)?;
        let remaining = remaining_millis(expires_at, now)?;
        match self {
            Self::Bootstrap(scope) => {
                let mut scope = scope.clone();
                scope.issued_at_monotonic_nanos = issued_at;
                scope.remaining_millis = remaining;
                scope
                    .validate()
                    .map_err(|_| NativeHelperError::RequestRefused)?;
            }
            Self::ApprovalConsent(consent) => {
                let mut consent = consent.clone();
                consent.issued_at_monotonic_nanos = issued_at;
                consent.remaining_millis = remaining;
                consent
                    .validate()
                    .map_err(|_| NativeHelperError::RequestRefused)?;
            }
        }
        Ok(())
    }

    /// Stamps the shared clock onto the document and renders the one frame this
    /// invocation writes.
    ///
    /// The stamp is taken here, once, for both variants: the OS observation is
    /// sampled before the local instant so any time between the two is deducted
    /// rather than silently renewing the lease, and the document is validated
    /// after being stamped so a lease that no longer fits its own grammar is
    /// refused rather than sent.
    fn stamp_and_encode(
        self,
        expires_at: Instant,
        now: Instant,
    ) -> Result<(String, Vec<u8>), NativeHelperError> {
        let issued_at = monotonic_nanos().map_err(|_| NativeHelperError::Unavailable)?;
        let remaining = remaining_millis(expires_at, now)?;
        match self {
            Self::Bootstrap(mut scope) => {
                scope.issued_at_monotonic_nanos = issued_at;
                scope.remaining_millis = remaining;
                let scope = scope
                    .validate()
                    .map_err(|_| NativeHelperError::RequestRefused)?;
                let encoded =
                    serde_json::to_vec(&scope).map_err(|_| NativeHelperError::RequestRefused)?;
                let frame = encode_frame(encoded, MAX_ASSISTANT_SCOPE_FRAME_BYTES)?;
                Ok((scope.request_id, frame))
            }
            Self::ApprovalConsent(mut consent) => {
                consent.issued_at_monotonic_nanos = issued_at;
                consent.remaining_millis = remaining;
                let consent = consent
                    .validate()
                    .map_err(|_| NativeHelperError::RequestRefused)?;
                let encoded =
                    serde_json::to_vec(&consent).map_err(|_| NativeHelperError::RequestRefused)?;
                let frame = encode_frame(encoded, MAX_APPROVAL_CONSENT_FRAME_BYTES)?;
                Ok((consent.request_id, frame))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NativeHelperPoll {
    Running,
    /// The helper proved the elevation of its session and said so on the one
    /// frame it ever writes. Reaching this verdict means three things held at
    /// once: the event was `access_verified`, the process exited with the code
    /// the protocol's own table pairs it with, and nothing of the helper's
    /// process group was left behind.
    ///
    /// La portée d'installation attestée voyage avec le verdict quand la
    /// route l'a jugée — c'est l'export de l'audit, celui qui permet à un
    /// refus de pose ultérieur de tomber avant toute session.
    AccessVerified {
        installation_scope: Option<AttestedInstallationScopeV1>,
        /// Le déroulé du registre, quand une séquence a couru — pose ou
        /// activation. Le poll rapporte, la clôture d'affaires le retient.
        install_ledger: Option<Vec<LedgerItemV1>>,
    },
    /// L'Assistant a écrit `refused` et s'est terminé sous le code que la
    /// table du protocole apparie. C'est un verdict du produit ou de l'humain,
    /// pas une demande malformée : le distinguer de `RequestRefused` est ce
    /// qui permet à la vue d'en faire une phrase plutôt qu'un code générique.
    /// Quand le refus est celui de l'entrée trop étroite, la portée attestée
    /// voyage avec lui et NOMME ce que l'entrée permet.
    Refused {
        installation_scope: Option<AttestedInstallationScopeV1>,
        /// Le déroulé au moment du refus : ce qui était posé quand il est
        /// tombé — la moitié du constat qui dit qu'un état partiel se NOMME.
        install_ledger: Option<Vec<LedgerItemV1>>,
        /// La cause, quand un contrôle a jugé : politique illisible sans son
        /// secret, ou politique ambiguë. C'est ce qui rend la phrase précise
        /// là où « n'a pas pu conclure » ne nommait rien (#157).
        refusal: Option<AssistantRefusalV1>,
    },
    Cancelled,
    Unavailable,
    /// The approval window answered. The outcome is carried whole rather than
    /// summarised: what the human decided, and the two digests a confirmation
    /// names, belong to the caller that will hold them against the pair it
    /// built. This poll reports; it never interprets.
    ApprovalDecided(Box<ApprovalConsentOutcomeV1>),
}

struct NativeHelperSession {
    kind: HelperKind,
    request_id: String,
    child: NativeChild,
    stdin: Option<NativeChildStdin>,
    stdout: NativeChildStdout,
    deadline: Instant,
}

#[derive(Clone, Copy)]
enum CleanupOutcome {
    Reaped,
    Unproven,
}

struct CleanupWorker {
    submit: Sender<NativeChild>,
    outcomes: Receiver<CleanupOutcome>,
    handle: thread::JoinHandle<()>,
}

impl CleanupWorker {
    fn spawn() -> Option<Self> {
        let (submit, tasks) = mpsc::channel::<NativeChild>();
        let (results, outcomes) = mpsc::channel::<CleanupOutcome>();
        let handle = thread::Builder::new()
            .name("native-assistant-reaper".into())
            .spawn(move || {
                while let Ok(child) = tasks.recv() {
                    if results.send(reap_until_terminal(child)).is_err() {
                        return;
                    }
                }
            })
            .ok()?;
        Some(Self {
            submit,
            outcomes,
            handle,
        })
    }
}

pub(crate) struct NativeHelperSupervisor {
    active: Option<NativeHelperSession>,
    cleanup_worker: Option<CleanupWorker>,
    cleanup_pending: bool,
    cleanup_unproven: bool,
    stranded_cleanup: Option<NativeChild>,
}

impl Default for NativeHelperSupervisor {
    fn default() -> Self {
        Self {
            active: None,
            cleanup_worker: CleanupWorker::spawn(),
            cleanup_pending: false,
            cleanup_unproven: false,
            stranded_cleanup: None,
        }
    }
}

impl NativeHelperSupervisor {
    pub(crate) fn start(
        &mut self,
        invocation: HelperInvocation,
        expires_at: Instant,
    ) -> Result<(), NativeHelperError> {
        let (path, expected_name) = installed_helper_binary()?;
        self.start_with_policy(&path, &expected_name, invocation, expires_at, true)
    }

    #[cfg(test)]
    #[allow(dead_code)] // Used by the helper's cross-crate parent contract.
    pub(crate) fn start_with_path(
        &mut self,
        path: &Path,
        expected_name: &OsStr,
        invocation: HelperInvocation,
        expires_at: Instant,
    ) -> Result<(), NativeHelperError> {
        self.start_with_policy(path, expected_name, invocation, expires_at, false)
    }

    fn start_with_policy(
        &mut self,
        path: &Path,
        expected_name: &OsStr,
        invocation: HelperInvocation,
        expires_at: Instant,
        enforce_installed_policy: bool,
    ) -> Result<(), NativeHelperError> {
        self.reconcile_pending_cleanup();
        if self.cleanup_unproven || self.cleanup_worker.is_none() || self.stranded_cleanup.is_some()
        {
            return Err(NativeHelperError::Unavailable);
        }
        if self.active.is_some() || self.cleanup_pending {
            return Err(NativeHelperError::Busy);
        }
        validate_executable(path, expected_name, enforce_installed_policy)?;
        // Refuse before a process exists. The frame written after the spawn is
        // stamped again from the same origin, which can shorten this lease and
        // can never renew it.
        invocation.preflight(expires_at, Instant::now())?;
        let kind = invocation.kind();
        let mode_argument = invocation.mode_argument();
        #[cfg(target_os = "linux")]
        let agent_prompt = invocation.agent_endpoint_prompt();

        let working_directory = path.parent().ok_or(NativeHelperError::Unavailable)?;
        #[cfg(target_os = "linux")]
        let (child_input, parent_input) =
            UnixStream::pair().map_err(|_| NativeHelperError::Unavailable)?;
        #[cfg(target_os = "linux")]
        let mut parent_input = Some(parent_input);
        #[cfg(not(target_os = "windows"))]
        let mut child = {
            let mut command = Command::new(path);
            command
                .arg(mode_argument)
                .current_dir(working_directory)
                .env_clear()
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            #[cfg(target_os = "linux")]
            command.stdin(Stdio::from(OwnedFd::from(child_input)));
            #[cfg(not(target_os = "linux"))]
            command.stdin(Stdio::piped());
            configure_public_gui_environment(&mut command, agent_prompt);
            #[cfg(target_os = "linux")]
            command.process_group(0);
            command
                .spawn()
                .map_err(|_| NativeHelperError::Unavailable)?
        };
        #[cfg(target_os = "windows")]
        let mut child = windows::spawn_helper_process(path, working_directory, mode_argument)?;

        let launch = (|| {
            // Recalculate from the native absolute deadline only after the child exists. Time
            // spent validating and spawning can shorten this lease but can never renew it. The
            // OS stamp is deliberately sampled first so the transmitted pair is conservative.
            // The invocation stamps and renders its own frame: the mode above and the document
            // here came from one value, so they cannot describe two different things.
            let (request_id, frame) = invocation.stamp_and_encode(expires_at, Instant::now())?;
            #[cfg(target_os = "linux")]
            let mut stdin = parent_input.take().ok_or(NativeHelperError::Unavailable)?;
            #[cfg(not(target_os = "linux"))]
            let mut stdin = take_child_stdin(&mut child).ok_or(NativeHelperError::Unavailable)?;
            stdin
                .write_all(&frame)
                .map_err(|_| NativeHelperError::Unavailable)?;
            stdin.flush().map_err(|_| NativeHelperError::Unavailable)?;
            let stdout = take_child_stdout(&mut child).ok_or(NativeHelperError::Unavailable)?;
            configure_nonblocking_stdout(&stdout)?;
            Ok((request_id, stdin, stdout))
        })();

        let (request_id, stdin, stdout) = match launch {
            Ok(launch) => launch,
            Err(error) => {
                if terminate_running_and_reap_bounded(&mut child).is_err() {
                    self.defer_cleanup(child);
                }
                return Err(error);
            }
        };
        self.active = Some(NativeHelperSession {
            kind,
            request_id,
            child,
            stdin: Some(stdin),
            stdout,
            deadline: expires_at,
        });
        Ok(())
    }

    pub(crate) fn poll(&mut self, request_id: &str) -> Result<NativeHelperPoll, NativeHelperError> {
        let active = self
            .active
            .as_mut()
            .ok_or(NativeHelperError::RequestRefused)?;
        if active.request_id != request_id {
            return Err(NativeHelperError::RequestRefused);
        }
        if Instant::now() >= active.deadline {
            let mut expired = self.active.take().expect("active assistant checked above");
            expired.stdin.take();
            if stop_bounded(&mut expired.child).is_err() {
                self.defer_cleanup(expired.child);
                return Err(NativeHelperError::Unavailable);
            }
            return Err(NativeHelperError::Expired);
        }
        let status = match child_try_wait(&mut active.child) {
            Ok(status) => status,
            Err(_) => {
                let mut failed = self.active.take().expect("active assistant checked above");
                failed.stdin.take();
                if terminate_running_and_reap_bounded(&mut failed.child).is_err() {
                    self.defer_cleanup(failed.child);
                }
                return Err(NativeHelperError::Unavailable);
            }
        };
        let Some(status) = status else {
            return Ok(NativeHelperPoll::Running);
        };
        let mut completed = self.active.take().expect("active assistant checked above");
        complete_session(&mut completed, status)
    }

    pub(crate) fn cancel(&mut self, request_id: &str) -> Result<(), NativeHelperError> {
        let active = self
            .active
            .as_ref()
            .ok_or(NativeHelperError::RequestRefused)?;
        if active.request_id != request_id {
            return Err(NativeHelperError::RequestRefused);
        }
        self.stop_active()
    }

    pub(crate) fn stop_active(&mut self) -> Result<(), NativeHelperError> {
        self.reconcile_pending_cleanup();
        if self.cleanup_pending || self.cleanup_unproven || self.stranded_cleanup.is_some() {
            return Err(NativeHelperError::Unavailable);
        }
        if let Some(mut active) = self.active.take() {
            // EOF is the normal cancellation path. The bounded process-tree termination below
            // remains a fallback when the native event loop cannot clean up cooperatively.
            active.stdin.take();
            if stop_bounded(&mut active.child).is_err() {
                self.defer_cleanup(active.child);
                return Err(NativeHelperError::Unavailable);
            }
        }
        Ok(())
    }

    fn defer_cleanup(&mut self, child: NativeChild) {
        debug_assert!(!self.cleanup_pending);
        let Some(worker) = self.cleanup_worker.as_ref() else {
            self.stranded_cleanup = Some(child);
            self.cleanup_unproven = true;
            return;
        };
        match worker.submit.send(child) {
            Ok(()) => self.cleanup_pending = true,
            Err(error) => {
                self.stranded_cleanup = Some(error.0);
                self.cleanup_unproven = true;
                self.cleanup_worker = None;
            }
        }
    }

    fn reconcile_pending_cleanup(&mut self) {
        let Some(worker) = self.cleanup_worker.as_ref() else {
            return;
        };
        if self.cleanup_pending {
            match worker.outcomes.try_recv() {
                Ok(CleanupOutcome::Reaped) => self.cleanup_pending = false,
                Ok(CleanupOutcome::Unproven) => {
                    self.cleanup_pending = false;
                    self.cleanup_unproven = true;
                }
                Err(TryRecvError::Empty) if worker.handle.is_finished() => {
                    self.cleanup_pending = false;
                    self.cleanup_unproven = true;
                    self.cleanup_worker = None;
                }
                Err(TryRecvError::Disconnected) => {
                    self.cleanup_pending = false;
                    self.cleanup_unproven = true;
                    self.cleanup_worker = None;
                }
                Err(TryRecvError::Empty) => {}
            }
        } else if worker.handle.is_finished() {
            self.cleanup_unproven = true;
            self.cleanup_worker = None;
        }
    }
}

fn remaining_millis(deadline: Instant, now: Instant) -> Result<u64, NativeHelperError> {
    let remaining = deadline
        .checked_duration_since(now)
        .ok_or(NativeHelperError::Expired)?;
    let millis =
        u64::try_from(remaining.as_millis()).map_err(|_| NativeHelperError::RequestRefused)?;
    if millis == 0 {
        return Err(NativeHelperError::Expired);
    }
    Ok(millis)
}

#[cfg(not(target_os = "windows"))]
fn configure_public_gui_environment(command: &mut Command, prompt: Option<NativePromptKind>) {
    for name in [
        "DISPLAY",
        "XAUTHORITY",
        "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    ] {
        if let Some(value) = env::var_os(name).filter(|value| !value.is_empty()) {
            command.env(name, value);
        }
    }
    command.env("NO_AT_BRIDGE", "1");
    configure_personal_agent_endpoint(command, prompt);
}

/// Hands the helper the endpoint of the user's personal SSH agent, and only
/// where that endpoint is the one thing the step cannot do without.
///
/// An agent is a signing oracle. A window that asks for a `sudo` password, a
/// key passphrase or a `root` confirmation never needs one, so it never
/// receives one: the allowlist stays a per-step grant rather than a single
/// environment every helper inherits. Only the personal access step reads it,
/// and it reads exactly this name once.
///
/// The App deliberately does not judge the value beyond "present and not
/// empty". Everything that decides whether the endpoint is *admissible* — an
/// absolute, bounded, NUL-free path naming a real socket this user owns,
/// inside a directory nobody else can rearrange — belongs to the helper's
/// `personal_access::agent_endpoint`, because only the helper observes the
/// filesystem it will then connect to. A check performed here would be a check
/// performed against a different moment and, being neither authoritative nor
/// re-verified, would invite trusting it. The one thing this side owes the
/// helper is that no *other* variable can name an endpoint, which `env_clear`
/// above already guarantees.
#[cfg(target_os = "linux")]
fn configure_personal_agent_endpoint(command: &mut Command, prompt: Option<NativePromptKind>) {
    // `None` is the approval consent invocation, which carries no prompt kind
    // at all: it does not decline the grant, there is no value it could hold
    // that would ask for one.
    if prompt != Some(NativePromptKind::ConfirmPersonalAccess) {
        return;
    }
    const PERSONAL_AGENT_ENDPOINT: &str = "SSH_AUTH_SOCK";
    if let Some(value) = env::var_os(PERSONAL_AGENT_ENDPOINT).filter(|value| !value.is_empty()) {
        command.env(PERSONAL_AGENT_ENDPOINT, value);
    }
}

/// No other Unix target reads an agent endpoint: the helper's observation is
/// Linux-only and no other target can even locate an installed helper.
#[cfg(all(not(target_os = "windows"), not(target_os = "linux")))]
fn configure_personal_agent_endpoint(_command: &mut Command, _prompt: Option<NativePromptKind>) {}

#[cfg(all(not(target_os = "windows"), not(target_os = "linux")))]
fn take_child_stdin(child: &mut NativeChild) -> Option<std::process::ChildStdin> {
    child.stdin.take()
}

#[cfg(target_os = "windows")]
fn take_child_stdin(child: &mut NativeChild) -> Option<std::fs::File> {
    child.take_stdin()
}

#[cfg(not(target_os = "windows"))]
fn take_child_stdout(child: &mut NativeChild) -> Option<NativeChildStdout> {
    child.stdout.take()
}

#[cfg(target_os = "windows")]
fn take_child_stdout(child: &mut NativeChild) -> Option<NativeChildStdout> {
    child.take_stdout()
}

#[cfg(not(target_os = "windows"))]
fn child_try_wait(child: &mut NativeChild) -> io::Result<Option<ExitStatus>> {
    child.try_wait()
}

#[cfg(target_os = "windows")]
fn child_try_wait(child: &mut NativeChild) -> io::Result<Option<ExitStatus>> {
    child.try_wait()
}

#[cfg(target_os = "linux")]
fn configure_nonblocking_stdout(stdout: &ChildStdout) -> Result<(), NativeHelperError> {
    let descriptor = stdout.as_raw_fd();
    // SAFETY: fcntl only reads and updates the flags of the owned pipe descriptor.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 {
        return Err(NativeHelperError::Unavailable);
    }
    // SAFETY: descriptor remains owned by stdout for the whole call.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(NativeHelperError::Unavailable);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn configure_nonblocking_stdout(_stdout: &NativeChildStdout) -> Result<(), NativeHelperError> {
    Ok(())
}

impl Drop for NativeHelperSupervisor {
    fn drop(&mut self) {
        let _ = self.stop_active();
    }
}

/// Wraps one already-encoded document in the one frame it travels in, against
/// **its own** bound rather than a shared one: the two documents of this
/// boundary are bounded by what their own fields can reach, and widening one
/// would loosen a bound on a document that never needs the room.
///
/// It takes bytes rather than a serialisable value on purpose. This file is
/// also compiled inside the helper crate's own integration tests, whose graph
/// holds `serde_json` and not `serde`; naming the trait here would make this
/// module build in one crate and not in the other, which is exactly the kind of
/// divergence the Windows suites exist to catch — and did.
fn encode_frame(payload: Vec<u8>, maximum: usize) -> Result<Vec<u8>, NativeHelperError> {
    if payload.is_empty() || payload.len() > maximum {
        return Err(NativeHelperError::RequestRefused);
    }
    let length = u32::try_from(payload.len()).map_err(|_| NativeHelperError::RequestRefused)?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn complete_session(
    session: &mut NativeHelperSession,
    status: ExitStatus,
) -> Result<NativeHelperPoll, NativeHelperError> {
    match session.kind {
        HelperKind::Bootstrap => complete_bootstrap_session(session, status),
        HelperKind::ApprovalConsent => complete_approval_session(session, status),
    }
}

/// The approval window's conclusion: one outcome, correlated with the request
/// it answers and paired with the exit code its own table names.
///
/// Nothing here reads what the human decided. A refusal, a confirmation, an
/// expiry and an unavailability are all *answers*, and telling them apart is
/// the business of the caller that holds the pair — this side only establishes
/// that the answer belongs to this session and that the process agreed with it.
fn complete_approval_session(
    session: &mut NativeHelperSession,
    status: ExitStatus,
) -> Result<NativeHelperPoll, NativeHelperError> {
    let outcome = read_approval_outcome(&mut session.stdout)?;
    if outcome.request_id != session.request_id {
        return Err(NativeHelperError::RequestRefused);
    }
    if status.code() != Some(i32::from(outcome.exit_code())) {
        return Err(NativeHelperError::RequestRefused);
    }
    // Whatever the answer, nothing of that helper may still be running when it
    // is read: the same rule the bootstrap success is held to, for the same
    // reason — a verdict read beside a survivor is a verdict about nothing.
    if !descendants_are_gone(&session.child) {
        return Err(NativeHelperError::RequestRefused);
    }
    Ok(NativeHelperPoll::ApprovalDecided(Box::new(outcome)))
}

fn complete_bootstrap_session(
    session: &mut NativeHelperSession,
    status: ExitStatus,
) -> Result<NativeHelperPoll, NativeHelperError> {
    let event = read_event(&mut session.stdout)?;
    if event.request_id != session.request_id {
        return Err(NativeHelperError::RequestRefused);
    }
    // The pair, read through the protocol's own table rather than through a
    // list restated here. An event that terminates nothing names no code and is
    // refused; an event whose code is not the one it names is refused whichever
    // way round the divergence runs — a zero without `access_verified`, an
    // `access_verified` without zero, a refusal wearing another refusal's code.
    let Some(expected_code) = event.event.terminal_exit_code() else {
        return Err(NativeHelperError::RequestRefused);
    };
    if status.code() != Some(i32::from(expected_code)) {
        return Err(NativeHelperError::RequestRefused);
    }
    match event.event {
        AssistantEventKind::AccessVerified => {
            // Nothing of that helper may still be running when its success is
            // read. A reaped root is not enough: what it started must be gone
            // too, and until that is observed the verdict is refused.
            if !descendants_are_gone(&session.child) {
                return Err(NativeHelperError::RequestRefused);
            }
            // La portée attestée que la route d'audit exporte remonte TELLE
            // QUELLE : le protocole l'a déjà validée (porteur, paire, borne),
            // et ce poll rapporte — il n'interprète jamais.
            Ok(NativeHelperPoll::AccessVerified {
                installation_scope: event.installation_scope,
                install_ledger: event.install_ledger,
            })
        }
        AssistantEventKind::Unavailable => Ok(NativeHelperPoll::Unavailable),
        AssistantEventKind::Expired => Err(NativeHelperError::Expired),
        // Un refus et une annulation sont des ISSUES, pas des anomalies : ils
        // remontent nommés pour que la clôture d'affaires en fasse une phrase.
        // Les confondre avec `RequestRefused` — ce que ce poll a fait jusqu'à
        // la clôture — laissait la vue dire « demande refusée » d'un verdict
        // que le produit avait rendu en bonne et due forme.
        AssistantEventKind::Refused => Ok(NativeHelperPoll::Refused {
            installation_scope: event.installation_scope,
            install_ledger: event.install_ledger,
            refusal: event.refusal,
        }),
        AssistantEventKind::Cancelled => Ok(NativeHelperPoll::Cancelled),
        // Un événement qui ne termine rien n'a rien à faire sur ce canal.
        AssistantEventKind::PromptOpen => Err(NativeHelperError::RequestRefused),
    }
}

/// Whether the helper's whole process group is gone, root included.
///
/// The helper is spawned as its own process group leader, so the group is
/// exactly it and whatever it started. Signal zero delivers nothing and only
/// reports whether anyone would have received it: `ESRCH` on the negated
/// identifier is the group being empty, and anything else — a survivor, or a
/// question that could not be asked — is refused.
#[cfg(target_os = "linux")]
fn descendants_are_gone(child: &NativeChild) -> bool {
    let Ok(group) = i32::try_from(child.id()) else {
        return false;
    };
    // SAFETY: signal zero performs no action on any process; it only reports
    // whether the group identifier could be signalled at all.
    if unsafe { libc::kill(-group, 0) } == 0 {
        return false;
    }
    io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

/// On Windows the same proof is already behind this call: `WindowsChild`
/// answers a terminal status only once its Job holds no process at all, so a
/// completed session *is* an empty Job there. Restating it here would be a
/// second, weaker way of asking.
#[cfg(not(target_os = "linux"))]
fn descendants_are_gone(_child: &NativeChild) -> bool {
    true
}

/// Reads the one frame a helper ever writes: a length, its payload, then end of
/// file and nothing else.
///
/// It is one function for both documents because the rule is one rule — exactly
/// one frame, bounded by what its own document can reach, followed by nothing.
/// A second copy of it would be a second place for "and nothing else" to stop
/// being true. What differs between the two invocations is the type parsed and
/// the bound applied, and both are arguments here.
fn read_single_frame(reader: &mut impl Read, maximum: usize) -> Result<Vec<u8>, NativeHelperError> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    read_exact(reader, &mut header)?;
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| NativeHelperError::RequestRefused)?;
    if length == 0 || length > maximum {
        return Err(NativeHelperError::RequestRefused);
    }
    let mut payload = vec![0_u8; length];
    read_exact(reader, &mut payload)?;
    let mut extra = [0_u8; 1];
    match reader.read(&mut extra) {
        Ok(0) => {}
        Ok(_) => return Err(NativeHelperError::RequestRefused),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {
            return payload_after_confirmed_eof(reader, payload)
        }
        Err(_) => return Err(NativeHelperError::Unavailable),
    }
    Ok(payload)
}

fn payload_after_confirmed_eof(
    reader: &mut impl Read,
    payload: Vec<u8>,
) -> Result<Vec<u8>, NativeHelperError> {
    let mut extra = [0_u8; 1];
    loop {
        match reader.read(&mut extra) {
            Ok(0) => break,
            Ok(_) => return Err(NativeHelperError::RequestRefused),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(NativeHelperError::Unavailable),
        }
    }
    Ok(payload)
}

fn read_event(reader: &mut impl Read) -> Result<AssistantEventV1, NativeHelperError> {
    let payload = read_single_frame(reader, MAX_ASSISTANT_EVENT_FRAME_BYTES)?;
    serde_json::from_slice::<AssistantEventV1>(&payload)
        .map_err(|_| NativeHelperError::RequestRefused)?
        .validate()
        .map_err(|_| NativeHelperError::RequestRefused)
}

fn read_approval_outcome(
    reader: &mut impl Read,
) -> Result<ApprovalConsentOutcomeV1, NativeHelperError> {
    let payload = read_single_frame(reader, MAX_APPROVAL_CONSENT_OUTCOME_FRAME_BYTES)?;
    serde_json::from_slice::<ApprovalConsentOutcomeV1>(&payload)
        .map_err(|_| NativeHelperError::RequestRefused)?
        .validate()
        .map_err(|_| NativeHelperError::RequestRefused)
}

fn read_exact(reader: &mut impl Read, mut buffer: &mut [u8]) -> Result<(), NativeHelperError> {
    while !buffer.is_empty() {
        match reader.read(buffer) {
            Ok(0) => return Err(NativeHelperError::RequestRefused),
            Ok(read) => buffer = &mut buffer[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(NativeHelperError::Unavailable),
        }
    }
    Ok(())
}

fn stop_bounded(child: &mut NativeChild) -> Result<(), NativeHelperError> {
    let deadline = Instant::now() + STOP_GRACE;
    loop {
        match child_try_wait(child) {
            Ok(Some(_)) => {
                return Ok(());
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) => break,
            Err(_) => return Err(NativeHelperError::Unavailable),
        }
    }
    terminate_running_and_reap_bounded(child)
}

fn terminate_running_and_reap_bounded(child: &mut NativeChild) -> Result<(), NativeHelperError> {
    match child_try_wait(child) {
        Ok(Some(_)) => return Ok(()),
        Ok(None) => terminate_child_tree(child)?,
        Err(_) => return Err(NativeHelperError::Unavailable),
    }
    let deadline = Instant::now() + KILL_REAP_GRACE;
    loop {
        match child_try_wait(child) {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) | Err(_) => return Err(NativeHelperError::Unavailable),
        }
    }
}

fn reap_until_terminal(mut child: NativeChild) -> CleanupOutcome {
    loop {
        match child_try_wait(&mut child) {
            Ok(Some(_)) => return CleanupOutcome::Reaped,
            Ok(None) => {
                if terminate_child_tree(&mut child).is_err() {
                    return CleanupOutcome::Unproven;
                }
            }
            Err(_) => return CleanupOutcome::Unproven,
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(not(target_os = "windows"))]
fn terminate_child_tree(child: &mut NativeChild) -> Result<(), NativeHelperError> {
    signal_process_group(child);
    let _ = child.kill();
    Ok(())
}

#[cfg(target_os = "windows")]
fn terminate_child_tree(child: &mut NativeChild) -> Result<(), NativeHelperError> {
    child
        .terminate_tree()
        .map_err(|_| NativeHelperError::Unavailable)
}

#[cfg(target_os = "linux")]
fn signal_process_group(child: &mut Child) {
    if let Ok(process_group) = i32::try_from(child.id()) {
        // SAFETY: the child was created as the leader of its own process group. A negative PID
        // targets that bounded group and never the App's group.
        let _ = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    }
}

#[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
fn signal_process_group(_child: &mut NativeChild) {}

fn validate_executable(
    path: &Path,
    expected_name: &OsStr,
    enforce_installed_policy: bool,
) -> Result<(), NativeHelperError> {
    if !path.is_absolute() || path.file_name() != Some(expected_name) {
        return Err(NativeHelperError::Unavailable);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| NativeHelperError::Unavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(NativeHelperError::Unavailable);
    }
    #[cfg(target_os = "linux")]
    validate_linux_metadata(path, &metadata, enforce_installed_policy)?;
    #[cfg(target_os = "windows")]
    validate_windows_metadata(path, &metadata, enforce_installed_policy)?;
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let _ = enforce_installed_policy;
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_linux_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    enforce_installed_policy: bool,
) -> Result<(), NativeHelperError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(NativeHelperError::Unavailable);
    }
    #[cfg(not(debug_assertions))]
    {
        if enforce_installed_policy {
            if path != Path::new("/usr/bin/your-cloud-native-bootstrap-assistant")
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
            {
                return Err(NativeHelperError::Unavailable);
            }
            let directory =
                fs::symlink_metadata("/usr/bin").map_err(|_| NativeHelperError::Unavailable)?;
            if directory.uid() != 0 || directory.mode() & 0o022 != 0 {
                return Err(NativeHelperError::Unavailable);
            }
        }
    }
    #[cfg(debug_assertions)]
    let _ = (path, metadata.uid(), enforce_installed_policy);
    Ok(())
}

#[cfg(target_os = "windows")]
fn validate_windows_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    enforce_installed_policy: bool,
) -> Result<(), NativeHelperError> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(NativeHelperError::Unavailable);
    }
    let directory = path.parent().ok_or(NativeHelperError::Unavailable)?;
    let directory_metadata =
        fs::symlink_metadata(directory).map_err(|_| NativeHelperError::Unavailable)?;
    if !directory_metadata.is_dir()
        || directory_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(NativeHelperError::Unavailable);
    }
    if !enforce_installed_policy {
        return Ok(());
    }

    #[cfg(debug_assertions)]
    let expected_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("binaries");
    #[cfg(not(debug_assertions))]
    let expected_directory = env::current_exe()
        .map_err(|_| NativeHelperError::Unavailable)?
        .parent()
        .ok_or(NativeHelperError::Unavailable)?
        .to_path_buf();
    if directory != expected_directory {
        return Err(NativeHelperError::Unavailable);
    }
    Ok(())
}

#[cfg(all(target_os = "linux", debug_assertions, target_arch = "x86_64"))]
fn installed_helper_binary() -> Result<(PathBuf, OsString), NativeHelperError> {
    let name = OsString::from(format!(
        "{NATIVE_ASSISTANT_BINARY}-x86_64-unknown-linux-gnu"
    ));
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join(&name);
    Ok((path, name))
}

#[cfg(all(target_os = "linux", not(debug_assertions), target_arch = "x86_64"))]
fn installed_helper_binary() -> Result<(PathBuf, OsString), NativeHelperError> {
    let name = OsString::from(NATIVE_ASSISTANT_BINARY);
    Ok((PathBuf::from("/usr/bin").join(&name), name))
}

#[cfg(all(target_os = "windows", debug_assertions, target_arch = "x86_64"))]
fn installed_helper_binary() -> Result<(PathBuf, OsString), NativeHelperError> {
    let name = OsString::from(format!(
        "{NATIVE_ASSISTANT_BINARY}-x86_64-pc-windows-msvc.exe"
    ));
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join(&name);
    Ok((path, name))
}

#[cfg(all(target_os = "windows", not(debug_assertions), target_arch = "x86_64"))]
fn installed_helper_binary() -> Result<(PathBuf, OsString), NativeHelperError> {
    let name = OsString::from(format!("{NATIVE_ASSISTANT_BINARY}.exe"));
    let directory = env::current_exe()
        .map_err(|_| NativeHelperError::Unavailable)?
        .parent()
        .ok_or(NativeHelperError::Unavailable)?
        .to_path_buf();
    Ok((directory.join(&name), name))
}

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "windows", target_arch = "x86_64")
)))]
fn installed_helper_binary() -> Result<(PathBuf, OsString), NativeHelperError> {
    Err(NativeHelperError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use your_cloud_bootstrap_protocol::{
        ApprovalOperation, BootstrapAccessKind, BootstrapAction, BootstrapMode, BootstrapStep,
        BootstrapTarget, NativePromptKind,
    };

    const REQUEST_ID: &str = "00112233445566778899aabbccddeeff";
    const HOST_KEY: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn scope() -> AssistantScopeV1 {
        AssistantScopeV1 {
            schema_version: 1,
            request_id: REQUEST_ID.into(),
            mode: BootstrapMode::Create,
            target: BootstrapTarget {
                host: "controller.example.test".into(),
                port: 22,
                username: "infra_admin".into(),
                host_key_sha256: HOST_KEY.into(),
                access_kind: BootstrapAccessKind::Administrator,
            },
            step: BootstrapStep::PersonalAccess,
            actions: [BootstrapAction::AuditTargetReadOnly],
            prompt: NativePromptKind::ConfirmPersonalAccess,
            target_addresses: Vec::new(),
            machine_configuration: None,
            declared_target: None,
            issued_at_monotonic_nanos: 1,
            remaining_millis: 5_000,
        }
    }

    fn consent() -> ApprovalConsentV1 {
        let plan = "a".repeat(64);
        let rollback = "b".repeat(64);
        ApprovalConsentV1 {
            schema_version: 1,
            request_id: REQUEST_ID.into(),
            infrastructure_id: "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2".into(),
            machine_id: "lab-machine-1".into(),
            operation: ApprovalOperation::DeployOciProbe,
            confirmation_lines: vec![
                "Machine : lab-machine-1".to_owned(),
                format!("Empreinte du plan : {plan}"),
                format!("Empreinte du rollback : {rollback}"),
            ],
            plan_sha256: plan,
            rollback_sha256: rollback,
            issued_at_monotonic_nanos: 1,
            remaining_millis: 5_000,
        }
    }

    /// Every invocation this product may spawn, so a variant added later is a
    /// variant this list must answer for.
    fn every_invocation() -> Vec<HelperInvocation> {
        vec![
            HelperInvocation::Bootstrap(scope()),
            HelperInvocation::ApprovalConsent(consent()),
        ]
    }

    fn event_frame(event: &AssistantEventV1) -> Vec<u8> {
        let payload = serde_json::to_vec(event).unwrap();
        let mut frame = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        frame
    }

    #[test]
    fn parent_scope_frame_is_bounded_and_exact() {
        let scope = scope();
        let frame = encode_frame(
            serde_json::to_vec(&scope).unwrap(),
            MAX_ASSISTANT_SCOPE_FRAME_BYTES,
        )
        .unwrap();
        let length = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;

        assert_eq!(length, frame.len() - 4);
        assert_eq!(
            serde_json::from_slice::<AssistantScopeV1>(&frame[4..])
                .unwrap()
                .validate()
                .unwrap(),
            scope
        );
    }

    #[test]
    fn parent_deadline_can_only_shorten_the_transmitted_lease() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(5);

        assert_eq!(remaining_millis(deadline, now).unwrap(), 5_000);
        assert_eq!(
            remaining_millis(deadline, now + Duration::from_millis(1_250)).unwrap(),
            3_750
        );
        assert_eq!(
            remaining_millis(deadline, deadline),
            Err(NativeHelperError::Expired)
        );
    }

    #[test]
    fn parent_accepts_only_one_bounded_validated_event() {
        let event = AssistantEventV1 {
            schema_version: 1,
            request_id: REQUEST_ID.into(),
            event: AssistantEventKind::Unavailable,
            installation_scope: None,
            install_ledger: None,
            refusal: None,
        };
        assert_eq!(
            read_event(&mut Cursor::new(event_frame(&event))).unwrap(),
            event
        );

        let mut extra = event_frame(&event);
        extra.push(0);
        assert_eq!(
            read_event(&mut Cursor::new(extra)),
            Err(NativeHelperError::RequestRefused)
        );
        assert_eq!(
            read_event(&mut Cursor::new(
                u32::try_from(MAX_ASSISTANT_EVENT_FRAME_BYTES + 1)
                    .unwrap()
                    .to_be_bytes()
            )),
            Err(NativeHelperError::RequestRefused)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deferred_cleanup_reaps_without_another_user_action() {
        let mut command = Command::new("/usr/bin/sleep");
        command
            .arg("30")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command.spawn().unwrap();
        let mut supervisor = NativeHelperSupervisor::default();
        assert!(supervisor.cleanup_worker.is_some());
        supervisor.defer_cleanup(child);
        let deadline = Instant::now() + Duration::from_secs(2);

        while supervisor.cleanup_pending && Instant::now() < deadline {
            supervisor.reconcile_pending_cleanup();
            thread::sleep(Duration::from_millis(5));
        }

        supervisor.reconcile_pending_cleanup();
        assert!(!supervisor.cleanup_pending);
        assert!(!supervisor.cleanup_unproven);
        assert!(supervisor.stranded_cleanup.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unproven_cleanup_keeps_new_launch_fail_closed() {
        let mut supervisor = NativeHelperSupervisor::default();
        supervisor.cleanup_unproven = true;

        assert_eq!(
            supervisor.start_with_path(
                Path::new("/usr/bin/sleep"),
                OsStr::new("sleep"),
                HelperInvocation::Bootstrap(scope()),
                Instant::now() + Duration::from_secs(5),
            ),
            Err(NativeHelperError::Unavailable)
        );
    }

    /// The one test that holds both invocations to the same launch policy.
    ///
    /// It exists because the alternative to a parameterised supervisor was a
    /// second one, and a second one would have put this policy in two copies.
    /// A guard that stopped being true for one mode and not the other is
    /// exactly what that duplication would have allowed, so the guards are
    /// walked here once per variant rather than once per supervisor.
    ///
    /// What is walked: the reconciled cleanup fails closed, a lease already
    /// spent is refused before any process exists, an executable that is not
    /// the installed one is refused under the enforced policy, and each
    /// invocation names its own mode argument and its own frame — never the
    /// other's.
    #[cfg(target_os = "linux")]
    #[test]
    fn both_invocations_cross_the_same_launch_guards() {
        for invocation in every_invocation() {
            // An unproven cleanup fails closed, whichever window was asked for.
            let mut supervisor = NativeHelperSupervisor::default();
            supervisor.cleanup_unproven = true;
            assert_eq!(
                supervisor.start_with_path(
                    Path::new("/usr/bin/sleep"),
                    OsStr::new("sleep"),
                    invocation,
                    Instant::now() + Duration::from_secs(5),
                ),
                Err(NativeHelperError::Unavailable)
            );
        }

        for invocation in every_invocation() {
            // A lease already spent is refused before a process exists.
            let mut supervisor = NativeHelperSupervisor::default();
            assert_eq!(
                supervisor.start_with_path(
                    Path::new("/usr/bin/sleep"),
                    OsStr::new("sleep"),
                    invocation,
                    Instant::now(),
                ),
                Err(NativeHelperError::Expired)
            );
            assert!(supervisor.active.is_none());
        }

        for invocation in every_invocation() {
            // An executable this product did not install is refused before a
            // process exists: the name must be the expected one, and it must be
            // a real, non-empty, executable, non-symlink file.
            let mut supervisor = NativeHelperSupervisor::default();
            assert_eq!(
                supervisor.start_with_path(
                    Path::new("/usr/bin/sleep"),
                    OsStr::new("your-cloud-native-bootstrap-assistant"),
                    invocation,
                    Instant::now() + Duration::from_secs(5),
                ),
                Err(NativeHelperError::Unavailable)
            );
        }

        // Each invocation names its own mode and renders its own frame, and the
        // two cannot be crossed because neither is nameable without the other.
        let bootstrap = HelperInvocation::Bootstrap(scope());
        let approval = HelperInvocation::ApprovalConsent(consent());
        assert_eq!(bootstrap.mode_argument(), REQUIRED_MODE_ARGUMENT);
        assert_eq!(approval.mode_argument(), REQUIRED_APPROVAL_MODE_ARGUMENT);
        assert_ne!(bootstrap.mode_argument(), approval.mode_argument());

        // The signing agent is granted by a window kind, and the approval
        // invocation carries none at all: it does not decline the grant, there
        // is no value it could hold that would ask for one.
        assert_eq!(
            bootstrap.agent_endpoint_prompt(),
            Some(NativePromptKind::ConfirmPersonalAccess)
        );
        assert_eq!(approval.agent_endpoint_prompt(), None);

        let deadline = Instant::now() + Duration::from_secs(5);
        let (bootstrap_id, bootstrap_frame) = HelperInvocation::Bootstrap(scope())
            .stamp_and_encode(deadline, Instant::now())
            .expect("a whole lease");
        let (approval_id, approval_frame) = HelperInvocation::ApprovalConsent(consent())
            .stamp_and_encode(deadline, Instant::now())
            .expect("a whole lease");
        assert_eq!(bootstrap_id, REQUEST_ID);
        assert_eq!(approval_id, REQUEST_ID);
        // Each frame decodes as its own document and as nothing else.
        assert!(serde_json::from_slice::<AssistantScopeV1>(&bootstrap_frame[4..]).is_ok());
        assert!(serde_json::from_slice::<ApprovalConsentV1>(&approval_frame[4..]).is_ok());
        assert!(serde_json::from_slice::<AssistantScopeV1>(&approval_frame[4..]).is_err());
        assert!(serde_json::from_slice::<ApprovalConsentV1>(&bootstrap_frame[4..]).is_err());
    }

    /// One helper at a time, across both modes rather than within each.
    ///
    /// Two native windows open at once are two windows a human can no longer
    /// attribute an answer to, and the product has no way of telling him which
    /// is which. A bootstrap in progress therefore blocks a consent, and a
    /// consent blocks a bootstrap.
    ///
    /// The running session is built here rather than spawned through the
    /// supervisor because no stand-in binary answers the helper protocol: what
    /// is under test is the exclusion, and the exclusion reads one field.
    #[cfg(target_os = "linux")]
    #[test]
    fn one_helper_at_a_time_is_global_to_both_modes() {
        for holder in [HelperKind::Bootstrap, HelperKind::ApprovalConsent] {
            let mut child = Command::new("/usr/bin/sleep")
                .arg("30")
                .process_group(0)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let stdout = child.stdout.take().unwrap();
            let mut supervisor = NativeHelperSupervisor::default();
            supervisor.active = Some(NativeHelperSession {
                kind: holder,
                request_id: REQUEST_ID.into(),
                child,
                stdin: None,
                stdout,
                deadline: Instant::now() + Duration::from_secs(30),
            });

            // Whichever window is already open, neither invocation may open a
            // second one.
            for invocation in every_invocation() {
                assert_eq!(
                    supervisor.start_with_path(
                        Path::new("/usr/bin/sleep"),
                        OsStr::new("sleep"),
                        invocation,
                        Instant::now() + Duration::from_secs(5),
                    ),
                    Err(NativeHelperError::Busy)
                );
            }
            let _ = supervisor.stop_active();
        }

        // A helper still being reaped holds the same exclusion: the two
        // conditions are one branch, so a window cannot open between a helper
        // ending and its cleanup being proven.
        let child = Command::new("/usr/bin/sleep")
            .arg("30")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut supervisor = NativeHelperSupervisor::default();
        supervisor.defer_cleanup(child);
        for invocation in every_invocation() {
            assert_eq!(
                supervisor.start_with_path(
                    Path::new("/usr/bin/sleep"),
                    OsStr::new("sleep"),
                    invocation,
                    Instant::now() + Duration::from_secs(5),
                ),
                Err(NativeHelperError::Busy)
            );
        }
    }
}
