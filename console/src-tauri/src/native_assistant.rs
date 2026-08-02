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

use your_cloud_bootstrap_protocol::{
    monotonic_nanos, AssistantEventKind, AssistantEventV1, AssistantScopeV1,
    ASSISTANT_EXIT_CANCELLED, ASSISTANT_EXIT_REFUSED, ASSISTANT_EXIT_UNAVAILABLE,
    ASSISTANT_EXIT_WATCHDOG_EXPIRED, MAX_ASSISTANT_EVENT_FRAME_BYTES,
    MAX_ASSISTANT_SCOPE_FRAME_BYTES,
};

#[cfg(target_os = "windows")]
#[path = "native_assistant/windows.rs"]
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
const FRAME_HEADER_BYTES: usize = 4;
const STOP_GRACE: Duration = Duration::from_millis(500);
const KILL_REAP_GRACE: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeAssistantError {
    Busy,
    Expired,
    RequestRefused,
    Unavailable,
}

impl NativeAssistantError {
    pub(crate) fn public_code(self) -> &'static str {
        match self {
            Self::Busy => "bootstrap_busy",
            Self::Expired => "bootstrap_expired",
            Self::RequestRefused => "bootstrap_request_refused",
            Self::Unavailable => "native_assistant_unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeAssistantPoll {
    Running,
    Unavailable,
}

struct NativeAssistantSession {
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

pub(crate) struct NativeAssistantSupervisor {
    active: Option<NativeAssistantSession>,
    cleanup_worker: Option<CleanupWorker>,
    cleanup_pending: bool,
    cleanup_unproven: bool,
    stranded_cleanup: Option<NativeChild>,
}

impl Default for NativeAssistantSupervisor {
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

impl NativeAssistantSupervisor {
    pub(crate) fn start(
        &mut self,
        scope: AssistantScopeV1,
        expires_at: Instant,
    ) -> Result<(), NativeAssistantError> {
        let (path, expected_name) = installed_native_assistant()?;
        self.start_with_policy(&path, &expected_name, scope, expires_at, true)
    }

    #[cfg(test)]
    #[allow(dead_code)] // Used by the helper's cross-crate parent contract.
    pub(crate) fn start_with_path(
        &mut self,
        path: &Path,
        expected_name: &OsStr,
        scope: AssistantScopeV1,
        expires_at: Instant,
    ) -> Result<(), NativeAssistantError> {
        self.start_with_policy(path, expected_name, scope, expires_at, false)
    }

    fn start_with_policy(
        &mut self,
        path: &Path,
        expected_name: &OsStr,
        mut scope: AssistantScopeV1,
        expires_at: Instant,
        enforce_installed_policy: bool,
    ) -> Result<(), NativeAssistantError> {
        self.reconcile_pending_cleanup();
        if self.cleanup_unproven || self.cleanup_worker.is_none() || self.stranded_cleanup.is_some()
        {
            return Err(NativeAssistantError::Unavailable);
        }
        if self.active.is_some() || self.cleanup_pending {
            return Err(NativeAssistantError::Busy);
        }
        validate_executable(path, expected_name, enforce_installed_policy)?;
        // Sample the shared OS clock before the local Instant: any time between
        // both observations is deducted twice rather than silently renewing TTL.
        scope.issued_at_monotonic_nanos =
            monotonic_nanos().map_err(|_| NativeAssistantError::Unavailable)?;
        scope.remaining_millis = remaining_millis(expires_at, Instant::now())?;
        let scope = scope
            .validate()
            .map_err(|_| NativeAssistantError::RequestRefused)?;

        let working_directory = path.parent().ok_or(NativeAssistantError::Unavailable)?;
        #[cfg(target_os = "linux")]
        let (child_input, parent_input) =
            UnixStream::pair().map_err(|_| NativeAssistantError::Unavailable)?;
        #[cfg(target_os = "linux")]
        let mut parent_input = Some(parent_input);
        #[cfg(not(target_os = "windows"))]
        let mut child = {
            let mut command = Command::new(path);
            command
                .arg(REQUIRED_MODE_ARGUMENT)
                .current_dir(working_directory)
                .env_clear()
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            #[cfg(target_os = "linux")]
            command.stdin(Stdio::from(OwnedFd::from(child_input)));
            #[cfg(not(target_os = "linux"))]
            command.stdin(Stdio::piped());
            configure_public_gui_environment(&mut command);
            #[cfg(target_os = "linux")]
            command.process_group(0);
            command
                .spawn()
                .map_err(|_| NativeAssistantError::Unavailable)?
        };
        #[cfg(target_os = "windows")]
        let mut child =
            windows::spawn_native_assistant(path, working_directory, REQUIRED_MODE_ARGUMENT)?;

        let launch = (|| {
            let mut scope = scope;
            // Recalculate from the native absolute deadline only after the child exists. Time
            // spent validating and spawning can shorten this lease but can never renew it. The
            // OS stamp is deliberately sampled first so the transmitted pair is conservative.
            scope.issued_at_monotonic_nanos =
                monotonic_nanos().map_err(|_| NativeAssistantError::Unavailable)?;
            scope.remaining_millis = remaining_millis(expires_at, Instant::now())?;
            let scope = scope
                .validate()
                .map_err(|_| NativeAssistantError::RequestRefused)?;
            let frame = encode_scope(&scope)?;
            #[cfg(target_os = "linux")]
            let mut stdin = parent_input
                .take()
                .ok_or(NativeAssistantError::Unavailable)?;
            #[cfg(not(target_os = "linux"))]
            let mut stdin =
                take_child_stdin(&mut child).ok_or(NativeAssistantError::Unavailable)?;
            stdin
                .write_all(&frame)
                .map_err(|_| NativeAssistantError::Unavailable)?;
            stdin
                .flush()
                .map_err(|_| NativeAssistantError::Unavailable)?;
            let stdout = take_child_stdout(&mut child).ok_or(NativeAssistantError::Unavailable)?;
            configure_nonblocking_stdout(&stdout)?;
            Ok((scope.request_id, stdin, stdout))
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
        self.active = Some(NativeAssistantSession {
            request_id,
            child,
            stdin: Some(stdin),
            stdout,
            deadline: expires_at,
        });
        Ok(())
    }

    pub(crate) fn poll(
        &mut self,
        request_id: &str,
    ) -> Result<NativeAssistantPoll, NativeAssistantError> {
        let active = self
            .active
            .as_mut()
            .ok_or(NativeAssistantError::RequestRefused)?;
        if active.request_id != request_id {
            return Err(NativeAssistantError::RequestRefused);
        }
        if Instant::now() >= active.deadline {
            let mut expired = self.active.take().expect("active assistant checked above");
            expired.stdin.take();
            if stop_bounded(&mut expired.child).is_err() {
                self.defer_cleanup(expired.child);
                return Err(NativeAssistantError::Unavailable);
            }
            return Err(NativeAssistantError::Expired);
        }
        let status = match child_try_wait(&mut active.child) {
            Ok(status) => status,
            Err(_) => {
                let mut failed = self.active.take().expect("active assistant checked above");
                failed.stdin.take();
                if terminate_running_and_reap_bounded(&mut failed.child).is_err() {
                    self.defer_cleanup(failed.child);
                }
                return Err(NativeAssistantError::Unavailable);
            }
        };
        let Some(status) = status else {
            return Ok(NativeAssistantPoll::Running);
        };
        let mut completed = self.active.take().expect("active assistant checked above");
        complete_session(&mut completed, status)
    }

    pub(crate) fn cancel(&mut self, request_id: &str) -> Result<(), NativeAssistantError> {
        let active = self
            .active
            .as_ref()
            .ok_or(NativeAssistantError::RequestRefused)?;
        if active.request_id != request_id {
            return Err(NativeAssistantError::RequestRefused);
        }
        self.stop_active()
    }

    pub(crate) fn stop_active(&mut self) -> Result<(), NativeAssistantError> {
        self.reconcile_pending_cleanup();
        if self.cleanup_pending || self.cleanup_unproven || self.stranded_cleanup.is_some() {
            return Err(NativeAssistantError::Unavailable);
        }
        if let Some(mut active) = self.active.take() {
            // EOF is the normal cancellation path. The bounded process-tree termination below
            // remains a fallback when the native event loop cannot clean up cooperatively.
            active.stdin.take();
            if stop_bounded(&mut active.child).is_err() {
                self.defer_cleanup(active.child);
                return Err(NativeAssistantError::Unavailable);
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

fn remaining_millis(deadline: Instant, now: Instant) -> Result<u64, NativeAssistantError> {
    let remaining = deadline
        .checked_duration_since(now)
        .ok_or(NativeAssistantError::Expired)?;
    let millis =
        u64::try_from(remaining.as_millis()).map_err(|_| NativeAssistantError::RequestRefused)?;
    if millis == 0 {
        return Err(NativeAssistantError::Expired);
    }
    Ok(millis)
}

#[cfg(not(target_os = "windows"))]
fn configure_public_gui_environment(command: &mut Command) {
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
}

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
fn configure_nonblocking_stdout(stdout: &ChildStdout) -> Result<(), NativeAssistantError> {
    let descriptor = stdout.as_raw_fd();
    // SAFETY: fcntl only reads and updates the flags of the owned pipe descriptor.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 {
        return Err(NativeAssistantError::Unavailable);
    }
    // SAFETY: descriptor remains owned by stdout for the whole call.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(NativeAssistantError::Unavailable);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn configure_nonblocking_stdout(_stdout: &NativeChildStdout) -> Result<(), NativeAssistantError> {
    Ok(())
}

impl Drop for NativeAssistantSupervisor {
    fn drop(&mut self) {
        let _ = self.stop_active();
    }
}

fn encode_scope(scope: &AssistantScopeV1) -> Result<Vec<u8>, NativeAssistantError> {
    let payload = serde_json::to_vec(scope).map_err(|_| NativeAssistantError::RequestRefused)?;
    if payload.is_empty() || payload.len() > MAX_ASSISTANT_SCOPE_FRAME_BYTES {
        return Err(NativeAssistantError::RequestRefused);
    }
    let length = u32::try_from(payload.len()).map_err(|_| NativeAssistantError::RequestRefused)?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn complete_session(
    session: &mut NativeAssistantSession,
    status: ExitStatus,
) -> Result<NativeAssistantPoll, NativeAssistantError> {
    let event = read_event(&mut session.stdout)?;
    if event.request_id != session.request_id {
        return Err(NativeAssistantError::RequestRefused);
    }
    match (status.code(), event.event) {
        (Some(code), AssistantEventKind::Unavailable)
            if code == i32::from(ASSISTANT_EXIT_UNAVAILABLE) =>
        {
            Ok(NativeAssistantPoll::Unavailable)
        }
        (Some(code), AssistantEventKind::Refused) if code == i32::from(ASSISTANT_EXIT_REFUSED) => {
            Err(NativeAssistantError::RequestRefused)
        }
        (Some(code), AssistantEventKind::Cancelled)
            if code == i32::from(ASSISTANT_EXIT_CANCELLED) =>
        {
            Err(NativeAssistantError::RequestRefused)
        }
        (Some(code), AssistantEventKind::Expired)
            if code == i32::from(ASSISTANT_EXIT_WATCHDOG_EXPIRED) =>
        {
            Err(NativeAssistantError::Expired)
        }
        _ => Err(NativeAssistantError::RequestRefused),
    }
}

fn read_event(reader: &mut impl Read) -> Result<AssistantEventV1, NativeAssistantError> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    read_exact(reader, &mut header)?;
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| NativeAssistantError::RequestRefused)?;
    if length == 0 || length > MAX_ASSISTANT_EVENT_FRAME_BYTES {
        return Err(NativeAssistantError::RequestRefused);
    }
    let mut payload = vec![0_u8; length];
    read_exact(reader, &mut payload)?;
    let mut extra = [0_u8; 1];
    match reader.read(&mut extra) {
        Ok(0) => {}
        Ok(_) => return Err(NativeAssistantError::RequestRefused),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {
            return read_event_eof_after_interrupt(reader, payload)
        }
        Err(_) => return Err(NativeAssistantError::Unavailable),
    }
    serde_json::from_slice::<AssistantEventV1>(&payload)
        .map_err(|_| NativeAssistantError::RequestRefused)?
        .validate()
        .map_err(|_| NativeAssistantError::RequestRefused)
}

fn read_event_eof_after_interrupt(
    reader: &mut impl Read,
    payload: Vec<u8>,
) -> Result<AssistantEventV1, NativeAssistantError> {
    let mut extra = [0_u8; 1];
    loop {
        match reader.read(&mut extra) {
            Ok(0) => break,
            Ok(_) => return Err(NativeAssistantError::RequestRefused),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(NativeAssistantError::Unavailable),
        }
    }
    serde_json::from_slice::<AssistantEventV1>(&payload)
        .map_err(|_| NativeAssistantError::RequestRefused)?
        .validate()
        .map_err(|_| NativeAssistantError::RequestRefused)
}

fn read_exact(reader: &mut impl Read, mut buffer: &mut [u8]) -> Result<(), NativeAssistantError> {
    while !buffer.is_empty() {
        match reader.read(buffer) {
            Ok(0) => return Err(NativeAssistantError::RequestRefused),
            Ok(read) => buffer = &mut buffer[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(NativeAssistantError::Unavailable),
        }
    }
    Ok(())
}

fn stop_bounded(child: &mut NativeChild) -> Result<(), NativeAssistantError> {
    let deadline = Instant::now() + STOP_GRACE;
    loop {
        match child_try_wait(child) {
            Ok(Some(_)) => {
                return Ok(());
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) => break,
            Err(_) => return Err(NativeAssistantError::Unavailable),
        }
    }
    terminate_running_and_reap_bounded(child)
}

fn terminate_running_and_reap_bounded(child: &mut NativeChild) -> Result<(), NativeAssistantError> {
    match child_try_wait(child) {
        Ok(Some(_)) => return Ok(()),
        Ok(None) => terminate_child_tree(child)?,
        Err(_) => return Err(NativeAssistantError::Unavailable),
    }
    let deadline = Instant::now() + KILL_REAP_GRACE;
    loop {
        match child_try_wait(child) {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) | Err(_) => return Err(NativeAssistantError::Unavailable),
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
fn terminate_child_tree(child: &mut NativeChild) -> Result<(), NativeAssistantError> {
    signal_process_group(child);
    let _ = child.kill();
    Ok(())
}

#[cfg(target_os = "windows")]
fn terminate_child_tree(child: &mut NativeChild) -> Result<(), NativeAssistantError> {
    child
        .terminate_tree()
        .map_err(|_| NativeAssistantError::Unavailable)
}

#[cfg(target_os = "linux")]
fn signal_process_group(child: &mut Child) {
    if let Ok(process_group) = i32::try_from(child.id()) {
        // SAFETY: the child was created as the leader of its own process group. A negative PID
        // targets that bounded group and never the Console's group.
        let _ = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    }
}

#[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
fn signal_process_group(_child: &mut NativeChild) {}

fn validate_executable(
    path: &Path,
    expected_name: &OsStr,
    enforce_installed_policy: bool,
) -> Result<(), NativeAssistantError> {
    if !path.is_absolute() || path.file_name() != Some(expected_name) {
        return Err(NativeAssistantError::Unavailable);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| NativeAssistantError::Unavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(NativeAssistantError::Unavailable);
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
) -> Result<(), NativeAssistantError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(NativeAssistantError::Unavailable);
    }
    #[cfg(not(debug_assertions))]
    {
        if enforce_installed_policy {
            if path != Path::new("/usr/bin/your-cloud-native-bootstrap-assistant")
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
            {
                return Err(NativeAssistantError::Unavailable);
            }
            let directory =
                fs::symlink_metadata("/usr/bin").map_err(|_| NativeAssistantError::Unavailable)?;
            if directory.uid() != 0 || directory.mode() & 0o022 != 0 {
                return Err(NativeAssistantError::Unavailable);
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
) -> Result<(), NativeAssistantError> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(NativeAssistantError::Unavailable);
    }
    let directory = path.parent().ok_or(NativeAssistantError::Unavailable)?;
    let directory_metadata =
        fs::symlink_metadata(directory).map_err(|_| NativeAssistantError::Unavailable)?;
    if !directory_metadata.is_dir()
        || directory_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(NativeAssistantError::Unavailable);
    }
    if !enforce_installed_policy {
        return Ok(());
    }

    #[cfg(debug_assertions)]
    let expected_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("binaries");
    #[cfg(not(debug_assertions))]
    let expected_directory = env::current_exe()
        .map_err(|_| NativeAssistantError::Unavailable)?
        .parent()
        .ok_or(NativeAssistantError::Unavailable)?
        .to_path_buf();
    if directory != expected_directory {
        return Err(NativeAssistantError::Unavailable);
    }
    Ok(())
}

#[cfg(all(target_os = "linux", debug_assertions, target_arch = "x86_64"))]
fn installed_native_assistant() -> Result<(PathBuf, OsString), NativeAssistantError> {
    let name = OsString::from(format!(
        "{NATIVE_ASSISTANT_BINARY}-x86_64-unknown-linux-gnu"
    ));
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join(&name);
    Ok((path, name))
}

#[cfg(all(target_os = "linux", not(debug_assertions), target_arch = "x86_64"))]
fn installed_native_assistant() -> Result<(PathBuf, OsString), NativeAssistantError> {
    let name = OsString::from(NATIVE_ASSISTANT_BINARY);
    Ok((PathBuf::from("/usr/bin").join(&name), name))
}

#[cfg(all(target_os = "windows", debug_assertions, target_arch = "x86_64"))]
fn installed_native_assistant() -> Result<(PathBuf, OsString), NativeAssistantError> {
    let name = OsString::from(format!(
        "{NATIVE_ASSISTANT_BINARY}-x86_64-pc-windows-msvc.exe"
    ));
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join(&name);
    Ok((path, name))
}

#[cfg(all(target_os = "windows", not(debug_assertions), target_arch = "x86_64"))]
fn installed_native_assistant() -> Result<(PathBuf, OsString), NativeAssistantError> {
    let name = OsString::from(format!("{NATIVE_ASSISTANT_BINARY}.exe"));
    let directory = env::current_exe()
        .map_err(|_| NativeAssistantError::Unavailable)?
        .parent()
        .ok_or(NativeAssistantError::Unavailable)?
        .to_path_buf();
    Ok((directory.join(&name), name))
}

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "windows", target_arch = "x86_64")
)))]
fn installed_native_assistant() -> Result<(PathBuf, OsString), NativeAssistantError> {
    Err(NativeAssistantError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use your_cloud_bootstrap_protocol::{
        BootstrapAccessKind, BootstrapAction, BootstrapMode, BootstrapStep, BootstrapTarget,
        NativePromptKind,
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
            issued_at_monotonic_nanos: 1,
            remaining_millis: 5_000,
        }
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
        let frame = encode_scope(&scope).unwrap();
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
            Err(NativeAssistantError::Expired)
        );
    }

    #[test]
    fn parent_accepts_only_one_bounded_validated_event() {
        let event = AssistantEventV1 {
            schema_version: 1,
            request_id: REQUEST_ID.into(),
            event: AssistantEventKind::Unavailable,
        };
        assert_eq!(
            read_event(&mut Cursor::new(event_frame(&event))).unwrap(),
            event
        );

        let mut extra = event_frame(&event);
        extra.push(0);
        assert_eq!(
            read_event(&mut Cursor::new(extra)),
            Err(NativeAssistantError::RequestRefused)
        );
        assert_eq!(
            read_event(&mut Cursor::new(
                u32::try_from(MAX_ASSISTANT_EVENT_FRAME_BYTES + 1)
                    .unwrap()
                    .to_be_bytes()
            )),
            Err(NativeAssistantError::RequestRefused)
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
        let mut supervisor = NativeAssistantSupervisor::default();
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
        let mut supervisor = NativeAssistantSupervisor::default();
        supervisor.cleanup_unproven = true;

        assert_eq!(
            supervisor.start_with_path(
                Path::new("/usr/bin/sleep"),
                OsStr::new("sleep"),
                scope(),
                Instant::now() + Duration::from_secs(5),
            ),
            Err(NativeAssistantError::Unavailable)
        );
    }
}
