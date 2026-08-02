#![cfg(any(target_os = "linux", target_os = "windows"))]

use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use std::os::{
    fd::OwnedFd,
    unix::{net::UnixStream, process::CommandExt},
};

#[cfg(target_os = "windows")]
use std::{
    ffi::c_void,
    fs::File,
    os::windows::{
        io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle},
        process::CommandExt,
    },
    ptr::{null, null_mut},
};

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE},
    Security::SECURITY_ATTRIBUTES,
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        Pipes::{CreatePipe, GetNamedPipeClientProcessId},
        Threading::{GetCurrentProcessId, CREATE_NO_WINDOW},
    },
};

use your_cloud_bootstrap_protocol::{
    monotonic_nanos, AssistantEventKind, AssistantEventV1, AssistantScopeV1, BootstrapAccessKind,
    BootstrapAction, BootstrapMode, BootstrapStep, BootstrapTarget, NativePromptKind,
};
use your_cloud_native_bootstrap_assistant::{EXIT_WATCHDOG_EXPIRED, REQUIRED_MODE_ARGUMENT};

const REQUEST_ID: &str = "00112233445566778899aabbccddeeff";
const HOST_KEY: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const READY_PATH_ENV: &str = "YOUR_CLOUD_DELAYED_START_READY_PATH";
const RELEASE_PATH_ENV: &str = "YOUR_CLOUD_DELAYED_START_RELEASE_PATH";
const TRANSMITTED_TTL_MILLIS: u64 = 3_000;
const RELEASE_MARGIN_MILLIS: u64 = 500;
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const MONOTONIC_BARRIER_TIMEOUT: Duration = Duration::from_secs(10);
const POST_RELEASE_TIMEOUT: Duration = Duration::from_secs(5);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
const POLL_INTERVAL: Duration = Duration::from_millis(5);
#[cfg(target_os = "windows")]
const FORCED_EXIT_CODE: u32 = 0xe054_544c;

#[cfg(target_os = "linux")]
type ContractStdin = UnixStream;
#[cfg(target_os = "windows")]
type ContractStdin = File;

#[test]
fn delay_before_process_main_cannot_renew_the_transmitted_ttl() {
    let issued_at_monotonic_nanos = monotonic_nanos().expect("shared monotonic issuance");
    let release_at_monotonic_nanos = issued_at_monotonic_nanos
        .checked_add(
            TRANSMITTED_TTL_MILLIS
                .checked_add(RELEASE_MARGIN_MILLIS)
                .and_then(|millis| millis.checked_mul(1_000_000))
                .expect("bounded delayed-start interval"),
        )
        .expect("bounded release stamp");
    let synchronization = SynchronizationPaths::new(issued_at_monotonic_nanos)
        .expect("private delayed-start synchronization");
    let mut process = ContractProcess::spawn(&synchronization).expect("delayed-start fixture");
    let mut stdin = process
        .take_stdin()
        .expect("live authenticated fixture stdin");
    stdin
        .write_all(&frame(&scope(issued_at_monotonic_nanos)))
        .expect("transmitted scope before process_main");
    stdin.flush().expect("transmitted scope flushed");

    wait_for_path(&synchronization.ready, READY_TIMEOUT)
        .expect("fixture ready before process_main");
    assert!(
        process.is_running().expect("fixture liveness"),
        "the fixture must remain blocked before process_main until explicit release",
    );
    wait_until_monotonic(release_at_monotonic_nanos, MONOTONIC_BARRIER_TIMEOUT)
        .expect("transmitted TTL exceeded on the shared OS clock");
    synchronization.release().expect("explicit fixture release");

    let status = match process.wait_bounded(POST_RELEASE_TIMEOUT) {
        Ok(status) => status,
        Err(wait_error) => {
            let cleanup = process.terminate_and_reap();
            panic!("delayed helper did not fail closed after release: {wait_error}; {cleanup:?}");
        }
    };
    drop(stdin);

    assert_eq!(
        status.code(),
        Some(EXIT_WATCHDOG_EXPIRED.into()),
        "an already elapsed scope must expire before any prompt",
    );
    let (stdout_bytes, stderr_bytes) = process.read_output().expect("terminal fixture output");
    assert_eq!(
        decode_event(&stdout_bytes),
        AssistantEventV1 {
            schema_version: 1,
            request_id: REQUEST_ID.into(),
            event: AssistantEventKind::Expired,
        }
    );
    assert!(stderr_bytes.is_empty());
}

fn scope(issued_at_monotonic_nanos: u64) -> AssistantScopeV1 {
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
        issued_at_monotonic_nanos,
        remaining_millis: TRANSMITTED_TTL_MILLIS,
    }
}

fn frame(scope: &AssistantScopeV1) -> Vec<u8> {
    let payload = serde_json::to_vec(scope).expect("scope JSON");
    let mut framed = u32::try_from(payload.len())
        .expect("bounded scope length")
        .to_be_bytes()
        .to_vec();
    framed.extend_from_slice(&payload);
    framed
}

fn decode_event(output: &[u8]) -> AssistantEventV1 {
    assert!(output.len() >= 4);
    let length = u32::from_be_bytes(output[..4].try_into().expect("event header")) as usize;
    assert_eq!(output.len(), length + 4);
    serde_json::from_slice::<AssistantEventV1>(&output[4..])
        .expect("event JSON")
        .validate()
        .expect("validated event")
}

struct SynchronizationPaths {
    directory: PathBuf,
    ready: PathBuf,
    release: PathBuf,
}

impl SynchronizationPaths {
    fn new(unique_stamp: u64) -> io::Result<Self> {
        let directory = std::env::temp_dir().join(format!(
            "your-cloud-delayed-start-{}-{unique_stamp}",
            std::process::id(),
        ));
        fs::create_dir(&directory)?;
        Ok(Self {
            ready: directory.join("ready"),
            release: directory.join("release"),
            directory,
        })
    }

    fn release(&self) -> io::Result<()> {
        let mut release = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.release)?;
        release.write_all(b"release")?;
        release.flush()
    }
}

impl Drop for SynchronizationPaths {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.ready);
        let _ = fs::remove_file(&self.release);
        let _ = fs::remove_dir(&self.directory);
    }
}

fn wait_for_path(path: &Path, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(invalid_data)?;
    loop {
        match path.try_exists() {
            Ok(true) => return Ok(()),
            Ok(false) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            Ok(false) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "delayed-start ready signal did not appear",
                ));
            }
            Err(error) => return Err(error),
        }
    }
}

fn wait_until_monotonic(target_nanos: u64, timeout: Duration) -> io::Result<()> {
    let wall_deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(invalid_data)?;
    loop {
        let observed = monotonic_nanos().map_err(|_| invalid_data())?;
        if observed >= target_nanos {
            return Ok(());
        }
        if Instant::now() >= wall_deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "shared monotonic release barrier did not resolve",
            ));
        }
        let until_target = Duration::from_nanos(target_nanos - observed);
        thread::sleep(POLL_INTERVAL.min(until_target));
    }
}

struct ContractProcess {
    child: Child,
    stdin: Option<ContractStdin>,
    #[cfg(target_os = "windows")]
    job: TestJob,
    terminal: bool,
}

impl ContractProcess {
    fn spawn(synchronization: &SynchronizationPaths) -> io::Result<Self> {
        let executable = Path::new(env!("CARGO_BIN_EXE_your-cloud-delayed-start-fixture"));
        let mut command = Command::new(executable);
        command
            .arg(REQUIRED_MODE_ARGUMENT)
            .current_dir(executable.parent().ok_or_else(invalid_data)?)
            .env_clear()
            .env(READY_PATH_ENV, &synchronization.ready)
            .env(RELEASE_PATH_ENV, &synchronization.release)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        #[cfg(target_os = "linux")]
        let (child_input, parent_input) = UnixStream::pair()?;
        #[cfg(target_os = "linux")]
        command
            .stdin(Stdio::from(OwnedFd::from(child_input)))
            .process_group(0);
        #[cfg(target_os = "windows")]
        let (child_input, parent_input) = authenticated_windows_pipe()?;
        #[cfg(target_os = "windows")]
        command
            .stdin(Stdio::from(child_input))
            .creation_flags(CREATE_NO_WINDOW);

        #[cfg(target_os = "windows")]
        let job = TestJob::new()?;
        let mut child = command.spawn()?;
        #[cfg(target_os = "windows")]
        if let Err(error) = job.assign(&child) {
            let _ = child.kill();
            let _ = wait_child_bounded(&mut child, CLEANUP_TIMEOUT);
            return Err(error);
        }
        Ok(Self {
            child,
            stdin: Some(parent_input),
            #[cfg(target_os = "windows")]
            job,
            terminal: false,
        })
    }

    fn take_stdin(&mut self) -> Option<ContractStdin> {
        self.stdin.take()
    }

    fn is_running(&mut self) -> io::Result<bool> {
        match self.child.try_wait()? {
            Some(_) => {
                self.terminal = true;
                Ok(false)
            }
            None => Ok(true),
        }
    }

    fn wait_bounded(&mut self, timeout: Duration) -> io::Result<ExitStatus> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(invalid_data)?;
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.terminal = true;
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "delayed helper reused the transmitted TTL after release",
                ));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn terminate_and_reap(&mut self) -> io::Result<()> {
        if self.terminal {
            return Ok(());
        }
        self.terminate()?;
        let _ = self.wait_bounded(CLEANUP_TIMEOUT)?;
        Ok(())
    }

    fn terminate(&mut self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let process_group = i32::try_from(self.child.id()).map_err(|_| invalid_data())?;
            if unsafe { libc::kill(-process_group, libc::SIGKILL) } != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error);
                }
            }
            Ok(())
        }
        #[cfg(target_os = "windows")]
        {
            self.job.terminate()
        }
    }

    fn read_output(&mut self) -> io::Result<(Vec<u8>, Vec<u8>)> {
        if !self.terminal {
            return Err(invalid_data());
        }
        let mut stdout_bytes = Vec::new();
        self.child
            .stdout
            .take()
            .ok_or_else(invalid_data)?
            .read_to_end(&mut stdout_bytes)?;
        let mut stderr_bytes = Vec::new();
        self.child
            .stderr
            .take()
            .ok_or_else(invalid_data)?
            .read_to_end(&mut stderr_bytes)?;
        Ok((stdout_bytes, stderr_bytes))
    }
}

impl Drop for ContractProcess {
    fn drop(&mut self) {
        if self.terminal {
            return;
        }
        let _ = self.terminate();
        if wait_child_bounded(&mut self.child, CLEANUP_TIMEOUT).is_ok() {
            self.terminal = true;
        }
    }
}

fn wait_child_bounded(child: &mut Child, timeout: Duration) -> io::Result<ExitStatus> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(invalid_data)?;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "delayed fixture did not become terminal before cleanup deadline",
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(target_os = "windows")]
fn authenticated_windows_pipe() -> io::Result<(File, File)> {
    let mut security = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| invalid_data())?,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let mut child_input = null_mut();
    let mut parent_input = null_mut();
    if unsafe { CreatePipe(&mut child_input, &mut parent_input, &mut security, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let child_input = owned_handle(child_input)?;
    let parent_input = owned_handle(parent_input)?;
    if unsafe { SetHandleInformation(parent_input.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut client_process_id = 0_u32;
    if unsafe { GetNamedPipeClientProcessId(child_input.as_raw_handle(), &mut client_process_id) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    if client_process_id != unsafe { GetCurrentProcessId() } {
        return Err(invalid_data());
    }
    Ok((
        owned_handle_into_file(child_input),
        owned_handle_into_file(parent_input),
    ))
}

#[cfg(target_os = "windows")]
struct TestJob {
    handle: OwnedHandle,
    terminated: bool,
}

#[cfg(target_os = "windows")]
impl TestJob {
    fn new() -> io::Result<Self> {
        let handle = owned_handle(unsafe { CreateJobObjectW(null(), null()) })?;
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                handle.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .map_err(|_| invalid_data())?,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            handle,
            terminated: false,
        })
    }

    fn assign(&self, child: &Child) -> io::Result<()> {
        if unsafe { AssignProcessToJobObject(self.handle.as_raw_handle(), child.as_raw_handle()) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn terminate(&mut self) -> io::Result<()> {
        if self.terminated {
            return Ok(());
        }
        if unsafe { TerminateJobObject(self.handle.as_raw_handle(), FORCED_EXIT_CODE) } == 0 {
            return Err(io::Error::last_os_error());
        }
        self.terminated = true;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl Drop for TestJob {
    fn drop(&mut self) {
        if !self.terminated {
            let _ = unsafe { TerminateJobObject(self.handle.as_raw_handle(), FORCED_EXIT_CODE) };
        }
    }
}

#[cfg(target_os = "windows")]
fn owned_handle(handle: *mut c_void) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

#[cfg(target_os = "windows")]
fn owned_handle_into_file(handle: OwnedHandle) -> File {
    unsafe { File::from_raw_handle(handle.into_raw_handle()) }
}

fn invalid_data() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid delayed-start contract value",
    )
}
