#![cfg(target_os = "windows")]

use std::{
    ffi::c_void,
    io::{self, Read, Write},
    os::windows::{
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
        process::CommandExt,
    },
    path::Path,
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    ptr::{null, null_mut},
    thread,
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{HWND, LPARAM},
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        Threading::CREATE_NO_WINDOW,
    },
    UI::WindowsAndMessaging::{
        EnumWindows, GetClassNameW, GetWindowTextLengthW, GetWindowThreadProcessId, IsWindowVisible,
    },
};
use your_cloud_bootstrap_protocol::{
    monotonic_nanos, AssistantScopeV1, BootstrapAccessKind, BootstrapAction, BootstrapMode,
    BootstrapStep, BootstrapTarget, NativePromptKind,
};
use your_cloud_native_bootstrap_assistant::{EXIT_PROTOCOL_REFUSED, REQUIRED_MODE_ARGUMENT};

const REQUEST_ID: &str = "00112233445566778899aabbccddeeff";
const HOST_KEY: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const INITIAL_REMAINING_MILLIS: u64 = 20_000;
const WINDOW_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(5);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const FORCED_EXIT_CODE: u32 = 0xe04c_5054;
const DIALOG_CLASS_NAME: &[u16] = &[
    b'#' as u16,
    b'3' as u16,
    b'2' as u16,
    b'7' as u16,
    b'7' as u16,
    b'0' as u16,
];

#[test]
fn live_prompt_refuses_target_step_action_and_expiration_mutations() {
    for mutation_kind in MutationKind::ALL {
        let initial_scope = scope(INITIAL_REMAINING_MILLIS);
        let initial_frame = frame(&initial_scope);
        let mutation = mutation_kind.derive_from(&initial_scope);
        assert_ne!(mutation.frame, initial_frame, "{} mutation", mutation.name);

        let mut process = ContractProcess::spawn().expect("bounded helper process");
        let process_id = process.process_id();
        let mut stdin = process.take_stdin().expect("live helper stdin");
        stdin
            .write_all(&initial_frame)
            .expect("initial validated scope frame");
        stdin.flush().expect("initial scope flushed");

        let prompt_window = wait_for_prompt_window(process_id, WINDOW_TIMEOUT)
            .unwrap_or_else(|error| panic!("{} mutation: {error}", mutation.name));
        assert_eq!(
            window_process_id(prompt_window).expect("live prompt process id"),
            process_id,
            "the observed HWND must belong to the helper child",
        );

        stdin
            .write_all(&mutation.frame)
            .unwrap_or_else(|error| panic!("{} mutation write failed: {error}", mutation.name));
        stdin
            .flush()
            .unwrap_or_else(|error| panic!("{} mutation flush failed: {error}", mutation.name));

        let status = match process.wait_bounded(PROCESS_TIMEOUT) {
            Ok(status) => status,
            Err(wait_error) => {
                let cleanup = process.terminate_and_reap();
                panic!(
                    "{} mutation did not terminate in time: {wait_error}; cleanup: {cleanup:?}",
                    mutation.name,
                );
            }
        };
        drop(stdin);

        assert_eq!(
            status.code(),
            Some(EXIT_PROTOCOL_REFUSED.into()),
            "{} mutation must be refused as extra protocol input",
            mutation.name,
        );
        let (stdout_bytes, stderr_bytes) = process.read_output().expect("terminal helper output");
        assert!(stdout_bytes.is_empty(), "{} mutation stdout", mutation.name);
        assert!(stderr_bytes.is_empty(), "{} mutation stderr", mutation.name);
    }
}

struct Mutation {
    name: &'static str,
    frame: Vec<u8>,
}

#[derive(Clone, Copy)]
enum MutationKind {
    Target,
    Step,
    Action,
    Expiration,
}

impl MutationKind {
    const ALL: [Self; 4] = [Self::Target, Self::Step, Self::Action, Self::Expiration];

    fn derive_from(self, initial: &AssistantScopeV1) -> Mutation {
        match self {
            Self::Target => {
                let mut target = initial.clone();
                target.target.host = "other-controller.example.test".into();
                Mutation {
                    name: "target",
                    frame: frame(&target),
                }
            }
            Self::Step => {
                let mut step = initial.clone();
                step.step = BootstrapStep::UnlockPersonalKey;
                step.prompt = NativePromptKind::KeyPassphrase;
                Mutation {
                    name: "step",
                    frame: frame(&step),
                }
            }
            Self::Action => {
                let mut action = serde_json::to_value(initial).expect("validated scope JSON");
                action["actions"] = serde_json::json!(["install_controller"]);
                Mutation {
                    name: "action",
                    frame: payload_frame(
                        &serde_json::to_vec(&action).expect("action mutation JSON"),
                    ),
                }
            }
            Self::Expiration => {
                let mut expiration = initial.clone();
                expiration.remaining_millis = INITIAL_REMAINING_MILLIS - 1_000;
                Mutation {
                    name: "expiration",
                    frame: frame(&expiration),
                }
            }
        }
    }
}

/// The scope this suite submits, deliberately not the personal access one.
///
/// `ConfirmPersonalAccess` no longer opens a window by itself on this system
/// either: it first resolves the target, freezes its addresses and attests the
/// agent pipe, and against a synthetic unreachable host it fails before any
/// window exists. The properties proven here belong to the window — the
/// mutations it refuses while live — so the scope carries the escalation
/// couple, which still goes straight to the native prompt with the same
/// administrator target. This mirrors the Linux homologue exactly.
fn scope(remaining_millis: u64) -> AssistantScopeV1 {
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
        step: BootstrapStep::PrivilegeEscalation,
        actions: [BootstrapAction::AuditTargetReadOnly],
        prompt: NativePromptKind::SudoPassword,
        target_addresses: Vec::new(),
        machine_configuration: None,
        issued_at_monotonic_nanos: monotonic_nanos().expect("shared monotonic clock"),
        remaining_millis,
    }
}

fn frame(scope: &AssistantScopeV1) -> Vec<u8> {
    payload_frame(&serde_json::to_vec(scope).expect("scope JSON"))
}

fn payload_frame(payload: &[u8]) -> Vec<u8> {
    let mut framed = u32::try_from(payload.len())
        .expect("bounded scope length")
        .to_be_bytes()
        .to_vec();
    framed.extend_from_slice(payload);
    framed
}

fn wait_for_prompt_window(process_id: u32, timeout: Duration) -> io::Result<HWND> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(invalid_data)?;
    loop {
        let mut search = WindowSearch {
            process_id,
            found: null_mut(),
        };
        unsafe {
            let _ = EnumWindows(
                Some(find_child_dialog),
                (&mut search as *mut WindowSearch) as LPARAM,
            );
        }
        if !search.found.is_null() {
            return Ok(search.found);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "helper child did not expose its Win32 prompt before the deadline",
            ));
        }
        thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

struct WindowSearch {
    process_id: u32,
    found: HWND,
}

unsafe extern "system" fn find_child_dialog(window: HWND, parameter: LPARAM) -> i32 {
    let search = unsafe { &mut *(parameter as *mut WindowSearch) };
    let Ok(process_id) = window_process_id(window) else {
        return 1;
    };
    if process_id != search.process_id
        || unsafe { IsWindowVisible(window) } == 0
        || unsafe { GetWindowTextLengthW(window) } <= 0
    {
        return 1;
    }

    let mut class_name = [0_u16; 16];
    let copied = unsafe {
        GetClassNameW(
            window,
            class_name.as_mut_ptr(),
            i32::try_from(class_name.len()).unwrap_or(i32::MAX),
        )
    };
    if usize::try_from(copied).ok() == Some(DIALOG_CLASS_NAME.len())
        && &class_name[..DIALOG_CLASS_NAME.len()] == DIALOG_CLASS_NAME
    {
        search.found = window;
        return 0;
    }
    1
}

fn window_process_id(window: HWND) -> io::Result<u32> {
    let mut process_id = 0_u32;
    if unsafe { GetWindowThreadProcessId(window, &mut process_id) } == 0 || process_id == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(process_id)
}

struct ContractProcess {
    child: Child,
    job: TestJob,
    terminal: bool,
}

impl ContractProcess {
    fn spawn() -> io::Result<Self> {
        let executable = Path::new(env!("CARGO_BIN_EXE_your-cloud-native-bootstrap-assistant"));
        let mut command = Command::new(executable);
        command
            .arg(REQUIRED_MODE_ARGUMENT)
            .current_dir(executable.parent().ok_or_else(invalid_data)?)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW);

        let job = TestJob::new()?;
        let mut child = command.spawn()?;
        if let Err(error) = job.assign(&child) {
            let _ = child.kill();
            let _ = wait_child_bounded(&mut child, CLEANUP_TIMEOUT);
            return Err(error);
        }
        Ok(Self {
            child,
            job,
            terminal: false,
        })
    }

    fn process_id(&self) -> u32 {
        self.child.id()
    }

    fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin.take()
    }

    fn wait_bounded(&mut self, timeout: Duration) -> io::Result<ExitStatus> {
        let status = wait_child_bounded(&mut self.child, timeout)?;
        self.terminal = true;
        Ok(status)
    }

    fn terminate_and_reap(&mut self) -> io::Result<()> {
        self.job.terminate()?;
        self.wait_bounded(CLEANUP_TIMEOUT).map(|_| ())
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
        let _ = self.job.terminate();
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
                "helper child did not terminate before the process deadline",
            ));
        }
        thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

struct TestJob {
    handle: OwnedHandle,
    terminated: bool,
}

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

impl Drop for TestJob {
    fn drop(&mut self) {
        if !self.terminated {
            let _ = unsafe { TerminateJobObject(self.handle.as_raw_handle(), FORCED_EXIT_CODE) };
        }
    }
}

fn owned_handle(handle: *mut c_void) -> io::Result<OwnedHandle> {
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn invalid_data() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid Win32 prompt contract value",
    )
}
