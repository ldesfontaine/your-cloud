use std::{
    env,
    ffi::{OsStr, OsString},
    fs::File,
    io,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle},
        process::ExitStatusExt,
    },
    path::Path,
    process::ExitStatus,
    ptr::{null, null_mut},
    sync::atomic::{AtomicBool, Ordering},
};

#[cfg(feature = "windows-contract-test")]
use std::sync::atomic::AtomicU8;

use windows_sys::Win32::{
    Foundation::{
        GetHandleInformation, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT,
        INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    },
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
            JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
            QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        Pipes::CreatePipe,
        Threading::{
            CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
            InitializeProcThreadAttributeList, ResumeThread, TerminateProcess,
            UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
            CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
        },
    },
};

use super::{NativeHelperError, KILL_REAP_GRACE};

const TERMINATED_EXIT_CODE: u32 = 1;
const MAX_WINDOWS_COMMAND_LINE_UNITS: usize = 32_767;
static WINDOWS_CLEANUP_UNPROVEN: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "windows-contract-test")]
static WINDOWS_SPAWN_FAULT: AtomicU8 = AtomicU8::new(0);

#[cfg(feature = "windows-contract-test")]
static WINDOWS_FORCE_CLEANUP_OBSERVATION_UNPROVEN: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "windows-contract-test")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum WindowsSpawnFault {
    AfterCreate = 1,
    AfterAssign = 2,
    BeforeResume = 3,
    CleanupObservationUnprovenBeforeResume = 4,
}

#[cfg(feature = "windows-contract-test")]
pub(super) fn inject_spawn_fault(fault: WindowsSpawnFault) {
    assert_eq!(
        WINDOWS_SPAWN_FAULT.swap(fault as u8, Ordering::SeqCst),
        0,
        "one Windows spawn fault may be active at a time"
    );
}

#[cfg(feature = "windows-contract-test")]
pub(super) fn cleanup_is_unproven() -> bool {
    WINDOWS_CLEANUP_UNPROVEN.load(Ordering::SeqCst)
}

#[cfg(feature = "windows-contract-test")]
fn take_spawn_fault(fault: WindowsSpawnFault) -> bool {
    WINDOWS_SPAWN_FAULT
        .compare_exchange(fault as u8, 0, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

pub(super) type WindowsChildStdout = File;

pub(super) struct WindowsChild {
    process: OwnedHandle,
    job: OwnedHandle,
    stdin: Option<File>,
    stdout: Option<File>,
}

impl WindowsChild {
    pub(super) fn take_stdin(&mut self) -> Option<File> {
        self.stdin.take()
    }

    pub(super) fn take_stdout(&mut self) -> Option<File> {
        self.stdout.take()
    }

    /// A terminal root is not enough: the session becomes terminal only once the Job contains
    /// no descendant either.
    pub(super) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        // SAFETY: both handles are owned by self and remain open for every Win32 call below.
        let wait = unsafe { WaitForSingleObject(self.process_handle(), 0) };
        match wait {
            WAIT_TIMEOUT => return Ok(None),
            WAIT_OBJECT_0 => {}
            _ => return Err(io::Error::last_os_error()),
        }

        if self.active_processes()? != 0 {
            return Ok(None);
        }

        let mut exit_code = 0_u32;
        if unsafe { GetExitCodeProcess(self.process_handle(), &mut exit_code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(ExitStatus::from_raw(exit_code)))
    }

    pub(super) fn terminate_tree(&mut self) -> io::Result<()> {
        if self.active_processes()? == 0 {
            return Ok(());
        }
        // SAFETY: the Job handle is owned by self and the exit code carries no application data.
        if unsafe { TerminateJobObject(self.job_handle(), TERMINATED_EXIT_CODE) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn active_processes(&self) -> io::Result<u32> {
        query_active_processes(self.job_handle())
    }

    fn process_handle(&self) -> HANDLE {
        self.process.as_raw_handle()
    }

    fn job_handle(&self) -> HANDLE {
        self.job.as_raw_handle()
    }
}

fn query_active_processes(job: HANDLE) -> io::Result<u32> {
    let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    let size = u32::try_from(size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    // SAFETY: job remains owned by the caller and accounting is a correctly sized writable
    // Job accounting structure.
    if unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(accounting.ActiveProcesses)
}

impl Drop for WindowsChild {
    fn drop(&mut self) {
        // Drop is only a last-resort kill. Callers must use the bounded stop path before they
        // claim that the root and every descendant were collected.
        if !terminate_job_and_observe(self.process_handle(), self.job_handle()) {
            WINDOWS_CLEANUP_UNPROVEN.store(true, Ordering::SeqCst);
        }
    }
}

pub(super) fn spawn_helper_process(
    path: &Path,
    working_directory: &Path,
    required_argument: &str,
) -> Result<WindowsChild, NativeHelperError> {
    if WINDOWS_CLEANUP_UNPROVEN.load(Ordering::SeqCst) {
        return Err(NativeHelperError::Unavailable);
    }
    let application = wide_null(path.as_os_str())?;
    let current_directory = wide_null(working_directory.as_os_str())?;
    let mut command_line = fixed_command_line(required_argument)?;
    let environment = public_environment_block()?;

    let job = configured_job()?;
    let stdin = PipePair::for_child_stdin()?;
    let stdout = PipePair::for_child_stdout()?;
    let stderr = inherited_null_stderr()?;
    let inherited_handles = [
        stdin.child.as_raw_handle(),
        stdout.child.as_raw_handle(),
        stderr.as_raw_handle(),
    ];
    for handle in inherited_handles {
        if !handle_is_inheritable(handle)? {
            return Err(NativeHelperError::Unavailable);
        }
    }
    let mut attributes = ProcThreadAttributeList::with_handle_list(&inherited_handles)?;

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb =
        u32::try_from(size_of::<STARTUPINFOEXW>()).map_err(|_| NativeHelperError::Unavailable)?;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = inherited_handles[0];
    startup.StartupInfo.hStdOutput = inherited_handles[1];
    startup.StartupInfo.hStdError = inherited_handles[2];
    startup.lpAttributeList = attributes.as_mut_ptr();

    let mut process_information = PROCESS_INFORMATION::default();
    let creation_flags = CREATE_SUSPENDED
        | CREATE_UNICODE_ENVIRONMENT
        | EXTENDED_STARTUPINFO_PRESENT
        | CREATE_NO_WINDOW;
    // SAFETY: all UTF-16 buffers, stdio handles and the initialized attribute list outlive this
    // call; PROCESS_INFORMATION is writable and inheritance is restricted by HANDLE_LIST.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            1,
            creation_flags,
            environment.as_ptr().cast(),
            current_directory.as_ptr(),
            &startup.StartupInfo,
            &mut process_information,
        )
    };
    if created == 0 {
        return Err(NativeHelperError::Unavailable);
    }

    let process = owned_handle(process_information.hProcess)?;
    let thread = match owned_handle(process_information.hThread) {
        Ok(thread) => thread,
        Err(error) => {
            let _ = unsafe { TerminateProcess(process.as_raw_handle(), TERMINATED_EXIT_CODE) };
            let timeout = u32::try_from(KILL_REAP_GRACE.as_millis()).unwrap_or(u32::MAX - 1);
            if unsafe { WaitForSingleObject(process.as_raw_handle(), timeout) } != WAIT_OBJECT_0 {
                WINDOWS_CLEANUP_UNPROVEN.store(true, Ordering::SeqCst);
            }
            return Err(error);
        }
    };
    let mut suspended = SuspendedProcess::new(process, thread, job);

    #[cfg(feature = "windows-contract-test")]
    if take_spawn_fault(WindowsSpawnFault::AfterCreate) {
        return Err(NativeHelperError::Unavailable);
    }

    // SAFETY: the process is still suspended and both owned handles remain valid.
    if unsafe { AssignProcessToJobObject(suspended.job_handle(), suspended.process_handle()) } == 0
    {
        return Err(NativeHelperError::Unavailable);
    }
    suspended.assigned = true;

    #[cfg(feature = "windows-contract-test")]
    if take_spawn_fault(WindowsSpawnFault::AfterAssign) {
        return Err(NativeHelperError::Unavailable);
    }

    let mut belongs_to_job = 0;
    // SAFETY: the BOOL output is writable and both handles remain owned by suspended.
    if unsafe {
        IsProcessInJob(
            suspended.process_handle(),
            suspended.job_handle(),
            &mut belongs_to_job,
        )
    } == 0
        || belongs_to_job == 0
    {
        return Err(NativeHelperError::Unavailable);
    }

    #[cfg(feature = "windows-contract-test")]
    if take_spawn_fault(WindowsSpawnFault::BeforeResume) {
        return Err(NativeHelperError::Unavailable);
    }

    #[cfg(feature = "windows-contract-test")]
    if take_spawn_fault(WindowsSpawnFault::CleanupObservationUnprovenBeforeResume) {
        // SuspendedProcess::drop still performs the real termination and bounded observations.
        // The test hook changes only the final observation result so the production Drop branch
        // remains responsible for poisoning every later launch.
        WINDOWS_FORCE_CLEANUP_OBSERVATION_UNPROVEN.store(true, Ordering::SeqCst);
        return Err(NativeHelperError::Unavailable);
    }

    // CREATE_SUSPENDED creates one suspension level. Any other previous count means the thread
    // either ran before this boundary or would remain suspended, so the Job is killed closed.
    // SAFETY: the primary thread handle is valid and has not been resumed before this point.
    if unsafe { ResumeThread(suspended.thread_handle()) } != 1 {
        return Err(NativeHelperError::Unavailable);
    }

    drop(attributes);
    drop(stdin.child);
    drop(stdout.child);
    drop(stderr);
    Ok(suspended.into_child(stdin.parent, stdout.parent))
}

fn configured_job() -> Result<OwnedHandle, NativeHelperError> {
    // SAFETY: null attributes and name request a private, non-inheritable unnamed Job.
    let handle = unsafe { CreateJobObjectW(null(), null()) };
    let job = owned_handle(handle)?;
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let size = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
        .map_err(|_| NativeHelperError::Unavailable)?;
    // SAFETY: limits is a correctly sized immutable extended-limit structure.
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size,
        )
    } == 0
    {
        return Err(NativeHelperError::Unavailable);
    }
    let mut confirmed = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    // SAFETY: confirmed is a correctly sized writable extended-limit structure.
    if unsafe {
        QueryInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&mut confirmed as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size,
            null_mut(),
        )
    } == 0
        || confirmed.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0
    {
        return Err(NativeHelperError::Unavailable);
    }
    Ok(job)
}

struct PipePair {
    child: OwnedHandle,
    parent: File,
}

impl PipePair {
    fn for_child_stdin() -> Result<Self, NativeHelperError> {
        let (read, write) = inheritable_pipe()?;
        clear_inheritance(&write)?;
        Ok(Self {
            child: read,
            parent: owned_handle_into_file(write),
        })
    }

    fn for_child_stdout() -> Result<Self, NativeHelperError> {
        let (read, write) = inheritable_pipe()?;
        clear_inheritance(&read)?;
        Ok(Self {
            child: write,
            parent: owned_handle_into_file(read),
        })
    }
}

fn inheritable_pipe() -> Result<(OwnedHandle, OwnedHandle), NativeHelperError> {
    let mut security = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| NativeHelperError::Unavailable)?,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let mut read = null_mut();
    let mut write = null_mut();
    // SAFETY: both outputs and SECURITY_ATTRIBUTES are initialized writable storage.
    if unsafe { CreatePipe(&mut read, &mut write, &mut security, 0) } == 0 {
        return Err(NativeHelperError::Unavailable);
    }
    Ok((owned_handle(read)?, owned_handle(write)?))
}

fn inherited_null_stderr() -> Result<OwnedHandle, NativeHelperError> {
    let mut security = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| NativeHelperError::Unavailable)?,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let name = wide_null(OsStr::new("NUL"))?;
    // SAFETY: name and SECURITY_ATTRIBUTES outlive the call; a null template handle is valid.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &mut security,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    owned_handle(handle)
}

fn clear_inheritance(handle: &OwnedHandle) -> Result<(), NativeHelperError> {
    // SAFETY: handle is owned and remains open throughout the flag update and verification.
    if unsafe { SetHandleInformation(handle.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(NativeHelperError::Unavailable);
    }
    if handle_is_inheritable(handle.as_raw_handle())? {
        return Err(NativeHelperError::Unavailable);
    }
    Ok(())
}

fn handle_is_inheritable(handle: HANDLE) -> Result<bool, NativeHelperError> {
    let mut flags = 0_u32;
    if unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
        return Err(NativeHelperError::Unavailable);
    }
    Ok(flags & HANDLE_FLAG_INHERIT != 0)
}

fn owned_handle(handle: HANDLE) -> Result<OwnedHandle, NativeHelperError> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(NativeHelperError::Unavailable);
    }
    // SAFETY: successful Win32 creators return a new handle whose ownership transfers here.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn owned_handle_into_file(handle: OwnedHandle) -> File {
    // SAFETY: ownership is transferred exactly once from OwnedHandle to File.
    unsafe { File::from_raw_handle(handle.into_raw_handle()) }
}

struct ProcThreadAttributeList {
    storage: Vec<usize>,
    initialized: bool,
}

impl ProcThreadAttributeList {
    fn with_handle_list(handles: &[HANDLE; 3]) -> Result<Self, NativeHelperError> {
        let mut bytes = 0_usize;
        // SAFETY: a null first argument is the documented size query; bytes is writable.
        let _ = unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut bytes) };
        if bytes == 0 {
            return Err(NativeHelperError::Unavailable);
        }
        let words = bytes
            .checked_add(size_of::<usize>() - 1)
            .and_then(|size| size.checked_div(size_of::<usize>()))
            .ok_or(NativeHelperError::Unavailable)?;
        let mut list = Self {
            storage: vec![0_usize; words],
            initialized: false,
        };
        // SAFETY: storage is aligned, sized from the preceding query and remains pinned in list.
        if unsafe { InitializeProcThreadAttributeList(list.as_mut_ptr(), 1, 0, &mut bytes) } == 0 {
            return Err(NativeHelperError::Unavailable);
        }
        list.initialized = true;

        let handles_size = handles
            .len()
            .checked_mul(size_of::<HANDLE>())
            .ok_or(NativeHelperError::Unavailable)?;
        // SAFETY: handles is an exact three-element array kept alive until CreateProcessW, and
        // list was initialized for one attribute.
        if unsafe {
            UpdateProcThreadAttribute(
                list.as_mut_ptr(),
                0,
                usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)
                    .map_err(|_| NativeHelperError::Unavailable)?,
                handles.as_ptr().cast(),
                handles_size,
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(NativeHelperError::Unavailable);
        }
        Ok(list)
    }

    fn as_mut_ptr(&mut self) -> *mut core::ffi::c_void {
        self.storage.as_mut_ptr().cast()
    }
}

impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: the list was initialized once and its backing storage is still alive.
            unsafe { DeleteProcThreadAttributeList(self.as_mut_ptr()) };
        }
    }
}

struct SuspendedProcess {
    process: Option<OwnedHandle>,
    thread: Option<OwnedHandle>,
    job: Option<OwnedHandle>,
    assigned: bool,
    resumed: bool,
}

impl SuspendedProcess {
    fn new(process: OwnedHandle, thread: OwnedHandle, job: OwnedHandle) -> Self {
        Self {
            process: Some(process),
            thread: Some(thread),
            job: Some(job),
            assigned: false,
            resumed: false,
        }
    }

    fn process_handle(&self) -> HANDLE {
        self.process
            .as_ref()
            .expect("suspended process owns process handle")
            .as_raw_handle()
    }

    fn thread_handle(&self) -> HANDLE {
        self.thread
            .as_ref()
            .expect("suspended process owns thread handle")
            .as_raw_handle()
    }

    fn job_handle(&self) -> HANDLE {
        self.job
            .as_ref()
            .expect("suspended process owns job handle")
            .as_raw_handle()
    }

    fn into_child(mut self, stdin: File, stdout: File) -> WindowsChild {
        self.resumed = true;
        drop(self.thread.take());
        WindowsChild {
            process: self
                .process
                .take()
                .expect("resumed process owns process handle"),
            job: self.job.take().expect("resumed process owns job handle"),
            stdin: Some(stdin),
            stdout: Some(stdout),
        }
    }
}

impl Drop for SuspendedProcess {
    fn drop(&mut self) {
        if self.resumed {
            return;
        }
        if self.assigned {
            if !terminate_job_and_observe(self.process_handle(), self.job_handle()) {
                WINDOWS_CLEANUP_UNPROVEN.store(true, Ordering::SeqCst);
            }
        } else {
            // SAFETY: before assignment, only the suspended root needs direct termination.
            let _ = unsafe { TerminateProcess(self.process_handle(), TERMINATED_EXIT_CODE) };
            let timeout = u32::try_from(KILL_REAP_GRACE.as_millis()).unwrap_or(u32::MAX - 1);
            if unsafe { WaitForSingleObject(self.process_handle(), timeout) } != WAIT_OBJECT_0 {
                WINDOWS_CLEANUP_UNPROVEN.store(true, Ordering::SeqCst);
            }
        }
    }
}

fn terminate_job_and_observe(process: HANDLE, job: HANDLE) -> bool {
    // Termination itself is asynchronous. The proof is the signalled root plus an empty Job;
    // either failed observation poisons every later launch in this App process.
    // SAFETY: both handles remain owned by the caller for the whole bounded observation.
    let _ = unsafe { TerminateJobObject(job, TERMINATED_EXIT_CODE) };
    let timeout = u32::try_from(KILL_REAP_GRACE.as_millis()).unwrap_or(u32::MAX - 1);
    let root_reaped = unsafe { WaitForSingleObject(process, timeout) } == WAIT_OBJECT_0;
    let job_empty = matches!(query_active_processes(job), Ok(0));
    #[cfg(feature = "windows-contract-test")]
    if WINDOWS_FORCE_CLEANUP_OBSERVATION_UNPROVEN.swap(false, Ordering::SeqCst) {
        return false;
    }
    root_reaped && job_empty
}

fn fixed_command_line(required_argument: &str) -> Result<Vec<u16>, NativeHelperError> {
    if required_argument.is_empty()
        || required_argument
            .chars()
            .any(|character| character == '\0' || character == '"' || character.is_whitespace())
    {
        return Err(NativeHelperError::Unavailable);
    }
    let command = format!("\"your-cloud-native-bootstrap-assistant.exe\" {required_argument}");
    wide_null(OsStr::new(&command))
}

fn public_environment_block() -> Result<Vec<u16>, NativeHelperError> {
    let mut entries = Vec::<(OsString, OsString)>::new();
    for name in [
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    ] {
        if let Some(value) = env::var_os(name).filter(|value| !value.is_empty()) {
            entries.push((OsString::from(name), value));
        }
    }
    entries.sort_by(|left, right| {
        left.0
            .to_string_lossy()
            .to_ascii_lowercase()
            .cmp(&right.0.to_string_lossy().to_ascii_lowercase())
    });

    let mut block = Vec::new();
    for (name, value) in entries {
        append_wide_without_nul(&mut block, &name)?;
        block.push(u16::from(b'='));
        append_wide_without_nul(&mut block, &value)?;
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn append_wide_without_nul(
    destination: &mut Vec<u16>,
    value: &OsStr,
) -> Result<(), NativeHelperError> {
    for unit in value.encode_wide() {
        if unit == 0 {
            return Err(NativeHelperError::Unavailable);
        }
        destination.push(unit);
    }
    Ok(())
}

fn wide_null(value: &OsStr) -> Result<Vec<u16>, NativeHelperError> {
    let mut wide = Vec::new();
    append_wide_without_nul(&mut wide, value)?;
    if wide.len() >= MAX_WINDOWS_COMMAND_LINE_UNITS {
        return Err(NativeHelperError::Unavailable);
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_contains_only_the_fixed_helper_mode() {
        let command = fixed_command_line("--native-bootstrap-assistant").unwrap();
        assert_eq!(
            String::from_utf16(&command[..command.len() - 1]).unwrap(),
            "\"your-cloud-native-bootstrap-assistant.exe\" --native-bootstrap-assistant"
        );
        assert_eq!(
            fixed_command_line("--native-bootstrap-assistant extra"),
            Err(NativeHelperError::Unavailable)
        );
    }

    #[test]
    fn environment_block_is_double_terminated() {
        let environment = public_environment_block().unwrap();
        assert!(environment.len() >= 2);
        assert_eq!(&environment[environment.len() - 2..], &[0, 0]);
    }
}
