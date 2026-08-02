#![cfg(target_os = "windows")]

use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read},
    mem::{size_of, size_of_val},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle},
    },
    path::Path,
    ptr::{null, null_mut},
    time::Duration,
};

use windows_sys::Win32::{
    Foundation::{
        GetHandleInformation, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT,
        INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
            JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        Pipes::{CreatePipe, GetNamedPipeClientProcessId},
        Threading::{
            CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetCurrentProcessId,
            GetExitCodeProcess, InitializeProcThreadAttributeList, ResumeThread, TerminateProcess,
            UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
            CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
        },
    },
};

use your_cloud_native_bootstrap_assistant::EXIT_INTERNAL_FAILURE;

const CONTRACT_TIMEOUT: Duration = Duration::from_secs(5);
const CLEANUP_TIMEOUT: Duration = Duration::from_millis(500);
const FORCED_EXIT_CODE: u32 = 0xe045_5943;
const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;

#[link(name = "kernel32")]
extern "system" {
    fn DuplicateHandle(
        source_process: HANDLE,
        source: HANDLE,
        target_process: HANDLE,
        target: *mut HANDLE,
        desired_access: u32,
        inherit: i32,
        options: u32,
    ) -> i32;
}

#[test]
fn declared_parent_cannot_authorize_an_attacker_owned_pipe() {
    let fixture = Path::new(env!("CARGO_BIN_EXE_your-cloud-parent-spoof-fixture"));
    let working_directory = fixture.parent().expect("fixture directory");
    let mut job = TestJob::new().expect("private cleanup job");
    let mut declared_parent =
        create_suspended_parent(fixture, working_directory).expect("suspended declared parent");
    job.assign(&declared_parent)
        .expect("declared parent assigned to cleanup job");

    let HostileLaunch {
        mut process,
        attacker_stdin,
        mut stdout,
        mut stderr,
        pipe_client_pid,
    } = create_hostile_child(fixture, working_directory, declared_parent.process_handle())
        .expect("hostile child with declared parent");
    job.ensure_assigned(&process)
        .expect("hostile child assigned to cleanup job");

    assert_eq!(
        observed_parent_pid(process.process_id()).expect("observable hostile child parent"),
        declared_parent.process_id(),
        "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS must create the forged OS parent relation",
    );
    assert_eq!(
        pipe_client_pid,
        unsafe { GetCurrentProcessId() },
        "the stdin pipe client must be the attacker B, not declared parent A",
    );
    assert_ne!(pipe_client_pid, declared_parent.process_id());
    assert_eq!(
        unsafe { WaitForSingleObject(declared_parent.process_handle(), 0) },
        WAIT_TIMEOUT,
        "the declared parent must remain alive while the verifier runs",
    );

    process.resume().expect("hostile child resumed once");
    let exit_code = match process.wait_bounded(CONTRACT_TIMEOUT) {
        Ok(exit_code) => exit_code,
        Err(error) => {
            let _ = job.terminate();
            let _ = process.wait_bounded(CLEANUP_TIMEOUT);
            panic!("hostile verifier did not terminate in time: {error}");
        }
    };
    drop(attacker_stdin);

    assert_eq!(
        exit_code,
        u32::from(EXIT_INTERNAL_FAILURE),
        "the forged parent relation must not authenticate the attacker-owned pipe",
    );
    job.terminate().expect("cleanup job terminated");
    declared_parent
        .wait_bounded(CLEANUP_TIMEOUT)
        .expect("declared parent reaped after bounded job termination");

    let mut stdout_bytes = Vec::new();
    stdout.read_to_end(&mut stdout_bytes).unwrap();
    let mut stderr_bytes = Vec::new();
    stderr.read_to_end(&mut stderr_bytes).unwrap();

    assert!(stdout_bytes.is_empty());
    assert!(stderr_bytes.is_empty());
}

struct HostileLaunch {
    process: ProcessGuard,
    attacker_stdin: File,
    stdout: File,
    stderr: File,
    pipe_client_pid: u32,
}

fn create_suspended_parent(fixture: &Path, working_directory: &Path) -> io::Result<ProcessGuard> {
    let application = wide_null(fixture.as_os_str())?;
    let mut command_line = quoted_command_line(fixture)?;
    let current_directory = wide_null(working_directory.as_os_str())?;
    let environment = [0_u16, 0_u16];
    let mut startup = STARTUPINFOW {
        cb: u32::try_from(size_of::<STARTUPINFOW>()).map_err(|_| invalid_data())?,
        ..STARTUPINFOW::default()
    };
    let mut information = PROCESS_INFORMATION::default();
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            0,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            environment.as_ptr().cast(),
            current_directory.as_ptr(),
            &mut startup,
            &mut information,
        )
    };
    if created == 0 {
        return Err(io::Error::last_os_error());
    }
    ProcessGuard::from_information(information)
}

fn create_hostile_child(
    fixture: &Path,
    working_directory: &Path,
    declared_parent: HANDLE,
) -> io::Result<HostileLaunch> {
    let stdin = PipePair::for_child_stdin()?;
    let stdout = PipePair::for_child_stdout()?;
    let stderr = PipePair::for_child_stdout()?;
    let attacker_handles = [
        stdin.child.as_raw_handle(),
        stdout.child.as_raw_handle(),
        stderr.child.as_raw_handle(),
    ];
    let pipe_client_pid = named_pipe_client_pid(attacker_handles[0])?;
    for handle in attacker_handles {
        if !handle_is_inheritable(handle)? {
            return Err(invalid_data());
        }
    }
    // PARENT_PROCESS makes Windows inherit handles from A's handle table, not
    // from the creating attacker B. Duplicate only the child ends into A; the
    // stdin client/writer remains exclusively in B, which preserves the hostile
    // peer identity observed by GetNamedPipeClientProcessId inside C.
    let inherited_handles = [
        duplicate_into_declared_parent(attacker_handles[0], declared_parent)?,
        duplicate_into_declared_parent(attacker_handles[1], declared_parent)?,
        duplicate_into_declared_parent(attacker_handles[2], declared_parent)?,
    ];

    let parent_attribute = declared_parent;
    let mut attributes = ProcThreadAttributeList::new(2)?;
    attributes.update(
        usize::try_from(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS).map_err(|_| invalid_data())?,
        (&parent_attribute as *const HANDLE).cast(),
        size_of::<HANDLE>(),
    )?;
    attributes.update(
        usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST).map_err(|_| invalid_data())?,
        inherited_handles.as_ptr().cast(),
        size_of_val(&inherited_handles),
    )?;

    let application = wide_null(fixture.as_os_str())?;
    let mut command_line = quoted_command_line(fixture)?;
    let current_directory = wide_null(working_directory.as_os_str())?;
    let environment = [0_u16, 0_u16];
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb =
        u32::try_from(size_of::<STARTUPINFOEXW>()).map_err(|_| invalid_data())?;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = inherited_handles[0];
    startup.StartupInfo.hStdOutput = inherited_handles[1];
    startup.StartupInfo.hStdError = inherited_handles[2];
    startup.lpAttributeList = attributes.as_mut_ptr();

    let mut information = PROCESS_INFORMATION::default();
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | CREATE_NO_WINDOW
                | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            current_directory.as_ptr(),
            &startup.StartupInfo,
            &mut information,
        )
    };
    if created == 0 {
        return Err(io::Error::last_os_error());
    }
    let process = ProcessGuard::from_information(information)?;

    drop(attributes);
    drop(stdin.child);
    drop(stdout.child);
    drop(stderr.child);
    Ok(HostileLaunch {
        process,
        attacker_stdin: stdin.attacker,
        stdout: stdout.attacker,
        stderr: stderr.attacker,
        pipe_client_pid,
    })
}

fn duplicate_into_declared_parent(source: HANDLE, declared_parent: HANDLE) -> io::Result<HANDLE> {
    let current_process = unsafe { GetCurrentProcess() };
    let mut remote_handle = null_mut();
    if unsafe {
        DuplicateHandle(
            current_process,
            source,
            declared_parent,
            &mut remote_handle,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
        || remote_handle.is_null()
        || remote_handle == INVALID_HANDLE_VALUE
    {
        return Err(io::Error::last_os_error());
    }
    Ok(remote_handle)
}

fn named_pipe_client_pid(handle: HANDLE) -> io::Result<u32> {
    if unsafe { GetFileType(handle) } != FILE_TYPE_PIPE {
        return Err(invalid_data());
    }
    let mut process_id = 0_u32;
    if unsafe { GetNamedPipeClientProcessId(handle, &mut process_id) } == 0 || process_id == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(process_id)
}

struct PipePair {
    child: OwnedHandle,
    attacker: File,
}

impl PipePair {
    fn for_child_stdin() -> io::Result<Self> {
        let (read, write) = inheritable_pipe()?;
        clear_inheritance(&write)?;
        Ok(Self {
            child: read,
            attacker: owned_handle_into_file(write),
        })
    }

    fn for_child_stdout() -> io::Result<Self> {
        let (read, write) = inheritable_pipe()?;
        clear_inheritance(&read)?;
        Ok(Self {
            child: write,
            attacker: owned_handle_into_file(read),
        })
    }
}

fn inheritable_pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let mut security = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).map_err(|_| invalid_data())?,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let mut read = null_mut();
    let mut write = null_mut();
    if unsafe { CreatePipe(&mut read, &mut write, &mut security, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((owned_handle(read)?, owned_handle(write)?))
}

fn clear_inheritance(handle: &OwnedHandle) -> io::Result<()> {
    if unsafe { SetHandleInformation(handle.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if handle_is_inheritable(handle.as_raw_handle())? {
        return Err(invalid_data());
    }
    Ok(())
}

fn handle_is_inheritable(handle: HANDLE) -> io::Result<bool> {
    let mut flags = 0_u32;
    if unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags & HANDLE_FLAG_INHERIT != 0)
}

struct ProcThreadAttributeList {
    storage: Vec<usize>,
    initialized: bool,
}

impl ProcThreadAttributeList {
    fn new(attribute_count: u32) -> io::Result<Self> {
        let mut bytes = 0_usize;
        let _ = unsafe {
            InitializeProcThreadAttributeList(null_mut(), attribute_count, 0, &mut bytes)
        };
        if bytes == 0 {
            return Err(io::Error::last_os_error());
        }
        let words = bytes
            .checked_add(size_of::<usize>() - 1)
            .and_then(|size| size.checked_div(size_of::<usize>()))
            .ok_or_else(invalid_data)?;
        let mut list = Self {
            storage: vec![0_usize; words],
            initialized: false,
        };
        if unsafe {
            InitializeProcThreadAttributeList(list.as_mut_ptr(), attribute_count, 0, &mut bytes)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        list.initialized = true;
        Ok(list)
    }

    fn update(
        &mut self,
        attribute: usize,
        value: *const core::ffi::c_void,
        value_bytes: usize,
    ) -> io::Result<()> {
        if unsafe {
            UpdateProcThreadAttribute(
                self.as_mut_ptr(),
                0,
                attribute,
                value,
                value_bytes,
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn as_mut_ptr(&mut self) -> *mut core::ffi::c_void {
        self.storage.as_mut_ptr().cast()
    }
}

impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        if self.initialized {
            unsafe { DeleteProcThreadAttributeList(self.as_mut_ptr()) };
        }
    }
}

struct ProcessGuard {
    process: OwnedHandle,
    thread: Option<OwnedHandle>,
    process_id: u32,
    terminal: bool,
}

impl ProcessGuard {
    fn from_information(information: PROCESS_INFORMATION) -> io::Result<Self> {
        let process = owned_handle(information.hProcess)?;
        let thread = match owned_handle(information.hThread) {
            Ok(thread) => thread,
            Err(error) => {
                let _ = unsafe { TerminateProcess(process.as_raw_handle(), FORCED_EXIT_CODE) };
                let _ = unsafe {
                    WaitForSingleObject(process.as_raw_handle(), duration_millis(CLEANUP_TIMEOUT))
                };
                return Err(error);
            }
        };
        Ok(Self {
            process,
            thread: Some(thread),
            process_id: information.dwProcessId,
            terminal: false,
        })
    }

    fn process_handle(&self) -> HANDLE {
        self.process.as_raw_handle()
    }

    fn process_id(&self) -> u32 {
        self.process_id
    }

    fn resume(&mut self) -> io::Result<()> {
        let thread = self.thread.as_ref().ok_or_else(invalid_data)?;
        if unsafe { ResumeThread(thread.as_raw_handle()) } != 1 {
            return Err(io::Error::last_os_error());
        }
        drop(self.thread.take());
        Ok(())
    }

    fn wait_bounded(&mut self, timeout: Duration) -> io::Result<u32> {
        match unsafe { WaitForSingleObject(self.process_handle(), duration_millis(timeout)) } {
            WAIT_OBJECT_0 => {
                self.terminal = true;
                let mut exit_code = 0_u32;
                if unsafe { GetExitCodeProcess(self.process_handle(), &mut exit_code) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(exit_code)
            }
            WAIT_TIMEOUT => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "process did not become terminal before its contract deadline",
            )),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if self.terminal {
            return;
        }
        let _ = unsafe { TerminateProcess(self.process_handle(), FORCED_EXIT_CODE) };
        if unsafe { WaitForSingleObject(self.process_handle(), duration_millis(CLEANUP_TIMEOUT)) }
            == WAIT_OBJECT_0
        {
            self.terminal = true;
        }
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
                u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
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

    fn assign(&self, process: &ProcessGuard) -> io::Result<()> {
        if unsafe {
            AssignProcessToJobObject(self.handle.as_raw_handle(), process.process_handle())
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn ensure_assigned(&self, process: &ProcessGuard) -> io::Result<()> {
        let mut belongs = 0;
        if unsafe {
            IsProcessInJob(
                process.process_handle(),
                self.handle.as_raw_handle(),
                &mut belongs,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if belongs == 0 {
            self.assign(process)?;
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

fn observed_parent_pid(process_id: u32) -> io::Result<u32> {
    let snapshot = owned_handle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })?;
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(size_of::<PROCESSENTRY32W>()).map_err(|_| invalid_data())?,
        ..PROCESSENTRY32W::default()
    };
    if unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) } == 0 {
        return Err(io::Error::last_os_error());
    }
    loop {
        if entry.th32ProcessID == process_id {
            return Ok(entry.th32ParentProcessID);
        }
        if unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "hostile child absent from the process snapshot",
            ));
        }
    }
}

fn owned_handle(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn owned_handle_into_file(handle: OwnedHandle) -> File {
    unsafe { File::from_raw_handle(handle.into_raw_handle()) }
}

fn wide_null(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut encoded = value.encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(invalid_data());
    }
    encoded.push(0);
    Ok(encoded)
}

fn quoted_command_line(path: &Path) -> io::Result<Vec<u16>> {
    let mut command = OsString::from("\"");
    command.push(path.as_os_str());
    command.push("\"");
    wide_null(&command)
}

fn duration_millis(duration: Duration) -> u32 {
    u32::try_from(duration.as_millis()).unwrap_or(u32::MAX - 1)
}

fn invalid_data() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid Win32 contract value")
}
