#[cfg(target_os = "windows")]
use std::{
    env,
    ffi::OsString,
    fs,
    io::{BufRead, BufReader, Write},
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    ptr::null_mut,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::{GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE},
    Security::SECURITY_ATTRIBUTES,
    System::{
        Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
        Pipes::CreatePipe,
    },
};

#[cfg(target_os = "windows")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeHelperError {
    Unavailable,
}

#[cfg(target_os = "windows")]
const KILL_REAP_GRACE: Duration = Duration::from_millis(500);

#[cfg(target_os = "windows")]
#[path = "../../../src/native_helper/windows.rs"]
mod windows;

#[cfg(target_os = "windows")]
#[path = "../src/hardening.rs"]
mod hardening;

#[cfg(not(target_os = "windows"))]
fn main() {}

#[cfg(target_os = "windows")]
fn main() {
    match std::env::args().nth(1).as_deref() {
        None => {
            prove_job_contains_and_reaps_a_descendant();
            prove_suspended_failures_never_execute_and_poison_unproven_cleanup();
        }
        Some("--native-bootstrap-assistant") => run_fixture_root(),
        Some("--job-descendant") => loop {
            thread::sleep(Duration::from_secs(1));
        },
        Some(_) => panic!("unexpected Windows Job contract argument"),
    }
}

#[cfg(target_os = "windows")]
fn prove_job_contains_and_reaps_a_descendant() {
    let executable = std::env::current_exe().expect("resolve Windows Job contract executable");
    let working_directory = executable
        .parent()
        .expect("Windows Job contract executable has a parent");
    let marker = fixture_marker(working_directory);
    remove_marker(&marker);

    let hostile_handle = inheritable_sentinel();
    let previous_lang = env::var_os("LANG");
    set_public_lang(hostile_handle.as_raw_handle() as usize);
    let spawn = windows::spawn_native_assistant(
        &executable,
        working_directory,
        "--native-bootstrap-assistant",
    );
    restore_public_lang(previous_lang);
    let mut child = spawn.expect("spawn suspended fixture inside the configured Job");
    drop(hostile_handle);

    let stdout = child.take_stdout().expect("fixture stdout is owned");
    let (line_sender, line_receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = line_sender.send(result);
    });

    let descendant_line = match line_receiver.recv_timeout(Duration::from_secs(2)) {
        Ok(Ok(line)) => line,
        Ok(Err(error)) => {
            let _ = child.terminate_tree();
            panic!("fixture stdout failed: {error}");
        }
        Err(error) => {
            let _ = child.terminate_tree();
            panic!("fixture did not announce its descendant: {error}");
        }
    };
    assert!(
        descendant_line.contains("stdio_inherit=cleared"),
        "the helper must clear inheritance from all three standard handles"
    );
    assert!(
        descendant_line.contains("hostile_handle=absent"),
        "a hostile inheritable handle must be absent from the helper"
    );
    let descendant_pid = descendant_line
        .split(';')
        .find_map(|field| field.strip_prefix("descendant_pid="))
        .expect("fixture announced one descendant PID")
        .parse::<u32>()
        .expect("fixture descendant PID is numeric");
    assert!(descendant_pid > 0);
    assert!(
        marker.is_file(),
        "the nominal suspended fixture must execute"
    );
    assert!(
        child.active_processes().expect("query active Job members") >= 2,
        "the root and its descendant must both belong to the private Job"
    );

    child
        .terminate_tree()
        .expect("terminate every process in the private Job");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait().expect("query bounded Job termination") {
            Some(_) => break,
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            None => panic!("root or descendant survived Job termination"),
        }
    }
    assert_eq!(
        child.active_processes().expect("query empty Job"),
        0,
        "Job termination must leave no descendant"
    );
    reader.join().expect("fixture stdout reader terminated");
    drop(child);
    remove_marker(&marker);
}

#[cfg(target_os = "windows")]
fn prove_suspended_failures_never_execute_and_poison_unproven_cleanup() {
    let executable = env::current_exe().expect("resolve Windows Job contract executable");
    let working_directory = executable
        .parent()
        .expect("Windows Job contract executable has a parent");
    let marker = fixture_marker(working_directory);

    for fault in [
        windows::WindowsSpawnFault::AfterCreate,
        windows::WindowsSpawnFault::AfterAssign,
        windows::WindowsSpawnFault::BeforeResume,
    ] {
        remove_marker(&marker);
        windows::inject_spawn_fault(fault);
        let result = windows::spawn_native_assistant(
            &executable,
            working_directory,
            "--native-bootstrap-assistant",
        );
        assert!(
            matches!(result, Err(NativeHelperError::Unavailable)),
            "injected failure {fault:?} must fail closed"
        );
        assert!(
            !windows::cleanup_is_unproven(),
            "injected failure {fault:?} must terminate and reap within the bound"
        );
        assert!(
            !marker.exists(),
            "injected failure {fault:?} must not execute the suspended fixture"
        );
    }

    remove_marker(&marker);
    windows::inject_spawn_fault(windows::WindowsSpawnFault::CleanupObservationUnprovenBeforeResume);
    let unproven = windows::spawn_native_assistant(
        &executable,
        working_directory,
        "--native-bootstrap-assistant",
    );
    assert!(matches!(unproven, Err(NativeHelperError::Unavailable)));
    assert!(
        windows::cleanup_is_unproven(),
        "an unproven cleanup observation must poison the launch boundary"
    );
    assert!(
        !marker.exists(),
        "the unproven cleanup branch must not execute the suspended fixture"
    );

    let replay = windows::spawn_native_assistant(
        &executable,
        working_directory,
        "--native-bootstrap-assistant",
    );
    assert!(
        matches!(replay, Err(NativeHelperError::Unavailable)),
        "every later launch must remain refused after cleanup is unproven"
    );
    assert!(
        !marker.exists(),
        "the refused replay must not start a process"
    );
}

#[cfg(target_os = "windows")]
fn run_fixture_root() {
    fs::write(
        fixture_marker(&env::current_dir().expect("resolve fixture cwd")),
        b"executed",
    )
    .expect("write fixture execution marker");
    hardening::apply().expect("remove inheritance from standard handles");
    assert_standard_handles_not_inheritable();
    assert_hostile_handle_absent();

    let mut descendant =
        Command::new(std::env::current_exe().expect("resolve Windows Job contract executable"))
            .arg("--job-descendant")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn one descendant that inherits Job membership");
    writeln!(
        std::io::stdout(),
        "descendant_pid={};stdio_inherit=cleared;hostile_handle=absent",
        descendant.id()
    )
    .expect("announce descendant PID and handle proof");
    std::io::stdout().flush().expect("flush descendant PID");
    loop {
        let _ = descendant.try_wait();
        thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(target_os = "windows")]
fn fixture_marker(working_directory: &Path) -> PathBuf {
    working_directory.join("windows-job-contract-ran.marker")
}

#[cfg(target_os = "windows")]
fn remove_marker(marker: &Path) {
    match fs::remove_file(marker) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("remove stale fixture marker: {error}"),
    }
}

#[cfg(target_os = "windows")]
fn inheritable_sentinel() -> OwnedHandle {
    let mut security = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .expect("SECURITY_ATTRIBUTES size fits in u32"),
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let mut read: HANDLE = null_mut();
    let mut write: HANDLE = null_mut();
    assert_ne!(
        unsafe { CreatePipe(&mut read, &mut write, &mut security, 0) },
        0,
        "create hostile inheritable sentinel pipe"
    );
    // SAFETY: CreatePipe returned two new owned handles.
    let read = unsafe { OwnedHandle::from_raw_handle(read) };
    // SAFETY: ownership of the second CreatePipe output transfers exactly once.
    let write = unsafe { OwnedHandle::from_raw_handle(write) };
    drop(read);
    write
}

#[cfg(target_os = "windows")]
fn set_public_lang(raw_handle: usize) {
    // This harness has one orchestrator thread. The value is copied into the explicit child
    // environment before it is restored and never contains user data.
    #[allow(unused_unsafe)]
    unsafe {
        env::set_var("LANG", raw_handle.to_string());
    }
}

#[cfg(target_os = "windows")]
fn restore_public_lang(previous: Option<OsString>) {
    #[allow(unused_unsafe)]
    unsafe {
        match previous {
            Some(value) => env::set_var("LANG", value),
            None => env::remove_var("LANG"),
        }
    }
}

#[cfg(target_os = "windows")]
fn assert_standard_handles_not_inheritable() {
    for (name, standard_handle) in [
        ("stdin", STD_INPUT_HANDLE),
        ("stdout", STD_OUTPUT_HANDLE),
        ("stderr", STD_ERROR_HANDLE),
    ] {
        let handle = unsafe { GetStdHandle(standard_handle) };
        assert!(
            !handle.is_null() && handle != INVALID_HANDLE_VALUE,
            "{name} must be a valid inherited handle"
        );
        let mut flags = 0_u32;
        assert_ne!(
            unsafe { GetHandleInformation(handle, &mut flags) },
            0,
            "read {name} handle flags after hardening"
        );
        assert_eq!(
            flags & HANDLE_FLAG_INHERIT,
            0,
            "{name} must no longer be inheritable"
        );
    }
}

#[cfg(target_os = "windows")]
fn assert_hostile_handle_absent() {
    let hostile = env::var("LANG")
        .expect("hostile handle sentinel is present in the public test environment")
        .parse::<usize>()
        .expect("hostile handle sentinel is numeric") as HANDLE;
    let mut flags = 0_u32;
    assert_eq!(
        unsafe { GetHandleInformation(hostile, &mut flags) },
        0,
        "hostile inheritable handle was not excluded by the exact handle list"
    );
}
