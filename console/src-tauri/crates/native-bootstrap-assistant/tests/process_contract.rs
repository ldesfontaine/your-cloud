use std::{
    io::{self, Read, Write},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use std::{
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::process::CommandExt,
    },
};

use your_cloud_bootstrap_protocol::{
    AssistantEventKind, AssistantEventV1, AssistantScopeV1, BootstrapAccessKind, BootstrapAction,
    BootstrapMode, BootstrapStep, BootstrapTarget, NativePromptKind,
};
use your_cloud_native_bootstrap_assistant::{
    EXIT_INVALID_INVOCATION, EXIT_PROTOCOL_REFUSED, EXIT_UNAVAILABLE, EXIT_WATCHDOG_EXPIRED,
    REQUIRED_MODE_ARGUMENT,
};

const REQUEST_ID: &str = "00112233445566778899aabbccddeeff";
const HOST_KEY: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

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
        step: BootstrapStep::PersonalAccess,
        actions: [BootstrapAction::AuditTargetReadOnly],
        prompt: NativePromptKind::ConfirmPersonalAccess,
        remaining_millis,
    }
}

fn frame(scope: &AssistantScopeV1) -> Vec<u8> {
    let payload = serde_json::to_vec(scope).unwrap();
    let mut frame = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
    frame
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_your-cloud-native-bootstrap-assistant"));
    command
        .arg(REQUIRED_MODE_ARGUMENT)
        .env_remove("DISPLAY")
        .env_remove("XAUTHORITY")
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("XDG_RUNTIME_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn decode_event(output: &[u8]) -> AssistantEventV1 {
    assert!(output.len() >= 4);
    let length = u32::from_be_bytes(output[..4].try_into().unwrap()) as usize;
    assert_eq!(output.len(), length + 4);
    serde_json::from_slice::<AssistantEventV1>(&output[4..])
        .unwrap()
        .validate()
        .unwrap()
}

#[test]
fn exact_invocation_returns_one_expurgated_unavailable_event() {
    let mut child = command().spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&frame(&scope(5_000)))
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(EXIT_UNAVAILABLE.into()));
    assert!(output.stderr.is_empty());
    assert_eq!(
        decode_event(&output.stdout),
        AssistantEventV1 {
            schema_version: 1,
            request_id: REQUEST_ID.into(),
            event: AssistantEventKind::Unavailable,
        }
    );
}

#[test]
fn wrong_argument_and_additional_input_fail_closed_without_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_your-cloud-native-bootstrap-assistant"))
        .arg("--other")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(EXIT_INVALID_INVOCATION.into()));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());

    let mut input = frame(&scope(5_000));
    input.push(0);
    let mut child = command().spawn().unwrap();
    child.stdin.take().unwrap().write_all(&input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(EXIT_PROTOCOL_REFUSED.into()));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn watchdog_closes_a_parent_that_keeps_stdin_open() {
    let mut child = command().spawn().unwrap();
    let mut child_input = child.stdin.take().unwrap();
    child_input.write_all(&frame(&scope(100))).unwrap();
    child_input.flush().unwrap();

    let started = Instant::now();
    let status = wait_bounded(&mut child, Duration::from_secs(2));
    let elapsed = started.elapsed();
    drop(child_input);

    assert_eq!(status.code(), Some(EXIT_WATCHDOG_EXPIRED.into()));
    assert!(elapsed < Duration::from_secs(2));
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn helper_closes_every_inherited_descriptor_outside_stdio() {
    let mut inherited = [-1; 2];
    // SAFETY: storage is valid for both descriptors. O_CLOEXEC prevents concurrent test
    // processes from inheriting either endpoint before the intended child is forked.
    assert_eq!(
        unsafe { libc::pipe2(inherited.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    // SAFETY: pipe2 returned two unique owned descriptors.
    let mut reader = unsafe { File::from_raw_fd(inherited[0]) };
    // SAFETY: pipe2 returned two unique owned descriptors.
    let writer = unsafe { OwnedFd::from_raw_fd(inherited[1]) };

    let writer_descriptor = writer.as_raw_fd();
    // SAFETY: writer remains owned and open until after spawn.
    let writer_flags = unsafe { libc::fcntl(writer_descriptor, libc::F_GETFD) };
    assert!(writer_flags >= 0);
    let mut helper = command();
    // SAFETY: fcntl is async-signal-safe. Only the forked child clears CLOEXEC on its copy, so
    // exactly this helper receives the hostile descriptor while parallel tests remain isolated.
    unsafe {
        helper.pre_exec(move || {
            if libc::fcntl(
                writer_descriptor,
                libc::F_SETFD,
                writer_flags & !libc::FD_CLOEXEC,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = helper.spawn().unwrap();
    drop(writer);
    let mut child_input = child.stdin.take().unwrap();
    child_input.write_all(&frame(&scope(1_000))).unwrap();
    child_input.flush().unwrap();

    // A closed inherited writer is observable as EOF without inspecting /proc/<pid>/fd. That
    // inspection is deliberately denied to the same user after PR_SET_DUMPABLE=0.
    // SAFETY: reader remains owned for the whole flag update.
    let reader_flags = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFL) };
    assert!(reader_flags >= 0);
    // SAFETY: reader remains owned for the whole flag update.
    assert_eq!(
        unsafe {
            libc::fcntl(
                reader.as_raw_fd(),
                libc::F_SETFL,
                reader_flags | libc::O_NONBLOCK,
            )
        },
        0
    );
    let inherited_writer_closed = read_eof_bounded(&mut reader, Duration::from_secs(1));
    let child_was_still_running = matches!(child.try_wait(), Ok(None));

    let _ = child.kill();
    let reaped = child.wait();
    drop(child_input);

    assert_eq!(inherited_writer_closed.unwrap(), true);
    assert!(child_was_still_running);
    assert!(reaped.is_ok());
}

#[cfg(target_os = "linux")]
fn read_eof_bounded(reader: &mut File, timeout: Duration) -> io::Result<bool> {
    let deadline = Instant::now() + timeout;
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Ok(true),
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
    }
}

fn wait_bounded(child: &mut std::process::Child, timeout: Duration) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("assistant subprocess did not stop before the test deadline");
        }
        thread::sleep(Duration::from_millis(10));
    }
}
