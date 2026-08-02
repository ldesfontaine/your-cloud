use std::{
    io::{Read, Write},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use std::fs;

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
    // SAFETY: storage is valid for both pipe descriptors and every descriptor is closed below.
    assert_eq!(unsafe { libc::pipe(inherited.as_mut_ptr()) }, 0);
    for descriptor in inherited {
        // SAFETY: descriptor was returned by pipe and remains open here. Explicitly clearing
        // CLOEXEC makes this a hostile inherited descriptor rather than a vacuous assertion.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0
        );
    }
    let mut child = command().spawn().unwrap();
    for descriptor in inherited {
        // SAFETY: these are the parent copies of the two pipe descriptors created above.
        assert_eq!(unsafe { libc::close(descriptor) }, 0);
    }
    let mut child_input = child.stdin.take().unwrap();
    child_input.write_all(&frame(&scope(1_000))).unwrap();
    child_input.flush().unwrap();
    thread::sleep(Duration::from_millis(25));

    let mut descriptors = fs::read_dir(format!("/proc/{}/fd", child.id()))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    descriptors.sort();
    assert_eq!(descriptors, ["0", "1", "2"]);

    child.kill().unwrap();
    child.wait().unwrap();
    drop(child_input);
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
