#![cfg(target_os = "linux")]

use std::{
    io::{self, Write},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use std::{
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{net::UnixStream, process::CommandExt},
    },
};

/// The bounded process helpers this suite first needed, now shared with the
/// personal access contract so both suites bound a subprocess the same way.
#[path = "support/bounded_process.rs"]
mod bounded_process;

use bounded_process::{
    collect_output_bounded, read_eof_bounded, terminate_and_reap_bounded, REAP_TIMEOUT,
};
use your_cloud_bootstrap_protocol::{
    monotonic_nanos, AssistantEventKind, AssistantEventV1, AssistantScopeV1, BootstrapAccessKind,
    BootstrapAction, BootstrapMode, BootstrapStep, BootstrapTarget, NativePromptKind,
};
use your_cloud_native_bootstrap_assistant::{
    EXIT_CANCELLED, EXIT_INVALID_INVOCATION, EXIT_PROTOCOL_REFUSED, EXIT_REFUSED, EXIT_UNAVAILABLE,
    EXIT_WATCHDOG_EXPIRED, REQUIRED_MODE_ARGUMENT, REQUIRED_VERIFY_EMBEDDED_MODE_ARGUMENT,
};

const REQUEST_ID: &str = "00112233445566778899aabbccddeeff";
const HOST_KEY: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const INITIAL_REMAINING_MILLIS: u64 = 10_000;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(5);
const WINDOW_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy)]
enum MutationKind {
    Target,
    Step,
    Action,
    Expiration,
}

impl MutationKind {
    fn name(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Step => "step",
            Self::Action => "action",
            Self::Expiration => "expiration",
        }
    }
}

/// The scope these fixtures submit, deliberately not the personal access one.
///
/// `ConfirmPersonalAccess` no longer opens a window by itself: it first
/// resolves the target, freezes its addresses and reads the agent, and against
/// a synthetic unreachable host it fails before any window exists. The
/// properties proven here belong to the window — its watchdog, the descriptors
/// it does not inherit, the mutations it refuses while live — so the scope
/// carries the escalation couple, which still goes straight to the native
/// prompt with the same administrator target.
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
        declared_target: None,
        issued_at_monotonic_nanos: monotonic_nanos().expect("shared monotonic clock"),
        remaining_millis,
    }
}

fn frame(scope: &AssistantScopeV1) -> Vec<u8> {
    let payload = serde_json::to_vec(scope).unwrap();
    payload_frame(&payload)
}

fn payload_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(payload);
    frame
}

fn base_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_your-cloud-native-bootstrap-assistant"));
    command
        .arg(REQUIRED_MODE_ARGUMENT)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn spawn_authenticated(mut command: Command) -> (Child, UnixStream) {
    let (child_input, parent_input) = UnixStream::pair().unwrap();
    command.stdin(Stdio::from(OwnedFd::from(child_input)));
    (command.spawn().unwrap(), parent_input)
}

fn command() -> Command {
    let mut command = base_command();
    command
        .env_remove("DISPLAY")
        .env_remove("XAUTHORITY")
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("XDG_RUNTIME_DIR");
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
    let (child, mut parent_lease) = spawn_authenticated(command());
    parent_lease.write_all(&frame(&scope(5_000))).unwrap();
    parent_lease.flush().unwrap();
    let output = collect_output_bounded(child, PROCESS_TIMEOUT).unwrap();
    drop(parent_lease);

    assert_eq!(output.status.code(), Some(EXIT_UNAVAILABLE.into()));
    assert!(output.stderr.is_empty());
    assert_eq!(
        decode_event(&output.stdout),
        AssistantEventV1 {
            schema_version: 1,
            request_id: REQUEST_ID.into(),
            event: AssistantEventKind::Unavailable,
            installation_scope: None,
        }
    );
}

#[test]
fn prebuffered_eof_wins_over_an_immediately_unavailable_prompt() {
    let (child, mut parent_lease) = spawn_authenticated(command());
    parent_lease.write_all(&frame(&scope(5_000))).unwrap();
    parent_lease.flush().unwrap();
    drop(parent_lease);
    let output = collect_output_bounded(child, PROCESS_TIMEOUT).unwrap();

    assert_eq!(output.status.code(), Some(EXIT_CANCELLED.into()));
    assert!(output.stderr.is_empty());
    assert_eq!(
        decode_event(&output.stdout),
        AssistantEventV1 {
            schema_version: 1,
            request_id: REQUEST_ID.into(),
            event: AssistantEventKind::Cancelled,
            installation_scope: None,
        }
    );
}

#[test]
fn wrong_argument_fails_closed_without_output() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_your-cloud-native-bootstrap-assistant"));
    command
        .arg("--other")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = collect_output_bounded(command.spawn().unwrap(), PROCESS_TIMEOUT).unwrap();
    assert_eq!(output.status.code(), Some(EXIT_INVALID_INVOCATION.into()));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

/// Le mode de vérification du lot embarqué, exercé là où cette suite vit : un
/// binaire d'arbre de travail, donc hors de la position installée. Le refus se
/// nomme sur la sortie standard — c'est la même ligne que la preuve LAB
/// asserte — et rien d'autre n'est écrit. Un binaire enrobé ou recopié reçoit
/// exactement ceci, et c'est le comportement que la résolution promet.
#[test]
fn verify_embedded_mode_outside_the_attested_position_names_its_refusal() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_your-cloud-native-bootstrap-assistant"));
    command
        .arg(REQUIRED_VERIFY_EMBEDDED_MODE_ARGUMENT)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = collect_output_bounded(command.spawn().unwrap(), PROCESS_TIMEOUT).unwrap();

    assert_eq!(output.status.code(), Some(EXIT_REFUSED.into()));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "REFUSED OutsideAttestedPosition\n"
    );
    assert!(output.stderr.is_empty());
}

/// Le troisième mode tient son invocation à un argument exact, comme les deux
/// autres : un argument de plus est une invocation invalide, pas une option.
#[test]
fn verify_embedded_mode_refuses_any_extra_argument() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_your-cloud-native-bootstrap-assistant"));
    command
        .arg(REQUIRED_VERIFY_EMBEDDED_MODE_ARGUMENT)
        .arg("/tmp/somewhere-else")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = collect_output_bounded(command.spawn().unwrap(), PROCESS_TIMEOUT).unwrap();

    assert_eq!(output.status.code(), Some(EXIT_INVALID_INVOCATION.into()));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn prebuffered_additional_input_wins_over_an_immediately_unavailable_prompt() {
    let mut input = frame(&scope(5_000));
    input.push(0);
    let (child, mut parent_lease) = spawn_authenticated(command());
    parent_lease.write_all(&input).unwrap();
    parent_lease.flush().unwrap();
    let output = collect_output_bounded(child, PROCESS_TIMEOUT).unwrap();
    drop(parent_lease);

    assert_eq!(output.status.code(), Some(EXIT_PROTOCOL_REFUSED.into()));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires isolated Xvfb"]
fn watchdog_expires_a_live_prompt_before_the_forced_fallback() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_your-cloud-native-bootstrap-assistant"));
    command
        .arg(REQUIRED_MODE_ARGUMENT)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (child, mut child_input) = spawn_authenticated(command);
    child_input.write_all(&frame(&scope(100))).unwrap();
    child_input.flush().unwrap();

    let started = Instant::now();
    let output = collect_output_bounded(child, Duration::from_secs(2)).unwrap();
    let elapsed = started.elapsed();
    drop(child_input);

    assert_eq!(output.status.code(), Some(EXIT_WATCHDOG_EXPIRED.into()));
    assert!(elapsed < Duration::from_secs(2));
    assert_eq!(
        decode_event(&output.stdout),
        AssistantEventV1 {
            schema_version: 1,
            request_id: REQUEST_ID.into(),
            event: AssistantEventKind::Expired,
            installation_scope: None,
        }
    );
    assert!(output.stderr.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires isolated Xvfb"]
fn live_prompt_refuses_target_step_action_and_expiration_mutations() {
    for mutation_kind in [
        MutationKind::Target,
        MutationKind::Step,
        MutationKind::Action,
        MutationKind::Expiration,
    ] {
        let initial = scope(INITIAL_REMAINING_MILLIS);
        let mutation = mutation_frame(&initial, mutation_kind);
        let (mut child, mut parent_lease) = spawn_authenticated(base_command());
        parent_lease.write_all(&frame(&initial)).unwrap();
        parent_lease.flush().unwrap();
        if let Err(error) = wait_for_visible_x11_window(&mut child, WINDOW_TIMEOUT) {
            let cleanup = terminate_and_reap_bounded(&mut child, REAP_TIMEOUT);
            drop(parent_lease);
            panic!(
                "{} mutation did not observe a live GTK window owned by the helper: {error}; cleanup: {cleanup:?}",
                mutation_kind.name(),
            );
        }

        parent_lease.write_all(&mutation).unwrap();
        parent_lease.flush().unwrap();
        let output = collect_output_bounded(child, PROCESS_TIMEOUT).unwrap_or_else(|error| {
            panic!(
                "{} mutation helper termination/output was not bounded: {error}",
                mutation_kind.name(),
            )
        });
        drop(parent_lease);

        assert_eq!(
            output.status.code(),
            Some(EXIT_PROTOCOL_REFUSED.into()),
            "{} mutation must be refused as extra protocol input",
            mutation_kind.name(),
        );
        assert!(
            output.stdout.is_empty(),
            "{} mutation stdout",
            mutation_kind.name(),
        );
        assert!(
            output.stderr.is_empty(),
            "{} mutation stderr",
            mutation_kind.name(),
        );
    }
}

fn mutation_frame(initial: &AssistantScopeV1, mutation_kind: MutationKind) -> Vec<u8> {
    match mutation_kind {
        MutationKind::Target => {
            let mut mutation = initial.clone();
            mutation.target.host = "other-controller.example.test".into();
            frame(&mutation)
        }
        MutationKind::Step => {
            // Another admissible step, carrying the prompt that step requires:
            // the frame must be refused because it arrives after the scope, not
            // because it is malformed.
            let mut mutation = initial.clone();
            mutation.step = BootstrapStep::UnlockPersonalKey;
            mutation.prompt = NativePromptKind::KeyPassphrase;
            frame(&mutation)
        }
        MutationKind::Action => {
            let mut mutation = serde_json::to_value(initial).unwrap();
            mutation["actions"] = serde_json::json!(["install_controller"]);
            payload_frame(&serde_json::to_vec(&mutation).unwrap())
        }
        MutationKind::Expiration => {
            let mut mutation = initial.clone();
            mutation.remaining_millis = INITIAL_REMAINING_MILLIS - 1_000;
            frame(&mutation)
        }
    }
}

fn wait_for_visible_x11_window(child: &mut Child, timeout: Duration) -> io::Result<()> {
    if let Some(status) = child.try_wait()? {
        return Err(io::Error::other(format!(
            "helper exited before its prompt became observable: {status}"
        )));
    }

    let process_id = child.id().to_string();
    let mut search = Command::new("xdotool");
    search
        .args([
            "search",
            "--sync",
            "--onlyvisible",
            "--pid",
            &process_id,
            ".",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let search_output = collect_output_bounded(search.spawn()?, timeout)?;
    if !search_output.status.success() {
        return Err(io::Error::other(format!(
            "xdotool search failed with {}: {}",
            search_output.status,
            String::from_utf8_lossy(&search_output.stderr).trim(),
        )));
    }
    let window_id = String::from_utf8(search_output.stdout)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .lines()
        .next()
        .ok_or_else(|| io::Error::other("xdotool returned no visible window"))?
        .trim()
        .to_owned();
    window_id
        .parse::<u64>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

    let mut owner = Command::new("xdotool");
    owner
        .args(["getwindowpid", &window_id])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let owner_output = collect_output_bounded(owner.spawn()?, timeout)?;
    if !owner_output.status.success() {
        return Err(io::Error::other(format!(
            "xdotool getwindowpid failed with {}: {}",
            owner_output.status,
            String::from_utf8_lossy(&owner_output.stderr).trim(),
        )));
    }
    let observed_process_id = String::from_utf8(owner_output.stdout)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .trim()
        .parse::<u32>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if observed_process_id != child.id() {
        return Err(io::Error::other(format!(
            "visible window owner {observed_process_id} differs from helper {}",
            child.id(),
        )));
    }
    if let Some(status) = child.try_wait()? {
        return Err(io::Error::other(format!(
            "helper exited after its visible prompt was observed: {status}"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires isolated Xvfb"]
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
    let mut helper = base_command();
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
    let (mut child, mut child_input) = spawn_authenticated(helper);
    drop(writer);
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

    let reaped = terminate_and_reap_bounded(&mut child, REAP_TIMEOUT);
    drop(child_input);

    assert_eq!(inherited_writer_closed.unwrap(), true);
    assert!(child_was_still_running);
    assert!(reaped.is_ok());
}
