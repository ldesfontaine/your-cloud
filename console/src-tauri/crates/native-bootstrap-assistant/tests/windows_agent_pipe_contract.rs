#![cfg(target_os = "windows")]

//! What a name is worth on Windows, and what an attestation adds to it.
//!
//! `\\.\pipe\openssh-ssh-agent` is a name in a namespace any account may
//! create into. This suite puts a separate hostile process on exactly that
//! name, as its first and only instance, so the helper necessarily lands on
//! it — and requires the endpoint to be refused for the one reason that
//! matters, the image serving it. It then requires the same code to accept the
//! real OpenSSH Authentication Agent, because a rule that refuses everything
//! attests nothing.
//!
//! The suite drives the `ssh-agent` service, since it is what holds or frees
//! the name, and puts back the configuration it found.

use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use windows_sys::Win32::Storage::FileSystem::{CreateSymbolicLinkW, GetShortPathNameW};

use your_cloud_native_bootstrap_assistant::personal_access::{
    agent_client::AgentRefusal,
    agent_endpoint::{EndpointRefusal, WINDOWS_AGENT_ACCOUNT, WINDOWS_AGENT_IMAGE},
    agent_pipe::{
        list_identities_once, normalised_path, observe_windows_endpoint, system_agent_image_path,
        AgentPipeRefusal,
    },
};

/// Longest the suite waits for a service transition or a fixture line.
const CONTRACT_TIMEOUT: Duration = Duration::from_secs(20);

/// How often the pipe namespace is consulted while waiting for a transition.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

const SERVICE: &str = "ssh-agent";

#[test]
fn a_pipe_server_that_is_not_the_system_openssh_agent_is_refused() {
    let service = AgentService::observe();
    service.free_the_name();

    // Nothing holds the name: the endpoint is unavailable, never "fine".
    assert_eq!(
        observe_windows_endpoint().err(),
        Some(EndpointRefusal::PipeUnavailable),
        "an unserved name must not become an endpoint",
    );

    let expected = system_agent_image_path().expect("this machine ships the OpenSSH agent");
    assert!(
        expected
            .to_ascii_lowercase()
            .ends_with(&WINDOWS_AGENT_IMAGE.to_ascii_lowercase()),
        "the expectation must be read from the machine: {expected}",
    );

    // A separate process, holding the exact name, first and only instance.
    let mut fixture = HostileFixture::start();
    fixture.await_ready();

    let refusal = observe_windows_endpoint()
        .err()
        .expect("a hostile server must never yield an endpoint");
    assert_eq!(
        refusal,
        EndpointRefusal::ForeignPipeServer,
        "the refusal must come from the image serving the pipe, not from a side effect",
    );
    assert_eq!(
        fixture.finish(),
        0,
        "a helper that attests before it speaks sends the hostile server no byte",
    );

    // The comparison must survive the three shapes the same file can be named
    // by. Each of them is the genuine system agent under another spelling.
    assert_same_path(&normalised_path(&expected.to_ascii_uppercase()), &expected);
    assert_same_path(&normalised_path(&short_path(&expected)), &expected);
    let link = symbolic_link_to(&expected);
    assert_same_path(&normalised_path(&link.display().to_string()), &expected);
    let _ = std::fs::remove_file(&link);

    // And the rule must accept the one server it exists for.
    service.hold_the_name();
    let attested = observe_windows_endpoint().expect("the live OpenSSH agent must be attested");
    assert_ne!(attested.server_process_id(), 0);
    assert_eq!(
        attested.server_account_sid(),
        WINDOWS_AGENT_ACCOUNT,
        "the agent service is registered as LocalSystem",
    );
    assert_same_path(&Some(attested.server_image_path().to_owned()), &expected);
    drop(attested);

    // And the attested pipe must really carry an agent conversation: the same
    // bounded framing and the same client the Linux half uses, over the handle
    // that was attested. This agent holds nothing, and holding nothing is a
    // refusal — which is only observable if the request and its answer really
    // crossed the pipe.
    let listed = list_identities_once(Instant::now() + CONTRACT_TIMEOUT)
        .err()
        .expect("an agent holding no identity offers nothing to select");
    assert_eq!(
        listed,
        AgentPipeRefusal::Agent(AgentRefusal::NoIdentity),
        "the agent answered, and an empty answer is refused rather than believed",
    );
}

fn assert_same_path(observed: &Option<String>, expected: &str) {
    let observed = observed
        .as_deref()
        .expect("a live file always has a normalised name");
    assert!(
        observed.eq_ignore_ascii_case(expected),
        "{observed} must name the same file as {expected}",
    );
}

/// The `8.3` spelling of a path, where the volume still keeps one.
fn short_path(path: &str) -> String {
    let wide = wide(path);
    let mut buffer = vec![0_u16; 1024];
    // SAFETY: both buffers are live and their announced lengths are exact.
    let written = unsafe {
        GetShortPathNameW(
            wide.as_ptr(),
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).expect("bounded buffer"),
        )
    };
    let written = usize::try_from(written).expect("bounded answer");
    assert!(written != 0 && written < buffer.len(), "no short path");
    buffer.truncate(written);
    String::from_utf16(&buffer).expect("short path is valid UTF-16")
}

/// A symbolic link to a file, in this process's own temporary directory.
fn symbolic_link_to(target: &str) -> PathBuf {
    let link = std::env::temp_dir().join(format!(
        "your-cloud-agent-pipe-{}-link.exe",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&link);
    let link_wide = wide(&link.display().to_string());
    let target_wide = wide(target);
    // SAFETY: both strings are live and NUL-terminated.
    let created = unsafe { CreateSymbolicLinkW(link_wide.as_ptr(), target_wide.as_ptr(), 0) };
    assert!(
        created,
        "creating a symbolic link requires the privilege this suite runs with",
    );
    link
}

fn wide(value: &str) -> Vec<u16> {
    let mut encoded: Vec<u16> = value.encode_utf16().collect();
    encoded.push(0);
    encoded
}

/// The hostile process holding the OpenSSH pipe name.
struct HostileFixture {
    child: Child,
    lines: Receiver<String>,
    reaped: bool,
}

impl HostileFixture {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_your-cloud-agent-pipe-fixture"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("hostile pipe server started");
        let stdout = child.stdout.take().expect("hostile server output");
        let (sender, lines) = mpsc::channel();
        // Read on its own thread so no wait here is unbounded.
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if sender.send(line).is_err() {
                    return;
                }
            }
        });
        Self {
            child,
            lines,
            reaped: false,
        }
    }

    fn await_ready(&mut self) {
        assert_eq!(
            self.next_line(),
            "READY",
            "the hostile server must hold the name before the helper opens it",
        );
    }

    /// How many bytes the hostile server was ever sent.
    fn finish(&mut self) -> usize {
        let line = self.next_line();
        let received = line
            .strip_prefix("RECEIVED ")
            .expect("the hostile server reports what it was sent")
            .parse()
            .expect("a byte count");
        let status = self.child.wait().expect("hostile server reaped");
        self.reaped = true;
        assert!(status.success(), "hostile server ended badly: {status}");
        received
    }

    fn next_line(&mut self) -> String {
        match self.lines.recv_timeout(CONTRACT_TIMEOUT) {
            Ok(line) => line,
            Err(RecvTimeoutError::Timeout) => panic!("hostile server said nothing in time"),
            Err(RecvTimeoutError::Disconnected) => panic!("hostile server ended without speaking"),
        }
    }
}

impl Drop for HostileFixture {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The `ssh-agent` service, as this suite found it and must leave it.
struct AgentService {
    start_type: String,
}

impl AgentService {
    fn observe() -> Self {
        let configuration = service_command(&["qc", SERVICE]);
        let start_type = configuration
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.trim() != "START_TYPE" {
                    return None;
                }
                match value.split_whitespace().next()? {
                    "2" => Some("auto"),
                    "3" => Some("demand"),
                    "4" => Some("disabled"),
                    _ => None,
                }
            })
            .expect("the OpenSSH agent service is registered on this machine");
        Self {
            start_type: start_type.to_owned(),
        }
    }

    /// Stops the service so nothing legitimate holds the pipe name.
    fn free_the_name(&self) {
        let _ = service_command(&["stop", SERVICE]);
        self.await_endpoint(|observed| observed == Some(EndpointRefusal::PipeUnavailable));
    }

    /// Starts the service so the real agent holds the pipe name.
    fn hold_the_name(&self) {
        let _ = service_command(&["config", SERVICE, "start=", "demand"]);
        let _ = service_command(&["start", SERVICE]);
        self.await_endpoint(|observed| observed.is_none());
    }

    fn await_endpoint(&self, settled: impl Fn(Option<EndpointRefusal>) -> bool) {
        let deadline = Instant::now() + CONTRACT_TIMEOUT;
        loop {
            let observed = observe_windows_endpoint().err();
            if settled(observed) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the agent service never reached the expected state: {observed:?}",
            );
            thread::sleep(POLL_INTERVAL);
        }
    }
}

/// The configuration the suite found is put back whatever ended it, so a run
/// that fails halfway leaves the machine as it was rather than enabled.
impl Drop for AgentService {
    fn drop(&mut self) {
        let _ = service_command(&["stop", SERVICE]);
        let _ = service_command(&["config", SERVICE, "start=", &self.start_type]);
    }
}

fn service_command(arguments: &[&str]) -> String {
    let output = Command::new("sc.exe")
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .expect("the service controller answers");
    String::from_utf8_lossy(&output.stdout).into_owned()
}
