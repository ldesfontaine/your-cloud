#![cfg(target_os = "windows")]

//! What a name is worth on Windows, what an attestation adds to it, and what
//! remains of that attestation for an account that holds nothing.
//!
//! `\\.\pipe\openssh-ssh-agent` is a name in a namespace any account may
//! create into. This suite puts a separate hostile process on exactly that
//! name, as its first and only instance, so the helper necessarily lands on
//! it — and requires the endpoint to be refused for the reason that survives
//! every level of privilege, the account that created the object. It then
//! requires the same code to accept the real OpenSSH Authentication Agent,
//! because a rule that refuses everything attests nothing.
//!
//! The second test is the one that matters most. `ssh-agent` is used by people
//! who are not administrators, and Windows hands a `LocalSystem` process to
//! nobody else: an attestation that needed such a handle would have been closed
//! against exactly the users it exists for. So every observation there is made
//! while impersonating a token with `Administrators` disabled and every
//! privilege dropped, and the live agent must still be attested — with the
//! image path demonstrably out of reach, so that the acceptance can only have
//! come from the owner — while the squatter must still be refused.
//!
//! The suite drives the `ssh-agent` service, since it is what holds or frees
//! the name, and puts back the configuration it found.

use std::{
    io::{BufRead, BufReader},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::PathBuf,
    process::{Child, Command, Stdio},
    ptr::{null, null_mut},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{GetLastError, LocalFree},
    Security::{
        Authorization::ConvertStringSidToSidW, CreateRestrictedToken, DuplicateTokenEx,
        RevertToSelf, SecurityImpersonation, TokenImpersonation, DISABLE_MAX_PRIVILEGE, PSID,
        SID_AND_ATTRIBUTES, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY,
    },
    Storage::FileSystem::{CreateSymbolicLinkW, GetShortPathNameW},
    System::Threading::{GetCurrentProcess, OpenProcessToken, SetThreadToken},
};

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

    assert_ne!(
        fixture.owner(),
        WINDOWS_AGENT_ACCOUNT,
        "no fixture may stamp the agent's own account on an object it created",
    );

    let refusal = observe_windows_endpoint()
        .err()
        .expect("a hostile server must never yield an endpoint");
    assert_eq!(
        refusal,
        EndpointRefusal::ForeignPipeOwner,
        "the refusal must come from who created the pipe, not from a side effect",
    );
    assert_eq!(
        fixture.finish(),
        0,
        "a helper that attests before it speaks sends the hostile server no byte",
    );

    // The same verdict, reached by a process that arranged nothing and holds
    // none of this suite's state: a refusal that needed the attester to be the
    // one who set the scene would attest nothing about the real path.
    let mut squatter = HostileFixture::start();
    squatter.await_ready();
    assert_eq!(
        attest_in_a_separate_process(),
        "REFUSED ForeignPipeOwner",
        "the refusal must belong to the code, not to this process",
    );
    assert_eq!(squatter.finish(), 0);

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
        attested.server_object_owner_sid(),
        WINDOWS_AGENT_ACCOUNT,
        "a LocalSystem service leaves its own account on the objects it creates",
    );
    assert_eq!(
        attested.server_account_sid(),
        Some(WINDOWS_AGENT_ACCOUNT),
        "an administrator can read the token too, and it is registered as LocalSystem",
    );
    assert_same_path(&attested.server_image_path().map(str::to_owned), &expected);
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

/// The test the whole change exists for.
///
/// Every observation below is made by a thread carrying a token with
/// `Administrators` disabled and every privilege dropped — which is, for every
/// access check Windows performs, an account that holds nothing. It must still
/// hold an endpoint against the real agent, and must still refuse a squatter.
#[test]
fn no_administrative_right_is_needed_to_attest_the_agent_pipe() {
    let service = AgentService::observe();
    let restricted = RestrictedToken::of_this_process();

    // The live agent, seen by an account that may not look at it.
    service.hold_the_name();
    let attested = restricted
        .observing(observe_windows_endpoint)
        .expect("an account without privilege must still hold the agent endpoint");
    assert_eq!(
        attested.server_object_owner_sid(),
        WINDOWS_AGENT_ACCOUNT,
        "the owner of the object is readable by anyone the pipe lets in",
    );
    assert_eq!(
        attested.server_image_path(),
        None,
        "Windows must really have refused the handle, or this test proves nothing",
    );
    assert_eq!(attested.server_account_sid(), None);
    drop(attested);

    // And that same account must still refuse a squatter. The fixture closes
    // its own process to everything but `SYSTEM` and the administrators, so
    // this thread cannot read its image either: the owner of the object is
    // literally the only thing left between it and an impostor. Take that check
    // away and this assertion sees no refusal at all.
    service.free_the_name();
    let mut fixture = HostileFixture::start();
    fixture.await_ready();
    assert_ne!(fixture.owner(), WINDOWS_AGENT_ACCOUNT);
    assert_eq!(
        restricted.observing(observe_windows_endpoint).err(),
        Some(EndpointRefusal::ForeignPipeOwner),
        "an account that cannot look at the server must not therefore believe it",
    );
    assert_eq!(
        fixture.finish(),
        0,
        "a helper that attests before it speaks sends the hostile server no byte",
    );
}

/// A token of this process with every administrative access taken away.
///
/// `Administrators` is turned into a deny-only SID and every privilege is
/// dropped, which is exactly what an access check sees when an ordinary member
/// of `Users` asks. It is derived from this process's own primary token, so
/// building it needs no privilege of its own.
struct RestrictedToken {
    token: OwnedHandle,
}

impl RestrictedToken {
    fn of_this_process() -> Self {
        let mut primary = null_mut();
        // SAFETY: the pseudo-handle names this process and primary is valid
        // output storage.
        let opened = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE,
                &mut primary,
            )
        };
        assert!(
            opened != 0 && !primary.is_null(),
            "this process has a token"
        );
        // SAFETY: primary is a fresh handle nothing else owns.
        let primary = unsafe { OwnedHandle::from_raw_handle(primary) };

        let administrators = string_sid("S-1-5-32-544");
        let disable = [SID_AND_ATTRIBUTES {
            Sid: administrators.as_ptr(),
            Attributes: 0,
        }];
        let mut restricted = null_mut();
        // SAFETY: primary is live, disable points at one live entry of exactly
        // the announced count, and every unused list is empty and null.
        let created = unsafe {
            CreateRestrictedToken(
                primary.as_raw_handle(),
                DISABLE_MAX_PRIVILEGE,
                1,
                disable.as_ptr(),
                0,
                null(),
                0,
                null(),
                &mut restricted,
            )
        };
        assert!(
            created != 0 && !restricted.is_null(),
            "a restricted version of one's own token needs no privilege: {}",
            // SAFETY: the call reads the failure this thread just produced.
            unsafe { GetLastError() },
        );
        // SAFETY: restricted is a fresh handle nothing else owns.
        Self {
            token: unsafe { OwnedHandle::from_raw_handle(restricted) },
        }
    }

    /// Runs one observation on a thread that carries the restricted token.
    ///
    /// The token is put back whatever the observation did, including a panic:
    /// a test that left this thread impersonating would silently change what
    /// every later test is allowed to see.
    fn observing<T>(&self, observe: impl FnOnce() -> T) -> T {
        let mut impersonation = null_mut();
        // SAFETY: the token is live and impersonation is valid output storage.
        let duplicated = unsafe {
            DuplicateTokenEx(
                self.token.as_raw_handle(),
                TOKEN_ALL_ACCESS,
                null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut impersonation,
            )
        };
        assert!(
            duplicated != 0 && !impersonation.is_null(),
            "impersonation token"
        );
        // SAFETY: impersonation is a fresh handle nothing else owns.
        let impersonation = unsafe { OwnedHandle::from_raw_handle(impersonation) };

        // SAFETY: a null thread means this one, and the token is live.
        let set = unsafe { SetThreadToken(null(), impersonation.as_raw_handle()) };
        assert!(set != 0, "this thread carries the restricted token");
        let restored = Impersonation;
        let observed = observe();
        drop(restored);
        observed
    }
}

/// Reverts the calling thread to its own identity when it goes out of scope.
struct Impersonation;

impl Drop for Impersonation {
    fn drop(&mut self) {
        // SAFETY: the call takes no argument and reverts this thread only.
        let reverted = unsafe { RevertToSelf() };
        assert!(reverted != 0, "the thread must get its own identity back");
    }
}

/// A SID parsed from the one spelling Windows itself writes.
fn string_sid(text: &str) -> OwnedSid {
    let wide = wide(text);
    let mut sid: PSID = null_mut();
    // SAFETY: wide is a live NUL-terminated wide string and sid is valid output
    // storage.
    let converted = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) };
    assert!(
        converted != 0 && !sid.is_null(),
        "{text} is a well-formed SID"
    );
    OwnedSid(sid)
}

/// A SID this test allocated through Win32 and must release the same way.
struct OwnedSid(PSID);

impl OwnedSid {
    fn as_ptr(&self) -> PSID {
        self.0
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        // SAFETY: the pointer is exactly what ConvertStringSidToSidW allocated.
        let _ = unsafe { LocalFree(self.0.cast()) };
    }
}

/// What a separate process, running the same attestation, concluded.
fn attest_in_a_separate_process() -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_your-cloud-agent-pipe-fixture"))
        .arg("attest")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .expect("the attesting fixture ran");
    assert!(output.status.success(), "the attesting fixture ended badly");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
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
    owner: String,
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
            owner: String::new(),
            reaped: false,
        }
    }

    fn await_ready(&mut self) {
        assert_eq!(
            self.next_line(),
            "READY",
            "the hostile server must hold the name before the helper opens it",
        );
        let owner = self.next_line();
        self.owner = owner
            .strip_prefix("OWNER ")
            .expect("the hostile server names the owner of the object it created")
            .to_owned();
        assert!(!self.owner.is_empty(), "an object always has an owner");
    }

    /// The account the kernel wrote on the object this fixture created.
    fn owner(&self) -> &str {
        &self.owner
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
