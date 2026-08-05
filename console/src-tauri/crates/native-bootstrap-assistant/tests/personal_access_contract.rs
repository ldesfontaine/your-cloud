//! Contract of the personal SSH access, against real components.
//!
//! Everything here needs what no unit test can synthesise: a live `ssh-agent`
//! really holding keys, and a live `sshd` on a *different* machine — the target
//! guard refuses this machine's own addresses, so a loopback server would never
//! be dialled at all. The suite is therefore gated behind its own feature
//! rather than ignored inside the library: a proof that only runs where the
//! perimeter exists should not be compiled into every build of the crate, and
//! `#[ignore]` inside `session.rs` said nothing about *which* perimeter was
//! required.
//!
//! The whole perimeter is driven from the environment, so this crate carries no
//! lab address, no account name and no key material. The harness that sets
//! those variables is documented with the run itself.
//!
//! Two things this suite deliberately does not do. It never asks the client to
//! misbehave: every hostile case is produced by the *server*, by the *agent* or
//! by the *resolver*, because the claim is about what this client refuses, not
//! about what a modified client would do. And it never asserts on a public
//! event: nothing at this palier announces a verified access, so every verdict
//! is read from a returned value or from the server's own journal.

#![cfg(target_os = "linux")]

/// The bounded process helpers, shared with the process contract so both
/// suites bound a subprocess the same way.
#[path = "support/bounded_process.rs"]
mod bounded_process;
/// The streaming canary search, shared with the crash contract so both suites
/// mean the same thing by "the canary is absent".
#[path = "support/canary_scan.rs"]
mod canary_scan;
/// The Console's own supervisor, compiled from the Console's own source the
/// way the parent contract already does it.
///
/// Nothing below re-implements how a helper is launched. The claim being made
/// — that a helper started by the *product* reaches the personal agent — is
/// only worth something if the launcher under test is the shipped one,
/// `env_clear` and environment allowlist included.
#[allow(dead_code)]
#[path = "../../../src/native_assistant.rs"]
mod native_assistant;

use std::{
    fs::{self, File},
    io::{self, Read, Write},
    net::IpAddr,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use russh::{
    keys::{agent::AgentIdentity, HashAlg, PublicKey},
    Signer,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use bounded_process::{
    collect_output_bounded, read_eof_bounded, terminate_and_reap_bounded, wait_bounded,
    PIPE_EOF_TIMEOUT, REAP_TIMEOUT,
};
use canary_scan::file_contains;
use native_assistant::{NativeAssistantPoll, NativeAssistantSupervisor};
use your_cloud_bootstrap_protocol::{
    monotonic_nanos, AssistantEventKind, AssistantEventV1, AssistantScopeV1, BootstrapAccessKind,
    BootstrapAction, BootstrapMode, BootstrapStep, BootstrapTarget, NativePromptKind,
};
use your_cloud_native_bootstrap_assistant::personal_access::{
    agent_client::{
        AgentRefusal, BoundedAgentStream, PersonalAgent, SigningRefusal, StreamRefusal,
        MAX_AGENT_FRAME_BYTES,
    },
    algorithms::{HostKeyType, IdentityKeyType},
    host_key::HostKeyRefusal,
    key_file::{self, KeyFileRefusal},
    key_unlock::{self, UnlockRefusal},
    openssh_key::{MAX_BCRYPT_ROUNDS, MAX_KEY_FILE_BYTES},
    session::{
        AuthenticationRequest, GuardVerdict, PersonalAccessRefusal, Prepared, RunObservation,
        TransportRefusal, MAX_PROBE_STREAM_BYTES,
    },
    signature_budget::{BudgetRefusal, MAX_AUTHENTICATION_SIGNATURES},
    target::TargetRefusal,
};
use your_cloud_native_bootstrap_assistant::personal_access_contract as fixture_names;
use your_cloud_native_bootstrap_assistant::{
    EXIT_PROTOCOL_REFUSED, EXIT_WATCHDOG_EXPIRED, REQUIRED_MODE_ARGUMENT,
};

/// Numeric address of the machine running the synthetic `sshd`.
const TARGET: &str = "YOUR_CLOUD_LAB_TARGET";
/// The same machine, reached through a synthetic *name* the resolver answers.
const NAME: &str = "YOUR_CLOUD_LAB_NAME";
/// Port of the nominal `sshd`.
const PORT: &str = "YOUR_CLOUD_LAB_PORT";
/// Synthetic account that holds the authorised key and runs the real probe.
const USERNAME: &str = "YOUR_CLOUD_LAB_USERNAME";
/// `SHA256:…` fingerprint of that machine's real Ed25519 host key.
const HOST_KEY: &str = "YOUR_CLOUD_LAB_HOST_KEY";
/// Fingerprint of the agent identity the server accepts.
const AUTHORIZED: &str = "YOUR_CLOUD_LAB_AUTHORIZED";
/// Fingerprint of an agent identity the server has never heard of.
const STRANGER: &str = "YOUR_CLOUD_LAB_STRANGER";
/// Numeric uid the fixed probe must report for the account above.
const EXPECTED_UID: &str = "YOUR_CLOUD_LAB_UID";
/// Where a trust-on-first-use would be recorded, if any existed.
const KNOWN_HOSTS: &str = "YOUR_CLOUD_LAB_KNOWN_HOSTS";

/// Account whose forced command floods `stdout` one byte past the bound.
const OVERSIZED_STDOUT_USERNAME: &str = "YOUR_CLOUD_LAB_OVERSIZED_STDOUT_USERNAME";
/// Account whose forced command floods `stderr` one byte past the bound.
const OVERSIZED_STDERR_USERNAME: &str = "YOUR_CLOUD_LAB_OVERSIZED_STDERR_USERNAME";
/// Account whose forced command writes exactly the bound, and no more.
const EXACT_BOUND_USERNAME: &str = "YOUR_CLOUD_LAB_EXACT_BOUND_USERNAME";
/// Account whose forced command holds the channel open until it is torn down.
const HELD_USERNAME: &str = "YOUR_CLOUD_LAB_HELD_USERNAME";

/// `sshd` offering an ECDSA host key and nothing else.
const ECDSA_PORT: &str = "YOUR_CLOUD_LAB_ECDSA_PORT";
/// `sshd` offering a key exchange outside the positive list.
const KEX_PORT: &str = "YOUR_CLOUD_LAB_KEX_PORT";
/// `sshd` offering a cipher and a MAC outside the positive lists.
const CIPHER_PORT: &str = "YOUR_CLOUD_LAB_CIPHER_PORT";

/// Name that resolves to more addresses than a target may freeze.
const MANY_NAME: &str = "YOUR_CLOUD_LAB_MANY_NAME";
/// Name that resolves onto an address this machine already holds.
const SELF_NAME: &str = "YOUR_CLOUD_LAB_SELF_NAME";
/// Name that resolves onto loopback.
const LOOPBACK_NAME: &str = "YOUR_CLOUD_LAB_LOOPBACK_NAME";
/// The resolver's own table, which the rebinding proof rewrites under the
/// session's feet. Rewriting the answer is the only honest way to prove the
/// question is never asked twice.
const HOSTS_FILE: &str = "YOUR_CLOUD_LAB_HOSTS_FILE";
/// Address the name is made to answer with, after consent.
const REBOUND_ADDRESS: &str = "YOUR_CLOUD_LAB_REBOUND_ADDRESS";

/// Program that runs one command on the server and prints its output. It is
/// the only way this suite observes the far side, and it carries the server's
/// address so this file does not.
const SERVER_COMMAND: &str = "YOUR_CLOUD_LAB_SERVER_COMMAND";
/// File holding, in hexadecimal, the raw private scalar of the authorised
/// identity. It is the canary: the agent never exports it, so no byte of it
/// may appear anywhere this client leaves a trace.
const KEY_NEEDLE: &str = "YOUR_CLOUD_LAB_KEY_NEEDLE";
/// Writable directory this suite may create files under.
const SCRATCH: &str = "YOUR_CLOUD_LAB_SCRATCH";

const LEASE: Duration = Duration::from_secs(30);
/// Longest one observation of the server may take.
const SERVER_TIMEOUT: Duration = Duration::from_secs(20);
/// Longest a server-side state may take to become what is expected.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(200);

// ---------------------------------------------------------------- perimeter

fn required(name: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| panic!("{name} must describe the LAB perimeter"))
}

fn required_port(name: &str) -> u16 {
    required(name)
        .parse()
        .unwrap_or_else(|_| panic!("{name} must be a decimal port"))
}

fn lease() -> Instant {
    Instant::now() + LEASE
}

fn always_continue() -> impl Fn() -> GuardVerdict + Sync {
    || GuardVerdict::Continue
}

/// Opens a preparation against the nominal `sshd`, by numeric address.
fn prepare() -> Prepared {
    Prepared::open(&required(TARGET), required_port(PORT), lease())
        .expect("the LAB target must be observable")
}

fn scratch() -> PathBuf {
    PathBuf::from(required(SCRATCH))
}

/// Runs one command on the server and returns its trimmed standard output.
fn server(command: &str) -> String {
    let child = Command::new(required(SERVER_COMMAND))
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the server observation bridge must be runnable");
    let output = collect_output_bounded(child, SERVER_TIMEOUT)
        .expect("the server observation must be bounded");
    assert!(
        output.status.success(),
        "server command {command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// Counts the probe processes the held account currently owns on the server.
///
/// The forced command the account runs is bound to its channel: its standard
/// input *is* the channel, so it lives exactly as long as the transport does.
/// A probe that outlived the transport would still be counted here, which is
/// the point.
fn held_probes() -> usize {
    let account = required(HELD_USERNAME);
    server(&format!("pgrep -c -u {account} cat || true"))
        .parse()
        .unwrap_or(0)
}

/// Waits, under a bound, for the server to report the expected probe count.
fn await_held_probes(expected: usize) {
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        let observed = held_probes();
        if observed == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the server still reports {observed} held probes instead of {expected}"
        );
        thread::sleep(POLL_INTERVAL);
    }
}

/// How many times the server has logged *closing the session channel* of the
/// held account.
///
/// This exact line is what the server writes when the channel this client
/// opened goes away, and it is the server's own account of the closure rather
/// than the client's. The pattern is deliberately not merely a line naming the
/// account: an accepted authentication names it too, and counting those would
/// make a session that never closed look closed.
///
/// A torn-down session is not always followed by the server's `Disconnected
/// from user` line — that one belongs to a transport the client shut down
/// politely, and a killed helper never gets to be polite. The channel close is
/// logged in every case, which is why the proof rests on it.
fn held_channel_closures() -> usize {
    let account = required(HELD_USERNAME);
    server(&format!(
        "journalctl -t sshd-session --since '-30 min' --no-pager \
         | grep -c 'Close session: user {account} ' || true"
    ))
    .parse()
    .unwrap_or(0)
}

// ------------------------------------------------------- the nominal access

/// The whole nominal path, end to end, against a real server: one transport,
/// one authentication, one probe — and exactly one signature taken from the
/// agent.
#[test]
fn a_nominal_personal_access_spends_exactly_one_signature() {
    let prepared = prepare();
    let authorized = required(AUTHORIZED);
    assert!(
        prepared
            .identities()
            .iter()
            .any(|identity| identity.fingerprint == authorized),
        "the agent must really hold the authorised identity"
    );

    let username = required(USERNAME);
    let host_key = required(HOST_KEY);
    let observation = prepared.run(
        &AuthenticationRequest {
            username: &username,
            approved_host_key_fingerprint: &host_key,
            selected_fingerprint: &authorized,
        },
        lease(),
        &always_continue(),
    );
    let report = observation
        .outcome
        .expect("the nominal access must succeed");

    assert_eq!(report.exit_status, 0);
    assert_eq!(
        String::from_utf8_lossy(&report.stdout).trim(),
        required(EXPECTED_UID),
        "the probe must report the synthetic account's own uid"
    );
    assert!(report.stderr.is_empty());
    assert_eq!(report.host_key_type, HostKeyType::Ed25519);
    assert_eq!(
        report.signatures_spent, MAX_AUTHENTICATION_SIGNATURES,
        "one access costs one signature, never two"
    );
    assert_eq!(observation.remaining_signatures, 0);
    assert_eq!(observation.stream_refusal, None);
}

/// The property the whole agent design rests on: an identity the server
/// refuses is refused *before* anything is signed.
#[test]
fn an_identity_the_server_refuses_costs_no_signature_at_all() {
    let stranger = required(STRANGER);
    let username = required(USERNAME);
    let host_key = required(HOST_KEY);
    let observation = prepare().run(
        &AuthenticationRequest {
            username: &username,
            approved_host_key_fingerprint: &host_key,
            selected_fingerprint: &stranger,
        },
        lease(),
        &always_continue(),
    );

    assert_eq!(
        observation.outcome.unwrap_err(),
        PersonalAccessRefusal::Transport(TransportRefusal::AuthenticationRefused)
    );
    assert_eq!(
        observation.remaining_signatures, MAX_AUTHENTICATION_SIGNATURES,
        "a refused authentication must leave the budget untouched"
    );
}

/// No trust on first use, proved against a server whose real key is simply not
/// the approved one.
#[test]
fn a_diverging_host_key_refuses_and_records_no_trust() {
    let known_hosts = PathBuf::from(required(KNOWN_HOSTS));
    assert!(
        !known_hosts.exists(),
        "the proof only means something starting from no recorded trust"
    );

    // A well-formed fingerprint that is certainly not this server's: an
    // identity fingerprint is never a host key fingerprint.
    let authorized = required(AUTHORIZED);
    let username = required(USERNAME);
    let observation = prepare().run(
        &AuthenticationRequest {
            username: &username,
            approved_host_key_fingerprint: &authorized,
            selected_fingerprint: &authorized,
        },
        lease(),
        &always_continue(),
    );

    assert_eq!(
        observation.outcome.unwrap_err(),
        PersonalAccessRefusal::Transport(TransportRefusal::HostKey(HostKeyRefusal::KeyMismatch))
    );
    assert_eq!(
        observation.remaining_signatures, MAX_AUTHENTICATION_SIGNATURES,
        "a refused host key must be refused before anything is signed"
    );
    assert!(
        !known_hosts.exists(),
        "no path of this assistant may record a host key"
    );
}

// ------------------------------------------------------- oversized probe output

/// Each probe stream is bounded separately, and the bound is a refusal rather
/// than a truncation.
///
/// The client is untouched: the probe it sends is the same fixed command in all
/// three cases. It is the server's forced command that decides how many bytes
/// come back, which is exactly the shape of the threat — a target that answers
/// more than agreed.
#[test]
fn a_probe_stream_one_byte_past_its_bound_fails_closed_on_both_streams() {
    let host_key = required(HOST_KEY);
    let authorized = required(AUTHORIZED);

    // The control first: exactly the bound is delivered whole, so "refused"
    // below cannot be confused with "this server floods everything".
    let exact = required(EXACT_BOUND_USERNAME);
    let report = prepare()
        .run(
            &AuthenticationRequest {
                username: &exact,
                approved_host_key_fingerprint: &host_key,
                selected_fingerprint: &authorized,
            },
            lease(),
            &always_continue(),
        )
        .outcome
        .expect("exactly the bound is not past the bound");
    assert_eq!(
        report.stdout.len(),
        MAX_PROBE_STREAM_BYTES,
        "a stream that fits must arrive whole"
    );

    for account in [
        required(OVERSIZED_STDOUT_USERNAME),
        required(OVERSIZED_STDERR_USERNAME),
    ] {
        let observation = prepare().run(
            &AuthenticationRequest {
                username: &account,
                approved_host_key_fingerprint: &host_key,
                selected_fingerprint: &authorized,
            },
            lease(),
            &always_continue(),
        );
        assert_eq!(
            observation.outcome.unwrap_err(),
            PersonalAccessRefusal::Transport(TransportRefusal::ProbeOutputTooLarge),
            "{account} floods one byte past the bound and must fail closed"
        );
    }
}

// --------------------------------------------------------------- the agent

/// Serves one hostile answer on a real Unix socket and then stops.
///
/// The two bounds below are byte-level properties of the framing: no real
/// `ssh-agent` will ever announce a megabyte or volunteer a frame, so the peer
/// producing them has to be synthetic. It is still a real socket, a real
/// listener and a real crossing of the kernel boundary — only the bytes are
/// chosen.
fn hostile_agent(path: &Path, answer: Vec<u8>) -> thread::JoinHandle<()> {
    let listener = UnixListener::bind(path).expect("the hostile agent must be able to bind");
    thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        // One request is read whole before anything is answered, so the client
        // is never refusing an answer it had not asked for by accident.
        let mut header = [0_u8; 4];
        if stream.read_exact(&mut header).is_err() {
            return;
        }
        let mut body = vec![0_u8; u32::from_be_bytes(header) as usize];
        if stream.read_exact(&mut body).is_err() {
            return;
        }
        let _ = stream.write_all(&answer);
        let _ = stream.flush();
        // The client must be the one that hangs up.
        thread::sleep(Duration::from_secs(2));
    })
}

fn hostile_socket_path(name: &str) -> PathBuf {
    let path = scratch().join(name);
    let _ = fs::remove_file(&path);
    path
}

/// Frames an agent message the way the protocol does.
fn agent_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(payload);
    frame
}

/// An agent that announces more than this process will ever read is cut off
/// before a single byte of that body is accepted.
#[test]
fn an_agent_frame_over_its_bound_is_refused_before_its_body() {
    let path = hostile_socket_path("oversized-agent.sock");
    // Announced one byte past the ceiling, and deliberately not followed by
    // the body: a client that had to read it to refuse it would hang here.
    let announcement = u32::try_from(MAX_AGENT_FRAME_BYTES + 1)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    let server = hostile_agent(&path, announcement);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime");
    let refusal = runtime.block_on(async {
        let stream = tokio::net::UnixStream::connect(&path)
            .await
            .expect("the hostile agent must accept");
        PersonalAgent::over(stream)
            .list_identities()
            .await
            .expect_err("an oversized frame is never an identity list")
    });
    assert_eq!(refusal, AgentRefusal::Stream(StreamRefusal::FrameTooLarge));

    drop(runtime);
    let _ = server.join();
    let _ = fs::remove_file(&path);
}

/// An agent that volunteers a second frame is cut off on that frame's header,
/// before it is parsed.
///
/// This one is read at the wire, through the bounded stream itself, because
/// the agent client above it reads exactly one framed answer and would leave
/// the volunteered frame in the socket instead of judging it.
#[test]
fn an_unsolicited_agent_message_is_cut_off_on_its_header() {
    let path = hostile_socket_path("unsolicited-agent.sock");
    // A well-formed, empty identity answer, immediately followed by a frame
    // nothing asked for. Both are written at once, so the client observes them
    // in the same read and cannot be excused by timing.
    const IDENTITIES_ANSWER: u8 = 12;
    let mut answer = agent_frame(&[IDENTITIES_ANSWER, 0, 0, 0, 0]);
    answer.extend_from_slice(&agent_frame(&[IDENTITIES_ANSWER, 0, 0, 0, 0]));
    let server = hostile_agent(&path, answer);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime");
    let refusal = runtime.block_on(async {
        let stream = tokio::net::UnixStream::connect(&path)
            .await
            .expect("the hostile agent must accept");
        let mut bounded = BoundedAgentStream::new(stream);
        let guard = bounded.guard();
        // One request, so exactly one answer is owed.
        const REQUEST_IDENTITIES: u8 = 11;
        bounded
            .write_all(&agent_frame(&[REQUEST_IDENTITIES]))
            .await
            .expect("the request must reach the agent");
        let mut buffer = [0_u8; 4096];
        let read = bounded.read(&mut buffer).await;
        assert!(read.is_err(), "a volunteered frame must end the stream");
        guard.refusal()
    });
    assert_eq!(refusal, Some(StreamRefusal::UnsolicitedMessage));

    drop(runtime);
    let _ = server.join();
    let _ = fs::remove_file(&path);
}

/// Builds an owned identity from a public key the real agent holds.
fn identity_of(key: &PublicKey) -> AgentIdentity {
    AgentIdentity::PublicKey {
        key: key.clone(),
        comment: String::new(),
    }
}

/// An identity other than the selected one is refused, and costs nothing.
///
/// Both identities are real: they are the two keys the live agent holds. What
/// is substituted is which of them the signer is asked to sign with, which is
/// precisely what an agent — or a transport — could change under the user.
#[test]
fn a_substituted_identity_is_refused_and_spends_no_signature() {
    let authorized = required(AUTHORIZED);
    let stranger = required(STRANGER);

    let (runtime, mut signer) = prepare()
        .into_signer(&authorized)
        .expect("the agent must hold the authorised identity");
    let (_stranger_runtime, stranger_signer) = prepare()
        .into_signer(&stranger)
        .expect("the agent must hold the unauthorised identity too");
    let substituted = identity_of(stranger_signer.public_key());

    let refusal = runtime
        .block_on(signer.auth_sign(&substituted, None, b"personal access contract".to_vec()))
        .expect_err("a substituted identity must never be signed with");
    assert!(
        matches!(
            refusal,
            SigningRefusal::Budget(BudgetRefusal::IdentityChanged)
        ),
        "unexpected refusal: {refusal:?}"
    );
    assert_eq!(
        signer.remaining_signatures(),
        MAX_AUTHENTICATION_SIGNATURES,
        "a refused signature must leave the budget untouched"
    );
}

/// The budget is finite against the real agent: the second signature of one
/// operation is refused, whoever asks and however well formed the request is.
#[test]
fn a_second_signature_is_refused_by_the_spent_budget() {
    let authorized = required(AUTHORIZED);
    let (runtime, mut signer) = prepare()
        .into_signer(&authorized)
        .expect("the agent must hold the authorised identity");
    let identity = identity_of(signer.public_key());

    let first = runtime.block_on(signer.auth_sign(&identity, None, b"first".to_vec()));
    assert!(first.is_ok(), "the single allowed signature must be given");
    assert_eq!(signer.remaining_signatures(), 0);

    let refusal = runtime
        .block_on(signer.auth_sign(&identity, None, b"second".to_vec()))
        .expect_err("the agent must not be used twice as an oracle");
    assert!(
        matches!(refusal, SigningRefusal::Budget(BudgetRefusal::Exhausted)),
        "unexpected refusal: {refusal:?}"
    );
    assert_eq!(signer.remaining_signatures(), 0);

    // A retry naming SHA-256 after a SHA-512 signature would spend a second
    // one from the same oracle; the budget refuses that too, and for its own
    // reason rather than by accident of exhaustion.
    let hashed =
        runtime.block_on(signer.auth_sign(&identity, Some(HashAlg::Sha256), b"r".to_vec()));
    assert!(hashed.is_err(), "no retry may reach the agent");
}

// ------------------------------------------------ tearing down a live session

/// Everything the suite must see gone once a live session is torn down.
fn assert_session_closed(closures_before: usize) {
    await_held_probes(0);
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        if held_channel_closures() > closures_before {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the server never logged the session closing"
        );
        thread::sleep(POLL_INTERVAL);
    }
}

/// A guard that lets the session establish itself and then fires.
///
/// It counts consultations rather than measuring time, because the guard is
/// polled between every step and then on every idle tick of the probe: a fixed
/// number of consultations lands inside the running probe on any machine,
/// where a fixed delay would race the handshake.
fn guard_firing_after(
    consultations: usize,
    verdict: GuardVerdict,
) -> impl Fn() -> GuardVerdict + Sync {
    let seen = std::sync::atomic::AtomicUsize::new(0);
    move || {
        if seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < consultations {
            GuardVerdict::Continue
        } else {
            verdict
        }
    }
}

/// Cancelling in the middle of a running probe closes the channel and the
/// transport, and the server sees the session end.
#[test]
fn a_cancellation_inside_a_live_session_closes_it_on_both_sides() {
    let held = required(HELD_USERNAME);
    let host_key = required(HOST_KEY);
    let authorized = required(AUTHORIZED);
    await_held_probes(0);
    let before = held_channel_closures();

    let observation = prepare().run(
        &AuthenticationRequest {
            username: &held,
            approved_host_key_fingerprint: &host_key,
            selected_fingerprint: &authorized,
        },
        lease(),
        &guard_firing_after(8, GuardVerdict::Cancelled),
    );
    assert_eq!(
        observation.outcome.unwrap_err(),
        PersonalAccessRefusal::Transport(TransportRefusal::Cancelled)
    );
    assert_session_closed(before);
}

/// The same, for a lease that runs out rather than a user who cancels.
#[test]
fn an_expired_lease_inside_a_live_session_closes_it_on_both_sides() {
    let held = required(HELD_USERNAME);
    let host_key = required(HOST_KEY);
    let authorized = required(AUTHORIZED);
    await_held_probes(0);
    let before = held_channel_closures();

    let observation = prepare().run(
        &AuthenticationRequest {
            username: &held,
            approved_host_key_fingerprint: &host_key,
            selected_fingerprint: &authorized,
        },
        lease(),
        &guard_firing_after(8, GuardVerdict::Expired),
    );
    assert_eq!(
        observation.outcome.unwrap_err(),
        PersonalAccessRefusal::Transport(TransportRefusal::Expired)
    );
    assert_session_closed(before);
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_your-cloud-personal-access-fixture"))
}

fn process_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// A helper whose parent dies mid-session leaves nothing behind: not itself,
/// not its transport, and not the probe the server was running for it.
///
/// The fixture is the helper's own hardened process, so what is proved here is
/// the helper's parent death signal and not a fixture's imitation of it. It is
/// started by an intermediate shell precisely so that a parent exists to kill.
#[test]
fn a_dead_parent_removes_the_helper_and_its_server_side_probe() {
    let held = required(HELD_USERNAME);
    await_held_probes(0);
    let before = held_channel_closures();

    let pid_path = scratch().join("held-fixture.pid");
    let _ = fs::remove_file(&pid_path);
    let mut parent = Command::new("/bin/sh")
        .arg("-c")
        .arg(r#""$1" hold & echo "$!" > "$2"; wait"#)
        .arg("sh")
        .arg(fixture_path())
        .arg(&pid_path)
        .env(fixture_names::TARGET, required(TARGET))
        .env(fixture_names::PORT, required(PORT))
        .env(fixture_names::USERNAME, &held)
        .env(fixture_names::HOST_KEY, required(HOST_KEY))
        .env(fixture_names::AUTHORIZED, required(AUTHORIZED))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the intermediate parent must start");

    let pid = read_pid_bounded(&pid_path);
    // The session is live once the server is really running the held probe.
    await_held_probes(1);
    assert!(process_alive(pid), "the fixture must still be running");

    terminate_and_reap_bounded(&mut parent, REAP_TIMEOUT).expect("the parent must be reaped");

    let deadline = Instant::now() + SETTLE_TIMEOUT;
    while process_alive(pid) {
        assert!(
            Instant::now() < deadline,
            "the helper outlived its parent at pid {pid}"
        );
        thread::sleep(POLL_INTERVAL);
    }
    assert_session_closed(before);
    let _ = fs::remove_file(&pid_path);
}

fn read_pid_bounded(path: &Path) -> u32 {
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(pid) = content.trim().parse::<u32>() {
                return pid;
            }
        }
        assert!(
            Instant::now() < deadline,
            "the intermediate parent never announced the fixture pid"
        );
        thread::sleep(POLL_INTERVAL);
    }
}

// ------------------------------------------------------------- negotiation

/// A server offering only algorithms outside the positive lists is refused at
/// the negotiation, before any key is examined.
///
/// The refusal is reported as an absent host key attestation rather than as a
/// transport error, and that is the point: the handshake ended before
/// `check_server_key` was ever reached, so this client never had an opinion on
/// the key that server holds.
#[test]
fn a_server_outside_the_positive_lists_is_refused_at_the_negotiation() {
    let username = required(USERNAME);
    let host_key = required(HOST_KEY);
    let authorized = required(AUTHORIZED);

    for port in [
        required_port(ECDSA_PORT),
        required_port(KEX_PORT),
        required_port(CIPHER_PORT),
    ] {
        let prepared = Prepared::open(&required(TARGET), port, lease())
            .expect("the LAB target must be observable on every port");
        let observation = prepared.run(
            &AuthenticationRequest {
                username: &username,
                approved_host_key_fingerprint: &host_key,
                selected_fingerprint: &authorized,
            },
            lease(),
            &always_continue(),
        );
        assert_eq!(
            observation.outcome.unwrap_err(),
            PersonalAccessRefusal::Transport(TransportRefusal::HostKey(
                HostKeyRefusal::NoApprovedKey
            )),
            "port {port} negotiated something outside the positive lists"
        );
        assert_eq!(
            observation.remaining_signatures, MAX_AUTHENTICATION_SIGNATURES,
            "a negotiation that failed must not have signed anything"
        );
    }
}

// -------------------------------------------------------------- resolution

/// Restores the resolver's table however the proof ends.
struct HostsFile {
    path: PathBuf,
    original: String,
}

impl HostsFile {
    fn take() -> Self {
        let path = PathBuf::from(required(HOSTS_FILE));
        let original = fs::read_to_string(&path).expect("the resolver table must be readable");
        Self { path, original }
    }

    /// Makes `name` answer with `address`, and nothing else.
    fn rebind(&self, name: &str, address: &str) {
        let mut rewritten: String = self
            .original
            .lines()
            .filter(|line| !line.split_whitespace().any(|field| field == name))
            .collect::<Vec<_>>()
            .join("\n");
        rewritten.push_str(&format!("\n{address} {name}\n"));
        fs::write(&self.path, rewritten).expect("the resolver table must be writable");
    }
}

impl Drop for HostsFile {
    fn drop(&mut self) {
        let _ = fs::write(&self.path, &self.original);
    }
}

/// A name that starts answering elsewhere after consent cannot move the
/// connection: the addresses were frozen once, and nothing re-resolves.
#[test]
fn a_name_that_moves_after_consent_never_moves_the_connection() {
    let name = required(NAME);
    let rebound = required(REBOUND_ADDRESS);
    let hosts = HostsFile::take();

    let prepared = Prepared::open(&name, required_port(PORT), lease())
        .expect("the synthetic name must resolve to the LAB target");
    let frozen: Vec<IpAddr> = prepared.target().addresses().to_vec();
    assert_eq!(
        frozen,
        [required(TARGET).parse::<IpAddr>().unwrap()],
        "the name must start out answering with the target's own address"
    );

    // The resolver now answers with something else entirely. Everything after
    // this point is what a rebinding attacker would have arranged.
    hosts.rebind(&name, &rebound);

    let username = required(USERNAME);
    let host_key = required(HOST_KEY);
    let authorized = required(AUTHORIZED);
    let report = prepared
        .run(
            &AuthenticationRequest {
                username: &username,
                approved_host_key_fingerprint: &host_key,
                selected_fingerprint: &authorized,
            },
            lease(),
            &always_continue(),
        )
        .outcome
        .expect("the frozen address must still be the one dialled");
    assert_eq!(
        String::from_utf8_lossy(&report.stdout).trim(),
        required(EXPECTED_UID),
        "the session reached the approved machine, not the rebound one"
    );

    // The control: a preparation started *now* really does answer elsewhere,
    // so the success above is the freeze holding and not a resolver that never
    // changed its mind.
    let moved = Prepared::open(&name, required_port(PORT), lease())
        .expect("the rebound name must still resolve");
    assert_eq!(
        moved.target().addresses(),
        [rebound.parse::<IpAddr>().unwrap()],
        "the resolver must really have moved for the proof to mean anything"
    );
}

/// More addresses behind one name than a target may hold is a refusal, never a
/// truncation: a truncated set would freeze addresses the user was never shown.
#[test]
fn more_addresses_than_the_maximum_behind_one_name_are_refused() {
    let refusal = Prepared::open(&required(MANY_NAME), required_port(PORT), lease())
        .err()
        .expect("an oversized address set must never be frozen");
    assert_eq!(
        refusal,
        PersonalAccessRefusal::Target(TargetRefusal::TooManyAddresses)
    );
}

/// A name pointing back at this machine is refused, whether it names one of
/// this machine's interfaces or plain loopback.
#[test]
fn a_name_resolving_onto_this_machine_is_refused() {
    let port = required_port(PORT);
    assert_eq!(
        Prepared::open(&required(SELF_NAME), port, lease())
            .err()
            .expect("this machine is never a remote host"),
        PersonalAccessRefusal::Target(TargetRefusal::LocalInterface)
    );
    assert_eq!(
        Prepared::open(&required(LOOPBACK_NAME), port, lease())
            .err()
            .expect("loopback is never a remote host"),
        PersonalAccessRefusal::Target(TargetRefusal::Loopback)
    );
}

// ------------------------------------------------------ canaries and invariance

fn key_needle() -> Vec<u8> {
    let hex = fs::read_to_string(required(KEY_NEEDLE)).expect("the canary must be readable");
    let hex = hex.trim();
    assert!(
        hex.len() >= 64 && hex.len() % 2 == 0,
        "the canary must be a full private scalar in hexadecimal"
    );
    (0..hex.len() / 2)
        .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hexadecimal"))
        .collect()
}

/// Nothing a finished session leaves behind contains the private key.
///
/// The agent never exports it, so this is the observable form of "authenticates
/// without exporting the key": the process that authenticated is searched — its
/// memory through a core dump, its environment, its command line, its two
/// output streams — together with both journals and every file it could have
/// written. A control copy of the same bytes is planted in the same directory
/// first, so that "absent" is a result of the search rather than of the search
/// being blind.
#[test]
fn a_finished_session_leaves_no_trace_of_the_private_key() {
    let needle = key_needle();
    let directory = scratch().join("canary");
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).expect("the canary directory must be creatable");

    let control = directory.join("control");
    fs::write(&control, &needle).expect("the control must be writable");
    assert!(
        file_contains(&control, &needle).expect("scan the control"),
        "the search must be able to find the canary when it is really there"
    );

    let ready = directory.join("ready");
    let mut fixture = Command::new(fixture_path())
        .arg(fixture_names::MODE_LINGER)
        .env(fixture_names::TARGET, required(TARGET))
        .env(fixture_names::PORT, required(PORT))
        .env(fixture_names::USERNAME, required(USERNAME))
        .env(fixture_names::HOST_KEY, required(HOST_KEY))
        .env(fixture_names::AUTHORIZED, required(AUTHORIZED))
        .env(fixture_names::READY_PATH, &ready)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the fixture must start");

    let deadline = Instant::now() + SETTLE_TIMEOUT;
    while !ready.exists() {
        if Instant::now() >= deadline {
            let _ = terminate_and_reap_bounded(&mut fixture, REAP_TIMEOUT);
            panic!("the fixture never completed a session");
        }
        thread::sleep(POLL_INTERVAL);
    }
    let pid = fixture.id();

    // A core is attempted, not required. The helper hardens itself
    // non-dumpable and refuses core files outright, so a run where no core can
    // be produced is a stronger result than one where a core is searched in
    // vain — but a privileged debugger can still take one, and that is exactly
    // the case worth searching.
    let dumped = Command::new("gcore")
        .arg("-o")
        .arg(directory.join("core"))
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    let core_path = fs::read_dir(&directory)
        .expect("read the canary directory")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("core"))
        });
    assert!(
        !dumped || core_path.is_some(),
        "the debugger reported a dump it did not produce"
    );

    // Both journals, captured straight to a file. They are redirected by the
    // shell rather than read through a pipe on purpose: a journal is far
    // larger than any bounded capture, and a reader that waits for the writer
    // to exit before draining the pipe would deadlock on exactly that size.
    let client_journal = directory.join("client-journal");
    capture(&client_journal, "journalctl -b --no-pager");
    let server_journal = directory.join("server-journal");
    capture(
        &server_journal,
        &format!("{} 'journalctl -b --no-pager'", required(SERVER_COMMAND)),
    );

    let mut searched: Vec<PathBuf> = vec![
        PathBuf::from(format!("/proc/{pid}/environ")),
        PathBuf::from(format!("/proc/{pid}/cmdline")),
        client_journal,
        server_journal,
    ];
    if let Some(core_path) = core_path {
        searched.push(core_path);
    }
    for entry in fs::read_dir(&directory).expect("read the canary directory") {
        let path = entry.expect("directory entry").path();
        if path != control && path.is_file() {
            searched.push(path);
        }
    }
    for path in &searched {
        assert!(
            !file_contains(path, &needle).unwrap_or(false),
            "the private key surfaced in {}",
            path.display()
        );
    }

    let output = {
        let _ = terminate_and_reap_bounded(&mut fixture, REAP_TIMEOUT);
        collect_output_bounded(fixture, REAP_TIMEOUT).expect("the fixture output must be bounded")
    };
    for stream in [&output.stdout, &output.stderr] {
        assert!(
            !canary_scan::contains_subslice(stream, &needle),
            "the private key surfaced on a fixture stream"
        );
    }
}

/// Writes what `command` prints into `path`, without ever holding it in memory.
fn capture(path: &Path, command: &str) {
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("{command} > \"$0\""))
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the capture must start");
    wait_bounded(&mut child, SERVER_TIMEOUT).expect("the capture must be bounded");
    assert!(path.exists(), "the capture produced nothing at all");
}

/// The perimeter this suite ran against is exactly the perimeter it started
/// from: no account, no authorised key and no agent identity moved.
#[test]
fn the_accounts_the_keys_and_the_agent_are_identical_before_and_after() {
    let inventory = "sha256sum /etc/passwd /etc/shadow /home/*/.ssh/authorized_keys | sort";
    let before = server(inventory);
    assert!(
        before.contains("authorized_keys"),
        "the inventory must really observe the authorised keys"
    );
    let agent_before = capture_local("ssh-add -l | sort");

    let username = required(USERNAME);
    let host_key = required(HOST_KEY);
    let authorized = required(AUTHORIZED);
    prepare()
        .run(
            &AuthenticationRequest {
                username: &username,
                approved_host_key_fingerprint: &host_key,
                selected_fingerprint: &authorized,
            },
            lease(),
            &always_continue(),
        )
        .outcome
        .expect("the nominal access must succeed");

    assert_eq!(
        server(inventory),
        before,
        "an access changed an account, a shadow entry or an authorised key"
    );
    assert_eq!(
        capture_local("ssh-add -l | sort"),
        agent_before,
        "an access changed what the agent holds"
    );
}

fn capture_local(command: &str) -> String {
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|child| collect_output_bounded(child, SERVER_TIMEOUT))
        .expect("the local capture must be bounded");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

// -------------------------------------------------- launched by the Console

/// Request identifier of the supervised personal access launch.
const SUPERVISED_REQUEST_ID: &str = "0123456789abcdef0123456789abcdef";
/// Request identifier of the escalation launch used as the control.
const ESCALATION_REQUEST_ID: &str = "fedcba9876543210fedcba9876543210";
/// Lease the Console gives a supervised helper here. It is generous on
/// purpose: the window only appears once the resolution, the address freeze,
/// the agent endpoint observation and the identity listing have all happened.
const SUPERVISED_LEASE_MILLIS: u64 = 60_000;
const SUPERVISED_LEASE: Duration = Duration::from_millis(SUPERVISED_LEASE_MILLIS);
/// Longest a supervised window may take to become observable.
const WINDOW_TIMEOUT: Duration = Duration::from_secs(30);
/// Title GTK gives the personal access window, and no other window.
const PERSONAL_ACCESS_TITLE: &str = "Your Cloud — autoriser l’accès personnel";
/// Title of the escalation window, which needs no agent at all.
const ESCALATION_TITLE: &str = "Your Cloud — mot de passe sudo";
/// The single environment name that can carry a Linux agent endpoint.
const ENDPOINT_VARIABLE: &str = "SSH_AUTH_SOCK";

/// The scope the Console submits for a real personal access against the LAB.
///
/// The host is the synthetic *name*, not the address, so reaching a window
/// also means the name was resolved once and its addresses frozen before
/// anything was displayed.
fn supervised_personal_access_scope() -> AssistantScopeV1 {
    AssistantScopeV1 {
        schema_version: 1,
        request_id: SUPERVISED_REQUEST_ID.into(),
        mode: BootstrapMode::Create,
        target: BootstrapTarget {
            host: required(NAME),
            port: required_port(PORT),
            username: required(USERNAME),
            host_key_sha256: required(HOST_KEY),
            access_kind: BootstrapAccessKind::Administrator,
        },
        step: BootstrapStep::PersonalAccess,
        actions: [BootstrapAction::AuditTargetReadOnly],
        prompt: NativePromptKind::ConfirmPersonalAccess,
        target_addresses: Vec::new(),
        // Both stamps are the launcher's to fill: it re-samples the shared
        // clock and recomputes what is left of the lease before transmitting.
        issued_at_monotonic_nanos: 0,
        remaining_millis: SUPERVISED_LEASE_MILLIS,
    }
}

/// The same launch, for the step that must never see an agent. It carries a
/// synthetic host because the escalation window opens without resolving
/// anything at all.
fn supervised_escalation_scope() -> AssistantScopeV1 {
    AssistantScopeV1 {
        request_id: ESCALATION_REQUEST_ID.into(),
        target: BootstrapTarget {
            host: "controller.example.test".into(),
            port: 22,
            username: "infra_admin".into(),
            host_key_sha256: required(HOST_KEY),
            access_kind: BootstrapAccessKind::Administrator,
        },
        step: BootstrapStep::PrivilegeEscalation,
        prompt: NativePromptKind::SudoPassword,
        ..supervised_personal_access_scope()
    }
}

/// One visible window, and the process the X server says owns it.
struct SupervisedWindow {
    pid: u32,
    title: String,
}

/// A helper launched by `supervisor`, observed through the window it opened.
///
/// The window is found by *ownership* and only then read: every visible window
/// is asked who owns it, and the one whose owner is a direct child of this
/// process is the supervised helper. The title is an assertion afterwards,
/// never the filter, so a window that opened under the wrong title fails the
/// case instead of being skipped over.
fn await_supervised_window(
    supervisor: &mut NativeAssistantSupervisor,
    request_id: &str,
) -> SupervisedWindow {
    let deadline = Instant::now() + WINDOW_TIMEOUT;
    loop {
        assert_eq!(
            supervisor.poll(request_id),
            Ok(NativeAssistantPoll::Running),
            "the supervised helper ended before opening a window"
        );
        if let Some(window) = visible_window_owned_by_a_child() {
            return window;
        }
        assert!(
            Instant::now() < deadline,
            "no visible window owned by a child of this Console appeared"
        );
        thread::sleep(POLL_INTERVAL);
    }
}

fn visible_window_owned_by_a_child() -> Option<SupervisedWindow> {
    let listing = xdotool(&["search", "--onlyvisible", "--name", "."])?;
    for window_id in listing.lines() {
        let window_id = window_id.trim();
        if window_id.is_empty() {
            continue;
        }
        let Some(pid) =
            xdotool(&["getwindowpid", window_id]).and_then(|pid| pid.trim().parse::<u32>().ok())
        else {
            continue;
        };
        if parent_of(pid) != Some(std::process::id()) {
            continue;
        }
        let title = xdotool(&["getwindowname", window_id])?.trim().to_owned();
        return Some(SupervisedWindow { pid, title });
    }
    None
}

/// Runs one bounded `xdotool` query, or answers nothing when it matched
/// nothing. A failing query is never a failing proof by itself: the caller
/// polls until its deadline.
fn xdotool(arguments: &[&str]) -> Option<String> {
    let child = Command::new("xdotool")
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("xdotool must be installed where a window is observed");
    let output = collect_output_bounded(child, REAP_TIMEOUT).expect("xdotool must be bounded");
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The parent this process table reports for `pid`.
///
/// The command field can itself contain spaces and parentheses, so the split
/// starts after its closing parenthesis: state is then the first field and the
/// parent identifier the second.
fn parent_of(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, after_command) = status.rsplit_once(')')?;
    after_command.split_whitespace().nth(1)?.parse().ok()
}

/// What the supervised helper actually received, read from the kernel rather
/// than from the launcher's intentions.
fn environment_of(pid: u32) -> Vec<String> {
    let environment = fs::read(format!("/proc/{pid}/environ"))
        .unwrap_or_else(|error| panic!("the helper environment must be observable: {error}"));
    environment
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| String::from_utf8_lossy(entry).into_owned())
        .collect()
}

/// A helper the *Console* launched really reaches the personal agent.
///
/// This is the case a unit test of the allowlist cannot make. The list of
/// names the launcher forwards can be asserted in isolation and still leave
/// the path unreachable in production, because what decides reachability is
/// the value arriving in a process that was started with `env_clear`, then
/// found by `observe_linux_endpoint`, then answered by a live agent.
///
/// The window is the observable form of all of that. `serve_personal_access`
/// opens one only after `Prepared::open` has resolved the name once, frozen
/// its addresses, read the endpoint from the environment, judged the socket
/// and obtained the identities the agent really holds — so a window carrying
/// the personal access title, owned by a child of this Console, is a proof
/// that the endpoint crossed the process boundary and led to a live agent.
/// The environment read back from the kernel then names the value itself.
#[test]
#[ignore = "requires the isolated Xvfb the LAB run provides"]
fn a_console_launched_helper_reaches_the_personal_agent_and_opens_its_window() {
    let endpoint = std::env::var(ENDPOINT_VARIABLE)
        .expect("this process must itself hold a live agent endpoint");
    assert!(
        std::env::var_os("DISPLAY").is_some(),
        "this case needs the isolated display the LAB run provides"
    );

    let path = PathBuf::from(env!("CARGO_BIN_EXE_your-cloud-native-bootstrap-assistant"));
    let name = path
        .file_name()
        .expect("the helper binary must be a file")
        .to_owned();
    let mut supervisor = NativeAssistantSupervisor::default();
    supervisor
        .start_with_path(
            &path,
            &name,
            supervised_personal_access_scope(),
            Instant::now() + SUPERVISED_LEASE,
        )
        .expect("the Console supervisor must launch the helper");

    let window = await_supervised_window(&mut supervisor, SUPERVISED_REQUEST_ID);
    assert_eq!(
        window.title, PERSONAL_ACCESS_TITLE,
        "the supervised helper opened a window that is not the personal access one"
    );

    let environment = environment_of(window.pid);
    assert!(
        environment.contains(&format!("{ENDPOINT_VARIABLE}={endpoint}")),
        "the helper reached its window without the endpoint the Console holds: {environment:?}"
    );

    // Cancelling from the Console closes the window, the helper and the agent
    // connection it opened, exactly as any other terminal path would.
    supervisor
        .cancel(SUPERVISED_REQUEST_ID)
        .expect("the Console must be able to cancel its own helper");
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    while process_alive(window.pid) {
        assert!(
            Instant::now() < deadline,
            "the cancelled helper is still alive at pid {}",
            window.pid
        );
        thread::sleep(POLL_INTERVAL);
    }
}

/// No other window is handed the user's signing oracle.
///
/// The endpoint is granted per step, not once per process: an escalation
/// window asks for a `sudo` password and has no use for an agent, so it must
/// not be able to reach one even though the Console that launched it can. The
/// same launch is otherwise identical, which is what makes the absence below
/// a decision rather than an accident of the environment.
#[test]
#[ignore = "requires the isolated Xvfb the LAB run provides"]
fn a_window_that_needs_no_agent_is_never_given_one() {
    assert!(
        std::env::var_os(ENDPOINT_VARIABLE).is_some(),
        "the control is meaningless unless this process holds an endpoint to withhold"
    );
    assert!(
        std::env::var_os("DISPLAY").is_some(),
        "this case needs the isolated display the LAB run provides"
    );

    let path = PathBuf::from(env!("CARGO_BIN_EXE_your-cloud-native-bootstrap-assistant"));
    let name = path
        .file_name()
        .expect("the helper binary must be a file")
        .to_owned();
    let mut supervisor = NativeAssistantSupervisor::default();
    supervisor
        .start_with_path(
            &path,
            &name,
            supervised_escalation_scope(),
            Instant::now() + SUPERVISED_LEASE,
        )
        .expect("the Console supervisor must launch the helper");

    let window = await_supervised_window(&mut supervisor, ESCALATION_REQUEST_ID);
    assert_eq!(
        window.title, ESCALATION_TITLE,
        "the control must really be the escalation window"
    );

    let environment = environment_of(window.pid);
    assert!(
        environment
            .iter()
            .any(|entry| entry.starts_with("DISPLAY=")),
        "the control window did receive the graphical allowlist: {environment:?}"
    );
    assert!(
        !environment
            .iter()
            .any(|entry| entry.starts_with(&format!("{ENDPOINT_VARIABLE}="))),
        "an escalation window was handed the personal agent endpoint: {environment:?}"
    );

    supervisor
        .cancel(ESCALATION_REQUEST_ID)
        .expect("the Console must be able to cancel its own helper");
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    while process_alive(window.pid) {
        assert!(
            Instant::now() < deadline,
            "the cancelled helper is still alive at pid {}",
            window.pid
        );
        thread::sleep(POLL_INTERVAL);
    }
}

// ------------------------------------- the window of this entry, as a process
//
// The three cases below are the personal access homologues of the window
// properties the process contract proves on the escalation couple. They are
// written here rather than there because the window they are about is reached
// through a different entry: `serve_personal_access` resolves the name, freezes
// the addresses, reads the agent endpoint and lists the identities *before*
// calling `prompt_with_identities`, and none of that exists on the escalation
// path. A proof taken on the simple path therefore says nothing about this one,
// and the perimeter is what makes this one runnable at all.
//
// Each case drives the shipped helper binary directly, over an authenticated
// socket pair, exactly as the process contract does: the Console's supervisor
// is deliberately not in between, because what is under test is the helper's
// own behaviour while its window is up, not the launcher's.

/// Request identifier of the launches this suite drives itself, with no
/// supervisor in between.
const DIRECT_REQUEST_ID: &str = "89abcdef0123456789abcdef01234567";
/// Lease given to a helper whose window this suite ends itself. It only has to
/// outlast the observation.
const LIVE_WINDOW_LEASE_MILLIS: u64 = 60_000;
/// Lease given to the helper the watchdog must cut *inside* its window.
///
/// It cannot be the hundred milliseconds the simple path uses: on this entry
/// the resolution, the address freeze, the endpoint observation and the
/// identity listing all consume the lease before any window exists, so such a
/// lease would expire with nothing on screen and the case would pass for the
/// opposite reason. It is instead long enough that the window is observed alive
/// with most of the lease still to run, which the case asserts rather than
/// assumes.
const WATCHDOG_LEASE_MILLIS: u64 = 12_000;
/// The grace the watchdog leaves for a controlled cleanup before it forces the
/// process down itself. A helper that stopped after this grace would have been
/// killed rather than have cut its own window.
const FORCED_FALLBACK_GRACE: Duration = Duration::from_secs(1);
/// Longest a helper may take to stop once its window has been ended.
const PROCESS_TIMEOUT: Duration = Duration::from_secs(10);

/// The personal access scope, addressed to the helper directly.
///
/// The launcher is what normally stamps the shared clock and the remaining
/// lease; here this process is the launcher, so it stamps them itself.
fn direct_personal_access_scope(remaining_millis: u64) -> AssistantScopeV1 {
    AssistantScopeV1 {
        request_id: DIRECT_REQUEST_ID.into(),
        issued_at_monotonic_nanos: monotonic_nanos().expect("shared monotonic clock"),
        remaining_millis,
        ..supervised_personal_access_scope()
    }
}

/// Frames a scope the way the Console's transport does.
///
/// The length prefix has the same shape as the agent's, and is deliberately not
/// the same function: the two protocols are free to diverge, and one helper
/// serving both would hide the day they do.
fn scope_frame(scope: &AssistantScopeV1) -> Vec<u8> {
    payload_frame(&serde_json::to_vec(scope).expect("a scope is serialisable"))
}

fn payload_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = u32::try_from(payload.len())
        .expect("a bounded payload")
        .to_be_bytes()
        .to_vec();
    frame.extend_from_slice(payload);
    frame
}

fn decode_event(output: &[u8]) -> AssistantEventV1 {
    assert!(output.len() >= 4, "an event frame carries its own length");
    let length = u32::from_be_bytes(output[..4].try_into().expect("four bytes")) as usize;
    assert_eq!(output.len(), length + 4, "exactly one event frame");
    serde_json::from_slice::<AssistantEventV1>(&output[4..])
        .expect("a well-formed event")
        .validate()
        .expect("a valid event")
}

/// The shipped helper, invoked exactly as the Console invokes it.
///
/// Nothing is removed from the environment: the display and the agent endpoint
/// this process holds are precisely what the window under test needs.
fn helper_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_your-cloud-native-bootstrap-assistant"));
    command
        .arg(REQUIRED_MODE_ARGUMENT)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Starts a helper whose standard input is a socket this process owns, which
/// is what the helper's parent attestation reads.
fn spawn_authenticated(mut command: Command) -> (Child, UnixStream) {
    let (child_input, parent_lease) = UnixStream::pair().expect("a socket pair for the lease");
    command.stdin(Stdio::from(OwnedFd::from(child_input)));
    (
        command.spawn().expect("the helper must start"),
        parent_lease,
    )
}

/// Waits for a visible window `child` itself owns, and answers its title.
///
/// The lookup is by the helper's own process identifier, and the owner is then
/// read back from the X server, so no other window on this display can stand in
/// for it. The helper is checked alive before and after: a window observed on a
/// process that has already gone would say nothing about a *live* prompt, which
/// is the only thing the three cases below are about.
fn await_live_window_of(child: &mut Child, timeout: Duration) -> Result<String, String> {
    let process_id = child.id().to_string();
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!(
                "the helper exited before any window of its own existed: {status}"
            ));
        }
        if let Some(title) = window_owned_by(&process_id) {
            return match child.try_wait() {
                Ok(None) => Ok(title),
                other => Err(format!(
                    "the helper exited as its window was read: {other:?}"
                )),
            };
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "no visible window owned by the helper appeared within {timeout:?}"
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// The title of one visible window `process_id` owns, when there is one.
///
/// `xdotool search` is asked without `--sync` on purpose: a blocking search
/// would keep waiting on a helper that has already died, and the caller's job
/// is precisely to tell those two situations apart.
fn window_owned_by(process_id: &str) -> Option<String> {
    let listing = xdotool(&["search", "--onlyvisible", "--pid", process_id, "."])?;
    let window_id = listing.lines().next()?.trim().to_owned();
    if window_id.parse::<u64>().is_err() {
        return None;
    }
    let owner = xdotool(&["getwindowpid", &window_id])?;
    if owner.trim() != process_id {
        return None;
    }
    Some(xdotool(&["getwindowname", &window_id])?.trim().to_owned())
}

/// Ends a helper the case could not observe, and says why it gave up.
fn abandon(child: &mut Child, reason: &str) -> ! {
    let cleanup = terminate_and_reap_bounded(child, REAP_TIMEOUT);
    panic!("{reason}; cleanup: {cleanup:?}");
}

/// The watchdog cuts the personal access window while it is really open, and
/// cuts it itself rather than being forced down.
///
/// Two failures must never be confused here, and the whole shape of the case is
/// what separates them. A lease that ran out during the resolution, the endpoint
/// observation or the identity listing — all of which happen before this entry
/// has a window — ends the same process with the same exit code, and a case that
/// only read that code would be green without a window ever having existed. So
/// the window is observed alive first, and it is required to have been observed
/// with most of the lease still to run; only then is the expiry awaited.
///
/// The second distinction is between the watchdog's own controlled cut and its
/// forced fallback: both exit with the same status, but only the controlled one
/// leaves the expurgated `Expired` frame on standard output, and only it happens
/// inside the cleanup grace. Both are asserted.
#[test]
#[ignore = "requires the isolated Xvfb the LAB run provides"]
fn the_watchdog_cuts_a_live_personal_access_window_before_the_forced_fallback() {
    assert!(
        std::env::var_os("DISPLAY").is_some(),
        "this case needs the isolated display the LAB run provides"
    );
    assert!(
        std::env::var_os(ENDPOINT_VARIABLE).is_some(),
        "this case needs the live agent endpoint the LAB run provides"
    );

    let lease = Duration::from_millis(WATCHDOG_LEASE_MILLIS);
    // Sampled before the scope stamps the shared clock, so the helper's own
    // deadline can only be later than this origin plus the lease.
    let started = Instant::now();
    let scope = direct_personal_access_scope(WATCHDOG_LEASE_MILLIS);
    let (mut child, mut parent_lease) = spawn_authenticated(helper_command());
    parent_lease
        .write_all(&scope_frame(&scope))
        .expect("the scope must reach the helper");
    parent_lease.flush().expect("the scope must be flushed");

    let title = match await_live_window_of(&mut child, WINDOW_TIMEOUT) {
        Ok(title) => title,
        Err(error) => abandon(
            &mut child,
            &format!("the watchdog case never saw the window it must cut: {error}"),
        ),
    };
    let observed_at = started.elapsed();
    assert_eq!(
        title, PERSONAL_ACCESS_TITLE,
        "the helper opened a window that is not the personal access one"
    );
    assert!(
        observed_at * 2 < lease,
        "the window only became observable at {observed_at:?} of a {lease:?} lease: \
         what expires afterwards is no longer distinguishable from what never opened"
    );

    let output = collect_output_bounded(child, lease - observed_at + PROCESS_TIMEOUT)
        .expect("the expiring helper must stop under a bound");
    let elapsed = started.elapsed();
    drop(parent_lease);

    assert_eq!(
        output.status.code(),
        Some(EXIT_WATCHDOG_EXPIRED.into()),
        "a window cut by the watchdog exits as expired"
    );
    assert!(
        elapsed >= lease,
        "the helper stopped at {elapsed:?}, before its {lease:?} lease could have run out"
    );
    assert!(
        elapsed < lease + FORCED_FALLBACK_GRACE,
        "the helper stopped at {elapsed:?}, past the cleanup grace: it was forced down \
         rather than having cut its own window"
    );
    assert_eq!(
        decode_event(&output.stdout),
        AssistantEventV1 {
            schema_version: 1,
            request_id: DIRECT_REQUEST_ID.into(),
            event: AssistantEventKind::Expired,
        },
        "only a controlled cut writes the expurgated expiry"
    );
    assert!(output.stderr.is_empty());
}

/// While the personal access window is open, no descriptor above stdio survives
/// from the launcher.
///
/// The closure itself happens when the helper hardens, long before any window
/// exists; what this case adds over its homologue on the simple path is *when*
/// it is observed. This entry is the one that opens an agent socket and a
/// transport of its own after hardening, so the honest question is whether the
/// leaked descriptor is still gone once all of that has happened and the window
/// is up. The order below is therefore the claim: window first, end of file
/// second, helper still running third.
#[test]
#[ignore = "requires the isolated Xvfb the LAB run provides"]
fn a_live_personal_access_window_holds_no_inherited_descriptor_outside_stdio() {
    assert!(
        std::env::var_os("DISPLAY").is_some(),
        "this case needs the isolated display the LAB run provides"
    );

    let mut inherited = [-1; 2];
    // SAFETY: storage is valid for both descriptors. O_CLOEXEC keeps every other
    // process of this run from inheriting either endpoint before the intended
    // child is forked.
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
    let mut helper = helper_command();
    // SAFETY: fcntl is async-signal-safe. Only the forked child clears CLOEXEC on
    // its own copy, so exactly this helper receives the hostile descriptor.
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
    let (mut child, mut parent_lease) = spawn_authenticated(helper);
    drop(writer);
    parent_lease
        .write_all(&scope_frame(&direct_personal_access_scope(
            LIVE_WINDOW_LEASE_MILLIS,
        )))
        .expect("the scope must reach the helper");
    parent_lease.flush().expect("the scope must be flushed");

    let title = match await_live_window_of(&mut child, WINDOW_TIMEOUT) {
        Ok(title) => title,
        Err(error) => abandon(
            &mut child,
            &format!("the descriptor case never saw a live window: {error}"),
        ),
    };

    // A closed inherited writer is observable as end of file without reading
    // `/proc/<pid>/fd`, which the helper denies to this very user once it has
    // made itself non-dumpable.
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
    let inherited_writer_closed = read_eof_bounded(&mut reader, PIPE_EOF_TIMEOUT);
    let child_was_still_running = matches!(child.try_wait(), Ok(None));

    let reaped = terminate_and_reap_bounded(&mut child, REAP_TIMEOUT);
    drop(parent_lease);

    assert_eq!(
        title, PERSONAL_ACCESS_TITLE,
        "the helper opened a window that is not the personal access one"
    );
    assert!(
        inherited_writer_closed.expect("the inherited descriptor must be observable"),
        "the personal access window was open while a launcher descriptor was still held"
    );
    assert!(
        child_was_still_running,
        "the helper died before the observation, so nothing was observed of a live window"
    );
    assert!(reaped.is_ok());
}

/// What a mutation of the agreed scope may change while the window is up.
#[derive(Clone, Copy)]
enum MutationKind {
    Target,
    Step,
    Action,
    Expiration,
}

impl MutationKind {
    const ALL: [Self; 4] = [Self::Target, Self::Step, Self::Action, Self::Expiration];

    fn name(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Step => "step",
            Self::Action => "action",
            Self::Expiration => "expiration",
        }
    }
}

fn mutation_frame(initial: &AssistantScopeV1, mutation_kind: MutationKind) -> Vec<u8> {
    match mutation_kind {
        MutationKind::Target => {
            // A well-formed host, so the frame is refused for arriving after the
            // scope rather than for being malformed. It is never resolved: the
            // addresses this window displays were frozen before it opened.
            let mut target = initial.clone();
            target.target.host = "other-controller.example.test".into();
            scope_frame(&target)
        }
        MutationKind::Step => {
            // Another admissible step, carrying the prompt that step requires:
            // the frame must be refused because it arrives after the scope, not
            // because it is malformed.
            let mut step = initial.clone();
            step.step = BootstrapStep::UnlockPersonalKey;
            step.prompt = NativePromptKind::KeyPassphrase;
            scope_frame(&step)
        }
        MutationKind::Action => {
            let mut action = serde_json::to_value(initial).expect("a scope is serialisable");
            action["actions"] = serde_json::json!(["install_controller"]);
            payload_frame(&serde_json::to_vec(&action).expect("a mutated scope is serialisable"))
        }
        MutationKind::Expiration => {
            let mut expiration = initial.clone();
            expiration.remaining_millis = LIVE_WINDOW_LEASE_MILLIS - 1_000;
            scope_frame(&expiration)
        }
    }
}

/// A live personal access window refuses every later word from its launcher.
///
/// The four mutations are the ones the consent is about: the machine it names,
/// the step it belongs to, the action it authorises and how long it lasts. Each
/// is sent *while the window is up* — the window is observed alive first, and
/// the case abandons rather than sends if it never appeared — so what is proven
/// is a refusal by a running dialog and not a refusal by a helper that had
/// already finished with its input.
///
/// Nothing is announced in return: the refusal is a bare exit status, with both
/// streams empty, because a helper that described what it had just refused would
/// be answering the launcher that tried it.
#[test]
#[ignore = "requires the isolated Xvfb the LAB run provides"]
fn a_live_personal_access_window_refuses_target_step_action_and_expiration_mutations() {
    assert!(
        std::env::var_os("DISPLAY").is_some(),
        "this case needs the isolated display the LAB run provides"
    );

    for mutation_kind in MutationKind::ALL {
        let initial = direct_personal_access_scope(LIVE_WINDOW_LEASE_MILLIS);
        let mutation = mutation_frame(&initial, mutation_kind);
        let (mut child, mut parent_lease) = spawn_authenticated(helper_command());
        parent_lease
            .write_all(&scope_frame(&initial))
            .expect("the scope must reach the helper");
        parent_lease.flush().expect("the scope must be flushed");

        let title = match await_live_window_of(&mut child, WINDOW_TIMEOUT) {
            Ok(title) => title,
            Err(error) => abandon(
                &mut child,
                &format!(
                    "the {} mutation never reached a live window: {error}",
                    mutation_kind.name()
                ),
            ),
        };
        assert_eq!(
            title,
            PERSONAL_ACCESS_TITLE,
            "the {} mutation was aimed at a window that is not the personal access one",
            mutation_kind.name()
        );

        parent_lease
            .write_all(&mutation)
            .expect("the mutation must reach the helper");
        parent_lease.flush().expect("the mutation must be flushed");
        let output = collect_output_bounded(child, PROCESS_TIMEOUT).unwrap_or_else(|error| {
            panic!(
                "the {} mutation left the helper running: {error}",
                mutation_kind.name()
            )
        });
        drop(parent_lease);

        assert_eq!(
            output.status.code(),
            Some(EXIT_PROTOCOL_REFUSED.into()),
            "the {} mutation must be refused as extra protocol input",
            mutation_kind.name()
        );
        assert!(
            output.stdout.is_empty(),
            "the {} mutation was answered on standard output",
            mutation_kind.name()
        );
        assert!(
            output.stderr.is_empty(),
            "the {} mutation was answered on standard error",
            mutation_kind.name()
        );
    }
}

// ------------------------------------------- the encrypted key file fallback
//
// Everything below is the other half of the same palier: when the agent is not
// retained, the *same* state machine opens an encrypted OpenSSH key the user
// selected, derives it in memory under the same deadline, and uses it for the
// same single approved connection. The proofs are therefore written against the
// same server, the same accounts, the same probe and the same budget as the
// agent path above — a fallback proven against a perimeter of its own would say
// nothing about the session it is supposed to join.
//
// Every key file is synthetic, generated when the perimeter is mounted and
// destroyed when it is removed. Every refusal below is paired with the control
// that shows the same call succeeding on a file that is in contract: a refusal
// that refuses everything proves nothing.

/// Directory holding the synthetic key files.
///
/// The names *inside* it are this harness's own layout and are written here
/// rather than exported one by one: they carry no address, no account and no
/// key material, only which shape each file has.
const KEY_DIR: &str = "YOUR_CLOUD_LAB_KEY_DIR";
/// File holding the synthetic passphrase of every encrypted key file.
const KEY_PASSPHRASE: &str = "YOUR_CLOUD_LAB_KEY_PASSPHRASE";
/// File holding, in hexadecimal, the raw private scalar of the nominal Ed25519
/// key *file*. It is the second canary of this suite: unlike the agent's, this
/// one really does enter the process, so its absence afterwards is a claim
/// about zeroisation rather than about never having held it.
const KEY_SEED_NEEDLE: &str = "YOUR_CLOUD_LAB_KEY_SEED_NEEDLE";
/// Fingerprint the nominal Ed25519 key file carries.
const KEY_ED25519_FINGERPRINT: &str = "YOUR_CLOUD_LAB_KEY_ED25519_FINGERPRINT";
/// Fingerprint the nominal RSA 3072 key file carries.
const KEY_RSA_FINGERPRINT: &str = "YOUR_CLOUD_LAB_KEY_RSA_FINGERPRINT";

/// The nominal Ed25519 file, encrypted with the default sixteen rounds.
const NOMINAL_ED25519: &str = "ed25519";
/// The nominal RSA file, at the smallest modulus the perimeter accepts.
const NOMINAL_RSA: &str = "rsa3072";
/// A second Ed25519 file, same passphrase, different key.
const REPLACEMENT: &str = "replacement";
/// A file whose declared round count sits exactly on the accepted bound.
const BOUND_ROUNDS: &str = "bound";
/// A file whose derivation is slow enough to still be running when a short
/// lease fires, and quick enough to finish under a full one.
const SLOW: &str = "slow";

/// Longest a derivation on the reference host may take, with room to spare.
const DERIVATION_TIMEOUT: Duration = Duration::from_secs(60);
/// A lease far too short for the slow file's derivation to complete under it.
const SHORT_DERIVATION_LEASE: Duration = Duration::from_millis(200);

fn key_directory() -> PathBuf {
    PathBuf::from(required(KEY_DIR))
}

fn key_file(name: &str) -> PathBuf {
    key_directory().join(name)
}

fn key_passphrase() -> Vec<u8> {
    let passphrase = fs::read(required(KEY_PASSPHRASE)).expect("the passphrase must be readable");
    assert!(
        passphrase.len() >= 32,
        "the synthetic passphrase must really have been generated"
    );
    passphrase
}

/// Opens and derives one key file, under a lease long enough for the bound.
fn open_key(name: &str) -> key_unlock::PersonalKey {
    let selected = key_file::open_and_validate(&key_file(name))
        .unwrap_or_else(|refusal| panic!("{name} must be openable: {refusal:?}"));
    key_unlock::unlock_with_passphrase(
        selected,
        &key_passphrase(),
        Instant::now() + DERIVATION_TIMEOUT,
    )
    .unwrap_or_else(|refusal| panic!("{name} must derive: {refusal:?}"))
}

/// Sha256 of every file of the perimeter's key directory, read on this machine.
fn key_directory_digest() -> String {
    capture_local(&format!(
        "find {} -maxdepth 1 -type f -print0 | sort -z | xargs -0 sha256sum",
        key_directory().display()
    ))
}

/// Runs one whole personal access authenticated by an opened key file.
fn run_with_key_file(name: &str, username: &str) -> RunObservation {
    let key = open_key(name);
    let fingerprint = key.fingerprint().to_owned();
    let host_key = required(HOST_KEY);
    prepare().run_with_key(
        key,
        &AuthenticationRequest {
            username,
            approved_host_key_fingerprint: &host_key,
            selected_fingerprint: &fingerprint,
        },
        lease(),
        &always_continue(),
    )
}

/// The whole fallback, end to end, against the real server: one file opened
/// once, one derivation, one transport, one probe — and exactly one signature.
///
/// It is deliberately asserted with the same values as the agent's nominal
/// case: the same uid from the same fixed probe, the same host key type, the
/// same single signature. That is the claim — not that a second path works,
/// but that it is the same path.
#[test]
fn a_nominal_ed25519_key_file_spends_exactly_one_signature() {
    let before = key_directory_digest();
    let username = required(USERNAME);
    let observation = run_with_key_file(NOMINAL_ED25519, &username);
    let report = observation
        .outcome
        .expect("the nominal key file access must succeed");

    assert_eq!(report.exit_status, 0);
    assert_eq!(
        String::from_utf8_lossy(&report.stdout).trim(),
        required(EXPECTED_UID),
        "the probe must report the synthetic account's own uid"
    );
    assert!(report.stderr.is_empty());
    assert_eq!(report.host_key_type, HostKeyType::Ed25519);
    assert_eq!(
        report.signatures_spent, MAX_AUTHENTICATION_SIGNATURES,
        "one access costs one signature, whoever holds the key"
    );
    assert_eq!(observation.remaining_signatures, 0);
    assert_eq!(
        observation.stream_refusal, None,
        "no agent stream exists on this path at all"
    );
    assert_eq!(
        key_directory_digest(),
        before,
        "the personal file must stay bit for bit unchanged"
    );
}

/// The same, with RSA at the smallest accepted modulus.
///
/// The signature it produces can only be `rsa-sha2-512`: the session names that
/// hash and the budget refuses every other pairing, so a server that accepted
/// this authentication accepted a SHA-2 signature and never a SHA-1 one.
#[test]
fn a_nominal_rsa_3072_key_file_authenticates_and_never_signs_with_sha1() {
    let before = key_directory_digest();
    let username = required(USERNAME);
    let key = open_key(NOMINAL_RSA);
    assert!(
        matches!(key.algorithm(), russh::keys::Algorithm::Rsa { .. }),
        "the RSA file must really open as an RSA key"
    );
    assert_eq!(key.fingerprint(), required(KEY_RSA_FINGERPRINT));
    drop(key);

    let observation = run_with_key_file(NOMINAL_RSA, &username);
    let report = observation
        .outcome
        .expect("the RSA 3072 key file access must succeed");
    assert_eq!(report.exit_status, 0);
    assert_eq!(
        String::from_utf8_lossy(&report.stdout).trim(),
        required(EXPECTED_UID)
    );
    assert_eq!(report.signatures_spent, MAX_AUTHENTICATION_SIGNATURES);
    assert_eq!(observation.remaining_signatures, 0);
    assert_eq!(key_directory_digest(), before);
}

/// Every envelope outside the contract is refused, and refused before a
/// passphrase could ever be asked for.
///
/// The ordering is structural rather than asserted by a timer: opening and
/// validating is one call, asking for the passphrase is another, and the second
/// is only reachable through an `Ok` of the first. What the table proves is
/// that each of these files stops at the first.
#[test]
fn every_envelope_outside_the_contract_is_refused_before_any_passphrase() {
    use your_cloud_native_bootstrap_assistant::personal_access::openssh_key::EnvelopeRefusal;

    for (name, expected) in [
        // The single most important one: a key in the clear. OpenSSH writes
        // `none` for both the cipher and the key derivation, and the cipher is
        // the first of the two to be read — the unit tests of `openssh_key`
        // hold each of them separately.
        ("clear", KeyFileRefusal::Envelope(EnvelopeRefusal::Cipher)),
        // The foreign formats, written by the tools that really write them.
        (
            "pkcs1",
            KeyFileRefusal::Envelope(EnvelopeRefusal::PemEnvelope),
        ),
        (
            "pkcs8",
            KeyFileRefusal::Envelope(EnvelopeRefusal::PemEnvelope),
        ),
        (
            "sec1",
            KeyFileRefusal::Envelope(EnvelopeRefusal::PemEnvelope),
        ),
        (
            "ppk",
            KeyFileRefusal::Envelope(EnvelopeRefusal::PemEnvelope),
        ),
        // An RSA key one step below the accepted modulus.
        (
            "rsa2048",
            KeyFileRefusal::Envelope(EnvelopeRefusal::RsaTooSmall),
        ),
        // Declarations rewritten out of contract.
        (
            "wrong-cipher",
            KeyFileRefusal::Envelope(EnvelopeRefusal::Cipher),
        ),
        ("wrong-kdf", KeyFileRefusal::Envelope(EnvelopeRefusal::Kdf)),
        (
            "rounds-zero",
            KeyFileRefusal::Envelope(EnvelopeRefusal::Rounds),
        ),
        (
            "rounds-over",
            KeyFileRefusal::Envelope(EnvelopeRefusal::Rounds),
        ),
        (
            "trailing",
            KeyFileRefusal::Envelope(EnvelopeRefusal::TrailingData),
        ),
        // And a file larger than the bound, refused before it is parsed.
        ("oversized", KeyFileRefusal::TooLarge),
    ] {
        let path = key_file(name);
        assert!(path.is_file(), "the perimeter never wrote {name}");
        let refusal = key_file::open_and_validate(&path)
            .err()
            .unwrap_or_else(|| panic!("{name} must never be opened as a personal key"));
        assert_eq!(refusal, expected, "{name} was refused for the wrong reason");
    }

    // The controls. The same call, on the two files that are in contract, and
    // it accepts them — with the envelope it really read.
    let nominal = key_file::open_and_validate(&key_file(NOMINAL_ED25519))
        .expect("the nominal Ed25519 file must be accepted");
    assert_eq!(nominal.envelope().key_type, IdentityKeyType::Ed25519);
    assert_eq!(nominal.envelope().rsa_modulus_bits, None);
    assert!(nominal.envelope().rounds >= 1 && nominal.envelope().rounds <= MAX_BCRYPT_ROUNDS);

    let rsa = key_file::open_and_validate(&key_file(NOMINAL_RSA))
        .expect("the nominal RSA file must be accepted");
    assert_eq!(rsa.envelope().key_type, IdentityKeyType::Rsa);
    assert_eq!(rsa.envelope().rsa_modulus_bits, Some(3072));

    // And the bound the oversized file is refused against is the decided one.
    assert_eq!(
        fs::metadata(key_file("oversized"))
            .expect("the oversized sample must exist")
            .len(),
        MAX_KEY_FILE_BYTES as u64 + 1,
        "one byte past the bound, and not a byte more"
    );
}

/// A symbolic link is refused rather than followed, and so is anything that is
/// not a regular file.
///
/// The link points at a file that is perfectly valid, which is the point: what
/// is refused is the indirection, not the target.
#[test]
fn a_symbolic_link_is_refused_rather_than_followed() {
    let directory = scratch().join("key-links");
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).expect("the link directory must be creatable");

    let link = directory.join("linked-key");
    std::os::unix::fs::symlink(key_file(NOMINAL_ED25519), &link)
        .expect("the synthetic link must be creatable");
    assert_eq!(
        key_file::open_and_validate(&link).err(),
        Some(KeyFileRefusal::SymbolicLink),
        "a link is an instruction to read elsewhere, never a key file"
    );

    // The control: the very same bytes, copied rather than linked, open.
    let copy = directory.join("copied-key");
    fs::copy(key_file(NOMINAL_ED25519), &copy).expect("the copy must be writable");
    assert!(
        key_file::open_and_validate(&copy).is_ok(),
        "the refusal above is about the link and not about the key"
    );

    assert_eq!(
        key_file::open_and_validate(&directory).err(),
        Some(KeyFileRefusal::NotRegularFile)
    );
}

/// The central property: a file replaced between validation and use is refused.
///
/// The replacement is a *valid* encrypted key with the very same passphrase, so
/// nothing about it would fail on its own. What must fail is that it is not the
/// file the user selected and the one that was validated. The control runs the
/// identical sequence without the replacement and derives.
#[test]
fn a_file_replaced_between_validation_and_use_is_refused() {
    let directory = scratch().join("key-substitution");
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).expect("the substitution directory must be creatable");
    let passphrase = key_passphrase();

    // The control first, so "refused" below cannot be a broken perimeter.
    let control = directory.join("control-key");
    fs::copy(key_file(NOMINAL_ED25519), &control).expect("the control must be writable");
    let selected = key_file::open_and_validate(&control).expect("the control must be accepted");
    assert!(
        key_unlock::unlock_with_passphrase(
            selected,
            &passphrase,
            Instant::now() + DERIVATION_TIMEOUT
        )
        .is_ok(),
        "the same sequence without a replacement must derive"
    );

    // And now the same sequence, with another key moved on top of the name
    // between the validation and the use.
    let subject = directory.join("subject-key");
    fs::copy(key_file(NOMINAL_ED25519), &subject).expect("the subject must be writable");
    let selected = key_file::open_and_validate(&subject).expect("the subject must be accepted");

    let substitute = directory.join("substitute-key");
    fs::copy(key_file(REPLACEMENT), &substitute).expect("the substitute must be writable");
    fs::rename(&substitute, &subject).expect("the substitution must succeed");

    assert_eq!(
        key_unlock::unlock_with_passphrase(
            selected,
            &passphrase,
            Instant::now() + DERIVATION_TIMEOUT
        )
        .err(),
        Some(UnlockRefusal::File(KeyFileRefusal::Substituted)),
        "the file that was validated is no longer the file this path names"
    );

    // A file rewritten in place under a stable inode is the same refusal, and
    // it is the one a device-and-inode comparison alone would miss.
    let rewritten = directory.join("rewritten-key");
    fs::copy(key_file(NOMINAL_ED25519), &rewritten).expect("the subject must be writable");
    let selected = key_file::open_and_validate(&rewritten).expect("the subject must be accepted");
    let replacement_bytes = fs::read(key_file(REPLACEMENT)).expect("the replacement must be read");
    fs::write(&rewritten, &replacement_bytes).expect("the rewrite must succeed");
    assert_eq!(
        key_unlock::unlock_with_passphrase(
            selected,
            &passphrase,
            Instant::now() + DERIVATION_TIMEOUT
        )
        .err(),
        Some(UnlockRefusal::File(KeyFileRefusal::Substituted)),
        "an inode that kept its number while its content moved is still a substitution"
    );
}

/// A wrong passphrase is one refusal, with no retry and nothing kept.
///
/// "Nothing kept" is enforced by the type rather than asserted: the derivation
/// consumes both the opened file and the passphrase, so the value that would
/// have to be retried no longer exists once this call has returned. What the
/// case adds is that the refusal is real — the same file, with the right
/// passphrase, derives — and that the file on disk did not move either.
#[test]
fn a_wrong_passphrase_refuses_without_retry_and_keeps_nothing() {
    let before = key_directory_digest();
    let mut wrong = key_passphrase();
    wrong.push(b'x');

    let selected =
        key_file::open_and_validate(&key_file(NOMINAL_ED25519)).expect("the nominal file opens");
    assert_eq!(
        key_unlock::unlock_with_passphrase(selected, &wrong, Instant::now() + DERIVATION_TIMEOUT)
            .err(),
        Some(UnlockRefusal::Passphrase)
    );

    // The control: the same file, the same call, the right passphrase.
    let selected =
        key_file::open_and_validate(&key_file(NOMINAL_ED25519)).expect("the nominal file opens");
    let key = key_unlock::unlock_with_passphrase(
        selected,
        &key_passphrase(),
        Instant::now() + DERIVATION_TIMEOUT,
    )
    .expect("the right passphrase must open the same file");
    assert_eq!(key.fingerprint(), required(KEY_ED25519_FINGERPRINT));

    assert_eq!(
        key_directory_digest(),
        before,
        "a refused passphrase must not have touched the file"
    );
}

/// A lease that runs out *during* the derivation is an expiration.
///
/// The refusal and its control differ by one thing only: the deadline. The very
/// same file, with the very same passphrase, derives when the lease can pay for
/// it — which is what says the refusal is the deadline firing rather than the
/// file being unusable. And the timings separate the two failures that would
/// otherwise look alike: the expiry is reported when the lease fires, long
/// before the derivation could have finished, so what was cut was a derivation
/// that had really started.
#[test]
fn a_lease_that_runs_out_during_the_derivation_is_an_expiry() {
    let passphrase = key_passphrase();

    // The highest round count the perimeter accepts is a real file, and its
    // envelope is accepted on the bound rather than one step inside it.
    let on_the_bound =
        key_file::open_and_validate(&key_file(BOUND_ROUNDS)).expect("the bound file opens");
    assert_eq!(
        on_the_bound.envelope().rounds,
        MAX_BCRYPT_ROUNDS,
        "the bound file must declare exactly the accepted maximum"
    );
    drop(on_the_bound);

    let selected = key_file::open_and_validate(&key_file(SLOW)).expect("the slow file opens");
    let started = Instant::now();
    assert_eq!(
        key_unlock::unlock_with_passphrase(
            selected,
            &passphrase,
            Instant::now() + SHORT_DERIVATION_LEASE
        )
        .err(),
        Some(UnlockRefusal::Expired),
        "a derivation the lease cannot pay for is an expiry"
    );
    let refused_after = started.elapsed();
    assert!(
        refused_after >= SHORT_DERIVATION_LEASE,
        "the expiry was reported at {refused_after:?}, before the lease could have fired"
    );

    // The control: the same file, the same passphrase, a lease that can pay.
    let selected = key_file::open_and_validate(&key_file(SLOW)).expect("the slow file opens");
    let started = Instant::now();
    let key = key_unlock::unlock_with_passphrase(
        selected,
        &passphrase,
        Instant::now() + DERIVATION_TIMEOUT,
    )
    .expect("the same file must derive under a lease that can pay");
    let derived_after = started.elapsed();
    assert!(key.fingerprint().starts_with("SHA256:"));
    assert!(
        derived_after > refused_after * 2,
        "the derivation finished in {derived_after:?} and the expiry fired at \
         {refused_after:?}: the lease cut nothing that was still running"
    );
}

/// A key file access changes nothing: not the file, not the accounts, not the
/// authorised keys, not what the agent holds.
#[test]
fn a_key_file_access_leaves_the_file_and_the_perimeter_identical() {
    let inventory = "sha256sum /etc/passwd /etc/shadow /home/*/.ssh/authorized_keys | sort";
    let server_before = server(inventory);
    assert!(server_before.contains("authorized_keys"));
    let agent_before = capture_local("ssh-add -l | sort");
    let files_before = key_directory_digest();
    assert!(
        files_before.contains(NOMINAL_ED25519),
        "the digest must really observe the key files"
    );

    let username = required(USERNAME);
    run_with_key_file(NOMINAL_ED25519, &username)
        .outcome
        .expect("the nominal key file access must succeed");

    assert_eq!(
        key_directory_digest(),
        files_before,
        "the personal key file must stay bit for bit unchanged"
    );
    assert_eq!(
        server(inventory),
        server_before,
        "a key file access changed an account, a shadow entry or an authorised key"
    );
    assert_eq!(
        capture_local("ssh-add -l | sort"),
        agent_before,
        "a key file access must not have touched the agent at all"
    );
}

/// Reads the canary of the key *file*: the private scalar the derivation really
/// produces inside the process.
fn key_seed_needle() -> Vec<u8> {
    let hex = fs::read_to_string(required(KEY_SEED_NEEDLE)).expect("the canary must be readable");
    let hex = hex.trim();
    assert!(
        hex.len() >= 64 && hex.len() % 2 == 0,
        "the canary must be a full private scalar in hexadecimal"
    );
    (0..hex.len() / 2)
        .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hexadecimal"))
        .collect()
}

/// What a finished key file session leaves behind, and what it does not.
///
/// This is the sharper form of the agent's canary case. There, the private key
/// never entered the process at all, so its absence was almost a tautology.
/// Here it did: the file was opened, the passphrase was typed into the
/// process's own protected memory, the derivation produced the scalar and the
/// transport used it. Two claims are therefore separated, because they are not
/// the same claim.
///
/// The **passphrase** must be absent everywhere, the core included. It only
/// ever lives in the protected allocation — locked, excluded from dumps — and
/// it is wiped when the derivation lets go of it. A privileged debugger's core
/// is searched for it, and the search is shown not to be blind by finding, in
/// that same core, something this process really does hold in ordinary memory.
///
/// The **private key** must be absent from everything this process emits — its
/// environment, its command line, both journals, every file it could have
/// written and both of its streams — and, since the key is held behind a box,
/// from the core as well.
///
/// That last claim is asserted here because it was first measured. An unboxed
/// key left eighteen copies of the private scalar in the dump of a process
/// whose session was already over: one per *move* of the value, a move in Rust
/// being a byte copy that leaves the source frame untouched, so nothing drops
/// it and nothing wipes it. None of the eighteen came from the decoding
/// buffers of the pinned RustCrypto stack — each was a `public || private`
/// pair with the key file's own comment string beside it, which is the shape
/// of `ssh-key`'s `PrivateKey` and of nothing else, and `ed25519-dalek` was
/// already built with `zeroize` by way of `russh`. Behind a box every one of
/// those moves copies a pointer, the single live copy never changes address,
/// and the drop that wipes it wipes the only copy there ever was.
///
/// The passphrase reaches the fixture on its standard input precisely so that
/// `environ` and `cmdline` can be read back and found clean.
#[test]
fn a_finished_key_file_session_emits_no_trace_of_the_key_or_its_passphrase() {
    let seed = key_seed_needle();
    let passphrase = key_passphrase();
    let directory = scratch().join("key-canary");
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).expect("the canary directory must be creatable");

    let control = directory.join("control");
    let mut planted = seed.clone();
    planted.extend_from_slice(&passphrase);
    fs::write(&control, &planted).expect("the control must be writable");
    for needle in [&seed, &passphrase] {
        assert!(
            file_contains(&control, needle).expect("scan the control"),
            "the search must be able to find a canary when it is really there"
        );
    }

    let ready = directory.join("ready");
    let mut fixture = Command::new(fixture_path())
        .arg(fixture_names::MODE_LINGER)
        .env(fixture_names::TARGET, required(TARGET))
        .env(fixture_names::PORT, required(PORT))
        .env(fixture_names::USERNAME, required(USERNAME))
        .env(fixture_names::HOST_KEY, required(HOST_KEY))
        .env(fixture_names::AUTHORIZED, required(AUTHORIZED))
        .env(fixture_names::KEY_PATH, key_file(NOMINAL_ED25519))
        .env(fixture_names::READY_PATH, &ready)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the fixture must start");
    {
        let mut input = fixture
            .stdin
            .take()
            .expect("the fixture reads its passphrase");
        input
            .write_all(&passphrase)
            .expect("the passphrase must reach the fixture");
    }

    let deadline = Instant::now() + SETTLE_TIMEOUT + DERIVATION_TIMEOUT;
    while !ready.exists() {
        if Instant::now() >= deadline {
            let _ = terminate_and_reap_bounded(&mut fixture, REAP_TIMEOUT);
            panic!("the fixture never completed a key file session");
        }
        thread::sleep(POLL_INTERVAL);
    }
    let pid = fixture.id();

    let dumped = Command::new("gcore")
        .arg("-o")
        .arg(directory.join("core"))
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    let core_path = fs::read_dir(&directory)
        .expect("read the canary directory")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("core"))
        });
    assert!(
        !dumped || core_path.is_some(),
        "the debugger reported a dump it did not produce"
    );

    let client_journal = directory.join("client-journal");
    capture(&client_journal, "journalctl -b --no-pager");
    let server_journal = directory.join("server-journal");
    capture(
        &server_journal,
        &format!("{} 'journalctl -b --no-pager'", required(SERVER_COMMAND)),
    );

    let mut emitted: Vec<PathBuf> = vec![
        PathBuf::from(format!("/proc/{pid}/environ")),
        PathBuf::from(format!("/proc/{pid}/cmdline")),
        client_journal,
        server_journal,
    ];
    for entry in fs::read_dir(&directory).expect("read the canary directory") {
        let path = entry.expect("directory entry").path();
        let is_core = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("core"));
        if path != control && path.is_file() && !is_core {
            emitted.push(path);
        }
    }
    for path in &emitted {
        for (needle, what) in [(&seed, "private key"), (&passphrase, "passphrase")] {
            assert!(
                !file_contains(path, needle).unwrap_or(false),
                "the {what} surfaced in {}",
                path.display()
            );
        }
    }

    // The core, for both canaries — and only once the search has been shown to
    // work on it. The account name is a string this process really holds in
    // ordinary memory, so finding it is what says the core was read at all: a
    // dump the search could not read would otherwise pass both claims below by
    // finding nothing in it.
    if let Some(core_path) = core_path {
        let ordinary = required(USERNAME).into_bytes();
        assert!(
            file_contains(&core_path, &ordinary).expect("scan the core"),
            "the core search found nothing this process certainly holds"
        );
        assert!(
            !file_contains(&core_path, &passphrase).unwrap_or(true),
            "the passphrase left the protected allocation and reached a dump"
        );
        assert!(
            !file_contains(&core_path, &seed).unwrap_or(true),
            "the private scalar outlived the session in a dump: a copy of the \
             key was moved somewhere its own drop no longer wipes"
        );
    }

    let output = {
        let _ = terminate_and_reap_bounded(&mut fixture, REAP_TIMEOUT);
        collect_output_bounded(fixture, REAP_TIMEOUT).expect("the fixture output must be bounded")
    };
    for stream in [&output.stdout, &output.stderr] {
        for needle in [&seed, &passphrase] {
            assert!(
                !canary_scan::contains_subslice(stream, needle),
                "a canary surfaced on a fixture stream"
            );
        }
    }
}

/// A helper authenticated by a key file, whose parent dies mid-session, leaves
/// nothing behind either.
///
/// It is the homologue of the agent case, on the same held account and read
/// from the same server-side journal. The passphrase arrives as the fixture's
/// standard input — redirected from the perimeter's own file, so it never
/// reaches any command line — and the derived key dies with the process.
#[test]
fn a_dead_parent_removes_a_key_authenticated_helper_and_its_probe() {
    let held = required(HELD_USERNAME);
    await_held_probes(0);
    let before = held_channel_closures();

    let pid_path = scratch().join("held-key-fixture.pid");
    let _ = fs::remove_file(&pid_path);
    let mut parent = Command::new("/bin/sh")
        .arg("-c")
        .arg(r#""$1" hold < "$3" & echo "$!" > "$2"; wait"#)
        .arg("sh")
        .arg(fixture_path())
        .arg(&pid_path)
        .arg(required(KEY_PASSPHRASE))
        .env(fixture_names::TARGET, required(TARGET))
        .env(fixture_names::PORT, required(PORT))
        .env(fixture_names::USERNAME, &held)
        .env(fixture_names::HOST_KEY, required(HOST_KEY))
        .env(fixture_names::AUTHORIZED, required(AUTHORIZED))
        .env(fixture_names::KEY_PATH, key_file(NOMINAL_ED25519))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the intermediate parent must start");

    let pid = read_pid_bounded(&pid_path);
    await_held_probes(1);
    assert!(process_alive(pid), "the fixture must still be running");

    terminate_and_reap_bounded(&mut parent, REAP_TIMEOUT).expect("the parent must be reaped");

    let deadline = Instant::now() + SETTLE_TIMEOUT;
    while process_alive(pid) {
        assert!(
            Instant::now() < deadline,
            "the helper outlived its parent at pid {pid}"
        );
        thread::sleep(POLL_INTERVAL);
    }
    assert_session_closed(before);
    let _ = fs::remove_file(&pid_path);
}
