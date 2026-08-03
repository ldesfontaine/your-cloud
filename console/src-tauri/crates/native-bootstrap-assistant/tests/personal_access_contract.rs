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

use std::{
    fs,
    io::{Read, Write},
    net::IpAddr,
    os::unix::net::UnixListener,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use russh::{
    keys::{agent::AgentIdentity, HashAlg, PublicKey},
    Signer,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use bounded_process::{
    collect_output_bounded, terminate_and_reap_bounded, wait_bounded, REAP_TIMEOUT,
};
use canary_scan::file_contains;
use your_cloud_native_bootstrap_assistant::personal_access::{
    agent_client::{
        AgentRefusal, BoundedAgentStream, PersonalAgent, SigningRefusal, StreamRefusal,
        MAX_AGENT_FRAME_BYTES,
    },
    algorithms::HostKeyType,
    host_key::HostKeyRefusal,
    session::{
        AuthenticationRequest, GuardVerdict, PersonalAccessRefusal, Prepared, TransportRefusal,
        MAX_PROBE_STREAM_BYTES,
    },
    signature_budget::{BudgetRefusal, MAX_AUTHENTICATION_SIGNATURES},
    target::TargetRefusal,
};
use your_cloud_native_bootstrap_assistant::personal_access_contract as fixture_names;

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
