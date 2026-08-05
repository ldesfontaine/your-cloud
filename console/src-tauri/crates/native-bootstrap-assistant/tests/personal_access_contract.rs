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
    elevation::{
        self, AccessRoute, Elevation, ElevationRefusal, FixedCommand, ELEVATE_WITHOUT_PASSWORD,
        ELEVATE_WITH_PASSWORD,
    },
    host_key::HostKeyRefusal,
    key_file::{self, KeyFileRefusal},
    key_unlock::{self, UnlockRefusal},
    openssh_key::{MAX_BCRYPT_ROUNDS, MAX_KEY_FILE_BYTES},
    session::{
        AuthenticationRequest, GuardVerdict, LiveSession, PersonalAccessRefusal, Prepared,
        RunObservation, TransportRefusal, MAX_EXEC_CHANNELS, MAX_PROBE_STREAM_BYTES,
    },
    signature_budget::{BudgetRefusal, MAX_AUTHENTICATION_SIGNATURES},
    sudo_policy::SudoRefusal,
    target::TargetRefusal,
};
use your_cloud_native_bootstrap_assistant::personal_access_contract as fixture_names;
use your_cloud_native_bootstrap_assistant::{
    EXIT_CANCELLED, EXIT_INVALID_INVOCATION, EXIT_PROTOCOL_REFUSED, EXIT_WATCHDOG_EXPIRED,
    REQUIRED_MODE_ARGUMENT,
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

/// Account whose policy is listable without a secret and whose elevation costs
/// exactly one password. It is the only shape in which a password ever travels.
const SUDO_PASSWORD_USERNAME: &str = "YOUR_CLOUD_LAB_SUDO_PASSWORD_USERNAME";
/// Account whose policy waives authentication entirely.
const SUDO_NOPASSWD_USERNAME: &str = "YOUR_CLOUD_LAB_SUDO_NOPASSWD_USERNAME";
/// Account whose policy cannot be listed without first authenticating.
const SUDO_UNLISTABLE_USERNAME: &str = "YOUR_CLOUD_LAB_SUDO_UNLISTABLE_USERNAME";
/// Account whose policy would write the standard input into the I/O log.
const SUDO_LOG_INPUT_USERNAME: &str = "YOUR_CLOUD_LAB_SUDO_LOG_INPUT_USERNAME";
/// Account whose policy demands a terminal this session never allocates.
const SUDO_REQUIRETTY_USERNAME: &str = "YOUR_CLOUD_LAB_SUDO_REQUIRETTY_USERNAME";
/// Account whose policy authorises another command entirely.
const SUDO_DIVERGENT_USERNAME: &str = "YOUR_CLOUD_LAB_SUDO_DIVERGENT_USERNAME";
/// Account whose policy carries two entries.
const SUDO_AMBIGUOUS_USERNAME: &str = "YOUR_CLOUD_LAB_SUDO_AMBIGUOUS_USERNAME";
/// Account whose listing is far past the bound it is read under.
const SUDO_OVERSIZED_USERNAME: &str = "YOUR_CLOUD_LAB_SUDO_OVERSIZED_USERNAME";
/// Numeric uid of the password account, so "not root" is asserted against the
/// account the perimeter really created rather than against a guess.
const SUDO_UID: &str = "YOUR_CLOUD_LAB_SUDO_UID";
/// File holding the synthetic `sudo` password. It is a path, never a value:
/// nothing this suite starts carries the password in its environment.
const SUDO_PASSWORD: &str = "YOUR_CLOUD_LAB_SUDO_PASSWORD";
/// The account the root route authenticates as.
const ROOT_USERNAME: &str = "YOUR_CLOUD_LAB_ROOT_USERNAME";

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

// ------------------------------------------- destroying each state of the fallback
//
// The cases above end a *session*. The ones below end the fallback while it is
// still building one, at the two moments where this process is holding
// something and doing nothing else: the passphrase awaited on a file already
// opened and validated, and the derivation itself.
//
// Each of them is written the same way, because the claim is the same and it is
// easy to prove by accident. "Killing it destroys the state" says nothing at
// all unless the state existed, so every case first observes it — the
// descriptor really open on the file the user chose, the derivation thread
// really running — and fails if it does not. Only then is the exit applied, and
// only then is what is left behind searched.
//
// The fixture used is the helper's own hardened process, stopped inside the
// fallback rather than around a whole session: at both of these moments the
// product has no transport open either, so a fixture that opened one would be
// holding more than the state under test.

/// A key file whose derivation lasts seconds rather than milliseconds, and
/// still finishes well inside the step ceiling when nothing interrupts it.
const COSTLY: &str = "costly";

/// Longest a fixture may take to reach the state it was asked to stop in.
const STATE_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest a killed process may take to leave `/proc`.
const DISAPPEARANCE_TIMEOUT: Duration = Duration::from_secs(5);

/// Names of every thread `pid` is running, as `/proc` answers them.
///
/// A process that has already gone answers none, which is exactly what the
/// cases below read after the exit.
fn thread_names(pid: u32) -> Vec<String> {
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/task")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| fs::read_to_string(entry.path().join("comm")).ok())
        .map(|name| name.trim().to_owned())
        .collect()
}

/// Whether the derivation thread of this process is running right now.
///
/// The name compared is the one the product gives that thread, truncated to
/// what Linux really stores: comparing the whole name would never match, and a
/// case built on it would conclude that no derivation had started.
fn derivation_running(pid: u32) -> bool {
    let expected = &fixture_names::DERIVATION_THREAD[..fixture_names::DERIVATION_THREAD_COMM_BYTES];
    thread_names(pid).iter().any(|name| name == expected)
}

/// Every regular file `pid` holds a descriptor on.
fn open_files(pid: u32) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| fs::read_link(entry.path()).ok())
        .collect()
}

/// Every process that declares `pid` as its parent.
///
/// Read *before* an exit, this answers the question that matters: does the
/// fallback create a process of its own at this state? Read afterwards it is
/// far weaker, because a child that outlived its parent has been reparented
/// and no longer names it — which is exactly why every case below asserts the
/// emptiness before the exit as well as after, and why the descendant these
/// states really do create is a thread, observed by name.
fn children_of(pid: u32) -> Vec<u32> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut children = Vec::new();
    for entry in entries.flatten() {
        let Some(candidate) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(status) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // The executable name sits in parentheses and may hold anything,
        // spaces and parentheses included, so the fields are read from the
        // last closing one: state, then the parent.
        let Some((_, tail)) = status.rsplit_once(')') else {
            continue;
        };
        if tail.split_whitespace().nth(1) == Some(&pid.to_string()) {
            children.push(candidate);
        }
    }
    children
}

/// Waits until `pid` has left `/proc` entirely, and says how long it took.
fn await_disappearance(pid: u32) {
    let deadline = Instant::now() + DISAPPEARANCE_TIMEOUT;
    while process_alive(pid) {
        assert!(
            Instant::now() < deadline,
            "the process at pid {pid} was still there {DISAPPEARANCE_TIMEOUT:?} after its exit"
        );
        thread::sleep(POLL_INTERVAL);
    }
}

/// Ends `pid` the way nothing can be handled: no signal handler runs, no
/// destructor runs, and nothing this process owns is wiped by its own code.
fn crash(pid: u32) {
    // SAFETY: `kill` reads no memory of this process. The pid was observed
    // alive one line above by the case that calls this.
    assert_eq!(
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) },
        0,
        "the crash could not be delivered to {pid}"
    );
}

/// An empty directory of this run's scratch, ready to be searched afterwards.
fn state_directory(name: &str) -> PathBuf {
    let directory = scratch().join(name);
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).expect("the state directory must be creatable");
    directory
}

/// Starts the fixture inside one clean state of the fallback.
///
/// Standard input stays a pipe this process owns in both modes: it is what the
/// passphrase travels through, and it is also the end of file one of the cases
/// below applies. Nothing travels on the command line or in the environment
/// except the path of the file, which is not a secret.
fn start_in_state(mode: &str, key: &str, ready: &Path) -> Child {
    let _ = fs::remove_file(ready);
    Command::new(fixture_path())
        .arg(mode)
        .env(fixture_names::KEY_PATH, key_file(key))
        .env(fixture_names::READY_PATH, ready)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the fixture must start")
}

/// Waits until the fixture announces the state it was asked to stop in, and
/// refuses to let a case continue against a process that never got there.
fn await_state(child: &mut Child, ready: &Path) {
    let deadline = Instant::now() + STATE_TIMEOUT;
    while !ready.exists() {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("the fixture stopped with {status} before reaching its state");
        }
        if Instant::now() >= deadline {
            let cleanup = terminate_and_reap_bounded(child, REAP_TIMEOUT);
            panic!("the fixture never reached its state; cleanup: {cleanup:?}");
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Hands the fixture its passphrase and closes the pipe behind it.
fn feed_passphrase(child: &mut Child, passphrase: &[u8]) {
    let mut input = child
        .stdin
        .take()
        .expect("the fixture reads its passphrase");
    input
        .write_all(passphrase)
        .expect("the passphrase must reach the fixture");
    drop(input);
}

/// The end of file at the state where the passphrase is awaited.
///
/// This is the moment the product is in while its passphrase window is up: the
/// file the user chose is open, validated and held, and not one byte of a
/// passphrase exists in the process. The exit applied is the parent letting go
/// — an end of file on the very descriptor the passphrase would have arrived
/// through — and it must leave nothing behind: no key derived, no descriptor
/// held, no process.
///
/// The control is what makes the claim mean anything: the open descriptor is
/// read back from `/proc` *before* the end of file, and it is required to name
/// the file that was chosen. A case that closed a pipe on a process holding
/// nothing would pass for the wrong reason.
#[test]
fn an_end_of_file_while_the_passphrase_is_awaited_returns_the_file_and_derives_nothing() {
    let before = key_directory_digest();
    let directory = state_directory("selected-eof");
    let ready = directory.join("ready");
    let mut fixture = start_in_state(fixture_names::MODE_SELECTED, NOMINAL_ED25519, &ready);
    await_state(&mut fixture, &ready);
    let pid = fixture.id();

    // The state really exists, and it is the state claimed.
    assert!(
        open_files(pid).contains(&key_file(NOMINAL_ED25519)),
        "the fixture announced a selected file it does not hold open"
    );
    assert!(
        !derivation_running(pid),
        "a derivation is running at a state where no passphrase has been typed"
    );
    assert!(
        children_of(pid).is_empty(),
        "the fallback started a process of its own before any passphrase existed"
    );

    drop(fixture.stdin.take().expect("the fixture reads its input"));

    let output = collect_output_bounded(fixture, STATE_TIMEOUT)
        .expect("the fixture must stop under a bound");
    assert_eq!(
        output.status.code(),
        Some(i32::from(EXIT_INVALID_INVOCATION)),
        "an end of file before a passphrase derives nothing and keeps nothing"
    );
    assert!(output.stdout.is_empty() && output.stderr.is_empty());

    await_disappearance(pid);
    assert!(
        open_files(pid).is_empty(),
        "a descriptor of the personal file outlived the process holding it"
    );
    assert!(children_of(pid).is_empty());
    assert_eq!(
        key_directory_digest(),
        before,
        "the personal file must stay bit for bit unchanged"
    );
}

/// The crash at that same state.
///
/// Nothing of the user's is in this process yet beyond the bytes of a file they
/// already hold on disk, which is why the claim here is about the descriptor
/// and the process rather than about a secret: the passphrase has not been
/// typed, and there is no derived key to lose. What must be true is that the
/// file is let go of and that nothing survives to hold it.
#[test]
fn a_crash_while_the_passphrase_is_awaited_takes_the_open_file_with_it() {
    use std::os::unix::process::ExitStatusExt as _;

    let before = key_directory_digest();
    let directory = state_directory("selected-crash");
    let ready = directory.join("ready");
    let mut fixture = start_in_state(fixture_names::MODE_SELECTED, NOMINAL_ED25519, &ready);
    await_state(&mut fixture, &ready);
    let pid = fixture.id();

    assert!(
        open_files(pid).contains(&key_file(NOMINAL_ED25519)),
        "the fixture announced a selected file it does not hold open"
    );
    assert!(children_of(pid).is_empty());

    crash(pid);

    let status = wait_bounded(&mut fixture, STATE_TIMEOUT).expect("the crashed fixture is reaped");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the case must have ended this process the one way nothing can handle"
    );
    await_disappearance(pid);
    assert!(
        open_files(pid).is_empty(),
        "a descriptor of the personal file outlived the crash"
    );
    assert!(
        thread_names(pid).is_empty(),
        "a thread of the crashed process is still running"
    );
    assert!(children_of(pid).is_empty());
    assert_eq!(key_directory_digest(), before);
}

/// Everywhere a process of this machine could have left a copy of what it held.
///
/// It is deliberately more than the fixture's own outputs: a crash writes
/// nothing on purpose, so the interesting places are the ones the *system*
/// writes to when a process dies — the collected cores and both journals — and
/// the one place the kernel itself could have put a page, which is the swap.
fn places_a_crash_could_leave_something(directory: &Path) -> Vec<PathBuf> {
    let client_journal = directory.join("client-journal");
    capture(&client_journal, "journalctl -b --no-pager");
    let server_journal = directory.join("server-journal");
    capture(
        &server_journal,
        &format!("{} 'journalctl -b --no-pager'", required(SERVER_COMMAND)),
    );

    let mut places = vec![client_journal, server_journal];
    for collected in ["/var/lib/systemd/coredump", "/var/crash"] {
        let Ok(entries) = fs::read_dir(collected) else {
            continue;
        };
        places.extend(
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.is_file()),
        );
    }
    places
}

/// The swap of this machine, and how much of it is in use, in bytes.
fn swap_in_use() -> Vec<(PathBuf, u64)> {
    capture_local("swapon --show=NAME,USED --bytes --noheadings")
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            let used = fields.next()?.parse::<u64>().ok()?;
            Some((PathBuf::from(name), used))
        })
        .collect()
}

/// Searches the swap for a needle, and proves the search really read it.
///
/// The control is the swap area's own signature, which Linux writes at the end
/// of the first page: a scan that cannot find `SWAPSPACE2` in a swap area did
/// not read the swap area, and its answer about the needle means nothing.
fn swap_holds(path: &Path, needle: &[u8]) -> bool {
    assert!(
        file_contains(path, b"SWAPSPACE2").expect("the swap must be readable"),
        "the swap scan of {} never found the signature of a swap area: it read \
         something else, and what it says about a secret is worthless",
        path.display()
    );
    file_contains(path, needle).expect("the swap must be readable")
}

/// Largest live mapping the memory search below will read in one piece. The
/// protected allocation is one page; anything far larger is a heap or a mapped
/// file and reading it whole would put a great deal of this process's memory
/// into the searcher's own.
const MAX_LIVE_REGION_BYTES: usize = 16 * 1024 * 1024;

/// Searches the *live* memory of `pid` for a needle, through `/proc`.
///
/// This is the counterpart of the dump, and the control that makes the dump
/// mean something. `MADV_DONTDUMP` removes a region from what a dump collects
/// and from nothing else: a privileged reader who goes to the memory itself
/// still finds whatever is there. Finding the passphrase this way, at the very
/// instant a dump of the same process does not hold it, is what turns "the
/// dump did not hold the passphrase" into a statement about the dump rather
/// than about the passphrase.
fn live_memory_holds(pid: u32, needle: &[u8]) -> bool {
    use std::os::unix::fs::FileExt as _;

    let Ok(maps) = fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return false;
    };
    let Ok(memory) = File::open(format!("/proc/{pid}/mem")) else {
        return false;
    };
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (Some(range), Some(permissions)) = (fields.next(), fields.next()) else {
            continue;
        };
        if !permissions.starts_with("rw") {
            continue;
        }
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            continue;
        };
        let length = end.saturating_sub(start) as usize;
        if length == 0 || length > MAX_LIVE_REGION_BYTES {
            continue;
        }
        let mut region = vec![0_u8; length];
        // A region the kernel refuses to read is skipped rather than fatal:
        // this walk is an observation of what is reachable, not of what exists.
        if memory.read_exact_at(&mut region, start).is_err() {
            continue;
        }
        if canary_scan::contains_subslice(&region, needle) {
            return true;
        }
    }
    false
}

/// Starts the fixture inside its derivation and answers once it is really
/// paying for the rounds.
///
/// The thread is the control. A file is opened, a passphrase is handed over and
/// a marker is written before the derivation is entered, but none of that says
/// a single round was ever computed; the thread the product spawns to compute
/// them does, and it exists only while they are being computed.
fn start_deriving(key: &str, ready: &Path) -> (Child, u32) {
    let mut fixture = start_in_state(fixture_names::MODE_DERIVING, key, ready);
    feed_passphrase(&mut fixture, &key_passphrase());
    await_state(&mut fixture, ready);
    let pid = fixture.id();

    let deadline = Instant::now() + STATE_TIMEOUT;
    while !derivation_running(pid) {
        if let Ok(Some(status)) = fixture.try_wait() {
            panic!("the fixture stopped with {status} instead of deriving");
        }
        if Instant::now() >= deadline {
            let cleanup = terminate_and_reap_bounded(&mut fixture, REAP_TIMEOUT);
            panic!(
                "no thread named {} ever appeared: nothing was deriving; cleanup: {cleanup:?}",
                fixture_names::DERIVATION_THREAD
            );
        }
        thread::sleep(POLL_INTERVAL);
    }
    (fixture, pid)
}

/// What a privileged debugger gets out of a derivation while it is running.
///
/// This is the measurement the whole crash case rests on, and it is taken while
/// the secret is not merely present but *in use*: the passphrase is in the
/// protected allocation, the file's bytes are in an ordinary buffer beside it,
/// and a thread is reading both. A core is taken by `gcore`, as root, of a
/// process that made itself non-dumpable — which is the strongest position an
/// attacker of this machine could be in short of reading its memory live.
///
/// Two claims, and the first is what makes the second worth anything. The
/// bytes of the *file* must be found, because they are held in ordinary memory
/// and finding them says the dump and the search really reached this process's
/// heap. The *passphrase* must not be, because it lives only in the mapping
/// that `mlock` pins and `MADV_DONTDUMP` excludes.
///
/// The file used is the one whose declared round count sits on the accepted
/// bound: under the unoptimised build this suite uses, its derivation outlasts
/// the step ceiling, so the state stays open for as long as the observation
/// needs rather than for as long as it happens to last.
#[test]
fn a_dump_of_a_live_derivation_holds_the_file_it_reads_and_never_the_passphrase() {
    let directory = state_directory("deriving-dump");
    let ready = directory.join("ready");
    let passphrase = key_passphrase();
    let ciphertext = fs::read(key_file(BOUND_ROUNDS)).expect("the key file must be readable");
    assert!(
        ciphertext.len() > 192,
        "the sample of the file's bytes must be a real part of it"
    );
    let held_bytes = ciphertext[64..192].to_vec();

    // The control of the search itself, before anything is dumped: both needles
    // planted in one file, and both found there.
    let control = directory.join("control");
    let mut planted = held_bytes.clone();
    planted.extend_from_slice(&passphrase);
    fs::write(&control, &planted).expect("the control must be writable");
    for needle in [&held_bytes, &passphrase] {
        assert!(
            file_contains(&control, needle).expect("scan the control"),
            "the search must be able to find a canary when it is really there"
        );
    }

    let (mut fixture, pid) = start_deriving(BOUND_ROUNDS, &ready);
    assert!(
        open_files(pid).contains(&key_file(BOUND_ROUNDS)),
        "the deriving fixture no longer holds the file it is deriving"
    );

    // The control the whole case turns on, taken before the dump: the
    // passphrase really is in this process's memory at this instant, and a
    // privileged reader who goes to the memory rather than to a dump of it
    // finds it there. Whatever the dump says below is therefore about the dump.
    let live = live_memory_holds(pid, &passphrase);

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
        .expect("read the state directory")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("core"))
        });
    let cleanup = terminate_and_reap_bounded(&mut fixture, REAP_TIMEOUT);

    assert!(dumped, "the derivation could not be dumped at all");
    let core_path = core_path.expect("the debugger reported a dump it did not produce");
    let holds_file = file_contains(&core_path, &held_bytes).expect("scan the core");
    let holds_passphrase = file_contains(&core_path, &passphrase).expect("scan the core");
    // The dump is the largest thing this run writes; it is removed before
    // anything is asserted so that a failing case cannot leave it behind.
    fs::remove_file(&core_path).expect("the dump must be removable");

    assert!(cleanup.is_ok(), "the dumped fixture must be reaped");
    assert!(
        live,
        "the passphrase was not in this process's memory at all while it was \
         deriving with it: the dump's silence about it says nothing"
    );
    assert!(
        holds_file,
        "the dump held none of the bytes the derivation is reading: it captured \
         nothing of this process, and its silence about the passphrase means nothing"
    );
    assert!(
        !holds_passphrase,
        "the passphrase of a live derivation reached a privileged dump: the \
         locked, non-dumpable allocation did not cover the one moment it is used"
    );
}

/// What the locked, non-dumpable allocation does *not* cover, said out loud.
///
/// The case above is only honest if this one is written beside it. Excluding a
/// region from a dump is exactly that and no more: a reader privileged enough
/// to dump the process is privileged enough to read its memory directly, and
/// there the passphrase is, for as long as the derivation needs it. The bound
/// on that exposure is the state's own lifetime and nothing else.
///
/// It is asserted rather than left as a remark because it is the residual risk
/// this fallback carries, and a residual risk that stops being true without
/// anyone noticing is a residual risk nobody is managing any more.
#[test]
fn the_protected_allocation_hides_the_passphrase_from_a_dump_and_from_nothing_else() {
    let directory = state_directory("deriving-live");
    let ready = directory.join("ready");
    let passphrase = key_passphrase();

    let (mut fixture, pid) = start_deriving(BOUND_ROUNDS, &ready);
    let reachable = live_memory_holds(pid, &passphrase);
    // The control that says the walk answers no by looking rather than by
    // failing: the same walk, on the same live process, for something no
    // process holds. Both are taken before anything is killed, because a walk
    // of a process that has gone answers no to everything.
    let absent = live_memory_holds(pid, b"ycpa-needle-that-belongs-to-nobody");
    let cleanup = terminate_and_reap_bounded(&mut fixture, REAP_TIMEOUT);

    assert!(cleanup.is_ok());
    assert!(!absent, "the memory walk answers yes to anything at all");
    assert!(
        reachable,
        "the passphrase could not be read out of a live derivation at all. That \
         is a stronger property than this project claims, and the claim above — \
         that the dump is what is empty — would no longer be measuring anything"
    );
}

/// A crash *during* the derivation, and everything it must take with it.
///
/// This is the sharpest of the exits and the only one on which the product's
/// own erasure does nothing at all: `SIGKILL` runs no destructor, so the
/// passphrase in the protected allocation and the bytes of the file beside it
/// are not wiped by any code of this project. What is claimed here is therefore
/// deliberately narrow and is exactly what was measured: the thread stops, the
/// descriptor is returned, no process survives, and nothing of the secret is
/// findable anywhere this machine writes.
///
/// Three controls, because three different things could make this case pass for
/// the wrong reason. The derivation must have been *running* when it was killed
/// — the thread is read from `/proc` on the line before the kill, and the same
/// file left alone is timed deriving for longer than the state lasted here.
/// The search must be able to find these needles — a control file holding both
/// is scanned first. And the swap must really have been read — the scan is
/// required to find the swap area's own signature before its answer counts.
#[test]
fn a_crash_during_the_derivation_destroys_the_thread_the_file_and_leaves_no_secret() {
    use std::os::unix::process::ExitStatusExt as _;

    let before = key_directory_digest();
    let directory = state_directory("deriving-crash");
    let ready = directory.join("ready");
    let passphrase = key_passphrase();
    let ciphertext = fs::read(key_file(COSTLY)).expect("the key file must be readable");
    assert!(ciphertext.len() > 192);
    let held_bytes = ciphertext[64..192].to_vec();

    let control = directory.join("control");
    let mut planted = held_bytes.clone();
    planted.extend_from_slice(&passphrase);
    fs::write(&control, &planted).expect("the control must be writable");
    for needle in [&held_bytes, &passphrase] {
        assert!(
            file_contains(&control, needle).expect("scan the control"),
            "the search must be able to find a canary when it is really there"
        );
    }

    let (mut fixture, pid) = start_deriving(COSTLY, &ready);
    let entered = Instant::now();
    assert!(
        open_files(pid).contains(&key_file(COSTLY)),
        "the deriving fixture no longer holds the file it is deriving"
    );
    assert!(
        children_of(pid).is_empty(),
        "the derivation started a process rather than a thread"
    );
    // Read once more on the line before the crash: what follows is about a
    // derivation that was running at the instant it was ended.
    assert!(derivation_running(pid), "the derivation ended on its own");
    crash(pid);
    let killed_at = entered.elapsed();

    let status = wait_bounded(&mut fixture, STATE_TIMEOUT).expect("the crashed fixture is reaped");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the case must have ended this process the one way nothing can handle"
    );
    await_disappearance(pid);
    assert!(
        thread_names(pid).is_empty(),
        "the derivation thread outlived the process it was running in"
    );
    assert!(
        open_files(pid).is_empty(),
        "a descriptor of the personal file outlived the crash"
    );
    assert!(children_of(pid).is_empty());

    // Nothing of the secret, anywhere this machine writes. The state directory
    // is swept whole rather than by name: it is where every artefact of this
    // case lives, and the control planted in it is the proof the sweep works.
    let mut places = places_a_crash_could_leave_something(&directory);
    for entry in fs::read_dir(&directory).expect("read the state directory") {
        let path = entry.expect("directory entry").path();
        if path != control && path.is_file() {
            places.push(path);
        }
    }
    for place in &places {
        for (needle, what) in [(&passphrase, "passphrase"), (&held_bytes, "key file")] {
            assert!(
                !file_contains(place, needle).unwrap_or(false),
                "the {what} of a crashed derivation surfaced in {}",
                place.display()
            );
        }
    }
    assert!(
        file_contains(&control, &passphrase).expect("scan the control"),
        "the sweep that found nothing cannot find a canary that is really there"
    );

    // And the one place the kernel, rather than this process, could have put a
    // page of it. `mlock` is what forbids it; the scan is what checks.
    let swap = swap_in_use();
    assert!(
        !swap.is_empty(),
        "this machine has no swap to search at all"
    );
    for (area, used) in &swap {
        assert!(
            !swap_holds(area, &passphrase),
            "the passphrase of a crashed derivation was written to {} ({used} bytes in use)",
            area.display()
        );
    }

    // The control that says what was cut was really running: the same file, the
    // same passphrase, left alone, derives — and takes longer doing it than the
    // state above lasted.
    let control_ready = directory.join("control-ready");
    let mut control_fixture = start_in_state(fixture_names::MODE_DERIVING, COSTLY, &control_ready);
    feed_passphrase(&mut control_fixture, &passphrase);
    let started = Instant::now();
    let control_output = collect_output_bounded(control_fixture, STATE_TIMEOUT)
        .expect("the control derivation must stop under a bound");
    let derived_after = started.elapsed();
    assert_eq!(
        control_output.status.code(),
        Some(0),
        "the same file must derive when nothing interrupts it"
    );
    assert!(
        derived_after > killed_at,
        "the derivation finished in {derived_after:?} and the crash landed at \
         {killed_at:?}: nothing that was still running was cut"
    );
    assert_eq!(key_directory_digest(), before);
}

// -------------------------------------- the two states that are a window
//
// The states above are held by a process and observed in `/proc`. These two are
// held by a *window*, and there is no other way to reach them: the path only
// exists because a user opened a native selector and typed into a native
// passphrase field, and every exit that ends them — the parent letting go of
// the lease, the window being closed — is an event of that window.
//
// Each case therefore drives the shipped helper the way a user drives it, and
// the driving is itself the control: the case does not continue until the X
// server says the window of the state it is aiming at is really up and really
// owned by the helper under test.

/// Title GTK gives the native selector of the encrypted key file.
const KEY_SELECTOR_TITLE: &str = "Your Cloud — choisir la clé OpenSSH chiffrée";
/// Title of the passphrase window the fallback opens once a file is chosen.
const KEY_PASSPHRASE_TITLE: &str = "Your Cloud — passphrase de la clé SSH";
/// Accelerator of the key file row of the personal access window.
const OPEN_SELECTOR: &str = "alt+o";
/// Accelerator of that window's acceptance.
const ACCEPT_ACCESS: &str = "alt+a";
/// Longest a driven window may take to appear or to go away.
const DRIVEN_WINDOW_TIMEOUT: Duration = Duration::from_secs(20);
/// How long the selector is given to answer an activated location entry on its
/// own before its own accelerator is used instead.
const SELECTOR_ANSWER_TIMEOUT: Duration = Duration::from_secs(2);
/// How many times naming a file in the selector is attempted before the case
/// gives up and says the state was never reached.
const SELECTOR_ATTEMPTS: usize = 4;

/// The identifier of one visible window `process_id` owns titled exactly
/// `title`, when there is one.
///
/// Both the ownership and the title are read back from the X server rather than
/// assumed from the search: several windows of this helper are up at once in
/// these cases, and naming the wrong one would drive the wrong state.
fn window_titled(process_id: &str, title: &str) -> Option<String> {
    let listing = xdotool(&["search", "--onlyvisible", "--pid", process_id, "."])?;
    listing
        .lines()
        .map(str::trim)
        .find(|window_id| {
            window_id.parse::<u64>().is_ok()
                && xdotool(&["getwindowpid", window_id])
                    .as_deref()
                    .map(str::trim)
                    == Some(process_id)
                && xdotool(&["getwindowname", window_id])
                    .as_deref()
                    .map(str::trim)
                    == Some(title)
        })
        .map(str::to_owned)
}

/// Waits for one window of `child` titled `title`, and refuses to let a case
/// continue against a state that was never reached.
///
/// A window that has just been mapped is not yet a window that takes a key: it
/// is visible, and its toolkit is still building what the keystroke would reach.
/// One poll interval is left for that, because a keystroke sent too early is
/// not refused, it is simply lost — and a lost keystroke would show up much
/// later as a state that was never driven rather than as a race here.
fn await_window_titled(child: &mut Child, title: &str) -> String {
    let process_id = child.id().to_string();
    let deadline = Instant::now() + DRIVEN_WINDOW_TIMEOUT;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("the helper exited with {status} before opening «{title}»");
        }
        if let Some(window) = window_titled(&process_id, title) {
            thread::sleep(POLL_INTERVAL);
            return window;
        }
        if Instant::now() >= deadline {
            abandon(child, &format!("no window titled «{title}» ever appeared"));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Answers whether one window of `child` titled `title` has gone within
/// `timeout`, with the helper still running: what is being observed is one
/// window closing, not a process dying and taking every window with it.
fn window_closed_within(child: &mut Child, title: &str, timeout: Duration) -> bool {
    let process_id = child.id().to_string();
    let deadline = Instant::now() + timeout;
    while window_titled(&process_id, title).is_some() {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("the helper exited with {status} instead of closing «{title}»");
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(POLL_INTERVAL);
    }
    true
}

/// The same, but a window that stays open is the case failing.
fn await_window_gone(child: &mut Child, title: &str) {
    if !window_closed_within(child, title, DRIVEN_WINDOW_TIMEOUT) {
        abandon(child, &format!("the window «{title}» never closed"));
    }
}

/// Presses one accelerator on one window of the helper.
///
/// The focus is set first and synchronously: without a window manager nothing
/// else assigns it, and a key sent to an unfocused display reaches no widget at
/// all. The event itself goes through the test extension rather than as a
/// synthetic message, so what the toolkit receives is what a keyboard produces.
fn press(window: &str, key: &str) {
    assert!(
        xdotool(&["windowfocus", "--sync", window]).is_some(),
        "the window {window} could not be given the input focus"
    );
    assert!(
        xdotool(&["key", "--clearmodifiers", key]).is_some(),
        "the key {key} could not be sent to {window}"
    );
}

/// Types one absolute path into the selector's location bar and opens it.
///
/// The steps are the ones a user takes, and each is needed. Activating the
/// location entry names the file; whether that alone answers the selector
/// depends on the toolkit build, so the selector's own accelerator is used when
/// the dialog is still up afterwards.
///
/// The whole sequence is attempted several times under one bound rather than
/// once, because a keystroke that reaches a dialog which is not yet listening
/// is lost rather than refused. Every attempt begins by replacing the entry's
/// whole contents, so an attempt that half worked cannot leave a path glued to
/// the one the next attempt types, and an attempt that did nothing leaves the
/// selector exactly as it found it — open, with nothing chosen. Nothing here
/// can make a *wrong* file be chosen quietly either: every case that drives
/// this reads the descriptor back from `/proc` and requires it to name the file
/// that was typed.
fn choose_file(child: &mut Child, selector: &str, path: &Path) {
    for _ in 0..SELECTOR_ATTEMPTS {
        press(selector, "ctrl+l");
        press(selector, "ctrl+a");
        assert!(
            xdotool(&[
                "type",
                "--clearmodifiers",
                "--delay",
                "20",
                &path.to_string_lossy(),
            ])
            .is_some(),
            "the path could not be typed into the selector"
        );
        press(selector, "Return");
        if window_closed_within(child, KEY_SELECTOR_TITLE, SELECTOR_ANSWER_TIMEOUT) {
            return;
        }
        press(selector, "alt+o");
        if window_closed_within(child, KEY_SELECTOR_TITLE, SELECTOR_ANSWER_TIMEOUT) {
            return;
        }
    }
    abandon(
        child,
        &format!("the selector never answered the path {}", path.display()),
    );
}

/// Starts one helper on the personal access step, with its scope delivered.
fn start_driven_helper() -> (Child, UnixStream) {
    let (mut child, mut parent_lease) = spawn_authenticated(helper_command());
    if parent_lease
        .write_all(&scope_frame(&direct_personal_access_scope(
            LIVE_WINDOW_LEASE_MILLIS,
        )))
        .and_then(|()| parent_lease.flush())
        .is_err()
    {
        abandon(&mut child, "the scope never reached the helper");
    }
    (child, parent_lease)
}

/// The parent letting go while the file selector is open.
///
/// The state is the first clean one of the fallback: a native selector is up,
/// nothing has been opened, and no passphrase exists anywhere. The exit is the
/// cancellation lease of the protocol, which on this transport *is* the end of
/// file — the parent closes the pipe and says nothing.
///
/// What must happen is that both loops end, not one: the selector runs a modal
/// loop of its own that the window underneath cannot interrupt, so a released
/// lease that only reached the outer window would leave a native dialog on
/// screen with no process to answer it.
#[test]
#[ignore = "requires the isolated Xvfb the LAB run provides"]
fn a_released_lease_closes_the_open_file_selector_and_the_window_under_it() {
    assert!(
        std::env::var_os("DISPLAY").is_some(),
        "this case needs the isolated display the LAB run provides"
    );

    let (mut child, parent_lease) = start_driven_helper();
    let window = await_window_titled(&mut child, PERSONAL_ACCESS_TITLE);
    press(&window, OPEN_SELECTOR);
    // The control: the selector is really up, and it belongs to this helper.
    let _selector = await_window_titled(&mut child, KEY_SELECTOR_TITLE);
    let pid = child.id();
    assert!(
        !open_files(pid).contains(&key_file(NOMINAL_ED25519)),
        "a file was opened while the user was still choosing one"
    );

    drop(parent_lease);

    let output = collect_output_bounded(child, PROCESS_TIMEOUT)
        .expect("the cancelled helper must stop under a bound");
    assert_eq!(
        output.status.code(),
        Some(i32::from(EXIT_CANCELLED)),
        "a lease released under an open selector is a cancellation; status {:?}, \
         stdout {:?}, stderr {:?}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        decode_event(&output.stdout),
        AssistantEventV1 {
            schema_version: 1,
            request_id: DIRECT_REQUEST_ID.into(),
            event: AssistantEventKind::Cancelled,
        }
    );
    assert!(output.stderr.is_empty());
    await_disappearance(pid);
    assert!(
        window_titled(&pid.to_string(), KEY_SELECTOR_TITLE).is_none(),
        "the native selector outlived the process that opened it"
    );
}

/// The user closing the selector itself.
///
/// This one is not a session ending, and saying so is the point: closing the
/// selector destroys the selector and nothing else. Nothing is chosen, nothing
/// is opened, and the window it was opened from is still there — which is what
/// makes the second half of the case possible, where closing *that* window is
/// what ends the session.
#[test]
#[ignore = "requires the isolated Xvfb the LAB run provides"]
fn a_closed_file_selector_chooses_nothing_and_leaves_the_window_it_came_from() {
    assert!(
        std::env::var_os("DISPLAY").is_some(),
        "this case needs the isolated display the LAB run provides"
    );

    let (mut child, parent_lease) = start_driven_helper();
    let window = await_window_titled(&mut child, PERSONAL_ACCESS_TITLE);
    press(&window, OPEN_SELECTOR);
    let selector = await_window_titled(&mut child, KEY_SELECTOR_TITLE);
    let pid = child.id();

    press(&selector, "Escape");
    await_window_gone(&mut child, KEY_SELECTOR_TITLE);
    assert!(
        matches!(child.try_wait(), Ok(None)),
        "closing the selector ended the whole session"
    );
    assert!(
        window_titled(&pid.to_string(), PERSONAL_ACCESS_TITLE).is_some(),
        "closing the selector took the window it was opened from with it"
    );
    assert!(
        !open_files(pid).contains(&key_file(NOMINAL_ED25519)),
        "a selector that was closed opened a file anyway"
    );

    // And now the window under it, which is a session ending.
    press(&window, "Escape");
    let output = collect_output_bounded(child, PROCESS_TIMEOUT)
        .expect("the closed helper must stop under a bound");
    drop(parent_lease);
    assert_eq!(
        output.status.code(),
        Some(i32::from(EXIT_CANCELLED)),
        "a personal access window the user closes is a cancellation"
    );
    assert_eq!(
        decode_event(&output.stdout),
        AssistantEventV1 {
            schema_version: 1,
            request_id: DIRECT_REQUEST_ID.into(),
            event: AssistantEventKind::Cancelled,
        }
    );
    await_disappearance(pid);
}

/// A crash while the selector is open.
///
/// Nothing has been opened at this state and nothing secret exists, so what
/// must be true is narrow and is exactly what is checked: the process goes, and
/// the native dialog it had put on the display goes with it rather than
/// outliving it on an X server that has no window manager to clean up after
/// anyone.
#[test]
#[ignore = "requires the isolated Xvfb the LAB run provides"]
fn a_crash_while_the_file_selector_is_open_leaves_no_window_and_no_open_file() {
    use std::os::unix::process::ExitStatusExt as _;

    assert!(
        std::env::var_os("DISPLAY").is_some(),
        "this case needs the isolated display the LAB run provides"
    );

    let (mut child, parent_lease) = start_driven_helper();
    let window = await_window_titled(&mut child, PERSONAL_ACCESS_TITLE);
    press(&window, OPEN_SELECTOR);
    let _selector = await_window_titled(&mut child, KEY_SELECTOR_TITLE);
    let pid = child.id();
    assert!(
        children_of(pid).is_empty(),
        "the selector was opened by a process of its own"
    );

    crash(pid);

    let status = wait_bounded(&mut child, PROCESS_TIMEOUT).expect("the crashed helper is reaped");
    drop(parent_lease);
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    await_disappearance(pid);
    let process_id = pid.to_string();
    for title in [PERSONAL_ACCESS_TITLE, KEY_SELECTOR_TITLE] {
        assert!(
            window_titled(&process_id, title).is_none(),
            "the window «{title}» outlived the process that opened it"
        );
    }
    assert!(open_files(pid).is_empty());
    assert!(children_of(pid).is_empty());
}

/// Drives one helper all the way to the passphrase window of the fallback.
///
/// The drive is the control. Reaching this window means a file was named in the
/// native selector, opened, and validated — the passphrase window is only ever
/// shown through an `Ok` of that opening — and the descriptor is read back from
/// `/proc` before any case is allowed to continue, so what follows is about a
/// state that is really held rather than about a window that merely looks like
/// it.
fn drive_to_passphrase_window(child: &mut Child, key: &str) -> String {
    let window = await_window_titled(child, PERSONAL_ACCESS_TITLE);
    press(&window, OPEN_SELECTOR);
    let selector = await_window_titled(child, KEY_SELECTOR_TITLE);
    choose_file(child, &selector, &key_file(key));
    press(&window, ACCEPT_ACCESS);
    let passphrase = await_window_titled(child, KEY_PASSPHRASE_TITLE);
    assert!(
        open_files(child.id()).contains(&key_file(key)),
        "the passphrase window is up on a file this process does not hold open"
    );
    assert!(
        !derivation_running(child.id()),
        "a derivation started before any passphrase was typed"
    );
    assert!(
        children_of(child.id()).is_empty(),
        "the fallback created a process of its own to hold this state"
    );
    passphrase
}

/// The parent letting go while the passphrase is being typed.
///
/// This is the state of the fallback that holds the most without holding a
/// secret: the file is open, validated and confirmed, its bytes are in memory,
/// and the very next thing that happens is a derivation. The lease is released
/// there, and what must follow is one controlled cancellation — the expurgated
/// terminal, the descriptor returned, no derivation ever started.
#[test]
#[ignore = "requires the isolated Xvfb the LAB run provides"]
fn a_released_lease_closes_the_passphrase_window_and_returns_the_file_it_opened() {
    assert!(
        std::env::var_os("DISPLAY").is_some(),
        "this case needs the isolated display the LAB run provides"
    );

    let before = key_directory_digest();
    let (mut child, parent_lease) = start_driven_helper();
    let _passphrase_window = drive_to_passphrase_window(&mut child, NOMINAL_ED25519);
    let pid = child.id();

    drop(parent_lease);

    let output = collect_output_bounded(child, PROCESS_TIMEOUT)
        .expect("the cancelled helper must stop under a bound");
    assert_eq!(
        output.status.code(),
        Some(i32::from(EXIT_CANCELLED)),
        "a lease released under the passphrase window is a cancellation; \
         status {:?}, stderr {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        decode_event(&output.stdout),
        AssistantEventV1 {
            schema_version: 1,
            request_id: DIRECT_REQUEST_ID.into(),
            event: AssistantEventKind::Cancelled,
        }
    );
    await_disappearance(pid);
    assert!(
        open_files(pid).is_empty(),
        "a descriptor of the personal file outlived the cancellation"
    );
    assert!(
        window_titled(&pid.to_string(), KEY_PASSPHRASE_TITLE).is_none(),
        "the passphrase window outlived the process that opened it"
    );
    assert_eq!(key_directory_digest(), before);
}

/// The user closing the passphrase window instead of answering it.
#[test]
#[ignore = "requires the isolated Xvfb the LAB run provides"]
fn a_closed_passphrase_window_returns_the_file_and_derives_nothing() {
    assert!(
        std::env::var_os("DISPLAY").is_some(),
        "this case needs the isolated display the LAB run provides"
    );

    let before = key_directory_digest();
    let (mut child, parent_lease) = start_driven_helper();
    let passphrase_window = drive_to_passphrase_window(&mut child, NOMINAL_ED25519);
    let pid = child.id();

    press(&passphrase_window, "Escape");

    let output = collect_output_bounded(child, PROCESS_TIMEOUT)
        .expect("the closed helper must stop under a bound");
    drop(parent_lease);
    assert_eq!(
        output.status.code(),
        Some(i32::from(EXIT_CANCELLED)),
        "a passphrase window the user closes is a cancellation; status {:?}, stderr {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        decode_event(&output.stdout),
        AssistantEventV1 {
            schema_version: 1,
            request_id: DIRECT_REQUEST_ID.into(),
            event: AssistantEventKind::Cancelled,
        }
    );
    await_disappearance(pid);
    assert!(open_files(pid).is_empty());
    assert_eq!(key_directory_digest(), before);
}

/// A crash while the passphrase window is open.
///
/// The file is held here, so the claim is about the descriptor as much as about
/// the process: a `SIGKILL` runs no destructor, and what returns the descriptor
/// is the kernel closing it with everything else this process owned.
#[test]
#[ignore = "requires the isolated Xvfb the LAB run provides"]
fn a_crash_while_the_passphrase_window_is_open_takes_the_window_and_the_file_with_it() {
    use std::os::unix::process::ExitStatusExt as _;

    assert!(
        std::env::var_os("DISPLAY").is_some(),
        "this case needs the isolated display the LAB run provides"
    );

    let before = key_directory_digest();
    let (mut child, parent_lease) = start_driven_helper();
    let _passphrase_window = drive_to_passphrase_window(&mut child, NOMINAL_ED25519);
    let pid = child.id();

    crash(pid);

    let status = wait_bounded(&mut child, PROCESS_TIMEOUT).expect("the crashed helper is reaped");
    drop(parent_lease);
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    await_disappearance(pid);
    assert!(
        open_files(pid).is_empty(),
        "a descriptor of the personal file outlived the crash"
    );
    assert!(
        thread_names(pid).is_empty(),
        "a thread of the crashed helper is still running"
    );
    assert!(children_of(pid).is_empty());
    let process_id = pid.to_string();
    for title in [PERSONAL_ACCESS_TITLE, KEY_PASSPHRASE_TITLE] {
        assert!(
            window_titled(&process_id, title).is_none(),
            "the window «{title}» outlived the process that opened it"
        );
    }
    assert_eq!(key_directory_digest(), before);
}

/// Accelerator of the passphrase field, and of the acceptance beside it.
const FOCUS_PASSPHRASE: &str = "alt+p";
const ACCEPT_PASSPHRASE: &str = "alt+c";
/// How long a released lease is given to prove it did *not* cut a derivation.
const NOT_CUT_GRACE: Duration = Duration::from_secs(1);
/// Longest a helper whose derivation was left to finish may take to stop.
const ABSORBED_TIMEOUT: Duration = Duration::from_secs(60);

/// How many times the server has accepted a public key for one account.
///
/// It is the server's own account of a connection having happened, taken from
/// its journal rather than from anything this client says about itself.
fn authentications_for(account: &str) -> usize {
    server(&format!(
        "journalctl -t sshd-session --since '-30 min' --no-pager \
         | grep -c 'Accepted publickey for {account} ' || true"
    ))
    .parse()
    .unwrap_or(0)
}

/// Hands the passphrase to the window that asks for it, and consents.
///
/// The passphrase travels as the *contents of a file* rather than as an
/// argument: a synthetic secret typed on a command line would sit in `/proc`
/// for as long as the typing lasts, and this suite spends its time proving that
/// nothing of the sort happens.
fn type_passphrase_and_accept(window: &str) {
    press(window, FOCUS_PASSPHRASE);
    assert!(
        xdotool(&[
            "type",
            "--clearmodifiers",
            "--delay",
            "20",
            "--file",
            &required(KEY_PASSPHRASE),
        ])
        .is_some(),
        "the passphrase could not be typed into the window"
    );
    press(window, ACCEPT_PASSPHRASE);
}

/// The parent letting go while the derivation is running — and what that does
/// not do.
///
/// This is the one exit of the fallback that is *not* immediate, and the case
/// exists to say so precisely rather than to hide it. `bcrypt-pbkdf` cannot be
/// interrupted once it has started; the derivation runs on a thread that owns
/// everything it was given, and the only bound on it is the deadline. So a
/// lease released here is not a cut: it is absorbed, and it is absorbed within
/// a bound — the shorter of what is left of the session and the derivation's
/// own ceiling.
///
/// What must nevertheless be true is that nothing is *used*. The key the
/// derivation produces is never carried into a transport, the server never sees
/// a connection, and the session ends on the expurgated cancellation like every
/// other released lease. All four are asserted, and the one that says the
/// derivation really was still running when the lease went is the thread, read
/// from `/proc` before and after.
#[test]
#[ignore = "requires the isolated Xvfb the LAB run provides"]
fn a_lease_released_during_the_derivation_is_absorbed_and_opens_no_connection() {
    assert!(
        std::env::var_os("DISPLAY").is_some(),
        "this case needs the isolated display the LAB run provides"
    );

    let username = required(USERNAME);
    let accepted_before = authentications_for(&username);
    let before = key_directory_digest();
    let (mut child, parent_lease) = start_driven_helper();
    let passphrase_window = drive_to_passphrase_window(&mut child, COSTLY);
    let pid = child.id();
    type_passphrase_and_accept(&passphrase_window);

    // The control: a derivation is really running before anything is released.
    let deadline = Instant::now() + DRIVEN_WINDOW_TIMEOUT;
    while !derivation_running(pid) {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("the helper exited with {status} instead of deriving");
        }
        if Instant::now() >= deadline {
            abandon(&mut child, "the consent never started a derivation");
        }
        thread::sleep(POLL_INTERVAL);
    }

    let released = Instant::now();
    drop(parent_lease);

    // And the finding: it keeps running. A cancellation observed here is
    // recorded, not acted on, because there is nothing safe to act on it with.
    thread::sleep(NOT_CUT_GRACE);
    assert!(
        derivation_running(pid),
        "the derivation stopped within {NOT_CUT_GRACE:?} of the release: it was cut \
         after all, and this case no longer describes what happens"
    );

    let output = collect_output_bounded(child, ABSORBED_TIMEOUT)
        .expect("the helper must stop under a bound even so");
    let stopped_after = released.elapsed();
    assert_eq!(
        output.status.code(),
        Some(i32::from(EXIT_CANCELLED)),
        "an absorbed cancellation is still a cancellation; status {:?}, stderr {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        decode_event(&output.stdout),
        AssistantEventV1 {
            schema_version: 1,
            request_id: DIRECT_REQUEST_ID.into(),
            event: AssistantEventKind::Cancelled,
        },
        "the terminal of an absorbed cancellation says nothing more than any other"
    );
    assert!(
        stopped_after > NOT_CUT_GRACE,
        "the helper stopped at {stopped_after:?}: nothing was absorbed"
    );

    await_disappearance(pid);
    assert!(
        thread_names(pid).is_empty(),
        "the derivation thread outlived the session it belonged to"
    );
    assert!(
        open_files(pid).is_empty(),
        "a descriptor of the personal file outlived the cancellation"
    );
    assert!(children_of(pid).is_empty());
    assert_eq!(
        authentications_for(&username),
        accepted_before,
        "a key derived under a released lease was carried into a connection"
    );
    assert_eq!(key_directory_digest(), before);
}

/// A crash while the shipped helper is deriving.
///
/// The fixture case above is the one that searches for what a crash leaves
/// behind; this one says the same exit reaches the same state through the
/// product's own path — a file named in the native selector, a passphrase typed
/// in the native window, a derivation started by the consent — and that nothing
/// of it survives: no thread, no descriptor, no window, and no connection the
/// server would have seen.
#[test]
#[ignore = "requires the isolated Xvfb the LAB run provides"]
fn a_crash_during_the_derivation_of_the_shipped_helper_leaves_nothing_of_it() {
    use std::os::unix::process::ExitStatusExt as _;

    assert!(
        std::env::var_os("DISPLAY").is_some(),
        "this case needs the isolated display the LAB run provides"
    );

    let username = required(USERNAME);
    let accepted_before = authentications_for(&username);
    let before = key_directory_digest();
    let (mut child, parent_lease) = start_driven_helper();
    let passphrase_window = drive_to_passphrase_window(&mut child, COSTLY);
    let pid = child.id();
    type_passphrase_and_accept(&passphrase_window);

    let deadline = Instant::now() + DRIVEN_WINDOW_TIMEOUT;
    while !derivation_running(pid) {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("the helper exited with {status} instead of deriving");
        }
        if Instant::now() >= deadline {
            abandon(&mut child, "the consent never started a derivation");
        }
        thread::sleep(POLL_INTERVAL);
    }
    assert!(open_files(pid).contains(&key_file(COSTLY)));

    crash(pid);

    let status = wait_bounded(&mut child, PROCESS_TIMEOUT).expect("the crashed helper is reaped");
    drop(parent_lease);
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    await_disappearance(pid);
    assert!(
        thread_names(pid).is_empty(),
        "the derivation thread outlived the crash"
    );
    assert!(open_files(pid).is_empty());
    assert!(children_of(pid).is_empty());
    let process_id = pid.to_string();
    for title in [PERSONAL_ACCESS_TITLE, KEY_PASSPHRASE_TITLE] {
        assert!(
            window_titled(&process_id, title).is_none(),
            "the window «{title}» outlived the crash"
        );
    }
    assert_eq!(
        authentications_for(&username),
        accepted_before,
        "a derivation that was killed still opened a connection"
    );
    assert_eq!(key_directory_digest(), before);
}

// ------------------------------------------------------------- the elevation
//
// The three channels of #54, against a real `sshd` and a real `sudo`. Every
// case below drives the same sequence the helper drives — identity, policy,
// then at most one elevation — on the one session #52 opened and #53 can also
// open. The hostile matrices are produced by the *server's* policy, never by a
// modified client: what is under test is what this client refuses to do with a
// policy it was handed.

/// Where a run of the elevation stopped, and why. It is deliberately not a
/// single flattened refusal: "the policy could not be attested" and "the
/// elevated command answered something else" are different claims, and a suite
/// that could not tell them apart would pass on the wrong one.
#[derive(Debug, PartialEq, Eq)]
enum Stop {
    Transport(TransportRefusal),
    Identity(ElevationRefusal),
    Policy(ElevationRefusal),
    Elevation(ElevationRefusal),
}

/// One whole administrator elevation, and what it cost.
#[derive(Debug)]
struct ElevationRun {
    outcome: Result<Elevation, Stop>,
    channels_spent: usize,
    /// The command the attested policy chose, when it got that far.
    command: Option<FixedCommand>,
    password_required: Option<bool>,
}

fn sudo_password() -> Vec<u8> {
    let password = fs::read(required(SUDO_PASSWORD)).expect("the sudo password must be readable");
    assert!(
        password.len() >= 32,
        "the synthetic sudo password must really have been generated"
    );
    password
}

/// Establishes one session on the nominal server, by numeric address, with the
/// agent identity the server accepts.
fn establish_as(username: &str) -> Result<LiveSession, PersonalAccessRefusal> {
    let host_key = required(HOST_KEY);
    let authorized = required(AUTHORIZED);
    prepare()
        .establish(
            &AuthenticationRequest {
                username,
                approved_host_key_fingerprint: &host_key,
                selected_fingerprint: &authorized,
            },
            lease(),
            &always_continue(),
        )
        .outcome
}

/// The same, authenticated by an encrypted key file instead of the agent.
fn establish_with_key_as(name: &str, username: &str) -> Result<LiveSession, PersonalAccessRefusal> {
    let key = open_key(name);
    let fingerprint = key.fingerprint().to_owned();
    let host_key = required(HOST_KEY);
    prepare()
        .establish_with_key(
            key,
            &AuthenticationRequest {
                username,
                approved_host_key_fingerprint: &host_key,
                selected_fingerprint: &fingerprint,
            },
            lease(),
            &always_continue(),
        )
        .outcome
}

/// Drives the administrator route on an already established session, in the
/// order and with the bounds the helper itself uses.
///
/// `password` is what the native window would have answered. It is only ever
/// reached when the attested policy says one is required, which is the whole
/// claim: a password that is never asked for is a password that never travels.
fn elevate(live: &mut LiveSession, password: Option<&[u8]>) -> ElevationRun {
    let mut command = None;
    let mut password_required = None;
    let outcome = drive_elevation(live, password, &mut command, &mut password_required);
    ElevationRun {
        outcome,
        channels_spent: live.channels_spent(),
        command,
        password_required,
    }
}

/// The three stages, in order, each reporting where it stopped.
///
/// It is written with `?` rather than with a state machine so that reading it
/// beside `prove_administrator_elevation` is enough to see that the suite drives
/// the same sequence the helper does.
fn drive_elevation(
    live: &mut LiveSession,
    password: Option<&[u8]>,
    command: &mut Option<FixedCommand>,
    password_required: &mut Option<bool>,
) -> Result<Elevation, Stop> {
    let probe = live
        .probe(lease(), &always_continue())
        .map_err(Stop::Transport)?;
    elevation::attest_identity(
        AccessRoute::Administrator,
        probe.exit_status,
        &probe.stdout,
        &probe.stderr,
    )
    .map_err(Stop::Identity)?;

    let preflight = live
        .run_channel(elevation::PREFLIGHT, None, lease(), &always_continue())
        .map_err(Stop::Transport)?;
    let succeeded = preflight.exit_status == 0;
    let capture = if succeeded {
        &preflight.stdout
    } else {
        &preflight.stderr
    };
    let attested = elevation::attest_policy(succeeded, capture, false).map_err(Stop::Policy)?;
    *command = Some(attested.command);
    *password_required = Some(attested.password_required);

    // A password travels exactly when the attested policy asked for one, and a
    // case that offered none where one was required is a broken case rather
    // than a refusal to report.
    let standard_input = if attested.password_required {
        Some(password.expect("this case must offer the password its policy demands"))
    } else {
        None
    };
    let elevated = live
        .run_channel(
            attested.command,
            standard_input,
            lease(),
            &always_continue(),
        )
        .map_err(Stop::Transport)?;
    elevation::elevated(elevated.exit_status, &elevated.stdout, &elevated.stderr)
        .map_err(Stop::Elevation)
}

/// Establishes, elevates and closes, which is what the helper does.
fn elevate_as(username: &str, password: Option<&[u8]>) -> ElevationRun {
    let mut live = establish_as(username).expect("the LAB session must open");
    let run = elevate(&mut live, password);
    live.close();
    run
}

/// The nominal password route, end to end: three channels, one password, one
/// proven elevation.
///
/// The account's policy is listable without a secret and its action is not,
/// which is the only configuration in which #51 lets a password travel at all.
/// The account is asserted to be a non-root one first, because an elevation
/// that started from `root` would prove nothing.
#[test]
fn a_password_protected_policy_spends_exactly_one_password_and_proves_the_elevation() {
    let username = required(SUDO_PASSWORD_USERNAME);
    let expected_uid: u32 = required(SUDO_UID).parse().expect("a decimal uid");
    assert_ne!(expected_uid, 0, "the perimeter must not have created root");

    let mut live = establish_as(&username).expect("the LAB session must open");
    let probe = live
        .probe(lease(), &always_continue())
        .expect("the fixed probe must answer");
    assert_eq!(
        elevation::attest_identity(
            AccessRoute::Administrator,
            probe.exit_status,
            &probe.stdout,
            &probe.stderr,
        ),
        Ok(expected_uid)
    );
    live.close();

    let run = elevate_as(&username, Some(&sudo_password()));
    assert!(
        run.outcome.is_ok(),
        "the nominal password elevation must be proven: {:?}",
        run.outcome
    );
    assert_eq!(run.outcome.unwrap().route(), AccessRoute::Administrator);
    assert_eq!(run.password_required, Some(true));
    assert_eq!(run.command, Some(ELEVATE_WITH_PASSWORD));
    assert_eq!(
        run.channels_spent, MAX_EXEC_CHANNELS,
        "the whole conversation is three channels, and it used all three"
    );
}

/// The passwordless route: the attested policy waives authentication, so no
/// password is asked for and none exists in this process at any point.
#[test]
fn a_policy_that_waives_authentication_elevates_without_any_password() {
    let run = elevate_as(&required(SUDO_NOPASSWD_USERNAME), None);
    assert!(
        run.outcome.is_ok(),
        "the passwordless elevation must be proven: {:?}",
        run.outcome
    );
    assert_eq!(run.password_required, Some(false));
    assert_eq!(run.command, Some(ELEVATE_WITHOUT_PASSWORD));
    assert_eq!(run.channels_spent, MAX_EXEC_CHANNELS);
}

/// The same elevation, on the fallback of #53. It is the same three channels of
/// the same session; only the signer changed.
#[test]
fn the_encrypted_key_file_reaches_the_same_proven_elevation() {
    let username = required(SUDO_PASSWORD_USERNAME);
    let mut live =
        establish_with_key_as(NOMINAL_ED25519, &username).expect("the key session must open");
    let run = elevate(&mut live, Some(&sudo_password()));
    live.close();

    assert!(
        run.outcome.is_ok(),
        "the key file must reach the same elevation: {:?}",
        run.outcome
    );
    assert_eq!(run.command, Some(ELEVATE_WITH_PASSWORD));
    assert_eq!(run.channels_spent, MAX_EXEC_CHANNELS);
}

/// The password is sent once and never again. `sudo` answers a wrong one by
/// printing the sentinel a second time, and that second prompt is exactly what
/// this client refuses: there is no answer left to give it.
#[test]
fn a_wrong_password_is_refused_on_its_second_prompt_and_never_retried() {
    let username = required(SUDO_PASSWORD_USERNAME);
    let run = elevate_as(&username, Some(b"synthetic-wrong-password"));
    assert_eq!(
        run.outcome,
        Err(Stop::Elevation(ElevationRefusal::UnexpectedPrompt)),
        "a second prompt is sudo asking again, and there is no second answer"
    );
    assert_eq!(
        run.channels_spent, MAX_EXEC_CHANNELS,
        "the refusal must not have cost a fourth channel"
    );

    // The control, on the same account and the same policy, with the password
    // the perimeter really generated.
    let control = elevate_as(&username, Some(&sudo_password()));
    assert!(control.outcome.is_ok(), "{:?}", control.outcome);
}

/// Every hostile policy of #51, each with the positive control beside it.
///
/// The refusals are read at the stage that produced them, so a case that failed
/// earlier than it should — a transport that broke before the policy was even
/// listed — fails this test instead of passing it.
#[test]
fn every_hostile_policy_fails_closed_at_the_stage_that_judged_it() {
    let hostile: [(&str, Stop); 5] = [
        (
            SUDO_UNLISTABLE_USERNAME,
            Stop::Policy(ElevationRefusal::Policy(
                SudoRefusal::AuthenticationRequired,
            )),
        ),
        (
            SUDO_REQUIRETTY_USERNAME,
            Stop::Policy(ElevationRefusal::Policy(
                SudoRefusal::AuthenticationRequired,
            )),
        ),
        (
            SUDO_LOG_INPUT_USERNAME,
            Stop::Policy(ElevationRefusal::Policy(SudoRefusal::InputLoggingActive)),
        ),
        (
            SUDO_DIVERGENT_USERNAME,
            Stop::Policy(ElevationRefusal::DivergentCommand),
        ),
        (
            SUDO_AMBIGUOUS_USERNAME,
            Stop::Policy(ElevationRefusal::AmbiguousPolicy),
        ),
    ];
    for (name, expected) in hostile {
        let username = required(name);
        // The password is offered on every one of them. None may reach a
        // channel: a policy that was refused never asks for one.
        let run = elevate_as(&username, Some(&sudo_password()));
        assert_eq!(
            run.outcome,
            Err(expected),
            "{username} did not fail closed where it should have"
        );
        assert_eq!(
            run.password_required, None,
            "{username} decided about a password despite an unattestable policy"
        );
        assert_eq!(
            run.channels_spent, 2,
            "{username} opened an elevation channel it had no policy for"
        );
    }

    // A listing past the bound is cut by the channel that reads it, before any
    // policy is judged at all.
    let oversized = required(SUDO_OVERSIZED_USERNAME);
    let run = elevate_as(&oversized, Some(&sudo_password()));
    assert_eq!(
        run.outcome,
        Err(Stop::Transport(TransportRefusal::ProbeOutputTooLarge))
    );
    assert_eq!(run.password_required, None);

    // The control: the same three channels, on a policy that is attestable.
    let control = elevate_as(&required(SUDO_NOPASSWD_USERNAME), None);
    assert!(control.outcome.is_ok(), "{:?}", control.outcome);
}

/// A session that has spent its three channels opens no fourth one, and the
/// refusal is the budget's rather than the server's.
#[test]
fn a_fourth_channel_is_refused_by_the_session_budget() {
    let username = required(SUDO_NOPASSWD_USERNAME);
    let mut live = establish_as(&username).expect("the LAB session must open");
    let run = elevate(&mut live, None);
    assert!(run.outcome.is_ok(), "{:?}", run.outcome);
    assert_eq!(live.channels_spent(), MAX_EXEC_CHANNELS);

    assert_eq!(
        live.run_channel(elevation::IDENTITY, None, lease(), &always_continue()),
        Err(TransportRefusal::ChannelBudgetSpent),
        "a session that spent its budget must refuse rather than negotiate"
    );
    assert_eq!(live.channels_spent(), MAX_EXEC_CHANNELS);
    live.close();
}

/// The administrator route never arrives at `root`.
///
/// The session really authenticates as `root` here — the perimeter authorises
/// the same identity on root's own `authorized_keys` — and the route still
/// refuses, at the identity probe, before a policy is even listed. That is the
/// implicit root attempt this palier forbids, taken against a session on which
/// it would otherwise have succeeded.
#[test]
fn an_account_that_is_already_root_is_refused_by_the_administrator_route() {
    let run = elevate_as(&required(ROOT_USERNAME), Some(&sudo_password()));
    assert_eq!(
        run.outcome,
        Err(Stop::Identity(ElevationRefusal::AlreadyRoot))
    );
    assert_eq!(
        run.channels_spent, 1,
        "the refusal must happen on the identity probe and cost nothing more"
    );
}

/// The root route: one channel, uid exactly zero, and its own consent.
///
/// The same probe of the same session is read three ways here. With the
/// dedicated consent it is an access; without it, it is not an access at all
/// even though every byte of the session is identical; and offered to the
/// administrator route it is refused outright.
#[test]
fn the_root_route_needs_its_own_consent_and_nothing_else_grants_it() {
    let username = required(ROOT_USERNAME);
    let mut live = establish_as(&username).expect("the root session must open");
    let probe = live
        .probe(lease(), &always_continue())
        .expect("the fixed probe must answer");
    live.close();

    assert_eq!(
        elevation::attest_identity(
            AccessRoute::Root,
            probe.exit_status,
            &probe.stdout,
            &probe.stderr,
        ),
        Ok(0),
        "the root route must really have reached uid zero"
    );
    assert_eq!(
        elevation::root_access(true, probe.exit_status, &probe.stdout, &probe.stderr)
            .map(Elevation::route),
        Ok(AccessRoute::Root)
    );
    assert_eq!(
        elevation::root_access(false, probe.exit_status, &probe.stdout, &probe.stderr),
        Err(ElevationRefusal::NotRoot),
        "the very same session is not an access without its own consent"
    );
    assert_eq!(
        elevation::attest_identity(
            AccessRoute::Administrator,
            probe.exit_status,
            &probe.stdout,
            &probe.stderr,
        ),
        Err(ElevationRefusal::AlreadyRoot)
    );
}

/// A non-root account is never mistaken for the root route.
#[test]
fn the_root_route_refuses_a_session_that_is_not_root() {
    let username = required(SUDO_NOPASSWD_USERNAME);
    let mut live = establish_as(&username).expect("the LAB session must open");
    let probe = live
        .probe(lease(), &always_continue())
        .expect("the fixed probe must answer");
    live.close();

    assert_eq!(
        elevation::root_access(true, probe.exit_status, &probe.stdout, &probe.stderr),
        Err(ElevationRefusal::NotRoot),
        "a consent to a root access does not make a session root"
    );
}

/// Cancellation and expiry at each of the three transitions.
///
/// The guard is what a released lease and a fired watchdog reach the session
/// through, and it is consulted between every step and on every idle tick. Each
/// case lets exactly as many consultations pass as it takes to be *inside* the
/// numbered channel, then fires, and the server's own journal is what says the
/// session really closed — on the client and on the far side.
#[test]
fn cancelling_or_expiring_at_each_transition_closes_the_whole_session() {
    let username = required(SUDO_NOPASSWD_USERNAME);
    let host_key = required(HOST_KEY);
    let authorized = required(AUTHORIZED);

    for verdict in [GuardVerdict::Cancelled, GuardVerdict::Expired] {
        let expected = match verdict {
            GuardVerdict::Cancelled => TransportRefusal::Cancelled,
            _ => TransportRefusal::Expired,
        };
        // Nought lets the guard fire before the first channel is even opened;
        // the larger counts land inside a running one.
        for consultations in [0, 2, 8] {
            let guard = guard_firing_after(consultations, verdict);
            let established = prepare().establish(
                &AuthenticationRequest {
                    username: &username,
                    approved_host_key_fingerprint: &host_key,
                    selected_fingerprint: &authorized,
                },
                lease(),
                &guard,
            );
            let mut live = match established.outcome {
                Ok(live) => live,
                // The guard fired during the authentication itself, which is
                // the earliest transition of all and still a closed session.
                Err(refusal) => {
                    assert_eq!(refusal, PersonalAccessRefusal::Transport(expected));
                    continue;
                }
            };
            let mut refusals = Vec::new();
            for command in [
                elevation::IDENTITY,
                elevation::PREFLIGHT,
                ELEVATE_WITHOUT_PASSWORD,
            ] {
                if let Err(refusal) = live.run_channel(command, None, lease(), &guard) {
                    refusals.push(refusal);
                }
            }
            live.close();
            assert!(
                refusals.contains(&expected),
                "a guard firing after {consultations} consultations left the session running: \
                 {refusals:?}"
            );
        }
    }
}

/// A cancellation while the far side is really holding a channel open closes it
/// on both sides, with the server's own account of the closure as the witness.
///
/// It is taken on the held account of #52 rather than on a `sudo` one because
/// only that account keeps a channel alive long enough to be interrupted, and
/// what is under test is the session's teardown rather than the policy.
#[test]
fn a_guard_firing_between_two_channels_leaves_nothing_running_on_the_server() {
    let held = required(HELD_USERNAME);
    let host_key = required(HOST_KEY);
    let authorized = required(AUTHORIZED);
    await_held_probes(0);
    let before = held_channel_closures();

    let established = prepare().establish(
        &AuthenticationRequest {
            username: &held,
            approved_host_key_fingerprint: &host_key,
            selected_fingerprint: &authorized,
        },
        lease(),
        &always_continue(),
    );
    let mut live = established.outcome.expect("the held session must open");
    // The first channel is the forced command that holds the transport, and it
    // is cut from under the session by the guard.
    let refusal = live
        .run_channel(
            elevation::IDENTITY,
            None,
            lease(),
            &guard_firing_after(8, GuardVerdict::Cancelled),
        )
        .expect_err("a cancelled channel cannot answer");
    assert_eq!(refusal, TransportRefusal::Cancelled);
    live.close();

    assert_session_closed(before);
}

/// Nothing of the elevation perimeter is left changed by any of the above.
///
/// The accounts, their policies, their `authorized_keys` and the synthetic
/// password's own hash are read on the server and compared with themselves. A
/// suite that had written anywhere — a timestamp file, a retry counter, a
/// changed password — would be seen here.
#[test]
fn the_sudo_accounts_and_their_policies_are_identical_before_and_after() {
    let accounts = [
        SUDO_PASSWORD_USERNAME,
        SUDO_NOPASSWD_USERNAME,
        SUDO_UNLISTABLE_USERNAME,
        SUDO_LOG_INPUT_USERNAME,
        SUDO_REQUIRETTY_USERNAME,
        SUDO_DIVERGENT_USERNAME,
        SUDO_AMBIGUOUS_USERNAME,
        SUDO_OVERSIZED_USERNAME,
    ]
    .map(required);
    // Built from the perimeter's own names rather than from a prefix written
    // here: this file carries no account name of its own.
    let inventory = format!(
        "for account in {}; do \
           sha256sum /etc/sudoers.d/*\"$account\" \"/home/$account/.ssh/authorized_keys\"; \
           getent shadow \"$account\" | sha256sum; \
         done 2>/dev/null | sort",
        accounts.join(" ")
    );
    let before = server(&inventory);
    assert!(
        before.lines().count() >= accounts.len(),
        "the elevation perimeter must really be mounted: {before}"
    );

    let run = elevate_as(&required(SUDO_NOPASSWD_USERNAME), None);
    assert!(run.outcome.is_ok(), "{:?}", run.outcome);
    let refused = elevate_as(
        &required(SUDO_PASSWORD_USERNAME),
        Some(b"synthetic-wrong-password"),
    );
    assert!(refused.outcome.is_err());

    assert_eq!(
        server(&inventory),
        before,
        "the elevation changed the perimeter it ran against"
    );
}

/// No trace of the synthetic `sudo` password anywhere the far side keeps one.
///
/// The far side's own account of what happened is *fetched back* and searched
/// here rather than searched there: a `grep` carrying the password would put it
/// on the server's command line and in its journal, which is the very leak this
/// case is about. What comes back is `sudo`'s log of the authentication, the
/// I/O log directory listing, and whatever those logs hold — and none of it may
/// contain a byte of the password that was really sent.
#[test]
fn no_byte_of_the_sent_password_survives_on_the_server() {
    let password = sudo_password();
    let run = elevate_as(&required(SUDO_PASSWORD_USERNAME), Some(&password));
    assert!(run.outcome.is_ok(), "{:?}", run.outcome);

    let account = required(SUDO_PASSWORD_USERNAME);
    let logged = server(&format!(
        "journalctl -t sudo --since '-30 min' --no-pager 2>/dev/null | grep -F {account} || true"
    ));
    assert!(
        logged.contains("/usr/bin/id"),
        "sudo must really have logged the one command it ran: {logged}"
    );
    let io_logs = server("ls -AR /var/log/sudo-io 2>/dev/null | head -50 || true");
    assert!(
        io_logs.is_empty(),
        "an I/O log exists for a policy this palier attested: {io_logs}"
    );

    for haystack in [&logged, &io_logs] {
        assert!(
            !haystack
                .as_bytes()
                .windows(password.len())
                .any(|window| window == password.as_slice()),
            "the password survived on the server"
        );
    }
}
