#![cfg(target_os = "windows")]

//! The personal SSH access, run from a Windows workstation against a real
//! Linux machine.
//!
//! Everything this suite needs already had a proof on Linux — the frozen
//! target, the exact host key, the single signature, the fixed probe — and none
//! of it said anything about Windows, because the session could not even start
//! there: the enumeration of this machine's own addresses had no Windows
//! implementation, so `Prepared::open` refused at its first line and the whole
//! transport was unreachable behind that refusal.
//!
//! So what is proved here is not the bounds again. It is that the *same* code
//! reaches them from Windows: the addresses of this workstation are really
//! enumerated and really refused as targets, the agent is the OpenSSH pipe
//! whose object owner was attested one module over, and the identity it holds
//! authenticates a session on a machine that is not this one, which runs the
//! fixed probe and answers with a real numeric identity.
//!
//! The far side is deliberately a Linux machine. What Windows changes is the
//! administrator's workstation, never the target: `/usr/bin/id -u` is an
//! absolute path on the machine being accessed.
//!
//! The whole perimeter comes from the environment — no address, no account, no
//! fingerprint and no key material is written here — and the agent is the
//! machine's real `ssh-agent`, holding real identities put there by whoever
//! arranged the run. Nothing in this file synthesises an agent, a server or a
//! signature: a suite that had to build its own peer would be testing the peer.

use std::time::{Duration, Instant};

use your_cloud_native_bootstrap_assistant::personal_access::{
    algorithms::HostKeyType,
    host_key::HostKeyRefusal,
    local_addresses::LocalAddresses,
    session::{
        AuthenticationRequest, GuardVerdict, PersonalAccessRefusal, Prepared, ProbeReport,
        TransportRefusal,
    },
    signature_budget::MAX_AUTHENTICATION_SIGNATURES,
    target::TargetRefusal,
};

/// Numeric address of the Linux machine running the real `sshd`.
const TARGET: &str = "YOUR_CLOUD_LAB_TARGET";
/// Port that `sshd` listens on, decimal.
const PORT: &str = "YOUR_CLOUD_LAB_PORT";
/// Account the session authenticates as.
const USERNAME: &str = "YOUR_CLOUD_LAB_USERNAME";
/// `SHA256:…` fingerprint of that machine's real Ed25519 host key.
const HOST_KEY: &str = "YOUR_CLOUD_LAB_HOST_KEY";
/// Fingerprint of the agent identity the server accepts.
const AUTHORIZED: &str = "YOUR_CLOUD_LAB_AUTHORIZED";
/// Fingerprint of a second, real agent identity the server has never heard of.
///
/// It answers two questions with one key. As a *selected identity* it is the
/// one the server refuses, which must cost no signature. As an *approved host
/// key* it is a well-formed fingerprint that is not the server's, which the
/// handshake must refuse before authenticating anything.
const STRANGER: &str = "YOUR_CLOUD_LAB_STRANGER";
/// Numeric uid the fixed probe must report for that account.
const EXPECTED_UID: &str = "YOUR_CLOUD_LAB_UID";
/// One address this Windows workstation itself holds.
///
/// It is announced by whoever arranged the run, read from Windows itself, so
/// the enumeration under test is confronted with an answer it did not produce.
const SELF_ADDRESS: &str = "YOUR_CLOUD_LAB_SELF_ADDRESS";

const LEASE: Duration = Duration::from_secs(30);

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

/// Opens a preparation against the nominal `sshd`, by numeric address.
fn prepare() -> Prepared {
    Prepared::open(&required(TARGET), required_port(PORT), lease())
        .expect("the LAB target must be observable from Windows")
}

/// Runs one session and returns everything it left behind.
fn run(
    host_key: &str,
    identity: &str,
    guard: &(dyn Fn() -> GuardVerdict + Sync),
) -> (Result<ProbeReport, PersonalAccessRefusal>, usize) {
    let username = required(USERNAME);
    let request = AuthenticationRequest {
        username: &username,
        approved_host_key_fingerprint: host_key,
        selected_fingerprint: identity,
    };
    let observation = prepare().run(&request, lease(), guard);
    assert_eq!(
        observation.stream_refusal, None,
        "the agent conversation must stay inside its own framing",
    );
    (observation.outcome, observation.remaining_signatures)
}

fn always_continue() -> impl Fn() -> GuardVerdict + Sync {
    || GuardVerdict::Continue
}

// ------------------------------------------------------------------ proofs

/// The whole point of this pass: from Windows, through the attested OpenSSH
/// pipe, a real Linux machine authenticates this administrator and runs the
/// fixed probe.
///
/// Every assertion here is about something that had to cross the machine
/// boundary. The identity list came out of the pipe; the numeric identity came
/// out of the target's own `id`; the host key type came out of a handshake that
/// had to negotiate an algorithm this client accepts; and exactly one signature
/// was spent, which is the agent having really signed once.
#[test]
fn a_windows_workstation_authenticates_a_linux_machine_through_the_personal_agent() {
    let prepared = prepare();

    // The frozen set is what the transport may dial, and it is the numeric
    // address that was named: nothing was added to it, nothing re-resolved.
    let target = prepared.target();
    let announced: Vec<String> = target
        .addresses()
        .iter()
        .map(|address| address.to_string())
        .collect();
    assert_eq!(
        announced,
        vec![required(TARGET)],
        "the frozen target must be exactly the named address",
    );

    // The identities were listed over the pipe `agent_pipe` attested. A session
    // that could not read them would not be able to select one either.
    let authorized = required(AUTHORIZED);
    let offered: Vec<&str> = prepared
        .identities()
        .iter()
        .map(|identity| identity.fingerprint.as_str())
        .collect();
    assert!(
        offered.contains(&authorized.as_str()),
        "the Windows agent must really hold the authorised identity: {offered:?}",
    );

    let username = required(USERNAME);
    let host_key = required(HOST_KEY);
    let request = AuthenticationRequest {
        username: &username,
        approved_host_key_fingerprint: &host_key,
        selected_fingerprint: &authorized,
    };
    let observation = prepared.run(&request, lease(), &always_continue());
    assert_eq!(observation.stream_refusal, None);
    let report = observation
        .outcome
        .expect("the session must reach the target and run the probe");

    assert_eq!(report.exit_status, 0);
    assert_eq!(
        String::from_utf8_lossy(&report.stdout).trim(),
        required(EXPECTED_UID),
        "the probe must report the numeric identity of the account on the target",
    );
    assert!(
        report.stderr.is_empty(),
        "the probe wrote on standard error: {}",
        String::from_utf8_lossy(&report.stderr),
    );
    assert_eq!(report.host_key_type, HostKeyType::Ed25519);
    assert_eq!(
        report.signatures_spent, 1,
        "one authentication asks the agent for exactly one signature",
    );
    assert_eq!(
        observation.remaining_signatures,
        MAX_AUTHENTICATION_SIGNATURES - 1,
    );
}

/// The guard that refuses to dial the administrator's own machine is only worth
/// its input, and until this pass Windows had no input at all.
///
/// The refusal that matters is [`TargetRefusal::LocalInterface`]: it can only
/// be reached by an enumeration that really ran and really found this address.
/// Before the Windows enumeration existed, this same call refused with
/// [`PersonalAccessRefusal::Local`] — closed, but for the opposite reason — so
/// the assertion is written to fail on that answer too.
#[test]
fn the_addresses_this_windows_workstation_holds_are_refused_as_targets() {
    let announced = required(SELF_ADDRESS);
    let observed = LocalAddresses::observe().expect("this machine holds addresses");
    let held: Vec<String> = observed
        .addresses()
        .iter()
        .map(|address| address.to_string())
        .collect();
    assert!(
        held.contains(&announced),
        "the enumeration missed an address Windows itself reports: {announced} not in {held:?}",
    );
    assert!(
        observed
            .addresses()
            .iter()
            .any(|address| address.is_loopback()),
        "loopback must never be filtered out of the observation: {held:?}",
    );

    let port = required_port(PORT);
    assert_eq!(
        Prepared::open(&announced, port, lease()).err(),
        Some(PersonalAccessRefusal::Target(TargetRefusal::LocalInterface)),
        "an address this workstation holds must be refused by the enumeration, \
         not by the absence of one",
    );
    assert_eq!(
        Prepared::open("127.0.0.1", port, lease()).err(),
        Some(PersonalAccessRefusal::Target(TargetRefusal::Loopback)),
    );
}

/// No trust on first use, and no signature spent on a server that failed to
/// prove which machine it is.
#[test]
fn a_host_key_that_is_not_the_approved_one_ends_the_session_before_authenticating() {
    let (outcome, remaining) = run(
        &required(STRANGER),
        &required(AUTHORIZED),
        &always_continue(),
    );
    assert_eq!(
        outcome.err(),
        Some(PersonalAccessRefusal::Transport(TransportRefusal::HostKey(
            HostKeyRefusal::KeyMismatch
        ))),
    );
    assert_eq!(
        remaining, MAX_AUTHENTICATION_SIGNATURES,
        "a handshake that never got past the host key must ask the agent for nothing",
    );
}

/// A refused authentication spends nothing: the transport probes the key first
/// and only asks the agent to sign once the server has said it would accept it.
#[test]
fn an_identity_the_target_does_not_know_spends_no_signature() {
    let (outcome, remaining) = run(&required(HOST_KEY), &required(STRANGER), &always_continue());
    assert_eq!(
        outcome.err(),
        Some(PersonalAccessRefusal::Transport(
            TransportRefusal::AuthenticationRefused
        )),
    );
    assert_eq!(
        remaining, MAX_AUTHENTICATION_SIGNATURES,
        "a server that refuses an identity must cost no signature",
    );
}

/// The guard is consulted before anything is dialled, on Windows as on Linux,
/// and a cancelled lease ends the session where it stands.
#[test]
fn a_cancelled_lease_stops_the_session_before_it_dials() {
    let (outcome, remaining) = run(&required(HOST_KEY), &required(AUTHORIZED), &|| {
        GuardVerdict::Cancelled
    });
    assert_eq!(
        outcome.err(),
        Some(PersonalAccessRefusal::Transport(
            TransportRefusal::Cancelled
        )),
    );
    assert_eq!(remaining, MAX_AUTHENTICATION_SIGNATURES);
}
