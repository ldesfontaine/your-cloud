//! The one personal SSH session, and the one probe it carries.
//!
//! Everything this module does happens once. One interface enumeration, one
//! name resolution, one agent connection, one identity listing — all of it
//! before the user is asked anything, so that what the consent window renders
//! is what the transport will later use and nothing can be re-derived
//! afterwards. Then, and only after consent, one transport to one frozen
//! address, one authentication spending one signature, and one `exec` channel
//! running one fixed command.
//!
//! The session is bounded on three independent axes, because any one of them
//! failing must still close the transport:
//!
//! * an outer deadline, the same instant the watchdog holds, wraps the whole
//!   asynchronous run;
//! * a guard, polled between every step and on every idle tick, reports
//!   cancellation, an invalid protocol lease or watchdog expiration;
//! * the parent's death is handled by the operating system — the process is
//!   killed outright — which closes every socket this module opened.
//!
//! Whatever ends the session, the channel and the transport are closed
//! explicitly before returning, on the refusal paths exactly as on the nominal
//! one. Nothing here announces a verified access: the probe result is returned
//! as a value to the caller, which is expected to discard it at this palier.

#[cfg(target_os = "linux")]
use std::future::Future;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use russh::{
    client::{self, Handle, Handler, Msg},
    keys::{Algorithm, HashAlg, PublicKey},
    Channel, ChannelMsg, Disconnect, Names,
};
use tokio::{net::TcpStream, runtime::Runtime, time::timeout};

#[cfg(target_os = "linux")]
use super::agent_endpoint;
#[cfg(target_os = "windows")]
use super::agent_pipe::{self, AgentPipeRefusal};
use super::{
    agent_client::{
        AgentRefusal, BudgetedAgentSigner, PersonalAgent, SigningRefusal, StreamRefusal,
    },
    agent_endpoint::EndpointRefusal,
    algorithms::HostKeyType,
    host_key::{self, HostKeyRefusal},
    local_addresses::{LocalAddressRefusal, LocalAddresses},
    resolver::{self, ResolutionRefusal},
    signature_budget::{OfferedIdentity, MAX_AUTHENTICATION_SIGNATURES},
    ssh_algorithms,
    target::{self, FrozenTarget, TargetRefusal},
};

/// The stream the personal agent is spoken to over.
///
/// It is the one thing about a session that the operating system decides: a
/// Unix socket whose owner and mode the Linux rule reads, or the Windows named
/// pipe whose object owner `agent_pipe` attests. Everything downstream — the
/// bounded framing, the signature budget, the transport, the probe — is
/// written once against this alias and is therefore literally the same code on
/// both platforms.
#[cfg(target_os = "linux")]
pub type AgentStream = tokio::net::UnixStream;

#[cfg(target_os = "windows")]
pub type AgentStream = tokio::net::windows::named_pipe::NamedPipeClient;

/// The single fixed probe. It is a constant, never assembled from input.
///
/// The target of a personal access is a Linux machine on both platforms: what
/// Windows changes is the administrator's own workstation, never the far side.
pub const PROBE_COMMAND: &str = "/usr/bin/id -u";

/// Largest accepted size of each probe stream, separately.
pub const MAX_PROBE_STREAM_BYTES: usize = 4096;

/// How often the guard is consulted while the session waits.
const GUARD_INTERVAL: Duration = Duration::from_millis(50);

/// Longest the agent endpoint may take to accept a connection. The Windows
/// endpoint holds the same two ceilings, declared beside the code that applies
/// them in `agent_pipe`, because opening a pipe and connecting a socket are not
/// the same operation and each must be bounded where it happens.
#[cfg(target_os = "linux")]
const AGENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Longest the agent may take to answer the single identity listing.
#[cfg(target_os = "linux")]
const AGENT_LIST_TIMEOUT: Duration = Duration::from_secs(2);

/// Longest one transport connection attempt may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// SSH's extended data type for the standard error stream.
const EXTENDED_DATA_STDERR: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersonalAccessRefusal {
    Local(LocalAddressRefusal),
    Resolution(ResolutionRefusal),
    Target(TargetRefusal),
    Endpoint(EndpointRefusal),
    Agent(AgentRefusal),
    Transport(TransportRefusal),
    /// The session lease ran out during the preparation itself. It is kept
    /// apart from every step's own failure because an expired lease says
    /// nothing about the agent, the resolver or the target — only that there
    /// was no time left to ask them.
    Expired,
}

/// The Windows agent step refuses in the same three ways the Linux one does,
/// and is carried into the same variants rather than into new ones. A caller
/// reading a refusal must not be able to tell which endpoint produced it: an
/// unavailable agent is an unavailable agent on both platforms, and the reasons
/// that differ — a socket's owner, a pipe object's creator — already live
/// inside [`EndpointRefusal`].
#[cfg(target_os = "windows")]
impl From<AgentPipeRefusal> for PersonalAccessRefusal {
    fn from(refusal: AgentPipeRefusal) -> Self {
        match refusal {
            AgentPipeRefusal::Endpoint(endpoint) => Self::Endpoint(endpoint),
            AgentPipeRefusal::Agent(agent) => Self::Agent(agent),
            AgentPipeRefusal::Expired => Self::Expired,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportRefusal {
    /// No asynchronous runtime could be started for the session.
    RuntimeUnavailable,
    /// No frozen address accepted a connection.
    NoReachableAddress,
    /// The peer that answered is not one of the frozen addresses.
    ForeignPeer,
    HostKey(HostKeyRefusal),
    /// The server refused the selected identity.
    AuthenticationRefused,
    Signing(SigningRefusal),
    /// The session channel could not be opened or the probe not started.
    ChannelRefused,
    /// A probe stream exceeded its own bound.
    ProbeOutputTooLarge,
    /// The probe wrote on a stream that is neither stdout nor stderr.
    UnexpectedProbeStream,
    /// The probe ended without both an exit status and an end of file.
    ProbeIncomplete,
    /// The session deadline elapsed.
    Expired,
    /// The parent lease was released, or the protocol was violated.
    Cancelled,
}

/// What the fixed probe observed. It is a value, never an announcement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeReport {
    pub exit_status: u32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub host_key_type: HostKeyType,
    pub signatures_spent: usize,
}

/// Why a running session must be torn down right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardVerdict {
    Continue,
    Expired,
    Cancelled,
}

/// What one session needs of whoever signs it.
///
/// Two things beyond the signature itself: the public key to authenticate with,
/// and how much of the single-signature budget is left once the session is over.
/// Both are what makes the session one path — it never asks *where* the key
/// lives, only these two questions and the one signature.
pub trait PersonalSigner: russh::Signer<Error = SigningRefusal> + Send {
    fn public_key(&self) -> &PublicKey;
    fn remaining_signatures(&self) -> usize;
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> PersonalSigner
    for BudgetedAgentSigner<S>
{
    fn public_key(&self) -> &PublicKey {
        BudgetedAgentSigner::public_key(self)
    }

    fn remaining_signatures(&self) -> usize {
        BudgetedAgentSigner::remaining_signatures(self)
    }
}

#[cfg(target_os = "linux")]
impl PersonalSigner for super::key_signer::BudgetedKeySigner {
    fn public_key(&self) -> &PublicKey {
        super::key_signer::BudgetedKeySigner::public_key(self)
    }

    fn remaining_signatures(&self) -> usize {
        super::key_signer::BudgetedKeySigner::remaining_signatures(self)
    }
}

/// Everything observed before the user is asked anything.
///
/// The agent is an `Option` because #53 made its absence a state rather than a
/// failure: a machine whose agent holds nothing, or whose endpoint is refused,
/// is exactly the machine where the encrypted key file is the way in. The
/// refusal that was observed is kept beside it, so that a caller which insists
/// on the agent still learns why there is none instead of being told something
/// vaguer.
pub struct Prepared {
    runtime: Runtime,
    agent: Option<PersonalAgent<AgentStream>>,
    /// Why no agent is held, when none is. Always `None` when one is.
    agent_refusal: Option<PersonalAccessRefusal>,
    target: FrozenTarget,
    identities: Vec<OfferedIdentity>,
}

/// What the transport needs once the user has consented and chosen.
pub struct AuthenticationRequest<'a> {
    pub username: &'a str,
    pub approved_host_key_fingerprint: &'a str,
    pub selected_fingerprint: &'a str,
}

/// Everything one session leaves behind: its outcome, and what the agent was
/// actually asked for while it ran.
///
/// The budget is reported beside the outcome rather than dropped with the
/// signer, because the central claim of this palier — "a refused
/// authentication spends no signature" — is not observable from a result that
/// only says the authentication failed. The same holds for the stream refusal:
/// an agent cut off for oversizing or volunteering a frame must be
/// distinguishable from one that simply declined.
///
/// It is a value like [`ProbeReport`], and like it announces nothing.
#[derive(Debug)]
pub struct RunObservation {
    pub outcome: Result<ProbeReport, PersonalAccessRefusal>,
    /// Signatures the selected identity had left when the session ended.
    pub remaining_signatures: usize,
    pub stream_refusal: Option<StreamRefusal>,
}

impl Prepared {
    /// Performs, once, every observation the consent window depends on.
    pub fn open(name: &str, port: u16, deadline: Instant) -> Result<Self, PersonalAccessRefusal> {
        // The machine's own addresses first: the frozen set is judged against
        // them, and an enumeration that did not happen is not an empty one.
        let local = LocalAddresses::observe().map_err(PersonalAccessRefusal::Local)?;
        let resolved = resolver::resolve_once_bounded(name, port, deadline)
            .map_err(PersonalAccessRefusal::Resolution)?;
        let target =
            target::freeze(name, port, &resolved, &local).map_err(PersonalAccessRefusal::Target)?;

        // The endpoint next, and by the rule its own operating system allows.
        // On Linux it is a filesystem entry, judged before any runtime exists.
        #[cfg(target_os = "linux")]
        let endpoint =
            agent_endpoint::observe_linux_endpoint().map_err(PersonalAccessRefusal::Endpoint);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| PersonalAccessRefusal::Transport(TransportRefusal::RuntimeUnavailable))?;

        #[cfg(target_os = "linux")]
        let held = match endpoint {
            Ok(endpoint) => runtime.block_on(open_agent(&endpoint, deadline)),
            Err(refusal) => Err(refusal),
        };
        // On Windows the endpoint is a pipe object, and attesting it *is*
        // opening it: the handle that was attested is the handle the agent is
        // spoken to over, and it is registered with this runtime rather than
        // reopened. That is why the whole step lives one module over and is
        // called, not repeated, here.
        #[cfg(target_os = "windows")]
        let held = runtime
            .block_on(agent_pipe::open_personal_agent(deadline))
            .map_err(PersonalAccessRefusal::from);

        // An agent that cannot be reached, or holds nothing usable, is not the
        // end of the preparation: it is the state in which the encrypted key
        // file of #53 is the only way in. A lease that ran out, on the other
        // hand, ends everything — there is no time left for a window either.
        if held.as_ref().err() == Some(&PersonalAccessRefusal::Expired) {
            return Err(PersonalAccessRefusal::Expired);
        }
        let (agent, agent_refusal, identities) = match held {
            Ok((agent, identities)) => (Some(agent), None, identities),
            Err(refusal) => (None, Some(refusal), Vec::new()),
        };

        Ok(Self {
            runtime,
            agent,
            agent_refusal,
            target,
            identities,
        })
    }

    /// The frozen addresses the consent window must display.
    pub fn target(&self) -> &FrozenTarget {
        &self.target
    }

    /// The identities the user chooses exactly one of.
    pub fn identities(&self) -> &[OfferedIdentity] {
        &self.identities
    }

    /// Opens the session, authenticates once and runs the fixed probe.
    ///
    /// `guard` is consulted between every step and on every idle tick. The
    /// transport and the channel are closed explicitly whatever it answers.
    ///
    /// The signer is borrowed rather than consumed by the session, so that the
    /// budget it holds can still be read once the session is over — refusal
    /// included — and reported in the returned [`RunObservation`].
    pub fn run(
        self,
        request: &AuthenticationRequest<'_>,
        deadline: Instant,
        guard: &(dyn Fn() -> GuardVerdict + Sync),
    ) -> RunObservation {
        let Some(agent) = self.agent else {
            // No agent was retained. Whoever asks for one anyway is told what
            // was observed, and nothing was signed to find out.
            return RunObservation {
                outcome: Err(self
                    .agent_refusal
                    .unwrap_or(PersonalAccessRefusal::Agent(AgentRefusal::ConnectionFailed))),
                remaining_signatures: MAX_AUTHENTICATION_SIGNATURES,
                stream_refusal: None,
            };
        };
        let mut signer = match agent.select(request.selected_fingerprint) {
            Ok(signer) => signer,
            // A selection that never happened spent nothing, and reached no
            // stream: the untouched budget is reported as such.
            Err(refusal) => {
                return RunObservation {
                    outcome: Err(PersonalAccessRefusal::Agent(refusal)),
                    remaining_signatures: MAX_AUTHENTICATION_SIGNATURES,
                    stream_refusal: None,
                }
            }
        };

        let outcome = drive(
            &self.runtime,
            &mut signer,
            &self.target,
            request,
            deadline,
            guard,
        );
        RunObservation {
            outcome: outcome.map_err(PersonalAccessRefusal::Transport),
            remaining_signatures: signer.remaining_signatures(),
            stream_refusal: signer.stream_refusal(),
        }
    }

    /// The same session, authenticated by a key this process opened itself.
    ///
    /// It is the fallback of #53, and it is deliberately three lines long: the
    /// transport, the frozen addresses, the host key attestation, the single
    /// signature budget and the fixed probe are literally the ones above, and
    /// the only thing that changes is which signer is handed to them. A bound
    /// proved on the agent path is therefore the bound this one runs, and a
    /// second implementation of the session never existed to drift from it.
    ///
    /// `request.selected_fingerprint` must name the opened key. It is not read
    /// to select anything here — there is nothing to select from — but the
    /// budget is bound to the key's own fingerprint, so a request naming
    /// another identity is refused by that budget rather than by a check that
    /// could be forgotten.
    #[cfg(target_os = "linux")]
    pub fn run_with_key(
        self,
        key: super::key_unlock::PersonalKey,
        request: &AuthenticationRequest<'_>,
        deadline: Instant,
        guard: &(dyn Fn() -> GuardVerdict + Sync),
    ) -> RunObservation {
        let mut signer = super::key_signer::BudgetedKeySigner::over(key);
        let outcome = drive(
            &self.runtime,
            &mut signer,
            &self.target,
            request,
            deadline,
            guard,
        );
        RunObservation {
            outcome: outcome.map_err(PersonalAccessRefusal::Transport),
            remaining_signatures: signer.remaining_signatures(),
            // No stream was opened towards any agent, so there is no stream
            // refusal to report. It is `None` because nothing happened, which
            // is not the same claim as "nothing went wrong".
            stream_refusal: None,
        }
    }

    /// Hands the selected signer, and the runtime it must be driven on, to the
    /// contract suite.
    ///
    /// It opens no transport on purpose. Two claims of this palier are about
    /// the agent and the budget alone — a substituted identity is refused, a
    /// second signature is refused — and proving them through a whole session
    /// would hide them behind a server's own verdict on the authentication.
    ///
    /// Compiled in only under the contract feature: a release build keeps
    /// exactly one way to reach the agent, which is [`Prepared::run`].
    #[cfg(feature = "personal-access-contract-test")]
    pub fn into_signer(
        self,
        fingerprint: &str,
    ) -> Result<(Runtime, BudgetedAgentSigner<AgentStream>), PersonalAccessRefusal> {
        let agent = self.agent.ok_or_else(|| {
            self.agent_refusal
                .unwrap_or(PersonalAccessRefusal::Agent(AgentRefusal::ConnectionFailed))
        })?;
        let signer = agent
            .select(fingerprint)
            .map_err(PersonalAccessRefusal::Agent)?;
        Ok((self.runtime, signer))
    }
}

/// Runs one whole session on the prepared runtime, whatever signs it.
///
/// This is where the agent path and the key path meet, and there is exactly one
/// of it. The outer bound is the caller's deadline; the guard is consulted
/// inside; the transport and the channel are closed on every path.
fn drive<S: PersonalSigner>(
    runtime: &Runtime,
    signer: &mut S,
    target: &FrozenTarget,
    request: &AuthenticationRequest<'_>,
    deadline: Instant,
    guard: &(dyn Fn() -> GuardVerdict + Sync),
) -> Result<ProbeReport, TransportRefusal> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(TransportRefusal::Expired);
    }
    runtime.block_on(async {
        match timeout(remaining, run_session(signer, target, request, guard)).await {
            Ok(outcome) => outcome,
            Err(_elapsed) => Err(TransportRefusal::Expired),
        }
    })
}

/// Connects to the Linux agent socket and asks it, once, what it holds.
///
/// Both waits are capped by the session lease, exactly like the resolution
/// before them: a socket that never accepts and an agent that never answers
/// must each cost at most what is left of the bail, never their own ceiling on
/// top of it. Its Windows counterpart applies the same two ceilings, for the
/// same reason, inside `agent_pipe::open_personal_agent`.
#[cfg(target_os = "linux")]
async fn open_agent(
    endpoint: &str,
    deadline: Instant,
) -> Result<(PersonalAgent<AgentStream>, Vec<OfferedIdentity>), PersonalAccessRefusal> {
    let stream = await_bounded(
        deadline,
        AGENT_CONNECT_TIMEOUT,
        PersonalAccessRefusal::Agent(AgentRefusal::ConnectionFailed),
        AgentStream::connect(endpoint),
    )
    .await?
    .map_err(|_| PersonalAccessRefusal::Agent(AgentRefusal::ConnectionFailed))?;

    let mut agent = PersonalAgent::over(stream);
    let identities = await_bounded(
        deadline,
        AGENT_LIST_TIMEOUT,
        PersonalAccessRefusal::Agent(AgentRefusal::ProtocolFailed),
        agent.list_identities(),
    )
    .await?
    .map_err(PersonalAccessRefusal::Agent)?;
    Ok((agent, identities))
}

/// Awaits one preparation step under two bounds at once, and tells them apart.
///
/// It serves the Linux agent socket, which is the only step of this module that
/// waits on something outside the transport. The Windows endpoint applies the
/// same two bounds where it opens its pipe.
///
/// The step keeps its own ceiling, which describes what that operation may
/// reasonably cost; the lease keeps its absolute one. Whichever is shorter
/// wins. Which of the two fired is not a detail: a lease that ran out is the
/// session expiring, and must be reported as such rather than blamed on the
/// step that happened to be waiting when it did.
#[cfg(target_os = "linux")]
async fn await_bounded<F: Future>(
    deadline: Instant,
    ceiling: Duration,
    on_ceiling: PersonalAccessRefusal,
    future: F,
) -> Result<F::Output, PersonalAccessRefusal> {
    let bail = deadline
        .saturating_duration_since(Instant::now())
        .min(ceiling);
    // An exhausted lease never starts the step at all.
    if bail.is_zero() {
        return Err(PersonalAccessRefusal::Expired);
    }
    match timeout(bail, future).await {
        Ok(output) => Ok(output),
        Err(_elapsed) if Instant::now() >= deadline => Err(PersonalAccessRefusal::Expired),
        Err(_elapsed) => Err(on_ceiling),
    }
}

/// The verdict the host key handler publishes to the session that owns it.
#[derive(Debug, Default)]
struct HostKeyVerdict {
    /// Wire name of the host key signature algorithm the transport negotiated.
    negotiated: Option<String>,
    attestation: Option<Result<HostKeyType, HostKeyRefusal>>,
}

/// The handler never carries the transport error itself: the session reports
/// its own refusal, and an opaque library message has no place in it.
#[derive(Debug)]
enum HandlerError {
    Transport,
}

impl From<russh::Error> for HandlerError {
    fn from(_: russh::Error) -> Self {
        Self::Transport
    }
}

struct PersonalAccessHandler {
    approved_fingerprint: String,
    verdict: Arc<Mutex<HostKeyVerdict>>,
}

impl Handler for PersonalAccessHandler {
    type Error = HandlerError;

    /// The negotiated host key signature algorithm is recorded here because it
    /// is the only place the transport exposes it, and the attestation below
    /// is meaningless without it.
    ///
    /// Only the first negotiation is kept. A later rekey calls this again but
    /// never calls the key check again, so overwriting the recorded algorithm
    /// would leave an attestation describing an exchange it never examined.
    ///
    /// The shared secret this callback also receives is deliberately ignored:
    /// it is never copied, stored or rendered anywhere.
    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let mut verdict = self
            .verdict
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if verdict.negotiated.is_none() {
            verdict.negotiated = Some(names.key.as_str().to_owned());
        }
        Ok(())
    }

    /// No trust on first use, no `known_hosts` write, no unknown key accepted:
    /// the presented key either is the approved one, attested together with a
    /// signature algorithm its own type may use, or the session ends here.
    async fn check_server_key(&mut self, presented: &PublicKey) -> Result<bool, Self::Error> {
        let mut verdict = self
            .verdict
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let attestation = match verdict.negotiated.as_deref() {
            Some(negotiated) => {
                host_key::attest_presented(&self.approved_fingerprint, presented, negotiated)
            }
            // Reaching the key check without having seen a negotiation is not
            // a case to interpret; it is a refusal.
            None => Err(HostKeyRefusal::AlgorithmRefused),
        };
        let accepted = attestation.is_ok();
        verdict.attestation = Some(attestation);
        Ok(accepted)
    }
}

/// The signer is borrowed rather than consumed so that the budget it holds
/// stays readable once the session is over, refusal included. "A refused
/// authentication spends nothing" is only provable if something can still be
/// asked how much was spent after the refusal.
///
/// It is generic over the signer, and over nothing else, because that is the
/// only difference between reaching the agent and holding the key: same
/// transport, same attestation, same probe, same budget.
async fn run_session<S: PersonalSigner>(
    signer: &mut S,
    target: &FrozenTarget,
    request: &AuthenticationRequest<'_>,
    guard: &(dyn Fn() -> GuardVerdict + Sync),
) -> Result<ProbeReport, TransportRefusal> {
    check(guard)?;

    let verdict = Arc::new(Mutex::new(HostKeyVerdict::default()));
    let handler = PersonalAccessHandler {
        approved_fingerprint: request.approved_host_key_fingerprint.to_owned(),
        verdict: Arc::clone(&verdict),
    };

    let socket = connect_to_frozen_address(target, guard).await?;
    let config = Arc::new(client::Config {
        preferred: ssh_algorithms::preferred(),
        // The session is bounded by the caller's deadline; an idle transport
        // must not outlive it while waiting for a peer that stopped talking.
        inactivity_timeout: Some(CONNECT_TIMEOUT),
        keepalive_interval: None,
        nodelay: true,
        ..client::Config::default()
    });

    let mut handle = match client::connect_stream(config, socket, handler).await {
        Ok(handle) => handle,
        Err(_) => return Err(host_key_refusal_or(&verdict, TransportRefusal::ForeignPeer)),
    };

    let outcome = authenticate_and_probe(&mut handle, signer, request, &verdict, guard).await;
    // The transport is closed on both paths, before the outcome is examined.
    close_transport(&handle).await;
    outcome
}

/// Connects to the frozen addresses in order, and to nothing else.
async fn connect_to_frozen_address(
    target: &FrozenTarget,
    guard: &(dyn Fn() -> GuardVerdict + Sync),
) -> Result<TcpStream, TransportRefusal> {
    for address in target.addresses() {
        check(guard)?;
        let endpoint = SocketAddr::new(*address, target.port());
        let Ok(Ok(socket)) = timeout(CONNECT_TIMEOUT, TcpStream::connect(endpoint)).await else {
            continue;
        };
        // The peer is confronted with the frozen set even though this process
        // chose it: a redirected connection must never pass unnoticed.
        match socket.peer_addr() {
            Ok(peer) if target.allows(peer.ip()) => {
                let _ = socket.set_nodelay(true);
                return Ok(socket);
            }
            _ => return Err(TransportRefusal::ForeignPeer),
        }
    }
    Err(TransportRefusal::NoReachableAddress)
}

async fn authenticate_and_probe<S: PersonalSigner>(
    handle: &mut Handle<PersonalAccessHandler>,
    signer: &mut S,
    request: &AuthenticationRequest<'_>,
    verdict: &Arc<Mutex<HostKeyVerdict>>,
    guard: &(dyn Fn() -> GuardVerdict + Sync),
) -> Result<ProbeReport, TransportRefusal> {
    let host_key_type = attested_host_key_type(verdict)?;
    check(guard)?;

    let public_key = signer.public_key().clone();
    // Ed25519 names no hash; an RSA key names SHA-512 and nothing else. There
    // is deliberately no fallback to SHA-256: retrying a refused signature
    // would spend a second one from the same oracle.
    let hash_alg = match public_key.algorithm() {
        Algorithm::Ed25519 => None,
        Algorithm::Rsa { .. } => Some(HashAlg::Sha512),
        _ => return Err(TransportRefusal::AuthenticationRefused),
    };

    // The transport probes the key without a signature first and only asks the
    // signer to sign once the server has answered that it would accept it, so
    // one call here costs at most one signature and a refusal costs none.
    let authenticated = handle
        .authenticate_publickey_with(request.username, public_key, hash_alg, signer)
        .await
        .map_err(TransportRefusal::Signing)?;
    if !authenticated.success() {
        return Err(TransportRefusal::AuthenticationRefused);
    }
    check(guard)?;

    let mut probe = probe_identity(handle, guard).await?;
    probe.host_key_type = host_key_type;
    probe.signatures_spent =
        MAX_AUTHENTICATION_SIGNATURES.saturating_sub(signer.remaining_signatures());
    Ok(probe)
}

/// Runs the fixed probe in a single `exec` channel.
async fn probe_identity(
    handle: &mut Handle<PersonalAccessHandler>,
    guard: &(dyn Fn() -> GuardVerdict + Sync),
) -> Result<ProbeReport, TransportRefusal> {
    let mut channel: Channel<Msg> = handle
        .channel_open_session()
        .await
        .map_err(|_| TransportRefusal::ChannelRefused)?;
    let outcome = collect_probe(&mut channel, guard).await;
    // The channel is closed explicitly on every path, including the refusals.
    let _ = channel.eof().await;
    let _ = channel.close().await;
    outcome
}

async fn collect_probe(
    channel: &mut Channel<Msg>,
    guard: &(dyn Fn() -> GuardVerdict + Sync),
) -> Result<ProbeReport, TransportRefusal> {
    channel
        .exec(true, PROBE_COMMAND)
        .await
        .map_err(|_| TransportRefusal::ChannelRefused)?;

    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let mut exit_status: Option<u32> = None;
    let mut end_of_file = false;

    loop {
        check(guard)?;
        let message = match timeout(GUARD_INTERVAL, channel.wait()).await {
            // An idle tick is only an opportunity to consult the guard again.
            Err(_elapsed) => continue,
            Ok(None) => break,
            Ok(Some(message)) => message,
        };
        match message {
            ChannelMsg::Data { data } => append_bounded(&mut stdout, &data)?,
            ChannelMsg::ExtendedData { data, ext } if ext == EXTENDED_DATA_STDERR => {
                append_bounded(&mut stderr, &data)?
            }
            ChannelMsg::ExtendedData { .. } => return Err(TransportRefusal::UnexpectedProbeStream),
            ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
            ChannelMsg::Eof => end_of_file = true,
            ChannelMsg::Close => break,
            _ => {}
        }
        if end_of_file && exit_status.is_some() {
            break;
        }
    }

    // Both an exit status and an end of file are required: a probe that stops
    // halfway is not a result, it is an unfinished conversation.
    let exit_status = match (exit_status, end_of_file) {
        (Some(exit_status), true) => exit_status,
        _ => return Err(TransportRefusal::ProbeIncomplete),
    };
    Ok(ProbeReport {
        exit_status,
        stdout,
        stderr,
        // Both are overwritten by the caller, which alone knows them.
        host_key_type: HostKeyType::Ed25519,
        signatures_spent: 0,
    })
}

/// Appends to one probe stream, failing closed on the first excess byte.
fn append_bounded(buffer: &mut Vec<u8>, data: &[u8]) -> Result<(), TransportRefusal> {
    if data.len() > MAX_PROBE_STREAM_BYTES - buffer.len() {
        return Err(TransportRefusal::ProbeOutputTooLarge);
    }
    buffer.extend_from_slice(data);
    Ok(())
}

fn attested_host_key_type(
    verdict: &Arc<Mutex<HostKeyVerdict>>,
) -> Result<HostKeyType, TransportRefusal> {
    let verdict = verdict
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match verdict.attestation {
        Some(Ok(host_key_type)) => Ok(host_key_type),
        Some(Err(refusal)) => Err(TransportRefusal::HostKey(refusal)),
        // No attestation at all is a refusal, never an unexamined key.
        None => Err(TransportRefusal::HostKey(HostKeyRefusal::NoApprovedKey)),
    }
}

/// Prefers the host key refusal, which explains a failed handshake better than
/// the transport error it surfaces as.
fn host_key_refusal_or(
    verdict: &Arc<Mutex<HostKeyVerdict>>,
    otherwise: TransportRefusal,
) -> TransportRefusal {
    match attested_host_key_type(verdict) {
        Ok(_) => otherwise,
        Err(refusal) => refusal,
    }
}

fn check(guard: &(dyn Fn() -> GuardVerdict + Sync)) -> Result<(), TransportRefusal> {
    match guard() {
        GuardVerdict::Continue => Ok(()),
        GuardVerdict::Expired => Err(TransportRefusal::Expired),
        GuardVerdict::Cancelled => Err(TransportRefusal::Cancelled),
    }
}

/// Sends a disconnect and drops the transport. Both matter: the peer learns the
/// session is over, and the socket is released even if it did not.
async fn close_transport(handle: &Handle<PersonalAccessHandler>) {
    let _ = handle.disconnect(Disconnect::ByApplication, "", "").await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The probe is a constant. Nothing assembles it, nothing extends it.
    #[test]
    fn the_probe_is_one_fixed_absolute_command() {
        assert_eq!(PROBE_COMMAND, "/usr/bin/id -u");
        assert!(PROBE_COMMAND.starts_with('/'));
        assert!(!PROBE_COMMAND.contains(';'));
        assert!(!PROBE_COMMAND.contains('&'));
        assert!(!PROBE_COMMAND.contains('|'));
        assert!(!PROBE_COMMAND.contains('\n'));
    }

    #[test]
    fn each_probe_stream_is_bounded_separately_at_four_kibibytes() {
        assert_eq!(MAX_PROBE_STREAM_BYTES, 4096);

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            append_bounded(&mut stdout, &vec![b'x'; MAX_PROBE_STREAM_BYTES]),
            Ok(())
        );
        // Filling one stream must leave the other its own full budget.
        assert_eq!(
            append_bounded(&mut stderr, &vec![b'y'; MAX_PROBE_STREAM_BYTES]),
            Ok(())
        );
        assert_eq!(stdout.len(), MAX_PROBE_STREAM_BYTES);
        assert_eq!(stderr.len(), MAX_PROBE_STREAM_BYTES);
    }

    /// "Fails closed on the first excess byte": one byte over the bound is
    /// refused, and nothing of that write is kept.
    #[test]
    fn the_first_excess_byte_fails_closed_without_being_kept() {
        let mut buffer = vec![b'x'; MAX_PROBE_STREAM_BYTES - 1];
        assert_eq!(append_bounded(&mut buffer, b"y"), Ok(()));
        assert_eq!(buffer.len(), MAX_PROBE_STREAM_BYTES);
        assert_eq!(
            append_bounded(&mut buffer, b"z"),
            Err(TransportRefusal::ProbeOutputTooLarge)
        );
        assert_eq!(
            buffer.len(),
            MAX_PROBE_STREAM_BYTES,
            "a refused write must not grow the buffer"
        );

        let mut oversized = Vec::new();
        assert_eq!(
            append_bounded(&mut oversized, &vec![b'x'; MAX_PROBE_STREAM_BYTES + 1]),
            Err(TransportRefusal::ProbeOutputTooLarge)
        );
        assert!(
            oversized.is_empty(),
            "an oversized chunk is refused whole, never partially kept"
        );
    }

    #[test]
    fn a_guard_that_fires_stops_the_session_with_its_own_reason() {
        assert_eq!(check(&|| GuardVerdict::Continue), Ok(()));
        assert_eq!(
            check(&|| GuardVerdict::Expired),
            Err(TransportRefusal::Expired)
        );
        assert_eq!(
            check(&|| GuardVerdict::Cancelled),
            Err(TransportRefusal::Cancelled)
        );
    }

    /// An unexamined key is a refusal, never an implicit acceptance.
    #[test]
    fn an_absent_attestation_never_becomes_an_acceptance() {
        let verdict = Arc::new(Mutex::new(HostKeyVerdict::default()));
        assert_eq!(
            attested_host_key_type(&verdict),
            Err(TransportRefusal::HostKey(HostKeyRefusal::NoApprovedKey))
        );

        verdict
            .lock()
            .unwrap()
            .attestation
            .replace(Err(HostKeyRefusal::KeyMismatch));
        assert_eq!(
            attested_host_key_type(&verdict),
            Err(TransportRefusal::HostKey(HostKeyRefusal::KeyMismatch))
        );
        assert_eq!(
            host_key_refusal_or(&verdict, TransportRefusal::NoReachableAddress),
            TransportRefusal::HostKey(HostKeyRefusal::KeyMismatch),
            "a handshake that failed on the key must not be reported as a network failure"
        );

        verdict
            .lock()
            .unwrap()
            .attestation
            .replace(Ok(HostKeyType::Ed25519));
        assert_eq!(attested_host_key_type(&verdict), Ok(HostKeyType::Ed25519));
    }

    #[cfg(target_os = "linux")]
    fn runtime() -> Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
    }

    /// The preparation steps must be capped by the lease and not only by their
    /// own ceilings, otherwise a stalled agent adds its full timeout on top of
    /// a bail that had already run out.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_step_that_outlives_the_lease_is_an_expiration_not_a_step_failure() {
        runtime().block_on(async {
            let deadline = Instant::now() + Duration::from_millis(60);
            let started = Instant::now();
            let refusal = await_bounded(
                deadline,
                Duration::from_secs(30),
                PersonalAccessRefusal::Agent(AgentRefusal::ConnectionFailed),
                std::future::pending::<()>(),
            )
            .await
            .expect_err("a lease that ran out cannot yield a result");

            assert_eq!(refusal, PersonalAccessRefusal::Expired);
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "the lease, not the step's own ceiling, must cut the wait"
            );
        });
    }

    /// The two bounds stay distinguishable: a step slower than its own ceiling
    /// while the lease still holds is that step's failure, not an expiration.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_step_that_outlives_only_its_own_ceiling_keeps_its_own_reason() {
        runtime().block_on(async {
            let refusal = await_bounded(
                Instant::now() + Duration::from_secs(30),
                Duration::from_millis(40),
                PersonalAccessRefusal::Agent(AgentRefusal::ProtocolFailed),
                std::future::pending::<()>(),
            )
            .await
            .expect_err("a step past its ceiling cannot yield a result");
            assert_eq!(
                refusal,
                PersonalAccessRefusal::Agent(AgentRefusal::ProtocolFailed)
            );
        });
    }

    /// An exhausted lease refuses before the step is even polled once.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_exhausted_lease_never_starts_a_step() {
        use std::sync::atomic::{AtomicBool, Ordering};

        runtime().block_on(async {
            let polled = AtomicBool::new(false);
            let step = async {
                polled.store(true, Ordering::SeqCst);
            };
            let refusal = await_bounded(
                Instant::now() - Duration::from_secs(1),
                Duration::from_secs(30),
                PersonalAccessRefusal::Agent(AgentRefusal::ConnectionFailed),
                step,
            )
            .await
            .expect_err("an exhausted lease authorises nothing");

            assert_eq!(refusal, PersonalAccessRefusal::Expired);
            assert!(
                !polled.load(Ordering::SeqCst),
                "no step may be started once the lease is gone"
            );
        });
    }

    /// A step that answers inside both bounds is carried through untouched.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_step_within_both_bounds_returns_its_own_answer() {
        runtime().block_on(async {
            let answer = await_bounded(
                Instant::now() + Duration::from_secs(30),
                Duration::from_secs(30),
                PersonalAccessRefusal::Agent(AgentRefusal::ConnectionFailed),
                async { 42_u8 },
            )
            .await;
            assert_eq!(answer, Ok(42));
        });
    }

    /// An exhausted lease never opens a transport at all.
    #[test]
    fn an_elapsed_deadline_refuses_before_any_socket_is_opened() {
        let past = Instant::now() - Duration::from_secs(1);
        let refusal = Prepared::open("192.0.2.10", 22, past)
            .err()
            .expect("an exhausted lease cannot open a session");
        assert_eq!(
            refusal,
            PersonalAccessRefusal::Resolution(ResolutionRefusal::TimedOut)
        );
    }
}
