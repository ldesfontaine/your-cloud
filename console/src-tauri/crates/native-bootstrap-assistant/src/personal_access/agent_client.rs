//! The personal SSH agent, seen through a bounded frame and a spent budget.
//!
//! An agent is a signing oracle that never exports its key. The danger is
//! therefore not theft but volume: how many things get signed, with which
//! identity, and how much this process is willing to read from a socket it
//! does not control. Three constructions answer those three questions.
//!
//! [`BoundedAgentStream`] wraps the socket underneath the agent client and
//! reads the protocol's own framing. It refuses any frame larger than
//! [`MAX_AGENT_FRAME_BYTES`], well below the client library's own ceiling, and
//! it refuses any inbound frame that no outbound request asked for. That second
//! rule is what "the agent refuses a second message" means on the wire: one
//! request, one answer, and an agent that volunteers an extra frame is cut off
//! before that frame is ever parsed.
//!
//! [`PersonalAgent`] lists identities and is then *consumed* by the selection.
//! After [`PersonalAgent::select`] the underlying client no longer exists as a
//! reachable value; the only thing left holding it is a
//! [`BudgetedAgentSigner`], whose sole signing entry point spends a
//! [`SignatureBudget`] first. Passing through the budget is therefore not a
//! discipline the caller must remember — it is the only path that type-checks.
//!
//! One behaviour of the transport library is decisive here and is relied upon
//! rather than hoped for: a public key authentication is sent first as a probe
//! carrying no signature, and the signer is asked for a signature only after
//! the server answers that it would accept that key. A server that refuses the
//! identity therefore costs no signature at all, and one authentication
//! attempt asks the agent for exactly one.

use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use russh::keys::{
    agent::{client::AgentClient, AgentIdentity},
    HashAlg, PublicKey,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::signature_budget::{BudgetRefusal, OfferedIdentity, SignatureBudget};

/// Largest agent frame this process is willing to read.
pub const MAX_AGENT_FRAME_BYTES: usize = 64 * 1024;

/// Largest identity list a native window will ever offer for selection.
///
/// Refused rather than truncated: a cut list would hide from the user exactly
/// the identity they meant to pick.
pub const MAX_OFFERED_IDENTITIES: usize = 16;

const STREAM_OK: u8 = 0;
const STREAM_FRAME_TOO_LARGE: u8 = 1;
const STREAM_UNSOLICITED_MESSAGE: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamRefusal {
    /// A frame announced more bytes than this process will ever read.
    FrameTooLarge,
    /// The agent sent a message no request had asked for.
    UnsolicitedMessage,
}

/// Shared, cheap view of why the bounded stream cut the conversation.
///
/// The stream itself disappears inside the agent client, so the refusal is
/// published through this handle instead of being lost inside an `io::Error`.
#[derive(Clone, Debug)]
pub struct StreamGuard {
    code: Arc<AtomicU8>,
}

impl StreamGuard {
    fn new() -> Self {
        Self {
            code: Arc::new(AtomicU8::new(STREAM_OK)),
        }
    }

    fn record(&self, refusal: StreamRefusal) {
        let code = match refusal {
            StreamRefusal::FrameTooLarge => STREAM_FRAME_TOO_LARGE,
            StreamRefusal::UnsolicitedMessage => STREAM_UNSOLICITED_MESSAGE,
        };
        // The first refusal wins: it is the one that describes what went wrong.
        let _ = self
            .code
            .compare_exchange(STREAM_OK, code, Ordering::SeqCst, Ordering::SeqCst);
    }

    pub fn refusal(&self) -> Option<StreamRefusal> {
        match self.code.load(Ordering::SeqCst) {
            STREAM_FRAME_TOO_LARGE => Some(StreamRefusal::FrameTooLarge),
            STREAM_UNSOLICITED_MESSAGE => Some(StreamRefusal::UnsolicitedMessage),
            _ => None,
        }
    }
}

/// Where one direction of the conversation stands inside the agent framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameCursor {
    Header { seen: usize, length: [u8; 4] },
    Body { remaining: usize },
}

impl FrameCursor {
    const fn start() -> Self {
        Self::Header {
            seen: 0,
            length: [0; 4],
        }
    }
}

/// A frame body of zero bytes is complete as soon as it is announced.
fn next_cursor(announced: usize) -> FrameCursor {
    if announced == 0 {
        FrameCursor::start()
    } else {
        FrameCursor::Body {
            remaining: announced,
        }
    }
}

/// A socket that only lets bounded, solicited agent frames through.
pub struct BoundedAgentStream<S> {
    inner: S,
    inbound: FrameCursor,
    outbound: FrameCursor,
    /// Answers the agent still owes. One completed request adds one; one
    /// completed answer removes one. An answer with nothing owed is a message
    /// nobody asked for.
    owed: usize,
    guard: StreamGuard,
}

impl<S> BoundedAgentStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            inbound: FrameCursor::start(),
            outbound: FrameCursor::start(),
            owed: 0,
            guard: StreamGuard::new(),
        }
    }

    pub fn guard(&self) -> StreamGuard {
        self.guard.clone()
    }

    /// Walks bytes coming from the agent and updates the inbound framing.
    fn observe_inbound(&mut self, mut bytes: &[u8]) -> Result<(), StreamRefusal> {
        while !bytes.is_empty() {
            match self.inbound {
                FrameCursor::Header {
                    ref mut seen,
                    ref mut length,
                } => {
                    let taken = (length.len() - *seen).min(bytes.len());
                    length[*seen..*seen + taken].copy_from_slice(&bytes[..taken]);
                    *seen += taken;
                    bytes = &bytes[taken..];
                    if *seen == length.len() {
                        let announced = u32::from_be_bytes(*length) as usize;
                        if announced > MAX_AGENT_FRAME_BYTES {
                            return Err(StreamRefusal::FrameTooLarge);
                        }
                        // The answer is matched against an outstanding request
                        // before a single byte of its body is accepted.
                        if self.owed == 0 {
                            return Err(StreamRefusal::UnsolicitedMessage);
                        }
                        self.owed -= 1;
                        self.inbound = next_cursor(announced);
                    }
                }
                FrameCursor::Body { ref mut remaining } => {
                    let taken = (*remaining).min(bytes.len());
                    *remaining -= taken;
                    bytes = &bytes[taken..];
                    if *remaining == 0 {
                        self.inbound = FrameCursor::start();
                    }
                }
            }
        }
        Ok(())
    }

    /// Walks bytes going to the agent, so an answer can be matched to a request.
    fn observe_outbound(&mut self, mut bytes: &[u8]) -> Result<(), StreamRefusal> {
        while !bytes.is_empty() {
            match self.outbound {
                FrameCursor::Header {
                    ref mut seen,
                    ref mut length,
                } => {
                    let taken = (length.len() - *seen).min(bytes.len());
                    length[*seen..*seen + taken].copy_from_slice(&bytes[..taken]);
                    *seen += taken;
                    bytes = &bytes[taken..];
                    if *seen == length.len() {
                        let announced = u32::from_be_bytes(*length) as usize;
                        if announced > MAX_AGENT_FRAME_BYTES {
                            return Err(StreamRefusal::FrameTooLarge);
                        }
                        self.outbound = next_cursor(announced);
                        if announced == 0 {
                            self.owed = self.owed.saturating_add(1);
                        }
                    }
                }
                FrameCursor::Body { ref mut remaining } => {
                    let taken = (*remaining).min(bytes.len());
                    *remaining -= taken;
                    bytes = &bytes[taken..];
                    if *remaining == 0 {
                        self.outbound = FrameCursor::start();
                        self.owed = self.owed.saturating_add(1);
                    }
                }
            }
        }
        Ok(())
    }

    fn fail(&mut self, refusal: StreamRefusal) -> io::Error {
        self.guard.record(refusal);
        // The reason travels through the guard; the transport only needs to
        // learn that the conversation is over.
        io::Error::new(io::ErrorKind::InvalidData, "agent frame refused")
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for BoundedAgentStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(refusal) = this.guard.refusal() {
            return Poll::Ready(Err(this.fail(refusal)));
        }
        let before = buffer.filled().len();
        match Pin::new(&mut this.inner).poll_read(context, buffer) {
            Poll::Ready(Ok(())) => {
                let observed = buffer.filled()[before..].to_vec();
                match this.observe_inbound(&observed) {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(refusal) => Poll::Ready(Err(this.fail(refusal))),
                }
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for BoundedAgentStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(context, data) {
            Poll::Ready(Ok(written)) => {
                // Only the bytes the socket accepted are counted, so a partial
                // write never credits a request that was not fully sent.
                match this.observe_outbound(&data[..written]) {
                    Ok(()) => Poll::Ready(Ok(written)),
                    Err(refusal) => Poll::Ready(Err(this.fail(refusal))),
                }
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentRefusal {
    /// The endpoint could not be reached at all.
    ConnectionFailed,
    /// The agent conversation failed, or a bound cut it.
    ProtocolFailed,
    Stream(StreamRefusal),
    /// The agent holds no identity at all.
    NoIdentity,
    TooManyIdentities,
    /// The selected fingerprint is not among the offered identities.
    UnknownSelection,
}

/// Turns an identity the agent holds into the value the budget decides on.
///
/// The fingerprint is the SHA-256 fingerprint of the public key, exactly as
/// OpenSSH renders it, which is also what the user reads in the native window.
pub fn offered_identity(identity: &AgentIdentity) -> OfferedIdentity {
    match identity {
        AgentIdentity::PublicKey { key, .. } => OfferedIdentity {
            algorithm: key.algorithm(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            is_certificate: false,
        },
        AgentIdentity::Certificate { certificate, .. } => OfferedIdentity {
            algorithm: certificate.algorithm(),
            // A certificate is refused by the budget, but it is still named by
            // the key it certifies rather than by nothing at all.
            fingerprint: certificate
                .public_key()
                .fingerprint(HashAlg::Sha256)
                .to_string(),
            is_certificate: true,
        },
    }
}

/// The personal agent, before an identity has been selected.
pub struct PersonalAgent<S: AsyncRead + AsyncWrite + Unpin + Send> {
    client: AgentClient<BoundedAgentStream<S>>,
    guard: StreamGuard,
    identities: Vec<AgentIdentity>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> PersonalAgent<S> {
    /// Wraps an already connected endpoint in the bounded framing.
    pub fn over(stream: S) -> Self {
        let stream = BoundedAgentStream::new(stream);
        let guard = stream.guard();
        Self {
            client: AgentClient::connect(stream),
            guard,
            identities: Vec::new(),
        }
    }

    /// Asks the agent once for what it holds.
    pub async fn list_identities(&mut self) -> Result<Vec<OfferedIdentity>, AgentRefusal> {
        let identities = self
            .client
            .request_identities()
            .await
            .map_err(|_| self.protocol_refusal())?;
        if identities.is_empty() {
            return Err(AgentRefusal::NoIdentity);
        }
        if identities.len() > MAX_OFFERED_IDENTITIES {
            return Err(AgentRefusal::TooManyIdentities);
        }
        let offered = identities.iter().map(offered_identity).collect();
        self.identities = identities;
        Ok(offered)
    }

    /// Binds the agent to the one identity the user selected.
    ///
    /// This consumes the agent: afterwards no value in the program can reach
    /// the client except through the returned signer, and that signer spends
    /// the budget before it signs.
    pub fn select(self, fingerprint: &str) -> Result<BudgetedAgentSigner<S>, AgentRefusal> {
        let selected = self
            .identities
            .into_iter()
            .find(|identity| offered_identity(identity).fingerprint == fingerprint)
            .ok_or(AgentRefusal::UnknownSelection)?;
        let public_key = selected.public_key().into_owned();
        Ok(BudgetedAgentSigner {
            client: self.client,
            guard: self.guard,
            budget: SignatureBudget::for_selected_identity(fingerprint),
            selected,
            public_key,
        })
    }

    fn protocol_refusal(&self) -> AgentRefusal {
        match self.guard.refusal() {
            Some(refusal) => AgentRefusal::Stream(refusal),
            None => AgentRefusal::ProtocolFailed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningRefusal {
    /// The transport could not carry the request.
    Transport,
    Budget(BudgetRefusal),
    Stream(StreamRefusal),
    /// The agent refused to sign, or answered something else.
    AgentFailure,
}

impl From<russh::SendError> for SigningRefusal {
    fn from(_: russh::SendError) -> Self {
        Self::Transport
    }
}

/// The only way this process can obtain a signature from the personal agent.
pub struct BudgetedAgentSigner<S: AsyncRead + AsyncWrite + Unpin + Send> {
    client: AgentClient<BoundedAgentStream<S>>,
    guard: StreamGuard,
    budget: SignatureBudget,
    selected: AgentIdentity,
    public_key: PublicKey,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> BudgetedAgentSigner<S> {
    /// The public key the transport must authenticate with.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The identity the user selected, as the agent named it.
    pub fn selected(&self) -> &AgentIdentity {
        &self.selected
    }

    pub fn remaining_signatures(&self) -> usize {
        self.budget.remaining()
    }

    pub fn stream_refusal(&self) -> Option<StreamRefusal> {
        self.guard.refusal()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> russh::Signer for BudgetedAgentSigner<S> {
    type Error = SigningRefusal;

    fn auth_sign(
        &mut self,
        key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        async move {
            // The identity the transport hands back is judged, never trusted:
            // a substituted key is refused here and costs no signature.
            let offered = offered_identity(key);
            self.budget
                .authorise(&offered, hash_alg)
                .map_err(SigningRefusal::Budget)?;
            match self.client.sign_request(key, hash_alg, to_sign).await {
                Ok(signed) => Ok(signed),
                Err(_) => Err(match self.guard.refusal() {
                    Some(refusal) => SigningRefusal::Stream(refusal),
                    None => SigningRefusal::AgentFailure,
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
    }

    fn frame(body_length: usize) -> Vec<u8> {
        let mut bytes = u32::try_from(body_length).unwrap().to_be_bytes().to_vec();
        bytes.resize(4 + body_length, 0);
        bytes
    }

    /// One request, one answer: the ordinary conversation must go through.
    #[test]
    fn a_solicited_bounded_answer_is_carried_unchanged() {
        runtime().block_on(async {
            let (ours, mut theirs) = tokio::io::duplex(4096);
            let mut stream = BoundedAgentStream::new(ours);
            let guard = stream.guard();

            stream.write_all(&frame(8)).await.expect("request");
            let mut request = vec![0_u8; 12];
            theirs.read_exact(&mut request).await.expect("agent read");
            theirs.write_all(&frame(16)).await.expect("answer");

            let mut answer = vec![0_u8; 20];
            stream.read_exact(&mut answer).await.expect("answer read");
            assert_eq!(answer, frame(16));
            assert_eq!(guard.refusal(), None);
        });
    }

    /// The bound the expected proofs call for: a frame above 64 KiB never gets
    /// its body read, whatever the client library would otherwise accept.
    #[test]
    fn an_oversized_frame_is_cut_before_its_body_is_read() {
        runtime().block_on(async {
            let (ours, mut theirs) = tokio::io::duplex(4096);
            let mut stream = BoundedAgentStream::new(ours);
            let guard = stream.guard();

            stream.write_all(&frame(8)).await.expect("request");
            let mut request = vec![0_u8; 12];
            theirs.read_exact(&mut request).await.expect("agent read");

            let announced = u32::try_from(MAX_AGENT_FRAME_BYTES + 1).unwrap();
            theirs
                .write_all(&announced.to_be_bytes())
                .await
                .expect("oversized header");

            let mut answer = [0_u8; 4];
            assert!(
                stream.read_exact(&mut answer).await.is_err(),
                "an oversized frame must not be read"
            );
            assert_eq!(guard.refusal(), Some(StreamRefusal::FrameTooLarge));
        });
    }

    /// "Refuses a second message": one request may be answered once, and an
    /// agent that keeps talking is cut off.
    #[test]
    fn a_second_unsolicited_message_is_refused() {
        runtime().block_on(async {
            let (ours, mut theirs) = tokio::io::duplex(4096);
            let mut stream = BoundedAgentStream::new(ours);
            let guard = stream.guard();

            stream.write_all(&frame(8)).await.expect("request");
            let mut request = vec![0_u8; 12];
            theirs.read_exact(&mut request).await.expect("agent read");

            theirs.write_all(&frame(4)).await.expect("first answer");
            let mut first = vec![0_u8; 8];
            stream.read_exact(&mut first).await.expect("first answer");
            assert_eq!(guard.refusal(), None);

            theirs.write_all(&frame(4)).await.expect("second answer");
            let mut second = vec![0_u8; 8];
            assert!(
                stream.read_exact(&mut second).await.is_err(),
                "nothing asked for this frame"
            );
            assert_eq!(guard.refusal(), Some(StreamRefusal::UnsolicitedMessage));
        });
    }

    /// An agent that speaks before being spoken to is refused just the same.
    #[test]
    fn an_answer_that_precedes_every_request_is_refused() {
        runtime().block_on(async {
            let (ours, mut theirs) = tokio::io::duplex(4096);
            let mut stream = BoundedAgentStream::new(ours);
            let guard = stream.guard();

            theirs.write_all(&frame(4)).await.expect("unsolicited");
            let mut answer = vec![0_u8; 8];
            assert!(stream.read_exact(&mut answer).await.is_err());
            assert_eq!(guard.refusal(), Some(StreamRefusal::UnsolicitedMessage));
        });
    }

    /// The framing must survive being delivered one byte at a time, which is
    /// exactly how a hostile peer would try to slip past a naive parser.
    #[test]
    fn the_framing_holds_when_bytes_arrive_one_at_a_time() {
        runtime().block_on(async {
            let (ours, mut theirs) = tokio::io::duplex(4096);
            let mut stream = BoundedAgentStream::new(ours);
            let guard = stream.guard();

            stream.write_all(&frame(3)).await.expect("request");
            let mut request = vec![0_u8; 7];
            theirs.read_exact(&mut request).await.expect("agent read");

            let answer = frame(5);
            for byte in &answer {
                theirs.write_all(&[*byte]).await.expect("dribbled byte");
            }
            let mut received = vec![0_u8; answer.len()];
            stream.read_exact(&mut received).await.expect("answer");
            assert_eq!(received, answer);
            assert_eq!(guard.refusal(), None);

            // A dribbled header for a frame nobody asked for is refused as
            // soon as its four announcing bytes are complete.
            theirs.write_all(&frame(1)).await.expect("extra frame");
            let mut extra = vec![0_u8; 5];
            assert!(stream.read_exact(&mut extra).await.is_err());
            assert_eq!(guard.refusal(), Some(StreamRefusal::UnsolicitedMessage));
        });
    }

    /// A request written in several pieces still credits exactly one answer.
    #[test]
    fn a_request_written_in_pieces_credits_exactly_one_answer() {
        runtime().block_on(async {
            let (ours, mut theirs) = tokio::io::duplex(4096);
            let mut stream = BoundedAgentStream::new(ours);
            let guard = stream.guard();

            let request = frame(6);
            for byte in &request {
                stream.write_all(&[*byte]).await.expect("dribbled request");
            }
            let mut received = vec![0_u8; request.len()];
            theirs.read_exact(&mut received).await.expect("agent read");

            theirs.write_all(&frame(2)).await.expect("answer");
            let mut answer = vec![0_u8; 6];
            stream.read_exact(&mut answer).await.expect("answer");
            assert_eq!(guard.refusal(), None);

            theirs.write_all(&frame(2)).await.expect("extra answer");
            let mut extra = vec![0_u8; 6];
            assert!(stream.read_exact(&mut extra).await.is_err());
            assert_eq!(guard.refusal(), Some(StreamRefusal::UnsolicitedMessage));
        });
    }

    #[test]
    fn the_frame_bound_is_the_decided_one() {
        assert_eq!(MAX_AGENT_FRAME_BYTES, 64 * 1024);
    }
}
