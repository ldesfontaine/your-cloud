//! The six plans of the private passage, on the side that displays them.
//!
//! Schema 3 keeps every procedure of the two schemas before it — one bounded
//! strict JSON document, one domain-separated binary transcript, a rollback that
//! is a complete inverse document, a pair frozen by the Controller, a signature
//! by the Console, a re-verification by the Auxiliary — and adds six operations
//! in three inverse pairs, each with its own closed field list. Neither older
//! schema is reopened by any of it: a probe plan and a public profile plan
//! decode, hash and verify exactly as before, and a document of any one schema
//! is refused by the decoders of the other two.
//!
//! **The operation is the discriminator.** It is read first, by a pass that
//! reads nothing else, and the document is then held against exactly the closed
//! field list that operation declares. A link document carrying a peer key is
//! therefore an unknown field of the link schema, refused before its value is
//! read, rather than retried as a junction that happens to be missing a port.
//! Nothing is decided by that first pass: it selects a schema, and the strict
//! decoding that follows is the whole of the authority.
//!
//! **Nothing here signs, and nothing here encodes.** As for the two older
//! schemas, the Controller freezes the canonical bytes and transports them; this
//! side receives those exact bytes beside the digests they are claimed to have,
//! rebuilds the digest from the fields it parsed, and refuses the pair when the
//! two disagree.
//!
//! **No private key can be here.** A private key of the passage is generated on
//! its own machine and never leaves it, so no document of this schema carries
//! one and nothing in this module could read one. The one key that travels is
//! the public half the other machine's preparation reported, and it travels as
//! the exact canonical spelling of thirty-two bytes.
//!
//! The transcript is laid out per operation group. The fields a group does not
//! have are simply not present rather than written empty, and the operation
//! string inside the transcript is what tells the groups apart:
//!
//! ```text
//! domain  "your-cloud/oci-plan.v3\0"
//! then    schema_version                       on one byte
//!         infrastructure_id, machine_id, operation
//!                                     as uint32 big-endian length-prefixed fields
//! then, per operation:
//!   prepare_link / withdraw_link
//!         link_role                            as a prefixed field
//!   attach_link_peer / detach_link_peer
//!         peer_public_key (32 decoded bytes)   as a prefixed field
//!         service_port                         as a uint32 big-endian
//!   join_link_peer / leave_link_peer
//!         peer_public_key (32 decoded bytes)   as a prefixed field
//!         peer_endpoint_host                   as a prefixed field
//!         service_port                         as a uint32 big-endian
//! ```
//!
//! The public key travels decoded, exactly as an image digest does in the two
//! older schemas: the textual field is one spelling of thirty-two bytes, and the
//! bytes are what the digest is taken over. That is also why the canonicity of
//! that field is required before the transcript is built — a key with a second
//! accepted spelling would be a key with two digests.
//!
//! The layout is unambiguous across the three groups without a group tag,
//! because everything before the operation is at a determined offset: the domain
//! and the version are fixed, and each of the two fields that follow announces
//! its own length. A reader that has consumed the operation therefore knows
//! which of the three tails it is looking at, so no two documents of different
//! groups can produce the same bytes.
//!
//! **The transcript is the counterpart of the one written on the Auxiliary
//! side.** The two are held against one another by deterministic vectors on both
//! sides rather than by reading. The six vectors below are the very ones pinned
//! in `internal/plan/schema3_test.go`.

use crate::{
    approval::{append_field, canonical_machine_id, canonical_uuid_v4, decode_digest},
    plan::{
        encode_lower_hex, MAX_PLAN_DOCUMENT_BYTES, MAX_PLAN_LOCAL_PORT, MIN_PLAN_LOCAL_PORT,
        PLAN_DIGEST_BYTES,
    },
    plan_v2::{MAX_ROUTE_HOST_BYTES, MIN_ROUTE_HOST_BYTES},
    ProtocolError,
};
use base64::{
    alphabet,
    engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig},
    Engine as _,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The third plan version, and the only one that describes the private passage
/// between two enrolled machines.
pub const PLAN_V3_SCHEMA_VERSION: u8 = 3;

/// Domain separator of this transcript, terminated by a byte no textual field
/// may contain. It differs from the two older separators by one byte on purpose:
/// the version is not a hint, it selects which closed contract a document is
/// held against, so a schema 3 digest can never be read as a digest of either
/// older schema.
pub const PLAN_V3_TRANSCRIPT_DOMAIN: &[u8] = b"your-cloud/oci-plan.v3\0";

/// What a peer public key decodes to, and the one length its canonical standard
/// base64 spelling has. Both are required, so a value that decodes to the right
/// bytes through another spelling is refused rather than accepted twice.
pub const PEER_PUBLIC_KEY_BYTES: usize = 32;
pub const PEER_PUBLIC_KEY_ENCODED_BYTES: usize = 44;

/// Bounds of the one port a passage may carry. They repeat the loopback range of
/// the two older schemas, because the port a passage carries may only be a port
/// a managed service of the joined machine could be listening on.
pub const MIN_PLAN_SERVICE_PORT: u32 = MIN_PLAN_LOCAL_PORT;
pub const MAX_PLAN_SERVICE_PORT: u32 = MAX_PLAN_LOCAL_PORT;

/// The interface the passage lives on, bounded to fifteen bytes as interface
/// names are. It is a constant of the reference scenario and a field of no
/// document: no approvable value chooses where the passage is held.
pub const LINK_INTERFACE_NAME: &str = "yc-link0";

/// The two tunnel addresses of the reference scenario. Each side holds exactly
/// one of them, announced as that address and its `/32` and nothing else: the
/// subnet of the LAN is never announced, never routed, and the listener knows of
/// the LAN one tunnel address.
pub const LINK_LISTENER_TUNNEL_ADDRESS: &str = "10.66.66.1";
pub const LINK_INITIATOR_TUNNEL_ADDRESS: &str = "10.66.66.2";

/// The UDP port the listener listens on, and the seconds of keepalive the
/// initiator sends to hold the tunnel open through its NAT. Each belongs to
/// exactly one role, the role decides it, and no field of any plan reopens it.
pub const LINK_LISTEN_PORT: u32 = 51_820;
pub const LINK_KEEPALIVE_SECONDS: u32 = 25;

/// The one rules table a junction poses, and removes with itself. It is a
/// declared effect of the junction plans, applied with them and removed with
/// them, and it is written in what the human approves rather than done in
/// silence.
pub const LINK_NFTABLES_TABLE: &str = "inet your-cloud-link";

/// The standard base64 alphabet, read leniently and written strictly.
///
/// The decoding deliberately accepts the trailing bits a thirty-two byte key has
/// no room for, and [`decode_peer_public_key`] then refuses every value the
/// re-encoding does not reproduce. Holding the two apart is what makes the
/// re-encoding the refusal rather than a precaution that a stricter decoder
/// happens to cover: a spelling that decodes to the right bytes and is not the
/// spelling of them is refused here, visibly, and would be refused the same way
/// under any engine.
const PEER_PUBLIC_KEY_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
);

/// Which of the three closed field lists an operation carries.
///
/// It is the whole of the discriminator: an operation names exactly one group,
/// and a document decoded into one shape is refused when its operation belongs
/// to another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanV3Group {
    Link,
    ListenerPeer,
    InitiatorPeer,
}

/// The closed list of states this palier can describe.
///
/// Every member has an inverse that is itself a member and carries the same
/// closed field list, which is what makes an operation without an undoing
/// impossible to add here by accident: a rollback is a plan in its own right,
/// read, displayed, approved and verified like any other.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanV3Operation {
    /// This machine holds the closed interface of the passage in one role — its
    /// keys generated on it and never leaving it — and its inverse asks for that
    /// interface and those keys to be gone. Neither carries a peer: preparing is
    /// what a machine does alone.
    PrepareLink,
    WithdrawLink,
    /// The listener holds exactly one peer and the bounds that peer's traffic is
    /// allowed inside, and its inverse asks for that peer and those bounds to be
    /// gone. The listener has no endpoint to reach, so the field does not exist
    /// here rather than travelling empty.
    AttachLinkPeer,
    DetachLinkPeer,
    /// The initiator reaches exactly one endpoint and holds the same bounds from
    /// its own side, and its inverse asks for the junction to be gone. The
    /// endpoint host is a field because only the initiator has one; the endpoint
    /// port is not, because it is the listening port of the contract.
    JoinLinkPeer,
    LeaveLinkPeer,
}

impl PlanV3Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrepareLink => "prepare_link",
            Self::WithdrawLink => "withdraw_link",
            Self::AttachLinkPeer => "attach_link_peer",
            Self::DetachLinkPeer => "detach_link_peer",
            Self::JoinLinkPeer => "join_link_peer",
            Self::LeaveLinkPeer => "leave_link_peer",
        }
    }

    /// The operation that undoes this one.
    pub fn inverse(self) -> Self {
        match self {
            Self::PrepareLink => Self::WithdrawLink,
            Self::WithdrawLink => Self::PrepareLink,
            Self::AttachLinkPeer => Self::DetachLinkPeer,
            Self::DetachLinkPeer => Self::AttachLinkPeer,
            Self::JoinLinkPeer => Self::LeaveLinkPeer,
            Self::LeaveLinkPeer => Self::JoinLinkPeer,
        }
    }

    /// The closed field list this operation carries.
    pub fn group(self) -> PlanV3Group {
        match self {
            Self::PrepareLink | Self::WithdrawLink => PlanV3Group::Link,
            Self::AttachLinkPeer | Self::DetachLinkPeer => PlanV3Group::ListenerPeer,
            Self::JoinLinkPeer | Self::LeaveLinkPeer => PlanV3Group::InitiatorPeer,
        }
    }
}

/// The side of the passage a machine holds.
///
/// The list is closed to two entries, and it is closed by being an enumeration
/// rather than by a validated string: a role outside it has no variant, so it is
/// refused while the document is still being parsed. The role decides every
/// constant of the scenario, and no field of any plan reopens one of them.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkRole {
    /// The side that listens on the port of the contract.
    Listener,
    /// The side that goes out and keeps the tunnel alive through its NAT.
    Initiator,
}

impl LinkRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Listener => "listener",
            Self::Initiator => "initiator",
        }
    }

    /// The tunnel address this role holds, announced as that address and its
    /// `/32`. It is read here rather than in whatever displays it, so that the
    /// two sides can never be named by two tables.
    pub fn tunnel_address(self) -> &'static str {
        match self {
            Self::Listener => LINK_LISTENER_TUNNEL_ADDRESS,
            Self::Initiator => LINK_INITIATOR_TUNNEL_ADDRESS,
        }
    }
}

/// The plan of one machine's own side of the passage: the closed interface and
/// the keys that never leave it, in exactly one role.
///
/// It names no peer. Preparing is what a machine does alone, and a field for the
/// other machine here would be an approvable value that decides nothing until a
/// junction plan names it.
///
/// The declaration order below is the canonical encoding order and the
/// transcript order at once, and no field of a link plan lives outside it. There
/// is deliberately no interface name, no address, no subnet, no listening port
/// and no keepalive: each of them is a constant the role decides, and a document
/// carrying one is an unknown field the decoding refuses before reading its
/// value.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinkPlanDocumentV3 {
    pub schema_version: u8,
    /// The infrastructure this plan belongs to, as a canonical UUIDv4.
    pub infrastructure_id: String,
    /// The one machine this plan describes a state of.
    pub machine_id: String,
    pub operation: PlanV3Operation,
    /// The closed role that decides everything this document does not state.
    pub link_role: LinkRole,
}

/// The plan of the listener's junction: exactly one peer, named by the public
/// key that peer's own preparation reported, and the one port the passage will
/// carry.
///
/// It carries no endpoint. The listener does not go out, so an endpoint field
/// here would be a value nothing reads — and a field of the other group is an
/// unknown field, refused before its value is read.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerPeerPlanDocumentV3 {
    pub schema_version: u8,
    pub infrastructure_id: String,
    pub machine_id: String,
    pub operation: PlanV3Operation,
    /// Canonical standard base64 of forty-four characters decoding to exactly
    /// thirty-two bytes.
    pub peer_public_key: String,
    /// The one port the rules will let through the passage.
    pub service_port: u32,
}

/// The plan of the initiator's junction: the same peer key and the same port,
/// plus the one host it reaches to establish the tunnel.
///
/// The endpoint port is deliberately absent: it is the listening port of the
/// contract, a constant the role decides, and a field for it would be an
/// approvable value that may only hold one value.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InitiatorPeerPlanDocumentV3 {
    pub schema_version: u8,
    pub infrastructure_id: String,
    pub machine_id: String,
    pub operation: PlanV3Operation,
    pub peer_public_key: String,
    /// The host the initiator reaches, under the very bound `route_host` already
    /// had. An IPv4 literal is written naturally here.
    pub peer_endpoint_host: String,
    pub service_port: u32,
}

/// One plan of schema 3, whatever its operation group.
///
/// The list is closed to the three shapes above: a fourth field list is a
/// decision taken here — beside the transcript it would need and beside the
/// inverse it must have — rather than a shape a caller could hand in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanDocumentV3 {
    Link(LinkPlanDocumentV3),
    ListenerPeer(ListenerPeerPlanDocumentV3),
    InitiatorPeer(InitiatorPeerPlanDocumentV3),
}

impl LinkPlanDocumentV3 {
    /// Holds a link plan against the whole contract of the palier.
    ///
    /// The role needs no check of its own: it is an enumeration of exactly the
    /// two entries the contract names, so a third role never becomes a value.
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if !valid_v3_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
            PlanV3Group::Link,
        ) {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(self)
    }

    /// The exact bytes a link plan digest is taken over.
    pub fn transcript(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut transcript = v3_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
        )?;
        append_field(&mut transcript, self.link_role.as_str().as_bytes())?;
        Ok(transcript)
    }

    /// The document that undoes this one, which differs from it by its operation
    /// and by nothing else.
    fn inverted(&self) -> Self {
        Self {
            operation: self.operation.inverse(),
            ..self.clone()
        }
    }

    /// Whether `rollback` is the complete document that undoes this plan.
    ///
    /// The two documents are compared whole, so a rollback naming another
    /// machine or another role is a second plan rather than an undoing, and is
    /// refused as one. Comparing the whole document rather than a list of fields
    /// is what keeps a field added later from silently falling outside the
    /// comparison.
    pub fn is_undone_by(&self, rollback: &Self) -> bool {
        self.inverted() == *rollback
    }
}

impl ListenerPeerPlanDocumentV3 {
    /// Holds a listener junction plan against the whole contract of the palier,
    /// the canonicity of the peer key included.
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if !valid_v3_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
            PlanV3Group::ListenerPeer,
        ) || decode_peer_public_key(&self.peer_public_key).is_none()
            || !(MIN_PLAN_SERVICE_PORT..=MAX_PLAN_SERVICE_PORT).contains(&self.service_port)
        {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(self)
    }

    /// The exact bytes a listener junction digest is taken over.
    pub fn transcript(&self) -> Result<Vec<u8>, ProtocolError> {
        let key =
            decode_peer_public_key(&self.peer_public_key).ok_or(ProtocolError::InvalidInput)?;
        let mut transcript = v3_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
        )?;
        append_field(&mut transcript, &key)?;
        transcript.extend_from_slice(&self.service_port.to_be_bytes());
        Ok(transcript)
    }

    fn inverted(&self) -> Self {
        Self {
            operation: self.operation.inverse(),
            ..self.clone()
        }
    }

    /// Whether `rollback` is the complete document that undoes this plan.
    pub fn is_undone_by(&self, rollback: &Self) -> bool {
        self.inverted() == *rollback
    }
}

impl InitiatorPeerPlanDocumentV3 {
    /// Holds an initiator junction plan against the whole contract of the
    /// palier.
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if !valid_v3_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
            PlanV3Group::InitiatorPeer,
        ) || decode_peer_public_key(&self.peer_public_key).is_none()
            || !canonical_peer_endpoint_host(&self.peer_endpoint_host)
            || !(MIN_PLAN_SERVICE_PORT..=MAX_PLAN_SERVICE_PORT).contains(&self.service_port)
        {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(self)
    }

    /// The exact bytes an initiator junction digest is taken over.
    pub fn transcript(&self) -> Result<Vec<u8>, ProtocolError> {
        let key =
            decode_peer_public_key(&self.peer_public_key).ok_or(ProtocolError::InvalidInput)?;
        let mut transcript = v3_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
        )?;
        append_field(&mut transcript, &key)?;
        append_field(&mut transcript, self.peer_endpoint_host.as_bytes())?;
        transcript.extend_from_slice(&self.service_port.to_be_bytes());
        Ok(transcript)
    }

    fn inverted(&self) -> Self {
        Self {
            operation: self.operation.inverse(),
            ..self.clone()
        }
    }

    /// Whether `rollback` is the complete document that undoes this plan.
    pub fn is_undone_by(&self, rollback: &Self) -> bool {
        self.inverted() == *rollback
    }
}

impl PlanDocumentV3 {
    /// Holds the document against the whole contract of the palier, closed role
    /// and canonical peer key included.
    pub fn validate(self) -> Result<Self, ProtocolError> {
        Ok(match self {
            Self::Link(document) => Self::Link(document.validate()?),
            Self::ListenerPeer(document) => Self::ListenerPeer(document.validate()?),
            Self::InitiatorPeer(document) => Self::InitiatorPeer(document.validate()?),
        })
    }

    /// The exact bytes this plan's digest is taken over.
    ///
    /// It is built from the parsed fields and never from a received document, so
    /// two implementations that read the same plan produce the same digest, a
    /// transport that reshapes the JSON transports the same plan, and a
    /// transport that changes one value transports a plan whose digest no longer
    /// matches the approval that named it.
    pub fn transcript(&self) -> Result<Vec<u8>, ProtocolError> {
        match self {
            Self::Link(document) => document.transcript(),
            Self::ListenerPeer(document) => document.transcript(),
            Self::InitiatorPeer(document) => document.transcript(),
        }
    }

    /// The raw digest of that transcript.
    pub fn digest(&self) -> Result<[u8; PLAN_DIGEST_BYTES], ProtocolError> {
        let mut digest = [0_u8; PLAN_DIGEST_BYTES];
        digest.copy_from_slice(Sha256::digest(self.transcript()?).as_slice());
        Ok(digest)
    }

    /// The lower-case hexadecimal value an envelope names as `plan_sha256` or
    /// `rollback_sha256`, in the exact spelling that envelope requires.
    pub fn sha256(&self) -> Result<String, ProtocolError> {
        Ok(encode_lower_hex(&self.digest()?))
    }

    pub fn operation(&self) -> PlanV3Operation {
        match self {
            Self::Link(document) => document.operation,
            Self::ListenerPeer(document) => document.operation,
            Self::InitiatorPeer(document) => document.operation,
        }
    }

    pub fn group(&self) -> PlanV3Group {
        self.operation().group()
    }

    pub fn infrastructure_id(&self) -> &str {
        match self {
            Self::Link(document) => &document.infrastructure_id,
            Self::ListenerPeer(document) => &document.infrastructure_id,
            Self::InitiatorPeer(document) => &document.infrastructure_id,
        }
    }

    pub fn machine_id(&self) -> &str {
        match self {
            Self::Link(document) => &document.machine_id,
            Self::ListenerPeer(document) => &document.machine_id,
            Self::InitiatorPeer(document) => &document.machine_id,
        }
    }

    /// Whether `rollback` is the complete document that undoes this plan.
    ///
    /// A document of another operation group is never an undoing, whatever it
    /// names: the junction of one side is not the junction of the other written
    /// differently.
    pub fn is_undone_by(&self, rollback: &Self) -> bool {
        match (self, rollback) {
            (Self::Link(plan), Self::Link(inverse)) => plan.is_undone_by(inverse),
            (Self::ListenerPeer(plan), Self::ListenerPeer(inverse)) => plan.is_undone_by(inverse),
            (Self::InitiatorPeer(plan), Self::InitiatorPeer(inverse)) => plan.is_undone_by(inverse),
            _ => false,
        }
    }
}

/// Accepts one bounded, strict, fully validated schema 3 document.
///
/// It never returns a partially checked plan: a caller that holds one may assume
/// every field is inside the bounds of the contract, and that the fields it
/// holds are exactly the ones its operation declares — no more, none borrowed
/// from another operation, and none borrowed from another schema.
///
/// The bound is applied before parsing, exactly one JSON value is accepted, a
/// repeated key is a refusal, an undeclared field is a refusal, and every field
/// must appear under its exact canonical name.
pub fn decode_plan_v3_document(document: &[u8]) -> Result<PlanDocumentV3, ProtocolError> {
    if document.is_empty() || document.len() > MAX_PLAN_DOCUMENT_BYTES {
        return Err(ProtocolError::InvalidInput);
    }
    let parsed = match declared_operation(document)?.group() {
        PlanV3Group::Link => PlanDocumentV3::Link(
            serde_json::from_slice(document).map_err(|_| ProtocolError::InvalidInput)?,
        ),
        PlanV3Group::ListenerPeer => PlanDocumentV3::ListenerPeer(
            serde_json::from_slice(document).map_err(|_| ProtocolError::InvalidInput)?,
        ),
        PlanV3Group::InitiatorPeer => PlanDocumentV3::InitiatorPeer(
            serde_json::from_slice(document).map_err(|_| ProtocolError::InvalidInput)?,
        ),
    };
    parsed.validate()
}

/// Accepts one received document only if it is the plan its digest names.
///
/// This is the whole reason the documents travel as their exact canonical bytes
/// beside their digests: the digest is rebuilt here from the fields that were
/// parsed out of those very bytes, so the Controller can reindent what it
/// carries and can change nothing in it. A mismatch is refused before the
/// document reaches anything that would display it, because a plan nobody can
/// hold to a digest is a plan nobody can be shown.
pub fn verify_plan_v3_document(
    document: &[u8],
    expected_sha256: &str,
) -> Result<PlanDocumentV3, ProtocolError> {
    let expected = decode_digest(expected_sha256).ok_or(ProtocolError::InvalidInput)?;
    let parsed = decode_plan_v3_document(document)?;
    if parsed.digest()? != expected {
        return Err(ProtocolError::InvalidInput);
    }
    Ok(parsed)
}

/// The one field the first pass reads.
///
/// It deliberately does not deny unknown fields: this pass selects a schema and
/// decides nothing, and the strict decoding that follows is what refuses every
/// field the selected schema does not declare. A repeated `operation` is still a
/// refusal here, because two declarations of the shape a document claims are two
/// documents rather than one.
#[derive(Deserialize)]
struct DeclaredOperation {
    operation: PlanV3Operation,
}

/// Reads only the operation, and decides which closed schema the document will
/// be held against from it alone.
///
/// It is the same principle as the discriminator of the two older schemas: the
/// shape is read in the document rather than guessed by trying each schema in
/// turn. That is what keeps the three field lists from covering for one another.
fn declared_operation(document: &[u8]) -> Result<PlanV3Operation, ProtocolError> {
    let declared: DeclaredOperation =
        serde_json::from_slice(document).map_err(|_| ProtocolError::InvalidInput)?;
    Ok(declared.operation)
}

/// The four fields every schema 3 document carries.
///
/// The last check is what makes the discriminator binding in both directions: a
/// document whose operation belongs to another group — or to another schema — is
/// refused even when a caller built the value in Rust rather than decoding it.
fn valid_v3_head(
    schema_version: u8,
    infrastructure_id: &str,
    machine_id: &str,
    operation: PlanV3Operation,
    group: PlanV3Group,
) -> bool {
    schema_version == PLAN_V3_SCHEMA_VERSION
        && canonical_uuid_v4(infrastructure_id)
        && canonical_machine_id(machine_id)
        && operation.group() == group
}

/// The head of every schema 3 transcript, in the layout documented at the top of
/// this file.
fn v3_head(
    schema_version: u8,
    infrastructure_id: &str,
    machine_id: &str,
    operation: PlanV3Operation,
) -> Result<Vec<u8>, ProtocolError> {
    let mut transcript = Vec::with_capacity(PLAN_V3_TRANSCRIPT_DOMAIN.len() + 192);
    transcript.extend_from_slice(PLAN_V3_TRANSCRIPT_DOMAIN);
    transcript.extend_from_slice(&schema_version.to_be_bytes());
    append_field(&mut transcript, infrastructure_id.as_bytes())?;
    append_field(&mut transcript, machine_id.as_bytes())?;
    append_field(&mut transcript, operation.as_str().as_bytes())?;
    Ok(transcript)
}

/// Turns the textual field into the thirty-two bytes the transcript carries, and
/// refuses every other spelling of the same key.
///
/// The three requirements are held together on purpose. The length removes the
/// shorter and longer strings a decoder might otherwise accept; the decoding
/// removes the alphabets and the paddings that are not this one; and the
/// re-encoding removes what remains — the trailing bits a peer key has no room
/// for, which decode without complaint under the lenient engine above and would
/// give the same key a second spelling and therefore a second digest.
fn decode_peer_public_key(value: &str) -> Option<[u8; PEER_PUBLIC_KEY_BYTES]> {
    if value.len() != PEER_PUBLIC_KEY_ENCODED_BYTES || !value.is_ascii() {
        return None;
    }
    let decoded = PEER_PUBLIC_KEY_BASE64.decode(value.as_bytes()).ok()?;
    if decoded.len() != PEER_PUBLIC_KEY_BYTES || PEER_PUBLIC_KEY_BASE64.encode(&decoded) != value {
        return None;
    }
    decoded.try_into().ok()
}

/// Bounds the one host the initiator reaches, exactly as `route_host` of the
/// previous palier is bounded: lower-case letters, digits, hyphens and dots,
/// three to two hundred fifty-three characters, opening and closing on a letter
/// or a digit, and no empty label.
///
/// It is the same expression on purpose, down to the two bounds it reads from
/// the schema 2 module rather than restating. An IPv4 literal is written
/// naturally inside it; an IPv6 literal does not belong to the character set and
/// therefore has no refusal of its own. The test suite of this module holds the
/// two readings against one another on a shared corpus rather than trusting that
/// they still agree.
fn canonical_peer_endpoint_host(host: &str) -> bool {
    let bytes = host.as_bytes();
    if bytes.len() < MIN_ROUTE_HOST_BYTES || bytes.len() > MAX_ROUTE_HOST_BYTES || !host.is_ascii()
    {
        return false;
    }
    let alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    if !alphanumeric(bytes[0]) || !alphanumeric(bytes[bytes.len() - 1]) || host.contains("..") {
        return false;
    }
    bytes
        .iter()
        .all(|byte| alphanumeric(*byte) || *byte == b'-' || *byte == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan_v2::{decode_plan_v2_document, PlanV2Operation, RoutePlanDocumentV2};

    const INFRASTRUCTURE: &str = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2";
    const OTHER_INFRASTRUCTURE: &str = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3";
    const MACHINE: &str = "lab-machine-1";
    const PORT: u32 = 8_080;
    const ENDPOINT_HOST: &str = "vps.lab.your-cloud.test";

    /// The synthetic peer key of the shared vectors: thirty-two bytes counting
    /// from one, which no machine will ever generate and every implementation
    /// can rebuild. It is pinned as a string here and rebuilt from its own bytes
    /// below, so that neither side copies a value whose origin nobody checked.
    const PEER_PUBLIC_KEY: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";

    /// A second synthetic key, canonical like the first and still not it, used
    /// wherever a case needs a well-formed value that is not the one under test.
    const OTHER_PEER_PUBLIC_KEY: &str = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=";

    /// The six canonical documents of the shared vectors, byte for byte. They
    /// are the bytes `internal/plan/schema3_test.go` pins as the ones the
    /// Controller emits, copied literally rather than rebuilt here.
    const LINK_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":3,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"prepare_link","link_role":"listener"}"#,
    );
    const LINK_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":3,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"withdraw_link","link_role":"listener"}"#,
    );
    const LISTENER_PEER_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":3,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"attach_link_peer","#,
        r#""peer_public_key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","service_port":8080}"#,
    );
    const LISTENER_PEER_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":3,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"detach_link_peer","#,
        r#""peer_public_key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","service_port":8080}"#,
    );
    const INITIATOR_PEER_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":3,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"join_link_peer","#,
        r#""peer_public_key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","#,
        r#""peer_endpoint_host":"vps.lab.your-cloud.test","service_port":8080}"#,
    );
    const INITIATOR_PEER_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":3,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"leave_link_peer","#,
        r#""peer_public_key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","#,
        r#""peer_endpoint_host":"vps.lab.your-cloud.test","service_port":8080}"#,
    );

    /// The six transcripts, byte for byte, copied literally from
    /// `internal/plan/schema3_test.go`. The Auxiliary side pins the very same
    /// values from its own encoder, so a single byte of drift in either
    /// implementation fails here rather than producing plans the other side
    /// hashes differently on a real machine.
    const LINK_PLAN_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763300030000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d310000000c707265706172655f6c696e",
        "6b000000086c697374656e6572",
    );
    const LINK_ROLLBACK_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763300030000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d310000000d77697468647261775f6c69",
        "6e6b000000086c697374656e6572",
    );
    const LISTENER_PEER_PLAN_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763300030000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d31000000106174746163685f6c696e6b",
        "5f70656572000000200102030405060708090a0b0c0d0e0f1011121314151617",
        "18191a1b1c1d1e1f2000001f90",
    );
    const LISTENER_PEER_ROLLBACK_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763300030000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d31000000106465746163685f6c696e6b",
        "5f70656572000000200102030405060708090a0b0c0d0e0f1011121314151617",
        "18191a1b1c1d1e1f2000001f90",
    );
    const INITIATOR_PEER_PLAN_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763300030000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d310000000e6a6f696e5f6c696e6b5f70",
        "656572000000200102030405060708090a0b0c0d0e0f10111213141516171819",
        "1a1b1c1d1e1f20000000177670732e6c61622e796f75722d636c6f75642e7465",
        "737400001f90",
    );
    const INITIATOR_PEER_ROLLBACK_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763300030000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d310000000f6c656176655f6c696e6b5f",
        "70656572000000200102030405060708090a0b0c0d0e0f101112131415161718",
        "191a1b1c1d1e1f20000000177670732e6c61622e796f75722d636c6f75642e74",
        "65737400001f90",
    );

    /// The six digests an approval envelope of these vectors names as
    /// `plan_sha256` and `rollback_sha256`, in the exact spelling that envelope
    /// requires.
    const LINK_PLAN_SHA256: &str =
        "09578598cc63b5746e795896cbe96c0781fa2da88c287da4162561510c47f3fa";
    const LINK_ROLLBACK_SHA256: &str =
        "fcf951067439c264159752a2df9d1d1a7e7a60e1bb893a6fd2806c8a0c7694bb";
    const LISTENER_PEER_PLAN_SHA256: &str =
        "078ddad1386cf8c30310a6df33e3bccc68cb84da8bb50500dd1c0aa325375c2b";
    const LISTENER_PEER_ROLLBACK_SHA256: &str =
        "a220f18a94ac48b1d4452307f12b72462d6c2e747073e9a897211ef0e48ab411";
    const INITIATOR_PEER_PLAN_SHA256: &str =
        "40731b446ce7e612e20b349225ff190cf08a23ecd9ea4851fc2e254dbc10ea8d";
    const INITIATOR_PEER_ROLLBACK_SHA256: &str =
        "ba47de1b3b59e0bb15fb115cdb998254541e430d3b3e2248120429bb6479b8ba";

    /// The schema 2 route vector, kept here so that the three decoders can be
    /// held against one another without reopening the older contracts.
    const ROUTE_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"publish_route","#,
        r#""route_host":"bentopdf.lab.your-cloud.test","backend_port":8080}"#,
    );
    /// The schema 1 probe vector, for the same reason.
    const PROBE_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":1,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"deploy_oci_probe","#,
        r#""image_reference":"docker.io/traefik/whoami","#,
        r#""image_digest":"sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab","#,
        r#""local_port":8080}"#,
    );

    fn link() -> LinkPlanDocumentV3 {
        LinkPlanDocumentV3 {
            schema_version: PLAN_V3_SCHEMA_VERSION,
            infrastructure_id: INFRASTRUCTURE.into(),
            machine_id: MACHINE.into(),
            operation: PlanV3Operation::PrepareLink,
            link_role: LinkRole::Listener,
        }
    }

    fn listener_peer() -> ListenerPeerPlanDocumentV3 {
        ListenerPeerPlanDocumentV3 {
            schema_version: PLAN_V3_SCHEMA_VERSION,
            infrastructure_id: INFRASTRUCTURE.into(),
            machine_id: MACHINE.into(),
            operation: PlanV3Operation::AttachLinkPeer,
            peer_public_key: PEER_PUBLIC_KEY.into(),
            service_port: PORT,
        }
    }

    fn initiator_peer() -> InitiatorPeerPlanDocumentV3 {
        InitiatorPeerPlanDocumentV3 {
            schema_version: PLAN_V3_SCHEMA_VERSION,
            infrastructure_id: INFRASTRUCTURE.into(),
            machine_id: MACHINE.into(),
            operation: PlanV3Operation::JoinLinkPeer,
            peer_public_key: PEER_PUBLIC_KEY.into(),
            peer_endpoint_host: ENDPOINT_HOST.into(),
            service_port: PORT,
        }
    }

    /// Encodes a document without validating it, which is what a hostile case
    /// needs: the refusal under test must come from the decoding rather than
    /// from something refusing to produce the bytes in the first place.
    fn hostile<T: Serialize>(document: &T) -> String {
        serde_json::to_string(document).expect("a plan is representable as JSON")
    }

    fn with_extra_member(document: &str, member: &str) -> String {
        format!("{},{member}}}", document.trim_end_matches('}'))
    }

    /// The pinned peer key is the synthetic value it claims to be.
    ///
    /// It is rebuilt from the thirty-two bytes counting from one rather than
    /// read, which is the same reconstruction `internal/plan/schema3_test.go`
    /// performs: two implementations that rebuild the same bytes cannot be
    /// pinning two different keys under one string.
    #[test]
    fn the_pinned_peer_key_is_the_synthetic_value_it_claims_to_be() {
        let mut synthetic = [0_u8; PEER_PUBLIC_KEY_BYTES];
        for (index, byte) in synthetic.iter_mut().enumerate() {
            *byte = u8::try_from(index + 1).unwrap();
        }
        assert_eq!(PEER_PUBLIC_KEY_BASE64.encode(synthetic), PEER_PUBLIC_KEY);
        assert_eq!(PEER_PUBLIC_KEY.len(), PEER_PUBLIC_KEY_ENCODED_BYTES);
        assert_eq!(decode_peer_public_key(PEER_PUBLIC_KEY), Some(synthetic));

        assert!(decode_peer_public_key(OTHER_PEER_PUBLIC_KEY).is_some());
        assert_ne!(OTHER_PEER_PUBLIC_KEY, PEER_PUBLIC_KEY);

        // The one refusal a length check and a decoding cannot reach on their
        // own: a spelling that decodes to exactly these thirty-two bytes and is
        // still not the spelling of them. It is refused by the re-encoding
        // alone, which is why the re-encoding is part of the contract rather
        // than a precaution.
        let trailing_bits = PEER_PUBLIC_KEY.replace("HyA=", "HyB=");
        assert_eq!(
            PEER_PUBLIC_KEY_BASE64
                .decode(trailing_bits.as_bytes())
                .unwrap(),
            synthetic,
            "the trailing-bits case must decode to the vector's own bytes"
        );
        assert!(
            decode_peer_public_key(&trailing_bits).is_none(),
            "a second spelling of the pinned key was accepted"
        );
    }

    /// The interoperability proof of the schema 3 encoding, for each of the
    /// three operation groups.
    ///
    /// Every transcript, every digest and every canonical document is pinned
    /// literally here and in `internal/plan/schema3_test.go`. Reading the two
    /// encoders against one another would not be a proof; producing the same
    /// bytes from both is.
    ///
    /// The two lengths of each pair are pinned rather than one: the transcripts
    /// of `withdraw_link` and `leave_link_peer` are one byte longer than the
    /// ones they undo, because their operation names are one character longer.
    /// That is the layout working, and pinning both lengths is what keeps it
    /// from ever being read as drift.
    #[test]
    fn the_deterministic_schema_three_vectors_are_held_with_the_auxiliary_side() {
        for (
            group,
            plan_document,
            rollback_document,
            plan_hex,
            rollback_hex,
            plan_sha,
            rollback_sha,
            plan_length,
            rollback_length,
        ) in [
            (
                "link",
                LINK_PLAN_DOCUMENT,
                LINK_ROLLBACK_DOCUMENT,
                LINK_PLAN_TRANSCRIPT_HEX,
                LINK_ROLLBACK_TRANSCRIPT_HEX,
                LINK_PLAN_SHA256,
                LINK_ROLLBACK_SHA256,
                109_usize,
                110_usize,
            ),
            (
                "listener peer",
                LISTENER_PEER_PLAN_DOCUMENT,
                LISTENER_PEER_ROLLBACK_DOCUMENT,
                LISTENER_PEER_PLAN_TRANSCRIPT_HEX,
                LISTENER_PEER_ROLLBACK_TRANSCRIPT_HEX,
                LISTENER_PEER_PLAN_SHA256,
                LISTENER_PEER_ROLLBACK_SHA256,
                141_usize,
                141_usize,
            ),
            (
                "initiator peer",
                INITIATOR_PEER_PLAN_DOCUMENT,
                INITIATOR_PEER_ROLLBACK_DOCUMENT,
                INITIATOR_PEER_PLAN_TRANSCRIPT_HEX,
                INITIATOR_PEER_ROLLBACK_TRANSCRIPT_HEX,
                INITIATOR_PEER_PLAN_SHA256,
                INITIATOR_PEER_ROLLBACK_SHA256,
                166_usize,
                167_usize,
            ),
        ] {
            let plan = decode_plan_v3_document(plan_document.as_bytes())
                .unwrap_or_else(|_| panic!("{group}: the nominal document"));
            let rollback = decode_plan_v3_document(rollback_document.as_bytes())
                .unwrap_or_else(|_| panic!("{group}: the nominal rollback"));

            let transcript = plan.transcript().expect("the vector transcript");
            let rollback_transcript = rollback.transcript().expect("the vector transcript");
            assert_eq!(
                transcript.len(),
                plan_length,
                "{group} transcript length drifted"
            );
            assert_eq!(
                rollback_transcript.len(),
                rollback_length,
                "{group} rollback transcript length drifted"
            );
            assert!(
                transcript.starts_with(PLAN_V3_TRANSCRIPT_DOMAIN),
                "{group} transcript does not start with its own domain separator"
            );
            assert_eq!(
                encode_lower_hex(&transcript),
                plan_hex,
                "{group} plan transcript drifted from the shared vector"
            );
            assert_eq!(
                encode_lower_hex(&rollback_transcript),
                rollback_hex,
                "{group} rollback transcript drifted from the shared vector"
            );

            assert_eq!(plan.sha256().unwrap(), plan_sha, "{group} plan_sha256");
            assert_eq!(
                rollback.sha256().unwrap(),
                rollback_sha,
                "{group} rollback_sha256"
            );
            assert!(plan.is_undone_by(&rollback));
            assert!(rollback.is_undone_by(&plan));
        }
    }

    /// The declaration order of the fields is the canonical encoding order the
    /// Controller emits, and serde is held to it rather than trusted with it.
    ///
    /// It is asserted rather than relied upon, because this side must recognise
    /// those exact bytes and never has to produce them: a serialiser that sorted
    /// its keys would still read every plan correctly and would silently stop
    /// agreeing with the Auxiliary about what a canonical document is.
    #[test]
    fn the_canonical_serialisation_order_is_the_declaration_order() {
        assert_eq!(hostile(&link()), LINK_PLAN_DOCUMENT);
        assert_eq!(hostile(&link().inverted()), LINK_ROLLBACK_DOCUMENT);
        assert_eq!(hostile(&listener_peer()), LISTENER_PEER_PLAN_DOCUMENT);
        assert_eq!(
            hostile(&listener_peer().inverted()),
            LISTENER_PEER_ROLLBACK_DOCUMENT
        );
        assert_eq!(hostile(&initiator_peer()), INITIATOR_PEER_PLAN_DOCUMENT);
        assert_eq!(
            hostile(&initiator_peer().inverted()),
            INITIATOR_PEER_ROLLBACK_DOCUMENT
        );
    }

    /// No two of the six vectors, nor the vectors of the two older schemas, name
    /// the same digest.
    ///
    /// This is what makes the three transcript layouts unambiguous without a
    /// group tag and without a schema tag: fourteen distinct documents produce
    /// fourteen distinct digests.
    #[test]
    fn no_two_schema_three_digests_collide_across_the_three_schemas() {
        let mut seen: Vec<&str> = vec![
            // The two schema 1 digests of the probe vector.
            "2d50d2bc935ce6c56ef14fbfae93d670d5fdb9ca735315e5a26760d818dd5b0e",
            "e953fb5f9d8423be61cad4a06d571e200977dd183f53c12d5a897746ad80497a",
            // The six schema 2 digests of the public profile vectors.
            "99f6e6401d74583f64e4200e6e47cd365ab299466eebe1c1a7210f260b0366ae",
            "4e480f76a7247cde6c41990e941512dce70f0a272a17a2618211bd03230ced68",
            "fe15d468f77ed9ca6b54da9a63860278894be7db4b6d997898b55fcb602f3722",
            "1b91a7fa77b7d02cc16ce5d694b1709f641a341c849b4459de0ee3960d1cfcd8",
            "3d92c310868a8ba98aca5501c069bd0e4674757f787c8095e7c39d65d8d20a89",
            "93e844abe96e68f157eb715ace9ff423004b0c64c68536d4e79ebc8206da1324",
        ];
        for digest in [
            LINK_PLAN_SHA256,
            LINK_ROLLBACK_SHA256,
            LISTENER_PEER_PLAN_SHA256,
            LISTENER_PEER_ROLLBACK_SHA256,
            INITIATOR_PEER_PLAN_SHA256,
            INITIATOR_PEER_ROLLBACK_SHA256,
        ] {
            assert!(!seen.contains(&digest), "{digest} is named twice");
            seen.push(digest);
        }
    }

    /// Every field of every schema 3 document is inside the hashed bytes.
    ///
    /// The test does not read the transcript builders: it changes one field at a
    /// time and requires the bytes to move. The wire documents are read back at
    /// the end, so a field added to a schema and forgotten in its transcript
    /// fails here rather than on a machine.
    #[test]
    fn changing_any_single_field_changes_the_schema_three_digest() {
        let reference = link().transcript().unwrap();
        let mut covered: Vec<&str> = Vec::new();
        for (field, moved) in [
            (
                "schema_version",
                LinkPlanDocumentV3 {
                    schema_version: 2,
                    ..link()
                },
            ),
            (
                "infrastructure_id",
                LinkPlanDocumentV3 {
                    infrastructure_id: OTHER_INFRASTRUCTURE.into(),
                    ..link()
                },
            ),
            (
                "machine_id",
                LinkPlanDocumentV3 {
                    machine_id: "lab-machine-2".into(),
                    ..link()
                },
            ),
            (
                "operation",
                LinkPlanDocumentV3 {
                    operation: PlanV3Operation::WithdrawLink,
                    ..link()
                },
            ),
            (
                "link_role",
                LinkPlanDocumentV3 {
                    link_role: LinkRole::Initiator,
                    ..link()
                },
            ),
        ] {
            assert_ne!(
                moved.transcript().unwrap(),
                reference,
                "link {field} is outside the hashed bytes"
            );
            covered.push(field);
        }
        require_every_wire_field_is_held(&hostile(&link()), &covered);

        let reference = listener_peer().transcript().unwrap();
        let mut covered: Vec<&str> = Vec::new();
        for (field, moved) in [
            (
                "schema_version",
                ListenerPeerPlanDocumentV3 {
                    schema_version: 2,
                    ..listener_peer()
                },
            ),
            (
                "infrastructure_id",
                ListenerPeerPlanDocumentV3 {
                    infrastructure_id: OTHER_INFRASTRUCTURE.into(),
                    ..listener_peer()
                },
            ),
            (
                "machine_id",
                ListenerPeerPlanDocumentV3 {
                    machine_id: "lab-machine-2".into(),
                    ..listener_peer()
                },
            ),
            (
                "operation",
                ListenerPeerPlanDocumentV3 {
                    operation: PlanV3Operation::DetachLinkPeer,
                    ..listener_peer()
                },
            ),
            (
                "peer_public_key",
                ListenerPeerPlanDocumentV3 {
                    peer_public_key: OTHER_PEER_PUBLIC_KEY.into(),
                    ..listener_peer()
                },
            ),
            (
                "service_port",
                ListenerPeerPlanDocumentV3 {
                    service_port: PORT + 1,
                    ..listener_peer()
                },
            ),
        ] {
            assert_ne!(
                moved.transcript().unwrap(),
                reference,
                "listener peer {field} is outside the hashed bytes"
            );
            covered.push(field);
        }
        require_every_wire_field_is_held(&hostile(&listener_peer()), &covered);

        let reference = initiator_peer().transcript().unwrap();
        let mut covered: Vec<&str> = Vec::new();
        for (field, moved) in [
            (
                "schema_version",
                InitiatorPeerPlanDocumentV3 {
                    schema_version: 2,
                    ..initiator_peer()
                },
            ),
            (
                "infrastructure_id",
                InitiatorPeerPlanDocumentV3 {
                    infrastructure_id: OTHER_INFRASTRUCTURE.into(),
                    ..initiator_peer()
                },
            ),
            (
                "machine_id",
                InitiatorPeerPlanDocumentV3 {
                    machine_id: "lab-machine-2".into(),
                    ..initiator_peer()
                },
            ),
            (
                "operation",
                InitiatorPeerPlanDocumentV3 {
                    operation: PlanV3Operation::LeaveLinkPeer,
                    ..initiator_peer()
                },
            ),
            (
                "peer_public_key",
                InitiatorPeerPlanDocumentV3 {
                    peer_public_key: OTHER_PEER_PUBLIC_KEY.into(),
                    ..initiator_peer()
                },
            ),
            (
                "peer_endpoint_host",
                InitiatorPeerPlanDocumentV3 {
                    peer_endpoint_host: "other.lab.your-cloud.test".into(),
                    ..initiator_peer()
                },
            ),
            (
                "service_port",
                InitiatorPeerPlanDocumentV3 {
                    service_port: PORT + 1,
                    ..initiator_peer()
                },
            ),
        ] {
            assert_ne!(
                moved.transcript().unwrap(),
                reference,
                "initiator peer {field} is outside the hashed bytes"
            );
            covered.push(field);
        }
        require_every_wire_field_is_held(&hostile(&initiator_peer()), &covered);
    }

    /// Every field the wire document carries is one of the ones that was moved.
    fn require_every_wire_field_is_held(document: &str, covered: &[&str]) {
        let wire: serde_json::Value = serde_json::from_str(document).unwrap();
        let mut names: Vec<String> = wire.as_object().unwrap().keys().cloned().collect();
        names.sort();
        let mut held: Vec<String> = covered.iter().map(|name| (*name).to_owned()).collect();
        held.sort();
        assert_eq!(
            names, held,
            "a field of the plan is never held against its digest"
        );
    }

    /// The hostile table of the link group, and the whole surface of
    /// `link_role`.
    ///
    /// The role is an enumeration, so every spelling outside the two entries is
    /// refused while the document is parsed. The cases below are therefore
    /// written as wire documents rather than as values: a value that cannot be
    /// built is a value that cannot be tested.
    #[test]
    fn decoding_refuses_every_link_document_outside_the_contract() {
        assert!(decode_plan_v3_document(LINK_PLAN_DOCUMENT.as_bytes()).is_ok());
        assert!(decode_plan_v3_document(LINK_ROLLBACK_DOCUMENT.as_bytes()).is_ok());

        // Both entries of the closed role list are accepted, so that the
        // refusals below name a role outside the list rather than a list of one.
        for role in [LinkRole::Listener, LinkRole::Initiator] {
            let accepted = LinkPlanDocumentV3 {
                link_role: role,
                ..link()
            };
            assert!(
                decode_plan_v3_document(hostile(&accepted).as_bytes()).is_ok(),
                "the role {} was refused",
                role.as_str()
            );
        }

        for (name, document) in [
            (
                "unknown role",
                LINK_PLAN_DOCUMENT.replace(r#""listener""#, r#""relay""#),
            ),
            (
                "upper-case role",
                LINK_PLAN_DOCUMENT.replace(r#""listener""#, r#""Listener""#),
            ),
            (
                "shouting role",
                LINK_PLAN_DOCUMENT.replace(r#""listener""#, r#""LISTENER""#),
            ),
            (
                "empty role",
                LINK_PLAN_DOCUMENT.replace(r#""listener""#, r#""""#),
            ),
            (
                "padded role",
                LINK_PLAN_DOCUMENT.replace(r#""listener""#, r#""listener ""#),
            ),
            (
                "both roles",
                LINK_PLAN_DOCUMENT.replace(r#""listener""#, r#""listener,initiator""#),
            ),
            (
                "role carrying a break",
                LINK_PLAN_DOCUMENT.replace(r#""listener""#, r#""listener\ninitiator""#),
            ),
            (
                "role carrying a NUL",
                LINK_PLAN_DOCUMENT.replace(r#""listener""#, r#""listener\u0000""#),
            ),
            (
                "role as a number",
                LINK_PLAN_DOCUMENT.replace(r#""listener""#, "1"),
            ),
            (
                "role as an array",
                LINK_PLAN_DOCUMENT.replace(r#""listener""#, r#"["listener"]"#),
            ),
        ] {
            assert_eq!(
                decode_plan_v3_document(document.as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }

        for (name, hostile_document) in [
            (
                "schema 1 version",
                LinkPlanDocumentV3 {
                    schema_version: 1,
                    ..link()
                },
            ),
            (
                "schema 2 version",
                LinkPlanDocumentV3 {
                    schema_version: 2,
                    ..link()
                },
            ),
            (
                "absent schema",
                LinkPlanDocumentV3 {
                    schema_version: 0,
                    ..link()
                },
            ),
            (
                "upper-case UUID",
                LinkPlanDocumentV3 {
                    infrastructure_id: INFRASTRUCTURE.to_ascii_uppercase(),
                    ..link()
                },
            ),
            (
                "empty infrastructure",
                LinkPlanDocumentV3 {
                    infrastructure_id: String::new(),
                    ..link()
                },
            ),
            (
                "non version 4 UUID",
                LinkPlanDocumentV3 {
                    infrastructure_id: "8f14e45f-ceea-1167-a8b1-1f7bd0a0f4c2".into(),
                    ..link()
                },
            ),
            (
                "traversal machine",
                LinkPlanDocumentV3 {
                    machine_id: "../../etc/shadow".into(),
                    ..link()
                },
            ),
            (
                "upper-case machine",
                LinkPlanDocumentV3 {
                    machine_id: "LAB-MACHINE-1".into(),
                    ..link()
                },
            ),
            (
                "listener operation",
                LinkPlanDocumentV3 {
                    operation: PlanV3Operation::AttachLinkPeer,
                    ..link()
                },
            ),
            (
                "initiator operation",
                LinkPlanDocumentV3 {
                    operation: PlanV3Operation::JoinLinkPeer,
                    ..link()
                },
            ),
        ] {
            assert_eq!(
                decode_plan_v3_document(hostile(&hostile_document).as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }
    }

    /// The hostile table of the listener junction, and the whole surface of
    /// `peer_public_key`.
    ///
    /// The key is an observation the other machine reported, so it is the one
    /// field of the palier whose value nobody chose. That is exactly why its
    /// spelling is closed here: a key with a second accepted spelling would be a
    /// key with a second digest, and the human would have approved one of the
    /// two.
    #[test]
    fn decoding_refuses_every_listener_peer_document_outside_the_contract() {
        assert!(decode_plan_v3_document(LISTENER_PEER_PLAN_DOCUMENT.as_bytes()).is_ok());
        assert!(decode_plan_v3_document(LISTENER_PEER_ROLLBACK_DOCUMENT.as_bytes()).is_ok());

        // The bounds themselves are accepted, so that the refusals below name a
        // malformation rather than an off-by-one.
        for port in [MIN_PLAN_SERVICE_PORT, MAX_PLAN_SERVICE_PORT] {
            let accepted = ListenerPeerPlanDocumentV3 {
                service_port: port,
                ..listener_peer()
            };
            assert!(
                decode_plan_v3_document(hostile(&accepted).as_bytes()).is_ok(),
                "the bound {port} of the service range was refused"
            );
        }
        for key in [PEER_PUBLIC_KEY, OTHER_PEER_PUBLIC_KEY] {
            let accepted = ListenerPeerPlanDocumentV3 {
                peer_public_key: key.into(),
                ..listener_peer()
            };
            assert!(
                decode_plan_v3_document(hostile(&accepted).as_bytes()).is_ok(),
                "the canonical key {key} was refused"
            );
        }

        // The whole surface of the peer key. Each of these decodes to the right
        // thirty-two bytes or nearly does, and each of them is a second spelling
        // the contract does not have.
        for (name, key) in [
            ("empty key", String::new()),
            (
                "unpadded key",
                PEER_PUBLIC_KEY.trim_end_matches('=').to_owned(),
            ),
            ("doubly padded key", format!("{PEER_PUBLIC_KEY}=")),
            (
                "padding in front",
                format!("={}", PEER_PUBLIC_KEY.trim_end_matches('=')),
            ),
            ("padding inside", PEER_PUBLIC_KEY.replace("HyA=", "H=yA")),
            ("URL alphabet", PEER_PUBLIC_KEY.replace("HB0e", "HB0_")),
            ("URL hyphen", PEER_PUBLIC_KEY.replace("HB0e", "HB0-")),
            (
                "non-zero trailing bits",
                PEER_PUBLIC_KEY.replace("HyA=", "HyB="),
            ),
            ("forty-three characters", PEER_PUBLIC_KEY[..43].to_owned()),
            ("forty-five characters", format!("{PEER_PUBLIC_KEY}A")),
            (
                "thirty-three bytes",
                format!("{}A", PEER_PUBLIC_KEY.trim_end_matches('=')),
            ),
            ("sixteen bytes", PEER_PUBLIC_KEY_BASE64.encode([0_u8; 16])),
            ("hexadecimal key", "0".repeat(44)),
            (
                "key carrying a break",
                PEER_PUBLIC_KEY.replace("HB0e", "HB\n0"),
            ),
            (
                "key carrying a space",
                PEER_PUBLIC_KEY.replace("HB0e", "HB0 "),
            ),
            (
                "key carrying a NUL",
                PEER_PUBLIC_KEY.replace("HB0e", "HB0\0"),
            ),
            (
                "key carrying an accent",
                PEER_PUBLIC_KEY.replace("HB0e", "HB0é"),
            ),
        ] {
            let hostile_document = ListenerPeerPlanDocumentV3 {
                peer_public_key: key,
                ..listener_peer()
            };
            assert_eq!(
                decode_plan_v3_document(hostile(&hostile_document).as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }

        for (name, hostile_document) in [
            (
                "schema 2 version",
                ListenerPeerPlanDocumentV3 {
                    schema_version: 2,
                    ..listener_peer()
                },
            ),
            (
                "upper-case UUID",
                ListenerPeerPlanDocumentV3 {
                    infrastructure_id: INFRASTRUCTURE.to_ascii_uppercase(),
                    ..listener_peer()
                },
            ),
            (
                "machine opening on a hyphen",
                ListenerPeerPlanDocumentV3 {
                    machine_id: "-lab-machine-1".into(),
                    ..listener_peer()
                },
            ),
            (
                "too short machine",
                ListenerPeerPlanDocumentV3 {
                    machine_id: "ab".into(),
                    ..listener_peer()
                },
            ),
            (
                "link operation",
                ListenerPeerPlanDocumentV3 {
                    operation: PlanV3Operation::PrepareLink,
                    ..listener_peer()
                },
            ),
            (
                "initiator operation",
                ListenerPeerPlanDocumentV3 {
                    operation: PlanV3Operation::JoinLinkPeer,
                    ..listener_peer()
                },
            ),
            (
                "port below the range",
                ListenerPeerPlanDocumentV3 {
                    service_port: MIN_PLAN_SERVICE_PORT - 1,
                    ..listener_peer()
                },
            ),
            (
                "privileged port",
                ListenerPeerPlanDocumentV3 {
                    service_port: 443,
                    ..listener_peer()
                },
            ),
            (
                "absent port",
                ListenerPeerPlanDocumentV3 {
                    service_port: 0,
                    ..listener_peer()
                },
            ),
            (
                "port above the range",
                ListenerPeerPlanDocumentV3 {
                    service_port: MAX_PLAN_SERVICE_PORT + 1,
                    ..listener_peer()
                },
            ),
            (
                "port beyond sixteen bits",
                ListenerPeerPlanDocumentV3 {
                    service_port: 70_000,
                    ..listener_peer()
                },
            ),
        ] {
            assert_eq!(
                decode_plan_v3_document(hostile(&hostile_document).as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }
    }

    /// The hostile table of the initiator junction, and the whole surface of
    /// `peer_endpoint_host`.
    ///
    /// The endpoint host reuses the bound of `route_host`, so the malformations
    /// that bound proved on a published name are presented here again on the
    /// name the initiator reaches: one expression, one surface, and no second
    /// host grammar nobody would have read.
    #[test]
    fn decoding_refuses_every_initiator_peer_document_outside_the_contract() {
        assert!(decode_plan_v3_document(INITIATOR_PEER_PLAN_DOCUMENT.as_bytes()).is_ok());
        assert!(decode_plan_v3_document(INITIATOR_PEER_ROLLBACK_DOCUMENT.as_bytes()).is_ok());

        for (name, host) in [
            ("shortest accepted name", "abc".to_owned()),
            ("longest accepted name", format!("{}.test", "a".repeat(248))),
            (
                "punycode label",
                "xn--bcher-kva.lab.your-cloud.test".to_owned(),
            ),
            ("IPv4 literal", "192.0.2.10".to_owned()),
        ] {
            let accepted = InitiatorPeerPlanDocumentV3 {
                peer_endpoint_host: host,
                ..initiator_peer()
            };
            assert!(
                decode_plan_v3_document(hostile(&accepted).as_bytes()).is_ok(),
                "{name} was refused"
            );
        }

        for (name, host) in [
            ("empty host", String::new()),
            ("host below the bound", "ab".to_owned()),
            ("host above the bound", format!("{}.test", "a".repeat(249))),
            ("wildcard host", "*.lab.your-cloud.test".to_owned()),
            ("bare wildcard", "*".to_owned()),
            ("upper-case host", "VPS.lab.your-cloud.test".to_owned()),
            ("leading dot", ".lab.your-cloud.test".to_owned()),
            ("trailing dot", "vps.lab.your-cloud.test.".to_owned()),
            ("leading hyphen", "-vps.lab.your-cloud.test".to_owned()),
            ("trailing hyphen", "vps.lab.your-cloud.test-".to_owned()),
            ("consecutive dots", "vps..lab.your-cloud.test".to_owned()),
            ("empty label at the start", "..test".to_owned()),
            ("underscore host", "vps_1.lab.your-cloud.test".to_owned()),
            (
                "host carrying a port",
                "vps.lab.your-cloud.test:51820".to_owned(),
            ),
            (
                "host carrying a path",
                "vps.lab.your-cloud.test/link".to_owned(),
            ),
            (
                "host carrying a space",
                "vps lab.your-cloud.test".to_owned(),
            ),
            (
                "host carrying a line break",
                "vps.lab.test\nevil.test".to_owned(),
            ),
            ("non ASCII host", "vpsé.lab.your-cloud.test".to_owned()),
            (
                "host carrying a trailing NUL",
                "vps.lab.your-cloud.test\0".to_owned(),
            ),
            ("IPv6 literal", "2001:db8::1".to_owned()),
        ] {
            let hostile_document = InitiatorPeerPlanDocumentV3 {
                peer_endpoint_host: host,
                ..initiator_peer()
            };
            assert_eq!(
                decode_plan_v3_document(hostile(&hostile_document).as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }

        for (name, hostile_document) in [
            (
                "schema 1 version",
                InitiatorPeerPlanDocumentV3 {
                    schema_version: 1,
                    ..initiator_peer()
                },
            ),
            (
                "traversal machine",
                InitiatorPeerPlanDocumentV3 {
                    machine_id: "../../etc/shadow".into(),
                    ..initiator_peer()
                },
            ),
            (
                "link operation",
                InitiatorPeerPlanDocumentV3 {
                    operation: PlanV3Operation::WithdrawLink,
                    ..initiator_peer()
                },
            ),
            (
                "listener operation",
                InitiatorPeerPlanDocumentV3 {
                    operation: PlanV3Operation::AttachLinkPeer,
                    ..initiator_peer()
                },
            ),
            (
                "unpadded key",
                InitiatorPeerPlanDocumentV3 {
                    peer_public_key: PEER_PUBLIC_KEY[..43].into(),
                    ..initiator_peer()
                },
            ),
            (
                "URL alphabet key",
                InitiatorPeerPlanDocumentV3 {
                    peer_public_key: PEER_PUBLIC_KEY.replace("HB0e", "HB0_"),
                    ..initiator_peer()
                },
            ),
            (
                "trailing bits key",
                InitiatorPeerPlanDocumentV3 {
                    peer_public_key: PEER_PUBLIC_KEY.replace("HyA=", "HyB="),
                    ..initiator_peer()
                },
            ),
            (
                "hexadecimal key",
                InitiatorPeerPlanDocumentV3 {
                    peer_public_key: "0".repeat(44),
                    ..initiator_peer()
                },
            ),
            (
                "privileged port",
                InitiatorPeerPlanDocumentV3 {
                    service_port: 443,
                    ..initiator_peer()
                },
            ),
            (
                "port above the range",
                InitiatorPeerPlanDocumentV3 {
                    service_port: MAX_PLAN_SERVICE_PORT + 1,
                    ..initiator_peer()
                },
            ),
        ] {
            assert_eq!(
                decode_plan_v3_document(hostile(&hostile_document).as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }
    }

    /// The endpoint host is bounded by the very reading `route_host` already
    /// had.
    ///
    /// The two expressions live in two modules, so agreeing by reading them is
    /// not enough: the same corpus is presented to both closed contracts through
    /// their public decoders, and a host accepted by one and refused by the
    /// other fails here. A second host grammar would then be a red test rather
    /// than a name the two sides bound differently.
    #[test]
    fn the_endpoint_host_bound_is_the_one_the_route_host_already_had() {
        for host in [
            "abc",
            "vps.lab.your-cloud.test",
            "xn--bcher-kva.lab.your-cloud.test",
            "192.0.2.10",
            "127.0.0.1",
            "",
            "ab",
            "*.lab.your-cloud.test",
            "*",
            "VPS.lab.your-cloud.test",
            ".lab.your-cloud.test",
            "vps.lab.your-cloud.test.",
            "-vps.lab.your-cloud.test",
            "vps.lab.your-cloud.test-",
            "vps..lab.your-cloud.test",
            "..test",
            "vps_1.lab.your-cloud.test",
            "vps.lab.your-cloud.test:51820",
            "vps.lab.your-cloud.test/link",
            "vps lab.your-cloud.test",
            "vps.lab.test\nevil.test",
            "vpsé.lab.your-cloud.test",
            "vps.lab.your-cloud.test\0",
            "2001:db8::1",
        ] {
            let initiator = InitiatorPeerPlanDocumentV3 {
                peer_endpoint_host: host.to_owned(),
                ..initiator_peer()
            };
            let route = RoutePlanDocumentV2 {
                schema_version: 2,
                infrastructure_id: INFRASTRUCTURE.into(),
                machine_id: MACHINE.into(),
                operation: PlanV2Operation::PublishRoute,
                route_host: host.to_owned(),
                backend_port: PORT,
            };
            assert_eq!(
                decode_plan_v3_document(hostile(&initiator).as_bytes()).is_ok(),
                decode_plan_v2_document(hostile(&route).as_bytes()).is_ok(),
                "the two paliers do not bound {host:?} the same way"
            );
        }

        // The two bounds are the same numbers, read from one declaration rather
        // than restated here.
        assert_eq!(MIN_ROUTE_HOST_BYTES, 3);
        assert_eq!(MAX_ROUTE_HOST_BYTES, 253);
    }

    /// What the discriminator exists for, across the three groups of schema 3
    /// and across the groups of the two older schemas.
    ///
    /// The operation is read first, and the document is then held against
    /// exactly the closed field list that operation declares. A field belonging
    /// to another operation — of this schema or of another one — is an unknown
    /// field of the claimed schema, refused before its value is read.
    #[test]
    fn no_schema_three_document_borrows_a_field_of_another_operation() {
        for (name, document) in [
            // Fields borrowed across the three groups of schema 3.
            (
                "a link plan carrying a peer key",
                with_extra_member(
                    LINK_PLAN_DOCUMENT,
                    &format!(r#""peer_public_key":"{PEER_PUBLIC_KEY}""#),
                ),
            ),
            (
                "a link plan carrying a service port",
                with_extra_member(LINK_PLAN_DOCUMENT, r#""service_port":8080"#),
            ),
            (
                "a link plan carrying an endpoint",
                with_extra_member(
                    LINK_PLAN_DOCUMENT,
                    r#""peer_endpoint_host":"vps.lab.your-cloud.test""#,
                ),
            ),
            (
                "a listener plan carrying an endpoint",
                with_extra_member(
                    LISTENER_PEER_PLAN_DOCUMENT,
                    r#""peer_endpoint_host":"vps.lab.your-cloud.test""#,
                ),
            ),
            (
                "a listener plan carrying a role",
                with_extra_member(LISTENER_PEER_PLAN_DOCUMENT, r#""link_role":"listener""#),
            ),
            (
                "an initiator plan carrying a role",
                with_extra_member(INITIATOR_PEER_PLAN_DOCUMENT, r#""link_role":"initiator""#),
            ),
            (
                "an initiator plan carrying an endpoint port",
                with_extra_member(
                    INITIATOR_PEER_PLAN_DOCUMENT,
                    r#""peer_endpoint_port":51820"#,
                ),
            ),
            // Fields borrowed from the groups of the two older schemas.
            (
                "a link plan carrying a route host",
                with_extra_member(LINK_PLAN_DOCUMENT, r#""route_host":"evil.test""#),
            ),
            (
                "a link plan carrying an image",
                with_extra_member(
                    LINK_PLAN_DOCUMENT,
                    r#""image_reference":"ghcr.io/alam00000/bentopdf""#,
                ),
            ),
            (
                "a listener plan carrying a profile",
                with_extra_member(
                    LISTENER_PEER_PLAN_DOCUMENT,
                    r#""service_profile":"bentopdf""#,
                ),
            ),
            (
                "a listener plan carrying a local port",
                with_extra_member(LISTENER_PEER_PLAN_DOCUMENT, r#""local_port":8080"#),
            ),
            (
                "an initiator plan carrying a backend",
                with_extra_member(INITIATOR_PEER_PLAN_DOCUMENT, r#""backend_port":8080"#),
            ),
            // Operations swapped between shapes.
            (
                "a link plan claiming a listener junction",
                LINK_PLAN_DOCUMENT.replace(r#""prepare_link""#, r#""attach_link_peer""#),
            ),
            (
                "a link plan claiming an initiator junction",
                LINK_PLAN_DOCUMENT.replace(r#""prepare_link""#, r#""join_link_peer""#),
            ),
            (
                "a listener plan claiming a link",
                LISTENER_PEER_PLAN_DOCUMENT.replace(r#""attach_link_peer""#, r#""prepare_link""#),
            ),
            (
                "a listener plan claiming an initiator",
                LISTENER_PEER_PLAN_DOCUMENT.replace(r#""attach_link_peer""#, r#""join_link_peer""#),
            ),
            (
                "an initiator plan claiming a listener",
                INITIATOR_PEER_PLAN_DOCUMENT
                    .replace(r#""join_link_peer""#, r#""attach_link_peer""#),
            ),
            (
                "an initiator plan claiming a route",
                INITIATOR_PEER_PLAN_DOCUMENT.replace(r#""join_link_peer""#, r#""publish_route""#),
            ),
            // Fields the shape requires and the document does not carry.
            (
                "a link plan without its role",
                LINK_PLAN_DOCUMENT.replace(r#","link_role":"listener""#, ""),
            ),
            (
                "a listener plan without its key",
                LISTENER_PEER_PLAN_DOCUMENT
                    .replace(&format!(r#""peer_public_key":"{PEER_PUBLIC_KEY}","#), ""),
            ),
            (
                "a listener plan without its port",
                LISTENER_PEER_PLAN_DOCUMENT.replace(r#","service_port":8080"#, ""),
            ),
            (
                "an initiator plan without its host",
                INITIATOR_PEER_PLAN_DOCUMENT
                    .replace(r#""peer_endpoint_host":"vps.lab.your-cloud.test","#, ""),
            ),
            (
                "an initiator plan without its key",
                INITIATOR_PEER_PLAN_DOCUMENT
                    .replace(&format!(r#""peer_public_key":"{PEER_PUBLIC_KEY}","#), ""),
            ),
            // The framing itself.
            (
                "a document with no operation",
                LINK_PLAN_DOCUMENT.replace(r#""operation":"prepare_link","#, ""),
            ),
            (
                "a document naming a number as its operation",
                LINK_PLAN_DOCUMENT.replace(r#""operation":"prepare_link""#, r#""operation":3"#),
            ),
            (
                "a document naming null as its operation",
                LINK_PLAN_DOCUMENT.replace(r#""operation":"prepare_link""#, r#""operation":null"#),
            ),
            (
                "a document naming an object as its operation",
                LINK_PLAN_DOCUMENT.replace(
                    r#""operation":"prepare_link""#,
                    r#""operation":{"name":"prepare_link"}"#,
                ),
            ),
            (
                "a document naming an upper-case operation",
                LINK_PLAN_DOCUMENT.replace(
                    r#""operation":"prepare_link""#,
                    r#""operation":"PREPARE_LINK""#,
                ),
            ),
            (
                "a document naming an unknown operation",
                LINK_PLAN_DOCUMENT.replace(
                    r#""operation":"prepare_link""#,
                    r#""operation":"establish_tunnel""#,
                ),
            ),
            (
                "a document repeating its operation",
                with_extra_member(LINK_PLAN_DOCUMENT, r#""operation":"withdraw_link""#),
            ),
            (
                "a document repeating its role",
                with_extra_member(LINK_PLAN_DOCUMENT, r#""link_role":"initiator""#),
            ),
            (
                "a document repeating its peer key",
                with_extra_member(
                    LISTENER_PEER_PLAN_DOCUMENT,
                    &format!(r#""peer_public_key":"{OTHER_PEER_PUBLIC_KEY}""#),
                ),
            ),
            (
                "a document repeating its port",
                with_extra_member(LISTENER_PEER_PLAN_DOCUMENT, r#""service_port":9090"#),
            ),
            (
                "a document with a non-canonical field name",
                LISTENER_PEER_PLAN_DOCUMENT.replace(r#""peer_public_key""#, r#""Peer_Public_Key""#),
            ),
            (
                "a document with a camel-case field name",
                LISTENER_PEER_PLAN_DOCUMENT.replace(r#""service_port""#, r#""servicePort""#),
            ),
            (
                "a document with a stringified port",
                LISTENER_PEER_PLAN_DOCUMENT
                    .replace(r#""service_port":8080"#, r#""service_port":"8080""#),
            ),
            (
                "a document with a fractional port",
                LISTENER_PEER_PLAN_DOCUMENT
                    .replace(r#""service_port":8080"#, r#""service_port":8080.5"#),
            ),
            (
                "a document with an exponent port",
                LISTENER_PEER_PLAN_DOCUMENT
                    .replace(r#""service_port":8080"#, r#""service_port":8.08e3"#),
            ),
            (
                "a document with a negative port",
                LISTENER_PEER_PLAN_DOCUMENT
                    .replace(r#""service_port":8080"#, r#""service_port":-1"#),
            ),
            (
                "a document with a key as an array",
                LISTENER_PEER_PLAN_DOCUMENT.replace(
                    &format!(r#""peer_public_key":"{PEER_PUBLIC_KEY}""#),
                    &format!(r#""peer_public_key":["{PEER_PUBLIC_KEY}"]"#),
                ),
            ),
            // The things a plan is never allowed to carry, whatever its schema.
            (
                "a document carrying a private key",
                with_extra_member(
                    LINK_PLAN_DOCUMENT,
                    &format!(r#""private_key":"{PEER_PUBLIC_KEY}""#),
                ),
            ),
            (
                "a document carrying an allowed IP",
                with_extra_member(
                    LISTENER_PEER_PLAN_DOCUMENT,
                    r#""allowed_ips":["0.0.0.0/0"]"#,
                ),
            ),
            (
                "a document carrying an interface",
                with_extra_member(LINK_PLAN_DOCUMENT, r#""interface":"yc-link1""#),
            ),
            (
                "a document carrying a listen port",
                with_extra_member(LINK_PLAN_DOCUMENT, r#""listen_port":51820"#),
            ),
            (
                "a document carrying a keepalive",
                with_extra_member(INITIATOR_PEER_PLAN_DOCUMENT, r#""keepalive_seconds":25"#),
            ),
            (
                "a document carrying an nftables rule",
                with_extra_member(LISTENER_PEER_PLAN_DOCUMENT, r#""nftables":"accept all""#),
            ),
            (
                "a document carrying a command",
                with_extra_member(LINK_PLAN_DOCUMENT, r#""command":"/bin/sh""#),
            ),
            ("an empty document", String::new()),
            ("two values", format!("{LINK_PLAN_DOCUMENT}{{}}")),
            ("an array of documents", format!("[{LINK_PLAN_DOCUMENT}]")),
            (
                "a truncated document",
                LINK_PLAN_DOCUMENT.trim_end_matches('}').to_owned(),
            ),
            (
                "an oversized document",
                INITIATOR_PEER_PLAN_DOCUMENT
                    .replace(ENDPOINT_HOST, &"a".repeat(MAX_PLAN_DOCUMENT_BYTES)),
            ),
            (
                "an oversized link document",
                LINK_PLAN_DOCUMENT.replace("listener", &"a".repeat(MAX_PLAN_DOCUMENT_BYTES)),
            ),
            (
                "a document that is only its operation",
                r#"{"operation":"prepare_link"}"#.to_owned(),
            ),
            (
                "a document whose operation belongs to schema 1",
                r#"{"operation":"deploy_oci_probe"}"#.to_owned(),
            ),
            (
                "a document whose operation belongs to schema 2",
                r#"{"operation":"publish_route"}"#.to_owned(),
            ),
        ] {
            assert_eq!(
                decode_plan_v3_document(document.as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }
    }

    /// The two older schemas stay exactly where they were.
    ///
    /// A probe plan and a public profile plan decode and hash as they always
    /// did, and no decoder accepts a document of another schema: the version is
    /// not a hint, it selects which closed contract the document is held
    /// against.
    #[test]
    fn the_three_schemas_refuse_one_another() {
        for document in [
            LINK_PLAN_DOCUMENT,
            LINK_ROLLBACK_DOCUMENT,
            LISTENER_PEER_PLAN_DOCUMENT,
            LISTENER_PEER_ROLLBACK_DOCUMENT,
            INITIATOR_PEER_PLAN_DOCUMENT,
            INITIATOR_PEER_ROLLBACK_DOCUMENT,
        ] {
            assert_eq!(
                crate::plan::decode_plan_document(document.as_bytes()),
                Err(ProtocolError::InvalidInput),
                "the schema 1 decoder accepted a schema 3 document"
            );
            assert_eq!(
                decode_plan_v2_document(document.as_bytes()),
                Err(ProtocolError::InvalidInput),
                "the schema 2 decoder accepted a schema 3 document"
            );
        }
        assert!(crate::plan::decode_plan_document(PROBE_PLAN_DOCUMENT.as_bytes()).is_ok());
        assert!(decode_plan_v2_document(ROUTE_PLAN_DOCUMENT.as_bytes()).is_ok());
        for older in [PROBE_PLAN_DOCUMENT, ROUTE_PLAN_DOCUMENT] {
            assert_eq!(
                decode_plan_v3_document(older.as_bytes()),
                Err(ProtocolError::InvalidInput),
                "the schema 3 decoder accepted a document of an older schema"
            );
        }
        assert_ne!(
            PLAN_V3_TRANSCRIPT_DOMAIN,
            crate::plan::PLAN_TRANSCRIPT_DOMAIN
        );
        assert_ne!(
            PLAN_V3_TRANSCRIPT_DOMAIN,
            crate::plan_v2::PLAN_V2_TRANSCRIPT_DOMAIN
        );
        assert_ne!(PLAN_V3_SCHEMA_VERSION, crate::plan::PLAN_SCHEMA_VERSION);
        assert_ne!(
            PLAN_V3_SCHEMA_VERSION,
            crate::plan_v2::PLAN_V2_SCHEMA_VERSION
        );
    }

    /// The exact limit of what a transport may do: reshape the JSON, and only
    /// that. The digest is rebuilt from the fields, so a reindented, reordered
    /// document is the same plan, and a document with one value changed is not.
    #[test]
    fn a_reindented_document_is_the_same_plan() {
        for (reshaped, digest) in [
            (
                format!(
                    "{{\n  \"link_role\": \"listener\",\n  \"operation\": \"prepare_link\",\n  \
                     \"machine_id\": \"{MACHINE}\",\n  \
                     \"infrastructure_id\": \"{INFRASTRUCTURE}\",\n  \"schema_version\": 3\n}}"
                ),
                LINK_PLAN_SHA256,
            ),
            (
                format!(
                    "{{\n  \"service_port\": {PORT},\n  \
                     \"peer_public_key\": \"{PEER_PUBLIC_KEY}\",\n  \
                     \"operation\": \"attach_link_peer\",\n  \"machine_id\": \"{MACHINE}\",\n  \
                     \"infrastructure_id\": \"{INFRASTRUCTURE}\",\n  \"schema_version\": 3\n}}"
                ),
                LISTENER_PEER_PLAN_SHA256,
            ),
            (
                format!(
                    "{{\n  \"service_port\": {PORT},\n  \
                     \"peer_endpoint_host\": \"{ENDPOINT_HOST}\",\n  \
                     \"peer_public_key\": \"{PEER_PUBLIC_KEY}\",\n  \
                     \"operation\": \"join_link_peer\",\n  \"machine_id\": \"{MACHINE}\",\n  \
                     \"infrastructure_id\": \"{INFRASTRUCTURE}\",\n  \"schema_version\": 3\n}}"
                ),
                INITIATOR_PEER_PLAN_SHA256,
            ),
        ] {
            let reordered = decode_plan_v3_document(reshaped.as_bytes())
                .expect("a reindented document is the same plan");
            assert_eq!(reordered.sha256().unwrap(), digest);
            assert_eq!(
                verify_plan_v3_document(reshaped.as_bytes(), digest).unwrap(),
                reordered
            );
        }
    }

    /// A plan is only ever accepted beside the digest it really has.
    #[test]
    fn verification_refuses_a_document_its_digest_does_not_name() {
        assert_eq!(
            verify_plan_v3_document(LINK_PLAN_DOCUMENT.as_bytes(), LINK_PLAN_SHA256).unwrap(),
            decode_plan_v3_document(LINK_PLAN_DOCUMENT.as_bytes()).unwrap()
        );
        assert_eq!(
            verify_plan_v3_document(
                INITIATOR_PEER_ROLLBACK_DOCUMENT.as_bytes(),
                INITIATOR_PEER_ROLLBACK_SHA256
            )
            .unwrap()
            .operation(),
            PlanV3Operation::LeaveLinkPeer
        );

        let upper_case_digest = LINK_PLAN_SHA256.to_ascii_uppercase();
        for (name, document, expected) in [
            (
                "the rollback presented under the plan digest",
                LINK_ROLLBACK_DOCUMENT,
                LINK_PLAN_SHA256,
            ),
            (
                "the plan presented under the rollback digest",
                LINK_PLAN_DOCUMENT,
                LINK_ROLLBACK_SHA256,
            ),
            (
                "a plan presented under the digest of another group",
                LINK_PLAN_DOCUMENT,
                LISTENER_PEER_PLAN_SHA256,
            ),
            (
                "a junction presented under the digest of the other side",
                LISTENER_PEER_PLAN_DOCUMENT,
                INITIATOR_PEER_PLAN_SHA256,
            ),
            (
                "an upper-case digest",
                LINK_PLAN_DOCUMENT,
                upper_case_digest.as_str(),
            ),
            ("a truncated digest", LINK_PLAN_DOCUMENT, "0957"),
            ("an empty digest", LINK_PLAN_DOCUMENT, ""),
        ] {
            assert_eq!(
                verify_plan_v3_document(document.as_bytes(), expected),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }
    }

    /// What makes a rollback a plan rather than a promise, in each of the three
    /// groups: `withdraw_link` for `prepare_link`, `detach_link_peer` for
    /// `attach_link_peer`, `leave_link_peer` for `join_link_peer`.
    #[test]
    fn a_rollback_is_recognised_only_when_it_undoes_exactly_the_plan() {
        let link_plan = decode_plan_v3_document(LINK_PLAN_DOCUMENT.as_bytes()).unwrap();
        let link_rollback = decode_plan_v3_document(LINK_ROLLBACK_DOCUMENT.as_bytes()).unwrap();
        let listener_plan =
            decode_plan_v3_document(LISTENER_PEER_PLAN_DOCUMENT.as_bytes()).unwrap();
        let listener_rollback =
            decode_plan_v3_document(LISTENER_PEER_ROLLBACK_DOCUMENT.as_bytes()).unwrap();
        let initiator_plan =
            decode_plan_v3_document(INITIATOR_PEER_PLAN_DOCUMENT.as_bytes()).unwrap();
        let initiator_rollback =
            decode_plan_v3_document(INITIATOR_PEER_ROLLBACK_DOCUMENT.as_bytes()).unwrap();

        for (plan, rollback) in [
            (&link_plan, &link_rollback),
            (&listener_plan, &listener_rollback),
            (&initiator_plan, &initiator_rollback),
        ] {
            assert!(plan.is_undone_by(rollback));
            assert!(rollback.is_undone_by(plan));
            assert_ne!(plan.sha256().unwrap(), rollback.sha256().unwrap());
            // A second copy of the plan undoes nothing.
            assert!(!plan.is_undone_by(plan));
        }

        // A document of another operation group is never an undoing, whatever it
        // names: the junction of one side is not the junction of the other.
        assert!(!listener_rollback.is_undone_by(&link_plan));
        assert!(!link_rollback.is_undone_by(&listener_plan));
        assert!(!initiator_rollback.is_undone_by(&listener_plan));
        assert!(!listener_rollback.is_undone_by(&initiator_plan));

        for forged in [
            LinkPlanDocumentV3 {
                machine_id: "lab-machine-2".into(),
                ..link().inverted()
            },
            LinkPlanDocumentV3 {
                infrastructure_id: OTHER_INFRASTRUCTURE.into(),
                ..link().inverted()
            },
            LinkPlanDocumentV3 {
                link_role: LinkRole::Initiator,
                ..link().inverted()
            },
            LinkPlanDocumentV3 {
                operation: PlanV3Operation::PrepareLink,
                ..link().inverted()
            },
        ] {
            assert!(
                !link().is_undone_by(&forged),
                "a rollback that targets another instance is not a rollback"
            );
        }

        for forged in [
            InitiatorPeerPlanDocumentV3 {
                peer_public_key: OTHER_PEER_PUBLIC_KEY.into(),
                ..initiator_peer().inverted()
            },
            InitiatorPeerPlanDocumentV3 {
                peer_endpoint_host: "other.lab.your-cloud.test".into(),
                ..initiator_peer().inverted()
            },
            InitiatorPeerPlanDocumentV3 {
                service_port: PORT + 1,
                ..initiator_peer().inverted()
            },
            InitiatorPeerPlanDocumentV3 {
                operation: PlanV3Operation::JoinLinkPeer,
                ..initiator_peer().inverted()
            },
        ] {
            assert!(
                !initiator_peer().is_undone_by(&forged),
                "a rollback that targets another junction is not a rollback"
            );
        }

        assert!(!listener_peer().is_undone_by(&ListenerPeerPlanDocumentV3 {
            peer_public_key: OTHER_PEER_PUBLIC_KEY.into(),
            ..listener_peer().inverted()
        }));
    }

    /// The decisions of the contract, kept testable rather than merely written.
    ///
    /// The subnet, the two tunnel addresses, the interface name, the listening
    /// port and the keepalive are constants of the reference scenario. None of
    /// them is an approvable value, so none of them may appear as a field of any
    /// schema 3 document — and the wire vectors above are what that is held
    /// against.
    #[test]
    fn the_constants_of_the_private_passage_are_not_fields_of_any_plan() {
        for document in [
            LINK_PLAN_DOCUMENT,
            LISTENER_PEER_PLAN_DOCUMENT,
            INITIATOR_PEER_PLAN_DOCUMENT,
        ] {
            let wire: serde_json::Value = serde_json::from_str(document).unwrap();
            let fields = wire.as_object().unwrap();
            for forbidden in [
                "allowed_ips",
                "interface",
                "listen_port",
                "keepalive_seconds",
                "private_key",
                "address",
                "subnet",
                "peer_endpoint_port",
                "nftables",
            ] {
                assert!(
                    !fields.contains_key(forbidden),
                    "a document carries {forbidden}, which is a constant of the contract"
                );
            }
        }

        assert_eq!(LINK_INTERFACE_NAME, "yc-link0");
        assert!(
            LINK_INTERFACE_NAME.len() <= 15,
            "an interface name is bounded to fifteen bytes"
        );
        assert_eq!(LINK_LISTENER_TUNNEL_ADDRESS, "10.66.66.1");
        assert_eq!(LINK_INITIATOR_TUNNEL_ADDRESS, "10.66.66.2");
        assert_ne!(LINK_LISTENER_TUNNEL_ADDRESS, LINK_INITIATOR_TUNNEL_ADDRESS);
        assert_eq!(LINK_LISTEN_PORT, 51_820);
        assert_eq!(LINK_KEEPALIVE_SECONDS, 25);
        assert_eq!(LINK_NFTABLES_TABLE, "inet your-cloud-link");
        assert_eq!(
            LinkRole::Listener.tunnel_address(),
            LINK_LISTENER_TUNNEL_ADDRESS
        );
        assert_eq!(
            LinkRole::Initiator.tunnel_address(),
            LINK_INITIATOR_TUNNEL_ADDRESS
        );

        // The one port a plan may name is a loopback port of a managed service,
        // and it is bounded by the very range the two older schemas already
        // read: the passage carries a port a service could be listening on, and
        // nothing wider.
        assert_eq!(MIN_PLAN_SERVICE_PORT, MIN_PLAN_LOCAL_PORT);
        assert_eq!(MAX_PLAN_SERVICE_PORT, MAX_PLAN_LOCAL_PORT);

        const DECLARED: [PlanV3Operation; 6] = [
            PlanV3Operation::PrepareLink,
            PlanV3Operation::WithdrawLink,
            PlanV3Operation::AttachLinkPeer,
            PlanV3Operation::DetachLinkPeer,
            PlanV3Operation::JoinLinkPeer,
            PlanV3Operation::LeaveLinkPeer,
        ];
        let mut names: Vec<&str> = Vec::new();
        for operation in DECLARED {
            assert_eq!(operation.inverse().inverse(), operation);
            assert_ne!(operation.inverse(), operation);
            assert_eq!(
                operation.inverse().group(),
                operation.group(),
                "{operation:?} and its undoing do not carry the same fields"
            );
            assert_eq!(
                serde_json::to_value(operation).unwrap(),
                serde_json::json!(operation.as_str())
            );
            assert!(!names.contains(&operation.as_str()));
            names.push(operation.as_str());
        }
        assert_eq!(
            names,
            [
                "prepare_link",
                "withdraw_link",
                "attach_link_peer",
                "detach_link_peer",
                "join_link_peer",
                "leave_link_peer",
            ]
        );

        // The role is closed to two entries, and neither of them is the wire
        // name of anything else this palier reads.
        const ROLES: [LinkRole; 2] = [LinkRole::Listener, LinkRole::Initiator];
        let mut role_names: Vec<&str> = Vec::new();
        for role in ROLES {
            assert_eq!(
                serde_json::to_value(role).unwrap(),
                serde_json::json!(role.as_str())
            );
            assert!(!role_names.contains(&role.as_str()));
            assert!(!names.contains(&role.as_str()));
            role_names.push(role.as_str());
        }
        assert_eq!(role_names, ["listener", "initiator"]);
    }
}
