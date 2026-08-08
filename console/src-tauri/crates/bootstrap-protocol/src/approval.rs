//! The one envelope a human approval is, and the exact bytes it is signed over.
//!
//! An approval crosses a machine the Console does not control: the Controller
//! builds the plan, carries the envelope and hands it to the Auxiliary. This
//! module exists so that carrying it is all the Controller can do. It is built
//! around three properties, and each of them is a property of the *encoding*
//! rather than a promise made by a caller.
//!
//! **Everything the approval means is inside the signed bytes.** The transcript
//! below covers the infrastructure, the machine, the authority epoch, the exact
//! sequence, the operation, the digest of the plan and the digest of its
//! rollback, the privileges, the moment of issue, the expiry and the public key
//! that is supposed to verify it. Nothing an approval means is left outside, so
//! there is no field a transport can rewrite and no field it can leave out.
//!
//! **The encoding admits exactly one reading.** Every variable-length value is
//! written under its own big-endian length, every number is written at a fixed
//! width, and the privilege list is written under its own count. Two different
//! envelopes therefore cannot produce the same transcript by moving a byte from
//! one field into the next, which is what makes "one changed field, one broken
//! signature" a fact rather than an intention.
//!
//! **There is no signing here at all.** This crate has no signature primitive
//! and no key type. It turns a validated envelope into bytes; the Console core
//! is the only place that owns a private key, and the Auxiliary is the only
//! place that verifies. A transcript is useless to whoever cannot sign it.

use crate::ProtocolError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

pub const APPROVAL_SCHEMA_VERSION: u8 = 1;

/// Domain separator of this transcript, terminated by a byte no textual field
/// may contain. A signature produced here can therefore never be replayed as a
/// signature of the pairing, session or recovery transcripts of the Console,
/// which carry their own separator under the same key.
pub const APPROVAL_TRANSCRIPT_DOMAIN: &[u8] = b"your-cloud/approval-envelope.v1\0";

pub const APPROVAL_DIGEST_BYTES: usize = 32;
pub const APPROVAL_DIGEST_ENCODED_BYTES: usize = APPROVAL_DIGEST_BYTES * 2;
pub const APPROVAL_PUBLIC_KEY_BYTES: usize = 32;
pub const APPROVAL_SIGNATURE_BYTES: usize = 64;

/// Longest identifier of a machine, as the product's own validator spells it.
pub const MAX_APPROVAL_MACHINE_BYTES: usize = 63;
/// Exact length of the canonical textual form of a version 4 UUID.
pub const APPROVAL_INFRASTRUCTURE_BYTES: usize = 36;

/// Most privileges one envelope may carry. The closed set below has two
/// members, so a list longer than two repeats one of them.
pub const MAX_APPROVAL_PRIVILEGES: usize = 2;

/// Longest life an approval may be given, in seconds.
///
/// It is deliberately short. An approval is consumed once, immediately after
/// the human confirmed it, and a window measured in hours would only widen the
/// period during which a captured envelope is still worth stealing.
pub const MAX_APPROVAL_LIFETIME_SECONDS: u64 = 900;

/// Largest signed approval document the Auxiliary reads before parsing it.
///
/// The envelope is a fixed set of bounded fields, so this is not a policy: it
/// is the size the fields below can actually reach, rounded up once.
pub const MAX_SIGNED_APPROVAL_BYTES: usize = 1_024;

/// What an approval authorises. The list is closed, and every member names its
/// own exact privileges below.
///
/// [`Self::DiagnoseProtocolReadOnly`] is the protocol diagnostic of the
/// previous palier: it states what it verified and what it consumed, and it
/// changes nothing. The two probe operations are the first ones that ask to
/// change a machine, the six operations of the public profile are the ones that
/// describe a service, an entrypoint and a published route, the six operations
/// of the private passage are the ones that describe one machine's own side of a
/// link and the two junctions that bound it, and the seven operations of the
/// private profile are the ones that describe a service whose data outlives its
/// container, the name that publishes it through the passage, and the archives
/// of its data, and the two operations of the third door are the ones that
/// describe a service whose definition its user wrote. Each of them belongs to an
/// exact pair of a plan and its
/// rollback — what each describes is the plan document whose digest the envelope
/// names, never anything the envelope itself could spell. An operation name
/// outside this list has no variant, so an envelope naming an installation, an
/// arbitrary container or an operation of a later palier is refused while it is
/// still being parsed.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOperation {
    DiagnoseProtocolReadOnly,
    DeployOciProbe,
    RemoveOciProbe,
    DeployWebService,
    RemoveWebService,
    DeployEntrypoint,
    RemoveEntrypoint,
    PublishRoute,
    RetireRoute,
    PrepareLink,
    WithdrawLink,
    AttachLinkPeer,
    DetachLinkPeer,
    JoinLinkPeer,
    LeaveLinkPeer,
    DeployPrivateService,
    RemovePrivateService,
    PublishLinkRoute,
    RetireLinkRoute,
    SnapshotService,
    DiscardSnapshot,
    RestoreService,
    /// The two operations of the third door. Both mutate, both are described by
    /// a plan document of schema 2 whose digest this envelope signs, and both are
    /// named in the same closed list as the others rather than derived from
    /// anything: an operation an Auxiliary may act on is a decision written once,
    /// in a list a reader can count.
    ///
    /// They are the first operations of the product whose effects are described
    /// by a document its user wrote. That changes nothing here: this envelope
    /// decides that a human approved two digests for one operation, and it has
    /// never known what those digests cover.
    DeployUserService,
    RemoveUserService,
}

impl ApprovalOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DiagnoseProtocolReadOnly => "diagnose_protocol_read_only",
            Self::DeployOciProbe => "deploy_oci_probe",
            Self::RemoveOciProbe => "remove_oci_probe",
            Self::DeployWebService => "deploy_web_service",
            Self::RemoveWebService => "remove_web_service",
            Self::DeployEntrypoint => "deploy_entrypoint",
            Self::RemoveEntrypoint => "remove_entrypoint",
            Self::PublishRoute => "publish_route",
            Self::RetireRoute => "retire_route",
            Self::PrepareLink => "prepare_link",
            Self::WithdrawLink => "withdraw_link",
            Self::AttachLinkPeer => "attach_link_peer",
            Self::DetachLinkPeer => "detach_link_peer",
            Self::JoinLinkPeer => "join_link_peer",
            Self::LeaveLinkPeer => "leave_link_peer",
            Self::DeployPrivateService => "deploy_private_service",
            Self::RemovePrivateService => "remove_private_service",
            Self::PublishLinkRoute => "publish_link_route",
            Self::RetireLinkRoute => "retire_link_route",
            Self::SnapshotService => "snapshot_service",
            Self::DiscardSnapshot => "discard_snapshot",
            Self::RestoreService => "restore_service",
            Self::DeployUserService => "deploy_user_service",
            Self::RemoveUserService => "remove_user_service",
        }
    }

    /// The exact privilege list this operation may ever be approved with.
    ///
    /// It is an equality rather than a maximum: an envelope that asks for less
    /// than its operation needs, or for more, is not a narrower or a wider
    /// approval, it is an envelope this palier does not recognise. Every
    /// operation that describes a state of a machine asks for the same pair,
    /// including the removals and the retirement: undoing has to read the
    /// machine to find the instance it names before it changes anything, and
    /// retiring a route rewrites the entrypoint's fragments exactly as
    /// publishing one does. The six operations of the private passage are in the
    /// same list for the same reason — withdrawing a link and leaving a peer
    /// read the machine to find what they are about to remove, and preparing a
    /// link reads it to refuse regenerating a key that already exists. The seven
    /// of the private profile are there too, and the archives are the case worth
    /// naming: a snapshot stops the service, writes an archive and restarts it,
    /// so it mutates the machine as much as a deployment does, whatever the word
    /// "backup" suggests. The two of the third door are there too: a user service
    /// is deployed and removed by the very machinery the delivered profiles use,
    /// so its operations mutate exactly as theirs do.
    pub fn required_privileges(self) -> &'static [ApprovalPrivilege] {
        match self {
            Self::DiagnoseProtocolReadOnly => &[ApprovalPrivilege::ReadLocalState],
            Self::DeployOciProbe
            | Self::RemoveOciProbe
            | Self::DeployWebService
            | Self::RemoveWebService
            | Self::DeployEntrypoint
            | Self::RemoveEntrypoint
            | Self::PublishRoute
            | Self::RetireRoute
            | Self::PrepareLink
            | Self::WithdrawLink
            | Self::AttachLinkPeer
            | Self::DetachLinkPeer
            | Self::JoinLinkPeer
            | Self::LeaveLinkPeer
            | Self::DeployPrivateService
            | Self::RemovePrivateService
            | Self::PublishLinkRoute
            | Self::RetireLinkRoute
            | Self::SnapshotService
            | Self::DiscardSnapshot
            | Self::RestoreService
            | Self::DeployUserService
            | Self::RemoveUserService => &[
                ApprovalPrivilege::MutateLocalState,
                ApprovalPrivilege::ReadLocalState,
            ],
        }
    }
}

/// What an operation is allowed to do to the machine it runs on.
///
/// The declaration order is the canonical order of the set, and it is the order
/// of the wire names rather than a taste: the Auxiliary holds the list to being
/// strictly increasing by comparing the names it parsed, so an order chosen
/// here that did not match theirs would produce envelopes this side signs and
/// the other side refuses. The test suite of this module holds the two against
/// one another rather than trusting the reading.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalPrivilege {
    /// Changing the machine. Every operation that describes a state requires
    /// it, and [`ApprovalOperation::DiagnoseProtocolReadOnly`] keeps refusing
    /// it: the read-only diagnostic of the previous palier stays the one
    /// approval that cannot change anything.
    MutateLocalState,
    /// Reading what the machine already holds, and nothing else.
    ReadLocalState,
}

impl ApprovalPrivilege {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadLocalState => "read_local_state",
            Self::MutateLocalState => "mutate_local_state",
        }
    }

    /// Whether this privilege may change the machine it is granted on.
    pub fn is_mutating(self) -> bool {
        matches!(self, Self::MutateLocalState)
    }
}

/// Everything one approval binds together.
///
/// Every field of this structure is covered by [`Self::signing_transcript`].
/// A field that were added here and forgotten there would be a field the
/// Controller could choose, so the test suite of this module holds the two
/// against each other field by field rather than trusting the reading.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalEnvelopeV1 {
    pub schema_version: u8,
    /// The infrastructure this approval belongs to, as a canonical UUIDv4.
    pub infrastructure_id: String,
    /// The one machine this approval may be presented to.
    pub machine_id: String,
    /// The authority epoch the approval key belongs to. Activating a new epoch
    /// on a machine invalidates the previous one instead of keeping two
    /// signers, so this is what separates a rotated Console from a forged one.
    pub approval_epoch: u64,
    /// The exact successor the target must be at. It is never a hint: the
    /// Auxiliary accepts this number or refuses the envelope.
    pub sequence: u64,
    pub operation: ApprovalOperation,
    /// SHA-256 of the plan, lower-case hexadecimal.
    pub plan_sha256: String,
    /// SHA-256 of the rollback of that same plan, lower-case hexadecimal. It is
    /// bound beside the plan because an approval that covered only the forward
    /// step would leave the return path unapproved.
    pub rollback_sha256: String,
    /// Strictly increasing, therefore free of repetition and of ordering.
    pub privileges: Vec<ApprovalPrivilege>,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    /// The key that must verify this envelope, raw-URL base64 of 32 bytes.
    ///
    /// Naming it inside the signed bytes is what stops one envelope from being
    /// presented under somebody else's anchor: the Auxiliary compares this to
    /// the key its own root-owned anchor names, and a mismatch is refused
    /// before the signature is even worth checking.
    pub approval_public_key: String,
}

impl ApprovalEnvelopeV1 {
    /// Accepts only an envelope whose every field is inside its own bounds and
    /// whose privileges are exactly the ones its operation requires.
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if self.schema_version != APPROVAL_SCHEMA_VERSION
            || !canonical_uuid_v4(&self.infrastructure_id)
            || !canonical_machine_id(&self.machine_id)
            || self.approval_epoch == 0
            || self.sequence == 0
            || !canonical_digest(&self.plan_sha256)
            || !canonical_digest(&self.rollback_sha256)
            || !canonical_privileges(&self.privileges)
            || self.privileges != self.operation.required_privileges()
            || !canonical_lifetime(self.issued_at_unix_seconds, self.expires_at_unix_seconds)
            || decode_raw_url(&self.approval_public_key, APPROVAL_PUBLIC_KEY_BYTES).is_none()
        {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(self)
    }

    /// The exact bytes a human approval is signed over.
    ///
    /// The layout is the one the Auxiliary rebuilds from the fields it parsed,
    /// never from the document it received: two spellings of the same JSON
    /// therefore produce one transcript, and a document whose bytes were
    /// rearranged in transport verifies exactly as long as its fields are
    /// unchanged.
    pub fn signing_transcript(&self) -> Result<Vec<u8>, ProtocolError> {
        let public_key = decode_raw_url(&self.approval_public_key, APPROVAL_PUBLIC_KEY_BYTES)
            .ok_or(ProtocolError::InvalidInput)?;
        let plan = decode_digest(&self.plan_sha256).ok_or(ProtocolError::InvalidInput)?;
        let rollback = decode_digest(&self.rollback_sha256).ok_or(ProtocolError::InvalidInput)?;
        let privilege_count =
            u32::try_from(self.privileges.len()).map_err(|_| ProtocolError::InvalidInput)?;

        let mut transcript = Vec::with_capacity(APPROVAL_TRANSCRIPT_DOMAIN.len() + 256);
        transcript.extend_from_slice(APPROVAL_TRANSCRIPT_DOMAIN);
        transcript.extend_from_slice(&self.schema_version.to_be_bytes());
        append_field(&mut transcript, self.infrastructure_id.as_bytes())?;
        append_field(&mut transcript, self.machine_id.as_bytes())?;
        transcript.extend_from_slice(&self.approval_epoch.to_be_bytes());
        transcript.extend_from_slice(&self.sequence.to_be_bytes());
        append_field(&mut transcript, self.operation.as_str().as_bytes())?;
        append_field(&mut transcript, &plan)?;
        append_field(&mut transcript, &rollback)?;
        transcript.extend_from_slice(&privilege_count.to_be_bytes());
        for privilege in &self.privileges {
            append_field(&mut transcript, privilege.as_str().as_bytes())?;
        }
        transcript.extend_from_slice(&self.issued_at_unix_seconds.to_be_bytes());
        transcript.extend_from_slice(&self.expires_at_unix_seconds.to_be_bytes());
        append_field(&mut transcript, &public_key)?;
        Ok(transcript)
    }

    /// The 32 raw bytes of the key this envelope must be verified with.
    pub fn approval_public_key_bytes(
        &self,
    ) -> Result<[u8; APPROVAL_PUBLIC_KEY_BYTES], ProtocolError> {
        let decoded = decode_raw_url(&self.approval_public_key, APPROVAL_PUBLIC_KEY_BYTES)
            .ok_or(ProtocolError::InvalidInput)?;
        decoded.try_into().map_err(|_| ProtocolError::InvalidInput)
    }

    /// Whether this envelope asks for anything that could change the machine.
    pub fn is_mutating(&self) -> bool {
        self.privileges
            .iter()
            .any(|privilege| privilege.is_mutating())
    }
}

/// An envelope and the signature that covers it, which is the whole document
/// the Controller transports.
///
/// The signature is deliberately outside [`ApprovalEnvelopeV1`]: what is signed
/// and what signs it are two different things, and keeping them apart in the
/// type removes the question of whether the signature covers itself.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApprovalV1 {
    pub envelope: ApprovalEnvelopeV1,
    /// Raw-URL base64 of the 64 signature bytes.
    pub signature: String,
}

impl SignedApprovalV1 {
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if decode_raw_url(&self.signature, APPROVAL_SIGNATURE_BYTES).is_none() {
            return Err(ProtocolError::InvalidInput);
        }
        let envelope = self.envelope.validate()?;
        Ok(Self {
            envelope,
            signature: self.signature,
        })
    }

    pub fn signature_bytes(&self) -> Result<[u8; APPROVAL_SIGNATURE_BYTES], ProtocolError> {
        let decoded = decode_raw_url(&self.signature, APPROVAL_SIGNATURE_BYTES)
            .ok_or(ProtocolError::InvalidInput)?;
        decoded.try_into().map_err(|_| ProtocolError::InvalidInput)
    }
}

/// Written under its own big-endian length, which is what keeps two adjacent
/// fields from being read as one. The plan transcript beside this one is built
/// out of the very same primitive rather than out of a copy of it.
pub(crate) fn append_field(buffer: &mut Vec<u8>, value: &[u8]) -> Result<(), ProtocolError> {
    let length = u32::try_from(value.len()).map_err(|_| ProtocolError::InvalidInput)?;
    buffer.extend_from_slice(&length.to_be_bytes());
    buffer.extend_from_slice(value);
    Ok(())
}

/// Strictly increasing, which refuses a repeated privilege and every ordering
/// but one. Two envelopes that grant the same set therefore have the same
/// bytes, and a transport cannot produce a second valid document by permuting
/// the list of a first.
fn canonical_privileges(privileges: &[ApprovalPrivilege]) -> bool {
    if privileges.is_empty() || privileges.len() > MAX_APPROVAL_PRIVILEGES {
        return false;
    }
    privileges.windows(2).all(|pair| pair[0] < pair[1])
}

/// An issue time strictly before an expiry, no further from it than the
/// declared ceiling. A zero issue time is refused: an approval that claims to
/// predate the epoch is not an approval whose expiry means anything.
fn canonical_lifetime(issued_at: u64, expires_at: u64) -> bool {
    issued_at != 0
        && expires_at > issued_at
        && expires_at - issued_at <= MAX_APPROVAL_LIFETIME_SECONDS
}

/// The canonical textual form of a version 4 UUID, lower-case, and nothing that
/// merely parses as one.
///
/// A plan names the same infrastructure as the envelope that will name its
/// digest, so it reads that identifier through this very function: two spellings
/// of "canonical" would eventually accept a plan the envelope refuses.
pub(crate) fn canonical_uuid_v4(value: &str) -> bool {
    if value.len() != APPROVAL_INFRASTRUCTURE_BYTES || !value.is_ascii() {
        return false;
    }
    let bytes = value.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        let expected_dash = matches!(index, 8 | 13 | 18 | 23);
        if expected_dash {
            if *byte != b'-' {
                return false;
            }
            continue;
        }
        if !byte.is_ascii_digit() && !(b'a'..=b'f').contains(byte) {
            return false;
        }
    }
    bytes[14] == b'4' && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

/// The identifier a machine is named by, spelled exactly as the product's own
/// validator spells it: lower-case, three to sixty-three bytes, starting on an
/// alphanumeric and carrying nothing that could ever mean a path. A plan names
/// its one machine through the same reader, for the same reason.
pub(crate) fn canonical_machine_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 3 || bytes.len() > MAX_APPROVAL_MACHINE_BYTES || !value.is_ascii() {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn canonical_digest(value: &str) -> bool {
    decode_digest(value).is_some()
}

/// Lower-case hexadecimal of exactly the digest length, and no other spelling
/// of the same number. The plan side reads both the digest an envelope names
/// and the digest an image is pinned by through this same reader.
pub(crate) fn decode_digest(value: &str) -> Option<[u8; APPROVAL_DIGEST_BYTES]> {
    if value.len() != APPROVAL_DIGEST_ENCODED_BYTES || !value.is_ascii() {
        return None;
    }
    let mut decoded = [0_u8; APPROVAL_DIGEST_BYTES];
    for (index, slot) in decoded.iter_mut().enumerate() {
        let high = hex_value(value.as_bytes()[index * 2])?;
        let low = hex_value(value.as_bytes()[index * 2 + 1])?;
        *slot = (high << 4) | low;
    }
    Some(decoded)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Raw-URL base64 of exactly the expected length, refusing padding, the
/// standard alphabet and every non-canonical spelling of the same bytes.
fn decode_raw_url(value: &str, expected_bytes: usize) -> Option<Vec<u8>> {
    if !value.is_ascii() {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(value.as_bytes()).ok()?;
    if decoded.len() != expected_bytes || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return None;
    }
    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFRASTRUCTURE: &str = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2";
    const MACHINE: &str = "lab-machine-1";
    /// SHA-256 of the plan document of the shared vector, `diagnose protocol
    /// read only`, and of its rollback, `no change to roll back`. The Console
    /// core hashes those very bytes in `src/approval.rs`, and the Auxiliary
    /// pins the same two digests in `internal/approval/envelope_test.go`.
    const PLAN: &str = "0057dd53cc58e914bba328007203c36bfc9f1ebb375a0b150abdddfd0f7eee9b";
    const ROLLBACK: &str = "0300401c8e3a5f90cd887fcb2a6c0ce0d35afd2c1a247f654162c275da00dcf1";
    /// Public key of the all-`0x01` seed. It is the counterpart of the vector
    /// pinned in `internal/approval/envelope_test.go`; the two must stay equal.
    const PUBLIC_KEY: &str = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w";

    fn envelope() -> ApprovalEnvelopeV1 {
        ApprovalEnvelopeV1 {
            schema_version: APPROVAL_SCHEMA_VERSION,
            infrastructure_id: INFRASTRUCTURE.into(),
            machine_id: MACHINE.into(),
            approval_epoch: 1,
            sequence: 1,
            operation: ApprovalOperation::DiagnoseProtocolReadOnly,
            plan_sha256: PLAN.into(),
            rollback_sha256: ROLLBACK.into(),
            privileges: vec![ApprovalPrivilege::ReadLocalState],
            issued_at_unix_seconds: 1_780_000_000,
            expires_at_unix_seconds: 1_780_000_300,
            approval_public_key: PUBLIC_KEY.into(),
        }
    }

    #[test]
    fn a_nominal_envelope_is_accepted_and_encodes_once() {
        let validated = envelope().validate().expect("nominal envelope");
        let transcript = validated.signing_transcript().expect("nominal transcript");
        assert!(transcript.starts_with(APPROVAL_TRANSCRIPT_DOMAIN));
        assert_eq!(
            validated.signing_transcript().unwrap(),
            transcript,
            "one envelope must always produce the same bytes"
        );
        assert!(!validated.is_mutating());
    }

    /// The deterministic vector this palier is verified against on both sides.
    ///
    /// The same envelope is written in `internal/approval/envelope_test.go`,
    /// which asserts the same transcript length and the same hexadecimal
    /// prefix. Any divergence between the two encoders therefore turns one of
    /// the two suites red instead of producing a signature the other side
    /// silently refuses.
    #[test]
    fn the_deterministic_transcript_vector_is_pinned() {
        let transcript = envelope()
            .validate()
            .unwrap()
            .signing_transcript()
            .expect("vector transcript");
        assert_eq!(transcript.len(), 285);
        assert_eq!(
            hex_lower(&transcript),
            "796f75722d636c6f75642f617070726f76616c2d656e76656c6f70652e7631000100\
             00002438663134653435662d636565612d343136372d613862312d31663762643061\
             30663463320000000d6c61622d6d616368696e652d310000000000000001000000000\
             00000010000001b646961676e6f73655f70726f746f636f6c5f726561645f6f6e6c79\
             000000200057dd53cc58e914bba328007203c36bfc9f1ebb375a0b150abdddfd0f7eee\
             9b000000200300401c8e3a5f90cd887fcb2a6c0ce0d35afd2c1a247f654162c275da00\
             dcf10000000100000010726561645f6c6f63616c5f7374617465000000006a18a50000\
             0000006a18a62c000000208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121b\
             f3748801b40f6f5c"
                .replace(char::is_whitespace, "")
        );
    }

    /// Every field of the envelope is inside the signed bytes.
    ///
    /// The test does not read the transcript builder: it changes one field at a
    /// time and requires the bytes to move. A field that could be changed
    /// without moving them is a field a Controller owns, and this is the
    /// assertion that refuses to ship one.
    #[test]
    fn changing_any_single_field_changes_the_signed_bytes() {
        let reference = envelope().signing_transcript().unwrap();
        let mutations: Vec<(&str, ApprovalEnvelopeV1)> = vec![
            (
                "schema_version",
                ApprovalEnvelopeV1 {
                    schema_version: 2,
                    ..envelope()
                },
            ),
            (
                "infrastructure_id",
                ApprovalEnvelopeV1 {
                    infrastructure_id: "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3".into(),
                    ..envelope()
                },
            ),
            (
                "machine_id",
                ApprovalEnvelopeV1 {
                    machine_id: "lab-machine-2".into(),
                    ..envelope()
                },
            ),
            (
                "approval_epoch",
                ApprovalEnvelopeV1 {
                    approval_epoch: 2,
                    ..envelope()
                },
            ),
            (
                "sequence",
                ApprovalEnvelopeV1 {
                    sequence: 2,
                    ..envelope()
                },
            ),
            (
                "plan_sha256",
                ApprovalEnvelopeV1 {
                    plan_sha256: ROLLBACK.into(),
                    ..envelope()
                },
            ),
            (
                "rollback_sha256",
                ApprovalEnvelopeV1 {
                    rollback_sha256: PLAN.into(),
                    ..envelope()
                },
            ),
            (
                "privileges",
                ApprovalEnvelopeV1 {
                    privileges: vec![ApprovalPrivilege::MutateLocalState],
                    ..envelope()
                },
            ),
            (
                "issued_at_unix_seconds",
                ApprovalEnvelopeV1 {
                    issued_at_unix_seconds: 1_780_000_001,
                    ..envelope()
                },
            ),
            (
                "expires_at_unix_seconds",
                ApprovalEnvelopeV1 {
                    expires_at_unix_seconds: 1_780_000_299,
                    ..envelope()
                },
            ),
            (
                "approval_public_key",
                ApprovalEnvelopeV1 {
                    approval_public_key: URL_SAFE_NO_PAD.encode([9_u8; 32]),
                    ..envelope()
                },
            ),
            (
                "operation",
                ApprovalEnvelopeV1 {
                    operation: ApprovalOperation::DeployOciProbe,
                    ..envelope()
                },
            ),
        ];

        let mut covered: Vec<&str> = Vec::new();
        for (field, mutated) in mutations {
            assert_ne!(
                mutated.signing_transcript().unwrap(),
                reference,
                "{field} is outside the signed bytes"
            );
            covered.push(field);
        }

        // Every field the wire document carries is one of the ones just moved.
        // A field added to the structure and forgotten in the transcript fails
        // here rather than in production.
        let document = serde_json::to_value(envelope()).unwrap();
        let mut wire_fields: Vec<String> = document.as_object().unwrap().keys().cloned().collect();
        wire_fields.sort();
        let mut expected: Vec<String> = covered.iter().map(|name| (*name).to_owned()).collect();
        expected.sort();
        assert_eq!(wire_fields, expected);
    }

    /// Two spellings of the same document are the same approval.
    ///
    /// The Auxiliary rebuilds the transcript from the fields it parsed, so a
    /// Controller that reorders the JSON or reindents it transports the same
    /// approval. That is not a weakness: what it may not do is change a value,
    /// and the test above is what states that.
    #[test]
    fn the_transcript_is_rebuilt_from_fields_rather_than_from_the_document() {
        let document = serde_json::json!({
            "approval_public_key": PUBLIC_KEY,
            "expires_at_unix_seconds": 1_780_000_300_u64,
            "issued_at_unix_seconds": 1_780_000_000_u64,
            "privileges": ["read_local_state"],
            "rollback_sha256": ROLLBACK,
            "plan_sha256": PLAN,
            "operation": "diagnose_protocol_read_only",
            "sequence": 1,
            "approval_epoch": 1,
            "machine_id": MACHINE,
            "infrastructure_id": INFRASTRUCTURE,
            "schema_version": 1,
        });
        let reordered: ApprovalEnvelopeV1 = serde_json::from_value(document).unwrap();
        assert_eq!(
            reordered.validate().unwrap().signing_transcript().unwrap(),
            envelope().signing_transcript().unwrap()
        );
    }

    /// The twenty-four operations this palier's envelope may name, in
    /// declaration order. Holding the list in one place is what keeps the tests
    /// below from silently covering twenty-three of twenty-four.
    const DECLARED_OPERATIONS: [ApprovalOperation; 24] = [
        ApprovalOperation::DiagnoseProtocolReadOnly,
        ApprovalOperation::DeployOciProbe,
        ApprovalOperation::RemoveOciProbe,
        ApprovalOperation::DeployWebService,
        ApprovalOperation::RemoveWebService,
        ApprovalOperation::DeployEntrypoint,
        ApprovalOperation::RemoveEntrypoint,
        ApprovalOperation::PublishRoute,
        ApprovalOperation::RetireRoute,
        ApprovalOperation::PrepareLink,
        ApprovalOperation::WithdrawLink,
        ApprovalOperation::AttachLinkPeer,
        ApprovalOperation::DetachLinkPeer,
        ApprovalOperation::JoinLinkPeer,
        ApprovalOperation::LeaveLinkPeer,
        ApprovalOperation::DeployPrivateService,
        ApprovalOperation::RemovePrivateService,
        ApprovalOperation::PublishLinkRoute,
        ApprovalOperation::RetireLinkRoute,
        ApprovalOperation::SnapshotService,
        ApprovalOperation::DiscardSnapshot,
        ApprovalOperation::RestoreService,
        ApprovalOperation::DeployUserService,
        ApprovalOperation::RemoveUserService,
    ];

    /// The twenty-three operations that describe a state of a machine, which is
    /// every declared operation but the read-only diagnostic.
    const MUTATING_OPERATIONS: [ApprovalOperation; 23] = [
        ApprovalOperation::DeployOciProbe,
        ApprovalOperation::RemoveOciProbe,
        ApprovalOperation::DeployWebService,
        ApprovalOperation::RemoveWebService,
        ApprovalOperation::DeployEntrypoint,
        ApprovalOperation::RemoveEntrypoint,
        ApprovalOperation::PublishRoute,
        ApprovalOperation::RetireRoute,
        ApprovalOperation::PrepareLink,
        ApprovalOperation::WithdrawLink,
        ApprovalOperation::AttachLinkPeer,
        ApprovalOperation::DetachLinkPeer,
        ApprovalOperation::JoinLinkPeer,
        ApprovalOperation::LeaveLinkPeer,
        ApprovalOperation::DeployPrivateService,
        ApprovalOperation::RemovePrivateService,
        ApprovalOperation::PublishLinkRoute,
        ApprovalOperation::RetireLinkRoute,
        ApprovalOperation::SnapshotService,
        ApprovalOperation::DiscardSnapshot,
        ApprovalOperation::RestoreService,
        ApprovalOperation::DeployUserService,
        ApprovalOperation::RemoveUserService,
    ];

    #[test]
    fn wire_variants_are_fixed() {
        for (operation, wire_name) in [
            (
                ApprovalOperation::DiagnoseProtocolReadOnly,
                "diagnose_protocol_read_only",
            ),
            (ApprovalOperation::DeployOciProbe, "deploy_oci_probe"),
            (ApprovalOperation::RemoveOciProbe, "remove_oci_probe"),
            (ApprovalOperation::DeployWebService, "deploy_web_service"),
            (ApprovalOperation::RemoveWebService, "remove_web_service"),
            (ApprovalOperation::DeployEntrypoint, "deploy_entrypoint"),
            (ApprovalOperation::RemoveEntrypoint, "remove_entrypoint"),
            (ApprovalOperation::PublishRoute, "publish_route"),
            (ApprovalOperation::RetireRoute, "retire_route"),
            (ApprovalOperation::PrepareLink, "prepare_link"),
            (ApprovalOperation::WithdrawLink, "withdraw_link"),
            (ApprovalOperation::AttachLinkPeer, "attach_link_peer"),
            (ApprovalOperation::DetachLinkPeer, "detach_link_peer"),
            (ApprovalOperation::JoinLinkPeer, "join_link_peer"),
            (ApprovalOperation::LeaveLinkPeer, "leave_link_peer"),
            (
                ApprovalOperation::DeployPrivateService,
                "deploy_private_service",
            ),
            (
                ApprovalOperation::RemovePrivateService,
                "remove_private_service",
            ),
            (ApprovalOperation::PublishLinkRoute, "publish_link_route"),
            (ApprovalOperation::RetireLinkRoute, "retire_link_route"),
            (ApprovalOperation::SnapshotService, "snapshot_service"),
            (ApprovalOperation::DiscardSnapshot, "discard_snapshot"),
            (ApprovalOperation::RestoreService, "restore_service"),
            (ApprovalOperation::DeployUserService, "deploy_user_service"),
            (ApprovalOperation::RemoveUserService, "remove_user_service"),
        ] {
            assert_eq!(
                serde_json::to_value(operation).unwrap(),
                serde_json::json!(wire_name)
            );
            assert_eq!(operation.as_str(), wire_name);
        }

        // Every declared operation is one of the ones just named, and no two of
        // them share a wire name: an operation added to the enum and forgotten
        // in the table above fails here rather than travelling unnamed.
        let mut names: Vec<&str> = Vec::new();
        for operation in DECLARED_OPERATIONS {
            assert!(
                !names.contains(&operation.as_str()),
                "{operation:?} reuses a wire name"
            );
            names.push(operation.as_str());
        }
        assert_eq!(names.len(), 24);
        for (privilege, wire_name) in [
            (ApprovalPrivilege::ReadLocalState, "read_local_state"),
            (ApprovalPrivilege::MutateLocalState, "mutate_local_state"),
        ] {
            assert_eq!(
                serde_json::to_value(privilege).unwrap(),
                serde_json::json!(wire_name)
            );
            assert_eq!(privilege.as_str(), wire_name);
        }
        assert!(!ApprovalPrivilege::ReadLocalState.is_mutating());
        assert!(ApprovalPrivilege::MutateLocalState.is_mutating());
    }

    /// The canonical order of the privilege set is the order of the wire names.
    ///
    /// The Auxiliary holds a privilege list to being strictly increasing by
    /// comparing the strings it parsed. This side compares the variants. The
    /// two agree only while the declaration order below is the alphabetical
    /// order of the names, so that agreement is asserted rather than assumed:
    /// an order that drifted here would produce envelopes this side signs and
    /// the other side refuses, on every operation that mutates a machine.
    #[test]
    fn the_canonical_privilege_order_is_the_order_of_the_wire_names() {
        const DECLARED: [ApprovalPrivilege; MAX_APPROVAL_PRIVILEGES] = [
            ApprovalPrivilege::MutateLocalState,
            ApprovalPrivilege::ReadLocalState,
        ];
        for pair in DECLARED.windows(2) {
            assert!(pair[0] < pair[1]);
            assert!(pair[0].as_str() < pair[1].as_str());
        }
        assert!(canonical_privileges(&DECLARED));

        // Held for the twenty-four operations rather than for the three of the
        // first palier: the invariant is about every list this side can sign,
        // and an operation added without being listed here would be one whose
        // privilege order nobody checked.
        assert_eq!(DECLARED_OPERATIONS.len(), 24);
        for operation in DECLARED_OPERATIONS {
            let required = operation.required_privileges();
            assert!(
                canonical_privileges(required),
                "{operation:?} requires a list the Auxiliary would refuse to read"
            );
        }
    }

    /// Each operation carries exactly its own privileges, and the read-only one
    /// still refuses to mutate whatever else its envelope carries.
    ///
    /// The equality runs both ways, for each of the twenty-three operations that
    /// describe a state: the diagnostic cannot be given the mutating pair, and
    /// none of them can be given the reading privilege alone or the mutating one
    /// alone. Naming an operation is therefore the whole of asking for a power
    /// here — there is no second field through which more could be requested.
    #[test]
    fn each_operation_carries_exactly_its_own_privileges() {
        assert_eq!(
            ApprovalOperation::DiagnoseProtocolReadOnly.required_privileges(),
            &[ApprovalPrivilege::ReadLocalState]
        );
        for describing in MUTATING_OPERATIONS {
            assert_eq!(
                describing.required_privileges(),
                &[
                    ApprovalPrivilege::MutateLocalState,
                    ApprovalPrivilege::ReadLocalState,
                ],
                "{describing:?} does not carry the exact pair of the contract"
            );
            let mutating = ApprovalEnvelopeV1 {
                operation: describing,
                privileges: describing.required_privileges().to_vec(),
                ..envelope()
            };
            assert!(mutating.is_mutating());
            assert!(mutating.validate().is_ok());

            // Neither less than the operation needs, nor the mutating
            // privilege on its own.
            for narrowed in [
                vec![ApprovalPrivilege::ReadLocalState],
                vec![ApprovalPrivilege::MutateLocalState],
            ] {
                assert_eq!(
                    ApprovalEnvelopeV1 {
                        operation: describing,
                        privileges: narrowed,
                        ..envelope()
                    }
                    .validate(),
                    Err(ProtocolError::InvalidInput),
                    "{describing:?} was approved with a list that is not its own"
                );
            }

            // The read-only diagnostic can never be given the pair this
            // operation requires.
            assert_eq!(
                ApprovalEnvelopeV1 {
                    operation: ApprovalOperation::DiagnoseProtocolReadOnly,
                    privileges: describing.required_privileges().to_vec(),
                    ..envelope()
                }
                .validate(),
                Err(ProtocolError::InvalidInput)
            );
        }
        assert_eq!(MUTATING_OPERATIONS.len(), DECLARED_OPERATIONS.len() - 1);

        for privileges in [
            vec![ApprovalPrivilege::MutateLocalState],
            vec![
                ApprovalPrivilege::MutateLocalState,
                ApprovalPrivilege::ReadLocalState,
            ],
        ] {
            let mutating = ApprovalEnvelopeV1 {
                privileges,
                ..envelope()
            };
            assert!(mutating.is_mutating());
            assert_eq!(mutating.validate(), Err(ProtocolError::InvalidInput));
        }

        // A probe operation asking for less than it needs is not a narrower
        // approval either.
        assert_eq!(
            ApprovalEnvelopeV1 {
                operation: ApprovalOperation::DeployOciProbe,
                privileges: vec![ApprovalPrivilege::ReadLocalState],
                ..envelope()
            }
            .validate(),
            Err(ProtocolError::InvalidInput)
        );
    }

    #[test]
    fn privileges_are_a_canonical_set_rather_than_a_list() {
        for privileges in [
            Vec::new(),
            vec![
                ApprovalPrivilege::ReadLocalState,
                ApprovalPrivilege::ReadLocalState,
            ],
            vec![
                ApprovalPrivilege::ReadLocalState,
                ApprovalPrivilege::MutateLocalState,
            ],
        ] {
            assert_eq!(
                ApprovalEnvelopeV1 {
                    privileges,
                    ..envelope()
                }
                .validate(),
                Err(ProtocolError::InvalidInput)
            );
        }
    }

    #[test]
    fn identifiers_epochs_and_sequences_are_bounded() {
        for hostile in [
            ApprovalEnvelopeV1 {
                schema_version: 2,
                ..envelope()
            },
            ApprovalEnvelopeV1 {
                infrastructure_id: "8F14E45F-CEEA-4167-A8B1-1F7BD0A0F4C2".into(),
                ..envelope()
            },
            ApprovalEnvelopeV1 {
                infrastructure_id: "8f14e45f-ceea-1167-a8b1-1f7bd0a0f4c2".into(),
                ..envelope()
            },
            ApprovalEnvelopeV1 {
                infrastructure_id: "8f14e45f-ceea-4167-c8b1-1f7bd0a0f4c2".into(),
                ..envelope()
            },
            ApprovalEnvelopeV1 {
                machine_id: "../../etc/shadow".into(),
                ..envelope()
            },
            ApprovalEnvelopeV1 {
                machine_id: "LAB-MACHINE-1".into(),
                ..envelope()
            },
            ApprovalEnvelopeV1 {
                machine_id: "-machine".into(),
                ..envelope()
            },
            ApprovalEnvelopeV1 {
                machine_id: "ab".into(),
                ..envelope()
            },
            ApprovalEnvelopeV1 {
                approval_epoch: 0,
                ..envelope()
            },
            ApprovalEnvelopeV1 {
                sequence: 0,
                ..envelope()
            },
            ApprovalEnvelopeV1 {
                plan_sha256: PLAN.to_ascii_uppercase(),
                ..envelope()
            },
            ApprovalEnvelopeV1 {
                plan_sha256: "11".into(),
                ..envelope()
            },
            ApprovalEnvelopeV1 {
                rollback_sha256: format!("{ROLLBACK}22"),
                ..envelope()
            },
            ApprovalEnvelopeV1 {
                approval_public_key: "not base64".into(),
                ..envelope()
            },
            ApprovalEnvelopeV1 {
                approval_public_key: URL_SAFE_NO_PAD.encode([1_u8; 31]),
                ..envelope()
            },
        ] {
            assert_eq!(hostile.clone().validate(), Err(ProtocolError::InvalidInput));
        }
    }

    /// An approval with no expiry, an expiry before its issue or a life longer
    /// than the ceiling is refused. The positive control is the nominal
    /// envelope, whose life is exactly the ceiling's third.
    #[test]
    fn the_life_of_an_approval_is_positive_and_bounded() {
        assert!(envelope().validate().is_ok());
        for (issued_at, expires_at) in [
            (0, 300),
            (1_780_000_000, 1_780_000_000),
            (1_780_000_000, 1_779_999_999),
            (
                1_780_000_000,
                1_780_000_000 + MAX_APPROVAL_LIFETIME_SECONDS + 1,
            ),
        ] {
            assert_eq!(
                ApprovalEnvelopeV1 {
                    issued_at_unix_seconds: issued_at,
                    expires_at_unix_seconds: expires_at,
                    ..envelope()
                }
                .validate(),
                Err(ProtocolError::InvalidInput)
            );
        }
        assert!(ApprovalEnvelopeV1 {
            issued_at_unix_seconds: 1_780_000_000,
            expires_at_unix_seconds: 1_780_000_000 + MAX_APPROVAL_LIFETIME_SECONDS,
            ..envelope()
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn the_wire_document_is_closed_and_the_signature_is_bounded() {
        let signed = SignedApprovalV1 {
            envelope: envelope(),
            signature: URL_SAFE_NO_PAD.encode([7_u8; APPROVAL_SIGNATURE_BYTES]),
        };
        let validated = signed.clone().validate().expect("nominal document");
        assert_eq!(
            validated.signature_bytes().unwrap(),
            [7_u8; APPROVAL_SIGNATURE_BYTES]
        );
        assert!(
            serde_json::to_vec(&validated).unwrap().len() <= MAX_SIGNED_APPROVAL_BYTES,
            "the declared ceiling must hold the document it bounds"
        );

        for hostile_signature in [
            String::new(),
            URL_SAFE_NO_PAD.encode([7_u8; 63]),
            "*".repeat(86),
        ] {
            assert_eq!(
                SignedApprovalV1 {
                    signature: hostile_signature,
                    ..signed.clone()
                }
                .validate(),
                Err(ProtocolError::InvalidInput)
            );
        }

        let mut document = serde_json::to_value(&signed).unwrap();
        document["forged"] = serde_json::json!("extra");
        assert!(serde_json::from_value::<SignedApprovalV1>(document).is_err());

        let mut nested = serde_json::to_value(&signed).unwrap();
        nested["envelope"]["forged"] = serde_json::json!("extra");
        assert!(serde_json::from_value::<SignedApprovalV1>(nested).is_err());

        let mut missing = serde_json::to_value(&signed).unwrap();
        missing["envelope"]
            .as_object_mut()
            .unwrap()
            .remove("rollback_sha256");
        assert!(serde_json::from_value::<SignedApprovalV1>(missing).is_err());
    }

    fn hex_lower(bytes: &[u8]) -> String {
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            text.push(char::from_digit(u32::from(byte >> 4), 16).unwrap());
            text.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap());
        }
        text
    }
}
