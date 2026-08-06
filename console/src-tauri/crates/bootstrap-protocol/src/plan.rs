//! What the two digests of an approval actually cover, on the side that
//! displays them.
//!
//! The envelope of the previous palier signs `plan_sha256` and
//! `rollback_sha256` without saying what they are digests *of*. A plan is what
//! they are digests of here: a closed description of a requested state, and the
//! complete second document that undoes it.
//!
//! **A plan is never a script.** Its field list is closed, and none of its
//! fields can carry a command, a path, a playbook, an inventory, a volume, a
//! network or a privilege. A document that tries to is refused by the strict
//! decoding below before any of its content is read, which is the strongest
//! form the refusal can take: it does not depend on understanding what was
//! smuggled in.
//!
//! **Nothing here signs, and nothing here encodes.** The Controller freezes the
//! canonical bytes and transports them; this side receives those exact bytes
//! beside the digests they are claimed to have, rebuilds the digest from the
//! fields it parsed, and refuses the pair when the two disagree. Owning a
//! second canonical encoder would give the Console a second truth about what a
//! human approved, so it owns none: [`PlanDocumentV1`] is deserialised from the
//! received bytes and hashed through its transcript, never re-emitted as the
//! authority on what those bytes were.
//!
//! **The transcript is the counterpart of the one written on the Auxiliary
//! side.** The two are held against one another by deterministic vectors on
//! both sides rather than by reading, because a canonical encoding that exists
//! in two implementations is only canonical while the two agree byte for byte.
//! The vectors below are the very ones pinned in `internal/plan/plan_test.go`.

use crate::{
    approval::{append_field, canonical_machine_id, canonical_uuid_v4, decode_digest},
    ProtocolError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The one plan version this palier reads.
pub const PLAN_SCHEMA_VERSION: u8 = 1;

/// Domain separator of this transcript, terminated by a byte no textual field
/// may contain. No prefix of one transcript of the product is therefore a
/// prefix of another, and a plan digest can never be read as an envelope
/// digest.
pub const PLAN_TRANSCRIPT_DOMAIN: &[u8] = b"your-cloud/oci-plan.v1\0";

/// Length of the decoded image digest, and of the plan digest the envelope
/// names.
pub const PLAN_DIGEST_BYTES: usize = 32;

/// Largest plan document read before it is parsed. A plan is a fixed set of
/// bounded fields; this is the size they reach with room for the reindentation
/// a transport is allowed to apply.
pub const MAX_PLAN_DOCUMENT_BYTES: usize = 4_096;

/// The one registry, repository and image this palier accepts. It carries no
/// tag: a tag would be a second, movable truth beside the digest, and the
/// digest is the identity.
pub const PROBE_IMAGE_REFERENCE: &str = "docker.io/traefik/whoami";

/// The manifest list this palier pins. Widening the accepted images is a
/// decision of a later palier, not a generalisation of this one, so the value
/// is compared for equality rather than parsed into a policy.
pub const PROBE_IMAGE_DIGEST: &str =
    "sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab";

/// The address the probe listens on. It is a constant of the contract and not a
/// field of the document: no approvable value can expose the probe beyond its
/// own machine, so the window that displays a plan reads the address from here.
pub const PROBE_LOCAL_ADDRESS: &str = "127.0.0.1";

/// Bounds of the loopback port the probe listens on.
pub const MIN_PLAN_LOCAL_PORT: u32 = 1_024;
pub const MAX_PLAN_LOCAL_PORT: u32 = 65_535;

/// The one digest algorithm an image may be pinned by, spelled the one way an
/// OCI reference spells it.
const OCI_DIGEST_PREFIX: &str = "sha256:";

/// The closed list of states this palier can describe.
///
/// Every member has an inverse that is itself a member, which is what makes an
/// operation without an undoing impossible to add here by accident: a rollback
/// is a plan in its own right, read, displayed, approved and verified like any
/// other, and never an implicit promise attached to the first document.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanOperation {
    /// The probe is present on exactly one machine, at exactly one local port.
    DeployOciProbe,
    /// That exact instance is absent. It carries the same fields as the
    /// deployment because a removal names an instance, never "whatever is
    /// running there".
    RemoveOciProbe,
}

impl PlanOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeployOciProbe => "deploy_oci_probe",
            Self::RemoveOciProbe => "remove_oci_probe",
        }
    }

    /// The operation that undoes this one.
    pub fn inverse(self) -> Self {
        match self {
            Self::DeployOciProbe => Self::RemoveOciProbe,
            Self::RemoveOciProbe => Self::DeployOciProbe,
        }
    }
}

/// The whole plan.
///
/// The declaration order below is the canonical encoding order and the
/// transcript order at once, and no field of a plan lives outside it. There is
/// deliberately no tag, no volume, no network, no container privilege and no
/// variable: the probe needs none of them, and a document carrying one is an
/// unknown field the decoding refuses before reading its value.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanDocumentV1 {
    pub schema_version: u8,
    /// The infrastructure this plan belongs to, as a canonical UUIDv4, under
    /// the same rule as the envelope that will name its digest.
    pub infrastructure_id: String,
    /// The one machine this plan describes a state of.
    pub machine_id: String,
    pub operation: PlanOperation,
    /// Registry and repository, without a tag.
    pub image_reference: String,
    /// `sha256:` followed by sixty-four lower-case hexadecimal characters.
    pub image_digest: String,
    /// The port the probe listens on, on [`PROBE_LOCAL_ADDRESS`] alone.
    pub local_port: u32,
}

impl PlanDocumentV1 {
    /// Holds a plan against the whole contract of the palier, image included.
    ///
    /// The image is checked for equality against the one pinned probe rather
    /// than against a policy, because this palier accepts exactly one probe and
    /// nothing else. A plan naming another registry, another repository or
    /// another digest is not a narrower or a wider plan: it is one this palier
    /// neither builds nor recognises.
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if self.schema_version != PLAN_SCHEMA_VERSION
            || !canonical_uuid_v4(&self.infrastructure_id)
            || !canonical_machine_id(&self.machine_id)
            || self.image_reference != PROBE_IMAGE_REFERENCE
            // The shape is required before the pin so that the transcript may
            // rely on decoding exactly thirty-two bytes out of the field, and
            // so that a malformed digest and an unpinned one stay two distinct
            // refusals.
            || decode_image_digest(&self.image_digest).is_none()
            || self.image_digest != PROBE_IMAGE_DIGEST
            || !(MIN_PLAN_LOCAL_PORT..=MAX_PLAN_LOCAL_PORT).contains(&self.local_port)
        {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(self)
    }

    /// The exact bytes a plan digest is taken over.
    ///
    /// It is built from the parsed fields and never from a received document,
    /// so two implementations that read the same plan produce the same digest,
    /// a transport that reshapes the JSON transports the same plan, and a
    /// transport that changes one value transports a plan whose digest no
    /// longer matches the approval that named it.
    pub fn transcript(&self) -> Result<Vec<u8>, ProtocolError> {
        let image = decode_image_digest(&self.image_digest).ok_or(ProtocolError::InvalidInput)?;

        let mut transcript = Vec::with_capacity(PLAN_TRANSCRIPT_DOMAIN.len() + 192);
        transcript.extend_from_slice(PLAN_TRANSCRIPT_DOMAIN);
        transcript.extend_from_slice(&self.schema_version.to_be_bytes());
        append_field(&mut transcript, self.infrastructure_id.as_bytes())?;
        append_field(&mut transcript, self.machine_id.as_bytes())?;
        append_field(&mut transcript, self.operation.as_str().as_bytes())?;
        append_field(&mut transcript, self.image_reference.as_bytes())?;
        append_field(&mut transcript, &image)?;
        transcript.extend_from_slice(&self.local_port.to_be_bytes());
        Ok(transcript)
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

    /// Whether `rollback` is the complete document that undoes this plan.
    ///
    /// The two differ by their operation and by nothing else: undoing a
    /// deployment removes that exact instance, and undoing a removal redeploys
    /// that exact instance. A rollback aimed at another machine, another port
    /// or another image is not a rollback of this plan at all.
    pub fn is_undone_by(&self, rollback: &Self) -> bool {
        rollback.operation == self.operation.inverse()
            && rollback.schema_version == self.schema_version
            && rollback.infrastructure_id == self.infrastructure_id
            && rollback.machine_id == self.machine_id
            && rollback.image_reference == self.image_reference
            && rollback.image_digest == self.image_digest
            && rollback.local_port == self.local_port
    }
}

/// Accepts one bounded, strict, fully validated plan document.
///
/// It never returns a partially checked plan: a caller that holds one may
/// assume every field is inside the bounds of the contract, which is what lets
/// the decisions that follow be about authority rather than about shape.
///
/// The bound is applied before parsing, exactly one JSON value is accepted, a
/// repeated key is a refusal, an undeclared field is a refusal, and every field
/// must appear under its exact canonical name.
pub fn decode_plan_document(document: &[u8]) -> Result<PlanDocumentV1, ProtocolError> {
    if document.is_empty() || document.len() > MAX_PLAN_DOCUMENT_BYTES {
        return Err(ProtocolError::InvalidInput);
    }
    let parsed: PlanDocumentV1 =
        serde_json::from_slice(document).map_err(|_| ProtocolError::InvalidInput)?;
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
pub fn verify_plan_document(
    document: &[u8],
    expected_sha256: &str,
) -> Result<PlanDocumentV1, ProtocolError> {
    let expected = decode_digest(expected_sha256).ok_or(ProtocolError::InvalidInput)?;
    let parsed = decode_plan_document(document)?;
    if parsed.digest()? != expected {
        return Err(ProtocolError::InvalidInput);
    }
    Ok(parsed)
}

/// The thirty-two bytes an `sha256:` image digest names, and nothing that
/// merely parses as one: the algorithm is spelled in lower case, the value is
/// lower-case hexadecimal, and no other spelling of the same number decodes.
fn decode_image_digest(value: &str) -> Option<[u8; PLAN_DIGEST_BYTES]> {
    decode_digest(value.strip_prefix(OCI_DIGEST_PREFIX)?)
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from_digit(u32::from(byte >> 4), 16).expect("a nibble is a hex digit"));
        text.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("a nibble is a hex digit"));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFRASTRUCTURE: &str = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2";
    const MACHINE: &str = "lab-machine-1";
    const PORT: u32 = 8_080;

    /// The two canonical documents of the shared vector, byte for byte. They
    /// are the bytes `internal/plan/plan_test.go` pins as the ones the
    /// Controller emits, copied literally rather than rebuilt here.
    const PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":1,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"deploy_oci_probe","#,
        r#""image_reference":"docker.io/traefik/whoami","#,
        r#""image_digest":"sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab","#,
        r#""local_port":8080}"#,
    );
    const ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":1,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"remove_oci_probe","#,
        r#""image_reference":"docker.io/traefik/whoami","#,
        r#""image_digest":"sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab","#,
        r#""local_port":8080}"#,
    );

    /// The two transcripts, byte for byte, and the two digests an envelope of
    /// this vector names. The Auxiliary side pins the very same values from its
    /// own encoder, so a single byte of drift in either implementation fails
    /// here rather than producing plans the other side hashes differently on a
    /// real machine.
    const PLAN_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e76310001000000243866313465",
        "3435662d636565612d343136372d613862312d3166376264306130663463320000",
        "000d6c61622d6d616368696e652d31000000106465706c6f795f6f63695f70726f",
        "626500000018646f636b65722e696f2f7472616566696b2f77686f616d69000000",
        "20200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab",
        "00001f90",
    );
    const ROLLBACK_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e76310001000000243866313465",
        "3435662d636565612d343136372d613862312d3166376264306130663463320000",
        "000d6c61622d6d616368696e652d310000001072656d6f76655f6f63695f70726f",
        "626500000018646f636b65722e696f2f7472616566696b2f77686f616d69000000",
        "20200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab",
        "00001f90",
    );
    const PLAN_SHA256: &str = "2d50d2bc935ce6c56ef14fbfae93d670d5fdb9ca735315e5a26760d818dd5b0e";
    const ROLLBACK_SHA256: &str =
        "e953fb5f9d8423be61cad4a06d571e200977dd183f53c12d5a897746ad80497a";

    /// The `amd64` image the pinned manifest list resolves to. It is a real
    /// digest of the same probe and is still refused, because the plan names
    /// the manifest list and nothing else may stand in for it.
    const RESOLVED_AMD64_DIGEST: &str =
        "sha256:4f90b33ddca9c4d4f06527070d6e503b16d71016edea036842be2a84e60c91cb";

    fn document() -> PlanDocumentV1 {
        PlanDocumentV1 {
            schema_version: PLAN_SCHEMA_VERSION,
            infrastructure_id: INFRASTRUCTURE.into(),
            machine_id: MACHINE.into(),
            operation: PlanOperation::DeployOciProbe,
            image_reference: PROBE_IMAGE_REFERENCE.into(),
            image_digest: PROBE_IMAGE_DIGEST.into(),
            local_port: PORT,
        }
    }

    /// Encodes a document without validating it, which is what a hostile case
    /// needs: the refusal under test must come from the decoding rather than
    /// from something refusing to produce the bytes in the first place.
    fn hostile_document(document: &PlanDocumentV1) -> String {
        serde_json::to_string(document).expect("a plan is representable as JSON")
    }

    fn with_extra_member(document: &str, member: &str) -> String {
        format!("{},{member}}}", document.trim_end_matches('}'))
    }

    /// The interoperability proof of the plan encoding.
    ///
    /// Both transcripts, both digests and both canonical documents are pinned
    /// literally here and in `internal/plan/plan_test.go`. Reading the two
    /// encoders against one another would not be a proof; producing the same
    /// bytes from both is.
    #[test]
    fn the_deterministic_plan_vectors_are_held_with_the_auxiliary_side() {
        let plan = decode_plan_document(PLAN_DOCUMENT.as_bytes()).expect("the nominal document");
        let rollback =
            decode_plan_document(ROLLBACK_DOCUMENT.as_bytes()).expect("the nominal rollback");

        let transcript = plan.transcript().expect("the vector transcript");
        assert_eq!(transcript.len(), 169);
        assert!(transcript.starts_with(PLAN_TRANSCRIPT_DOMAIN));
        assert_eq!(encode_lower_hex(&transcript), PLAN_TRANSCRIPT_HEX);
        assert_eq!(
            encode_lower_hex(&rollback.transcript().unwrap()),
            ROLLBACK_TRANSCRIPT_HEX
        );

        assert_eq!(plan.sha256().unwrap(), PLAN_SHA256);
        assert_eq!(rollback.sha256().unwrap(), ROLLBACK_SHA256);

        // The declaration order of the fields is the canonical encoding order
        // the Controller emits. It is asserted rather than relied upon, because
        // this side must recognise those exact bytes and never has to produce
        // them.
        assert_eq!(hostile_document(&plan), PLAN_DOCUMENT);
        assert_eq!(hostile_document(&rollback), ROLLBACK_DOCUMENT);
    }

    /// Every field of a plan is inside the hashed bytes.
    ///
    /// The test does not read the transcript builder: it changes one field at a
    /// time and requires the bytes to move. A field that could move without
    /// moving the digest would be a field the Controller owns, since the
    /// Controller is the only thing between the human who approved a plan and
    /// the machine that performs it.
    #[test]
    fn changing_any_single_field_changes_the_plan_digest() {
        let reference = document().transcript().unwrap();
        let mutations: Vec<(&str, PlanDocumentV1)> = vec![
            (
                "schema_version",
                PlanDocumentV1 {
                    schema_version: 2,
                    ..document()
                },
            ),
            (
                "infrastructure_id",
                PlanDocumentV1 {
                    infrastructure_id: "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3".into(),
                    ..document()
                },
            ),
            (
                "machine_id",
                PlanDocumentV1 {
                    machine_id: "lab-machine-2".into(),
                    ..document()
                },
            ),
            (
                "operation",
                PlanDocumentV1 {
                    operation: PlanOperation::RemoveOciProbe,
                    ..document()
                },
            ),
            (
                "image_reference",
                PlanDocumentV1 {
                    image_reference: "ghcr.io/traefik/whoami".into(),
                    ..document()
                },
            ),
            (
                "image_digest",
                PlanDocumentV1 {
                    image_digest: RESOLVED_AMD64_DIGEST.into(),
                    ..document()
                },
            ),
            (
                "local_port",
                PlanDocumentV1 {
                    local_port: PORT + 1,
                    ..document()
                },
            ),
        ];

        let mut covered: Vec<String> = Vec::new();
        for (field, moved) in mutations {
            assert_ne!(
                moved.transcript().unwrap(),
                reference,
                "{field} is outside the hashed bytes"
            );
            covered.push(field.to_owned());
        }

        // Every field the wire document carries is one of the ones just moved.
        // A field added to the plan and forgotten in the transcript fails here
        // rather than on a machine.
        let wire = serde_json::to_value(document()).unwrap();
        let mut wire_fields: Vec<String> = wire.as_object().unwrap().keys().cloned().collect();
        wire_fields.sort();
        covered.sort();
        assert_eq!(wire_fields.len(), 7);
        assert_eq!(wire_fields, covered);
    }

    #[test]
    fn decoding_refuses_every_document_outside_the_contract() {
        // Positive control.
        assert!(decode_plan_document(PLAN_DOCUMENT.as_bytes()).is_ok());

        for (name, hostile) in [
            (
                "unsupported schema",
                PlanDocumentV1 {
                    schema_version: 2,
                    ..document()
                },
            ),
            (
                "absent schema",
                PlanDocumentV1 {
                    schema_version: 0,
                    ..document()
                },
            ),
            (
                "upper-case UUID",
                PlanDocumentV1 {
                    infrastructure_id: INFRASTRUCTURE.to_ascii_uppercase(),
                    ..document()
                },
            ),
            (
                "non version 4 UUID",
                PlanDocumentV1 {
                    infrastructure_id: "8f14e45f-ceea-1167-a8b1-1f7bd0a0f4c2".into(),
                    ..document()
                },
            ),
            (
                "empty infrastructure",
                PlanDocumentV1 {
                    infrastructure_id: String::new(),
                    ..document()
                },
            ),
            (
                "traversal machine",
                PlanDocumentV1 {
                    machine_id: "../../etc/shadow".into(),
                    ..document()
                },
            ),
            (
                "upper-case machine",
                PlanDocumentV1 {
                    machine_id: "LAB-MACHINE-1".into(),
                    ..document()
                },
            ),
            (
                "too short machine",
                PlanDocumentV1 {
                    machine_id: "ab".into(),
                    ..document()
                },
            ),
            (
                "machine opening on a hyphen",
                PlanDocumentV1 {
                    machine_id: "-lab-machine-1".into(),
                    ..document()
                },
            ),
            (
                "other registry",
                PlanDocumentV1 {
                    image_reference: "ghcr.io/traefik/whoami".into(),
                    ..document()
                },
            ),
            (
                "other repository",
                PlanDocumentV1 {
                    image_reference: "docker.io/attacker/whoami".into(),
                    ..document()
                },
            ),
            (
                "tagged reference",
                PlanDocumentV1 {
                    image_reference: format!("{PROBE_IMAGE_REFERENCE}:latest"),
                    ..document()
                },
            ),
            (
                "reference carrying its own digest",
                PlanDocumentV1 {
                    image_reference: format!("{PROBE_IMAGE_REFERENCE}@{PROBE_IMAGE_DIGEST}"),
                    ..document()
                },
            ),
            (
                "registry-less reference",
                PlanDocumentV1 {
                    image_reference: "traefik/whoami".into(),
                    ..document()
                },
            ),
            (
                "resolved amd64 digest",
                PlanDocumentV1 {
                    image_digest: RESOLVED_AMD64_DIGEST.into(),
                    ..document()
                },
            ),
            (
                "upper-case digest",
                PlanDocumentV1 {
                    image_digest: PROBE_IMAGE_DIGEST.to_ascii_uppercase(),
                    ..document()
                },
            ),
            (
                "unprefixed digest",
                PlanDocumentV1 {
                    image_digest: PROBE_IMAGE_DIGEST
                        .trim_start_matches(OCI_DIGEST_PREFIX)
                        .into(),
                    ..document()
                },
            ),
            (
                "upper-case digest algorithm",
                PlanDocumentV1 {
                    image_digest: format!(
                        "SHA256:{}",
                        PROBE_IMAGE_DIGEST.trim_start_matches(OCI_DIGEST_PREFIX)
                    ),
                    ..document()
                },
            ),
            (
                "other digest algorithm",
                PlanDocumentV1 {
                    image_digest: format!(
                        "sha512:{}",
                        PROBE_IMAGE_DIGEST.trim_start_matches(OCI_DIGEST_PREFIX)
                    ),
                    ..document()
                },
            ),
            (
                "short digest",
                PlanDocumentV1 {
                    image_digest: "sha256:2006".into(),
                    ..document()
                },
            ),
            (
                "port below the range",
                PlanDocumentV1 {
                    local_port: MIN_PLAN_LOCAL_PORT - 1,
                    ..document()
                },
            ),
            (
                "privileged port",
                PlanDocumentV1 {
                    local_port: 80,
                    ..document()
                },
            ),
            (
                "absent port",
                PlanDocumentV1 {
                    local_port: 0,
                    ..document()
                },
            ),
            (
                "port above the range",
                PlanDocumentV1 {
                    local_port: MAX_PLAN_LOCAL_PORT + 1,
                    ..document()
                },
            ),
            (
                "port beyond sixteen bits",
                PlanDocumentV1 {
                    local_port: 70_000,
                    ..document()
                },
            ),
        ] {
            assert_eq!(
                decode_plan_document(hostile_document(&hostile).as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }

        for (name, hostile) in [
            ("empty", String::new()),
            ("two values", format!("{PLAN_DOCUMENT}{{}}")),
            ("array", format!("[{PLAN_DOCUMENT}]")),
            ("truncated", PLAN_DOCUMENT.trim_end_matches('}').to_owned()),
            // A tag, a volume, a network, a privilege or a command are all the
            // same refusal: a field the schema does not declare, refused before
            // its value is read.
            (
                "tag field",
                with_extra_member(PLAN_DOCUMENT, r#""tag":"latest""#),
            ),
            (
                "volume field",
                with_extra_member(PLAN_DOCUMENT, r#""volumes":["/etc:/etc"]"#),
            ),
            (
                "network field",
                with_extra_member(PLAN_DOCUMENT, r#""network":"host""#),
            ),
            (
                "privileged field",
                with_extra_member(PLAN_DOCUMENT, r#""privileged":true"#),
            ),
            (
                "command field",
                with_extra_member(PLAN_DOCUMENT, r#""command":"/bin/sh""#),
            ),
            (
                "environment field",
                with_extra_member(PLAN_DOCUMENT, r#""environment":{"YOUR_CLOUD":"1"}"#),
            ),
            (
                "repeated field",
                with_extra_member(PLAN_DOCUMENT, r#""local_port":9090"#),
            ),
            (
                "non-canonical field name",
                PLAN_DOCUMENT.replace(r#""local_port""#, r#""Local_Port""#),
            ),
            (
                "camel-case field name",
                PLAN_DOCUMENT.replace(r#""machine_id""#, r#""machineId""#),
            ),
            (
                "absent field",
                PLAN_DOCUMENT.replace(r#","local_port":8080"#, ""),
            ),
            (
                "port as a string",
                PLAN_DOCUMENT.replace(r#""local_port":8080"#, r#""local_port":"8080""#),
            ),
            (
                "fractional port",
                PLAN_DOCUMENT.replace(r#""local_port":8080"#, r#""local_port":8080.5"#),
            ),
            (
                "exponent port",
                PLAN_DOCUMENT.replace(r#""local_port":8080"#, r#""local_port":8.08e3"#),
            ),
            (
                "negative port",
                PLAN_DOCUMENT.replace(r#""local_port":8080"#, r#""local_port":-1"#),
            ),
            (
                "null operation",
                PLAN_DOCUMENT.replace(r#""operation":"deploy_oci_probe""#, r#""operation":null"#),
            ),
            (
                "unknown operation",
                PLAN_DOCUMENT.replace(
                    r#""operation":"deploy_oci_probe""#,
                    r#""operation":"install_container""#,
                ),
            ),
            (
                "upper-case operation",
                PLAN_DOCUMENT.replace(
                    r#""operation":"deploy_oci_probe""#,
                    r#""operation":"DEPLOY_OCI_PROBE""#,
                ),
            ),
            (
                "read-only operation of the previous palier",
                PLAN_DOCUMENT.replace(
                    r#""operation":"deploy_oci_probe""#,
                    r#""operation":"diagnose_protocol_read_only""#,
                ),
            ),
            (
                "oversized",
                PLAN_DOCUMENT.replace(PROBE_IMAGE_REFERENCE, &"a".repeat(MAX_PLAN_DOCUMENT_BYTES)),
            ),
        ] {
            assert_eq!(
                decode_plan_document(hostile.as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} document was accepted"
            );
        }
    }

    /// The exact limit of what a transport may do: reshape the JSON, and only
    /// that. The digest is rebuilt from the fields, so a reindented, reordered
    /// document is the same plan, and a document with one value changed is not.
    #[test]
    fn a_reindented_document_is_the_same_plan() {
        let reshaped = format!(
            "{{\n  \"local_port\": {PORT},\n  \"image_digest\": \"{PROBE_IMAGE_DIGEST}\",\n  \
             \"image_reference\": \"{PROBE_IMAGE_REFERENCE}\",\n  \
             \"operation\": \"deploy_oci_probe\",\n  \"machine_id\": \"{MACHINE}\",\n  \
             \"infrastructure_id\": \"{INFRASTRUCTURE}\",\n  \"schema_version\": 1\n}}"
        );
        let reordered = decode_plan_document(reshaped.as_bytes())
            .expect("a reindented document is the same plan");
        assert_eq!(reordered.sha256().unwrap(), PLAN_SHA256);
        assert_eq!(
            verify_plan_document(reshaped.as_bytes(), PLAN_SHA256).unwrap(),
            reordered
        );
    }

    /// A plan is only ever accepted beside the digest it really has.
    #[test]
    fn verification_refuses_a_document_its_digest_does_not_name() {
        assert_eq!(
            verify_plan_document(PLAN_DOCUMENT.as_bytes(), PLAN_SHA256).unwrap(),
            decode_plan_document(PLAN_DOCUMENT.as_bytes()).unwrap()
        );
        assert_eq!(
            verify_plan_document(ROLLBACK_DOCUMENT.as_bytes(), ROLLBACK_SHA256)
                .unwrap()
                .operation,
            PlanOperation::RemoveOciProbe
        );

        let upper_case_digest = PLAN_SHA256.to_ascii_uppercase();
        for (name, document, expected) in [
            (
                "the rollback presented under the plan digest",
                ROLLBACK_DOCUMENT,
                PLAN_SHA256,
            ),
            (
                "the plan presented under the rollback digest",
                PLAN_DOCUMENT,
                ROLLBACK_SHA256,
            ),
            (
                "an upper-case digest",
                PLAN_DOCUMENT,
                upper_case_digest.as_str(),
            ),
            ("a truncated digest", PLAN_DOCUMENT, "2d50"),
            ("an empty digest", PLAN_DOCUMENT, ""),
        ] {
            assert_eq!(
                verify_plan_document(document.as_bytes(), expected),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }
    }

    /// What makes a rollback a plan rather than a promise: undoing a deployment
    /// is the removal a human could have approved on its own, with its own
    /// digest, and undoing that removal is the deployment it came from.
    #[test]
    fn the_rollback_of_the_vector_is_the_exact_inverse_document() {
        let plan = decode_plan_document(PLAN_DOCUMENT.as_bytes()).unwrap();
        let rollback = decode_plan_document(ROLLBACK_DOCUMENT.as_bytes()).unwrap();

        assert!(plan.is_undone_by(&rollback));
        assert!(rollback.is_undone_by(&plan));
        assert_ne!(plan.sha256().unwrap(), rollback.sha256().unwrap());

        for other in [
            PlanDocumentV1 {
                machine_id: "lab-machine-2".into(),
                ..rollback.clone()
            },
            PlanDocumentV1 {
                local_port: PORT + 1,
                ..rollback.clone()
            },
            PlanDocumentV1 {
                infrastructure_id: "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3".into(),
                ..rollback.clone()
            },
            // A second copy of the plan itself undoes nothing.
            plan.clone(),
        ] {
            assert!(
                !plan.is_undone_by(&other),
                "a rollback that targets another instance is not a rollback"
            );
        }
    }

    /// The two decisions of the contract, kept testable rather than merely
    /// written: one image, and no second truth beside its digest.
    #[test]
    fn the_probe_of_this_palier_is_pinned_by_digest_alone() {
        assert!(!PROBE_IMAGE_REFERENCE.contains(':'));
        assert!(!PROBE_IMAGE_REFERENCE.contains('@'));
        assert!(decode_image_digest(PROBE_IMAGE_DIGEST).is_some());
        assert_eq!(PROBE_LOCAL_ADDRESS, "127.0.0.1");

        for operation in [PlanOperation::DeployOciProbe, PlanOperation::RemoveOciProbe] {
            assert_eq!(operation.inverse().inverse(), operation);
            assert_ne!(operation.inverse(), operation);
            assert_eq!(
                serde_json::to_value(operation).unwrap(),
                serde_json::json!(operation.as_str())
            );
        }
        assert_eq!(PlanOperation::DeployOciProbe.as_str(), "deploy_oci_probe");
        assert_eq!(PlanOperation::RemoveOciProbe.as_str(), "remove_oci_probe");
    }
}
