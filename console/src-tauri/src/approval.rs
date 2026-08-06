//! The only place a human approval is ever signed, and the shape that keeps it
//! from becoming a signing oracle.
//!
//! The private half of the human key already lives in the Console's vault: it
//! is what authenticates the user to their own Controller. This palier gives it
//! a second, narrower use — approving one operation on one machine — and the
//! whole difficulty is that a signature is a transferable authority. A function
//! that signed bytes chosen by its caller would hand that authority to whoever
//! can call it, which on this side of the process boundary means the WebView.
//!
//! Three properties keep that from being possible.
//!
//! **Nothing here accepts bytes to sign.** The single entry point takes an
//! [`ApprovalRequest`], whose fields are an identifier, two numbers, a closed
//! operation and the two documents that were displayed. The bytes that end up
//! under the signature are built by
//! [`your_cloud_bootstrap_protocol::ApprovalEnvelopeV1::signing_transcript`]
//! from those fields and from nothing else, under its own domain separator. A
//! caller that wants a different signature must describe a different approval.
//!
//! **The caller does not choose what it is allowed to do.** Privileges are read
//! from the operation, never from the request, so `mutate_local_state` is not
//! something a request can ask for — there is no field in which to ask. The
//! infrastructure is read from the association, so an approval cannot be aimed
//! at an infrastructure the Console is not associated to.
//!
//! **The plan is hashed here, not received hashed.** The request carries the
//! bytes the two digests are defined over — for a probe plan, the ones
//! [`crate::probe_plan`] rebuilt from the fields it verified and displayed —
//! and this module digests them. A caller therefore cannot bind the approval to
//! a digest whose preimage nobody displayed.
//!
//! No Tauri command reaches this module in this palier: the approval path is
//! signed and verified end to end, but the confirmation window that must
//! precede it belongs to the palier that adds the command. `check-source-contract`
//! holds the registered command list against that, so a signing command cannot
//! appear here without the contract failing first.

use crate::{network, vault::AssociationRecord};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};
use your_cloud_bootstrap_protocol::{
    ApprovalEnvelopeV1, ApprovalOperation, SignedApprovalV1, APPROVAL_SCHEMA_VERSION,
    MAX_APPROVAL_LIFETIME_SECONDS,
};

#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    #[error("the approval request is outside the signed schema")]
    InvalidRequest,
    #[error("local Console state is unavailable")]
    ConsoleUnavailable,
}

impl ApprovalError {
    pub fn public_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_input",
            Self::ConsoleUnavailable => "console_unavailable",
        }
    }
}

/// One approval, described by what it is about rather than by its bytes.
///
/// There is deliberately no `privileges`, no `infrastructure_id`, no
/// `approval_public_key` and no `transcript` here: each of those is derived
/// below from something the caller does not control.
#[derive(Clone, Copy, Debug)]
pub struct ApprovalRequest<'a> {
    /// The one machine the approval may be presented to.
    pub machine_id: &'a str,
    /// The authority epoch the target machine's anchor is at.
    pub approval_epoch: u64,
    /// The exact successor the target machine must be at. The Console signs the
    /// number it is given; the target is what decides whether it is the right
    /// one, which is the whole point of not trusting the transport.
    pub sequence: u64,
    pub operation: ApprovalOperation,
    /// The exact bytes the plan digest is defined over, for the plan that was
    /// displayed. A caller that owns a plan document hands in the
    /// domain-separated bytes its own module rebuilt from the fields it parsed,
    /// so what is named below is the digest that was on screen rather than a
    /// second digest of the same idea.
    pub plan: &'a [u8],
    /// The same, for the rollback of that same plan.
    pub rollback: &'a [u8],
    pub issued_at_unix_seconds: u64,
    pub lifetime_seconds: u64,
}

/// Signs one approval with the human key of one association.
///
/// The association is the whole authorisation: it only exists while the vault
/// is unlocked, and it carries the infrastructure this approval will name.
pub fn sign_approval(
    association: &AssociationRecord,
    request: ApprovalRequest<'_>,
) -> Result<SignedApprovalV1, ApprovalError> {
    if request.lifetime_seconds == 0 || request.lifetime_seconds > MAX_APPROVAL_LIFETIME_SECONDS {
        return Err(ApprovalError::InvalidRequest);
    }
    let expires_at_unix_seconds = request
        .issued_at_unix_seconds
        .checked_add(request.lifetime_seconds)
        .ok_or(ApprovalError::InvalidRequest)?;

    let human =
        network::human_signing_key(association).map_err(|_| ApprovalError::ConsoleUnavailable)?;

    let envelope = ApprovalEnvelopeV1 {
        schema_version: APPROVAL_SCHEMA_VERSION,
        // Read from the association, never from the request: an approval can
        // only ever name the infrastructure this Console is associated to.
        infrastructure_id: association.summary.infrastructure_id.clone(),
        machine_id: request.machine_id.to_owned(),
        approval_epoch: request.approval_epoch,
        sequence: request.sequence,
        operation: request.operation,
        plan_sha256: hex::encode(Sha256::digest(request.plan)),
        rollback_sha256: hex::encode(Sha256::digest(request.rollback)),
        // Read from the operation, never from the request. There is no field
        // through which a caller could ask to mutate anything.
        privileges: request.operation.required_privileges().to_vec(),
        issued_at_unix_seconds: request.issued_at_unix_seconds,
        expires_at_unix_seconds,
        approval_public_key: URL_SAFE_NO_PAD.encode(human.verifying_key().as_bytes()),
    }
    .validate()
    .map_err(|_| ApprovalError::InvalidRequest)?;

    let transcript = envelope
        .signing_transcript()
        .map_err(|_| ApprovalError::InvalidRequest)?;

    SignedApprovalV1 {
        envelope,
        signature: URL_SAFE_NO_PAD.encode(human.sign(&transcript).to_bytes()),
    }
    .validate()
    .map_err(|_| ApprovalError::InvalidRequest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::AssociationSummary;
    use ed25519_dalek::{Signature, SigningKey, Verifier};
    use your_cloud_bootstrap_protocol::ApprovalPrivilege;

    const INFRASTRUCTURE: &str = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2";
    const MACHINE: &str = "lab-machine-1";
    const PLAN: &[u8] = b"diagnose protocol read only";
    const ROLLBACK: &[u8] = b"no change to roll back";
    const ISSUED_AT: u64 = 1_780_000_000;

    /// A synthetic association whose human seed is the all-`0x01` vector. It is
    /// never a real key: it exists so the signature below is reproducible on
    /// both sides of the product.
    fn association(infrastructure_id: &str, seed: [u8; 32]) -> AssociationRecord {
        AssociationRecord {
            summary: AssociationSummary {
                controller_id: "123e4567-e89b-42d3-a456-426614174001".to_owned(),
                infrastructure_id: infrastructure_id.to_owned(),
                infrastructure_label: None,
                origin: format!("https://controller.{infrastructure_id}.your-cloud.test:9443"),
                device_status: "active".to_owned(),
                certificate_expires_at: None,
            },
            device_id: "123e4567-e89b-42d3-a456-426614174002".to_owned(),
            server_ca_pem: "ca".to_owned(),
            server_spki_sha256: "0".repeat(64),
            device_private_key_pem: "key".to_owned(),
            device_certificate_pem: "certificate".to_owned(),
            human_private_seed: URL_SAFE_NO_PAD.encode(seed),
            identity_revision: 1,
            recovery_salt: URL_SAFE_NO_PAD.encode([2_u8; 32]),
            recovery_epoch: 1,
            pending_mode: None,
            pending_transaction_id: None,
            pending_device_private_key_pem: None,
            pending_device_certificate_pem: None,
            pending_certificate_expires_at: None,
        }
    }

    fn request() -> ApprovalRequest<'static> {
        ApprovalRequest {
            machine_id: MACHINE,
            approval_epoch: 1,
            sequence: 1,
            operation: ApprovalOperation::DiagnoseProtocolReadOnly,
            plan: PLAN,
            rollback: ROLLBACK,
            issued_at_unix_seconds: ISSUED_AT,
            lifetime_seconds: 300,
        }
    }

    /// The deterministic vector of the Console side.
    ///
    /// The very same envelope, transcript and signature are pinned in
    /// `crates/bootstrap-protocol/src/approval.rs` and in
    /// `internal/approval/envelope_test.go`. The three are written from the same
    /// synthetic seed, so an encoder that drifts on one side stops matching the
    /// other two instead of producing an approval the Auxiliary silently
    /// refuses in the field.
    #[test]
    fn the_console_signature_vector_is_pinned() {
        let signed = sign_approval(&association(INFRASTRUCTURE, [1_u8; 32]), request())
            .expect("nominal approval");

        assert_eq!(
            signed.envelope.approval_public_key,
            "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"
        );
        assert_eq!(
            signed.envelope.plan_sha256,
            "0057dd53cc58e914bba328007203c36bfc9f1ebb375a0b150abdddfd0f7eee9b"
        );
        assert_eq!(
            signed.envelope.rollback_sha256,
            "0300401c8e3a5f90cd887fcb2a6c0ce0d35afd2c1a247f654162c275da00dcf1"
        );
        assert_eq!(signed.envelope.signing_transcript().unwrap().len(), 285);
        assert_eq!(
            signed.signature,
            "rmoKkEc47JjAkPMXv_0q_Qgust3FNKoOlwDc8eajMpsWl6LqB6phBnPkR-CaMNpkm4X0oH_Gg-6CrVczUL6zCg"
        );
    }

    /// The signature really covers the transcript, verified with the key the
    /// envelope itself names.
    #[test]
    fn the_signature_verifies_against_the_key_the_envelope_names() {
        let signed =
            sign_approval(&association(INFRASTRUCTURE, [1_u8; 32]), request()).expect("approval");
        let verifying = SigningKey::from_bytes(&[1_u8; 32]).verifying_key();

        assert_eq!(
            signed.envelope.approval_public_key_bytes().unwrap(),
            verifying.to_bytes()
        );
        verifying
            .verify(
                &signed.envelope.signing_transcript().unwrap(),
                &Signature::from_bytes(&signed.signature_bytes().unwrap()),
            )
            .expect("the signature must cover the transcript it was built from");
    }

    /// Changing one described field changes the signature.
    ///
    /// This is the same property the protocol crate asserts on the bytes, held
    /// one level higher: it is the *request* that is varied here, so it also
    /// covers the fields this module derives rather than copies.
    #[test]
    fn no_two_different_approvals_share_a_signature() {
        let record = association(INFRASTRUCTURE, [1_u8; 32]);
        let reference = sign_approval(&record, request()).unwrap();

        let variants = [
            ApprovalRequest {
                machine_id: "lab-machine-2",
                ..request()
            },
            ApprovalRequest {
                approval_epoch: 2,
                ..request()
            },
            ApprovalRequest {
                sequence: 2,
                ..request()
            },
            ApprovalRequest {
                plan: b"install a container",
                ..request()
            },
            ApprovalRequest {
                rollback: b"remove that container",
                ..request()
            },
            ApprovalRequest {
                issued_at_unix_seconds: ISSUED_AT + 1,
                ..request()
            },
            ApprovalRequest {
                lifetime_seconds: 301,
                ..request()
            },
        ];
        for variant in variants {
            assert_ne!(
                sign_approval(&record, variant).unwrap().signature,
                reference.signature
            );
        }

        // The infrastructure is not in the request at all, so it is varied
        // where it really comes from.
        assert_ne!(
            sign_approval(
                &association("8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3", [1_u8; 32]),
                request()
            )
            .unwrap()
            .signature,
            reference.signature
        );

        // A different human key is a different approval authority, and the
        // envelope says so rather than silently reusing the previous key.
        let rotated = sign_approval(&association(INFRASTRUCTURE, [3_u8; 32]), request()).unwrap();
        assert_ne!(rotated.signature, reference.signature);
        assert_ne!(
            rotated.envelope.approval_public_key,
            reference.envelope.approval_public_key
        );
    }

    /// The privileges are the operation's, and a caller has no way of asking
    /// for anything else. This is the positive control of "every mutation is
    /// still refused": the only reachable approval is a reading one.
    #[test]
    fn a_signed_approval_can_never_carry_a_mutating_privilege() {
        let signed =
            sign_approval(&association(INFRASTRUCTURE, [1_u8; 32]), request()).expect("approval");
        assert_eq!(
            signed.envelope.privileges,
            vec![ApprovalPrivilege::ReadLocalState]
        );
        assert!(!signed.envelope.is_mutating());
    }

    #[test]
    fn a_request_outside_the_schema_produces_no_signature() {
        let record = association(INFRASTRUCTURE, [1_u8; 32]);
        for hostile in [
            ApprovalRequest {
                machine_id: "../../etc/shadow",
                ..request()
            },
            ApprovalRequest {
                machine_id: "",
                ..request()
            },
            ApprovalRequest {
                approval_epoch: 0,
                ..request()
            },
            ApprovalRequest {
                sequence: 0,
                ..request()
            },
            ApprovalRequest {
                lifetime_seconds: 0,
                ..request()
            },
            ApprovalRequest {
                lifetime_seconds: MAX_APPROVAL_LIFETIME_SECONDS + 1,
                ..request()
            },
            ApprovalRequest {
                issued_at_unix_seconds: 0,
                ..request()
            },
            ApprovalRequest {
                issued_at_unix_seconds: u64::MAX,
                ..request()
            },
        ] {
            assert!(matches!(
                sign_approval(&record, hostile),
                Err(ApprovalError::InvalidRequest)
            ));
        }

        // A record whose seed is not a key produces no signature either, and
        // says the Console is unavailable rather than inventing one.
        let mut broken = association(INFRASTRUCTURE, [1_u8; 32]);
        broken.human_private_seed = "not-a-seed".to_owned();
        assert!(matches!(
            sign_approval(&broken, request()),
            Err(ApprovalError::ConsoleUnavailable)
        ));
    }
}
