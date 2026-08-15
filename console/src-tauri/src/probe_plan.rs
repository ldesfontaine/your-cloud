//! The probe plan, from the bytes the Controller froze to the envelope the
//! native core signs over them.
//!
//! The Controller builds the pair and transports it; it holds no approval key
//! and can therefore propose a plan and never approve one. This module is what
//! makes that separation worth something on this side: it verifies both
//! documents against their own digests *before* anything is displayed, it hands
//! the confirmation window exactly the values it verified, and it signs only
//! what a human confirmed on those very bytes.
//!
//! Three properties hold the path together, and each is a property of the types
//! rather than a promise made by a caller.
//!
//! **Nothing is displayed that has not been verified.** [`PresentedProbePlan`]
//! is the only way to obtain the lines a window renders, and the only way to
//! obtain one is [`PresentedProbePlan::verify`], which rebuilds both digests
//! from the fields it parsed out of the received bytes. A pair whose digests do
//! not match never becomes a thing anyone can be shown.
//!
//! **A confirmation covers two exact documents.** [`ProbePlanConfirmation`]
//! carries the two digests it was given for, and signing re-reads the documents
//! from scratch and refuses when either the pair or the confirmed digests have
//! moved. A document altered after the window rendered it therefore invalidates
//! the confirmation instead of travelling under it.
//!
//! **The signature is the one that already exists.** Nothing here holds a key
//! or builds a transcript: [`crate::approval::sign_approval`] does, from a
//! typed request, and what this module hands it as the plan is the exact bytes
//! the plan digest is taken over. `plan_sha256` therefore ends up being the
//! digest that was verified and displayed, without a second hashing rule and
//! without a caller able to name a digest whose preimage nobody read.

use crate::{
    approval::{
        build_consent, consent_confirms, sign_approval, ApprovalError, ApprovalRequest,
        ConsentRequest,
    },
    vault::AssociationRecord,
};
use serde::Deserialize;
use your_cloud_bootstrap_protocol::{
    verify_plan_document, ApprovalConsentOutcomeV1, ApprovalConsentV1, ApprovalOperation,
    PlanDocumentV1, PlanOperation, SignedApprovalV1, PROBE_LOCAL_ADDRESS,
};

/// The one schema of the pair this palier reads.
const PROBE_PLAN_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, thiserror::Error)]
pub enum ProbePlanError {
    #[error("the probe plan pair is not the one its own digests name")]
    UnverifiedPlan,
    #[error("the probe plan names another infrastructure than this Console is associated to")]
    ForeignInfrastructure,
    #[error("no confirmation covers these exact documents")]
    UnconfirmedPlan,
    #[error("the approval of this plan could not be signed")]
    Approval(#[from] ApprovalError),
}

impl ProbePlanError {
    pub fn public_code(&self) -> &'static str {
        // Trois refus, trois codes — le même geste que `publication_plan`, et
        // pour la même raison, sur du code que personne n'appelle encore.
        //
        // Ce repli était identique mot pour mot à celui que `#136` a mesuré :
        // trois refus de sécurité rendus à l'humain comme une saisie mal formée.
        // Un repli identique à un défaut mesuré est une graine du même défaut,
        // et le rendre distinct **aujourd'hui** arme la garde inter-sources pour
        // le jour du câblage. Différé, il aurait fallu s'en souvenir au moment
        // exact où personne n'y pense.
        match self {
            Self::UnverifiedPlan => "unverified_plan",
            Self::ForeignInfrastructure => "foreign_infrastructure",
            Self::UnconfirmedPlan => "unconfirmed_plan",
            Self::Approval(error) => error.public_code(),
        }
    }
}

/// The frozen pair exactly as `POST /v0/probe-plans` answers it.
///
/// The two documents travel as strings holding their own canonical bytes rather
/// than as nested objects, which is the whole reason this side needs no
/// canonical encoder: what it verifies, what it displays and what the Auxiliary
/// will later receive are the same bytes rather than three encodings that
/// happen to agree. The digests travel beside them and are not an authority —
/// they are the claim this module refuses or accepts.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbePlanView {
    pub schema_version: u8,
    pub plan_document: String,
    pub plan_sha256: String,
    pub rollback_document: String,
    pub rollback_sha256: String,
}

/// A pair that has been held against its own digests, and the digests this side
/// computed rather than the ones it was handed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentedProbePlan {
    plan: PlanDocumentV1,
    rollback: PlanDocumentV1,
    plan_sha256: String,
    rollback_sha256: String,
}

/// What the native confirmation window answered.
///
/// A confirmation names the two digests it was given for. It is therefore not a
/// permission to sign "the current plan": it is a permission to sign those two
/// documents, and it stops meaning anything the moment either of them moves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbePlanConfirmation {
    Confirmed {
        plan_sha256: String,
        rollback_sha256: String,
    },
    Refused,
}

/// What a caller may choose about an approval, and nothing else.
///
/// The machine, the operation and the infrastructure are absent on purpose:
/// they are read from the plan and from the association below, so a caller
/// cannot aim a confirmed plan at another machine or another installation.
#[derive(Clone, Copy, Debug)]
pub struct ProbeApprovalRequest {
    pub approval_epoch: u64,
    pub sequence: u64,
    pub issued_at_unix_seconds: u64,
    pub lifetime_seconds: u64,
}

impl PresentedProbePlan {
    /// Verifies the whole pair before any of it can be displayed.
    ///
    /// Both documents are strict-decoded inside the bounds of the plan
    /// contract, both digests are rebuilt from the parsed fields, and the
    /// rollback is required to be the complete document that undoes the plan —
    /// same machine, same image, same port, inverse operation. A pair that
    /// fails any of the three is refused whole: there is no partially verified
    /// plan a window could render "most of".
    pub fn verify(view: &ProbePlanView) -> Result<Self, ProbePlanError> {
        if view.schema_version != PROBE_PLAN_SCHEMA_VERSION {
            return Err(ProbePlanError::UnverifiedPlan);
        }
        let plan = verify_plan_document(view.plan_document.as_bytes(), &view.plan_sha256)
            .map_err(|_| ProbePlanError::UnverifiedPlan)?;
        let rollback =
            verify_plan_document(view.rollback_document.as_bytes(), &view.rollback_sha256)
                .map_err(|_| ProbePlanError::UnverifiedPlan)?;
        if !plan.is_undone_by(&rollback) {
            return Err(ProbePlanError::UnverifiedPlan);
        }
        // The digests kept are the ones computed here, never the ones received.
        // They are equal — the verification above is exactly that equality —
        // and keeping the computed ones is what makes every value below the
        // result of reading the documents rather than of trusting their escort.
        let plan_sha256 = plan.sha256().map_err(|_| ProbePlanError::UnverifiedPlan)?;
        let rollback_sha256 = rollback
            .sha256()
            .map_err(|_| ProbePlanError::UnverifiedPlan)?;
        Ok(Self {
            plan,
            rollback,
            plan_sha256,
            rollback_sha256,
        })
    }

    pub fn machine_id(&self) -> &str {
        &self.plan.machine_id
    }

    pub fn operation(&self) -> PlanOperation {
        self.plan.operation
    }

    pub fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }

    pub fn rollback_sha256(&self) -> &str {
        &self.rollback_sha256
    }

    /// The lines the native confirmation window renders, in the order it
    /// renders them.
    ///
    /// They are built in the shape the consent windows of the bootstrap
    /// assistant already use — one labelled fact per line, no prose around it —
    /// and every value comes from the verified documents or from a constant of
    /// the contract. The loopback address is one of those constants rather than
    /// a field, so it is displayed and never approved: no value a human can
    /// confirm exposes the probe beyond its own machine.
    ///
    /// The rollback is named as the plan it is, with what it shares with the
    /// plan spelled out, because a return path a human did not read is a return
    /// path nobody approved.
    pub fn confirmation_lines(&self) -> Vec<String> {
        vec![
            format!("Machine : {}", self.plan.machine_id),
            format!("Opération : {}", operation_text(self.plan.operation)),
            format!("Image : {}", self.plan.image_reference),
            format!("Digest de l’image : {}", self.plan.image_digest),
            format!(
                "Port local : {PROBE_LOCAL_ADDRESS}:{}",
                self.plan.local_port
            ),
            format!(
                "Rollback : {}, sur la même machine, la même image et le même port",
                operation_text(self.rollback.operation)
            ),
            format!("Empreinte du plan : {}", self.plan_sha256),
            format!("Empreinte du rollback : {}", self.rollback_sha256),
        ]
    }

    /// The confirmation a window produces once the human accepted these lines.
    ///
    /// It can only be built from a pair that was verified, and it carries the
    /// two digests of that pair, so a confirmation collected on one plan can
    /// never be presented for another.
    pub fn confirmed(&self) -> ProbePlanConfirmation {
        ProbePlanConfirmation::Confirmed {
            plan_sha256: self.plan_sha256.clone(),
            rollback_sha256: self.rollback_sha256.clone(),
        }
    }

    /// The document the native confirmation window is given for this plan.
    ///
    /// It carries the sentences above and the two digests this side computed,
    /// and no document: the window renders what a human must read, and the pair
    /// stays here, where it was verified. A plan of another infrastructure never
    /// reaches a window at all, for the same reason it never reaches a
    /// signature.
    pub fn consent(
        &self,
        association: &AssociationRecord,
        request_id: &str,
        remaining_millis: u64,
    ) -> Result<ApprovalConsentV1, ProbePlanError> {
        if self.plan.infrastructure_id != association.summary.infrastructure_id {
            return Err(ProbePlanError::ForeignInfrastructure);
        }
        let confirmation_lines = self.confirmation_lines();
        Ok(build_consent(
            association,
            ConsentRequest {
                request_id,
                machine_id: &self.plan.machine_id,
                operation: approval_operation(self.plan.operation),
                plan_sha256: &self.plan_sha256,
                rollback_sha256: &self.rollback_sha256,
                confirmation_lines: &confirmation_lines,
                remaining_millis,
            },
        )?)
    }

    /// The confirmation a window answer produces, and a refusal for everything
    /// else.
    ///
    /// The consent is held against this presentation before the answer is even
    /// looked at, so an answer to a window opened on another pair cannot be
    /// laundered through a presentation of this one. What comes back is the
    /// ordinary [`ProbePlanConfirmation`], which [`Self::sign`] already refuses
    /// unless it names these exact two digests.
    pub fn confirmed_by(
        &self,
        consent: &ApprovalConsentV1,
        outcome: &ApprovalConsentOutcomeV1,
    ) -> ProbePlanConfirmation {
        if consent.plan_sha256 != self.plan_sha256
            || consent.rollback_sha256 != self.rollback_sha256
            || !consent_confirms(consent, outcome)
        {
            return ProbePlanConfirmation::Refused;
        }
        self.confirmed()
    }

    /// Signs the approval of this confirmed plan, and refuses everything else.
    ///
    /// The documents are re-verified here from the bytes that are still in
    /// hand: a transport that altered either of them between the window and
    /// this call produces another pair, which no longer matches this
    /// presentation nor the digests the confirmation names, and the signature
    /// does not happen. What is handed to the signing path as the plan is the
    /// exact bytes the plan digest is taken over, so the envelope names the
    /// digest that was displayed rather than a second digest of the same idea.
    pub fn sign(
        &self,
        association: &AssociationRecord,
        documents: &ProbePlanView,
        confirmation: &ProbePlanConfirmation,
        request: ProbeApprovalRequest,
    ) -> Result<SignedApprovalV1, ProbePlanError> {
        let ProbePlanConfirmation::Confirmed {
            plan_sha256,
            rollback_sha256,
        } = confirmation
        else {
            return Err(ProbePlanError::UnconfirmedPlan);
        };
        if *plan_sha256 != self.plan_sha256 || *rollback_sha256 != self.rollback_sha256 {
            return Err(ProbePlanError::UnconfirmedPlan);
        }
        if Self::verify(documents)? != *self {
            return Err(ProbePlanError::UnconfirmedPlan);
        }
        // Read from the plan and from the association, never from the request:
        // an approval can only ever name the infrastructure this Console is
        // associated to, and a plan that names another one is not this
        // Console's to approve.
        if self.plan.infrastructure_id != association.summary.infrastructure_id {
            return Err(ProbePlanError::ForeignInfrastructure);
        }

        let hashed_plan = self
            .plan
            .transcript()
            .map_err(|_| ProbePlanError::UnverifiedPlan)?;
        let hashed_rollback = self
            .rollback
            .transcript()
            .map_err(|_| ProbePlanError::UnverifiedPlan)?;
        let signed = sign_approval(
            association,
            ApprovalRequest {
                machine_id: &self.plan.machine_id,
                approval_epoch: request.approval_epoch,
                sequence: request.sequence,
                operation: approval_operation(self.plan.operation),
                plan: &hashed_plan,
                rollback: &hashed_rollback,
                issued_at_unix_seconds: request.issued_at_unix_seconds,
                lifetime_seconds: request.lifetime_seconds,
            },
        )?;
        // The envelope must name the two digests that were read on screen. The
        // equality is a fact of the encoding rather than a hope, and it is
        // asserted here so that it stays one.
        if signed.envelope.plan_sha256 != self.plan_sha256
            || signed.envelope.rollback_sha256 != self.rollback_sha256
        {
            return Err(ProbePlanError::UnconfirmedPlan);
        }
        Ok(signed)
    }
}

/// The closed bridge between what a plan describes and what an envelope
/// authorises. Each side has its own closed list, and this is the only place
/// they are mapped onto one another.
fn approval_operation(operation: PlanOperation) -> ApprovalOperation {
    match operation {
        PlanOperation::DeployOciProbe => ApprovalOperation::DeployOciProbe,
        PlanOperation::RemoveOciProbe => ApprovalOperation::RemoveOciProbe,
    }
}

fn operation_text(operation: PlanOperation) -> &'static str {
    match operation {
        PlanOperation::DeployOciProbe => "déployer la sonde de validation",
        PlanOperation::RemoveOciProbe => "retirer la sonde de validation",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::AssociationSummary;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use your_cloud_bootstrap_protocol::{
        ApprovalConsentOutcomeKind, ApprovalPrivilege, PROBE_IMAGE_DIGEST, PROBE_IMAGE_REFERENCE,
    };

    const INFRASTRUCTURE: &str = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2";
    const MACHINE: &str = "lab-machine-1";
    const ISSUED_AT: u64 = 1_780_000_000;
    const CONSENT_REQUEST_ID: &str = "00112233445566778899aabbccddeeff";

    /// The shared vector of the plan encoding, byte for byte. The very same
    /// documents and digests are pinned in
    /// `crates/bootstrap-protocol/src/plan.rs` and in
    /// `internal/plan/plan_test.go`.
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
    const PLAN_SHA256: &str = "2d50d2bc935ce6c56ef14fbfae93d670d5fdb9ca735315e5a26760d818dd5b0e";
    const ROLLBACK_SHA256: &str =
        "e953fb5f9d8423be61cad4a06d571e200977dd183f53c12d5a897746ad80497a";

    fn view() -> ProbePlanView {
        ProbePlanView {
            schema_version: PROBE_PLAN_SCHEMA_VERSION,
            plan_document: PLAN_DOCUMENT.to_owned(),
            plan_sha256: PLAN_SHA256.to_owned(),
            rollback_document: ROLLBACK_DOCUMENT.to_owned(),
            rollback_sha256: ROLLBACK_SHA256.to_owned(),
        }
    }

    fn request() -> ProbeApprovalRequest {
        ProbeApprovalRequest {
            approval_epoch: 1,
            sequence: 1,
            issued_at_unix_seconds: ISSUED_AT,
            lifetime_seconds: 300,
        }
    }

    /// A synthetic association whose human seed is the all-`0x01` vector. It is
    /// never a real key: it exists so the signature below is reproducible.
    fn association(infrastructure_id: &str) -> AssociationRecord {
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
            // Distinctive enough to be searched for in what this module emits.
            // A short word would be found inside a field name and would make
            // the search below pass for the wrong reason.
            device_private_key_pem: "synthetic-device-private-material".to_owned(),
            device_certificate_pem: "certificate".to_owned(),
            human_private_seed: URL_SAFE_NO_PAD.encode([1_u8; 32]),
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

    /// The nominal path, and the two facts it must produce: the pair is the one
    /// its digests name, and every value a human is about to read comes from
    /// the documents rather than from their escort.
    #[test]
    fn a_verified_pair_displays_exactly_what_its_documents_say() {
        let presented = PresentedProbePlan::verify(&view()).expect("the shared vector");
        assert_eq!(presented.machine_id(), MACHINE);
        assert_eq!(presented.operation(), PlanOperation::DeployOciProbe);
        assert_eq!(presented.plan_sha256(), PLAN_SHA256);
        assert_eq!(presented.rollback_sha256(), ROLLBACK_SHA256);

        assert_eq!(
            presented.confirmation_lines(),
            vec![
                format!("Machine : {MACHINE}"),
                "Opération : déployer la sonde de validation".to_owned(),
                format!("Image : {PROBE_IMAGE_REFERENCE}"),
                format!("Digest de l’image : {PROBE_IMAGE_DIGEST}"),
                format!("Port local : {PROBE_LOCAL_ADDRESS}:8080"),
                "Rollback : retirer la sonde de validation, sur la même machine, \
                 la même image et le même port"
                    .to_owned(),
                format!("Empreinte du plan : {PLAN_SHA256}"),
                format!("Empreinte du rollback : {ROLLBACK_SHA256}"),
            ]
        );
    }

    /// Nothing reaches a window before its digests are held.
    ///
    /// Each hostile pair below is one a transport could actually send: a
    /// document swapped for the other, a value moved inside a document, a
    /// rollback that undoes something else, a document outside the plan
    /// contract. None of them produces a value that can be displayed at all.
    #[test]
    fn an_unverified_pair_is_refused_before_it_can_be_displayed() {
        let altered_port = PLAN_DOCUMENT.replace(r#""local_port":8080"#, r#""local_port":9090"#);
        let altered_machine = PLAN_DOCUMENT.replace(
            r#""machine_id":"lab-machine-1""#,
            r#""machine_id":"lab-machine-2""#,
        );
        let other_image = PLAN_DOCUMENT.replace(PROBE_IMAGE_REFERENCE, "ghcr.io/attacker/whoami");
        for (name, hostile) in [
            (
                "an unsupported schema",
                ProbePlanView {
                    schema_version: 2,
                    ..view()
                },
            ),
            (
                "a plan whose port was moved after it was frozen",
                ProbePlanView {
                    plan_document: altered_port,
                    ..view()
                },
            ),
            (
                "a plan aimed at another machine under the same digest",
                ProbePlanView {
                    plan_document: altered_machine,
                    ..view()
                },
            ),
            (
                "a plan naming an image this palier does not pin",
                ProbePlanView {
                    plan_document: other_image,
                    ..view()
                },
            ),
            (
                "the two documents exchanged",
                ProbePlanView {
                    plan_document: ROLLBACK_DOCUMENT.to_owned(),
                    rollback_document: PLAN_DOCUMENT.to_owned(),
                    ..view()
                },
            ),
            (
                "a rollback that is a second copy of the plan",
                ProbePlanView {
                    rollback_document: PLAN_DOCUMENT.to_owned(),
                    rollback_sha256: PLAN_SHA256.to_owned(),
                    ..view()
                },
            ),
            (
                "an upper-case digest",
                ProbePlanView {
                    plan_sha256: PLAN_SHA256.to_ascii_uppercase(),
                    ..view()
                },
            ),
            (
                "an empty document",
                ProbePlanView {
                    plan_document: String::new(),
                    ..view()
                },
            ),
        ] {
            assert!(
                matches!(
                    PresentedProbePlan::verify(&hostile),
                    Err(ProbePlanError::UnverifiedPlan)
                ),
                "{name} reached the confirmation window"
            );
        }
    }

    /// The envelope names exactly the digests that were displayed, and exactly
    /// the privileges the contract's table gives the operation.
    #[test]
    fn a_confirmed_plan_is_signed_with_the_digests_that_were_displayed() {
        let record = association(INFRASTRUCTURE);
        let presented = PresentedProbePlan::verify(&view()).unwrap();
        let signed = presented
            .sign(&record, &view(), &presented.confirmed(), request())
            .expect("a confirmed plan is signed");

        assert_eq!(signed.envelope.plan_sha256, PLAN_SHA256);
        assert_eq!(signed.envelope.rollback_sha256, ROLLBACK_SHA256);
        assert_eq!(signed.envelope.machine_id, MACHINE);
        assert_eq!(signed.envelope.infrastructure_id, INFRASTRUCTURE);
        assert_eq!(signed.envelope.operation, ApprovalOperation::DeployOciProbe);
        assert_eq!(
            signed.envelope.privileges,
            vec![
                ApprovalPrivilege::MutateLocalState,
                ApprovalPrivilege::ReadLocalState,
            ]
        );
        assert!(signed.envelope.is_mutating());
        // The signature really covers the transcript of that envelope, and the
        // envelope really is one the shared contract accepts.
        assert!(signed.clone().validate().is_ok());

        // The rollback direction of the same instance is the other operation,
        // with the two digests exchanged and the same exact privilege list.
        let reverse = ProbePlanView {
            plan_document: ROLLBACK_DOCUMENT.to_owned(),
            plan_sha256: ROLLBACK_SHA256.to_owned(),
            rollback_document: PLAN_DOCUMENT.to_owned(),
            rollback_sha256: PLAN_SHA256.to_owned(),
            ..view()
        };
        let presented_reverse = PresentedProbePlan::verify(&reverse).unwrap();
        let signed_reverse = presented_reverse
            .sign(&record, &reverse, &presented_reverse.confirmed(), request())
            .expect("the removal of the same instance");
        assert_eq!(
            signed_reverse.envelope.operation,
            ApprovalOperation::RemoveOciProbe
        );
        assert_eq!(signed_reverse.envelope.plan_sha256, ROLLBACK_SHA256);
        assert_eq!(signed_reverse.envelope.rollback_sha256, PLAN_SHA256);
        assert_eq!(
            signed_reverse.envelope.privileges,
            signed.envelope.privileges
        );
        assert_ne!(signed_reverse.signature, signed.signature);
    }

    /// A confirmation covers two exact documents, and stops covering anything
    /// the moment either of them moves.
    #[test]
    fn a_confirmation_does_not_survive_the_documents_it_was_given_for() {
        let record = association(INFRASTRUCTURE);
        let presented = PresentedProbePlan::verify(&view()).unwrap();
        let confirmation = presented.confirmed();

        // The pair the window rendered, re-presented with the removal in place
        // of the deployment: a valid pair in its own right, and not the one
        // that was confirmed.
        let exchanged = ProbePlanView {
            plan_document: ROLLBACK_DOCUMENT.to_owned(),
            plan_sha256: ROLLBACK_SHA256.to_owned(),
            rollback_document: PLAN_DOCUMENT.to_owned(),
            rollback_sha256: PLAN_SHA256.to_owned(),
            ..view()
        };
        assert!(matches!(
            presented.sign(&record, &exchanged, &confirmation, request()),
            Err(ProbePlanError::UnconfirmedPlan)
        ));

        // Documents altered after they were displayed no longer verify at all.
        let altered = ProbePlanView {
            plan_document: PLAN_DOCUMENT.replace(r#""local_port":8080"#, r#""local_port":9090"#),
            ..view()
        };
        assert!(matches!(
            presented.sign(&record, &altered, &confirmation, request()),
            Err(ProbePlanError::UnverifiedPlan)
        ));

        // A refusal is not a confirmation, and neither is a confirmation whose
        // digests name another pair.
        for hostile in [
            ProbePlanConfirmation::Refused,
            ProbePlanConfirmation::Confirmed {
                plan_sha256: ROLLBACK_SHA256.to_owned(),
                rollback_sha256: PLAN_SHA256.to_owned(),
            },
            ProbePlanConfirmation::Confirmed {
                plan_sha256: PLAN_SHA256.to_owned(),
                rollback_sha256: String::new(),
            },
        ] {
            assert!(matches!(
                presented.sign(&record, &view(), &hostile, request()),
                Err(ProbePlanError::UnconfirmedPlan)
            ));
        }
    }

    /// A plan is approved by the Console of its own infrastructure or by none.
    #[test]
    fn a_plan_of_another_infrastructure_is_never_signed() {
        let presented = PresentedProbePlan::verify(&view()).unwrap();
        let foreign = association("8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3");
        assert!(matches!(
            presented.sign(&foreign, &view(), &presented.confirmed(), request()),
            Err(ProbePlanError::ForeignInfrastructure)
        ));
    }

    /// A request outside the bounds of the envelope produces no signature, and
    /// the refusal comes from the one signing path rather than from a second
    /// rule written here.
    #[test]
    fn a_request_outside_the_envelope_bounds_produces_no_signature() {
        let record = association(INFRASTRUCTURE);
        let presented = PresentedProbePlan::verify(&view()).unwrap();
        for hostile in [
            ProbeApprovalRequest {
                approval_epoch: 0,
                ..request()
            },
            ProbeApprovalRequest {
                sequence: 0,
                ..request()
            },
            ProbeApprovalRequest {
                lifetime_seconds: 0,
                ..request()
            },
            ProbeApprovalRequest {
                issued_at_unix_seconds: 0,
                ..request()
            },
        ] {
            assert!(matches!(
                presented.sign(&record, &view(), &presented.confirmed(), hostile),
                Err(ProbePlanError::Approval(ApprovalError::InvalidRequest))
            ));
        }
    }

    /// The whole path a human really travels, in one test.
    ///
    /// A verified pair becomes the document a native window is given; the
    /// window answers; and only an answer that confirms *this* pair produces a
    /// signature. The two ends of that path are already asserted elsewhere —
    /// what is asserted here is that they are joined, and that nothing joins
    /// them except a window.
    #[test]
    fn only_a_window_answer_on_this_pair_leads_to_a_signature() {
        let record = association(INFRASTRUCTURE);
        let presented = PresentedProbePlan::verify(&view()).unwrap();
        let consent = presented
            .consent(&record, CONSENT_REQUEST_ID, 120_000)
            .expect("a verified pair opens a window");

        // The window is given the sentences and the two digests, and neither
        // document: what it renders is what a human reads, not what a machine
        // will receive.
        assert_eq!(consent.confirmation_lines, presented.confirmation_lines());
        assert_eq!(consent.plan_sha256, PLAN_SHA256);
        assert_eq!(consent.rollback_sha256, ROLLBACK_SHA256);
        assert_eq!(consent.machine_id, MACHINE);
        assert_eq!(consent.infrastructure_id, INFRASTRUCTURE);
        let rendered = serde_json::to_string(&consent).unwrap();
        assert!(!rendered.contains(PLAN_DOCUMENT));
        assert!(!rendered.contains(ROLLBACK_DOCUMENT));
        assert!(!rendered.contains(&record.human_private_seed));

        // Its confirmation is the one the signing path already accepts.
        let confirmation = presented.confirmed_by(&consent, &consent.confirmed());
        assert_eq!(confirmation, presented.confirmed());
        let signed = presented
            .sign(&record, &view(), &confirmation, request())
            .expect("a window-confirmed plan is signed");
        assert_eq!(signed.envelope.plan_sha256, PLAN_SHA256);
        assert_eq!(signed.envelope.rollback_sha256, ROLLBACK_SHA256);

        // Every other answer refuses, and a refusal signs nothing.
        for kind in [
            ApprovalConsentOutcomeKind::Refused,
            ApprovalConsentOutcomeKind::Cancelled,
            ApprovalConsentOutcomeKind::Expired,
            ApprovalConsentOutcomeKind::Unavailable,
        ] {
            let answered = ApprovalConsentOutcomeV1::without_confirmation(CONSENT_REQUEST_ID, kind);
            let refused = presented.confirmed_by(&consent, &answered);
            assert_eq!(refused, ProbePlanConfirmation::Refused, "{kind:?}");
            assert!(matches!(
                presented.sign(&record, &view(), &refused, request()),
                Err(ProbePlanError::UnconfirmedPlan)
            ));
        }

        // A window opened on the reverse pair is a window about another plan,
        // and its confirmation does not carry over.
        let reverse = ProbePlanView {
            plan_document: ROLLBACK_DOCUMENT.to_owned(),
            plan_sha256: ROLLBACK_SHA256.to_owned(),
            rollback_document: PLAN_DOCUMENT.to_owned(),
            rollback_sha256: PLAN_SHA256.to_owned(),
            ..view()
        };
        let reverse_presented = PresentedProbePlan::verify(&reverse).unwrap();
        let reverse_consent = reverse_presented
            .consent(&record, CONSENT_REQUEST_ID, 120_000)
            .unwrap();
        assert_eq!(
            presented.confirmed_by(&reverse_consent, &reverse_consent.confirmed()),
            ProbePlanConfirmation::Refused
        );
        // Nor does an answer meant for this pair confirm the reverse one.
        assert_eq!(
            reverse_presented.confirmed_by(&consent, &consent.confirmed()),
            ProbePlanConfirmation::Refused
        );

        // A plan of another infrastructure opens no window at all, for the same
        // reason it reaches no signature.
        assert!(matches!(
            presented.consent(
                &association("8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3"),
                CONSENT_REQUEST_ID,
                120_000,
            ),
            Err(ProbePlanError::ForeignInfrastructure)
        ));
    }

    /// Nothing this module produces carries key material.
    ///
    /// The signed document names the public half and the signature, both of
    /// which are meant to travel, and the lines a window renders are facts
    /// about a plan. The private seed of the association appears in neither,
    /// which is what "the native core signs and the frontend never sees the
    /// key" has to mean at the surface.
    #[test]
    fn the_surface_this_module_produces_carries_no_key_material() {
        let record = association(INFRASTRUCTURE);
        let presented = PresentedProbePlan::verify(&view()).unwrap();
        let signed = presented
            .sign(&record, &view(), &presented.confirmed(), request())
            .unwrap();

        let rendered = serde_json::to_string(&signed).unwrap();
        assert!(rendered.contains(&signed.envelope.approval_public_key));
        assert!(!rendered.contains(&record.human_private_seed));
        assert!(!rendered.contains(&record.device_private_key_pem));

        let displayed = presented.confirmation_lines().concat();
        assert!(!displayed.contains(&record.human_private_seed));
        assert!(!displayed.contains(&signed.signature));
        assert!(!format!("{:?}", presented.confirmed()).contains(&record.human_private_seed));
    }

    /// Chaque refus de cette table porte son propre code, et aucun ne se
    /// présente comme une saisie mal formée.
    ///
    /// Le contrôle est direct sur la table plutôt que sur un refus produit par
    /// un chemin : ces variantes ne sont encore atteintes par aucun appelant, et
    /// c'est exactement pourquoi le contrôle existe. La garde inter-sources de
    /// `check-source-contract.mjs` confronte les codes que le cœur émet aux
    /// phrases que la vue porte ; elle ne peut rien dire d'une table qu'aucun
    /// chemin n'emprunte. Ce test est ce qui tient cette table-là jusqu'au jour
    /// du câblage (`#136`).
    #[test]
    fn each_refusal_of_this_table_carries_its_own_code() {
        let codes = [
            ProbePlanError::UnverifiedPlan.public_code(),
            ProbePlanError::ForeignInfrastructure.public_code(),
            ProbePlanError::UnconfirmedPlan.public_code(),
        ];
        assert_eq!(
            codes,
            [
                "unverified_plan",
                "foreign_infrastructure",
                "unconfirmed_plan"
            ]
        );
        let distinct: std::collections::BTreeSet<&&str> = codes.iter().collect();
        assert_eq!(
            distinct.len(),
            codes.len(),
            "deux refus partagent un code : {codes:?}"
        );
        assert!(
            !codes.contains(&"invalid_input"),
            "un refus de sécurité se présente encore comme une saisie mal formée : {codes:?}"
        );
    }
}
