//! The three plans of the public profile, from the bytes the Controller froze
//! to the envelope the native core signs over them.
//!
//! It is the schema 2 counterpart of [`crate::probe_plan`], and it holds the
//! same three properties for the same reasons — a plan is verified before it is
//! displayed, a confirmation covers two exact documents, and the signature is
//! the one that already exists. What changes is what a human reads: a service
//! names a profile, an image and a loopback port; an entrypoint names an image
//! and the constants a public listener implies; a route names a declared host,
//! the loopback port behind it and the isolation headers its fragment adds.
//!
//! **Nothing is displayed that has not been verified.**
//! [`PresentedPublicationPlan`] is the only way to obtain the lines a window
//! renders, and the only way to obtain one is
//! [`PresentedPublicationPlan::verify`], which rebuilds both digests from the
//! fields it parsed out of the received bytes. A pair whose digests do not match
//! never becomes a thing anyone can be shown.
//!
//! **A confirmation covers two exact documents.**
//! [`PublicationPlanConfirmation`] carries the two digests it was given for, and
//! signing re-reads the documents from scratch and refuses when either the pair
//! or the confirmed digests have moved.
//!
//! **The signature is the one that already exists.** Nothing here holds a key or
//! builds a transcript: [`crate::approval::sign_approval`] does, from a typed
//! request, and what this module hands it as the plan is the exact bytes the
//! plan digest is taken over.
//!
//! **The kind of plan is read in the document, never in the route.** The three
//! sibling Controller routes answer the same frozen-pair shape, so the operation
//! inside the document is what decides which closed field list was approved and
//! which lines a human is shown. A service plan returned by the route endpoint
//! is therefore still a service plan here, displayed as one and signed as one.

use crate::{
    approval::{sign_approval, ApprovalError, ApprovalRequest},
    vault::AssociationRecord,
};
use serde::Deserialize;
use your_cloud_bootstrap_protocol::{
    verify_plan_v2_document, ApprovalOperation, PlanDocumentV2, PlanV2Group, PlanV2Operation,
    SignedApprovalV1, ENTRYPOINT_PUBLIC_HTTPS_PORT, ENTRYPOINT_PUBLIC_HTTP_PORT,
    ENTRYPOINT_UNPRIVILEGED_PORT_SYSCTL, ROUTE_ISOLATION_HEADERS, SERVICE_LOCAL_ADDRESS,
};

/// The one schema of the pairs this palier reads.
const PUBLICATION_PLAN_SCHEMA_VERSION: u8 = 2;

#[derive(Debug, thiserror::Error)]
pub enum PublicationPlanError {
    #[error("the plan pair is not the one its own digests name")]
    UnverifiedPlan,
    #[error("the plan names another infrastructure than this Console is associated to")]
    ForeignInfrastructure,
    #[error("no confirmation covers these exact documents")]
    UnconfirmedPlan,
    #[error("the approval of this plan could not be signed")]
    Approval(#[from] ApprovalError),
}

impl PublicationPlanError {
    pub fn public_code(&self) -> &'static str {
        match self {
            Self::UnverifiedPlan | Self::ForeignInfrastructure | Self::UnconfirmedPlan => {
                "invalid_input"
            }
            Self::Approval(error) => error.public_code(),
        }
    }
}

/// The frozen pair exactly as `POST /v0/service-plans`, `/v0/entrypoint-plans`
/// and `/v0/route-plans` answer it.
///
/// It is one shape for the three routes because what differs between them is
/// what a human approves, not how the bytes travel. The two documents travel as
/// strings holding their own canonical bytes rather than as nested objects,
/// which is the whole reason this side needs no canonical encoder: what it
/// verifies, what it displays and what the Auxiliary will later receive are the
/// same bytes rather than three encodings that happen to agree. The digests
/// travel beside them and are not an authority — they are the claim this module
/// refuses or accepts.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanPairView {
    pub schema_version: u8,
    pub plan_document: String,
    pub plan_sha256: String,
    pub rollback_document: String,
    pub rollback_sha256: String,
}

/// A pair that has been held against its own digests, and the digests this side
/// computed rather than the ones it was handed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentedPublicationPlan {
    plan: PlanDocumentV2,
    rollback: PlanDocumentV2,
    plan_sha256: String,
    rollback_sha256: String,
}

/// What the native confirmation window answered.
///
/// A confirmation names the two digests it was given for. It is therefore not a
/// permission to sign "the current plan": it is a permission to sign those two
/// documents, and it stops meaning anything the moment either of them moves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicationPlanConfirmation {
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
pub struct PublicationApprovalRequest {
    pub approval_epoch: u64,
    pub sequence: u64,
    pub issued_at_unix_seconds: u64,
    pub lifetime_seconds: u64,
}

impl PresentedPublicationPlan {
    /// Verifies the whole pair before any of it can be displayed.
    ///
    /// Both documents are strict-decoded inside the bounds of the schema 2
    /// contract — profile, pinned image, port range, host bounds included — both
    /// digests are rebuilt from the parsed fields, and the rollback is required
    /// to be the complete document that undoes the plan: the same operation
    /// group, the same instance, the inverse operation and nothing else changed.
    /// A pair that fails any of the three is refused whole: there is no
    /// partially verified plan a window could render "most of".
    pub fn verify(view: &PlanPairView) -> Result<Self, PublicationPlanError> {
        if view.schema_version != PUBLICATION_PLAN_SCHEMA_VERSION {
            return Err(PublicationPlanError::UnverifiedPlan);
        }
        let plan = verify_plan_v2_document(view.plan_document.as_bytes(), &view.plan_sha256)
            .map_err(|_| PublicationPlanError::UnverifiedPlan)?;
        let rollback =
            verify_plan_v2_document(view.rollback_document.as_bytes(), &view.rollback_sha256)
                .map_err(|_| PublicationPlanError::UnverifiedPlan)?;
        if !plan.is_undone_by(&rollback) {
            return Err(PublicationPlanError::UnverifiedPlan);
        }
        // The digests kept are the ones computed here, never the ones received.
        // They are equal — the verification above is exactly that equality —
        // and keeping the computed ones is what makes every value below the
        // result of reading the documents rather than of trusting their escort.
        let plan_sha256 = plan
            .sha256()
            .map_err(|_| PublicationPlanError::UnverifiedPlan)?;
        let rollback_sha256 = rollback
            .sha256()
            .map_err(|_| PublicationPlanError::UnverifiedPlan)?;
        Ok(Self {
            plan,
            rollback,
            plan_sha256,
            rollback_sha256,
        })
    }

    pub fn machine_id(&self) -> &str {
        self.plan.machine_id()
    }

    pub fn operation(&self) -> PlanV2Operation {
        self.plan.operation()
    }

    pub fn group(&self) -> PlanV2Group {
        self.plan.group()
    }

    pub fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }

    pub fn rollback_sha256(&self) -> &str {
        &self.rollback_sha256
    }

    /// The lines the native confirmation window renders, in the order it renders
    /// them.
    ///
    /// They are built in the shape the consent windows of the bootstrap
    /// assistant already use — one labelled fact per line, no prose around it —
    /// and every value comes from the verified documents or from a constant of
    /// the contract. The constants are displayed and never approved as values:
    /// the loopback address, the two public ports of the entrypoint and the
    /// isolation headers of a route decide nothing a human could change, but
    /// each of them is part of what the plan does to the machine, so none of
    /// them is left out.
    ///
    /// The entrypoint names its host-wide effect explicitly. Lowering the
    /// unprivileged port floor is the one relaxation this palier applies outside
    /// the service's own namespace, and the contract requires it to be written
    /// in what the human approves rather than done in silence.
    ///
    /// The rollback is named as the plan it is, with what it shares with the
    /// plan spelled out, because a return path a human did not read is a return
    /// path nobody approved.
    pub fn confirmation_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("Machine : {}", self.plan.machine_id()),
            format!("Opération : {}", operation_text(self.plan.operation())),
        ];
        match &self.plan {
            PlanDocumentV2::WebService(document) => {
                lines.push(format!("Profil de service : {}", document.service_profile));
                lines.push(format!("Image : {}", document.image_reference));
                lines.push(format!("Digest de l’image : {}", document.image_digest));
                lines.push(format!(
                    "Port local : {SERVICE_LOCAL_ADDRESS}:{}",
                    document.local_port
                ));
            }
            PlanDocumentV2::Entrypoint(document) => {
                lines.push(format!("Image : {}", document.image_reference));
                lines.push(format!("Digest de l’image : {}", document.image_digest));
                lines.push(format!(
                    "Ports publics : {ENTRYPOINT_PUBLIC_HTTPS_PORT} en HTTPS, \
                     {ENTRYPOINT_PUBLIC_HTTP_PORT} limité à la redirection"
                ));
                lines.push(format!(
                    "Effet sur l’hôte : sysctl {ENTRYPOINT_UNPRIVILEGED_PORT_SYSCTL}, \
                     appliqué avec ce plan et retiré avec lui"
                ));
            }
            PlanDocumentV2::Route(document) => {
                lines.push(format!("Nom publié : {}", document.route_host));
                lines.push(format!(
                    "Service joint : {SERVICE_LOCAL_ADDRESS}:{}",
                    document.backend_port
                ));
                for header in ROUTE_ISOLATION_HEADERS {
                    lines.push(format!("En-tête d’isolation : {header}"));
                }
            }
        }
        lines.push(format!(
            "Rollback : {}, {}",
            operation_text(self.rollback.operation()),
            rollback_scope_text(self.rollback.group())
        ));
        lines.push(format!("Empreinte du plan : {}", self.plan_sha256));
        lines.push(format!("Empreinte du rollback : {}", self.rollback_sha256));
        lines
    }

    /// The confirmation a window produces once the human accepted these lines.
    ///
    /// It can only be built from a pair that was verified, and it carries the
    /// two digests of that pair, so a confirmation collected on one plan can
    /// never be presented for another.
    pub fn confirmed(&self) -> PublicationPlanConfirmation {
        PublicationPlanConfirmation::Confirmed {
            plan_sha256: self.plan_sha256.clone(),
            rollback_sha256: self.rollback_sha256.clone(),
        }
    }

    /// Signs the approval of this confirmed plan, and refuses everything else.
    ///
    /// The documents are re-verified here from the bytes that are still in
    /// hand: a transport that altered either of them between the window and this
    /// call produces another pair, which no longer matches this presentation nor
    /// the digests the confirmation names, and the signature does not happen.
    /// What is handed to the signing path as the plan is the exact bytes the
    /// plan digest is taken over, so the envelope names the digest that was
    /// displayed rather than a second digest of the same idea.
    pub fn sign(
        &self,
        association: &AssociationRecord,
        documents: &PlanPairView,
        confirmation: &PublicationPlanConfirmation,
        request: PublicationApprovalRequest,
    ) -> Result<SignedApprovalV1, PublicationPlanError> {
        let PublicationPlanConfirmation::Confirmed {
            plan_sha256,
            rollback_sha256,
        } = confirmation
        else {
            return Err(PublicationPlanError::UnconfirmedPlan);
        };
        if *plan_sha256 != self.plan_sha256 || *rollback_sha256 != self.rollback_sha256 {
            return Err(PublicationPlanError::UnconfirmedPlan);
        }
        if Self::verify(documents)? != *self {
            return Err(PublicationPlanError::UnconfirmedPlan);
        }
        // Read from the plan and from the association, never from the request:
        // an approval can only ever name the infrastructure this Console is
        // associated to, and a plan that names another one is not this
        // Console's to approve.
        if self.plan.infrastructure_id() != association.summary.infrastructure_id.as_str() {
            return Err(PublicationPlanError::ForeignInfrastructure);
        }

        let hashed_plan = self
            .plan
            .transcript()
            .map_err(|_| PublicationPlanError::UnverifiedPlan)?;
        let hashed_rollback = self
            .rollback
            .transcript()
            .map_err(|_| PublicationPlanError::UnverifiedPlan)?;
        let signed = sign_approval(
            association,
            ApprovalRequest {
                machine_id: self.plan.machine_id(),
                approval_epoch: request.approval_epoch,
                sequence: request.sequence,
                operation: approval_operation(self.plan.operation()),
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
            return Err(PublicationPlanError::UnconfirmedPlan);
        }
        Ok(signed)
    }
}

/// The closed bridge between what a plan describes and what an envelope
/// authorises. Each side has its own closed list, and this is the only place
/// they are mapped onto one another for schema 2.
fn approval_operation(operation: PlanV2Operation) -> ApprovalOperation {
    match operation {
        PlanV2Operation::DeployWebService => ApprovalOperation::DeployWebService,
        PlanV2Operation::RemoveWebService => ApprovalOperation::RemoveWebService,
        PlanV2Operation::DeployEntrypoint => ApprovalOperation::DeployEntrypoint,
        PlanV2Operation::RemoveEntrypoint => ApprovalOperation::RemoveEntrypoint,
        PlanV2Operation::PublishRoute => ApprovalOperation::PublishRoute,
        PlanV2Operation::RetireRoute => ApprovalOperation::RetireRoute,
    }
}

fn operation_text(operation: PlanV2Operation) -> &'static str {
    match operation {
        PlanV2Operation::DeployWebService => "déployer le service web du profil public",
        PlanV2Operation::RemoveWebService => "retirer le service web du profil public",
        PlanV2Operation::DeployEntrypoint => "déployer le point d’entrée public",
        PlanV2Operation::RemoveEntrypoint => "retirer le point d’entrée public",
        PlanV2Operation::PublishRoute => "publier la route déclarée",
        PlanV2Operation::RetireRoute => "retirer la route déclarée",
    }
}

/// What a rollback shares with the plan it undoes, group by group. It is the
/// whole of what "exact inverse" means on screen: everything but the operation.
fn rollback_scope_text(group: PlanV2Group) -> &'static str {
    match group {
        PlanV2Group::WebService => {
            "sur la même machine, le même profil, la même image et le même port"
        }
        PlanV2Group::Entrypoint => "sur la même machine et la même image",
        PlanV2Group::Route => "sur la même machine, le même nom et le même port",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::AssociationSummary;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use your_cloud_bootstrap_protocol::{
        ApprovalPrivilege, BENTOPDF_IMAGE_DIGEST, BENTOPDF_IMAGE_REFERENCE,
        ENTRYPOINT_IMAGE_DIGEST, ENTRYPOINT_IMAGE_REFERENCE, SERVICE_PROFILE_BENTOPDF,
    };

    const INFRASTRUCTURE: &str = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2";
    const MACHINE: &str = "lab-machine-1";
    const ROUTE_HOST: &str = "bentopdf.lab.your-cloud.test";
    const ISSUED_AT: u64 = 1_780_000_000;

    /// The six shared vectors of the schema 2 encoding, byte for byte. The very
    /// same documents and digests are pinned in
    /// `crates/bootstrap-protocol/src/plan_v2.rs` and in
    /// `internal/plan/schema2_test.go`.
    const WEB_SERVICE_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"deploy_web_service","#,
        r#""service_profile":"bentopdf","image_reference":"ghcr.io/alam00000/bentopdf","#,
        r#""image_digest":"sha256:a4ed090f29823da5e296e2c2f8603664da71676156ea47c3f186cc73eec38db0","#,
        r#""local_port":8080}"#,
    );
    const WEB_SERVICE_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"remove_web_service","#,
        r#""service_profile":"bentopdf","image_reference":"ghcr.io/alam00000/bentopdf","#,
        r#""image_digest":"sha256:a4ed090f29823da5e296e2c2f8603664da71676156ea47c3f186cc73eec38db0","#,
        r#""local_port":8080}"#,
    );
    const ENTRYPOINT_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"deploy_entrypoint","#,
        r#""image_reference":"docker.io/library/traefik","#,
        r#""image_digest":"sha256:9c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab2614cbaf410dcb2ac"}"#,
    );
    const ENTRYPOINT_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"remove_entrypoint","#,
        r#""image_reference":"docker.io/library/traefik","#,
        r#""image_digest":"sha256:9c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab2614cbaf410dcb2ac"}"#,
    );
    const ROUTE_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"publish_route","#,
        r#""route_host":"bentopdf.lab.your-cloud.test","backend_port":8080}"#,
    );
    const ROUTE_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"retire_route","#,
        r#""route_host":"bentopdf.lab.your-cloud.test","backend_port":8080}"#,
    );

    const WEB_SERVICE_PLAN_SHA256: &str =
        "99f6e6401d74583f64e4200e6e47cd365ab299466eebe1c1a7210f260b0366ae";
    const WEB_SERVICE_ROLLBACK_SHA256: &str =
        "4e480f76a7247cde6c41990e941512dce70f0a272a17a2618211bd03230ced68";
    const ENTRYPOINT_PLAN_SHA256: &str =
        "fe15d468f77ed9ca6b54da9a63860278894be7db4b6d997898b55fcb602f3722";
    const ENTRYPOINT_ROLLBACK_SHA256: &str =
        "1b91a7fa77b7d02cc16ce5d694b1709f641a341c849b4459de0ee3960d1cfcd8";
    const ROUTE_PLAN_SHA256: &str =
        "3d92c310868a8ba98aca5501c069bd0e4674757f787c8095e7c39d65d8d20a89";
    const ROUTE_ROLLBACK_SHA256: &str =
        "93e844abe96e68f157eb715ace9ff423004b0c64c68536d4e79ebc8206da1324";

    fn view(
        plan_document: &str,
        plan_sha256: &str,
        rollback_document: &str,
        rollback_sha256: &str,
    ) -> PlanPairView {
        PlanPairView {
            schema_version: PUBLICATION_PLAN_SCHEMA_VERSION,
            plan_document: plan_document.to_owned(),
            plan_sha256: plan_sha256.to_owned(),
            rollback_document: rollback_document.to_owned(),
            rollback_sha256: rollback_sha256.to_owned(),
        }
    }

    fn service_view() -> PlanPairView {
        view(
            WEB_SERVICE_PLAN_DOCUMENT,
            WEB_SERVICE_PLAN_SHA256,
            WEB_SERVICE_ROLLBACK_DOCUMENT,
            WEB_SERVICE_ROLLBACK_SHA256,
        )
    }

    fn entrypoint_view() -> PlanPairView {
        view(
            ENTRYPOINT_PLAN_DOCUMENT,
            ENTRYPOINT_PLAN_SHA256,
            ENTRYPOINT_ROLLBACK_DOCUMENT,
            ENTRYPOINT_ROLLBACK_SHA256,
        )
    }

    fn route_view() -> PlanPairView {
        view(
            ROUTE_PLAN_DOCUMENT,
            ROUTE_PLAN_SHA256,
            ROUTE_ROLLBACK_DOCUMENT,
            ROUTE_ROLLBACK_SHA256,
        )
    }

    fn request() -> PublicationApprovalRequest {
        PublicationApprovalRequest {
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

    /// The nominal path of the service group: the pair is the one its digests
    /// name, and every value a human is about to read comes from the documents
    /// or from a constant of the contract rather than from their escort.
    #[test]
    fn a_verified_service_pair_displays_exactly_what_its_documents_say() {
        let presented = PresentedPublicationPlan::verify(&service_view()).expect("the vector");
        assert_eq!(presented.machine_id(), MACHINE);
        assert_eq!(presented.operation(), PlanV2Operation::DeployWebService);
        assert_eq!(presented.group(), PlanV2Group::WebService);
        assert_eq!(presented.plan_sha256(), WEB_SERVICE_PLAN_SHA256);
        assert_eq!(presented.rollback_sha256(), WEB_SERVICE_ROLLBACK_SHA256);

        assert_eq!(
            presented.confirmation_lines(),
            vec![
                format!("Machine : {MACHINE}"),
                "Opération : déployer le service web du profil public".to_owned(),
                format!("Profil de service : {SERVICE_PROFILE_BENTOPDF}"),
                format!("Image : {BENTOPDF_IMAGE_REFERENCE}"),
                format!("Digest de l’image : {BENTOPDF_IMAGE_DIGEST}"),
                format!("Port local : {SERVICE_LOCAL_ADDRESS}:8080"),
                "Rollback : retirer le service web du profil public, sur la même machine, \
                 le même profil, la même image et le même port"
                    .to_owned(),
                format!("Empreinte du plan : {WEB_SERVICE_PLAN_SHA256}"),
                format!("Empreinte du rollback : {WEB_SERVICE_ROLLBACK_SHA256}"),
            ]
        );
    }

    /// The entrypoint names its image and the constants a public listener
    /// implies, including the host-wide relaxation the plan applies and removes.
    #[test]
    fn a_verified_entrypoint_pair_displays_the_constants_it_implies() {
        let presented = PresentedPublicationPlan::verify(&entrypoint_view()).expect("the vector");
        assert_eq!(presented.operation(), PlanV2Operation::DeployEntrypoint);
        assert_eq!(presented.group(), PlanV2Group::Entrypoint);

        assert_eq!(
            presented.confirmation_lines(),
            vec![
                format!("Machine : {MACHINE}"),
                "Opération : déployer le point d’entrée public".to_owned(),
                format!("Image : {ENTRYPOINT_IMAGE_REFERENCE}"),
                format!("Digest de l’image : {ENTRYPOINT_IMAGE_DIGEST}"),
                "Ports publics : 443 en HTTPS, 80 limité à la redirection".to_owned(),
                "Effet sur l’hôte : sysctl net.ipv4.ip_unprivileged_port_start=80, \
                 appliqué avec ce plan et retiré avec lui"
                    .to_owned(),
                "Rollback : retirer le point d’entrée public, sur la même machine \
                 et la même image"
                    .to_owned(),
                format!("Empreinte du plan : {ENTRYPOINT_PLAN_SHA256}"),
                format!("Empreinte du rollback : {ENTRYPOINT_ROLLBACK_SHA256}"),
            ]
        );
    }

    /// The route names the host, the loopback port behind it and the two
    /// isolation headers its fragment adds.
    #[test]
    fn a_verified_route_pair_displays_the_headers_it_adds() {
        let presented = PresentedPublicationPlan::verify(&route_view()).expect("the vector");
        assert_eq!(presented.operation(), PlanV2Operation::PublishRoute);
        assert_eq!(presented.group(), PlanV2Group::Route);

        assert_eq!(
            presented.confirmation_lines(),
            vec![
                format!("Machine : {MACHINE}"),
                "Opération : publier la route déclarée".to_owned(),
                format!("Nom publié : {ROUTE_HOST}"),
                format!("Service joint : {SERVICE_LOCAL_ADDRESS}:8080"),
                "En-tête d’isolation : Cross-Origin-Opener-Policy: same-origin".to_owned(),
                "En-tête d’isolation : Cross-Origin-Embedder-Policy: require-corp".to_owned(),
                "Rollback : retirer la route déclarée, sur la même machine, le même nom \
                 et le même port"
                    .to_owned(),
                format!("Empreinte du plan : {ROUTE_PLAN_SHA256}"),
                format!("Empreinte du rollback : {ROUTE_ROLLBACK_SHA256}"),
            ]
        );
    }

    /// Nothing reaches a window before its digests are held.
    ///
    /// Each hostile pair below is one a transport could actually send: a
    /// document swapped for the other, a value moved inside a document, a
    /// rollback that undoes something else, a pair whose two documents belong to
    /// different operation groups, a document outside the schema 2 contract.
    /// None of them produces a value that can be displayed at all.
    #[test]
    fn an_unverified_pair_is_refused_before_it_can_be_displayed() {
        let altered_port =
            WEB_SERVICE_PLAN_DOCUMENT.replace(r#""local_port":8080"#, r#""local_port":9090"#);
        let altered_machine = ROUTE_PLAN_DOCUMENT.replace(
            r#""machine_id":"lab-machine-1""#,
            r#""machine_id":"lab-machine-2""#,
        );
        let other_image = WEB_SERVICE_PLAN_DOCUMENT
            .replace(BENTOPDF_IMAGE_REFERENCE, "ghcr.io/attacker/bentopdf");
        let other_host = ROUTE_PLAN_DOCUMENT.replace(ROUTE_HOST, "evil.lab.your-cloud.test");
        for (name, hostile) in [
            (
                "an unsupported schema",
                PlanPairView {
                    schema_version: 1,
                    ..service_view()
                },
            ),
            (
                "a plan whose port was moved after it was frozen",
                PlanPairView {
                    plan_document: altered_port,
                    ..service_view()
                },
            ),
            (
                "a plan aimed at another machine under the same digest",
                PlanPairView {
                    plan_document: altered_machine,
                    ..route_view()
                },
            ),
            (
                "a plan naming an image this palier does not pin",
                PlanPairView {
                    plan_document: other_image,
                    ..service_view()
                },
            ),
            (
                "a route whose host was moved after it was frozen",
                PlanPairView {
                    plan_document: other_host,
                    ..route_view()
                },
            ),
            (
                "the two documents exchanged",
                PlanPairView {
                    plan_document: WEB_SERVICE_ROLLBACK_DOCUMENT.to_owned(),
                    rollback_document: WEB_SERVICE_PLAN_DOCUMENT.to_owned(),
                    ..service_view()
                },
            ),
            (
                "a rollback that is a second copy of the plan",
                PlanPairView {
                    rollback_document: ROUTE_PLAN_DOCUMENT.to_owned(),
                    rollback_sha256: ROUTE_PLAN_SHA256.to_owned(),
                    ..route_view()
                },
            ),
            (
                "a rollback of another operation group",
                PlanPairView {
                    rollback_document: ENTRYPOINT_ROLLBACK_DOCUMENT.to_owned(),
                    rollback_sha256: ENTRYPOINT_ROLLBACK_SHA256.to_owned(),
                    ..service_view()
                },
            ),
            (
                "a rollback of another instance",
                PlanPairView {
                    rollback_document: ROUTE_ROLLBACK_DOCUMENT.to_owned(),
                    rollback_sha256: ROUTE_ROLLBACK_SHA256.to_owned(),
                    ..entrypoint_view()
                },
            ),
            (
                "an upper-case digest",
                PlanPairView {
                    plan_sha256: ROUTE_PLAN_SHA256.to_ascii_uppercase(),
                    ..route_view()
                },
            ),
            (
                "an empty document",
                PlanPairView {
                    plan_document: String::new(),
                    ..entrypoint_view()
                },
            ),
            (
                "a schema 1 probe plan under a schema 2 pair",
                PlanPairView {
                    plan_document: concat!(
                        r#"{"schema_version":1,"#,
                        r#""infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
                        r#""machine_id":"lab-machine-1","operation":"deploy_oci_probe","#,
                        r#""image_reference":"docker.io/traefik/whoami","#,
                        r#""image_digest":"sha256:200689790a0a0ea48ca45992e0450bc26ccab53073"#,
                        r#"75b41c84dfc4f2475937ab","local_port":8080}"#,
                    )
                    .to_owned(),
                    plan_sha256: "2d50d2bc935ce6c56ef14fbfae93d670d5fdb9ca735315e5a26760d818dd5b0e"
                        .to_owned(),
                    ..service_view()
                },
            ),
        ] {
            assert!(
                matches!(
                    PresentedPublicationPlan::verify(&hostile),
                    Err(PublicationPlanError::UnverifiedPlan)
                ),
                "{name} reached the confirmation window"
            );
        }
    }

    /// The envelope names exactly the digests that were displayed, exactly the
    /// operation the document declares, and exactly the privileges the
    /// contract's table gives that operation — for each of the three groups and
    /// in both directions.
    #[test]
    fn a_confirmed_plan_is_signed_with_the_digests_that_were_displayed() {
        let record = association(INFRASTRUCTURE);
        for (name, forward, reverse, forward_operation, reverse_operation) in [
            (
                "web service",
                service_view(),
                view(
                    WEB_SERVICE_ROLLBACK_DOCUMENT,
                    WEB_SERVICE_ROLLBACK_SHA256,
                    WEB_SERVICE_PLAN_DOCUMENT,
                    WEB_SERVICE_PLAN_SHA256,
                ),
                ApprovalOperation::DeployWebService,
                ApprovalOperation::RemoveWebService,
            ),
            (
                "entrypoint",
                entrypoint_view(),
                view(
                    ENTRYPOINT_ROLLBACK_DOCUMENT,
                    ENTRYPOINT_ROLLBACK_SHA256,
                    ENTRYPOINT_PLAN_DOCUMENT,
                    ENTRYPOINT_PLAN_SHA256,
                ),
                ApprovalOperation::DeployEntrypoint,
                ApprovalOperation::RemoveEntrypoint,
            ),
            (
                "route",
                route_view(),
                view(
                    ROUTE_ROLLBACK_DOCUMENT,
                    ROUTE_ROLLBACK_SHA256,
                    ROUTE_PLAN_DOCUMENT,
                    ROUTE_PLAN_SHA256,
                ),
                ApprovalOperation::PublishRoute,
                ApprovalOperation::RetireRoute,
            ),
        ] {
            let presented = PresentedPublicationPlan::verify(&forward).unwrap();
            let signed = presented
                .sign(&record, &forward, &presented.confirmed(), request())
                .unwrap_or_else(|_| panic!("{name}: a confirmed plan is signed"));

            assert_eq!(signed.envelope.plan_sha256, forward.plan_sha256, "{name}");
            assert_eq!(
                signed.envelope.rollback_sha256, forward.rollback_sha256,
                "{name}"
            );
            assert_eq!(signed.envelope.machine_id, MACHINE, "{name}");
            assert_eq!(signed.envelope.infrastructure_id, INFRASTRUCTURE, "{name}");
            assert_eq!(signed.envelope.operation, forward_operation, "{name}");
            assert_eq!(
                signed.envelope.privileges,
                vec![
                    ApprovalPrivilege::MutateLocalState,
                    ApprovalPrivilege::ReadLocalState,
                ],
                "{name}"
            );
            assert!(signed.envelope.is_mutating(), "{name}");
            // The signature really covers the transcript of that envelope, and
            // the envelope really is one the shared contract accepts.
            assert!(signed.clone().validate().is_ok(), "{name}");

            // The other direction of the same instance is the inverse
            // operation, with the two digests exchanged and the same exact
            // privilege list.
            let presented_reverse = PresentedPublicationPlan::verify(&reverse).unwrap();
            let signed_reverse = presented_reverse
                .sign(&record, &reverse, &presented_reverse.confirmed(), request())
                .unwrap_or_else(|_| panic!("{name}: the undoing of the same instance"));
            assert_eq!(
                signed_reverse.envelope.operation, reverse_operation,
                "{name}"
            );
            assert_eq!(
                signed_reverse.envelope.plan_sha256, forward.rollback_sha256,
                "{name}"
            );
            assert_eq!(
                signed_reverse.envelope.rollback_sha256, forward.plan_sha256,
                "{name}"
            );
            assert_eq!(
                signed_reverse.envelope.privileges, signed.envelope.privileges,
                "{name}"
            );
            assert_ne!(signed_reverse.signature, signed.signature, "{name}");
        }
    }

    /// A confirmation covers two exact documents, and stops covering anything
    /// the moment either of them moves.
    #[test]
    fn a_confirmation_does_not_survive_the_documents_it_was_given_for() {
        let record = association(INFRASTRUCTURE);
        let presented = PresentedPublicationPlan::verify(&route_view()).unwrap();
        let confirmation = presented.confirmed();

        // The pair the window rendered, re-presented with the retirement in
        // place of the publication: a valid pair in its own right, and not the
        // one that was confirmed.
        let exchanged = view(
            ROUTE_ROLLBACK_DOCUMENT,
            ROUTE_ROLLBACK_SHA256,
            ROUTE_PLAN_DOCUMENT,
            ROUTE_PLAN_SHA256,
        );
        assert!(matches!(
            presented.sign(&record, &exchanged, &confirmation, request()),
            Err(PublicationPlanError::UnconfirmedPlan)
        ));

        // A pair of another operation group is not the confirmed one either,
        // even though it verifies perfectly on its own.
        assert!(matches!(
            presented.sign(&record, &service_view(), &confirmation, request()),
            Err(PublicationPlanError::UnconfirmedPlan)
        ));

        // Documents altered after they were displayed no longer verify at all.
        let altered = PlanPairView {
            plan_document: ROUTE_PLAN_DOCUMENT
                .replace(r#""backend_port":8080"#, r#""backend_port":9090"#),
            ..route_view()
        };
        assert!(matches!(
            presented.sign(&record, &altered, &confirmation, request()),
            Err(PublicationPlanError::UnverifiedPlan)
        ));

        // A refusal is not a confirmation, and neither is a confirmation whose
        // digests name another pair.
        for hostile in [
            PublicationPlanConfirmation::Refused,
            PublicationPlanConfirmation::Confirmed {
                plan_sha256: ROUTE_ROLLBACK_SHA256.to_owned(),
                rollback_sha256: ROUTE_PLAN_SHA256.to_owned(),
            },
            PublicationPlanConfirmation::Confirmed {
                plan_sha256: WEB_SERVICE_PLAN_SHA256.to_owned(),
                rollback_sha256: WEB_SERVICE_ROLLBACK_SHA256.to_owned(),
            },
            PublicationPlanConfirmation::Confirmed {
                plan_sha256: ROUTE_PLAN_SHA256.to_owned(),
                rollback_sha256: String::new(),
            },
        ] {
            assert!(matches!(
                presented.sign(&record, &route_view(), &hostile, request()),
                Err(PublicationPlanError::UnconfirmedPlan)
            ));
        }
    }

    /// A plan is approved by the Console of its own infrastructure or by none.
    #[test]
    fn a_plan_of_another_infrastructure_is_never_signed() {
        let foreign = association("8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3");
        for pair in [service_view(), entrypoint_view(), route_view()] {
            let presented = PresentedPublicationPlan::verify(&pair).unwrap();
            assert!(matches!(
                presented.sign(&foreign, &pair, &presented.confirmed(), request()),
                Err(PublicationPlanError::ForeignInfrastructure)
            ));
        }
    }

    /// A request outside the bounds of the envelope produces no signature, and
    /// the refusal comes from the one signing path rather than from a second
    /// rule written here.
    #[test]
    fn a_request_outside_the_envelope_bounds_produces_no_signature() {
        let record = association(INFRASTRUCTURE);
        let presented = PresentedPublicationPlan::verify(&entrypoint_view()).unwrap();
        for hostile in [
            PublicationApprovalRequest {
                approval_epoch: 0,
                ..request()
            },
            PublicationApprovalRequest {
                sequence: 0,
                ..request()
            },
            PublicationApprovalRequest {
                lifetime_seconds: 0,
                ..request()
            },
            PublicationApprovalRequest {
                issued_at_unix_seconds: 0,
                ..request()
            },
        ] {
            assert!(matches!(
                presented.sign(&record, &entrypoint_view(), &presented.confirmed(), hostile),
                Err(PublicationPlanError::Approval(
                    ApprovalError::InvalidRequest
                ))
            ));
        }
    }

    /// Nothing this module produces carries key material.
    ///
    /// The signed document names the public half and the signature, both of
    /// which are meant to travel, and the lines a window renders are facts about
    /// a plan. The private seed of the association appears in neither, which is
    /// what "the native core signs and the frontend never sees the key" has to
    /// mean at the surface.
    #[test]
    fn the_surface_this_module_produces_carries_no_key_material() {
        let record = association(INFRASTRUCTURE);
        for pair in [service_view(), entrypoint_view(), route_view()] {
            let presented = PresentedPublicationPlan::verify(&pair).unwrap();
            let signed = presented
                .sign(&record, &pair, &presented.confirmed(), request())
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
    }
}
