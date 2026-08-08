//! The plans of the public profile and of the private one, from the bytes the
//! Controller froze to the envelope the native core signs over them.
//!
//! It is the schema 2 counterpart of [`crate::probe_plan`], and it holds the
//! same three properties for the same reasons — a plan is verified before it is
//! displayed, a confirmation covers two exact documents, and the signature is
//! the one that already exists. What changes is what a human reads: a service
//! names a profile, an image and a loopback port; an entrypoint names an image
//! and the constants a public listener implies; a route names a declared host,
//! the loopback port behind it and the isolation headers its fragment adds; a
//! private service names all of a service's own and, besides, the origin it will
//! answer under, the one durable path it writes to, the four lines of its closed
//! environment and the table that refuses it every outbound flow; a link route
//! names the host and the peer of the tunnel behind it; an archive names a
//! profile and a slot, and says in what terms it can and cannot be undone; a user
//! service names the definition it runs and the exact revision of it, and says
//! that everything the plan does not carry comes from that revision.
//!
//! **Nothing is displayed that has not been verified.**
//! [`PresentedPublicationPlan`] is the only way to obtain the lines a window
//! renders, and the only way to obtain one is
//! [`PresentedPublicationPlan::verify`], which rebuilds both digests from the
//! fields it parsed out of the received bytes. A pair whose digests do not
//! match, a pair whose two documents belong to different operation groups, and a
//! pair whose two documents are one document, never become a thing anyone can be
//! shown.
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
//! **The kind of plan is read in the document, never in the route.** The seven
//! sibling Controller routes answer the same frozen-pair shape, so the operation
//! inside the document is what decides which closed field list was approved and
//! which lines a human is shown. A service plan returned by the route endpoint
//! is therefore still a service plan here, displayed as one and signed as one —
//! and a route of the public profile carrying the very host and port of a link
//! route is still the other plan, because the two hash differently.

use crate::{
    approval::{sign_approval, ApprovalError, ApprovalRequest},
    vault::AssociationRecord,
};
use serde::Deserialize;
use your_cloud_bootstrap_protocol::{
    verify_plan_v2_document, ApprovalOperation, PlanDocumentV2, PlanV2Group, PlanV2Operation,
    SignedApprovalV1, ENTRYPOINT_PUBLIC_HTTPS_PORT, ENTRYPOINT_PUBLIC_HTTP_PORT,
    ENTRYPOINT_UNPRIVILEGED_PORT_SYSCTL, LINK_INITIATOR_TUNNEL_ADDRESS, ORIGIN_HOST_PLACEHOLDER,
    PRIVATE_SERVICE_DATA_VOLUME, PRIVATE_SERVICE_EGRESS_TABLE,
    PRIVATE_SERVICE_ENVIRONMENT_HARDENING, PRIVATE_SERVICE_ORIGIN_SCHEME,
    PRIVATE_SERVICE_ORIGIN_VARIABLE, RESERVED_SNAPSHOT_SLOT, ROUTE_ISOLATION_HEADERS,
    SERVICE_LOCAL_ADDRESS,
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
    /// contract — profiles of both doors, pinned images, port range, host
    /// bounds, slot bound and the reserved slot's own rule included — both
    /// digests are rebuilt from the parsed fields, and the rollback is required
    /// to be the complete document that undoes the plan: the same operation
    /// group, the same instance, and the one thing that differs — the operation,
    /// or, for a return, the slot the mechanism owns. A pair that fails any of
    /// the three is refused whole: there is no partially verified plan a window
    /// could render "most of".
    ///
    /// The last refusal is the one the return makes necessary. A restore already
    /// naming the reserved slot undoes itself, so a pair could be built whose two
    /// documents are one document and whose two digests are one digest — and a
    /// human shown that pair would be approving the same plan as its own
    /// rollback. Two identical digests are therefore refused before anything is
    /// displayed, whichever group they belong to.
    pub fn verify(view: &PlanPairView) -> Result<Self, PublicationPlanError> {
        if view.schema_version != PUBLICATION_PLAN_SCHEMA_VERSION {
            return Err(PublicationPlanError::UnverifiedPlan);
        }
        let plan = verify_plan_v2_document(view.plan_document.as_bytes(), &view.plan_sha256)
            .map_err(|_| PublicationPlanError::UnverifiedPlan)?;
        let rollback =
            verify_plan_v2_document(view.rollback_document.as_bytes(), &view.rollback_sha256)
                .map_err(|_| PublicationPlanError::UnverifiedPlan)?;
        if !plan.is_undone_by(&rollback) || plan == rollback {
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
    /// A private service names everything a stateless one does and, besides,
    /// the four things the private door adds: the origin the instance answers
    /// under, the one durable path it writes to, the four lines of its closed
    /// environment — three constants of the profile and the one approved value —
    /// and the egress table that refuses it every outbound flow. None of them is
    /// a field, and each of them is part of what the plan does to the machine, so
    /// a human who approved the deployment without reading them would have
    /// approved a volume, an environment and a firewall unread.
    ///
    /// A link route names the peer of the tunnel rather than a loopback address,
    /// and says what happens when the passage falls: the entrypoint answers with
    /// its own gateway error, never a false success and never a fallback route.
    ///
    /// The archives are where this window has to be most careful, because the two
    /// directions are not symmetrical. A snapshot says that an existing slot is
    /// refused, which is what makes archives immutable. A discard says what its
    /// own rollback really does — recreate an archive of the *current* state
    /// under that name, never the archive that was destroyed, which nothing can
    /// bring back. A restore says where the return comes from: the reserved slot,
    /// written before any data is touched.
    ///
    /// A user service is the one plan whose values decide almost nothing, and
    /// the lines say so. The slug and the revision are what a human really
    /// approves: the account, the home, the volumes, the environment lines and
    /// the names of the generated secrets all come from the definition frozen
    /// under that exact digest, and no field of the plan can move any of them. A
    /// window that showed the image and the port without naming the revision
    /// would be showing the two least decisive facts about the service.
    ///
    /// Its origin is the one field of the schema a document may or may not
    /// carry, so both forms are written rather than one being left out: a plan
    /// that answers under a name and a plan that answers under none are two
    /// states, and a human must be able to tell them apart on screen as surely
    /// as their digests do.
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
            PlanDocumentV2::PrivateService(document) => {
                lines.push(format!("Profil de service : {}", document.service_profile));
                lines.push(format!("Image : {}", document.image_reference));
                lines.push(format!("Digest de l’image : {}", document.image_digest));
                lines.push(format!(
                    "Port local : {SERVICE_LOCAL_ADDRESS}:{}",
                    document.local_port
                ));
                lines.push(format!(
                    "Origine : {PRIVATE_SERVICE_ORIGIN_SCHEME}://{}",
                    document.origin_host
                ));
                lines.push(format!("Volume persistant : {PRIVATE_SERVICE_DATA_VOLUME}"));
                for hardening in PRIVATE_SERVICE_ENVIRONMENT_HARDENING {
                    lines.push(format!("Ligne d’environnement : {hardening}"));
                }
                lines.push(format!(
                    "Ligne d’environnement : {PRIVATE_SERVICE_ORIGIN_VARIABLE}=\
                     {PRIVATE_SERVICE_ORIGIN_SCHEME}://{}",
                    document.origin_host
                ));
                lines.push(format!(
                    "Confinement de sortie : table {PRIVATE_SERVICE_EGRESS_TABLE}, le service ne \
                     parle à personne : sortie refusée hors loopback et réponses"
                ));
            }
            PlanDocumentV2::LinkRoute(document) => {
                lines.push(format!("Nom publié : {}", document.route_host));
                lines.push(format!(
                    "Service joint : {LINK_INITIATOR_TUNNEL_ADDRESS}:{}, publié par le seul \
                     passage privé",
                    document.backend_port
                ));
                lines.push(
                    "Panne du passage : le nom rend l’erreur de passerelle du point d’entrée, \
                     jamais un faux succès ni une route de repli"
                        .to_owned(),
                );
            }
            PlanDocumentV2::Snapshot(document) => {
                lines.push(format!("Profil de service : {}", document.service_profile));
                lines.push(format!("Emplacement : {}", document.snapshot_slot));
                match document.operation {
                    PlanV2Operation::SnapshotService => lines.push(
                        "Immuabilité : un emplacement existant est refusé ; l’écraser exige un \
                         plan de destruction approuvé à part"
                            .to_owned(),
                    ),
                    // The asymmetry the contract names rather than hides:
                    // destroying an archive has no honest inverse, and the
                    // rollback that is signed beside it archives the state the
                    // machine holds when it runs.
                    _ => lines.push(
                        "Ce que le rollback fait vraiment : il recrée une archive de l’état \
                         courant sous ce nom, jamais l’archive détruite, que rien ne ramène"
                            .to_owned(),
                    ),
                }
            }
            PlanDocumentV2::Restore(document) => {
                lines.push(format!("Profil de service : {}", document.service_profile));
                lines.push(format!("Emplacement restauré : {}", document.snapshot_slot));
                lines.push(format!(
                    "Retour : le rollback restaure ce que « {RESERVED_SNAPSHOT_SLOT} » détient, \
                     écrit avant que la moindre donnée ne soit touchée"
                ));
            }
            PlanDocumentV2::UserService(document) => {
                lines.push(format!("Service défini : {}", document.definition_slug));
                lines.push(format!(
                    "Révision de la définition : {}",
                    document.definition_digest
                ));
                lines.push(format!("Image : {}", document.image_reference));
                lines.push(format!("Digest de l’image : {}", document.image_digest));
                lines.push(format!(
                    "Port local : {SERVICE_LOCAL_ADDRESS}:{}",
                    document.local_port
                ));
                if document.origin_host.is_empty() {
                    lines.push(format!(
                        "Origine : aucune, aucune ligne de la définition gelée ne nomme \
                         {ORIGIN_HOST_PLACEHOLDER}"
                    ));
                } else {
                    lines.push(format!(
                        "Origine : {}, portée par les lignes de la définition qui nomment \
                         {ORIGIN_HOST_PLACEHOLDER}",
                        document.origin_host
                    ));
                }
                lines.push(
                    "Ce que la révision décide : le compte, le foyer, les volumes, \
                     l’environnement et les noms de secrets viennent de la définition gelée sous \
                     cette empreinte, et d’aucun champ de ce plan"
                        .to_owned(),
                );
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
        PlanV2Operation::DeployPrivateService => ApprovalOperation::DeployPrivateService,
        PlanV2Operation::RemovePrivateService => ApprovalOperation::RemovePrivateService,
        PlanV2Operation::PublishLinkRoute => ApprovalOperation::PublishLinkRoute,
        PlanV2Operation::RetireLinkRoute => ApprovalOperation::RetireLinkRoute,
        PlanV2Operation::SnapshotService => ApprovalOperation::SnapshotService,
        PlanV2Operation::DiscardSnapshot => ApprovalOperation::DiscardSnapshot,
        PlanV2Operation::RestoreService => ApprovalOperation::RestoreService,
        PlanV2Operation::DeployUserService => ApprovalOperation::DeployUserService,
        PlanV2Operation::RemoveUserService => ApprovalOperation::RemoveUserService,
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
        PlanV2Operation::DeployPrivateService => "déployer le service privé à données",
        PlanV2Operation::RemovePrivateService => "retirer le service privé à données",
        PlanV2Operation::PublishLinkRoute => "publier la route du passage privé",
        PlanV2Operation::RetireLinkRoute => "retirer la route du passage privé",
        PlanV2Operation::SnapshotService => "sauvegarder les données du service privé",
        PlanV2Operation::DiscardSnapshot => "détruire l’archive nommée",
        PlanV2Operation::RestoreService => "restaurer les données du service privé",
        PlanV2Operation::DeployUserService => "déployer le service utilisateur",
        PlanV2Operation::RemoveUserService => "retirer le service utilisateur",
    }
}

/// What a rollback shares with the plan it undoes, group by group. It is the
/// whole of what "exact inverse" means on screen: everything but the operation —
/// except for the return, whose rollback shares even the operation and differs
/// by the one slot the mechanism owns.
fn rollback_scope_text(group: PlanV2Group) -> &'static str {
    match group {
        PlanV2Group::WebService => {
            "sur la même machine, le même profil, la même image et le même port"
        }
        PlanV2Group::Entrypoint => "sur la même machine et la même image",
        PlanV2Group::Route => "sur la même machine, le même nom et le même port",
        PlanV2Group::PrivateService => {
            "sur la même machine, le même profil, la même image, le même port et la même origine"
        }
        PlanV2Group::LinkRoute => "sur la même machine, le même nom et le même port",
        PlanV2Group::Snapshot => "sur la même machine, le même profil et le même emplacement",
        PlanV2Group::Restore => {
            "sur la même machine et le même profil, vers l’emplacement réservé du mécanisme de retour"
        }
        PlanV2Group::UserService => {
            "sur la même machine, la même définition, la même révision, la même image, le même \
             port et la même origine"
        }
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
        SERVICE_PROFILE_VAULTWARDEN, VAULTWARDEN_IMAGE_DIGEST, VAULTWARDEN_IMAGE_REFERENCE,
    };

    const INFRASTRUCTURE: &str = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2";
    const MACHINE: &str = "lab-machine-1";
    const ROUTE_HOST: &str = "bentopdf.lab.your-cloud.test";
    const ORIGIN_HOST: &str = "vault.lab.your-cloud.test";
    const SNAPSHOT_SLOT: &str = "nightly";
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
    const PRIVATE_SERVICE_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"deploy_private_service","#,
        r#""service_profile":"vaultwarden","image_reference":"docker.io/vaultwarden/server","#,
        r#""image_digest":"sha256:ebdfe70701c60ac0c28c697e787cea767d7972940b786037b29fe0d507f821e8","#,
        r#""local_port":8080,"origin_host":"vault.lab.your-cloud.test"}"#,
    );
    const PRIVATE_SERVICE_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"remove_private_service","#,
        r#""service_profile":"vaultwarden","image_reference":"docker.io/vaultwarden/server","#,
        r#""image_digest":"sha256:ebdfe70701c60ac0c28c697e787cea767d7972940b786037b29fe0d507f821e8","#,
        r#""local_port":8080,"origin_host":"vault.lab.your-cloud.test"}"#,
    );
    const LINK_ROUTE_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"publish_link_route","#,
        r#""route_host":"vault.lab.your-cloud.test","backend_port":8080}"#,
    );
    const LINK_ROUTE_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"retire_link_route","#,
        r#""route_host":"vault.lab.your-cloud.test","backend_port":8080}"#,
    );
    const SNAPSHOT_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"snapshot_service","#,
        r#""service_profile":"vaultwarden","snapshot_slot":"nightly"}"#,
    );
    const SNAPSHOT_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"discard_snapshot","#,
        r#""service_profile":"vaultwarden","snapshot_slot":"nightly"}"#,
    );
    const RESTORE_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"restore_service","#,
        r#""service_profile":"vaultwarden","snapshot_slot":"nightly"}"#,
    );
    const RESTORE_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"restore_service","#,
        r#""service_profile":"vaultwarden","snapshot_slot":"previous"}"#,
    );

    /// The four documents of the third door, byte for byte, under the same rule
    /// as the six above. The pair without an origin is here because it is the
    /// one shape of the schema whose conditional field is empty, and what a
    /// human reads about it has to differ from what they read about the other.
    const USER_SERVICE_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"deploy_user_service","#,
        r#""definition_slug":"lab-notes","#,
        r#""definition_digest":"c0f30d7c7f8635d2fb56445d7b75c6523b440d35de8e1867444c788e4b30f3ce","#,
        r#""image_reference":"registry.lab.your-cloud.test/your-cloud/lab-notes","#,
        r#""image_digest":"sha256:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","#,
        r#""local_port":8080,"origin_host":"notes.lab.your-cloud.test"}"#,
    );
    const USER_SERVICE_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"remove_user_service","#,
        r#""definition_slug":"lab-notes","#,
        r#""definition_digest":"c0f30d7c7f8635d2fb56445d7b75c6523b440d35de8e1867444c788e4b30f3ce","#,
        r#""image_reference":"registry.lab.your-cloud.test/your-cloud/lab-notes","#,
        r#""image_digest":"sha256:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","#,
        r#""local_port":8080,"origin_host":"notes.lab.your-cloud.test"}"#,
    );
    const MINIMAL_USER_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"deploy_user_service","#,
        r#""definition_slug":"minimal","#,
        r#""definition_digest":"faf14b5c09ce83169466632fe2d37063453fe924154b6cc265b62fdd6aebd95c","#,
        r#""image_reference":"registry.lab.your-cloud.test/minimal","#,
        r#""image_digest":"sha256:2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40","#,
        r#""local_port":8081,"origin_host":""}"#,
    );
    const MINIMAL_USER_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"remove_user_service","#,
        r#""definition_slug":"minimal","#,
        r#""definition_digest":"faf14b5c09ce83169466632fe2d37063453fe924154b6cc265b62fdd6aebd95c","#,
        r#""image_reference":"registry.lab.your-cloud.test/minimal","#,
        r#""image_digest":"sha256:2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40","#,
        r#""local_port":8081,"origin_host":""}"#,
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
    const PRIVATE_SERVICE_PLAN_SHA256: &str =
        "b4d69bc7fcd277a5c165cd9494f2a88cb3ea8acf06f66906a10f831292f03372";
    const PRIVATE_SERVICE_ROLLBACK_SHA256: &str =
        "c1650b0d359671aafc7fc19bc1d0f050bcf561558cfe3a82bfd897c16d0c7ba0";
    const LINK_ROUTE_PLAN_SHA256: &str =
        "384fe095408f815bcc6d9b0be5655eaadabefe01c1a717bd0ff641567a5f3fbd";
    const LINK_ROUTE_ROLLBACK_SHA256: &str =
        "c17842e513bd8af2da8cee699db20c24b59ae00d2fcfddfa0004caad1cc2d1db";
    const SNAPSHOT_PLAN_SHA256: &str =
        "3de5108f5e7f2934579128bcfa8a09b3a6bbb16739b37f53e61d941261c7c6e3";
    const SNAPSHOT_ROLLBACK_SHA256: &str =
        "0bedf38650c70b58a36e8a0a28944dd53bd9720bce77012be2227ffa85192cae";
    const RESTORE_PLAN_SHA256: &str =
        "6a6b71a15f969916a426fdfdcefca22ab670935a04459079eb724c18e180aebc";
    const RESTORE_ROLLBACK_SHA256: &str =
        "1be3be0186ff3be565e6c4df4fc5a864a8a28f1c3929d029b3ec6ecb38c11b5a";
    const USER_SERVICE_PLAN_SHA256: &str =
        "604b9300bb6f321d53759365cc7064fed1fc9b794b8afdbe811a1742d8133a59";
    const USER_SERVICE_ROLLBACK_SHA256: &str =
        "b2737aba239eb3d43326c43e1508687b33ade43ed5fd62a97cfe0866b6deabc8";
    const MINIMAL_USER_PLAN_SHA256: &str =
        "305f7fac725f8c7cd0970cd4db3b92af60a339b1cd1fa569b61858865210a753";
    const MINIMAL_USER_ROLLBACK_SHA256: &str =
        "bb76c62b75d4fd70d7437e75d82396c5b9ae6df3ef6a65e881ac20a222bcc5d3";

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

    fn private_service_view() -> PlanPairView {
        view(
            PRIVATE_SERVICE_PLAN_DOCUMENT,
            PRIVATE_SERVICE_PLAN_SHA256,
            PRIVATE_SERVICE_ROLLBACK_DOCUMENT,
            PRIVATE_SERVICE_ROLLBACK_SHA256,
        )
    }

    fn link_route_view() -> PlanPairView {
        view(
            LINK_ROUTE_PLAN_DOCUMENT,
            LINK_ROUTE_PLAN_SHA256,
            LINK_ROUTE_ROLLBACK_DOCUMENT,
            LINK_ROUTE_ROLLBACK_SHA256,
        )
    }

    fn snapshot_view() -> PlanPairView {
        view(
            SNAPSHOT_PLAN_DOCUMENT,
            SNAPSHOT_PLAN_SHA256,
            SNAPSHOT_ROLLBACK_DOCUMENT,
            SNAPSHOT_ROLLBACK_SHA256,
        )
    }

    fn discard_view() -> PlanPairView {
        view(
            SNAPSHOT_ROLLBACK_DOCUMENT,
            SNAPSHOT_ROLLBACK_SHA256,
            SNAPSHOT_PLAN_DOCUMENT,
            SNAPSHOT_PLAN_SHA256,
        )
    }

    fn restore_view() -> PlanPairView {
        view(
            RESTORE_PLAN_DOCUMENT,
            RESTORE_PLAN_SHA256,
            RESTORE_ROLLBACK_DOCUMENT,
            RESTORE_ROLLBACK_SHA256,
        )
    }

    fn user_service_view() -> PlanPairView {
        view(
            USER_SERVICE_PLAN_DOCUMENT,
            USER_SERVICE_PLAN_SHA256,
            USER_SERVICE_ROLLBACK_DOCUMENT,
            USER_SERVICE_ROLLBACK_SHA256,
        )
    }

    fn minimal_user_service_view() -> PlanPairView {
        view(
            MINIMAL_USER_PLAN_DOCUMENT,
            MINIMAL_USER_PLAN_SHA256,
            MINIMAL_USER_ROLLBACK_DOCUMENT,
            MINIMAL_USER_ROLLBACK_SHA256,
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

    /// The private service names everything a stateless one names and, besides,
    /// the four things the private door adds and no field carries: the origin,
    /// the one durable path, the four closed environment lines, and the table
    /// that refuses it every outbound flow.
    #[test]
    fn a_verified_private_service_pair_displays_what_the_private_door_adds() {
        let presented =
            PresentedPublicationPlan::verify(&private_service_view()).expect("the vector");
        assert_eq!(presented.machine_id(), MACHINE);
        assert_eq!(presented.operation(), PlanV2Operation::DeployPrivateService);
        assert_eq!(presented.group(), PlanV2Group::PrivateService);

        assert_eq!(
            presented.confirmation_lines(),
            vec![
                format!("Machine : {MACHINE}"),
                "Opération : déployer le service privé à données".to_owned(),
                format!("Profil de service : {SERVICE_PROFILE_VAULTWARDEN}"),
                format!("Image : {VAULTWARDEN_IMAGE_REFERENCE}"),
                format!("Digest de l’image : {VAULTWARDEN_IMAGE_DIGEST}"),
                format!("Port local : {SERVICE_LOCAL_ADDRESS}:8080"),
                format!("Origine : https://{ORIGIN_HOST}"),
                "Volume persistant : /var/lib/your-cloud-svc-vaultwarden/data".to_owned(),
                "Ligne d’environnement : SIGNUPS_ALLOWED=false".to_owned(),
                "Ligne d’environnement : INVITATIONS_ALLOWED=false".to_owned(),
                "Ligne d’environnement : SHOW_PASSWORD_HINT=false".to_owned(),
                format!("Ligne d’environnement : DOMAIN=https://{ORIGIN_HOST}"),
                "Confinement de sortie : table inet your-cloud-egress, le service ne parle à \
                 personne : sortie refusée hors loopback et réponses"
                    .to_owned(),
                "Rollback : retirer le service privé à données, sur la même machine, le même \
                 profil, la même image, le même port et la même origine"
                    .to_owned(),
                format!("Empreinte du plan : {PRIVATE_SERVICE_PLAN_SHA256}"),
                format!("Empreinte du rollback : {PRIVATE_SERVICE_ROLLBACK_SHA256}"),
            ]
        );
    }

    /// The link route names the peer of the tunnel behind the published name,
    /// and says what a fallen passage looks like.
    #[test]
    fn a_verified_link_route_pair_displays_the_peer_of_the_tunnel() {
        let presented = PresentedPublicationPlan::verify(&link_route_view()).expect("the vector");
        assert_eq!(presented.operation(), PlanV2Operation::PublishLinkRoute);
        assert_eq!(presented.group(), PlanV2Group::LinkRoute);

        assert_eq!(
            presented.confirmation_lines(),
            vec![
                format!("Machine : {MACHINE}"),
                "Opération : publier la route du passage privé".to_owned(),
                format!("Nom publié : {ORIGIN_HOST}"),
                "Service joint : 10.66.66.2:8080, publié par le seul passage privé".to_owned(),
                "Panne du passage : le nom rend l’erreur de passerelle du point d’entrée, \
                 jamais un faux succès ni une route de repli"
                    .to_owned(),
                "Rollback : retirer la route du passage privé, sur la même machine, le même nom \
                 et le même port"
                    .to_owned(),
                format!("Empreinte du plan : {LINK_ROUTE_PLAN_SHA256}"),
                format!("Empreinte du rollback : {LINK_ROUTE_ROLLBACK_SHA256}"),
            ]
        );
        // The address behind the name is the peer of the passage and never this
        // machine's own loopback: a link route that displayed the loopback would
        // be describing the public profile's route.
        assert!(!presented
            .confirmation_lines()
            .concat()
            .contains(&format!("Service joint : {SERVICE_LOCAL_ADDRESS}")));
    }

    /// An archive says that it is immutable, and its destruction says what its
    /// own rollback really does.
    ///
    /// This is the one place the window has to contradict a comfortable reading:
    /// the rollback of a discard is a snapshot of the same slot, and what it will
    /// archive is the state the machine holds when it runs — not the archive that
    /// was destroyed, which nothing brings back. The contract requires those
    /// terms, so they are asserted here word for word.
    #[test]
    fn a_verified_archive_pair_displays_what_its_rollback_can_and_cannot_do() {
        let presented = PresentedPublicationPlan::verify(&snapshot_view()).expect("the vector");
        assert_eq!(presented.operation(), PlanV2Operation::SnapshotService);
        assert_eq!(presented.group(), PlanV2Group::Snapshot);
        assert_eq!(
            presented.confirmation_lines(),
            vec![
                format!("Machine : {MACHINE}"),
                "Opération : sauvegarder les données du service privé".to_owned(),
                format!("Profil de service : {SERVICE_PROFILE_VAULTWARDEN}"),
                format!("Emplacement : {SNAPSHOT_SLOT}"),
                "Immuabilité : un emplacement existant est refusé ; l’écraser exige un plan de \
                 destruction approuvé à part"
                    .to_owned(),
                "Rollback : détruire l’archive nommée, sur la même machine, le même profil et le \
                 même emplacement"
                    .to_owned(),
                format!("Empreinte du plan : {SNAPSHOT_PLAN_SHA256}"),
                format!("Empreinte du rollback : {SNAPSHOT_ROLLBACK_SHA256}"),
            ]
        );

        let discard = PresentedPublicationPlan::verify(&discard_view()).expect("the vector");
        assert_eq!(discard.operation(), PlanV2Operation::DiscardSnapshot);
        assert_eq!(
            discard.confirmation_lines(),
            vec![
                format!("Machine : {MACHINE}"),
                "Opération : détruire l’archive nommée".to_owned(),
                format!("Profil de service : {SERVICE_PROFILE_VAULTWARDEN}"),
                format!("Emplacement : {SNAPSHOT_SLOT}"),
                "Ce que le rollback fait vraiment : il recrée une archive de l’état courant sous \
                 ce nom, jamais l’archive détruite, que rien ne ramène"
                    .to_owned(),
                "Rollback : sauvegarder les données du service privé, sur la même machine, le \
                 même profil et le même emplacement"
                    .to_owned(),
                format!("Empreinte du plan : {SNAPSHOT_ROLLBACK_SHA256}"),
                format!("Empreinte du rollback : {SNAPSHOT_PLAN_SHA256}"),
            ]
        );
    }

    /// The return names where its own return comes from.
    ///
    /// The rollback of a restore is a restore of the reserved slot, and the slot
    /// holds the state the flow wrote there before touching any data. A human who
    /// read only "restaurer" twice would not know which of the two states each
    /// document names, so the window says it.
    #[test]
    fn a_verified_restore_pair_displays_where_the_return_comes_from() {
        let presented = PresentedPublicationPlan::verify(&restore_view()).expect("the vector");
        assert_eq!(presented.operation(), PlanV2Operation::RestoreService);
        assert_eq!(presented.group(), PlanV2Group::Restore);
        assert_eq!(
            presented.confirmation_lines(),
            vec![
                format!("Machine : {MACHINE}"),
                "Opération : restaurer les données du service privé".to_owned(),
                format!("Profil de service : {SERVICE_PROFILE_VAULTWARDEN}"),
                format!("Emplacement restauré : {SNAPSHOT_SLOT}"),
                "Retour : le rollback restaure ce que « previous » détient, écrit avant que la \
                 moindre donnée ne soit touchée"
                    .to_owned(),
                "Rollback : restaurer les données du service privé, sur la même machine et le \
                 même profil, vers l’emplacement réservé du mécanisme de retour"
                    .to_owned(),
                format!("Empreinte du plan : {RESTORE_PLAN_SHA256}"),
                format!("Empreinte du rollback : {RESTORE_ROLLBACK_SHA256}"),
            ]
        );
        assert_ne!(presented.plan_sha256(), presented.rollback_sha256());
    }

    /// The user service names the definition it runs, the exact revision of it,
    /// and says that everything the plan does not carry comes from that
    /// revision.
    ///
    /// The revision is the line this window exists for. A human who read the
    /// image and the port and not the digest of the frozen definition would have
    /// approved an account, a home, a set of volumes, an environment and a list
    /// of generated secret names without reading any of them — none of which is
    /// a field of the plan, and all of which the revision decides.
    #[test]
    fn a_verified_user_service_pair_displays_the_revision_it_runs() {
        let presented = PresentedPublicationPlan::verify(&user_service_view()).expect("the vector");
        assert_eq!(presented.machine_id(), MACHINE);
        assert_eq!(presented.operation(), PlanV2Operation::DeployUserService);
        assert_eq!(presented.group(), PlanV2Group::UserService);

        assert_eq!(
            presented.confirmation_lines(),
            vec![
                format!("Machine : {MACHINE}"),
                "Opération : déployer le service utilisateur".to_owned(),
                "Service défini : lab-notes".to_owned(),
                "Révision de la définition : \
                 c0f30d7c7f8635d2fb56445d7b75c6523b440d35de8e1867444c788e4b30f3ce"
                    .to_owned(),
                "Image : registry.lab.your-cloud.test/your-cloud/lab-notes".to_owned(),
                "Digest de l’image : \
                 sha256:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                    .to_owned(),
                format!("Port local : {SERVICE_LOCAL_ADDRESS}:8080"),
                "Origine : notes.lab.your-cloud.test, portée par les lignes de la définition qui \
                 nomment {origin_host}"
                    .to_owned(),
                "Ce que la révision décide : le compte, le foyer, les volumes, l’environnement et \
                 les noms de secrets viennent de la définition gelée sous cette empreinte, et \
                 d’aucun champ de ce plan"
                    .to_owned(),
                "Rollback : retirer le service utilisateur, sur la même machine, la même \
                 définition, la même révision, la même image, le même port et la même origine"
                    .to_owned(),
                format!("Empreinte du plan : {USER_SERVICE_PLAN_SHA256}"),
                format!("Empreinte du rollback : {USER_SERVICE_ROLLBACK_SHA256}"),
            ]
        );
    }

    /// A user service whose definition consumes no origin says so, rather than
    /// leaving the line out.
    ///
    /// The origin is the one field of this schema a document may or may not
    /// carry, and the two plans are two states with two digests. A window that
    /// simply omitted the line would render the two nearly identically, and a
    /// human comparing what they approved to what runs would have nothing to
    /// compare.
    #[test]
    fn a_user_service_without_an_origin_says_that_it_has_none() {
        let presented =
            PresentedPublicationPlan::verify(&minimal_user_service_view()).expect("the vector");
        assert_eq!(presented.operation(), PlanV2Operation::DeployUserService);
        assert_eq!(
            presented.confirmation_lines(),
            vec![
                format!("Machine : {MACHINE}"),
                "Opération : déployer le service utilisateur".to_owned(),
                "Service défini : minimal".to_owned(),
                "Révision de la définition : \
                 faf14b5c09ce83169466632fe2d37063453fe924154b6cc265b62fdd6aebd95c"
                    .to_owned(),
                "Image : registry.lab.your-cloud.test/minimal".to_owned(),
                "Digest de l’image : \
                 sha256:2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
                    .to_owned(),
                format!("Port local : {SERVICE_LOCAL_ADDRESS}:8081"),
                "Origine : aucune, aucune ligne de la définition gelée ne nomme {origin_host}"
                    .to_owned(),
                "Ce que la révision décide : le compte, le foyer, les volumes, l’environnement et \
                 les noms de secrets viennent de la définition gelée sous cette empreinte, et \
                 d’aucun champ de ce plan"
                    .to_owned(),
                "Rollback : retirer le service utilisateur, sur la même machine, la même \
                 définition, la même révision, la même image, le même port et la même origine"
                    .to_owned(),
                format!("Empreinte du plan : {MINIMAL_USER_PLAN_SHA256}"),
                format!("Empreinte du rollback : {MINIMAL_USER_ROLLBACK_SHA256}"),
            ]
        );

        // The two plans really are two on screen as they are in the bytes: the
        // one line that differs is the one that has to.
        let with_origin =
            PresentedPublicationPlan::verify(&user_service_view()).expect("the vector");
        assert_ne!(
            presented.confirmation_lines(),
            with_origin.confirmation_lines()
        );
        assert_ne!(presented.plan_sha256(), with_origin.plan_sha256());
    }

    /// An archive of a user service reaches the window unchanged.
    ///
    /// `service_profile` is the one field two doors share, so a slug travels
    /// through the archive shape and through its lines exactly as a delivered
    /// profile does: the value is displayed verbatim, and the four reserved
    /// names are what keeps one name from meaning two things.
    #[test]
    fn an_archive_of_a_user_service_is_displayed_like_any_other_archive() {
        let plan = SNAPSHOT_PLAN_DOCUMENT.replace(
            &format!(r#""service_profile":"{SERVICE_PROFILE_VAULTWARDEN}""#),
            r#""service_profile":"lab-notes""#,
        );
        let rollback = SNAPSHOT_ROLLBACK_DOCUMENT.replace(
            &format!(r#""service_profile":"{SERVICE_PROFILE_VAULTWARDEN}""#),
            r#""service_profile":"lab-notes""#,
        );
        let plan_digest = your_cloud_bootstrap_protocol::decode_plan_v2_document(plan.as_bytes())
            .expect("an archive of a definition is a plan")
            .sha256()
            .unwrap();
        let rollback_digest =
            your_cloud_bootstrap_protocol::decode_plan_v2_document(rollback.as_bytes())
                .expect("its destruction is one too")
                .sha256()
                .unwrap();
        let presented = PresentedPublicationPlan::verify(&view(
            &plan,
            &plan_digest,
            &rollback,
            &rollback_digest,
        ))
        .expect("an archive of a user service");
        assert_eq!(presented.group(), PlanV2Group::Snapshot);
        assert!(presented
            .confirmation_lines()
            .contains(&"Profil de service : lab-notes".to_owned()));
        // And the digest of an archive of a definition is not the digest of an
        // archive of the delivered profile of the same slot.
        assert_ne!(plan_digest, SNAPSHOT_PLAN_SHA256);
    }

    /// A pair whose two documents are one document never reaches a window.
    ///
    /// It is the return that makes the refusal necessary: a restore already
    /// naming the reserved slot undoes itself, so the pair verifies as an exact
    /// inverse and still is not a pair — a human shown it would be approving the
    /// same plan as its own rollback. The refusal is on the digests, so it holds
    /// whichever group builds such a pair.
    #[test]
    fn a_pair_whose_two_documents_are_one_document_is_refused_before_display() {
        for (name, hostile) in [
            (
                "a return of the reserved slot presented as its own rollback",
                view(
                    RESTORE_ROLLBACK_DOCUMENT,
                    RESTORE_ROLLBACK_SHA256,
                    RESTORE_ROLLBACK_DOCUMENT,
                    RESTORE_ROLLBACK_SHA256,
                ),
            ),
            (
                "a link route presented as its own rollback",
                view(
                    LINK_ROUTE_PLAN_DOCUMENT,
                    LINK_ROUTE_PLAN_SHA256,
                    LINK_ROUTE_PLAN_DOCUMENT,
                    LINK_ROUTE_PLAN_SHA256,
                ),
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

    /// The two couples of operations that carry identical fields are two plans,
    /// and this side treats them as two.
    ///
    /// A public route and a link route naming the same host and the same port
    /// hash differently, so a pair of one kind presented under the digests of the
    /// other never verifies — and the rollback of one never undoes the other.
    /// The same holds for an archive and a return naming the same profile and
    /// slot.
    #[test]
    fn two_plans_carrying_the_same_fields_are_never_taken_for_one_another() {
        let public_route_of_the_same_name = ROUTE_PLAN_DOCUMENT.replace(ROUTE_HOST, ORIGIN_HOST);
        for (name, hostile) in [
            (
                "a public route under the digests of a link route",
                PlanPairView {
                    plan_document: public_route_of_the_same_name,
                    ..link_route_view()
                },
            ),
            (
                "a link route rolled back by a public retirement",
                PlanPairView {
                    rollback_document: ROUTE_ROLLBACK_DOCUMENT.replace(ROUTE_HOST, ORIGIN_HOST),
                    ..link_route_view()
                },
            ),
            (
                "an archive rolled back by a return of the same slot",
                PlanPairView {
                    rollback_document: RESTORE_PLAN_DOCUMENT.to_owned(),
                    rollback_sha256: RESTORE_PLAN_SHA256.to_owned(),
                    ..snapshot_view()
                },
            ),
            (
                "a return rolled back by a discard of the same slot",
                PlanPairView {
                    rollback_document: SNAPSHOT_ROLLBACK_DOCUMENT.to_owned(),
                    rollback_sha256: SNAPSHOT_ROLLBACK_SHA256.to_owned(),
                    ..restore_view()
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

        // The four digests really are four, which is what all of the above rests
        // on.
        let mut seen: Vec<&str> = Vec::new();
        for digest in [
            LINK_ROUTE_PLAN_SHA256,
            LINK_ROUTE_ROLLBACK_SHA256,
            SNAPSHOT_PLAN_SHA256,
            RESTORE_PLAN_SHA256,
        ] {
            assert!(!seen.contains(&digest), "{digest} is named twice");
            seen.push(digest);
        }
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
                "a private service whose origin was moved after it was frozen",
                PlanPairView {
                    plan_document: PRIVATE_SERVICE_PLAN_DOCUMENT
                        .replace(ORIGIN_HOST, "evil.lab.your-cloud.test"),
                    ..private_service_view()
                },
            ),
            (
                "a private service naming the profile of the stateless door",
                PlanPairView {
                    plan_document: PRIVATE_SERVICE_PLAN_DOCUMENT.replace(
                        &format!(r#""service_profile":"{SERVICE_PROFILE_VAULTWARDEN}""#),
                        &format!(r#""service_profile":"{SERVICE_PROFILE_BENTOPDF}""#),
                    ),
                    ..private_service_view()
                },
            ),
            (
                "an archive of the slot the return mechanism owns",
                PlanPairView {
                    plan_document: SNAPSHOT_PLAN_DOCUMENT.replace(SNAPSHOT_SLOT, "previous"),
                    ..snapshot_view()
                },
            ),
            (
                "an archive whose slot climbs out of the profile's directory",
                PlanPairView {
                    plan_document: SNAPSHOT_PLAN_DOCUMENT.replace(SNAPSHOT_SLOT, "../../etc"),
                    ..snapshot_view()
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
            (
                "private service",
                private_service_view(),
                view(
                    PRIVATE_SERVICE_ROLLBACK_DOCUMENT,
                    PRIVATE_SERVICE_ROLLBACK_SHA256,
                    PRIVATE_SERVICE_PLAN_DOCUMENT,
                    PRIVATE_SERVICE_PLAN_SHA256,
                ),
                ApprovalOperation::DeployPrivateService,
                ApprovalOperation::RemovePrivateService,
            ),
            (
                "link route",
                link_route_view(),
                view(
                    LINK_ROUTE_ROLLBACK_DOCUMENT,
                    LINK_ROUTE_ROLLBACK_SHA256,
                    LINK_ROUTE_PLAN_DOCUMENT,
                    LINK_ROUTE_PLAN_SHA256,
                ),
                ApprovalOperation::PublishLinkRoute,
                ApprovalOperation::RetireLinkRoute,
            ),
            (
                // The archive is the case the word "backup" makes tempting to
                // read as harmless: it stops the service, writes and restarts,
                // so its envelope asks for the mutating pair like any other.
                "snapshot",
                snapshot_view(),
                discard_view(),
                ApprovalOperation::SnapshotService,
                ApprovalOperation::DiscardSnapshot,
            ),
            (
                // The third door signs like the two others: the envelope names
                // the operation the document declares and the same mutating
                // pair, and it has never known that what those digests cover was
                // written by a user rather than pinned by the product.
                "user service",
                user_service_view(),
                view(
                    USER_SERVICE_ROLLBACK_DOCUMENT,
                    USER_SERVICE_ROLLBACK_SHA256,
                    USER_SERVICE_PLAN_DOCUMENT,
                    USER_SERVICE_PLAN_SHA256,
                ),
                ApprovalOperation::DeployUserService,
                ApprovalOperation::RemoveUserService,
            ),
            (
                "user service without an origin",
                minimal_user_service_view(),
                view(
                    MINIMAL_USER_ROLLBACK_DOCUMENT,
                    MINIMAL_USER_ROLLBACK_SHA256,
                    MINIMAL_USER_PLAN_DOCUMENT,
                    MINIMAL_USER_PLAN_SHA256,
                ),
                ApprovalOperation::DeployUserService,
                ApprovalOperation::RemoveUserService,
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

        // The return has one direction, so it has no reverse pair to sign: the
        // document that returns from it is a restore of the reserved slot, and a
        // pair whose two documents would be that one document is refused above.
        // What is asserted here is that the one direction signs, under its own
        // operation and the same mutating pair.
        let presented = PresentedPublicationPlan::verify(&restore_view()).unwrap();
        let signed = presented
            .sign(&record, &restore_view(), &presented.confirmed(), request())
            .expect("a confirmed return is signed");
        assert_eq!(signed.envelope.operation, ApprovalOperation::RestoreService);
        assert_eq!(signed.envelope.plan_sha256, RESTORE_PLAN_SHA256);
        assert_eq!(signed.envelope.rollback_sha256, RESTORE_ROLLBACK_SHA256);
        assert_eq!(
            signed.envelope.privileges,
            vec![
                ApprovalPrivilege::MutateLocalState,
                ApprovalPrivilege::ReadLocalState,
            ]
        );
        assert!(signed.clone().validate().is_ok());
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
        for pair in [
            service_view(),
            entrypoint_view(),
            route_view(),
            private_service_view(),
            link_route_view(),
            snapshot_view(),
            restore_view(),
            user_service_view(),
            minimal_user_service_view(),
        ] {
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
        for pair in [
            service_view(),
            entrypoint_view(),
            route_view(),
            private_service_view(),
            link_route_view(),
            snapshot_view(),
            restore_view(),
            user_service_view(),
            minimal_user_service_view(),
        ] {
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
