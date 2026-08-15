//! The six plans of the private passage, from the bytes the Controller froze to
//! the envelope the native core signs over them.
//!
//! It is the schema 3 counterpart of [`crate::publication_plan`], and it holds
//! the same three properties for the same reasons — a plan is verified before it
//! is displayed, a confirmation covers two exact documents, and the signature is
//! the one that already exists. What changes is what a human reads: a link plan
//! names a role and the constants that role decides; a listener junction names
//! the peer it accepts, the one port the passage will carry and the fact that
//! nothing else will pass; an initiator junction names the same and the one
//! endpoint it will reach.
//!
//! **Nothing is displayed that has not been verified.** [`PresentedLinkPlan`] is
//! the only way to obtain the lines a window renders, and the only way to obtain
//! one is [`PresentedLinkPlan::verify`], which rebuilds both digests from the
//! fields it parsed out of the received bytes. A pair whose digests do not
//! match, and a pair whose two documents belong to different operation groups,
//! never becomes a thing anyone can be shown.
//!
//! **A confirmation covers two exact documents.** [`LinkPlanConfirmation`]
//! carries the two digests it was given for, and signing re-reads the documents
//! from scratch and refuses when either the pair or the confirmed digests have
//! moved.
//!
//! **The signature is the one that already exists.** Nothing here holds a key or
//! builds a transcript: [`crate::approval::sign_approval`] does, from a typed
//! request, and what this module hands it as the plan is the exact bytes the
//! plan digest is taken over.
//!
//! **What the contract fixes is displayed, and approved as nothing.** The
//! interface, the two tunnel addresses, the listening port, the keepalive and
//! the rules table are constants no plan carries — the role decides them — but
//! each of them is part of what the plan does to the machine. A human who
//! approved a role without reading the port that role opens would have approved
//! a listener without knowing it listens, so none of them is left out.
//!
//! **The kind of plan is read in the document, never in the route.** The three
//! sibling Controller routes answer the same frozen-pair shape, so the operation
//! inside the document is what decides which closed field list was approved and
//! which lines a human is shown.

use crate::{
    approval::{
        build_consent, consent_confirms, sign_approval, ApprovalError, ApprovalRequest,
        ConsentRequest,
    },
    vault::AssociationRecord,
};
use serde::Deserialize;
use your_cloud_bootstrap_protocol::{
    verify_plan_v3_document, ApprovalConsentOutcomeV1, ApprovalConsentV1, ApprovalOperation,
    LinkRole, PlanDocumentV3, PlanV3Group, PlanV3Operation, SignedApprovalV1,
    LINK_INITIATOR_TUNNEL_ADDRESS, LINK_INTERFACE_NAME, LINK_KEEPALIVE_SECONDS,
    LINK_LISTENER_TUNNEL_ADDRESS, LINK_LISTEN_PORT, LINK_NFTABLES_TABLE,
};

/// The one schema of the pairs this palier reads.
const LINK_PLAN_SCHEMA_VERSION: u8 = 3;

#[derive(Debug, thiserror::Error)]
pub enum LinkPlanError {
    #[error("the plan pair is not the one its own digests name")]
    UnverifiedPlan,
    #[error("the plan names another infrastructure than this Console is associated to")]
    ForeignInfrastructure,
    #[error("no confirmation covers these exact documents")]
    UnconfirmedPlan,
    #[error("the approval of this plan could not be signed")]
    Approval(#[from] ApprovalError),
}

impl LinkPlanError {
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

/// The frozen pair exactly as `POST /v0/link-plans`, `/v0/listener-peer-plans`
/// and `/v0/initiator-peer-plans` answer it.
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
pub struct LinkPlanPairView {
    pub schema_version: u8,
    pub plan_document: String,
    pub plan_sha256: String,
    pub rollback_document: String,
    pub rollback_sha256: String,
}

/// A pair that has been held against its own digests, and the digests this side
/// computed rather than the ones it was handed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentedLinkPlan {
    plan: PlanDocumentV3,
    rollback: PlanDocumentV3,
    plan_sha256: String,
    rollback_sha256: String,
}

/// What the native confirmation window answered.
///
/// A confirmation names the two digests it was given for. It is therefore not a
/// permission to sign "the current plan": it is a permission to sign those two
/// documents, and it stops meaning anything the moment either of them moves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkPlanConfirmation {
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
pub struct LinkApprovalRequest {
    pub approval_epoch: u64,
    pub sequence: u64,
    pub issued_at_unix_seconds: u64,
    pub lifetime_seconds: u64,
}

impl PresentedLinkPlan {
    /// Verifies the whole pair before any of it can be displayed.
    ///
    /// Both documents are strict-decoded inside the bounds of the schema 3
    /// contract — closed role, canonical peer key, endpoint host bound and port
    /// range included — both digests are rebuilt from the parsed fields, and the
    /// rollback is required to be the complete document that undoes the plan:
    /// the same operation group, the same instance, the inverse operation and
    /// nothing else changed. A pair whose two documents belong to different
    /// groups therefore fails here, before anything of it is rendered. A pair
    /// that fails any of the three is refused whole: there is no partially
    /// verified plan a window could render "most of".
    pub fn verify(view: &LinkPlanPairView) -> Result<Self, LinkPlanError> {
        if view.schema_version != LINK_PLAN_SCHEMA_VERSION {
            return Err(LinkPlanError::UnverifiedPlan);
        }
        let plan = verify_plan_v3_document(view.plan_document.as_bytes(), &view.plan_sha256)
            .map_err(|_| LinkPlanError::UnverifiedPlan)?;
        let rollback =
            verify_plan_v3_document(view.rollback_document.as_bytes(), &view.rollback_sha256)
                .map_err(|_| LinkPlanError::UnverifiedPlan)?;
        if !plan.is_undone_by(&rollback) {
            return Err(LinkPlanError::UnverifiedPlan);
        }
        // The digests kept are the ones computed here, never the ones received.
        // They are equal — the verification above is exactly that equality —
        // and keeping the computed ones is what makes every value below the
        // result of reading the documents rather than of trusting their escort.
        let plan_sha256 = plan.sha256().map_err(|_| LinkPlanError::UnverifiedPlan)?;
        let rollback_sha256 = rollback
            .sha256()
            .map_err(|_| LinkPlanError::UnverifiedPlan)?;
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

    pub fn operation(&self) -> PlanV3Operation {
        self.plan.operation()
    }

    pub fn group(&self) -> PlanV3Group {
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
    /// the contract.
    ///
    /// A link plan names its role and everything that role decides: the tunnel
    /// address and its `/32`, the interface it lives on, and then the one
    /// constant that belongs to that role alone — the listening port for the
    /// listener, the keepalive for the initiator. It also names what happens to
    /// the keys, because a plan that generates key material and says nothing
    /// about where it goes would be approved on a silence.
    ///
    /// A junction plan names the peer public key exactly as the document spells
    /// it, the one port the rules will bind, and the single couple that will be
    /// allowed through — an address and a port, and nothing else. The rules
    /// table is named as the declared effect it is, posed with the plan and
    /// removed with it. The initiator's junction adds the one endpoint it
    /// reaches, beside the listening port of the contract that endpoint is
    /// reached on, because that port is not a field and would otherwise be
    /// approved unread.
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
            PlanDocumentV3::Link(document) => {
                lines.push(format!("Rôle du lien : {}", role_text(document.link_role)));
                lines.push(format!(
                    "Adresse de tunnel : {}/32 sur l’interface {LINK_INTERFACE_NAME}",
                    document.link_role.tunnel_address()
                ));
                match document.link_role {
                    LinkRole::Listener => lines.push(format!(
                        "Port d’écoute (UDP) : {LINK_LISTEN_PORT}, sur l’écouteur seulement"
                    )),
                    LinkRole::Initiator => lines.push(format!(
                        "Keepalive : {LINK_KEEPALIVE_SECONDS} s, sur l’initiateur seulement"
                    )),
                }
                lines.push(
                    "Clés : générées sur cette machine, la moitié privée n’en sort jamais"
                        .to_owned(),
                );
            }
            PlanDocumentV3::ListenerPeer(document) => {
                lines.push(format!(
                    "Clé publique du pair : {}",
                    document.peer_public_key
                ));
                lines.push(format!("Port du service : {}", document.service_port));
                lines.push(format!(
                    "Seul flux autorisé : TCP vers {LINK_INITIATOR_TUNNEL_ADDRESS}:{}, \
                     et rien d’autre",
                    document.service_port
                ));
                lines.push(format!(
                    "Table de règles : {LINK_NFTABLES_TABLE}, posée avec ce plan \
                     et retirée avec lui"
                ));
            }
            PlanDocumentV3::InitiatorPeer(document) => {
                lines.push(format!(
                    "Clé publique du pair : {}",
                    document.peer_public_key
                ));
                lines.push(format!(
                    "Endpoint joint : {}:{LINK_LISTEN_PORT}",
                    document.peer_endpoint_host
                ));
                lines.push(format!("Port du service : {}", document.service_port));
                lines.push(format!(
                    "Seul flux autorisé : TCP depuis {LINK_LISTENER_TUNNEL_ADDRESS} vers \
                     ce port, et rien d’autre"
                ));
                lines.push(format!(
                    "Table de règles : {LINK_NFTABLES_TABLE}, posée avec ce plan \
                     et retirée avec lui"
                ));
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
    pub fn confirmed(&self) -> LinkPlanConfirmation {
        LinkPlanConfirmation::Confirmed {
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
    ) -> Result<ApprovalConsentV1, LinkPlanError> {
        if self.plan.infrastructure_id() != association.summary.infrastructure_id.as_str() {
            return Err(LinkPlanError::ForeignInfrastructure);
        }
        let confirmation_lines = self.confirmation_lines();
        Ok(build_consent(
            association,
            ConsentRequest {
                request_id,
                machine_id: self.plan.machine_id(),
                operation: approval_operation(self.plan.operation()),
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
    /// laundered through a presentation of this one.
    pub fn confirmed_by(
        &self,
        consent: &ApprovalConsentV1,
        outcome: &ApprovalConsentOutcomeV1,
    ) -> LinkPlanConfirmation {
        if consent.plan_sha256 != self.plan_sha256
            || consent.rollback_sha256 != self.rollback_sha256
            || !consent_confirms(consent, outcome)
        {
            return LinkPlanConfirmation::Refused;
        }
        self.confirmed()
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
        documents: &LinkPlanPairView,
        confirmation: &LinkPlanConfirmation,
        request: LinkApprovalRequest,
    ) -> Result<SignedApprovalV1, LinkPlanError> {
        let LinkPlanConfirmation::Confirmed {
            plan_sha256,
            rollback_sha256,
        } = confirmation
        else {
            return Err(LinkPlanError::UnconfirmedPlan);
        };
        if *plan_sha256 != self.plan_sha256 || *rollback_sha256 != self.rollback_sha256 {
            return Err(LinkPlanError::UnconfirmedPlan);
        }
        if Self::verify(documents)? != *self {
            return Err(LinkPlanError::UnconfirmedPlan);
        }
        // Read from the plan and from the association, never from the request:
        // an approval can only ever name the infrastructure this Console is
        // associated to, and a plan that names another one is not this
        // Console's to approve.
        if self.plan.infrastructure_id() != association.summary.infrastructure_id.as_str() {
            return Err(LinkPlanError::ForeignInfrastructure);
        }

        let hashed_plan = self
            .plan
            .transcript()
            .map_err(|_| LinkPlanError::UnverifiedPlan)?;
        let hashed_rollback = self
            .rollback
            .transcript()
            .map_err(|_| LinkPlanError::UnverifiedPlan)?;
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
            return Err(LinkPlanError::UnconfirmedPlan);
        }
        Ok(signed)
    }
}

/// The closed bridge between what a plan describes and what an envelope
/// authorises. Each side has its own closed list, and this is the only place
/// they are mapped onto one another for schema 3.
fn approval_operation(operation: PlanV3Operation) -> ApprovalOperation {
    match operation {
        PlanV3Operation::PrepareLink => ApprovalOperation::PrepareLink,
        PlanV3Operation::WithdrawLink => ApprovalOperation::WithdrawLink,
        PlanV3Operation::AttachLinkPeer => ApprovalOperation::AttachLinkPeer,
        PlanV3Operation::DetachLinkPeer => ApprovalOperation::DetachLinkPeer,
        PlanV3Operation::JoinLinkPeer => ApprovalOperation::JoinLinkPeer,
        PlanV3Operation::LeaveLinkPeer => ApprovalOperation::LeaveLinkPeer,
    }
}

fn operation_text(operation: PlanV3Operation) -> &'static str {
    match operation {
        PlanV3Operation::PrepareLink => "préparer le lien privé de cette machine",
        PlanV3Operation::WithdrawLink => "retirer le lien privé de cette machine",
        PlanV3Operation::AttachLinkPeer => "joindre le pair au lien de l’écouteur",
        PlanV3Operation::DetachLinkPeer => "détacher le pair du lien de l’écouteur",
        PlanV3Operation::JoinLinkPeer => "joindre le pair depuis l’initiateur",
        PlanV3Operation::LeaveLinkPeer => "quitter le pair depuis l’initiateur",
    }
}

/// The two sides of the passage, named as what they do rather than by their
/// wire spelling: the role is what decides every constant displayed beside it.
fn role_text(role: LinkRole) -> &'static str {
    match role {
        LinkRole::Listener => "écouteur, le côté qui écoute le port du contrat",
        LinkRole::Initiator => "initiateur, le côté qui sort et maintient le tunnel",
    }
}

/// What a rollback shares with the plan it undoes, group by group. It is the
/// whole of what "exact inverse" means on screen: everything but the operation.
fn rollback_scope_text(group: PlanV3Group) -> &'static str {
    match group {
        PlanV3Group::Link => "sur la même machine et le même rôle",
        PlanV3Group::ListenerPeer => "sur la même machine, le même pair et le même port",
        PlanV3Group::InitiatorPeer => {
            "sur la même machine, le même pair, le même endpoint et le même port"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::AssociationSummary;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use your_cloud_bootstrap_protocol::ApprovalPrivilege;

    const INFRASTRUCTURE: &str = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2";
    const MACHINE: &str = "lab-machine-1";
    const PEER_PUBLIC_KEY: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    const ENDPOINT_HOST: &str = "vps.lab.your-cloud.test";
    const ISSUED_AT: u64 = 1_780_000_000;

    /// The six shared vectors of the schema 3 encoding, byte for byte. The very
    /// same documents and digests are pinned in
    /// `crates/bootstrap-protocol/src/plan_v3.rs` and in
    /// `internal/plan/schema3_test.go`.
    const LINK_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":3,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"prepare_link","link_role":"listener"}"#,
    );
    const LINK_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":3,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"withdraw_link","link_role":"listener"}"#,
    );
    const INITIATOR_LINK_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":3,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"prepare_link","link_role":"initiator"}"#,
    );
    const INITIATOR_LINK_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":3,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"withdraw_link","link_role":"initiator"}"#,
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

    /// A schema 2 pair, kept here so that a document of the previous palier can
    /// be presented to this one and refused as what it is.
    const ROUTE_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"publish_route","#,
        r#""route_host":"bentopdf.lab.your-cloud.test","backend_port":8080}"#,
    );
    const ROUTE_PLAN_SHA256: &str =
        "3d92c310868a8ba98aca5501c069bd0e4674757f787c8095e7c39d65d8d20a89";

    fn view(
        plan_document: &str,
        plan_sha256: &str,
        rollback_document: &str,
        rollback_sha256: &str,
    ) -> LinkPlanPairView {
        LinkPlanPairView {
            schema_version: LINK_PLAN_SCHEMA_VERSION,
            plan_document: plan_document.to_owned(),
            plan_sha256: plan_sha256.to_owned(),
            rollback_document: rollback_document.to_owned(),
            rollback_sha256: rollback_sha256.to_owned(),
        }
    }

    fn link_view() -> LinkPlanPairView {
        view(
            LINK_PLAN_DOCUMENT,
            LINK_PLAN_SHA256,
            LINK_ROLLBACK_DOCUMENT,
            LINK_ROLLBACK_SHA256,
        )
    }

    fn listener_peer_view() -> LinkPlanPairView {
        view(
            LISTENER_PEER_PLAN_DOCUMENT,
            LISTENER_PEER_PLAN_SHA256,
            LISTENER_PEER_ROLLBACK_DOCUMENT,
            LISTENER_PEER_ROLLBACK_SHA256,
        )
    }

    fn initiator_peer_view() -> LinkPlanPairView {
        view(
            INITIATOR_PEER_PLAN_DOCUMENT,
            INITIATOR_PEER_PLAN_SHA256,
            INITIATOR_PEER_ROLLBACK_DOCUMENT,
            INITIATOR_PEER_ROLLBACK_SHA256,
        )
    }

    /// The initiator's own side of the link, whose digests are not pinned in the
    /// shared vectors: it is presented through the pair the Controller would
    /// freeze, and this side computes the two digests it is verified against, so
    /// no digest is written here that nobody produced.
    fn initiator_link_view() -> LinkPlanPairView {
        let plan_sha256 = digest_of(INITIATOR_LINK_PLAN_DOCUMENT);
        let rollback_sha256 = digest_of(INITIATOR_LINK_ROLLBACK_DOCUMENT);
        view(
            INITIATOR_LINK_PLAN_DOCUMENT,
            &plan_sha256,
            INITIATOR_LINK_ROLLBACK_DOCUMENT,
            &rollback_sha256,
        )
    }

    fn digest_of(document: &str) -> String {
        your_cloud_bootstrap_protocol::decode_plan_v3_document(document.as_bytes())
            .expect("a document of the contract")
            .sha256()
            .expect("its digest")
    }

    fn request() -> LinkApprovalRequest {
        LinkApprovalRequest {
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

    /// The nominal path of the link group, in the listener role: the pair is the
    /// one its digests name, and the constants the role decides are displayed
    /// beside it although no field carries them.
    #[test]
    fn a_verified_listener_link_displays_the_constants_its_role_decides() {
        let presented = PresentedLinkPlan::verify(&link_view()).expect("the vector");
        assert_eq!(presented.machine_id(), MACHINE);
        assert_eq!(presented.operation(), PlanV3Operation::PrepareLink);
        assert_eq!(presented.group(), PlanV3Group::Link);
        assert_eq!(presented.plan_sha256(), LINK_PLAN_SHA256);
        assert_eq!(presented.rollback_sha256(), LINK_ROLLBACK_SHA256);

        assert_eq!(
            presented.confirmation_lines(),
            vec![
                format!("Machine : {MACHINE}"),
                "Opération : préparer le lien privé de cette machine".to_owned(),
                "Rôle du lien : écouteur, le côté qui écoute le port du contrat".to_owned(),
                "Adresse de tunnel : 10.66.66.1/32 sur l’interface yc-link0".to_owned(),
                "Port d’écoute (UDP) : 51820, sur l’écouteur seulement".to_owned(),
                "Clés : générées sur cette machine, la moitié privée n’en sort jamais".to_owned(),
                "Rollback : retirer le lien privé de cette machine, sur la même machine \
                 et le même rôle"
                    .to_owned(),
                format!("Empreinte du plan : {LINK_PLAN_SHA256}"),
                format!("Empreinte du rollback : {LINK_ROLLBACK_SHA256}"),
            ]
        );
    }

    /// The other role of the same group names the other constant, and only it:
    /// the initiator has no listening port to display and the listener has no
    /// keepalive.
    #[test]
    fn a_verified_initiator_link_names_the_keepalive_and_no_listening_port() {
        let presented = PresentedLinkPlan::verify(&initiator_link_view()).expect("the pair");
        let lines = presented.confirmation_lines();
        assert_eq!(
            lines[2],
            "Rôle du lien : initiateur, le côté qui sort et maintient le tunnel"
        );
        assert_eq!(
            lines[3],
            "Adresse de tunnel : 10.66.66.2/32 sur l’interface yc-link0"
        );
        assert_eq!(lines[4], "Keepalive : 25 s, sur l’initiateur seulement");
        let displayed = lines.concat();
        assert!(!displayed.contains("Port d’écoute"));
        assert!(!displayed.contains("51820"));

        let listener = PresentedLinkPlan::verify(&link_view()).unwrap();
        assert!(!listener.confirmation_lines().concat().contains("Keepalive"));
    }

    /// The listener's junction names the peer it accepts, the port the rules
    /// bind and the one couple that will pass.
    #[test]
    fn a_verified_listener_junction_displays_the_only_couple_that_passes() {
        let presented = PresentedLinkPlan::verify(&listener_peer_view()).expect("the vector");
        assert_eq!(presented.operation(), PlanV3Operation::AttachLinkPeer);
        assert_eq!(presented.group(), PlanV3Group::ListenerPeer);

        assert_eq!(
            presented.confirmation_lines(),
            vec![
                format!("Machine : {MACHINE}"),
                "Opération : joindre le pair au lien de l’écouteur".to_owned(),
                format!("Clé publique du pair : {PEER_PUBLIC_KEY}"),
                "Port du service : 8080".to_owned(),
                "Seul flux autorisé : TCP vers 10.66.66.2:8080, et rien d’autre".to_owned(),
                "Table de règles : inet your-cloud-link, posée avec ce plan \
                 et retirée avec lui"
                    .to_owned(),
                "Rollback : détacher le pair du lien de l’écouteur, sur la même machine, \
                 le même pair et le même port"
                    .to_owned(),
                format!("Empreinte du plan : {LISTENER_PEER_PLAN_SHA256}"),
                format!("Empreinte du rollback : {LISTENER_PEER_ROLLBACK_SHA256}"),
            ]
        );
    }

    /// The initiator's junction names the same couple and the one endpoint it
    /// reaches, beside the listening port of the contract that endpoint is
    /// reached on.
    #[test]
    fn a_verified_initiator_junction_displays_the_endpoint_and_the_contract_port() {
        let presented = PresentedLinkPlan::verify(&initiator_peer_view()).expect("the vector");
        assert_eq!(presented.operation(), PlanV3Operation::JoinLinkPeer);
        assert_eq!(presented.group(), PlanV3Group::InitiatorPeer);

        assert_eq!(
            presented.confirmation_lines(),
            vec![
                format!("Machine : {MACHINE}"),
                "Opération : joindre le pair depuis l’initiateur".to_owned(),
                format!("Clé publique du pair : {PEER_PUBLIC_KEY}"),
                format!("Endpoint joint : {ENDPOINT_HOST}:51820"),
                "Port du service : 8080".to_owned(),
                "Seul flux autorisé : TCP depuis 10.66.66.1 vers ce port, et rien d’autre"
                    .to_owned(),
                "Table de règles : inet your-cloud-link, posée avec ce plan \
                 et retirée avec lui"
                    .to_owned(),
                "Rollback : quitter le pair depuis l’initiateur, sur la même machine, \
                 le même pair, le même endpoint et le même port"
                    .to_owned(),
                format!("Empreinte du plan : {INITIATOR_PEER_PLAN_SHA256}"),
                format!("Empreinte du rollback : {INITIATOR_PEER_ROLLBACK_SHA256}"),
            ]
        );
    }

    /// The peer key is displayed exactly as the document spells it.
    ///
    /// It is the one value nobody chose — an observation the other machine
    /// reported — so the human approves the string the plan carries rather than
    /// a shortened or re-spelled version of it. A truncated key on screen would
    /// be a key nobody could compare with the report it came from.
    #[test]
    fn the_peer_key_is_displayed_whole_and_unaltered() {
        for pair in [listener_peer_view(), initiator_peer_view()] {
            let presented = PresentedLinkPlan::verify(&pair).unwrap();
            let key_line = presented
                .confirmation_lines()
                .into_iter()
                .find(|line| line.starts_with("Clé publique du pair : "))
                .expect("the key is on screen");
            assert_eq!(
                key_line,
                format!("Clé publique du pair : {PEER_PUBLIC_KEY}")
            );
            assert!(key_line.ends_with(PEER_PUBLIC_KEY));
        }
    }

    /// Nothing reaches a window before its digests are held.
    ///
    /// Each hostile pair below is one a transport could actually send: a
    /// document swapped for the other, a value moved inside a document, a
    /// rollback that undoes something else, a pair whose two documents belong to
    /// different operation groups, a document outside the schema 3 contract.
    /// None of them produces a value that can be displayed at all.
    #[test]
    fn an_unverified_pair_is_refused_before_it_can_be_displayed() {
        let altered_port =
            LISTENER_PEER_PLAN_DOCUMENT.replace(r#""service_port":8080"#, r#""service_port":9090"#);
        let altered_machine = LINK_PLAN_DOCUMENT.replace(
            r#""machine_id":"lab-machine-1""#,
            r#""machine_id":"lab-machine-2""#,
        );
        let other_role = LINK_PLAN_DOCUMENT.replace(r#""listener""#, r#""initiator""#);
        let other_key = INITIATOR_PEER_PLAN_DOCUMENT.replace(
            PEER_PUBLIC_KEY,
            "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=",
        );
        let other_endpoint =
            INITIATOR_PEER_PLAN_DOCUMENT.replace(ENDPOINT_HOST, "evil.lab.your-cloud.test");
        let non_canonical_key = LISTENER_PEER_PLAN_DOCUMENT
            .replace(PEER_PUBLIC_KEY, &PEER_PUBLIC_KEY.replace("HyA=", "HyB="));
        for (name, hostile) in [
            (
                "an unsupported schema",
                LinkPlanPairView {
                    schema_version: 2,
                    ..link_view()
                },
            ),
            (
                "a junction whose port was moved after it was frozen",
                LinkPlanPairView {
                    plan_document: altered_port,
                    ..listener_peer_view()
                },
            ),
            (
                "a plan aimed at another machine under the same digest",
                LinkPlanPairView {
                    plan_document: altered_machine,
                    ..link_view()
                },
            ),
            (
                "a link plan whose role was moved after it was frozen",
                LinkPlanPairView {
                    plan_document: other_role,
                    ..link_view()
                },
            ),
            (
                "a junction naming another peer under the same digest",
                LinkPlanPairView {
                    plan_document: other_key,
                    ..initiator_peer_view()
                },
            ),
            (
                "a junction naming another endpoint under the same digest",
                LinkPlanPairView {
                    plan_document: other_endpoint,
                    ..initiator_peer_view()
                },
            ),
            (
                "a junction naming a second spelling of the same key",
                LinkPlanPairView {
                    plan_document: non_canonical_key,
                    ..listener_peer_view()
                },
            ),
            (
                "the two documents exchanged",
                LinkPlanPairView {
                    plan_document: LINK_ROLLBACK_DOCUMENT.to_owned(),
                    rollback_document: LINK_PLAN_DOCUMENT.to_owned(),
                    ..link_view()
                },
            ),
            (
                "a rollback that is a second copy of the plan",
                LinkPlanPairView {
                    rollback_document: LINK_PLAN_DOCUMENT.to_owned(),
                    rollback_sha256: LINK_PLAN_SHA256.to_owned(),
                    ..link_view()
                },
            ),
            (
                "a rollback of another operation group",
                LinkPlanPairView {
                    rollback_document: LISTENER_PEER_ROLLBACK_DOCUMENT.to_owned(),
                    rollback_sha256: LISTENER_PEER_ROLLBACK_SHA256.to_owned(),
                    ..link_view()
                },
            ),
            (
                "a junction of one side undone by the junction of the other",
                LinkPlanPairView {
                    rollback_document: INITIATOR_PEER_ROLLBACK_DOCUMENT.to_owned(),
                    rollback_sha256: INITIATOR_PEER_ROLLBACK_SHA256.to_owned(),
                    ..listener_peer_view()
                },
            ),
            (
                "a rollback of another instance",
                LinkPlanPairView {
                    rollback_document: INITIATOR_PEER_ROLLBACK_DOCUMENT.to_owned(),
                    rollback_sha256: INITIATOR_PEER_ROLLBACK_SHA256.to_owned(),
                    ..link_view()
                },
            ),
            (
                "an upper-case digest",
                LinkPlanPairView {
                    plan_sha256: LINK_PLAN_SHA256.to_ascii_uppercase(),
                    ..link_view()
                },
            ),
            (
                "an empty document",
                LinkPlanPairView {
                    plan_document: String::new(),
                    ..link_view()
                },
            ),
            (
                "a schema 2 route plan under a schema 3 pair",
                LinkPlanPairView {
                    plan_document: ROUTE_PLAN_DOCUMENT.to_owned(),
                    plan_sha256: ROUTE_PLAN_SHA256.to_owned(),
                    ..link_view()
                },
            ),
        ] {
            assert!(
                matches!(
                    PresentedLinkPlan::verify(&hostile),
                    Err(LinkPlanError::UnverifiedPlan)
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
                "link",
                link_view(),
                view(
                    LINK_ROLLBACK_DOCUMENT,
                    LINK_ROLLBACK_SHA256,
                    LINK_PLAN_DOCUMENT,
                    LINK_PLAN_SHA256,
                ),
                ApprovalOperation::PrepareLink,
                ApprovalOperation::WithdrawLink,
            ),
            (
                "listener peer",
                listener_peer_view(),
                view(
                    LISTENER_PEER_ROLLBACK_DOCUMENT,
                    LISTENER_PEER_ROLLBACK_SHA256,
                    LISTENER_PEER_PLAN_DOCUMENT,
                    LISTENER_PEER_PLAN_SHA256,
                ),
                ApprovalOperation::AttachLinkPeer,
                ApprovalOperation::DetachLinkPeer,
            ),
            (
                "initiator peer",
                initiator_peer_view(),
                view(
                    INITIATOR_PEER_ROLLBACK_DOCUMENT,
                    INITIATOR_PEER_ROLLBACK_SHA256,
                    INITIATOR_PEER_PLAN_DOCUMENT,
                    INITIATOR_PEER_PLAN_SHA256,
                ),
                ApprovalOperation::JoinLinkPeer,
                ApprovalOperation::LeaveLinkPeer,
            ),
        ] {
            let presented = PresentedLinkPlan::verify(&forward).unwrap();
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
            let presented_reverse = PresentedLinkPlan::verify(&reverse).unwrap();
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
        let presented = PresentedLinkPlan::verify(&initiator_peer_view()).unwrap();
        let confirmation = presented.confirmed();

        // The pair the window rendered, re-presented with the departure in place
        // of the junction: a valid pair in its own right, and not the one that
        // was confirmed.
        let exchanged = view(
            INITIATOR_PEER_ROLLBACK_DOCUMENT,
            INITIATOR_PEER_ROLLBACK_SHA256,
            INITIATOR_PEER_PLAN_DOCUMENT,
            INITIATOR_PEER_PLAN_SHA256,
        );
        assert!(matches!(
            presented.sign(&record, &exchanged, &confirmation, request()),
            Err(LinkPlanError::UnconfirmedPlan)
        ));

        // A pair of another operation group is not the confirmed one either,
        // even though it verifies perfectly on its own.
        assert!(matches!(
            presented.sign(&record, &listener_peer_view(), &confirmation, request()),
            Err(LinkPlanError::UnconfirmedPlan)
        ));

        // Documents altered after they were displayed no longer verify at all.
        let altered = LinkPlanPairView {
            plan_document: INITIATOR_PEER_PLAN_DOCUMENT
                .replace(r#""service_port":8080"#, r#""service_port":9090"#),
            ..initiator_peer_view()
        };
        assert!(matches!(
            presented.sign(&record, &altered, &confirmation, request()),
            Err(LinkPlanError::UnverifiedPlan)
        ));

        // A refusal is not a confirmation, and neither is a confirmation whose
        // digests name another pair.
        for hostile in [
            LinkPlanConfirmation::Refused,
            LinkPlanConfirmation::Confirmed {
                plan_sha256: INITIATOR_PEER_ROLLBACK_SHA256.to_owned(),
                rollback_sha256: INITIATOR_PEER_PLAN_SHA256.to_owned(),
            },
            LinkPlanConfirmation::Confirmed {
                plan_sha256: LINK_PLAN_SHA256.to_owned(),
                rollback_sha256: LINK_ROLLBACK_SHA256.to_owned(),
            },
            LinkPlanConfirmation::Confirmed {
                plan_sha256: INITIATOR_PEER_PLAN_SHA256.to_owned(),
                rollback_sha256: String::new(),
            },
        ] {
            assert!(matches!(
                presented.sign(&record, &initiator_peer_view(), &hostile, request()),
                Err(LinkPlanError::UnconfirmedPlan)
            ));
        }
    }

    /// A plan is approved by the Console of its own infrastructure or by none.
    #[test]
    fn a_plan_of_another_infrastructure_is_never_signed() {
        let foreign = association("8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3");
        for pair in [link_view(), listener_peer_view(), initiator_peer_view()] {
            let presented = PresentedLinkPlan::verify(&pair).unwrap();
            assert!(matches!(
                presented.sign(&foreign, &pair, &presented.confirmed(), request()),
                Err(LinkPlanError::ForeignInfrastructure)
            ));
        }
    }

    /// A request outside the bounds of the envelope produces no signature, and
    /// the refusal comes from the one signing path rather than from a second
    /// rule written here.
    #[test]
    fn a_request_outside_the_envelope_bounds_produces_no_signature() {
        let record = association(INFRASTRUCTURE);
        let presented = PresentedLinkPlan::verify(&link_view()).unwrap();
        for hostile in [
            LinkApprovalRequest {
                approval_epoch: 0,
                ..request()
            },
            LinkApprovalRequest {
                sequence: 0,
                ..request()
            },
            LinkApprovalRequest {
                lifetime_seconds: 0,
                ..request()
            },
            LinkApprovalRequest {
                issued_at_unix_seconds: 0,
                ..request()
            },
        ] {
            assert!(matches!(
                presented.sign(&record, &link_view(), &presented.confirmed(), hostile),
                Err(LinkPlanError::Approval(ApprovalError::InvalidRequest))
            ));
        }
    }

    /// Nothing this module produces carries key material.
    ///
    /// The signed document names the public half and the signature, both of
    /// which are meant to travel, and the lines a window renders are facts about
    /// a plan. The private seed of the association appears in neither, and no
    /// private half of a passage key could appear anywhere: it is generated on
    /// its own machine and nothing here has ever seen one.
    #[test]
    fn the_surface_this_module_produces_carries_no_key_material() {
        let record = association(INFRASTRUCTURE);
        for pair in [link_view(), listener_peer_view(), initiator_peer_view()] {
            let presented = PresentedLinkPlan::verify(&pair).unwrap();
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
            LinkPlanError::UnverifiedPlan.public_code(),
            LinkPlanError::ForeignInfrastructure.public_code(),
            LinkPlanError::UnconfirmedPlan.public_code(),
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
