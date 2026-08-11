use crate::{
    publication_plan::PlanPairView,
    service_definition::displayable_definition,
    vault::{
        parse_recovery_code, AssociationRecord, AssociationSummary, RecoveryControllerProgress,
    },
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use rcgen::{
    string::Ia5String, CertificateParams, DistinguishedName, KeyPair, SanType,
    PKCS_ECDSA_P256_SHA256,
};
use reqwest::{
    blocking::{Client, Response},
    header::{
        ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING,
    },
    redirect::Policy,
    tls::Version,
    StatusCode,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::Read,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use unicode_general_category::{get_general_category, GeneralCategory};
use unicode_normalization::UnicodeNormalization;
use url::Url;
use uuid::Uuid;
use x509_parser::{extensions::GeneralName, parse_x509_certificate, pem::parse_x509_pem};
use your_cloud_bootstrap_protocol::MAX_SERVICE_DEFINITION_BYTES;
use zeroize::{Zeroize, Zeroizing};

const REQUEST_MAX_BYTES: usize = 4 * 1024;
const RESPONSE_MAX_BYTES: usize = 128 * 1024;
// The declared inventory is bounded by the Controller at 128 declarations, and
// a label is closed on bytes rather than on the managed label profile: 1 to 64
// printable ASCII characters, kept exactly as the human wrote them.
const MAX_EXTERNAL_ELEMENTS: usize = 128;
const MAX_EXTERNAL_LABEL_BYTES: usize = 64;
// The frozen definitions are bounded by the Controller at 128 revisions, all
// slugs taken together, and the listing carries every one of them.
const MAX_FROZEN_SERVICE_DEFINITIONS: usize = 128;
// The one request of this Console whose bound is not the common four kilobytes,
// and it is the Controller's own bound rather than a second number: a definition
// travels as a JSON string, a canonical definition is printable ASCII in which
// only the quote and the backslash are escaped, so a document at its bound
// arrives as at most twice its bytes plus the two other fields of the envelope.
// Deriving it from the document's bound is what keeps a definition the contract
// admits from being one this Console could never send.
const DEFINITION_REQUEST_MAX_BYTES: usize = 2 * MAX_SERVICE_DEFINITION_BYTES + 512;
const TEMPORARY_RESPONSE_MAX_BYTES: usize = 8 * 1024;
const ERROR_MAX_BYTES: usize = 1024;
const CSR_MAX_BYTES: usize = 2 * 1024;
const CA_MAX_BYTES: usize = 16 * 1024;
const RECOVERY_DOMAIN: &[u8] = b"your-cloud/recovery-signing.v1";
const RECOVERY_ROTATION_SALT_DOMAIN: &[u8] = b"your-cloud/recovery-rotation-salt.v1\0";
const RECOVERY_KEY_TRANSCRIPT_DOMAIN: &[u8] = b"your-cloud/recovery-key-rotation.v1\0";
const IDENTITY_TRANSCRIPT_DOMAIN: &[u8] = b"your-cloud/identity-transcript.v1\0";
const HUMAN_SESSION_DOMAIN: &[u8] = b"your-cloud/human-session.v1\0";

#[derive(Debug, thiserror::Error)]
pub(crate) enum NetworkError {
    #[error("invalid local input")]
    InvalidInput,
    #[error("association failed")]
    AssociationFailed,
    #[error("human session expired")]
    SessionExpired,
    #[error("Controller unavailable")]
    ControllerUnavailable,
    #[error("Controller response refused")]
    ResponseRefused,
    #[error("request was cancelled")]
    Cancelled,
    #[error("local Console state is unavailable")]
    ConsoleUnavailable,
}

impl NetworkError {
    pub(crate) fn public_code(&self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::AssociationFailed => "association_failed",
            Self::SessionExpired => "session_expired",
            Self::ControllerUnavailable | Self::Cancelled => "controller_unavailable",
            Self::ResponseRefused => "response_refused",
            Self::ConsoleUnavailable => "console_unavailable",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairingInput {
    pub mode: String,
    pub origin: String,
    pub temporary_origin: String,
    pub controller_id: String,
    pub infrastructure_id: String,
    pub server_ca_pem: String,
    pub server_spki_sha256: String,
    pub window_id: String,
    pub window_code: String,
    pub recovery_code: String,
}

impl Drop for PairingInput {
    fn drop(&mut self) {
        self.window_code.zeroize();
        self.recovery_code.zeroize();
    }
}

pub(crate) struct NetworkState {
    sessions: HashMap<String, Zeroizing<String>>,
}

impl NetworkState {
    pub(crate) fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub(crate) fn clear_sessions(&mut self) {
        self.sessions.clear();
    }

    pub(crate) fn pair<F>(
        &mut self,
        input: PairingInput,
        generation: u64,
        current_generation: &AtomicU64,
        persist_candidate: F,
    ) -> Result<AssociationRecord, NetworkError>
    where
        F: FnOnce(AssociationRecord) -> Result<(), NetworkError>,
    {
        let validated = ValidatedPairing::new(&input)?;
        ensure_current(generation, current_generation)?;
        let temporary_client = controller_client(&input.server_ca_pem, None)?;
        let request_id = random_raw_url(16);
        let challenge_request = IdentityChallengeRequest {
            schema_version: 1,
            window_id: &input.window_id,
            window_code: &input.window_code,
            request_id: &request_id,
        };
        let challenge: IdentityChallengeResponse = send_json(
            &temporary_client,
            "POST",
            &format!("{}/v0/{}/challenge", input.temporary_origin, input.mode),
            None,
            &challenge_request,
            TEMPORARY_RESPONSE_MAX_BYTES,
            &[StatusCode::OK],
        )
        .map_err(pairing_error)?;
        validate_identity_challenge(&challenge, &input)?;
        ensure_current(generation, current_generation)?;

        let device_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|_| NetworkError::ControllerUnavailable)?;
        let mut parameters = CertificateParams::default();
        parameters.distinguished_name = DistinguishedName::new();
        let device_uri = device_uri(&input.infrastructure_id, &challenge.device_id);
        parameters.subject_alt_names = vec![SanType::URI(
            Ia5String::try_from(device_uri).map_err(|_| NetworkError::ResponseRefused)?,
        )];
        let csr = parameters
            .serialize_request(&device_key)
            .map_err(|_| NetworkError::ControllerUnavailable)?;
        let csr_der = csr.der().as_ref();
        if csr_der.is_empty() || csr_der.len() > CSR_MAX_BYTES {
            return Err(NetworkError::ControllerUnavailable);
        }

        let human = SigningKey::generate(&mut OsRng);
        let next_recovery = recovery_signing_key(
            &validated.recovery_code,
            &challenge.next_recovery_salt,
            challenge.next_recovery_epoch,
            &validated.infrastructure_uuid,
            &validated.spki,
        )?;
        let current_recovery = if input.mode == "recovery" {
            Some(recovery_signing_key(
                &validated.recovery_code,
                &challenge.current_recovery_salt,
                challenge.current_recovery_epoch,
                &validated.infrastructure_uuid,
                &validated.spki,
            )?)
        } else {
            None
        };
        if let Some(current) = &current_recovery {
            let rendered = URL_SAFE_NO_PAD.encode(current.verifying_key().as_bytes());
            if rendered != challenge.current_recovery_public_key {
                return Err(NetworkError::AssociationFailed);
            }
        }
        let human_public = human.verifying_key().to_bytes();
        let next_recovery_public = next_recovery.verifying_key().to_bytes();
        let transcript = identity_transcript(
            &input,
            &challenge,
            &request_id,
            csr_der,
            &human_public,
            &next_recovery_public,
        )?;
        let completion = IdentityCompletionRequest {
            schema_version: 1,
            transaction_id: &challenge.transaction_id,
            device_csr: URL_SAFE_NO_PAD.encode(csr_der),
            human_public_key: URL_SAFE_NO_PAD.encode(human_public),
            next_recovery_public_key: URL_SAFE_NO_PAD.encode(next_recovery_public),
            human_signature: URL_SAFE_NO_PAD.encode(human.sign(&transcript).to_bytes()),
            next_recovery_signature: URL_SAFE_NO_PAD
                .encode(next_recovery.sign(&transcript).to_bytes()),
            current_recovery_signature: current_recovery
                .as_ref()
                .map(|key| URL_SAFE_NO_PAD.encode(key.sign(&transcript).to_bytes()))
                .unwrap_or_default(),
        };
        let completed: IdentityCompletionResponse = send_json(
            &temporary_client,
            "PUT",
            &format!("{}/v0/{}", input.temporary_origin, input.mode),
            None,
            &completion,
            TEMPORARY_RESPONSE_MAX_BYTES,
            &[StatusCode::OK],
        )
        .map_err(pairing_error)?;
        validate_identity_completion(&completed, &challenge)?;
        ensure_current(generation, current_generation)?;

        let private_key_pem = Zeroizing::new(device_key.serialize_pem());
        let main_client = controller_client(
            &input.server_ca_pem,
            Some((&completed.certificate_pem, private_key_pem.as_str())),
        )?;
        let human_seed = Zeroizing::new(URL_SAFE_NO_PAD.encode(human.to_bytes()));
        let mut association = AssociationRecord {
            summary: AssociationSummary {
                controller_id: input.controller_id.clone(),
                infrastructure_id: input.infrastructure_id.clone(),
                infrastructure_label: None,
                origin: input.origin.clone(),
                device_status: "candidate".to_owned(),
                certificate_expires_at: Some(completed.expires_at.clone()),
            },
            device_id: challenge.device_id.clone(),
            server_ca_pem: input.server_ca_pem.clone(),
            server_spki_sha256: input.server_spki_sha256.clone(),
            device_private_key_pem: private_key_pem.to_string(),
            device_certificate_pem: completed.certificate_pem.clone(),
            human_private_seed: human_seed.to_string(),
            identity_revision: 0,
            recovery_salt: challenge.next_recovery_salt.clone(),
            recovery_epoch: challenge.next_recovery_epoch,
            pending_mode: Some(input.mode.clone()),
            pending_transaction_id: Some(challenge.transaction_id.clone()),
            pending_device_private_key_pem: None,
            pending_device_certificate_pem: None,
            pending_certificate_expires_at: None,
        };
        persist_candidate(association.clone())?;
        let activation: IdentityActivationResponse = send_json(
            &main_client,
            "PUT",
            &format!(
                "{}/v0/{}/{}/activation",
                input.origin, input.mode, challenge.transaction_id
            ),
            None,
            &SchemaVersionOnly { schema_version: 1 },
            RESPONSE_MAX_BYTES,
            &[StatusCode::OK],
        )
        .map_err(pairing_error)?;
        validate_activation(&activation, &input, &challenge, &completed)?;
        ensure_current(generation, current_generation)?;
        association.summary.device_status = "active".to_owned();
        association.summary.certificate_expires_at = Some(activation.certificate_expires_at);
        association.identity_revision = activation.identity_revision;
        association.pending_mode = None;
        association.pending_transaction_id = None;
        Ok(association)
    }

    pub(crate) fn activate_pending(
        &mut self,
        mut association: AssociationRecord,
        generation: u64,
        current_generation: &AtomicU64,
    ) -> Result<AssociationRecord, NetworkError> {
        if association.summary.device_status != "candidate"
            && association.pending_mode.as_deref() != Some("rotation")
        {
            return Ok(association);
        }
        let mode = association
            .pending_mode
            .as_deref()
            .filter(|mode| *mode == "enrollment" || *mode == "recovery" || *mode == "rotation")
            .map(str::to_owned)
            .ok_or(NetworkError::ResponseRefused)?;
        let transaction = association
            .pending_transaction_id
            .as_deref()
            .filter(|value| canonical_raw_url(value, 16))
            .ok_or(NetworkError::ResponseRefused)?;
        let client = if mode == "rotation" {
            pending_association_client(&association)?
        } else {
            association_client(&association)?
        };
        ensure_current(generation, current_generation)?;
        let route = if mode == "rotation" {
            format!(
                "{}/v0/device-rotations/{transaction}/activation",
                association.summary.origin
            )
        } else {
            format!(
                "{}/v0/{mode}/{transaction}/activation",
                association.summary.origin
            )
        };
        let activation: IdentityActivationResponse = send_json(
            &client,
            "PUT",
            &route,
            None,
            &SchemaVersionOnly { schema_version: 1 },
            RESPONSE_MAX_BYTES,
            &[StatusCode::OK],
        )?;
        if activation.schema_version != 1
            || activation.controller_id != association.summary.controller_id
            || activation.infrastructure_id != association.summary.infrastructure_id
            || activation.device_id != association.device_id
            || activation.device_status != "active"
            || Some(activation.certificate_expires_at.as_str())
                != if mode == "rotation" {
                    association.pending_certificate_expires_at.as_deref()
                } else {
                    association.summary.certificate_expires_at.as_deref()
                }
            || activation.identity_revision == 0
        {
            return Err(NetworkError::ResponseRefused);
        }
        ensure_current(generation, current_generation)?;
        association.summary.device_status = "active".to_owned();
        if mode == "rotation" {
            association.device_private_key_pem = association
                .pending_device_private_key_pem
                .take()
                .ok_or(NetworkError::ResponseRefused)?;
            association.device_certificate_pem = association
                .pending_device_certificate_pem
                .take()
                .ok_or(NetworkError::ResponseRefused)?;
            association.summary.certificate_expires_at =
                association.pending_certificate_expires_at.take();
        }
        association.identity_revision = activation.identity_revision;
        association.pending_mode = None;
        association.pending_transaction_id = None;
        if mode == "rotation" {
            self.sessions.remove(&association.summary.infrastructure_id);
        }
        Ok(association)
    }

    pub(crate) fn read_infrastructure(
        &mut self,
        association: &AssociationRecord,
        generation: u64,
        current_generation: &AtomicU64,
    ) -> Result<InfrastructureView, NetworkError> {
        let client = association_client(association)?;
        let token = self.session(association, &client, generation, current_generation)?;
        let response = send_empty::<InfrastructureView>(
            &client,
            "GET",
            &format!("{}/v0/infrastructure", association.summary.origin),
            Some(token.as_str()),
            &[StatusCode::OK],
        );
        let view =
            self.handle_session_response(&association.summary.infrastructure_id, response)?;
        validate_infrastructure(&view, association)?;
        ensure_current(generation, current_generation)?;
        Ok(view)
    }

    pub(crate) fn read_machines(
        &mut self,
        association: &AssociationRecord,
        generation: u64,
        current_generation: &AtomicU64,
    ) -> Result<MachinesView, NetworkError> {
        let client = association_client(association)?;
        let token = self.session(association, &client, generation, current_generation)?;
        let response = send_empty::<MachinesView>(
            &client,
            "GET",
            &format!("{}/v0/machines", association.summary.origin),
            Some(token.as_str()),
            &[StatusCode::OK],
        );
        let view =
            self.handle_session_response(&association.summary.infrastructure_id, response)?;
        validate_machines(&view, association)?;
        ensure_current(generation, current_generation)?;
        Ok(view)
    }

    /// Reads the declared inventory beside the managed one, by the same session
    /// and the same bounded decode.
    ///
    /// It is a second read rather than a second field of `GET /v0/machines`:
    /// a declaration must not move the revision a Console caches its machines
    /// against, and the two inventories refuse each other in both directions.
    pub(crate) fn read_external_elements(
        &mut self,
        association: &AssociationRecord,
        generation: u64,
        current_generation: &AtomicU64,
    ) -> Result<ExternalElementsView, NetworkError> {
        let client = association_client(association)?;
        let token = self.session(association, &client, generation, current_generation)?;
        let response = send_empty::<ExternalElementsView>(
            &client,
            "GET",
            &format!("{}/v0/external-elements", association.summary.origin),
            Some(token.as_str()),
            &[StatusCode::OK],
        );
        let view =
            self.handle_session_response(&association.summary.infrastructure_id, response)?;
        validate_external_elements(&view, association)?;
        ensure_current(generation, current_generation)?;
        Ok(view)
    }

    pub(crate) fn put_infrastructure(
        &mut self,
        association: &AssociationRecord,
        label: &str,
        generation: u64,
        current_generation: &AtomicU64,
    ) -> Result<InfrastructureView, NetworkError> {
        let label = canonical_label(label)?;
        let client = association_client(association)?;
        let token = self.session(association, &client, generation, current_generation)?;
        let response = send_json::<InfrastructureView, _>(
            &client,
            "PUT",
            &format!("{}/v0/infrastructure", association.summary.origin),
            Some(token.as_str()),
            &InfrastructureMutationRequest {
                schema_version: 1,
                infrastructure_id: &association.summary.infrastructure_id,
                label: &label,
            },
            RESPONSE_MAX_BYTES,
            &[StatusCode::OK, StatusCode::CREATED],
        );
        let view =
            self.handle_session_response(&association.summary.infrastructure_id, response)?;
        validate_infrastructure(&view, association)?;
        if view.label.as_deref() != Some(label.as_str()) {
            return Err(NetworkError::ResponseRefused);
        }
        ensure_current(generation, current_generation)?;
        Ok(view)
    }

    pub(crate) fn put_machine(
        &mut self,
        association: &AssociationRecord,
        machine_id: &str,
        label: &str,
        generation: u64,
        current_generation: &AtomicU64,
    ) -> Result<MachineMutationView, NetworkError> {
        if !valid_machine_id(machine_id) {
            return Err(NetworkError::InvalidInput);
        }
        let label = canonical_label(label)?;
        let client = association_client(association)?;
        let token = self.session(association, &client, generation, current_generation)?;
        let response = send_json::<MachineMutationView, _>(
            &client,
            "PUT",
            &format!("{}/v0/machines/{machine_id}", association.summary.origin),
            Some(token.as_str()),
            &MachineMutationRequest {
                schema_version: 1,
                label: &label,
            },
            RESPONSE_MAX_BYTES,
            &[StatusCode::OK, StatusCode::CREATED],
        );
        let view =
            self.handle_session_response(&association.summary.infrastructure_id, response)?;
        if view.schema_version != 1
            || view.machine_id != machine_id
            || view.label != label
            || view.inventory_revision == 0
        {
            return Err(NetworkError::ResponseRefused);
        }
        ensure_current(generation, current_generation)?;
        Ok(view)
    }

    /// Withdraws one declaration, and nothing else.
    ///
    /// It is a POST on its own route and never a DELETE on the element: the
    /// product owns nothing here, so there is no resource of its own to delete.
    /// The sentence a human reads before confirming — the thing keeps existing —
    /// is written by this Console from the context of this route, because a
    /// Controller that could send a user-facing text could send a reassuring one.
    pub(crate) fn withdraw_external_element(
        &mut self,
        association: &AssociationRecord,
        element_id: &str,
        generation: u64,
        current_generation: &AtomicU64,
    ) -> Result<ExternalWithdrawalView, NetworkError> {
        if !canonical_raw_url(element_id, 16) {
            return Err(NetworkError::InvalidInput);
        }
        let client = association_client(association)?;
        let token = self.session(association, &client, generation, current_generation)?;
        let response = send_json::<ExternalWithdrawalView, _>(
            &client,
            "POST",
            &format!(
                "{}/v0/external-element-withdrawals",
                association.summary.origin
            ),
            Some(token.as_str()),
            &ExternalWithdrawalRequest {
                schema_version: 1,
                element_id,
            },
            RESPONSE_MAX_BYTES,
            &[StatusCode::OK],
        );
        let view =
            self.handle_session_response(&association.summary.infrastructure_id, response)?;
        if view.schema_version != 1 || view.element_id != element_id || view.external_revision == 0
        {
            return Err(NetworkError::ResponseRefused);
        }
        ensure_current(generation, current_generation)?;
        Ok(view)
    }

    /// Reads every definition this infrastructure has frozen.
    ///
    /// It is a third inventory beside the managed and the declared ones, read by
    /// the same session and refused by the same rules — and it is read on its own
    /// revision, because freezing a definition must not move the revision a
    /// Console caches its machines against.
    ///
    /// Every entry is rehashed here before it can be displayed. The Controller
    /// is not the authority on what a definition says: it stores bytes and a
    /// digest, and this Console holds the two against one another with the very
    /// function the Auxiliary uses the day a plan pins that digest.
    pub(crate) fn read_service_definitions(
        &mut self,
        association: &AssociationRecord,
        generation: u64,
        current_generation: &AtomicU64,
    ) -> Result<ServiceDefinitionsView, NetworkError> {
        let client = association_client(association)?;
        let token = self.session(association, &client, generation, current_generation)?;
        let response = send_empty::<ServiceDefinitionsView>(
            &client,
            "GET",
            &format!("{}/v0/service-definitions", association.summary.origin),
            Some(token.as_str()),
            &[StatusCode::OK],
        );
        let view =
            self.handle_session_response(&association.summary.infrastructure_id, response)?;
        validate_service_definitions(&view, association)?;
        ensure_current(generation, current_generation)?;
        Ok(view)
    }

    /// Asks the Controller for the frozen pair of one deployment, and reads it
    /// back as a pair rather than as a promise.
    ///
    /// The Console assembles no plan. It names a machine, a frozen revision and
    /// the three values a deployment really chooses, and what comes back is two
    /// documents and two digests the Controller froze. Nothing here trusts that
    /// escort: the verification that holds each document against its own digest
    /// belongs to `publication_plan`, and it runs on the caller's side of this
    /// function — this one only refuses a shape that is not a pair at all.
    pub(crate) fn build_user_service_plan(
        &mut self,
        association: &AssociationRecord,
        machine_id: &str,
        operation: &str,
        definition_slug: &str,
        definition_digest: &str,
        image_digest: &str,
        local_port: u16,
        origin_host: &str,
        generation: u64,
        current_generation: &AtomicU64,
    ) -> Result<PlanPairView, NetworkError> {
        let client = association_client(association)?;
        let token = self.session(association, &client, generation, current_generation)?;
        let response = send_json_within::<PlanPairView, _>(
            &client,
            "POST",
            &format!(
                "{}/v0/user-service-plans",
                association.summary.origin
            ),
            Some(token.as_str()),
            &UserServicePlanRequest {
                schema_version: 2,
                machine_id,
                operation,
                definition_slug,
                definition_digest,
                image_digest,
                local_port,
                origin_host,
            },
            DEFINITION_REQUEST_MAX_BYTES,
            RESPONSE_MAX_BYTES,
            &[StatusCode::OK],
        );
        let view =
            self.handle_session_response(&association.summary.infrastructure_id, response)?;
        // The one thing held here is that a pair arrived. What makes it *this*
        // pair — each document rendering the digest beside it, and the rollback
        // being the complete undoing of the plan — is held where the grammar
        // lives, and a caller that skipped it would have nothing to display.
        if view.plan_document.is_empty()
            || view.rollback_document.is_empty()
            || view.plan_sha256 == view.rollback_sha256
        {
            return Err(NetworkError::InvalidInput);
        }
        ensure_current(generation, current_generation)?;
        Ok(view)
    }

    /// Freezes one definition, and nothing else.
    ///
    /// Freezing is not signing. No envelope is built, no approval is minted and
    /// the native window of the assistant is not on this path: the definition is
    /// inert, so what travels is the ordinary authenticated request every other
    /// business route of this Console uses.
    ///
    /// The digest is not sent as an authority. It is this Console's own answer,
    /// computed by the mirror from the very bytes it sends, and the Controller
    /// refuses the submission when its own answer differs — the cross-check
    /// between the two implementations of one canonical encoding, done the
    /// moment a definition enters the product. What comes back is required to be
    /// the exact document that went out, under the exact digest that was
    /// displayed: a Controller that froze something else has frozen something
    /// nobody read.
    pub(crate) fn freeze_service_definition(
        &mut self,
        association: &AssociationRecord,
        document: &str,
        digest: &str,
        generation: u64,
        current_generation: &AtomicU64,
    ) -> Result<FrozenServiceDefinitionView, NetworkError> {
        // The bytes are held against their digest before they leave, by the
        // mirror rather than by a comparison written here: what is submitted is
        // a definition of the contract in its one canonical spelling, or nothing
        // is submitted at all.
        let parsed = displayable_definition(document, digest).ok_or(NetworkError::InvalidInput)?;
        let client = association_client(association)?;
        let token = self.session(association, &client, generation, current_generation)?;
        let response = send_json_within::<FrozenServiceDefinitionView, _>(
            &client,
            "POST",
            &format!("{}/v0/service-definitions", association.summary.origin),
            Some(token.as_str()),
            &ServiceDefinitionFreezeRequest {
                schema_version: 1,
                definition_document: document,
                definition_sha256: digest,
            },
            DEFINITION_REQUEST_MAX_BYTES,
            RESPONSE_MAX_BYTES,
            &[StatusCode::OK, StatusCode::CREATED],
        );
        let view =
            self.handle_session_response(&association.summary.infrastructure_id, response)?;
        if view.schema_version != 1
            || view.definition_revision == 0
            || view.definition.definition_document != document
            || view.definition.definition_sha256 != digest
            || view.definition.slug != parsed.slug
            || !canonical_timestamp(&view.definition.frozen_at)
        {
            return Err(NetworkError::ResponseRefused);
        }
        ensure_current(generation, current_generation)?;
        Ok(view)
    }

    pub(crate) fn rotate_device<F>(
        &mut self,
        mut association: AssociationRecord,
        generation: u64,
        current_generation: &AtomicU64,
        persist_candidate: F,
    ) -> Result<AssociationRecord, NetworkError>
    where
        F: FnOnce(AssociationRecord) -> Result<(), NetworkError>,
    {
        validate_persisted_association(&association)?;
        if association.summary.device_status != "active" || association.pending_mode.is_some() {
            return Err(NetworkError::InvalidInput);
        }
        let client = association_client(&association)?;
        let token = self.session(&association, &client, generation, current_generation)?;
        let rotation_id = random_raw_url(16);
        let device_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|_| NetworkError::ControllerUnavailable)?;
        let mut parameters = CertificateParams::default();
        parameters.distinguished_name = DistinguishedName::new();
        let uri = device_uri(
            &association.summary.infrastructure_id,
            &association.device_id,
        );
        parameters.subject_alt_names = vec![SanType::URI(
            Ia5String::try_from(uri).map_err(|_| NetworkError::ResponseRefused)?,
        )];
        let csr = parameters
            .serialize_request(&device_key)
            .map_err(|_| NetworkError::ControllerUnavailable)?;
        let csr_der = csr.der().as_ref();
        if csr_der.is_empty() || csr_der.len() > CSR_MAX_BYTES {
            return Err(NetworkError::ControllerUnavailable);
        }
        let core = DeviceRotationCore {
            schema_version: 1,
            rotation_id: &rotation_id,
            device_csr: URL_SAFE_NO_PAD.encode(csr_der),
        };
        let core_encoded =
            serde_json::to_vec(&core).map_err(|_| NetworkError::ControllerUnavailable)?;
        if core_encoded.is_empty() || core_encoded.len() > REQUEST_MAX_BYTES {
            return Err(NetworkError::InvalidInput);
        }
        let body_digest = Sha256::digest(&core_encoded);
        let challenge_request = SessionChallengeRequest {
            schema_version: 1,
            purpose: "rotate_device",
            target_method: "PUT",
            target_route: "/v0/device-rotations",
            body_sha256: URL_SAFE_NO_PAD.encode(body_digest),
        };
        let challenge: SessionChallengeResponse = send_json(
            &client,
            "POST",
            &format!("{}/v0/session/challenge", association.summary.origin),
            Some(token.as_str()),
            &challenge_request,
            RESPONSE_MAX_BYTES,
            &[StatusCode::OK],
        )?;
        validate_session_challenge(&challenge)?;
        ensure_current(generation, current_generation)?;
        let human = human_signing_key(&association)?;
        let transcript = session_transcript(
            &association,
            &challenge,
            &body_digest,
            "rotate_device",
            "PUT",
            "/v0/device-rotations",
        )?;
        let request = DeviceRotationRequest {
            schema_version: core.schema_version,
            rotation_id: core.rotation_id,
            device_csr: &core.device_csr,
            challenge_id: &challenge.challenge_id,
            human_signature: URL_SAFE_NO_PAD.encode(human.sign(&transcript).to_bytes()),
        };
        let completed: IdentityCompletionResponse = send_json(
            &client,
            "PUT",
            &format!(
                "{}/v0/device-rotations/{rotation_id}",
                association.summary.origin
            ),
            Some(token.as_str()),
            &request,
            RESPONSE_MAX_BYTES,
            &[StatusCode::OK, StatusCode::CREATED],
        )?;
        if completed.schema_version != 1
            || completed.transaction_id != rotation_id
            || completed.device_id != association.device_id
            || !canonical_timestamp(&completed.expires_at)
            || device_id_from_certificate(
                &completed.certificate_pem,
                &association.summary.infrastructure_id,
            )? != association.device_id
        {
            return Err(NetworkError::ResponseRefused);
        }
        ensure_current(generation, current_generation)?;
        association.pending_mode = Some("rotation".to_owned());
        association.pending_transaction_id = Some(rotation_id.clone());
        association.pending_device_private_key_pem = Some(device_key.serialize_pem());
        association.pending_device_certificate_pem = Some(completed.certificate_pem.clone());
        association.pending_certificate_expires_at = Some(completed.expires_at.clone());
        persist_candidate(association.clone())?;
        let candidate_client = pending_association_client(&association)?;
        let activation: IdentityActivationResponse = send_json(
            &candidate_client,
            "PUT",
            &format!(
                "{}/v0/device-rotations/{rotation_id}/activation",
                association.summary.origin
            ),
            None,
            &SchemaVersionOnly { schema_version: 1 },
            RESPONSE_MAX_BYTES,
            &[StatusCode::OK],
        )?;
        if activation.schema_version != 1
            || activation.controller_id != association.summary.controller_id
            || activation.infrastructure_id != association.summary.infrastructure_id
            || activation.device_id != association.device_id
            || activation.device_status != "active"
            || activation.certificate_expires_at != completed.expires_at
            || activation.identity_revision != association.identity_revision.saturating_add(1)
        {
            return Err(NetworkError::ResponseRefused);
        }
        ensure_current(generation, current_generation)?;
        association.device_private_key_pem = association
            .pending_device_private_key_pem
            .take()
            .ok_or(NetworkError::ConsoleUnavailable)?;
        association.device_certificate_pem = association
            .pending_device_certificate_pem
            .take()
            .ok_or(NetworkError::ConsoleUnavailable)?;
        association.summary.certificate_expires_at =
            association.pending_certificate_expires_at.take();
        association.identity_revision = activation.identity_revision;
        association.pending_mode = None;
        association.pending_transaction_id = None;
        self.sessions.remove(&association.summary.infrastructure_id);
        Ok(association)
    }

    pub(crate) fn rotate_recovery_key(
        &mut self,
        mut association: AssociationRecord,
        target: &RecoveryControllerProgress,
        old_recovery_code: &str,
        new_recovery_code: &str,
        generation: u64,
        current_generation: &AtomicU64,
    ) -> Result<AssociationRecord, NetworkError> {
        validate_persisted_association(&association)?;
        if association.summary.device_status != "active"
            || association.pending_mode.is_some()
            || association.summary.controller_id != target.controller_id
            || association.summary.infrastructure_id != target.infrastructure_id
            || !canonical_raw_url(&target.operation_id, 16)
            || association.recovery_epoch.checked_add(1) != Some(target.target_recovery_epoch)
        {
            return Err(NetworkError::InvalidInput);
        }
        let old_code =
            parse_recovery_code(old_recovery_code).map_err(|_| NetworkError::InvalidInput)?;
        let new_code =
            parse_recovery_code(new_recovery_code).map_err(|_| NetworkError::InvalidInput)?;
        if old_code.as_slice() == new_code.as_slice() {
            return Err(NetworkError::InvalidInput);
        }
        let infrastructure = Uuid::parse_str(&association.summary.infrastructure_id)
            .map_err(|_| NetworkError::ResponseRefused)?;
        let spki: [u8; 32] = hex::decode(&association.server_spki_sha256)
            .map_err(|_| NetworkError::ResponseRefused)?
            .try_into()
            .map_err(|_| NetworkError::ResponseRefused)?;
        let next_salt = recovery_rotation_salt(
            &new_code,
            &target.operation_id,
            &association.summary.controller_id,
            &association.summary.infrastructure_id,
        );
        let current_recovery = recovery_signing_key(
            &old_code,
            &association.recovery_salt,
            association.recovery_epoch,
            &infrastructure,
            &spki,
        )?;
        let current_recovery_public =
            URL_SAFE_NO_PAD.encode(current_recovery.verifying_key().as_bytes());
        let next_salt_encoded = URL_SAFE_NO_PAD.encode(next_salt);
        let next_recovery = recovery_signing_key(
            &new_code,
            &next_salt_encoded,
            target.target_recovery_epoch,
            &infrastructure,
            &spki,
        )?;
        let mutation = RecoveryKeyMutationRequest {
            schema_version: 1,
            operation_id: &target.operation_id,
            next_recovery_epoch: target.target_recovery_epoch,
            next_recovery_salt: &next_salt_encoded,
            next_recovery_public_key: URL_SAFE_NO_PAD
                .encode(next_recovery.verifying_key().as_bytes()),
        };
        let mutation_encoded =
            serde_json::to_vec(&mutation).map_err(|_| NetworkError::ControllerUnavailable)?;
        if mutation_encoded.is_empty() || mutation_encoded.len() > REQUEST_MAX_BYTES {
            return Err(NetworkError::InvalidInput);
        }
        let digest = Sha256::digest(&mutation_encoded);
        let client = association_client(&association)?;
        let token = self.session(&association, &client, generation, current_generation)?;
        let challenge: SessionChallengeResponse = send_json(
            &client,
            "POST",
            &format!("{}/v0/session/challenge", association.summary.origin),
            Some(token.as_str()),
            &SessionChallengeRequest {
                schema_version: 1,
                purpose: "rotate_recovery_key",
                target_method: "PUT",
                target_route: "/v0/recovery-key",
                body_sha256: URL_SAFE_NO_PAD.encode(digest),
            },
            RESPONSE_MAX_BYTES,
            &[StatusCode::OK],
        )?;
        validate_session_challenge(&challenge)?;
        ensure_current(generation, current_generation)?;
        let human = human_signing_key(&association)?;
        let human_transcript = session_transcript(
            &association,
            &challenge,
            &digest,
            "rotate_recovery_key",
            "PUT",
            "/v0/recovery-key",
        )?;
        let recovery_transcript =
            recovery_key_transcript(&association, &mutation, &current_recovery_public)?;
        let response: RecoveryKeyRotationResponse = send_json(
            &client,
            "PUT",
            &format!("{}/v0/recovery-key", association.summary.origin),
            Some(token.as_str()),
            &RecoveryKeyRotationRequest {
                schema_version: mutation.schema_version,
                operation_id: mutation.operation_id,
                next_recovery_epoch: mutation.next_recovery_epoch,
                next_recovery_salt: mutation.next_recovery_salt,
                next_recovery_public_key: &mutation.next_recovery_public_key,
                challenge_id: &challenge.challenge_id,
                human_signature: URL_SAFE_NO_PAD.encode(human.sign(&human_transcript).to_bytes()),
                current_recovery_signature: URL_SAFE_NO_PAD
                    .encode(current_recovery.sign(&recovery_transcript).to_bytes()),
                next_recovery_signature: URL_SAFE_NO_PAD
                    .encode(next_recovery.sign(&recovery_transcript).to_bytes()),
            },
            RESPONSE_MAX_BYTES,
            &[StatusCode::OK],
        )?;
        if response.schema_version != 1
            || response.operation_id != target.operation_id
            || response.recovery_epoch != target.target_recovery_epoch
            || response.identity_revision != association.identity_revision
        {
            return Err(NetworkError::ResponseRefused);
        }
        ensure_current(generation, current_generation)?;
        association.recovery_salt = next_salt_encoded;
        association.recovery_epoch = response.recovery_epoch;
        Ok(association)
    }

    pub(crate) fn logout(&mut self, association: &AssociationRecord) -> Result<(), NetworkError> {
        let Some(token) = self.sessions.remove(&association.summary.infrastructure_id) else {
            return Ok(());
        };
        let client = association_client(association)?;
        let response: LogoutResponse = send_empty(
            &client,
            "DELETE",
            &format!("{}/v0/session", association.summary.origin),
            Some(token.as_str()),
            &[StatusCode::OK],
        )?;
        if response.schema_version != 1 || response.status != "logged_out" {
            return Err(NetworkError::ResponseRefused);
        }
        Ok(())
    }

    fn session(
        &mut self,
        association: &AssociationRecord,
        client: &Client,
        generation: u64,
        current_generation: &AtomicU64,
    ) -> Result<Zeroizing<String>, NetworkError> {
        if let Some(current) = self.sessions.get(&association.summary.infrastructure_id) {
            return Ok(Zeroizing::new(current.to_string()));
        }
        ensure_current(generation, current_generation)?;
        let skeleton = br#"{"schema_version":1}"#;
        let body_digest = Sha256::digest(skeleton);
        let challenge_request = SessionChallengeRequest {
            schema_version: 1,
            purpose: "open_session",
            target_method: "POST",
            target_route: "/v0/session",
            body_sha256: URL_SAFE_NO_PAD.encode(body_digest),
        };
        let challenge: SessionChallengeResponse = send_json(
            client,
            "POST",
            &format!("{}/v0/session/challenge", association.summary.origin),
            None,
            &challenge_request,
            RESPONSE_MAX_BYTES,
            &[StatusCode::OK],
        )?;
        validate_session_challenge(&challenge)?;
        ensure_current(generation, current_generation)?;
        let human = human_signing_key(association)?;
        let transcript = session_transcript(
            association,
            &challenge,
            &body_digest,
            "open_session",
            "POST",
            "/v0/session",
        )?;
        let opened: SessionOpenResponse = send_json(
            client,
            "POST",
            &format!("{}/v0/session", association.summary.origin),
            None,
            &SessionOpenRequest {
                schema_version: 1,
                challenge_id: &challenge.challenge_id,
                signature: URL_SAFE_NO_PAD.encode(human.sign(&transcript).to_bytes()),
            },
            RESPONSE_MAX_BYTES,
            &[StatusCode::OK],
        )?;
        validate_session_open(&opened)?;
        ensure_current(generation, current_generation)?;
        let token = Zeroizing::new(opened.session_token);
        self.sessions.insert(
            association.summary.infrastructure_id.clone(),
            Zeroizing::new(token.to_string()),
        );
        Ok(token)
    }

    fn handle_session_response<T>(
        &mut self,
        infrastructure_id: &str,
        response: Result<T, NetworkError>,
    ) -> Result<T, NetworkError> {
        if matches!(response, Err(NetworkError::SessionExpired)) {
            self.sessions.remove(infrastructure_id);
        }
        response
    }
}

struct ValidatedPairing {
    infrastructure_uuid: Uuid,
    spki: [u8; 32],
    recovery_code: Zeroizing<Vec<u8>>,
}

impl ValidatedPairing {
    fn new(input: &PairingInput) -> Result<Self, NetworkError> {
        if input.mode != "enrollment" && input.mode != "recovery" {
            return Err(NetworkError::InvalidInput);
        }
        let controller =
            Uuid::parse_str(&input.controller_id).map_err(|_| NetworkError::InvalidInput)?;
        let infrastructure =
            Uuid::parse_str(&input.infrastructure_id).map_err(|_| NetworkError::InvalidInput)?;
        if controller.get_version_num() != 4
            || infrastructure.get_version_num() != 4
            || controller.to_string() != input.controller_id
            || infrastructure.to_string() != input.infrastructure_id
        {
            return Err(NetworkError::InvalidInput);
        }
        let host = controller_server_name(&input.infrastructure_id);
        validate_origin(&input.origin, &host, 9443)?;
        validate_origin(&input.temporary_origin, &host, 9444)?;
        if !canonical_raw_url(&input.window_id, 16)
            || !valid_window_code(&input.window_code)
            || input.server_ca_pem.is_empty()
            || input.server_ca_pem.len() > CA_MAX_BYTES
            || !input.server_ca_pem.is_ascii()
            || input.server_spki_sha256.len() != 64
            || !input
                .server_spki_sha256
                .bytes()
                .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
        {
            return Err(NetworkError::InvalidInput);
        }
        let spki_vec =
            hex::decode(&input.server_spki_sha256).map_err(|_| NetworkError::InvalidInput)?;
        let spki: [u8; 32] = spki_vec
            .try_into()
            .map_err(|_| NetworkError::InvalidInput)?;
        validate_ca_pin(&input.server_ca_pem, &spki)?;
        let recovery_code =
            parse_recovery_code(&input.recovery_code).map_err(|_| NetworkError::InvalidInput)?;
        Ok(Self {
            infrastructure_uuid: infrastructure,
            spki,
            recovery_code,
        })
    }
}

#[derive(Serialize)]
struct IdentityChallengeRequest<'a> {
    schema_version: u8,
    window_id: &'a str,
    window_code: &'a str,
    request_id: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityChallengeResponse {
    schema_version: u8,
    transaction_id: String,
    device_id: String,
    challenge: String,
    created_at: String,
    expires_at: String,
    next_recovery_salt: String,
    next_recovery_epoch: u64,
    #[serde(default)]
    current_recovery_salt: String,
    #[serde(default)]
    current_recovery_epoch: u64,
    #[serde(default)]
    current_recovery_public_key: String,
}

#[derive(Serialize)]
struct IdentityCompletionRequest<'a> {
    schema_version: u8,
    transaction_id: &'a str,
    device_csr: String,
    human_public_key: String,
    next_recovery_public_key: String,
    human_signature: String,
    next_recovery_signature: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    current_recovery_signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityCompletionResponse {
    schema_version: u8,
    transaction_id: String,
    device_id: String,
    certificate_pem: String,
    expires_at: String,
}

#[derive(Serialize)]
struct SchemaVersionOnly {
    schema_version: u8,
}

#[derive(Serialize)]
struct RecoveryKeyMutationRequest<'a> {
    schema_version: u8,
    operation_id: &'a str,
    next_recovery_epoch: u64,
    next_recovery_salt: &'a str,
    next_recovery_public_key: String,
}

#[derive(Serialize)]
struct RecoveryKeyRotationRequest<'a> {
    schema_version: u8,
    operation_id: &'a str,
    next_recovery_epoch: u64,
    next_recovery_salt: &'a str,
    next_recovery_public_key: &'a str,
    challenge_id: &'a str,
    human_signature: String,
    current_recovery_signature: String,
    next_recovery_signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryKeyRotationResponse {
    schema_version: u8,
    operation_id: String,
    recovery_epoch: u64,
    identity_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityActivationResponse {
    schema_version: u8,
    controller_id: String,
    infrastructure_id: String,
    device_id: String,
    device_status: String,
    certificate_expires_at: String,
    identity_revision: u64,
}

#[derive(Serialize)]
struct SessionChallengeRequest {
    schema_version: u8,
    purpose: &'static str,
    target_method: &'static str,
    target_route: &'static str,
    body_sha256: String,
}

#[derive(Serialize)]
struct InfrastructureMutationRequest<'a> {
    schema_version: u8,
    infrastructure_id: &'a str,
    label: &'a str,
}

#[derive(Serialize)]
struct MachineMutationRequest<'a> {
    schema_version: u8,
    label: &'a str,
}

// The withdrawal names the one declaration to withdraw and carries nothing
// else: no label, no machine, no port. A request that could restate the
// declaration could withdraw one thing while describing another.
#[derive(Serialize)]
struct ExternalWithdrawalRequest<'a> {
    schema_version: u8,
    element_id: &'a str,
}

#[derive(Serialize)]
struct DeviceRotationCore<'a> {
    schema_version: u8,
    rotation_id: &'a str,
    device_csr: String,
}

#[derive(Serialize)]
struct DeviceRotationRequest<'a> {
    schema_version: u8,
    rotation_id: &'a str,
    device_csr: &'a str,
    challenge_id: &'a str,
    human_signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionChallengeResponse {
    schema_version: u8,
    challenge_id: String,
    challenge: String,
    created_at: String,
    expires_at: String,
}

#[derive(Serialize)]
struct SessionOpenRequest<'a> {
    schema_version: u8,
    challenge_id: &'a str,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionOpenResponse {
    schema_version: u8,
    session_token: String,
    idle_expires_at: String,
    absolute_expires_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogoutResponse {
    schema_version: u8,
    status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InfrastructureView {
    pub schema_version: u8,
    pub controller_id: String,
    pub infrastructure_id: String,
    pub initialized: bool,
    pub label: Option<String>,
    pub inventory_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MachineMutationView {
    pub schema_version: u8,
    pub inventory_revision: u64,
    pub machine_id: String,
    pub label: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MachinesView {
    pub schema_version: u8,
    pub controller_id: String,
    pub infrastructure_id: String,
    pub inventory_revision: u64,
    pub relay_status: String,
    pub relay_snapshot_at: Option<String>,
    pub machines: Vec<MachineView>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MachineView {
    pub machine_id: String,
    pub label: String,
    pub enrollment_status: Option<String>,
    pub observation_status: Option<String>,
    pub observation: Option<MachineObservation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MachineObservation {
    pub profile: String,
    pub sequence: u64,
    pub observed_at: String,
    pub received_at: String,
    pub observed_time_warning: bool,
    pub continuity: String,
    pub gap_summary: Option<GapSummary>,
    pub health: HostHealth,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GapSummary {
    pub range_count: u64,
    pub dropped_count: u64,
    pub first_sequence: u64,
    pub last_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostHealth {
    pub uptime: UptimeHealth,
    pub memory: CapacityHealth,
    pub rootfs: CapacityHealth,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UptimeHealth {
    pub status: String,
    pub uptime_seconds: Option<u64>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapacityHealth {
    pub status: String,
    pub total_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub error: Option<String>,
}

/// The declared inventory as this Console reads it.
///
/// It carries no capability field, and `deny_unknown_fields` is what makes that
/// a property rather than a habit. The four things the product cannot do to an
/// external element — update it, restore it, delete it, guarantee its state —
/// are properties of what an external element is, identical for every line, and
/// this Console announces them from the context of the route. A Controller that
/// sent one would be offering a management action, so it is an unknown field,
/// and an unknown field refuses the whole view rather than one line of it.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExternalElementsView {
    pub schema_version: u8,
    pub controller_id: String,
    pub infrastructure_id: String,
    pub external_revision: u64,
    pub elements: Vec<ExternalElementView>,
}

/// One declaration, the last reading taken against it, and the age of that
/// reading, held as three separate facts.
///
/// `state` is the contract's vocabulary and never a fourth value in disguise;
/// `observation_status` is the independent ageing dimension, in the same three
/// words the managed machines already use, because two meanings of "old" on one
/// screen would leave the reader guessing which one a line is speaking.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExternalElementView {
    pub element_id: String,
    pub machine_id: String,
    pub label: String,
    pub kind: String,
    pub probe_port: u16,
    pub declared_at: String,
    pub state: String,
    pub reason: Option<String>,
    pub observed_at: Option<String>,
    pub observation_status: String,
}

/// What a withdrawal answers: which declaration is gone, and nothing more.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExternalWithdrawalView {
    pub schema_version: u8,
    pub external_revision: u64,
    pub element_id: String,
}

/// The frozen definitions, on their own revision.
///
/// Nothing here describes an effect, and `deny_unknown_fields` is what keeps
/// that a property rather than a habit: a Controller that added a machine, a
/// state, an instance or a date of deployment to this listing would be
/// describing something a definition is not, and the whole view is refused
/// rather than one field of it ignored.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceDefinitionsView {
    pub schema_version: u8,
    pub controller_id: String,
    pub infrastructure_id: String,
    pub definition_revision: u64,
    pub definitions: Vec<ServiceDefinitionEntryView>,
}

/// One frozen revision: the exact canonical bytes, the digest they hash to, the
/// slug they declare and the date this Controller minted.
///
/// `slug` is not a second truth beside the document — every reading holds it
/// against the slug the document itself declares — and it is carried because it
/// is what a listing groups and sorts on.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceDefinitionEntryView {
    pub slug: String,
    pub definition_document: String,
    pub definition_sha256: String,
    pub frozen_at: String,
}

/// What one freeze answers: the revision the inventory now holds, and the
/// definition exactly as a listing carries it.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrozenServiceDefinitionView {
    pub schema_version: u8,
    pub definition_revision: u64,
    pub definition: ServiceDefinitionEntryView,
}

/// Everything a Console may choose about a freeze, which is the document and its
/// digest and nothing else.
///
/// There is no field for a machine, an account, a host path, a port of a host,
/// an operation or a date: freezing touches no machine, so a request that could
/// name one would be a request whose refusal had to be written somewhere.
#[derive(Serialize)]
/// What the Console may choose about one deployment of a frozen revision, and
/// nothing else.
///
/// The account, the home, the volume paths, the environment and the names of
/// the secrets are absent on purpose: the revision decides them, the Controller
/// reads them out of it, and the Auxiliary re-reads them from the definition's
/// own bytes before touching the machine. What is here is what a human really
/// chooses for one deployment — which image revision, which local port, and
/// which public name the service answers as.
#[derive(Serialize)]
struct UserServicePlanRequest<'a> {
    schema_version: u8,
    machine_id: &'a str,
    operation: &'a str,
    definition_slug: &'a str,
    definition_digest: &'a str,
    image_digest: &'a str,
    local_port: u16,
    origin_host: &'a str,
}

struct ServiceDefinitionFreezeRequest<'a> {
    schema_version: u8,
    definition_document: &'a str,
    definition_sha256: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControllerProblem {
    schema_version: u8,
    error_code: String,
    request_id: String,
}

fn controller_client(ca_pem: &str, identity: Option<(&str, &str)>) -> Result<Client, NetworkError> {
    ensure_rustls_provider()?;
    let ca = reqwest::Certificate::from_pem(ca_pem.as_bytes())
        .map_err(|_| NetworkError::InvalidInput)?;
    let mut builder = Client::builder()
        .tls_backend_rustls()
        .tls_certs_only([ca])
        .min_tls_version(Version::TLS_1_3)
        .max_tls_version(Version::TLS_1_3)
        .https_only(true)
        .http1_only()
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10));
    if let Some((certificate, private_key)) = identity {
        let mut combined =
            Zeroizing::new(String::with_capacity(certificate.len() + private_key.len()));
        combined.push_str(certificate);
        combined.push_str(private_key);
        let identity = reqwest::Identity::from_pem(combined.as_bytes())
            .map_err(|_| NetworkError::ResponseRefused)?;
        builder = builder.identity(identity);
    }
    builder
        .build()
        .map_err(|_| NetworkError::ControllerUnavailable)
}

fn ensure_rustls_provider() -> Result<(), NetworkError> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|_| NetworkError::ControllerUnavailable)?;
    }
    Ok(())
}

fn association_client(association: &AssociationRecord) -> Result<Client, NetworkError> {
    validate_persisted_association(association)?;
    validate_ca_pin(
        &association.server_ca_pem,
        &decode_hex_32(&association.server_spki_sha256)?,
    )
    .map_err(|_| NetworkError::ResponseRefused)?;
    controller_client(
        &association.server_ca_pem,
        Some((
            &association.device_certificate_pem,
            &association.device_private_key_pem,
        )),
    )
}

fn pending_association_client(association: &AssociationRecord) -> Result<Client, NetworkError> {
    validate_persisted_association(association)?;
    if association.pending_mode.as_deref() != Some("rotation") {
        return Err(NetworkError::ResponseRefused);
    }
    let certificate = association
        .pending_device_certificate_pem
        .as_deref()
        .ok_or(NetworkError::ResponseRefused)?;
    let private_key = association
        .pending_device_private_key_pem
        .as_deref()
        .ok_or(NetworkError::ResponseRefused)?;
    controller_client(&association.server_ca_pem, Some((certificate, private_key)))
}

fn send_json<T: DeserializeOwned, B: Serialize>(
    client: &Client,
    method: &str,
    url: &str,
    token: Option<&str>,
    body: &B,
    maximum: usize,
    expected_statuses: &[StatusCode],
) -> Result<T, NetworkError> {
    send_json_within(
        client,
        method,
        url,
        token,
        body,
        REQUEST_MAX_BYTES,
        maximum,
        expected_statuses,
    )
}

/// The same send, with the request bound named by the caller.
///
/// It exists for the one route whose bound is not the common one, and the bound
/// stays an argument rather than becoming a wider default: every other request
/// of this Console keeps the four kilobytes it has, because one named document
/// is wider and requests in general are not.
#[allow(clippy::too_many_arguments)]
fn send_json_within<T: DeserializeOwned, B: Serialize>(
    client: &Client,
    method: &str,
    url: &str,
    token: Option<&str>,
    body: &B,
    request_maximum: usize,
    maximum: usize,
    expected_statuses: &[StatusCode],
) -> Result<T, NetworkError> {
    let encoded = serde_json::to_vec(body).map_err(|_| NetworkError::ControllerUnavailable)?;
    if encoded.is_empty() || encoded.len() > request_maximum {
        return Err(NetworkError::InvalidInput);
    }
    let method =
        reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| NetworkError::InvalidInput)?;
    let mut request = client
        .request(method, url)
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/json")
        .body(encoded);
    if let Some(token) = token {
        request = request.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = request
        .send()
        .map_err(|_| NetworkError::ControllerUnavailable)?;
    decode_response(response, maximum, expected_statuses)
}

fn send_empty<T: DeserializeOwned>(
    client: &Client,
    method: &str,
    url: &str,
    token: Option<&str>,
    expected_statuses: &[StatusCode],
) -> Result<T, NetworkError> {
    let method =
        reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| NetworkError::InvalidInput)?;
    let mut request = client
        .request(method, url)
        .header(ACCEPT, "application/json");
    if let Some(token) = token {
        request = request.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = request
        .send()
        .map_err(|_| NetworkError::ControllerUnavailable)?;
    decode_response(response, RESPONSE_MAX_BYTES, expected_statuses)
}

fn decode_response<T: DeserializeOwned>(
    mut response: Response,
    success_maximum: usize,
    expected_statuses: &[StatusCode],
) -> Result<T, NetworkError> {
    let status = response.status();
    let maximum = if expected_statuses.contains(&status) {
        success_maximum
    } else {
        ERROR_MAX_BYTES
    };
    if response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/json")
        || response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            != Some("no-store")
        || response.headers().contains_key(TRANSFER_ENCODING)
    {
        return Err(NetworkError::ResponseRefused);
    }
    let declared = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|length| *length > 0 && *length <= maximum)
        .ok_or(NetworkError::ResponseRefused)?;
    let mut bytes = Vec::with_capacity(declared);
    response
        .by_ref()
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| NetworkError::ControllerUnavailable)?;
    if bytes.len() != declared || bytes.len() > maximum {
        return Err(NetworkError::ResponseRefused);
    }
    if expected_statuses.contains(&status) {
        return serde_json::from_slice(&bytes).map_err(|_| NetworkError::ResponseRefused);
    }
    let problem: ControllerProblem =
        serde_json::from_slice(&bytes).map_err(|_| NetworkError::ResponseRefused)?;
    if problem.schema_version != 1
        || !canonical_raw_url(&problem.request_id, 16)
        || !known_problem(status, &problem.error_code)
    {
        return Err(NetworkError::ResponseRefused);
    }
    if status == StatusCode::UNAUTHORIZED {
        Err(NetworkError::SessionExpired)
    } else {
        Err(NetworkError::ControllerUnavailable)
    }
}

fn pairing_error(error: NetworkError) -> NetworkError {
    match error {
        NetworkError::InvalidInput
        | NetworkError::ResponseRefused
        | NetworkError::Cancelled
        | NetworkError::ConsoleUnavailable => error,
        _ => NetworkError::AssociationFailed,
    }
}

fn known_problem(status: StatusCode, code: &str) -> bool {
    matches!(
        (status.as_u16(), code),
        (400, "invalid_request")
            | (401, "authentication_failed")
            | (403, "scope_forbidden")
            | (404, "route_not_found")
            // A withdrawal aimed at a declaration nobody made is answered from
            // the same closed list the business surface already publishes: this
            // palier adds three routes and no error code.
            | (404, "resource_not_found")
            | (405, "method_not_allowed")
            | (406, "not_acceptable")
            | (409, "state_conflict")
            | (413, "request_too_large")
            | (415, "unsupported_media_type")
            | (422, "label_invalid")
            | (422, "machine_not_active")
            | (429, "rate_limited")
            | (503, "relay_unavailable")
            | (503, "projection_unavailable")
            | (503, "controller_state_unavailable")
    )
}

fn validate_identity_challenge(
    response: &IdentityChallengeResponse,
    input: &PairingInput,
) -> Result<(), NetworkError> {
    let device = Uuid::parse_str(&response.device_id).map_err(|_| NetworkError::ResponseRefused)?;
    if response.schema_version != 1
        || !canonical_raw_url(&response.transaction_id, 16)
        || device.get_version_num() != 4
        || device.to_string() != response.device_id
        || !canonical_raw_url(&response.challenge, 32)
        || !canonical_timestamp(&response.created_at)
        || !canonical_timestamp(&response.expires_at)
        || !canonical_raw_url(&response.next_recovery_salt, 32)
        || response.next_recovery_epoch == 0
    {
        return Err(NetworkError::ResponseRefused);
    }
    if input.mode == "enrollment" {
        if response.next_recovery_epoch != 1
            || !response.current_recovery_salt.is_empty()
            || response.current_recovery_epoch != 0
            || !response.current_recovery_public_key.is_empty()
        {
            return Err(NetworkError::ResponseRefused);
        }
    } else if !canonical_raw_url(&response.current_recovery_salt, 32)
        || !canonical_raw_url(&response.current_recovery_public_key, 32)
        || response.current_recovery_epoch == 0
        || response.current_recovery_epoch.checked_add(1) != Some(response.next_recovery_epoch)
    {
        return Err(NetworkError::ResponseRefused);
    }
    let created = parse_timestamp(&response.created_at).ok_or(NetworkError::ResponseRefused)?;
    let expires = parse_timestamp(&response.expires_at).ok_or(NetworkError::ResponseRefused)?;
    if expires <= created || expires - created > time::Duration::minutes(2) {
        return Err(NetworkError::ResponseRefused);
    }
    Ok(())
}

fn validate_identity_completion(
    response: &IdentityCompletionResponse,
    challenge: &IdentityChallengeResponse,
) -> Result<(), NetworkError> {
    if response.schema_version != 1
        || response.transaction_id != challenge.transaction_id
        || response.device_id != challenge.device_id
        || response.certificate_pem.is_empty()
        || response.certificate_pem.len() > 8 * 1024
        || !canonical_timestamp(&response.expires_at)
        || pem_certificate_der(&response.certificate_pem).is_err()
    {
        return Err(NetworkError::ResponseRefused);
    }
    Ok(())
}

fn validate_activation(
    response: &IdentityActivationResponse,
    input: &PairingInput,
    challenge: &IdentityChallengeResponse,
    completion: &IdentityCompletionResponse,
) -> Result<(), NetworkError> {
    if response.schema_version != 1
        || response.controller_id != input.controller_id
        || response.infrastructure_id != input.infrastructure_id
        || response.device_id != challenge.device_id
        || response.device_status != "active"
        || response.certificate_expires_at != completion.expires_at
        || response.identity_revision == 0
    {
        return Err(NetworkError::ResponseRefused);
    }
    Ok(())
}

fn validate_session_challenge(response: &SessionChallengeResponse) -> Result<(), NetworkError> {
    if response.schema_version != 1
        || !canonical_raw_url(&response.challenge_id, 16)
        || !canonical_raw_url(&response.challenge, 32)
        || !canonical_timestamp(&response.created_at)
        || !canonical_timestamp(&response.expires_at)
    {
        return Err(NetworkError::ResponseRefused);
    }
    Ok(())
}

fn validate_session_open(response: &SessionOpenResponse) -> Result<(), NetworkError> {
    if response.schema_version != 1
        || !canonical_raw_url(&response.session_token, 32)
        || !canonical_timestamp(&response.idle_expires_at)
        || !canonical_timestamp(&response.absolute_expires_at)
    {
        return Err(NetworkError::ResponseRefused);
    }
    Ok(())
}

fn validate_infrastructure(
    view: &InfrastructureView,
    association: &AssociationRecord,
) -> Result<(), NetworkError> {
    if view.schema_version != 1
        || view.controller_id != association.summary.controller_id
        || view.infrastructure_id != association.summary.infrastructure_id
        || view.initialized != view.label.is_some()
        || view.label.as_ref().is_some_and(|label| !valid_label(label))
    {
        return Err(NetworkError::ResponseRefused);
    }
    Ok(())
}

fn validate_persisted_association(association: &AssociationRecord) -> Result<(), NetworkError> {
    let controller = Uuid::parse_str(&association.summary.controller_id)
        .map_err(|_| NetworkError::ResponseRefused)?;
    let infrastructure = Uuid::parse_str(&association.summary.infrastructure_id)
        .map_err(|_| NetworkError::ResponseRefused)?;
    let device =
        Uuid::parse_str(&association.device_id).map_err(|_| NetworkError::ResponseRefused)?;
    if controller.get_version_num() != 4
        || controller.to_string() != association.summary.controller_id
        || infrastructure.get_version_num() != 4
        || infrastructure.to_string() != association.summary.infrastructure_id
        || device.get_version_num() != 4
        || device.to_string() != association.device_id
        || !matches!(
            association.summary.device_status.as_str(),
            "candidate" | "active" | "revoked"
        )
        || association
            .summary
            .certificate_expires_at
            .as_ref()
            .is_none_or(|value| !canonical_timestamp(value))
    {
        return Err(NetworkError::ResponseRefused);
    }
    let host = controller_server_name(&association.summary.infrastructure_id);
    validate_origin(&association.summary.origin, &host, 9443)
        .map_err(|_| NetworkError::ResponseRefused)?;
    let certificate_device = device_id_from_certificate(
        &association.device_certificate_pem,
        &association.summary.infrastructure_id,
    )?;
    if certificate_device != association.device_id
        || !canonical_raw_url(&association.human_private_seed, 32)
        || !canonical_raw_url(&association.recovery_salt, 32)
        || association.recovery_epoch == 0
    {
        return Err(NetworkError::ResponseRefused);
    }
    if association.pending_mode.as_deref() == Some("rotation") {
        let pending_certificate = association
            .pending_device_certificate_pem
            .as_deref()
            .ok_or(NetworkError::ResponseRefused)?;
        if device_id_from_certificate(pending_certificate, &association.summary.infrastructure_id)?
            != association.device_id
            || association
                .pending_certificate_expires_at
                .as_deref()
                .is_none_or(|value| !canonical_timestamp(value))
        {
            return Err(NetworkError::ResponseRefused);
        }
    }
    Ok(())
}

fn validate_machines(
    view: &MachinesView,
    association: &AssociationRecord,
) -> Result<(), NetworkError> {
    if view.schema_version != 1
        || view.controller_id != association.summary.controller_id
        || view.infrastructure_id != association.summary.infrastructure_id
        || !matches!(
            view.relay_status.as_str(),
            "available" | "unavailable" | "clock_untrusted"
        )
        || view.machines.len() > 64
        || view
            .relay_snapshot_at
            .as_ref()
            .is_some_and(|value| !canonical_timestamp(value))
    {
        return Err(NetworkError::ResponseRefused);
    }
    let mut previous = "";
    for machine in &view.machines {
        if !valid_machine_id(&machine.machine_id)
            || machine.machine_id.as_str() <= previous
            || !valid_label(&machine.label)
            || !matches!(
                machine.enrollment_status.as_deref(),
                None | Some("active") | Some("revoked")
            )
            || !matches!(
                machine.observation_status.as_deref(),
                None | Some("absent") | Some("recent") | Some("old") | Some("untrusted")
            )
        {
            return Err(NetworkError::ResponseRefused);
        }
        if let Some(observation) = &machine.observation {
            validate_observation(observation)?;
        }
        previous = &machine.machine_id;
    }
    Ok(())
}

fn validate_observation(observation: &MachineObservation) -> Result<(), NetworkError> {
    if observation.profile != "host-health.v1"
        || observation.sequence == 0
        || !canonical_timestamp(&observation.observed_at)
        || !canonical_timestamp(&observation.received_at)
        || !matches!(observation.continuity.as_str(), "complete" | "gapped")
        || observation.continuity == "complete" && observation.gap_summary.is_some()
        || observation.continuity == "gapped" && observation.gap_summary.is_none()
        || !valid_uptime(&observation.health.uptime)
        || !valid_capacity(&observation.health.memory)
        || !valid_capacity(&observation.health.rootfs)
    {
        return Err(NetworkError::ResponseRefused);
    }
    if let Some(gap) = &observation.gap_summary {
        if gap.range_count == 0
            || gap.dropped_count == 0
            || gap.first_sequence == 0
            || gap.first_sequence > gap.last_sequence
        {
            return Err(NetworkError::ResponseRefused);
        }
    }
    Ok(())
}

/// Holds the declared inventory to the exact shape the contract projects.
///
/// The list is bounded, the pair that must be unique is checked as an order —
/// a machine and a probe port, strictly increasing — and every line is held to
/// the closed vocabulary of the contract. Nothing here is rendered leniently: a
/// projection this Console cannot read entirely is a projection it refuses
/// entirely, because a Console that dropped the one line it could not parse
/// would show a shorter inventory than the human declared.
fn validate_external_elements(
    view: &ExternalElementsView,
    association: &AssociationRecord,
) -> Result<(), NetworkError> {
    if view.schema_version != 1
        || view.controller_id != association.summary.controller_id
        || view.infrastructure_id != association.summary.infrastructure_id
        || view.elements.len() > MAX_EXTERNAL_ELEMENTS
    {
        return Err(NetworkError::ResponseRefused);
    }
    let mut identifiers = HashSet::with_capacity(view.elements.len());
    let mut previous: Option<(&str, u16)> = None;
    for element in &view.elements {
        validate_external_element(element)?;
        if !identifiers.insert(element.element_id.as_str()) {
            return Err(NetworkError::ResponseRefused);
        }
        let key = (element.machine_id.as_str(), element.probe_port);
        if previous.is_some_and(|earlier| earlier >= key) {
            return Err(NetworkError::ResponseRefused);
        }
        previous = Some(key);
    }
    Ok(())
}

/// Holds the frozen definitions to the exact shape the contract projects, and
/// holds every document to its own digest.
///
/// The rehash is the point of this function. A definition is the one document a
/// plan pins by its digest, so a Controller that served altered bytes under a
/// frozen digest would be showing a human one revision and handing an Auxiliary
/// another. The check is the mirror's own, and it is applied to every entry: a
/// listing this Console cannot verify entirely is a listing it refuses entirely,
/// because dropping the one revision that failed would show a human a definition
/// they never froze — or hide one they did.
///
/// The slug is held against the document rather than trusted beside it, for the
/// same reason: it is a key of the listing and never a second truth.
fn validate_service_definitions(
    view: &ServiceDefinitionsView,
    association: &AssociationRecord,
) -> Result<(), NetworkError> {
    if view.schema_version != 1
        || view.controller_id != association.summary.controller_id
        || view.infrastructure_id != association.summary.infrastructure_id
        || view.definitions.len() > MAX_FROZEN_SERVICE_DEFINITIONS
    {
        return Err(NetworkError::ResponseRefused);
    }
    let mut digests = HashSet::with_capacity(view.definitions.len());
    for entry in &view.definitions {
        let parsed = displayable_definition(&entry.definition_document, &entry.definition_sha256)
            .ok_or(NetworkError::ResponseRefused)?;
        if parsed.slug != entry.slug || !canonical_timestamp(&entry.frozen_at) {
            return Err(NetworkError::ResponseRefused);
        }
        // A revision is its digest. The same digest twice would be one revision
        // presented as two, and a human counting revisions would be counting a
        // repetition of the Controller's own state file.
        if !digests.insert(entry.definition_sha256.as_str()) {
            return Err(NetworkError::ResponseRefused);
        }
    }
    Ok(())
}

/// One line of the declared inventory.
///
/// A state or a reason this Console does not know is a refusal and never a
/// fallback rendering: the vocabulary is what the human reads, so a Controller
/// that invented a word would otherwise be choosing what an element looks like.
/// The dated constat and its age travel together for the same reason — a state
/// without its date could be presented as current forever.
fn validate_external_element(element: &ExternalElementView) -> Result<(), NetworkError> {
    if !canonical_raw_url(&element.element_id, 16)
        || !valid_machine_id(&element.machine_id)
        || !valid_external_label(&element.label)
        || !matches!(
            element.kind.as_str(),
            "external_service" | "external_passage"
        )
        || element.probe_port == 0
        || !canonical_timestamp(&element.declared_at)
    {
        return Err(NetworkError::ResponseRefused);
    }
    if !matches!(
        (element.state.as_str(), element.reason.as_deref()),
        ("declared" | "verified" | "contradicted", None)
            | (
                "unverifiable",
                Some(
                    "nothing_listening"
                        | "response_too_large"
                        | "machine_unreachable"
                        | "port_is_managed"
                )
            )
    ) {
        return Err(NetworkError::ResponseRefused);
    }
    // `declared` is the state of an element nobody has read: it carries no date
    // and no age, and a Controller that dated it would be dating a reading that
    // never happened. Every other state carries both.
    let read = element.state != "declared";
    if read != element.observed_at.is_some()
        || element
            .observed_at
            .as_deref()
            .is_some_and(|observed_at| !canonical_timestamp(observed_at))
        || !matches!(
            (read, element.observation_status.as_str()),
            (false, "absent") | (true, "recent") | (true, "old")
        )
    {
        return Err(NetworkError::ResponseRefused);
    }
    Ok(())
}

fn valid_uptime(value: &UptimeHealth) -> bool {
    match value.status.as_str() {
        "ok" => value.uptime_seconds.is_some() && value.error.is_none(),
        "error" => {
            value.uptime_seconds.is_none()
                && matches!(
                    value.error.as_deref(),
                    Some("source_unavailable") | Some("source_invalid")
                )
        }
        _ => false,
    }
}

fn valid_capacity(value: &CapacityHealth) -> bool {
    match value.status.as_str() {
        "ok" => {
            value.total_bytes.is_some()
                && value.available_bytes.is_some()
                && value.available_bytes <= value.total_bytes
                && value.error.is_none()
        }
        "error" => {
            value.total_bytes.is_none()
                && value.available_bytes.is_none()
                && matches!(
                    value.error.as_deref(),
                    Some("source_unavailable") | Some("source_invalid")
                )
        }
        _ => false,
    }
}

fn recovery_signing_key(
    code: &[u8],
    salt: &str,
    epoch: u64,
    infrastructure_id: &Uuid,
    spki: &[u8; 32],
) -> Result<SigningKey, NetworkError> {
    let salt = decode_raw_url_32(salt)?;
    let mut info = Vec::with_capacity(RECOVERY_DOMAIN.len() + 1 + 8 + 16 + 32);
    info.extend_from_slice(RECOVERY_DOMAIN);
    info.push(0);
    info.extend_from_slice(&epoch.to_be_bytes());
    info.extend_from_slice(infrastructure_id.as_bytes());
    info.extend_from_slice(spki);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), code);
    let mut seed = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, seed.as_mut())
        .map_err(|_| NetworkError::ControllerUnavailable)?;
    info.zeroize();
    Ok(SigningKey::from_bytes(&seed))
}

fn recovery_rotation_salt(
    new_code: &[u8],
    operation_id: &str,
    controller_id: &str,
    infrastructure_id: &str,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(RECOVERY_ROTATION_SALT_DOMAIN);
    digest.update(new_code);
    digest.update(operation_id.as_bytes());
    digest.update(controller_id.as_bytes());
    digest.update(infrastructure_id.as_bytes());
    digest.finalize().into()
}

fn recovery_key_transcript(
    association: &AssociationRecord,
    mutation: &RecoveryKeyMutationRequest<'_>,
    current_recovery_public: &str,
) -> Result<Zeroizing<Vec<u8>>, NetworkError> {
    let certificate = pem_certificate_der(&association.device_certificate_pem)?;
    let fingerprint = hex::encode(Sha256::digest(&certificate));
    let mut transcript = Zeroizing::new(Vec::with_capacity(768));
    transcript.extend_from_slice(RECOVERY_KEY_TRANSCRIPT_DOMAIN);
    append_field(&mut transcript, mutation.operation_id.as_bytes())?;
    append_field(
        &mut transcript,
        association.summary.controller_id.as_bytes(),
    )?;
    append_field(
        &mut transcript,
        association.summary.infrastructure_id.as_bytes(),
    )?;
    append_field(&mut transcript, association.device_id.as_bytes())?;
    append_field(&mut transcript, fingerprint.as_bytes())?;
    append_field(&mut transcript, association.recovery_salt.as_bytes())?;
    transcript.extend_from_slice(&association.recovery_epoch.to_be_bytes());
    append_field(&mut transcript, current_recovery_public.as_bytes())?;
    append_field(&mut transcript, mutation.next_recovery_salt.as_bytes())?;
    transcript.extend_from_slice(&mutation.next_recovery_epoch.to_be_bytes());
    append_field(
        &mut transcript,
        mutation.next_recovery_public_key.as_bytes(),
    )?;
    Ok(transcript)
}

fn identity_transcript(
    input: &PairingInput,
    challenge: &IdentityChallengeResponse,
    request_id: &str,
    csr_der: &[u8],
    human_public: &[u8; 32],
    next_recovery_public: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, NetworkError> {
    let challenge_bytes = decode_raw_url_32(&challenge.challenge)?;
    let current_salt = if input.mode == "recovery" {
        decode_raw_url_32(&challenge.current_recovery_salt)?.to_vec()
    } else {
        Vec::new()
    };
    let current_public = if input.mode == "recovery" {
        decode_raw_url_32(&challenge.current_recovery_public_key)?.to_vec()
    } else {
        Vec::new()
    };
    let next_salt = decode_raw_url_32(&challenge.next_recovery_salt)?;
    let mut transcript = Zeroizing::new(Vec::with_capacity(1024));
    transcript.extend_from_slice(IDENTITY_TRANSCRIPT_DOMAIN);
    append_field(&mut transcript, input.mode.as_bytes())?;
    append_field(&mut transcript, input.temporary_origin.as_bytes())?;
    append_field(
        &mut transcript,
        format!("PUT /v0/{}", input.mode).as_bytes(),
    )?;
    append_field(&mut transcript, input.window_id.as_bytes())?;
    append_field(&mut transcript, request_id.as_bytes())?;
    append_field(&mut transcript, challenge.transaction_id.as_bytes())?;
    append_field(&mut transcript, input.controller_id.as_bytes())?;
    append_field(&mut transcript, input.infrastructure_id.as_bytes())?;
    append_field(&mut transcript, challenge.device_id.as_bytes())?;
    append_field(&mut transcript, &challenge_bytes)?;
    append_field(&mut transcript, challenge.created_at.as_bytes())?;
    append_field(&mut transcript, challenge.expires_at.as_bytes())?;
    append_field(&mut transcript, &current_salt)?;
    transcript.extend_from_slice(&challenge.current_recovery_epoch.to_be_bytes());
    append_field(&mut transcript, &next_salt)?;
    transcript.extend_from_slice(&challenge.next_recovery_epoch.to_be_bytes());
    append_field(&mut transcript, &Sha256::digest(csr_der))?;
    append_field(&mut transcript, human_public)?;
    append_field(&mut transcript, &current_public)?;
    append_field(&mut transcript, next_recovery_public)?;
    Ok(transcript)
}

fn session_transcript(
    association: &AssociationRecord,
    challenge: &SessionChallengeResponse,
    body_digest: &[u8],
    purpose: &str,
    target_method: &str,
    target_route: &str,
) -> Result<Zeroizing<Vec<u8>>, NetworkError> {
    let challenge_value = decode_raw_url_32(&challenge.challenge)?;
    let certificate = pem_certificate_der(&association.device_certificate_pem)?;
    let fingerprint = hex::encode(Sha256::digest(&certificate));
    let human = human_signing_key(association)?;
    let human_public = URL_SAFE_NO_PAD.encode(human.verifying_key().as_bytes());
    let mut transcript = Zeroizing::new(Vec::with_capacity(768));
    transcript.extend_from_slice(HUMAN_SESSION_DOMAIN);
    append_field(&mut transcript, purpose.as_bytes())?;
    append_field(&mut transcript, target_method.as_bytes())?;
    append_field(&mut transcript, target_route.as_bytes())?;
    append_field(&mut transcript, body_digest)?;
    append_field(
        &mut transcript,
        association.summary.controller_id.as_bytes(),
    )?;
    append_field(
        &mut transcript,
        association.summary.infrastructure_id.as_bytes(),
    )?;
    append_field(
        &mut transcript,
        device_id_from_certificate(
            &association.device_certificate_pem,
            &association.summary.infrastructure_id,
        )?
        .as_bytes(),
    )?;
    append_field(&mut transcript, fingerprint.as_bytes())?;
    append_field(&mut transcript, human_public.as_bytes())?;
    append_field(&mut transcript, challenge.challenge_id.as_bytes())?;
    append_field(&mut transcript, &challenge_value)?;
    append_field(&mut transcript, challenge.created_at.as_bytes())?;
    append_field(&mut transcript, challenge.expires_at.as_bytes())?;
    transcript.extend_from_slice(&association.identity_revision.to_be_bytes());
    Ok(transcript)
}

fn append_field(buffer: &mut Vec<u8>, value: &[u8]) -> Result<(), NetworkError> {
    let length = u32::try_from(value.len()).map_err(|_| NetworkError::ResponseRefused)?;
    buffer.extend_from_slice(&length.to_be_bytes());
    buffer.extend_from_slice(value);
    Ok(())
}

/// The human key of one association, opened from the seed the unlocked vault
/// holds. It stays crate-private: the approval module of the same crate is the
/// only other caller, and no command surface reaches either of them.
pub(crate) fn human_signing_key(
    association: &AssociationRecord,
) -> Result<SigningKey, NetworkError> {
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(association.human_private_seed.as_bytes())
            .map_err(|_| NetworkError::ResponseRefused)?,
    );
    let bytes = Zeroizing::new(
        decoded
            .as_slice()
            .try_into()
            .map_err(|_| NetworkError::ResponseRefused)?,
    );
    Ok(SigningKey::from_bytes(&bytes))
}

fn validate_ca_pin(pem: &str, expected: &[u8; 32]) -> Result<(), NetworkError> {
    let (remainder, block) =
        parse_x509_pem(pem.as_bytes()).map_err(|_| NetworkError::InvalidInput)?;
    if !remainder.iter().all(u8::is_ascii_whitespace) || block.label != "CERTIFICATE" {
        return Err(NetworkError::InvalidInput);
    }
    let (certificate_remainder, certificate) =
        parse_x509_certificate(&block.contents).map_err(|_| NetworkError::InvalidInput)?;
    if !certificate_remainder.is_empty()
        || Sha256::digest(certificate.public_key().raw).as_slice() != expected
    {
        return Err(NetworkError::InvalidInput);
    }
    Ok(())
}

fn pem_certificate_der(pem: &str) -> Result<Vec<u8>, NetworkError> {
    let (remainder, block) =
        parse_x509_pem(pem.as_bytes()).map_err(|_| NetworkError::ResponseRefused)?;
    if !remainder.iter().all(u8::is_ascii_whitespace) || block.label != "CERTIFICATE" {
        return Err(NetworkError::ResponseRefused);
    }
    let (certificate_remainder, _) =
        parse_x509_certificate(&block.contents).map_err(|_| NetworkError::ResponseRefused)?;
    if !certificate_remainder.is_empty() {
        return Err(NetworkError::ResponseRefused);
    }
    Ok(block.contents)
}

fn device_id_from_certificate(pem: &str, infrastructure_id: &str) -> Result<String, NetworkError> {
    let der = pem_certificate_der(pem)?;
    let (_, certificate) =
        parse_x509_certificate(&der).map_err(|_| NetworkError::ResponseRefused)?;
    let san = certificate
        .subject_alternative_name()
        .map_err(|_| NetworkError::ResponseRefused)?
        .ok_or(NetworkError::ResponseRefused)?;
    if san.value.general_names.len() != 1 {
        return Err(NetworkError::ResponseRefused);
    }
    let GeneralName::URI(rendered) = &san.value.general_names[0] else {
        return Err(NetworkError::ResponseRefused);
    };
    let prefix = format!("urn:your-cloud:device:v1:{infrastructure_id}:");
    let device = rendered
        .strip_prefix(&prefix)
        .ok_or(NetworkError::ResponseRefused)?;
    let parsed = Uuid::parse_str(device).map_err(|_| NetworkError::ResponseRefused)?;
    if parsed.get_version_num() != 4 || parsed.to_string() != device {
        return Err(NetworkError::ResponseRefused);
    }
    Ok(device.to_owned())
}

fn validate_origin(raw: &str, expected_host: &str, expected_port: u16) -> Result<(), NetworkError> {
    let parsed = Url::parse(raw).map_err(|_| NetworkError::InvalidInput)?;
    if parsed.scheme() != "https"
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.host_str() != Some(expected_host)
        || parsed.port() != Some(expected_port)
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || raw != format!("https://{expected_host}:{expected_port}")
    {
        return Err(NetworkError::InvalidInput);
    }
    Ok(())
}

fn controller_server_name(infrastructure_id: &str) -> String {
    format!("controller.{infrastructure_id}.your-cloud.test")
}

fn device_uri(infrastructure_id: &str, device_id: &str) -> String {
    format!("urn:your-cloud:device:v1:{infrastructure_id}:{device_id}")
}

fn canonical_timestamp(value: &str) -> bool {
    parse_timestamp(value).is_some()
}

fn parse_timestamp(value: &str) -> Option<OffsetDateTime> {
    if value.len() < 20
        || value.len() > 30
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
        || value.as_bytes().get(10) != Some(&b'T')
        || value.as_bytes().get(13) != Some(&b':')
        || value.as_bytes().get(16) != Some(&b':')
        || !value.ends_with('Z')
    {
        return None;
    }
    if value.len() > 20 {
        let fraction = &value[19..value.len() - 1];
        if !fraction.starts_with('.')
            || fraction.len() < 2
            || fraction.len() > 10
            || !fraction[1..].bytes().all(|byte| byte.is_ascii_digit())
            || fraction.ends_with('0')
        {
            return None;
        }
    }
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

fn canonical_raw_url(value: &str, size: usize) -> bool {
    URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .ok()
        .filter(|decoded| decoded.len() == size && URL_SAFE_NO_PAD.encode(decoded) == value)
        .is_some()
}

fn decode_raw_url_32(value: &str) -> Result<[u8; 32], NetworkError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| NetworkError::ResponseRefused)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(NetworkError::ResponseRefused);
    }
    decoded
        .try_into()
        .map_err(|_| NetworkError::ResponseRefused)
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], NetworkError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(NetworkError::ResponseRefused);
    }
    hex::decode(value)
        .map_err(|_| NetworkError::ResponseRefused)?
        .try_into()
        .map_err(|_| NetworkError::ResponseRefused)
}

fn valid_window_code(value: &str) -> bool {
    if value.len() > 64 || !value.is_ascii() {
        return false;
    }
    let uppercase = value.to_ascii_uppercase();
    let compact = if uppercase.len() == 30 {
        let parts = uppercase.split('-').collect::<Vec<_>>();
        if parts.len() != 5 || parts[..4].iter().any(|part| part.len() != 5) || parts[4].len() != 6
        {
            return false;
        }
        parts.concat()
    } else if uppercase.len() == 26 && !uppercase.contains('-') {
        uppercase
    } else {
        return false;
    };
    compact
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
}

fn valid_machine_id(value: &str) -> bool {
    (3..=63).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || index > 0 && byte == b'-'
        })
}

fn valid_label(value: &str) -> bool {
    if value.is_empty() || value.len() > 256 || value.nfc().collect::<String>() != value {
        return false;
    }
    let characters = value.chars().collect::<Vec<_>>();
    if characters.is_empty()
        || characters.len() > 80
        || !is_letter_or_decimal(characters[0])
        || !is_letter_or_decimal(*characters.last().unwrap_or(&' '))
    {
        return false;
    }
    let mut previous_letter_or_mark = false;
    let mut previous_space = false;
    for character in characters {
        let category = get_general_category(character);
        match category {
            GeneralCategory::UppercaseLetter
            | GeneralCategory::LowercaseLetter
            | GeneralCategory::TitlecaseLetter
            | GeneralCategory::ModifierLetter
            | GeneralCategory::OtherLetter => {
                previous_letter_or_mark = true;
                previous_space = false;
            }
            GeneralCategory::NonspacingMark
            | GeneralCategory::SpacingMark
            | GeneralCategory::EnclosingMark => {
                if !previous_letter_or_mark {
                    return false;
                }
                previous_letter_or_mark = true;
                previous_space = false;
            }
            GeneralCategory::DecimalNumber => {
                previous_letter_or_mark = false;
                previous_space = false;
            }
            _ if character == ' ' => {
                if previous_space {
                    return false;
                }
                previous_letter_or_mark = false;
                previous_space = true;
            }
            _ if matches!(character, '-' | '_' | '.' | '\'' | '(' | ')') => {
                previous_letter_or_mark = false;
                previous_space = false;
            }
            _ => return false,
        }
    }
    true
}

/// The label of an external element does not borrow the managed label profile.
///
/// A managed label names a thing the product owns, so it is normalised and held
/// to a positive Unicode list. This one is the human's own words about a thing
/// the product does not own: the contract closes it on bytes — 1 to 64 printable
/// ASCII characters — and it is kept exactly as written, never trimmed and never
/// normalised. Refusing a byte outside that bound is not correcting a label; it
/// is refusing a Controller that sent something the contract says cannot be one.
/// What makes the label inert is where it is displayed, not a rewrite here.
fn valid_external_label(value: &str) -> bool {
    (1..=MAX_EXTERNAL_LABEL_BYTES).contains(&value.len())
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

fn canonical_label(value: &str) -> Result<String, NetworkError> {
    if value.is_empty() || value.len() > 256 {
        return Err(NetworkError::InvalidInput);
    }
    let canonical = value.nfc().collect::<String>();
    if valid_label(&canonical) {
        Ok(canonical)
    } else {
        Err(NetworkError::InvalidInput)
    }
}

fn is_letter_or_decimal(character: char) -> bool {
    matches!(
        get_general_category(character),
        GeneralCategory::UppercaseLetter
            | GeneralCategory::LowercaseLetter
            | GeneralCategory::TitlecaseLetter
            | GeneralCategory::ModifierLetter
            | GeneralCategory::OtherLetter
            | GeneralCategory::DecimalNumber
    )
}

fn random_raw_url(size: usize) -> String {
    let mut value = vec![0_u8; size];
    OsRng.fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn ensure_current(generation: u64, current: &AtomicU64) -> Result<(), NetworkError> {
    if current.load(Ordering::SeqCst) == generation {
        Ok(())
    } else {
        Err(NetworkError::Cancelled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::ConsoleCore;

    #[test]
    fn origins_and_identifiers_are_exact() {
        let infrastructure = "123e4567-e89b-42d3-a456-426614174000";
        let host = controller_server_name(infrastructure);
        assert!(validate_origin(&format!("https://{host}:9443"), &host, 9443).is_ok());
        assert!(validate_origin(&format!("https://{host}:9443/"), &host, 9443).is_err());
        assert!(validate_origin(&format!("http://{host}:9443"), &host, 9443).is_err());
        assert!(valid_machine_id("lab-machine-1"));
        assert!(!valid_machine_id("Lab-machine-1"));
    }

    #[test]
    fn recovery_derivation_is_stable_and_context_bound() {
        let code = [0x5a_u8; 32];
        let salt = URL_SAFE_NO_PAD.encode([0x33_u8; 32]);
        let infrastructure = Uuid::parse_str("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let spki = [0x77_u8; 32];
        let first = recovery_signing_key(&code, &salt, 7, &infrastructure, &spki).unwrap();
        let second = recovery_signing_key(&code, &salt, 8, &infrastructure, &spki).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(first.to_bytes()),
            "3zCrQciXcAUbEKNsqhm4fsKoDeUbbqOAuiyKWATbFTs"
        );
        assert_ne!(first.to_bytes(), second.to_bytes());
    }

    fn declared_element() -> ExternalElementView {
        ExternalElementView {
            element_id: URL_SAFE_NO_PAD.encode([0x11_u8; 16]),
            machine_id: "lab-machine-1".to_owned(),
            label: "vaultwarden pose a la main".to_owned(),
            kind: "external_service".to_owned(),
            probe_port: 8080,
            declared_at: "2026-08-07T10:00:00Z".to_owned(),
            state: "declared".to_owned(),
            reason: None,
            observed_at: None,
            observation_status: "absent".to_owned(),
        }
    }

    #[test]
    fn external_labels_are_bytes_and_never_the_managed_profile() {
        assert!(valid_external_label("vaultwarden pose a la main"));
        // Printable ASCII markup is a legitimate label: it is what the human
        // typed about their own thing, and its inertness is obtained where it is
        // displayed rather than by correcting it here.
        assert!(valid_external_label("<script>alert(\"x\")</script>"));
        assert!(valid_external_label("\" onmouseover=\"alert(1)"));
        assert!(valid_external_label(&"<".repeat(MAX_EXTERNAL_LABEL_BYTES)));
        // The rest of the hostile corpus cannot be a label at all: an override of
        // the reading order, control bytes, an escape sequence, a line break, an
        // empty string and one byte past the bound.
        assert!(!valid_external_label("facture\u{202e}exe.gnp"));
        assert!(!valid_external_label("vault\u{7}rouge"));
        assert!(!valid_external_label("vault\u{1b}[31mrouge"));
        assert!(!valid_external_label("ligne\nsuivante"));
        assert!(!valid_external_label(""));
        assert!(!valid_external_label(
            &"<".repeat(MAX_EXTERNAL_LABEL_BYTES + 1)
        ));
        // The two profiles are deliberately different bounds on different things:
        // a managed label the product owns passes its own list and not this one.
        assert!(valid_label("Étiquette gérée"));
        assert!(!valid_external_label("Étiquette gérée"));
    }

    #[test]
    fn external_readings_refuse_a_word_this_console_does_not_know() {
        assert!(validate_external_element(&declared_element()).is_ok());
        let mut invented = declared_element();
        invented.state = "probablement_la".to_owned();
        assert!(validate_external_element(&invented).is_err());

        // A verified reading past the announced limit keeps saying verified and
        // stops saying recent: the age is a separate dimension and never a state.
        let mut verified = declared_element();
        verified.state = "verified".to_owned();
        verified.observed_at = Some("2026-08-07T10:00:00Z".to_owned());
        verified.observation_status = "old".to_owned();
        assert!(validate_external_element(&verified).is_ok());
        verified.reason = Some("nothing_listening".to_owned());
        assert!(validate_external_element(&verified).is_err());

        let mut unverifiable = declared_element();
        unverifiable.state = "unverifiable".to_owned();
        unverifiable.observed_at = Some("2026-08-07T10:00:00Z".to_owned());
        unverifiable.observation_status = "recent".to_owned();
        for reason in [
            "nothing_listening",
            "response_too_large",
            "machine_unreachable",
            "port_is_managed",
        ] {
            unverifiable.reason = Some(reason.to_owned());
            assert!(validate_external_element(&unverifiable).is_ok());
        }
        unverifiable.reason = Some("port_is_busy".to_owned());
        assert!(validate_external_element(&unverifiable).is_err());
        unverifiable.reason = None;
        assert!(validate_external_element(&unverifiable).is_err());

        // A declaration nobody has read carries no date and no age. Neither half
        // may arrive alone: a dated nothing and an undated freshness are both a
        // reading that never happened.
        let mut dated = declared_element();
        dated.observed_at = Some("2026-08-07T10:00:00Z".to_owned());
        assert!(validate_external_element(&dated).is_err());
        let mut fresh = declared_element();
        fresh.observation_status = "recent".to_owned();
        assert!(validate_external_element(&fresh).is_err());
    }

    #[test]
    fn a_capability_on_the_wire_is_an_unknown_field() {
        let honest = serde_json::to_string(&declared_element()).unwrap();
        assert!(serde_json::from_str::<ExternalElementView>(&honest).is_ok());
        // The four absences are known from the route, never read from the wire.
        // A Controller that offered one would be offering a management action.
        for capability in [
            r#""can_update":true,"#,
            r#""can_restore":true,"#,
            r#""can_delete":true,"#,
            r#""guaranteed":true,"#,
        ] {
            let widened = honest.replacen('{', &format!("{{{capability}"), 1);
            assert!(serde_json::from_str::<ExternalElementView>(&widened).is_err());
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LabWindowSheet {
        schema_version: u8,
        mode: String,
        origin: String,
        temporary_origin: String,
        controller_id: String,
        infrastructure_id: String,
        server_ca_pem: String,
        server_spki_sha256: String,
        window_id: String,
        window_code: String,
        expires_at: String,
    }

    #[test]
    #[ignore = "requires the isolated LAB Controller and one live enrollment window"]
    fn lab_console_enrollment_session_and_inventory() {
        let path = std::env::var("YOUR_CLOUD_V003_WINDOW_SHEET")
            .expect("the LAB window sheet path must be explicit");
        let encoded = std::fs::read(&path).expect("the LAB window sheet must be readable");
        assert!(encoded.len() <= TEMPORARY_RESPONSE_MAX_BYTES);
        let sheet: LabWindowSheet =
            serde_json::from_slice(&encoded).expect("the LAB window sheet must be strict JSON");
        assert_eq!(sheet.schema_version, 1);
        assert_eq!(sheet.mode, "enrollment");
        assert!(canonical_timestamp(&sheet.expires_at));

        let directory = tempfile::tempdir().unwrap();
        let mut core = ConsoleCore::new(directory.path().join("state"));
        let generated = core.prepare().unwrap();
        core.confirm_initialization(
            &generated.generation_id,
            generated.unlock_phrase.clone(),
            generated.recovery_code.clone(),
            true,
        )
        .unwrap();
        let original_recovery_code = generated.recovery_code.clone();
        let input = PairingInput {
            mode: sheet.mode,
            origin: sheet.origin,
            temporary_origin: sheet.temporary_origin,
            controller_id: sheet.controller_id,
            infrastructure_id: sheet.infrastructure_id.clone(),
            server_ca_pem: sheet.server_ca_pem,
            server_spki_sha256: sheet.server_spki_sha256,
            window_id: sheet.window_id,
            window_code: sheet.window_code,
            recovery_code: generated.recovery_code,
        };
        let generation = AtomicU64::new(0);
        let mut network = NetworkState::new();
        let mut association = network
            .pair(input, 0, &generation, |candidate| {
                core.store_association(candidate, false)
                    .map(|_| ())
                    .map_err(|_| NetworkError::ConsoleUnavailable)
            })
            .expect("the real LAB enrollment must complete");
        core.store_association(association.clone(), true).unwrap();
        assert_eq!(core.status().unwrap().associations.len(), 1);

        let infrastructure = network
            .put_infrastructure(&association, "Infrastructure principale", 0, &generation)
            .expect("the authenticated infrastructure initialization must complete");
        assert!(infrastructure.initialized);
        assert_eq!(
            infrastructure.label.as_deref(),
            Some("Infrastructure principale")
        );
        if let Ok(machine_id) = std::env::var("YOUR_CLOUD_V003_ACTIVE_MACHINE") {
            let attached = network
                .put_machine(
                    &association,
                    &machine_id,
                    "Machine principale",
                    0,
                    &generation,
                )
                .expect("a fresh active Relay enrollment must permit the machine attachment");
            assert_eq!(attached.machine_id, machine_id);
            let machines = network
                .read_machines(&association, 0, &generation)
                .expect("the authenticated projection must be readable");
            assert_eq!(machines.relay_status, "available");
            assert_eq!(machines.machines.len(), 1);
            assert_eq!(machines.machines[0].machine_id, machine_id);
        } else {
            let machines = network
                .read_machines(&association, 0, &generation)
                .expect("a Relay outage must remain an authenticated bounded projection");
            assert_eq!(machines.relay_status, "unavailable");
            assert!(machines.machines.is_empty());
        }
        let revoked_association = association.clone();
        let previous_revision = association.identity_revision;
        association = network
            .rotate_device(association, 0, &generation, |candidate| {
                core.store_association(candidate, true)
                    .map(|_| ())
                    .map_err(|_| NetworkError::ConsoleUnavailable)
            })
            .expect("the real LAB device rotation must complete");
        assert_eq!(association.identity_revision, previous_revision + 1);
        core.store_association(association.clone(), true).unwrap();
        let infrastructure = network
            .read_infrastructure(&association, 0, &generation)
            .expect("the rotated device must open a fresh human session");
        assert!(infrastructure.initialized);
        assert!(network
            .read_infrastructure(&revoked_association, 0, &generation)
            .is_err());
        let prepared = core.prepare_recovery_rotation().unwrap();
        let progress = core
            .confirm_recovery_rotation(
                &prepared.generation_id,
                prepared.new_recovery_code.clone(),
                true,
            )
            .unwrap();
        association = network
            .rotate_recovery_key(
                association,
                &progress.controllers[0],
                &original_recovery_code,
                &prepared.new_recovery_code,
                0,
                &generation,
            )
            .expect("the global recovery key must rotate on the real Controller");
        let progress = core
            .record_recovery_rotation_result(
                Some(association.clone()),
                &association.summary.infrastructure_id,
                true,
            )
            .unwrap();
        assert_eq!(progress.controllers[0].status, "completed");
        assert_eq!(association.recovery_epoch, 2);
        core.complete_recovery_rotation().unwrap();
        assert!(network
            .read_infrastructure(&association, 0, &generation)
            .is_ok());
        let token = network
            .sessions
            .get(&association.summary.infrastructure_id)
            .expect("the rotated identity must own one native session")
            .to_string();
        let client = association_client(&association).unwrap();
        let origin = association.summary.origin.as_str();
        assert_eq!(
            lab_raw_status(
                &client,
                "GET",
                &format!("{origin}/v0/infrastructure"),
                "invalid-human-session",
                None,
                None,
            ),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            lab_raw_status(
                &client,
                "GET",
                &format!("{origin}/v0/unknown"),
                &token,
                None,
                None
            ),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            lab_raw_status(
                &client,
                "POST",
                &format!("{origin}/v0/infrastructure"),
                &token,
                None,
                None
            ),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            lab_raw_status(
                &client,
                "GET",
                &format!("{origin}/v0/infrastructure?crossed=1"),
                &token,
                None,
                None
            ),
            StatusCode::BAD_REQUEST
        );
        let invalid_schema = format!(
            r#"{{"schema_version":2,"infrastructure_id":"{}","label":"Refusée"}}"#,
            association.summary.infrastructure_id
        );
        assert_eq!(
            lab_raw_status(
                &client,
                "PUT",
                &format!("{origin}/v0/infrastructure"),
                &token,
                Some(invalid_schema.as_bytes()),
                None,
            ),
            StatusCode::BAD_REQUEST
        );
        let oversized = vec![b'x'; REQUEST_MAX_BYTES + 1];
        assert_eq!(
            lab_raw_status(
                &client,
                "PUT",
                &format!("{origin}/v0/infrastructure"),
                &token,
                Some(&oversized),
                None,
            ),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            lab_raw_status(
                &client,
                "GET",
                &format!("{origin}/v0/infrastructure"),
                &token,
                None,
                Some("controller.invalid.your-cloud.test:9443"),
            ),
            StatusCode::FORBIDDEN
        );
        network
            .logout(&association)
            .expect("logout must be accepted");
        assert_eq!(
            lab_raw_status(
                &client,
                "GET",
                &format!("{origin}/v0/infrastructure"),
                &token,
                None,
                None,
            ),
            StatusCode::UNAUTHORIZED
        );
    }

    fn lab_raw_status(
        client: &Client,
        method: &str,
        url: &str,
        token: &str,
        body: Option<&[u8]>,
        host: Option<&str>,
    ) -> StatusCode {
        let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let mut request = client
            .request(method, url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, format!("Bearer {token}"));
        if let Some(body) = body {
            request = request
                .header(CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        if let Some(host) = host {
            request = request.header(reqwest::header::HOST, host);
        }
        request
            .send()
            .expect("hostile LAB request must receive a bounded response")
            .status()
    }
}
