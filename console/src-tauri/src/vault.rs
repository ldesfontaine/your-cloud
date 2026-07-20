use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bip39::Language;
use iota_stronghold::{KeyProvider, SnapshotPath, Stronghold};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

const METADATA_FILE: &str = "vault.json";
const SNAPSHOT_FILE: &str = "console.stronghold";
const CLIENT_PATH: &[u8] = b"your-cloud-console/v0.0.3";
const DOCUMENT_KEY: &[u8] = b"console-document/v1";
const METADATA_MAX_BYTES: u64 = 2_048;
const SNAPSHOT_MAX_BYTES: u64 = 16 * 1024 * 1024;
const RAW_PHRASE_MAX_BYTES: usize = 192;
const CANONICAL_PHRASE_MAX_BYTES: usize = 96;
const RAW_RECOVERY_MAX_BYTES: usize = 80;
const WORDLIST_SHA256: &str = "ebc3959ab7801a1df6bac4fa7d970652f1df76b683cd2f4003c941c63d517e59";
const RECOVERY_DOMAIN: &[u8] = b"your-cloud/v0.0.3/recovery-check";
const RECOVERY_ROTATION_DIGEST_DOMAIN: &[u8] = b"your-cloud/v0.0.3/recovery-code-rotation\0";

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("invalid local input")]
    InvalidInput,
    #[error("local authentication failed")]
    AuthenticationFailed,
    #[error("the Console is locked")]
    Locked,
    #[error("local Console state is unavailable")]
    Unavailable,
}

impl VaultError {
    pub fn public_code(&self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::AuthenticationFailed => "authentication_failed",
            Self::Locked => "console_locked",
            Self::Unavailable => "console_unavailable",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssociationSummary {
    pub controller_id: String,
    pub infrastructure_id: String,
    pub infrastructure_label: Option<String>,
    pub origin: String,
    pub device_status: String,
    pub certificate_expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ConsoleStatus {
    pub schema_version: u8,
    pub lock_state: &'static str,
    pub associations: Vec<AssociationSummary>,
    pub recovery_rotation: Option<RecoveryRotationProgress>,
}

#[derive(Debug, Serialize)]
pub struct GeneratedLocalSecrets {
    pub generation_id: String,
    pub unlock_phrase: String,
    pub recovery_code: String,
}

#[derive(Debug, Serialize)]
pub struct PreparedPhraseChange {
    pub generation_id: String,
    pub new_unlock_phrase: String,
}

#[derive(Debug, Serialize)]
pub struct PreparedRecoveryRotation {
    pub generation_id: String,
    pub new_recovery_code: String,
    pub target_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryControllerProgress {
    pub controller_id: String,
    pub infrastructure_id: String,
    pub operation_id: String,
    pub target_recovery_epoch: u64,
    pub status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryRotationProgress {
    pub schema_version: u8,
    pub new_code_sha256: String,
    pub controllers: Vec<RecoveryControllerProgress>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AssociationRecord {
    pub summary: AssociationSummary,
    pub device_id: String,
    pub server_ca_pem: String,
    pub server_spki_sha256: String,
    pub device_private_key_pem: String,
    pub device_certificate_pem: String,
    pub human_private_seed: String,
    pub identity_revision: u64,
    pub recovery_salt: String,
    pub recovery_epoch: u64,
    pub pending_mode: Option<String>,
    pub pending_transaction_id: Option<String>,
    #[serde(default)]
    pub pending_device_private_key_pem: Option<String>,
    #[serde(default)]
    pub pending_device_certificate_pem: Option<String>,
    #[serde(default)]
    pub pending_certificate_expires_at: Option<String>,
}

impl Drop for AssociationRecord {
    fn drop(&mut self) {
        self.server_ca_pem.zeroize();
        self.server_spki_sha256.zeroize();
        self.device_private_key_pem.zeroize();
        self.device_certificate_pem.zeroize();
        self.human_private_seed.zeroize();
        self.recovery_salt.zeroize();
        self.device_id.zeroize();
        self.pending_mode.zeroize();
        self.pending_transaction_id.zeroize();
        self.pending_device_private_key_pem.zeroize();
        self.pending_device_certificate_pem.zeroize();
        self.pending_certificate_expires_at.zeroize();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ConsoleDocument {
    schema_version: u8,
    associations: Vec<AssociationRecord>,
    #[serde(default)]
    recovery_rotation: Option<RecoveryRotationProgress>,
}

impl ConsoleDocument {
    fn empty() -> Self {
        Self {
            schema_version: 1,
            associations: Vec::new(),
            recovery_rotation: None,
        }
    }

    fn validate(&self) -> Result<(), VaultError> {
        if self.schema_version != 1 || self.associations.len() > 64 {
            return Err(VaultError::Unavailable);
        }
        let mut previous: Option<(&str, &str)> = None;
        for association in &self.associations {
            let summary = &association.summary;
            if summary.controller_id.is_empty()
                || summary.infrastructure_id.is_empty()
                || summary.origin.is_empty()
                || summary.controller_id.len() > 36
                || summary.infrastructure_id.len() > 36
                || summary.origin.len() > 256
                || !matches!(
                    summary.device_status.as_str(),
                    "candidate" | "active" | "revoked"
                )
                || association.device_id.len() != 36
                || association.server_ca_pem.is_empty()
                || association.server_ca_pem.len() > 16 * 1024
                || association.server_spki_sha256.len() != 64
                || association.device_private_key_pem.is_empty()
                || association.device_private_key_pem.len() > 4 * 1024
                || association.device_certificate_pem.is_empty()
                || association.device_certificate_pem.len() > 8 * 1024
                || URL_SAFE_NO_PAD
                    .decode(association.human_private_seed.as_bytes())
                    .map_or(true, |decoded| decoded.len() != 32)
                || URL_SAFE_NO_PAD
                    .decode(association.recovery_salt.as_bytes())
                    .map_or(true, |decoded| decoded.len() != 32)
                || association.recovery_epoch == 0
                || !valid_pending_identity(association)
            {
                return Err(VaultError::Unavailable);
            }
            let current = (
                summary.infrastructure_id.as_str(),
                summary.controller_id.as_str(),
            );
            if previous.is_some_and(|value| value >= current) {
                return Err(VaultError::Unavailable);
            }
            previous = Some(current);
        }
        if let Some(rotation) = &self.recovery_rotation {
            if rotation.schema_version != 1
                || rotation.controllers.is_empty()
                || rotation.controllers.len() > self.associations.len()
                || rotation.new_code_sha256.len() != 64
                || !rotation
                    .new_code_sha256
                    .bytes()
                    .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
            {
                return Err(VaultError::Unavailable);
            }
            let mut previous: Option<(&str, &str)> = None;
            for controller in &rotation.controllers {
                let current = (
                    controller.infrastructure_id.as_str(),
                    controller.controller_id.as_str(),
                );
                if previous.is_some_and(|value| value >= current)
                    || !matches!(
                        controller.status.as_str(),
                        "pending" | "failed" | "completed"
                    )
                    || controller.target_recovery_epoch == 0
                    || URL_SAFE_NO_PAD
                        .decode(controller.operation_id.as_bytes())
                        .map_or(true, |decoded| decoded.len() != 16)
                    || !self.associations.iter().any(|association| {
                        association.summary.infrastructure_id == controller.infrastructure_id
                            && association.summary.controller_id == controller.controller_id
                    })
                {
                    return Err(VaultError::Unavailable);
                }
                previous = Some(current);
            }
        }
        Ok(())
    }
}

fn valid_pending_identity(association: &AssociationRecord) -> bool {
    let pending_material_absent = association.pending_device_private_key_pem.is_none()
        && association.pending_device_certificate_pem.is_none()
        && association.pending_certificate_expires_at.is_none();
    if association.summary.device_status == "candidate" {
        return association.identity_revision == 0
            && matches!(
                association.pending_mode.as_deref(),
                Some("enrollment") | Some("recovery")
            )
            && association
                .pending_transaction_id
                .as_ref()
                .is_some_and(|value| value.len() == 22)
            && pending_material_absent;
    }
    if association.identity_revision == 0 {
        return false;
    }
    match association.pending_mode.as_deref() {
        None => association.pending_transaction_id.is_none() && pending_material_absent,
        Some("rotation") if association.summary.device_status == "active" => {
            association
                .pending_transaction_id
                .as_ref()
                .is_some_and(|value| value.len() == 22)
                && association
                    .pending_device_private_key_pem
                    .as_ref()
                    .is_some_and(|value| !value.is_empty() && value.len() <= 4 * 1024)
                && association
                    .pending_device_certificate_pem
                    .as_ref()
                    .is_some_and(|value| !value.is_empty() && value.len() <= 8 * 1024)
                && association
                    .pending_certificate_expires_at
                    .as_ref()
                    .is_some_and(|value| !value.is_empty() && value.len() <= 30)
        }
        _ => false,
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct KdfProfile {
    algorithm: String,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    output_bytes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultMetadata {
    schema_version: u8,
    salt: String,
    argon2: KdfProfile,
    snapshot: String,
    wordlist_sha256: String,
}

impl VaultMetadata {
    fn new(salt: &[u8; 16], snapshot: String) -> Self {
        Self {
            schema_version: 1,
            salt: URL_SAFE_NO_PAD.encode(salt),
            argon2: KdfProfile {
                algorithm: "argon2id".to_owned(),
                version: 19,
                memory_kib: 65_536,
                iterations: 3,
                parallelism: 1,
                output_bytes: 32,
            },
            snapshot,
            wordlist_sha256: WORDLIST_SHA256.to_owned(),
        }
    }

    fn validate(&self) -> Result<([u8; 16], String), VaultError> {
        if self.schema_version != 1
            || self.argon2.algorithm != "argon2id"
            || self.argon2.version != 19
            || self.argon2.memory_kib != 65_536
            || self.argon2.iterations != 3
            || self.argon2.parallelism != 1
            || self.argon2.output_bytes != 32
            || !valid_snapshot_name(&self.snapshot)
            || self.wordlist_sha256 != WORDLIST_SHA256
        {
            return Err(VaultError::Unavailable);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(self.salt.as_bytes())
            .map_err(|_| VaultError::Unavailable)?;
        let salt = decoded.try_into().map_err(|_| VaultError::Unavailable)?;
        Ok((salt, self.snapshot.clone()))
    }
}

struct PendingInitialization {
    generation_id: String,
    phrase: Zeroizing<String>,
    recovery: Zeroizing<Vec<u8>>,
    displayed_recovery: Zeroizing<String>,
}

struct PendingRecoveryRotation {
    generation_id: String,
    recovery: Zeroizing<Vec<u8>>,
    displayed_recovery: Zeroizing<String>,
}

struct PendingPhraseChange {
    generation_id: String,
    phrase: Zeroizing<String>,
}

struct UnlockedVault {
    stronghold: Stronghold,
    snapshot_key: Zeroizing<Vec<u8>>,
    snapshot_path: PathBuf,
    document: ConsoleDocument,
}

pub struct ConsoleCore {
    directory: PathBuf,
    pending: Option<PendingInitialization>,
    pending_phrase_change: Option<PendingPhraseChange>,
    pending_recovery_rotation: Option<PendingRecoveryRotation>,
    unlocked: Option<UnlockedVault>,
}

impl ConsoleCore {
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            pending: None,
            pending_phrase_change: None,
            pending_recovery_rotation: None,
            unlocked: None,
        }
    }

    pub fn status(&mut self) -> Result<ConsoleStatus, VaultError> {
        if let Some(unlocked) = &self.unlocked {
            return Ok(ConsoleStatus {
                schema_version: 1,
                lock_state: "unlocked",
                associations: unlocked
                    .document
                    .associations
                    .iter()
                    .map(|association| association.summary.clone())
                    .collect(),
                recovery_rotation: unlocked.document.recovery_rotation.clone(),
            });
        }
        let metadata = self.metadata_path();
        match metadata.try_exists() {
            Ok(false) => Ok(ConsoleStatus {
                schema_version: 1,
                lock_state: "uninitialized",
                associations: Vec::new(),
                recovery_rotation: None,
            }),
            Ok(true) => {
                validate_private_directory(&self.directory)?;
                let metadata = read_metadata(&metadata)?;
                let (_, snapshot) = metadata.validate()?;
                let _ = read_private_file(&self.directory.join(snapshot), SNAPSHOT_MAX_BYTES)?;
                Ok(ConsoleStatus {
                    schema_version: 1,
                    lock_state: "locked",
                    associations: Vec::new(),
                    recovery_rotation: None,
                })
            }
            Err(_) => Err(VaultError::Unavailable),
        }
    }

    pub fn prepare(&mut self) -> Result<GeneratedLocalSecrets, VaultError> {
        if self.status()?.lock_state != "uninitialized" {
            return Err(VaultError::InvalidInput);
        }
        validate_wordlist()?;
        let generation_id = random_identifier();
        let phrase = generate_phrase();
        let mut recovery = Zeroizing::new(vec![0_u8; 32]);
        OsRng.fill_bytes(&mut recovery);
        let displayed_recovery = format_recovery_code(&recovery);
        self.pending = Some(PendingInitialization {
            generation_id: generation_id.clone(),
            phrase: Zeroizing::new(phrase.clone()),
            recovery,
            displayed_recovery: Zeroizing::new(displayed_recovery.clone()),
        });
        Ok(GeneratedLocalSecrets {
            generation_id,
            unlock_phrase: phrase,
            recovery_code: displayed_recovery,
        })
    }

    pub fn discard_preparation(&mut self, generation_id: &str) -> Result<(), VaultError> {
        let pending = self.pending.as_ref().ok_or(VaultError::InvalidInput)?;
        if pending.generation_id != generation_id {
            return Err(VaultError::InvalidInput);
        }
        self.pending = None;
        Ok(())
    }

    pub fn confirm_initialization(
        &mut self,
        generation_id: &str,
        unlock_phrase: String,
        recovery_code: String,
        confirmed_copies: bool,
    ) -> Result<ConsoleStatus, VaultError> {
        let unlock_phrase = Zeroizing::new(unlock_phrase);
        let recovery_code = Zeroizing::new(recovery_code);
        if !confirmed_copies || self.status()?.lock_state != "uninitialized" {
            return Err(VaultError::InvalidInput);
        }
        let pending = self.pending.as_ref().ok_or(VaultError::InvalidInput)?;
        let canonical_phrase = Zeroizing::new(canonical_phrase(&unlock_phrase)?);
        let parsed_recovery = parse_recovery_code(&recovery_code)?;
        if pending.generation_id != generation_id
            || pending.phrase.as_str() != canonical_phrase.as_str()
            || pending.recovery.as_slice() != parsed_recovery.as_slice()
            || pending.displayed_recovery.as_str() != format_recovery_code(&parsed_recovery)
        {
            return Err(VaultError::AuthenticationFailed);
        }

        ensure_private_directory(&self.directory)?;
        let mut salt = [0_u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key = derive_snapshot_key(&canonical_phrase, &salt)?;
        let snapshot = snapshot_file_name();
        let unlocked = create_snapshot(&self.directory, key, &snapshot)?;
        let metadata = VaultMetadata::new(&salt, snapshot.clone());
        if let Err(error) = write_metadata_atomic(&self.directory, &metadata) {
            let _ = fs::remove_file(self.directory.join(snapshot));
            return Err(error);
        }
        self.pending = None;
        self.unlocked = Some(unlocked);
        self.status()
    }

    pub fn unlock(&mut self, phrase: String) -> Result<ConsoleStatus, VaultError> {
        let phrase = Zeroizing::new(phrase);
        if self.unlocked.is_some() {
            return self.status();
        }
        if self.status()?.lock_state != "locked" {
            return Err(VaultError::InvalidInput);
        }
        let canonical = Zeroizing::new(canonical_phrase(&phrase)?);
        let metadata = read_metadata(&self.metadata_path())?;
        let (salt, snapshot_name) = metadata.validate()?;
        let key = derive_snapshot_key(&canonical, &salt)?;
        let snapshot = self.directory.join(snapshot_name);
        let stronghold = Stronghold::default();
        let client = stronghold
            .load_client_from_snapshot(
                CLIENT_PATH.to_vec(),
                &key_provider(key.clone())?,
                &SnapshotPath::from_path(&snapshot),
            )
            .map_err(|_| VaultError::AuthenticationFailed)?;
        let encoded = client
            .store()
            .get(DOCUMENT_KEY)
            .map_err(|_| VaultError::Unavailable)?
            .ok_or(VaultError::Unavailable)?;
        let document: ConsoleDocument =
            serde_json::from_slice(&encoded).map_err(|_| VaultError::Unavailable)?;
        document.validate()?;
        self.unlocked = Some(UnlockedVault {
            stronghold,
            snapshot_key: key,
            snapshot_path: snapshot,
            document,
        });
        self.status()
    }

    pub fn prepare_phrase_change(&mut self) -> Result<PreparedPhraseChange, VaultError> {
        if self.unlocked.is_none() {
            return Err(VaultError::Locked);
        }
        validate_wordlist()?;
        let generation_id = random_identifier();
        let phrase = generate_phrase();
        self.pending_phrase_change = Some(PendingPhraseChange {
            generation_id: generation_id.clone(),
            phrase: Zeroizing::new(phrase.clone()),
        });
        Ok(PreparedPhraseChange {
            generation_id,
            new_unlock_phrase: phrase,
        })
    }

    pub fn confirm_phrase_change(
        &mut self,
        generation_id: &str,
        current_phrase: String,
        new_phrase: String,
    ) -> Result<(), VaultError> {
        let current_phrase = Zeroizing::new(canonical_phrase(&current_phrase)?);
        let new_phrase = Zeroizing::new(canonical_phrase(&new_phrase)?);
        let pending = self
            .pending_phrase_change
            .as_ref()
            .ok_or(VaultError::InvalidInput)?;
        if pending.generation_id != generation_id || pending.phrase.as_str() != new_phrase.as_str()
        {
            return Err(VaultError::AuthenticationFailed);
        }

        let metadata = read_metadata(&self.metadata_path())?;
        let (current_salt, _) = metadata.validate()?;
        let current_key = derive_snapshot_key(&current_phrase, &current_salt)?;
        if constant_time_equal(current_phrase.as_bytes(), new_phrase.as_bytes()) {
            return Err(VaultError::InvalidInput);
        }
        let metadata_path = self.metadata_path();
        let unlocked = self.unlocked.as_mut().ok_or(VaultError::Locked)?;
        if !constant_time_equal(&current_key, &unlocked.snapshot_key) {
            return Err(VaultError::AuthenticationFailed);
        }

        let mut next_salt = [0_u8; 16];
        OsRng.fill_bytes(&mut next_salt);
        let next_key = derive_snapshot_key(&new_phrase, &next_salt)?;
        let next_snapshot_name = snapshot_file_name();
        let next_snapshot = self.directory.join(&next_snapshot_name);
        let temporary = self
            .directory
            .join(format!(".console-{}.stronghold", random_identifier()));
        unlocked
            .stronghold
            .commit_with_keyprovider(
                &SnapshotPath::from_path(&temporary),
                &key_provider(next_key.clone())?,
            )
            .map_err(|_| VaultError::Unavailable)?;
        set_private_file_mode(&temporary)?;
        if !snapshot_contains_document(&temporary, next_key.clone(), &unlocked.document) {
            let _ = fs::remove_file(&temporary);
            return Err(VaultError::Unavailable);
        }
        fs::rename(&temporary, &next_snapshot).map_err(|_| VaultError::Unavailable)?;
        sync_directory(&self.directory)?;

        let next_metadata = VaultMetadata::new(&next_salt, next_snapshot_name.clone());
        let write_result = write_metadata_atomic(&self.directory, &next_metadata);
        let published = read_metadata(&metadata_path)
            .ok()
            .and_then(|candidate| candidate.validate().ok())
            .is_some_and(|(_, snapshot)| snapshot == next_snapshot_name);
        if !published {
            let _ = fs::remove_file(&next_snapshot);
            return Err(write_result.err().unwrap_or(VaultError::Unavailable));
        }

        let previous_snapshot = std::mem::replace(&mut unlocked.snapshot_path, next_snapshot);
        unlocked.snapshot_key = next_key;
        self.pending_phrase_change = None;
        if previous_snapshot != unlocked.snapshot_path {
            fs::remove_file(previous_snapshot).map_err(|_| VaultError::Unavailable)?;
            sync_directory(&self.directory)?;
        }
        Ok(())
    }

    pub(crate) fn association(
        &self,
        infrastructure_id: &str,
    ) -> Result<AssociationRecord, VaultError> {
        let unlocked = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        unlocked
            .document
            .associations
            .iter()
            .find(|association| association.summary.infrastructure_id == infrastructure_id)
            .cloned()
            .ok_or(VaultError::InvalidInput)
    }

    pub(crate) fn store_association(
        &mut self,
        association: AssociationRecord,
        replacing: bool,
    ) -> Result<AssociationSummary, VaultError> {
        let unlocked = self.unlocked.as_mut().ok_or(VaultError::Locked)?;
        let target_infrastructure = association.summary.infrastructure_id.clone();
        let target_controller = association.summary.controller_id.clone();
        let mut candidate = unlocked.document.clone();
        let exact = candidate.associations.iter().position(|current| {
            current.summary.infrastructure_id == association.summary.infrastructure_id
                && current.summary.controller_id == association.summary.controller_id
        });
        let crossed = candidate.associations.iter().any(|current| {
            current.summary.infrastructure_id == association.summary.infrastructure_id
                || current.summary.controller_id == association.summary.controller_id
        });
        match (replacing, exact, crossed) {
            (true, Some(index), _) => candidate.associations[index] = association,
            (true, None, false) => candidate.associations.push(association),
            (false, None, false) => candidate.associations.push(association),
            _ => return Err(VaultError::InvalidInput),
        }
        candidate.associations.sort_by(|left, right| {
            (
                left.summary.infrastructure_id.as_str(),
                left.summary.controller_id.as_str(),
            )
                .cmp(&(
                    right.summary.infrastructure_id.as_str(),
                    right.summary.controller_id.as_str(),
                ))
        });
        candidate.validate()?;
        commit_document(&self.directory, unlocked, &candidate)?;
        unlocked
            .document
            .associations
            .iter()
            .find(|current| {
                current.summary.infrastructure_id == target_infrastructure
                    && current.summary.controller_id == target_controller
            })
            .map(|current| current.summary.clone())
            .ok_or(VaultError::Unavailable)
    }

    pub(crate) fn update_association_label(
        &mut self,
        infrastructure_id: &str,
        label: String,
    ) -> Result<AssociationSummary, VaultError> {
        let mut association = self.association(infrastructure_id)?;
        association.summary.infrastructure_label = Some(label);
        self.store_association(association, true)
    }

    pub fn prepare_recovery_rotation(&mut self) -> Result<PreparedRecoveryRotation, VaultError> {
        let unlocked = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        if unlocked.document.recovery_rotation.is_some()
            || unlocked.document.associations.is_empty()
            || unlocked
                .document
                .associations
                .iter()
                .any(|association| association.summary.device_status != "active")
        {
            return Err(VaultError::InvalidInput);
        }
        let generation_id = random_identifier();
        let mut recovery = Zeroizing::new(vec![0_u8; 32]);
        OsRng.fill_bytes(&mut recovery);
        let displayed_recovery = format_recovery_code(&recovery);
        self.pending_recovery_rotation = Some(PendingRecoveryRotation {
            generation_id: generation_id.clone(),
            recovery,
            displayed_recovery: Zeroizing::new(displayed_recovery.clone()),
        });
        Ok(PreparedRecoveryRotation {
            generation_id,
            new_recovery_code: displayed_recovery,
            target_count: unlocked.document.associations.len(),
        })
    }

    pub fn confirm_recovery_rotation(
        &mut self,
        generation_id: &str,
        new_recovery_code: String,
        confirmed_copies: bool,
    ) -> Result<RecoveryRotationProgress, VaultError> {
        let new_recovery_code = Zeroizing::new(new_recovery_code);
        if !confirmed_copies {
            return Err(VaultError::InvalidInput);
        }
        let pending = self
            .pending_recovery_rotation
            .as_ref()
            .ok_or(VaultError::InvalidInput)?;
        let parsed = parse_recovery_code(&new_recovery_code)?;
        if pending.generation_id != generation_id
            || pending.recovery.as_slice() != parsed.as_slice()
            || pending.displayed_recovery.as_str() != format_recovery_code(&parsed)
        {
            return Err(VaultError::AuthenticationFailed);
        }
        let unlocked = self.unlocked.as_mut().ok_or(VaultError::Locked)?;
        if unlocked.document.recovery_rotation.is_some()
            || unlocked.document.associations.is_empty()
        {
            return Err(VaultError::InvalidInput);
        }
        let mut digest = Sha256::new();
        digest.update(RECOVERY_ROTATION_DIGEST_DOMAIN);
        digest.update(parsed.as_slice());
        let mut controllers = unlocked
            .document
            .associations
            .iter()
            .map(|association| {
                Ok(RecoveryControllerProgress {
                    controller_id: association.summary.controller_id.clone(),
                    infrastructure_id: association.summary.infrastructure_id.clone(),
                    operation_id: random_identifier(),
                    target_recovery_epoch: association
                        .recovery_epoch
                        .checked_add(1)
                        .ok_or(VaultError::Unavailable)?,
                    status: "pending".to_owned(),
                })
            })
            .collect::<Result<Vec<_>, VaultError>>()?;
        controllers.sort_by(|left, right| {
            (left.infrastructure_id.as_str(), left.controller_id.as_str()).cmp(&(
                right.infrastructure_id.as_str(),
                right.controller_id.as_str(),
            ))
        });
        let progress = RecoveryRotationProgress {
            schema_version: 1,
            new_code_sha256: hex::encode(digest.finalize()),
            controllers,
        };
        let mut candidate = unlocked.document.clone();
        candidate.recovery_rotation = Some(progress.clone());
        candidate.validate()?;
        commit_document(&self.directory, unlocked, &candidate)?;
        self.pending_recovery_rotation = None;
        Ok(progress)
    }

    pub(crate) fn recovery_rotation(
        &self,
        old_recovery_code: &str,
        new_recovery_code: &str,
    ) -> Result<(RecoveryRotationProgress, Vec<AssociationRecord>), VaultError> {
        let unlocked = self.unlocked.as_ref().ok_or(VaultError::Locked)?;
        let progress = unlocked
            .document
            .recovery_rotation
            .clone()
            .ok_or(VaultError::InvalidInput)?;
        let old = parse_recovery_code(old_recovery_code)?;
        let new = parse_recovery_code(new_recovery_code)?;
        if old.as_slice() == new.as_slice() {
            return Err(VaultError::InvalidInput);
        }
        let mut digest = Sha256::new();
        digest.update(RECOVERY_ROTATION_DIGEST_DOMAIN);
        digest.update(new.as_slice());
        if hex::encode(digest.finalize()) != progress.new_code_sha256 {
            return Err(VaultError::AuthenticationFailed);
        }
        Ok((progress, unlocked.document.associations.clone()))
    }

    pub(crate) fn record_recovery_rotation_result(
        &mut self,
        association: Option<AssociationRecord>,
        infrastructure_id: &str,
        completed: bool,
    ) -> Result<RecoveryRotationProgress, VaultError> {
        let unlocked = self.unlocked.as_mut().ok_or(VaultError::Locked)?;
        let mut candidate = unlocked.document.clone();
        let progress = candidate
            .recovery_rotation
            .as_mut()
            .ok_or(VaultError::InvalidInput)?;
        let target = progress
            .controllers
            .iter_mut()
            .find(|target| target.infrastructure_id == infrastructure_id)
            .ok_or(VaultError::InvalidInput)?;
        if completed {
            let association = association.ok_or(VaultError::InvalidInput)?;
            if association.summary.infrastructure_id != target.infrastructure_id
                || association.summary.controller_id != target.controller_id
                || association.recovery_epoch != target.target_recovery_epoch
            {
                return Err(VaultError::InvalidInput);
            }
            let stored = candidate
                .associations
                .iter_mut()
                .find(|current| {
                    current.summary.infrastructure_id == target.infrastructure_id
                        && current.summary.controller_id == target.controller_id
                })
                .ok_or(VaultError::Unavailable)?;
            *stored = association;
            target.status = "completed".to_owned();
        } else if target.status != "completed" {
            target.status = "failed".to_owned();
        }
        candidate.validate()?;
        commit_document(&self.directory, unlocked, &candidate)?;
        candidate
            .recovery_rotation
            .clone()
            .ok_or(VaultError::Unavailable)
    }

    pub fn complete_recovery_rotation(&mut self) -> Result<(), VaultError> {
        let unlocked = self.unlocked.as_mut().ok_or(VaultError::Locked)?;
        let progress = unlocked
            .document
            .recovery_rotation
            .as_ref()
            .ok_or(VaultError::InvalidInput)?;
        if progress
            .controllers
            .iter()
            .any(|controller| controller.status != "completed")
        {
            return Err(VaultError::InvalidInput);
        }
        let mut candidate = unlocked.document.clone();
        candidate.recovery_rotation = None;
        candidate.validate()?;
        commit_document(&self.directory, unlocked, &candidate)
    }

    pub fn lock(&mut self) {
        self.unlocked = None;
        self.pending = None;
        self.pending_phrase_change = None;
        self.pending_recovery_rotation = None;
    }

    fn metadata_path(&self) -> PathBuf {
        self.directory.join(METADATA_FILE)
    }
}

fn create_snapshot(
    directory: &Path,
    key: Zeroizing<Vec<u8>>,
    snapshot_name: &str,
) -> Result<UnlockedVault, VaultError> {
    let stronghold = Stronghold::default();
    let client = stronghold
        .create_client(CLIENT_PATH.to_vec())
        .map_err(|_| VaultError::Unavailable)?;
    let document = ConsoleDocument::empty();
    let encoded = serde_json::to_vec(&document).map_err(|_| VaultError::Unavailable)?;
    client
        .store()
        .insert(DOCUMENT_KEY.to_vec(), encoded, None)
        .map_err(|_| VaultError::Unavailable)?;
    stronghold
        .write_client(CLIENT_PATH.to_vec())
        .map_err(|_| VaultError::Unavailable)?;

    let temporary = directory.join(format!(".console-{}.stronghold", random_identifier()));
    stronghold
        .commit_with_keyprovider(
            &SnapshotPath::from_path(&temporary),
            &key_provider(key.clone())?,
        )
        .map_err(|_| VaultError::Unavailable)?;
    set_private_file_mode(&temporary)?;
    let verifier = Stronghold::default();
    verifier
        .load_client_from_snapshot(
            CLIENT_PATH.to_vec(),
            &key_provider(key.clone())?,
            &SnapshotPath::from_path(&temporary),
        )
        .map_err(|_| VaultError::Unavailable)?;
    let snapshot_path = directory.join(snapshot_name);
    fs::rename(&temporary, &snapshot_path).map_err(|_| VaultError::Unavailable)?;
    sync_directory(directory)?;
    Ok(UnlockedVault {
        stronghold,
        snapshot_key: key,
        snapshot_path,
        document,
    })
}

fn commit_document(
    directory: &Path,
    unlocked: &mut UnlockedVault,
    candidate: &ConsoleDocument,
) -> Result<(), VaultError> {
    let previous = serde_json::to_vec(&unlocked.document).map_err(|_| VaultError::Unavailable)?;
    let encoded = serde_json::to_vec(candidate).map_err(|_| VaultError::Unavailable)?;
    if encoded.len() as u64 > SNAPSHOT_MAX_BYTES {
        return Err(VaultError::Unavailable);
    }
    let client = unlocked
        .stronghold
        .get_client(CLIENT_PATH)
        .map_err(|_| VaultError::Unavailable)?;
    client
        .store()
        .insert(DOCUMENT_KEY.to_vec(), encoded, None)
        .map_err(|_| VaultError::Unavailable)?;
    if unlocked
        .stronghold
        .write_client(CLIENT_PATH.to_vec())
        .is_err()
    {
        let _ = client.store().insert(DOCUMENT_KEY.to_vec(), previous, None);
        let _ = unlocked.stronghold.write_client(CLIENT_PATH.to_vec());
        return Err(VaultError::Unavailable);
    }
    let temporary = directory.join(format!(".console-{}.stronghold", random_identifier()));
    if unlocked
        .stronghold
        .commit_with_keyprovider(
            &SnapshotPath::from_path(&temporary),
            &key_provider(unlocked.snapshot_key.clone())?,
        )
        .is_err()
        || set_private_file_mode(&temporary).is_err()
    {
        let _ = client.store().insert(DOCUMENT_KEY.to_vec(), previous, None);
        let _ = unlocked.stronghold.write_client(CLIENT_PATH.to_vec());
        let _ = fs::remove_file(&temporary);
        return Err(VaultError::Unavailable);
    }
    let verifier = Stronghold::default();
    let verified = verifier
        .load_client_from_snapshot(
            CLIENT_PATH.to_vec(),
            &key_provider(unlocked.snapshot_key.clone())?,
            &SnapshotPath::from_path(&temporary),
        )
        .and_then(|verified_client| verified_client.store().get(DOCUMENT_KEY))
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice::<ConsoleDocument>(&bytes).ok())
        .is_some_and(|document| document == *candidate);
    if !verified {
        let _ = client.store().insert(DOCUMENT_KEY.to_vec(), previous, None);
        let _ = unlocked.stronghold.write_client(CLIENT_PATH.to_vec());
        let _ = fs::remove_file(&temporary);
        return Err(VaultError::Unavailable);
    }
    if fs::rename(&temporary, &unlocked.snapshot_path).is_err() {
        let _ = client.store().insert(DOCUMENT_KEY.to_vec(), previous, None);
        let _ = unlocked.stronghold.write_client(CLIENT_PATH.to_vec());
        let _ = fs::remove_file(&temporary);
        return Err(VaultError::Unavailable);
    }
    unlocked.document = candidate.clone();
    sync_directory(directory)
}

fn key_provider(key: Zeroizing<Vec<u8>>) -> Result<KeyProvider, VaultError> {
    KeyProvider::try_from(key).map_err(|_| VaultError::Unavailable)
}

fn derive_snapshot_key(phrase: &str, salt: &[u8; 16]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let parameters = Params::new(65_536, 3, 1, Some(32)).map_err(|_| VaultError::Unavailable)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters);
    let mut output = Zeroizing::new(vec![0_u8; 32]);
    argon
        .hash_password_into(phrase.as_bytes(), salt, &mut output)
        .map_err(|_| VaultError::Unavailable)?;
    Ok(output)
}

fn canonical_phrase(raw: &str) -> Result<String, VaultError> {
    if raw.is_empty() || raw.len() > RAW_PHRASE_MAX_BYTES {
        return Err(VaultError::InvalidInput);
    }
    let normalized: String = raw.nfkd().collect();
    let canonical = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    if canonical.len() > CANONICAL_PHRASE_MAX_BYTES {
        return Err(VaultError::InvalidInput);
    }
    let words = canonical.split(' ').collect::<Vec<_>>();
    if words.len() != 6
        || words
            .iter()
            .any(|word| Language::French.find_word(word).is_none())
    {
        return Err(VaultError::InvalidInput);
    }
    Ok(canonical)
}

fn validate_wordlist() -> Result<(), VaultError> {
    let mut digest = Sha256::new();
    for word in Language::French.word_list() {
        digest.update(word.as_bytes());
        digest.update(b"\n");
    }
    if format!("{:x}", digest.finalize()) != WORDLIST_SHA256 {
        return Err(VaultError::Unavailable);
    }
    Ok(())
}

fn generate_phrase() -> String {
    let words = Language::French.word_list();
    let mut selected = Vec::with_capacity(6);
    for _ in 0..6 {
        selected.push(words[(OsRng.next_u32() & 2_047) as usize]);
    }
    selected.join(" ")
}

fn snapshot_file_name() -> String {
    format!("console-{}.stronghold", random_identifier())
}

fn valid_snapshot_name(name: &str) -> bool {
    if name == SNAPSHOT_FILE {
        return true;
    }
    name.strip_prefix("console-")
        .and_then(|value| value.strip_suffix(".stronghold"))
        .is_some_and(|identifier| {
            identifier.len() == 22
                && identifier
                    .bytes()
                    .all(|value| value.is_ascii_alphanumeric() || value == b'-' || value == b'_')
        })
}

fn random_identifier() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn snapshot_contains_document(
    path: &Path,
    key: Zeroizing<Vec<u8>>,
    expected: &ConsoleDocument,
) -> bool {
    let verifier = Stronghold::default();
    verifier
        .load_client_from_snapshot(
            CLIENT_PATH.to_vec(),
            &match key_provider(key) {
                Ok(provider) => provider,
                Err(_) => return false,
            },
            &SnapshotPath::from_path(path),
        )
        .and_then(|client| client.store().get(DOCUMENT_KEY))
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice::<ConsoleDocument>(&bytes).ok())
        .is_some_and(|document| document == *expected)
}

fn format_recovery_code(raw: &[u8]) -> String {
    let encoded = base32_encode(raw);
    let mut digest = Sha256::new();
    digest.update(RECOVERY_DOMAIN);
    digest.update(raw);
    let checksum = digest.finalize();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let first = alphabet[(checksum[0] >> 3) as usize] as char;
    let second = alphabet[(((checksum[0] & 0x07) << 2) | (checksum[1] >> 6)) as usize] as char;
    let mut complete = format!("{encoded}{first}{second}");
    let mut grouped = String::with_capacity(62);
    for index in 0..9 {
        if index > 0 {
            grouped.push('-');
        }
        let start = index * 6;
        grouped.push_str(&complete[start..start + 6]);
    }
    complete.zeroize();
    grouped
}

pub(crate) fn parse_recovery_code(raw: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if raw.is_empty() || raw.len() > RAW_RECOVERY_MAX_BYTES || !raw.is_ascii() {
        return Err(VaultError::InvalidInput);
    }
    let uppercase = raw.to_ascii_uppercase();
    let canonical = if uppercase.len() == 54 && !uppercase.contains('-') {
        uppercase
    } else if uppercase.len() == 62
        && uppercase.chars().enumerate().all(|(index, value)| {
            (index + 1) % 7 == 0 && index < 56 && value == '-'
                || ((index + 1) % 7 != 0 || index >= 56) && value != '-'
        })
    {
        uppercase.replace('-', "")
    } else {
        return Err(VaultError::InvalidInput);
    };
    if canonical.len() != 54 {
        return Err(VaultError::InvalidInput);
    }
    let decoded = Zeroizing::new(base32_decode(&canonical[..52])?);
    if decoded.len() != 32 || base32_encode(&decoded) != canonical[..52] {
        return Err(VaultError::InvalidInput);
    }
    if format_recovery_code(&decoded).replace('-', "") != canonical {
        return Err(VaultError::AuthenticationFailed);
    }
    Ok(decoded)
}

fn base32_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::with_capacity((input.len() * 8 + 4) / 5);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in input {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((accumulator >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        output.push(ALPHABET[((accumulator << (5 - bits)) & 0x1f) as usize] as char);
    }
    output
}

fn base32_decode(input: &str) -> Result<Vec<u8>, VaultError> {
    let mut output = Vec::with_capacity(input.len() * 5 / 8);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err(VaultError::InvalidInput),
        };
        accumulator = (accumulator << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push(((accumulator >> bits) & 0xff) as u8);
        }
    }
    if bits > 0 && accumulator & ((1_u32 << bits) - 1) != 0 {
        return Err(VaultError::InvalidInput);
    }
    Ok(output)
}

fn read_metadata(path: &Path) -> Result<VaultMetadata, VaultError> {
    let bytes = read_private_file(path, METADATA_MAX_BYTES)?;
    let metadata: VaultMetadata =
        serde_json::from_slice(&bytes).map_err(|_| VaultError::Unavailable)?;
    metadata.validate()?;
    Ok(metadata)
}

fn write_metadata_atomic(directory: &Path, metadata: &VaultMetadata) -> Result<(), VaultError> {
    let encoded = serde_json::to_vec(metadata).map_err(|_| VaultError::Unavailable)?;
    if encoded.len() as u64 > METADATA_MAX_BYTES {
        return Err(VaultError::Unavailable);
    }
    let temporary = directory.join(format!(".vault-{}.json", random_identifier()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| VaultError::Unavailable)?;
    set_private_file_mode(&temporary)?;
    file.write_all(&encoded)
        .map_err(|_| VaultError::Unavailable)?;
    file.sync_all().map_err(|_| VaultError::Unavailable)?;
    drop(file);
    fs::rename(&temporary, directory.join(METADATA_FILE)).map_err(|_| VaultError::Unavailable)?;
    sync_directory(directory)
}

fn read_private_file(path: &Path, maximum: u64) -> Result<Vec<u8>, VaultError> {
    #[cfg(windows)]
    let file = crate::windows_security::open_private_file(path, maximum)
        .map_err(|_| VaultError::Unavailable)?;

    #[cfg(not(windows))]
    let file = {
        let metadata = fs::symlink_metadata(path).map_err(|_| VaultError::Unavailable)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > maximum
        {
            return Err(VaultError::Unavailable);
        }
        validate_private_file_metadata(&metadata)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(path).map_err(|_| VaultError::Unavailable)?;
        let opened = file.metadata().map_err(|_| VaultError::Unavailable)?;
        validate_private_file_metadata(&opened)?;
        if opened.len() != metadata.len() || opened.len() == 0 || opened.len() > maximum {
            return Err(VaultError::Unavailable);
        }
        file
    };
    let opened = file.metadata().map_err(|_| VaultError::Unavailable)?;
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| VaultError::Unavailable)?;
    if bytes.len() as u64 != opened.len() || bytes.len() as u64 > maximum {
        return Err(VaultError::Unavailable);
    }
    Ok(bytes)
}

fn ensure_private_directory(path: &Path) -> Result<(), VaultError> {
    if !path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700).recursive(true);
            builder.create(path).map_err(|_| VaultError::Unavailable)?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(path).map_err(|_| VaultError::Unavailable)?;
    }
    #[cfg(windows)]
    crate::windows_security::protect_directory(path).map_err(|_| VaultError::Unavailable)?;
    validate_private_directory(path)
}

fn validate_private_directory(path: &Path) -> Result<(), VaultError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| VaultError::Unavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(VaultError::Unavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o700 {
            return Err(VaultError::Unavailable);
        }
    }
    #[cfg(windows)]
    crate::windows_security::validate_private_directory(path)
        .map_err(|_| VaultError::Unavailable)?;
    Ok(())
}

fn set_private_file_mode(path: &Path) -> Result<(), VaultError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| VaultError::Unavailable)?;
    }
    #[cfg(windows)]
    crate::windows_security::protect_file(path).map_err(|_| VaultError::Unavailable)?;
    Ok(())
}

fn validate_private_file_metadata(metadata: &fs::Metadata) -> Result<(), VaultError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(VaultError::Unavailable);
        }
    }
    Ok(())
}

fn sync_directory(directory: &Path) -> Result<(), VaultError> {
    #[cfg(unix)]
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| VaultError::Unavailable)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_french_wordlist_is_pinned() {
        validate_wordlist().expect("the pinned wordlist must match the contract");
    }

    #[test]
    fn phrase_normalization_is_bounded_and_canonical() {
        let phrase = "abaisser abandon abdiquer abeille abolir aborder";
        assert_eq!(canonical_phrase(phrase).unwrap(), phrase);
        assert_eq!(
            canonical_phrase("  abaisser\tabandon abdiquer\nabeille abolir aborder  ").unwrap(),
            phrase
        );
        assert!(canonical_phrase("abaisser abandon abdiquer abeille abolir").is_err());
        assert!(canonical_phrase(&"a".repeat(RAW_PHRASE_MAX_BYTES + 1)).is_err());
    }

    #[test]
    fn recovery_code_round_trip_rejects_noncanonical_or_bad_checksum() {
        let raw = [0x5a_u8; 32];
        let displayed = format_recovery_code(&raw);
        assert_eq!(displayed.split('-').count(), 9);
        assert_eq!(parse_recovery_code(&displayed).unwrap().as_slice(), raw);
        assert_eq!(
            parse_recovery_code(&displayed.replace('-', "").to_ascii_lowercase())
                .unwrap()
                .as_slice(),
            raw
        );
        let mut invalid = displayed.into_bytes();
        let last = invalid.len() - 1;
        invalid[last] = if invalid[last] == b'A' { b'B' } else { b'A' };
        assert!(parse_recovery_code(std::str::from_utf8(&invalid).unwrap()).is_err());
    }

    #[test]
    fn initialization_is_confirmed_before_durable_state_exists() {
        let directory = tempfile::tempdir().unwrap();
        let state_path = directory.path().join("state");
        let mut core = ConsoleCore::new(state_path.clone());
        assert_eq!(core.status().unwrap().lock_state, "uninitialized");
        let generated = core.prepare().unwrap();
        let original_unlock_phrase = generated.unlock_phrase.clone();
        let original_recovery_code = generated.recovery_code.clone();
        assert!(!state_path.exists());
        assert!(core
            .confirm_initialization(
                &generated.generation_id,
                generated.unlock_phrase.clone(),
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                true,
            )
            .is_err());
        assert!(!state_path.exists());
        let status = core
            .confirm_initialization(
                &generated.generation_id,
                generated.unlock_phrase.clone(),
                generated.recovery_code,
                true,
            )
            .unwrap();
        assert_eq!(status.lock_state, "unlocked");
        let association = AssociationRecord {
            summary: AssociationSummary {
                controller_id: "123e4567-e89b-42d3-a456-426614174001".to_owned(),
                infrastructure_id: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
                infrastructure_label: None,
                origin: "https://controller.123e4567-e89b-42d3-a456-426614174000.v0-0-3.your-cloud.test:9443".to_owned(),
                device_status: "active".to_owned(),
                certificate_expires_at: Some("2027-01-01T00:00:00Z".to_owned()),
            },
            device_id: "123e4567-e89b-42d3-a456-426614174002".to_owned(),
            server_ca_pem: "ca".to_owned(),
            server_spki_sha256: "0".repeat(64),
            device_private_key_pem: "key".to_owned(),
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
		};
        core.store_association(association.clone(), false).unwrap();
        assert_eq!(core.status().unwrap().associations.len(), 1);
        let prepared = core.prepare_recovery_rotation().unwrap();
        assert!(core
            .confirm_recovery_rotation(
                &prepared.generation_id,
                prepared.new_recovery_code.clone(),
                false,
            )
            .is_err());
        let progress = core
            .confirm_recovery_rotation(
                &prepared.generation_id,
                prepared.new_recovery_code.clone(),
                true,
            )
            .unwrap();
        assert_eq!(progress.controllers.len(), 1);
        assert_eq!(progress.controllers[0].status, "pending");
        let (resumed, _) = core
            .recovery_rotation(&original_recovery_code, &prepared.new_recovery_code)
            .unwrap();
        assert_eq!(resumed, progress);
        let mut rotated = association;
        rotated.recovery_epoch = progress.controllers[0].target_recovery_epoch;
        rotated.recovery_salt = URL_SAFE_NO_PAD.encode([3_u8; 32]);
        let completed = core
            .record_recovery_rotation_result(
                Some(rotated),
                &progress.controllers[0].infrastructure_id,
                true,
            )
            .unwrap();
        assert_eq!(completed.controllers[0].status, "completed");
        core.lock();
        assert_eq!(core.status().unwrap().lock_state, "locked");
        assert!(core
            .unlock("abaisser abandon abdiquer abeille abolir aborder".to_owned())
            .is_err());
        let reopened = core.unlock(original_unlock_phrase.clone()).unwrap();
        assert_eq!(reopened.lock_state, "unlocked");
        assert_eq!(reopened.associations.len(), 1);
        assert_eq!(
            reopened.recovery_rotation.unwrap().controllers[0].status,
            "completed"
        );
        core.complete_recovery_rotation().unwrap();
        assert!(core.status().unwrap().recovery_rotation.is_none());

        let previous_metadata = read_metadata(&state_path.join(METADATA_FILE)).unwrap();
        let (_, previous_snapshot) = previous_metadata.validate().unwrap();
        let first_change = core.prepare_phrase_change().unwrap();
        assert!(core
            .confirm_phrase_change(
                &first_change.generation_id,
                "abaisser abandon abdiquer abeille abolir aborder".to_owned(),
                first_change.new_unlock_phrase,
            )
            .is_err());
        core.lock();
        assert_eq!(
            core.unlock(original_unlock_phrase.clone())
                .unwrap()
                .lock_state,
            "unlocked"
        );

        core.pending_phrase_change = Some(PendingPhraseChange {
            generation_id: "same-phrase".to_owned(),
            phrase: Zeroizing::new(original_unlock_phrase.clone()),
        });
        assert!(matches!(
            core.confirm_phrase_change(
                "same-phrase",
                original_unlock_phrase.clone(),
                original_unlock_phrase.clone(),
            ),
            Err(VaultError::InvalidInput)
        ));

        let second_change = core.prepare_phrase_change().unwrap();
        let next_unlock_phrase = second_change.new_unlock_phrase.clone();
        core.confirm_phrase_change(
            &second_change.generation_id,
            original_unlock_phrase.clone(),
            second_change.new_unlock_phrase,
        )
        .unwrap();
        let next_metadata = read_metadata(&state_path.join(METADATA_FILE)).unwrap();
        let (_, next_snapshot) = next_metadata.validate().unwrap();
        assert_ne!(previous_snapshot, next_snapshot);
        assert!(!state_path.join(previous_snapshot).exists());
        assert!(state_path.join(next_snapshot).exists());
        core.lock();
        assert!(core.unlock(original_unlock_phrase).is_err());
        let reopened = core.unlock(next_unlock_phrase).unwrap();
        assert_eq!(reopened.associations.len(), 1);
    }
}
