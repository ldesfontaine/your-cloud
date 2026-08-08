//! The third door of the product, on the side that writes and displays its one
//! document: the definition a user writes for a service the product does not
//! know.
//!
//! A definition is inert. Validating, canonising and hashing one creates no
//! account, no directory, no unit and no plan, and this module contacts nothing:
//! it turns bytes into a bounded value, one canonical spelling and one digest.
//! Every effect continues to be born of a plan a human approved, and a plan only
//! ever pins a definition by that digest.
//!
//! Nothing here depends on the plan schemas, and nothing here is a plan. The two
//! documents share their procedures — one bounded strict JSON document, one
//! domain-separated binary transcript, one SHA-256 over the transcript rather
//! than over the received bytes — and they share no field, no bound and no
//! domain, so neither can ever grow because the other did.
//!
//! **The transcript below is the counterpart of the one written on the
//! Controller side**, in `internal/servicedefinition/definition.go`. The two are
//! held against one another by deterministic vectors on both sides rather than
//! by reading, because a canonical encoding that exists in two implementations
//! is only canonical while the two agree byte for byte.
//!
//! The layout is:
//!
//! ```text
//! domain  "your-cloud/service-definition.v1\0"
//! then    schema_version                 on 1 byte
//!         slug, image_repository         as uint32 length-prefixed fields
//!         container_port                 as a uint32 big-endian
//! then the four lists, always all four and always in this order:
//!         volumes, tmpfs, environment, secret_keys
//!         each one a uint32 big-endian count, followed by exactly that many
//!         uint32 length-prefixed fields, in the order the document declares
//! ```
//!
//! A count-prefixed sequence is what makes a list unambiguous without a
//! separator: nothing inside an element can be read as the end of it, because
//! the reader knows how many fields follow before it reads any, and each of
//! those fields announces its own length. Every list is written even when it is
//! empty — as a count of zero — so the four counts are always at determined
//! offsets and no document can be read as another with one list shifted into the
//! next.
//!
//! An environment line travels whole rather than split into a key and a value.
//! The key grammar excludes the separator, so splitting a line at its first `=`
//! is a function of the line and nothing is lost by hashing the line itself —
//! and one field instead of two is one fewer place for the two implementations
//! to disagree.
//!
//! The order of a list is the order the document declares, and the digest covers
//! it. Two definitions that differ only by the order of a list are two documents
//! and two digests, exactly as two definitions differing by a value are: this
//! module freezes what its author wrote rather than a reordering of it, so that
//! re-reading a frozen definition returns the bytes that were frozen.

use crate::{
    approval::{append_field, decode_digest},
    plan::encode_lower_hex,
    ProtocolError,
};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

/// The one definition version this palier reads and writes.
pub const SERVICE_DEFINITION_SCHEMA_VERSION: u8 = 1;

/// Separates a definition digest from every plan transcript of the product and
/// from every other transcript of it. Its terminating NUL cannot appear in any
/// textual field, so no prefix of one transcript is a prefix of another.
pub const SERVICE_DEFINITION_TRANSCRIPT_DOMAIN: &[u8] = b"your-cloud/service-definition.v1\0";

/// What a definition digest is, in bytes. It is declared here rather than read
/// from a plan module because a definition is not a plan and this contract
/// depends on no plan schema: the two happen to hash with the same function, and
/// that is not a reason for one to move when the other does.
pub const SERVICE_DEFINITION_DIGEST_BYTES: usize = 32;

/// Bounds a definition before it is parsed.
///
/// It is the bound of the contract and it is its own: a definition carries lists
/// no plan has ever carried, and this is twice the plan bound while staying
/// small enough for the Console to always display the whole document. The two
/// bounds are separate so that neither document grows one day because the other
/// did.
pub const MAX_SERVICE_DEFINITION_BYTES: usize = 8_192;

/// The whole reason the slug is narrower than the archive slot whose grammar it
/// borrows. The derived account is `your-cloud-user-<slug>` and must fit the
/// thirty-two characters a user name of the machine has; the prefix consumes
/// exactly sixteen of them, and the derivation never truncates — so two distinct
/// slugs are two distinct accounts by construction rather than by vigilance.
pub const MAX_SERVICE_SLUG_CHARS: usize = 16;

/// Bounds the repository a definition names. It is the bound a repository name
/// has in the distribution specification, applied here so that the field is
/// bounded on its own rather than only by the document.
pub const MAX_IMAGE_REPOSITORY_BYTES: usize = 255;

/// Bound the port the image listens on inside its own namespace. The range opens
/// at 1 and not at 1024: a container port is not a port of the host, and the
/// privilege a low one used to require is a sysctl the placement derives from
/// this very field.
pub const MIN_CONTAINER_PORT: u32 = 1;
pub const MAX_CONTAINER_PORT: u32 = 65_535;

/// Bound how many container paths one definition declares, on each of the two
/// lists.
pub const MAX_SERVICE_VOLUMES: usize = 8;
pub const MAX_SERVICE_TMPFS: usize = 8;

/// Bounds one declared container path.
pub const MAX_CONTAINER_PATH_BYTES: usize = 253;

/// Bound the inert configuration and the names of the values the machine will
/// generate.
pub const MAX_SERVICE_ENVIRONMENT_LINES: usize = 32;
pub const MAX_SERVICE_SECRET_KEYS: usize = 16;

/// Bound the two halves of an environment line.
pub const MAX_ENVIRONMENT_KEY_CHARS: usize = 64;
pub const MAX_ENVIRONMENT_VALUE_BYTES: usize = 512;

/// The one interpolation a definition may carry, and the one sequence in which a
/// brace may appear in a value. There is no other template and no escape: a
/// brace anywhere else is a named refusal rather than a syntax a later palier
/// would have to keep accepting.
pub const ORIGIN_HOST_PLACEHOLDER: &str = "{origin_host}";

/// The four names a definition may not take.
///
/// The reason is stronger than a collision of names: an archive operation names
/// a service by its `service_profile` field, and the third door shares that
/// namespace with the profiles the product delivers. Reserving the four names at
/// the source is what makes one name designate exactly one door — a lookup that
/// succeeds on one side only, rather than a comparison someone has to remember
/// to write.
///
/// They are spelled here rather than imported from the plan modules, because a
/// definition is not a plan and this contract depends on no plan schema. Holding
/// the two lists against one another belongs where both are already in scope:
/// the Controller that serves the two doors.
pub const RESERVED_SERVICE_SLUGS: [&str; 4] = ["bentopdf", "vaultwarden", "probe", "entrypoint"];

/// One definition of a user service. The declaration order below is the
/// canonical encoding order and the transcript order at once, and no field of a
/// definition lives outside it.
///
/// Everything the machine owns is absent on purpose. A definition names no
/// account, no host path, no home, no egress table and no secret value: all of
/// those are derived from the slug by the machine that acts, and no field here
/// can move any of them.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceDefinitionDocument {
    pub schema_version: u8,
    /// The name of the service, and the only value everything else derives from.
    pub slug: String,
    /// Where the images of this service come from — never which one.
    pub image_repository: String,
    /// The port the image listens on inside its own namespace.
    pub container_port: u32,
    /// What must survive the container.
    #[serde(default, deserialize_with = "list_or_null")]
    pub volumes: Vec<String>,
    /// The scratch in memory the image requires under a read-only root.
    #[serde(default, deserialize_with = "list_or_null")]
    pub tmpfs: Vec<String>,
    /// The inert configuration, displayed everywhere the definition is.
    #[serde(default, deserialize_with = "list_or_null")]
    pub environment: Vec<String>,
    /// The names of the secrets the machine will generate — never a value.
    #[serde(default, deserialize_with = "list_or_null")]
    pub secret_keys: Vec<String>,
}

/// The one place a list that was never declared becomes an empty one, so that
/// the canonical spelling of a definition does not depend on how its author left
/// a list out.
///
/// A list nobody declared, a list spelled `null` and a list spelled empty
/// describe the same state, so they are one definition with one digest, and the
/// canonical spelling of all three is the empty array. Nothing else in the
/// document has a second accepted spelling: a value of any other shape — a
/// string, an object, a number — is still refused here, because this reads an
/// optional list and not an optional anything.
fn list_or_null<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<Vec<String>>::deserialize(deserializer)?.unwrap_or_default())
}

/// The field of a definition one refusal belongs to, named in the declaration
/// order of the document.
///
/// It exists so that a form can put a refusal beside the input that caused it
/// instead of beside the document as a whole. It is the shape of the contract
/// and never a shape of a screen: nothing here knows that a field is an input,
/// and a caller that renders none of them still reads the same verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceDefinitionField {
    SchemaVersion,
    Slug,
    ImageRepository,
    ContainerPort,
    Volumes,
    Tmpfs,
    Environment,
    SecretKeys,
    /// The whole document rather than one of its fields. A definition whose
    /// every field is inside its own bounds and which still does not fit the
    /// bound of the document is refused by the document, and no single field is
    /// the one to blame.
    Document,
}

/// Why one field is outside the contract, as a closed list of named refusals.
///
/// A closed list rather than a message: what a human reads is written where the
/// product speaks to humans, in one sentence per name, and a name added here
/// without its sentence is a hole a caller can be held against. Nothing in this
/// module renders a word of French, and nothing in it decides what a refusal
/// looks like.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceDefinitionRefusal {
    /// A version this palier does not read.
    UnknownSchemaVersion,
    /// Outside the grammar the derived account is bounded by.
    SlugGrammar,
    /// One of the four names the product already owns.
    SlugReserved,
    /// A repository naming which image rather than where images come from: a
    /// tag or a digest. It is told apart from a plain malformation because it is
    /// the most likely mistake a human makes — pasting the reference they pull
    /// with.
    ImageRepositoryPinned,
    /// Outside the grammar of a repository.
    ImageRepositoryGrammar,
    /// Outside `1..=65535`.
    ContainerPortRange,
    /// More entries than the list admits.
    ListTooLong,
    /// Not one absolute, normalised, lower-case container path.
    ContainerPathGrammar,
    /// Two mounts where one opens or is the other. Two overlapping mounts would
    /// be two writes whose order decided the result, and the order is not a
    /// field.
    MountsOverlap,
    /// An environment entry that is not a `KEY=value` line at all.
    EnvironmentLineShape,
    /// Outside the one grammar an environment key and a secret key share.
    KeyGrammar,
    /// Outside printable ASCII, above its bound, or carrying a brace anywhere
    /// but in the one interpolation this product has.
    ValueGrammar,
    /// A name already taken by another line or by the other list: one key is one
    /// name in one namespace.
    KeyAlreadyDeclared,
    /// Every field is inside its own bounds and the document is still above
    /// [`MAX_SERVICE_DEFINITION_BYTES`]. The cardinals and the byte bounds are
    /// separate rules, and a definition has to hold both.
    DocumentTooLarge,
}

/// One named refusal, on the field and — inside a list — on the entry it
/// belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ServiceDefinitionFieldRefusal {
    pub field: ServiceDefinitionField,
    /// The index of the entry inside its list, and `None` for a field that is
    /// not one.
    pub entry: Option<usize>,
    pub refusal: ServiceDefinitionRefusal,
}

impl ServiceDefinitionFieldRefusal {
    fn of(
        field: ServiceDefinitionField,
        entry: Option<usize>,
        refusal: ServiceDefinitionRefusal,
    ) -> Self {
        Self {
            field,
            entry,
            refusal,
        }
    }
}

impl ServiceDefinitionDocument {
    /// Holds a definition against the whole contract of the palier.
    ///
    /// It never returns a partially checked definition: a caller that holds one
    /// may assume every field is inside the bounds of the contract and that the
    /// two lists of container paths do not overlap.
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if !self.holds_the_contract() {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(self)
    }

    /// Every way this definition is outside the contract, named one by one.
    ///
    /// It is the same contract [`Self::validate`] holds a document against, read
    /// through the same predicates rather than through a second reading of them:
    /// a definition has no refusal exactly when it validates, and a test states
    /// that equivalence over every table of this module rather than leaving it
    /// to be believed. What this adds is *where* and *why*, which is the whole
    /// of what a form needs to answer a human before they submit anything.
    ///
    /// Unlike validation it does not stop at the first refusal: a human who
    /// fixes one field and discovers the next is being told the contract one
    /// sentence per attempt, which is a worse way of learning bounds than being
    /// shown them at once.
    pub fn refusals(&self) -> Vec<ServiceDefinitionFieldRefusal> {
        use ServiceDefinitionField as Field;
        use ServiceDefinitionRefusal as Why;

        let mut refusals = Vec::new();
        if self.schema_version != SERVICE_DEFINITION_SCHEMA_VERSION {
            refusals.push(ServiceDefinitionFieldRefusal::of(
                Field::SchemaVersion,
                None,
                Why::UnknownSchemaVersion,
            ));
        }
        if !canonical_service_slug(&self.slug) {
            refusals.push(ServiceDefinitionFieldRefusal::of(
                Field::Slug,
                None,
                Why::SlugGrammar,
            ));
        } else if RESERVED_SERVICE_SLUGS.contains(&self.slug.as_str()) {
            refusals.push(ServiceDefinitionFieldRefusal::of(
                Field::Slug,
                None,
                Why::SlugReserved,
            ));
        }
        if !canonical_image_repository(&self.image_repository) {
            refusals.push(ServiceDefinitionFieldRefusal::of(
                Field::ImageRepository,
                None,
                if image_repository_names_one_image(&self.image_repository) {
                    Why::ImageRepositoryPinned
                } else {
                    Why::ImageRepositoryGrammar
                },
            ));
        }
        if !(MIN_CONTAINER_PORT..=MAX_CONTAINER_PORT).contains(&self.container_port) {
            refusals.push(ServiceDefinitionFieldRefusal::of(
                Field::ContainerPort,
                None,
                Why::ContainerPortRange,
            ));
        }
        self.mount_refusals(&mut refusals);
        self.environment_refusals(&mut refusals);
        // The bound of the document is the last thing read, and only when every
        // field holds: a definition whose cardinals are all licit and whose
        // bytes are not is refused by the document rather than by a field, and
        // saying so on a field would send a human to shorten the wrong one.
        if refusals.is_empty() && self.encode().is_err() {
            refusals.push(ServiceDefinitionFieldRefusal::of(
                Field::Document,
                None,
                Why::DocumentTooLarge,
            ));
        }
        refusals
    }

    /// The two lists of container paths, then the two held against one another
    /// as one list, in the order [`Self::holds_the_mounts`] reads them.
    fn mount_refusals(&self, refusals: &mut Vec<ServiceDefinitionFieldRefusal>) {
        use ServiceDefinitionField as Field;
        use ServiceDefinitionRefusal as Why;

        if self.volumes.len() > MAX_SERVICE_VOLUMES {
            refusals.push(ServiceDefinitionFieldRefusal::of(
                Field::Volumes,
                None,
                Why::ListTooLong,
            ));
        }
        if self.tmpfs.len() > MAX_SERVICE_TMPFS {
            refusals.push(ServiceDefinitionFieldRefusal::of(
                Field::Tmpfs,
                None,
                Why::ListTooLong,
            ));
        }
        // The union is what the overlap rule is stated on, so the two lists walk
        // as one sequence that remembers which side each entry came from.
        let declared: Vec<(Field, usize, &String)> = self
            .volumes
            .iter()
            .enumerate()
            .map(|(index, path)| (Field::Volumes, index, path))
            .chain(
                self.tmpfs
                    .iter()
                    .enumerate()
                    .map(|(index, path)| (Field::Tmpfs, index, path)),
            )
            .collect();
        let mut accepted: Vec<(Field, usize, Vec<&str>)> = Vec::with_capacity(declared.len());
        for (field, index, path) in declared {
            match canonical_container_path(path) {
                Some(segments) => accepted.push((field, index, segments)),
                None => refusals.push(ServiceDefinitionFieldRefusal::of(
                    field,
                    Some(index),
                    Why::ContainerPathGrammar,
                )),
            }
        }
        // An overlap is a property of a pair, and it is reported on the later of
        // the two entries: the earlier one is the mount that was already
        // declared, so the entry a human has to change is the one that arrived
        // beside it.
        for (position, (field, index, entry)) in accepted.iter().enumerate() {
            if accepted[..position]
                .iter()
                .any(|(_, _, other)| opens_or_equals(entry, other) || opens_or_equals(other, entry))
            {
                refusals.push(ServiceDefinitionFieldRefusal::of(
                    *field,
                    Some(*index),
                    Why::MountsOverlap,
                ));
            }
        }
    }

    /// The inert configuration and the names of the generated secrets, in the
    /// order [`Self::holds_the_environment`] reads them and against the one
    /// namespace they share.
    fn environment_refusals(&self, refusals: &mut Vec<ServiceDefinitionFieldRefusal>) {
        use ServiceDefinitionField as Field;
        use ServiceDefinitionRefusal as Why;

        if self.environment.len() > MAX_SERVICE_ENVIRONMENT_LINES {
            refusals.push(ServiceDefinitionFieldRefusal::of(
                Field::Environment,
                None,
                Why::ListTooLong,
            ));
        }
        if self.secret_keys.len() > MAX_SERVICE_SECRET_KEYS {
            refusals.push(ServiceDefinitionFieldRefusal::of(
                Field::SecretKeys,
                None,
                Why::ListTooLong,
            ));
        }
        let mut declared: Vec<&str> =
            Vec::with_capacity(self.environment.len() + self.secret_keys.len());
        for (index, line) in self.environment.iter().enumerate() {
            let Some((key, value)) = line.split_once('=') else {
                refusals.push(ServiceDefinitionFieldRefusal::of(
                    Field::Environment,
                    Some(index),
                    Why::EnvironmentLineShape,
                ));
                continue;
            };
            if !canonical_environment_key(key) {
                refusals.push(ServiceDefinitionFieldRefusal::of(
                    Field::Environment,
                    Some(index),
                    Why::KeyGrammar,
                ));
            } else if declared.contains(&key) {
                refusals.push(ServiceDefinitionFieldRefusal::of(
                    Field::Environment,
                    Some(index),
                    Why::KeyAlreadyDeclared,
                ));
            } else {
                declared.push(key);
            }
            if !canonical_environment_value(value) {
                refusals.push(ServiceDefinitionFieldRefusal::of(
                    Field::Environment,
                    Some(index),
                    Why::ValueGrammar,
                ));
            }
        }
        for (index, key) in self.secret_keys.iter().enumerate() {
            if !canonical_environment_key(key) {
                refusals.push(ServiceDefinitionFieldRefusal::of(
                    Field::SecretKeys,
                    Some(index),
                    Why::KeyGrammar,
                ));
            } else if declared.contains(&key.as_str()) {
                refusals.push(ServiceDefinitionFieldRefusal::of(
                    Field::SecretKeys,
                    Some(index),
                    Why::KeyAlreadyDeclared,
                ));
            } else {
                declared.push(key);
            }
        }
    }

    /// Whether any line of this definition consumes the one interpolation the
    /// product has.
    ///
    /// It is the counterpart of `Document.InterpolatesOriginHost` on the
    /// Controller side, and it decides a presence rather than a value: a plan
    /// pinning this definition carries an origin exactly when this answers yes.
    /// The Console reads it to say, before a freeze, that approving a deployment
    /// of this revision will mean approving a name.
    pub fn interpolates_origin_host(&self) -> bool {
        self.environment
            .iter()
            .any(|line| line.contains(ORIGIN_HOST_PLACEHOLDER))
    }

    /// Renders the one canonical encoding of a definition.
    ///
    /// A transport may reindent what it carries without changing the definition
    /// — the digest is rebuilt from the fields, not from the bytes — but there
    /// is exactly one spelling, so that the document a human is shown, the
    /// document an Auxiliary receives and the document a digest was taken over
    /// are the same bytes rather than three encodings that happen to agree.
    ///
    /// The four lists are always rendered, an empty one as an empty array.
    pub fn encode(&self) -> Result<String, ProtocolError> {
        if !self.holds_the_contract() {
            return Err(ProtocolError::InvalidInput);
        }
        let encoded = serde_json::to_string(self).map_err(|_| ProtocolError::InvalidInput)?;
        // The bound is required again after the rendering rather than trusted
        // from the fields: a definition that validates and still does not fit is
        // refused rather than transported.
        if encoded.is_empty() || encoded.len() > MAX_SERVICE_DEFINITION_BYTES {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(encoded)
    }

    /// Rebuilds the exact bytes a definition digest is taken over, in the layout
    /// documented at the head of this file.
    ///
    /// It is built from the parsed fields and never from a received document, so
    /// two implementations that read the same definition produce the same
    /// digest, a transport that reshapes the JSON transports the same
    /// definition, and a transport that changes one value transports a
    /// definition whose digest no longer matches the plan that pinned it.
    pub fn transcript(&self) -> Result<Vec<u8>, ProtocolError> {
        if !self.holds_the_contract() {
            return Err(ProtocolError::InvalidInput);
        }
        self.raw_transcript()
    }

    /// The raw digest of that transcript.
    pub fn digest(&self) -> Result<[u8; SERVICE_DEFINITION_DIGEST_BYTES], ProtocolError> {
        let mut digest = [0_u8; SERVICE_DEFINITION_DIGEST_BYTES];
        digest.copy_from_slice(Sha256::digest(self.transcript()?).as_slice());
        Ok(digest)
    }

    /// The lower-case hexadecimal value a plan names as `definition_digest`, in
    /// the exact spelling that field requires.
    pub fn sha256(&self) -> Result<String, ProtocolError> {
        Ok(encode_lower_hex(&self.digest()?))
    }

    /// The hashed bytes, laid out without holding the document to the contract
    /// first.
    ///
    /// It exists apart from [`Self::transcript`] so that the layout can be
    /// stated on documents validation would refuse: a test that moves one field
    /// out of its bounds is testing the layout, and it must not be answered by
    /// validation refusing the subject before the bytes are built.
    fn raw_transcript(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut transcript = Vec::with_capacity(
            SERVICE_DEFINITION_TRANSCRIPT_DOMAIN.len() + MAX_SERVICE_DEFINITION_BYTES / 8,
        );
        transcript.extend_from_slice(SERVICE_DEFINITION_TRANSCRIPT_DOMAIN);
        transcript.extend_from_slice(&self.schema_version.to_be_bytes());
        append_field(&mut transcript, self.slug.as_bytes())?;
        append_field(&mut transcript, self.image_repository.as_bytes())?;
        transcript.extend_from_slice(&self.container_port.to_be_bytes());
        append_list(&mut transcript, &self.volumes)?;
        append_list(&mut transcript, &self.tmpfs)?;
        append_list(&mut transcript, &self.environment)?;
        append_list(&mut transcript, &self.secret_keys)?;
        Ok(transcript)
    }

    /// The whole contract, read from the top down as the contract is written:
    /// the version, the name, where the images come from, the port the image
    /// listens on, then the two lists of paths held against one another, then
    /// the two lists of keys held against one another.
    ///
    /// Nothing here looks at a machine, and nothing here has an effect.
    fn holds_the_contract(&self) -> bool {
        self.schema_version == SERVICE_DEFINITION_SCHEMA_VERSION
            && canonical_definition_slug(&self.slug)
            && canonical_image_repository(&self.image_repository)
            && (MIN_CONTAINER_PORT..=MAX_CONTAINER_PORT).contains(&self.container_port)
            && self.holds_the_mounts()
            && self.holds_the_environment()
    }

    /// Holds the two lists of container paths, then holds them against one
    /// another as one list.
    ///
    /// The union is what the contract bounds, and it has to be: two mounts that
    /// overlap would be two writes whose order decides the result, and the order
    /// is not a field.
    fn holds_the_mounts(&self) -> bool {
        if self.volumes.len() > MAX_SERVICE_VOLUMES || self.tmpfs.len() > MAX_SERVICE_TMPFS {
            return false;
        }
        let mut declared: Vec<Vec<&str>> =
            Vec::with_capacity(self.volumes.len() + self.tmpfs.len());
        for path in self.volumes.iter().chain(self.tmpfs.iter()) {
            match canonical_container_path(path) {
                Some(segments) => declared.push(segments),
                None => return false,
            }
        }
        for (index, entry) in declared.iter().enumerate() {
            for other in &declared[index + 1..] {
                if opens_or_equals(entry, other) || opens_or_equals(other, entry) {
                    return false;
                }
            }
        }
        true
    }

    /// Holds the inert configuration and the names of the generated secrets, and
    /// holds the two against one another.
    ///
    /// They are validated together because the rule that matters is shared: one
    /// key is one name in one namespace. A key declared twice would let the
    /// order of the list decide which value the container receives, and a key
    /// that is at once an environment line and a secret would be a value
    /// displayed everywhere the definition is displayed and a value the machine
    /// generates and never shows — the two cannot be the same name.
    fn holds_the_environment(&self) -> bool {
        if self.environment.len() > MAX_SERVICE_ENVIRONMENT_LINES
            || self.secret_keys.len() > MAX_SERVICE_SECRET_KEYS
        {
            return false;
        }
        let mut declared: Vec<&str> =
            Vec::with_capacity(self.environment.len() + self.secret_keys.len());
        for line in &self.environment {
            let Some((key, value)) = line.split_once('=') else {
                return false;
            };
            if !canonical_environment_key(key)
                || !canonical_environment_value(value)
                || declared.contains(&key)
            {
                return false;
            }
            declared.push(key);
        }
        for key in &self.secret_keys {
            if !canonical_environment_key(key) || declared.contains(&key.as_str()) {
                return false;
            }
            declared.push(key);
        }
        true
    }
}

/// Accepts one bounded, strict, fully validated definition.
///
/// The bound is applied before parsing, exactly one JSON value is accepted, a
/// repeated key is a refusal, an undeclared field is a refusal before its value
/// is read, and every field must appear under its exact canonical name.
pub fn decode_service_definition_document(
    document: &[u8],
) -> Result<ServiceDefinitionDocument, ProtocolError> {
    if document.is_empty() || document.len() > MAX_SERVICE_DEFINITION_BYTES {
        return Err(ProtocolError::InvalidInput);
    }
    let parsed: ServiceDefinitionDocument =
        serde_json::from_slice(document).map_err(|_| ProtocolError::InvalidInput)?;
    parsed.validate()
}

/// Accepts one received definition only if it is the definition its digest
/// names.
///
/// This is the whole reason a definition travels as its exact canonical bytes
/// beside its digest: the digest is rebuilt here from the fields that were
/// parsed out of those very bytes, so a transport can reindent what it carries
/// and can change nothing in it. A definition altered by one byte no longer
/// carries the `definition_digest` a plan pinned, and is refused before anything
/// displays it.
pub fn verify_service_definition_document(
    document: &[u8],
    expected_sha256: &str,
) -> Result<ServiceDefinitionDocument, ProtocolError> {
    let expected = decode_digest(expected_sha256).ok_or(ProtocolError::InvalidInput)?;
    let parsed = decode_service_definition_document(document)?;
    if parsed.digest()? != expected {
        return Err(ProtocolError::InvalidInput);
    }
    Ok(parsed)
}

/// Writes one list as the count of its elements followed by the elements
/// themselves, which is what makes the four lists readable in sequence without a
/// separator any element could contain.
fn append_list(buffer: &mut Vec<u8>, entries: &[String]) -> Result<(), ProtocolError> {
    let count = u32::try_from(entries.len()).map_err(|_| ProtocolError::InvalidInput)?;
    buffer.extend_from_slice(&count.to_be_bytes());
    for entry in entries {
        append_field(buffer, entry.as_bytes())?;
    }
    Ok(())
}

/// The grammar of `snapshot_slot` narrowed to sixteen characters: lower-case
/// letters, digits and hyphens, opening on a letter or a digit.
///
/// There is no dot and no separator inside those bounds, so a slug is always
/// exactly one name and never a path something derived from it could climb out
/// of.
fn canonical_service_slug(slug: &str) -> bool {
    let bytes = slug.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_SERVICE_SLUG_CHARS {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// The whole of what a definition may be filed under: the grammar above, and
/// none of the four names the product already owns.
///
/// It is one function rather than two conditions written side by side, because
/// the plan schema of the third door reads the very same rule: a plan naming a
/// definition may never name something no definition could exist under, and an
/// archive naming a slug may never name one of the four either. Spelling it once
/// is what keeps the two sides from drifting into two grammars for one name.
pub(crate) fn canonical_definition_slug(slug: &str) -> bool {
    canonical_service_slug(slug) && !RESERVED_SERVICE_SLUGS.contains(&slug)
}

/// Requires where the images come from, and refuses to be told which one.
///
/// It is shared with the plan schema of the third door for the reason
/// [`canonical_definition_slug`] is: the `image_reference` of a user service plan
/// must be exactly the repository of the definition it pins, so that field is
/// bounded by this very rule rather than by a second one that would have to keep
/// agreeing with it.
///
/// The tag and the digest are refused before the grammar is read, so that the
/// most likely mistake a human makes — pasting the reference they pull with — is
/// answered by the rule rather than by a generic malformation. The digest of an
/// instance lives in the plan that deploys it, and updating a service is a new
/// plan whose digest differs, never a silent mutation of what a definition
/// names.
pub(crate) fn canonical_image_repository(repository: &str) -> bool {
    if repository.is_empty() || repository.len() > MAX_IMAGE_REPOSITORY_BYTES {
        return false;
    }
    if repository.contains('@') {
        return false;
    }
    let last_component = match repository.rsplit_once('/') {
        Some((_, last)) => last,
        None => repository,
    };
    if last_component.contains(':') {
        return false;
    }
    let Some((registry, path)) = repository.split_once('/') else {
        return false;
    };
    // A first component that carries neither a dot nor a port is a name, not a
    // registry: what it resolves to would be decided by the search list of
    // whatever daemon pulls it, which is a second and movable truth beside the
    // digest the plan pins.
    if !registry.contains('.') && !registry.contains(':') {
        return false;
    }
    canonical_registry_host(registry) && canonical_repository_path(path)
}

/// Whether a rejected repository was rejected for naming *which* image.
///
/// It reads the two suffixes [`canonical_image_repository`] refuses before it
/// reads any grammar — a digest anywhere, a tag on the last component — and it
/// exists only so that the most likely mistake a human makes can be answered by
/// the rule they broke instead of by a generic malformation. It decides nothing:
/// a repository this returns `false` for is not thereby acceptable, and the one
/// function that admits a repository is still the one above.
fn image_repository_names_one_image(repository: &str) -> bool {
    if repository.contains('@') {
        return true;
    }
    let last_component = match repository.rsplit_once('/') {
        Some((_, last)) => last,
        None => repository,
    };
    last_component.contains(':')
}

/// The part of a repository that names where the images come from: a lower-case
/// host, optionally carrying the port of a registry that does not listen on the
/// usual one.
///
/// The host is one or more lower-case alphanumeric labels joined by single dots
/// or hyphens: it opens and closes on an alphanumeric and never carries two
/// separators in a row, which is what keeps one registry from having a second
/// spelling.
fn canonical_registry_host(registry: &str) -> bool {
    let (host, port) = match registry.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (registry, None),
    };
    if let Some(port) = port {
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
    }
    let bytes = host.as_bytes();
    let alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    if bytes.is_empty() || !alphanumeric(bytes[0]) || !alphanumeric(bytes[bytes.len() - 1]) {
        return false;
    }
    if !bytes
        .iter()
        .all(|byte| alphanumeric(*byte) || *byte == b'.' || *byte == b'-')
    {
        return false;
    }
    // A single separator between two labels, and never two: the grammar joins
    // labels rather than allowing a run of punctuation the host could be spelled
    // two ways with.
    !bytes
        .windows(2)
        .any(|pair| !alphanumeric(pair[0]) && !alphanumeric(pair[1]))
}

/// What follows the registry: one or more lower-case components of the
/// distribution specification's own grammar.
///
/// It admits neither a tag nor a digest, and it admits no upper case, which is
/// what keeps one repository from having two spellings. Inside a component a run
/// of dots, underscores and hyphens is admitted, exactly as the specification
/// admits it; a component may neither be empty nor open or close on one of them.
fn canonical_repository_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    path.split('/').all(|component| {
        let bytes = component.as_bytes();
        let alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
        !bytes.is_empty()
            && alphanumeric(bytes[0])
            && alphanumeric(bytes[bytes.len() - 1])
            && bytes
                .iter()
                .all(|byte| alphanumeric(*byte) || matches!(*byte, b'.' | b'_' | b'-'))
    })
}

/// Bounds one path inside the container, and returns the segments the overlap
/// rule is stated on.
///
/// Absolute, normalised and lower-case is the whole of it. A path that is not
/// normalised has a second spelling, and a second spelling of a mount is a
/// second digest for the same state; a path that climbs, or that is the root
/// itself, names something the definition has no business naming. The closed
/// character set excludes the colon that separates a mount specification, with
/// no escape existing anywhere.
fn canonical_container_path(path: &str) -> Option<Vec<&str>> {
    if !path.starts_with('/') || path == "/" || path.len() > MAX_CONTAINER_PATH_BYTES {
        return None;
    }
    if path.ends_with('/') {
        return None;
    }
    // Exactly one leading separator is removed, so a path opening on two of them
    // is read as an empty first segment and refused as one rather than quietly
    // becoming the path it was almost spelled as.
    let segments: Vec<&str> = path.strip_prefix('/')?.split('/').collect();
    for segment in &segments {
        if segment.is_empty() || *segment == "." || *segment == ".." {
            return None;
        }
        if !segment.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        }) {
            return None;
        }
    }
    Some(segments)
}

/// Whether the first path is the second or contains it, segment by segment.
///
/// Comparing segments rather than strings is what keeps `/srv/data` out of
/// `/srv` while leaving `/srvdata` beside `/srv` where it belongs.
fn opens_or_equals(outer: &[&str], inner: &[&str]) -> bool {
    outer.len() <= inner.len() && outer.iter().zip(inner).all(|(one, other)| one == other)
}

/// The grammar of both an environment key and a secret key.
///
/// They are one grammar because they are one namespace: the two lists are
/// required to be disjoint, and a name that could be spelled in one and not in
/// the other would make that requirement depend on which list it was written in.
fn canonical_environment_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_ENVIRONMENT_KEY_CHARS {
        return false;
    }
    if !bytes[0].is_ascii_uppercase() {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

/// Bounds one inert value and the one interpolation the product has.
///
/// The scan walks the value rather than searching it, so that the rule holds in
/// one direction only: a brace is accepted exactly when it opens the whole
/// sequence, and everything else — a truncated placeholder, an unknown name
/// between braces, a closing brace on its own — is refused at the byte where it
/// stops being the sequence. There is no escape to reach past it, which is what
/// keeps a value from ever becoming a template a later palier has to keep
/// evaluating. An empty value is licit.
fn canonical_environment_value(value: &str) -> bool {
    if value.len() > MAX_ENVIRONMENT_VALUE_BYTES {
        return false;
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let character = bytes[index];
        if !(0x20..=0x7e).contains(&character) {
            return false;
        }
        match character {
            b'{' => {
                if !value[index..].starts_with(ORIGIN_HOST_PLACEHOLDER) {
                    return false;
                }
                index += ORIGIN_HOST_PLACEHOLDER.len();
            }
            b'}' => return false,
            _ => index += 1,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The inputs of the reference vector. It is the definition of the synthetic
    /// application the proof of this milestone deploys — two volumes, one tmpfs,
    /// three inert lines one of which interpolates the origin, one generated
    /// secret — so that the vector proves the encoding of the shape the proof
    /// actually exercises rather than of a shape nothing uses.
    const VECTOR_SLUG: &str = "lab-notes";
    const VECTOR_IMAGE_REPOSITORY: &str = "registry.lab.your-cloud.test/your-cloud/lab-notes";
    const VECTOR_CONTAINER_PORT: u32 = 8_080;
    const VECTOR_DATA_VOLUME: &str = "/srv/notes";
    const VECTOR_STATE_VOLUME: &str = "/var/lib/lab-notes";
    const VECTOR_SCRATCH_TMPFS: &str = "/tmp";
    const VECTOR_TITLE_LINE: &str = "LAB_NOTES_TITLE=Your Cloud lab notes";
    const VECTOR_ORIGIN_LINE: &str = "LAB_NOTES_ORIGIN=https://{origin_host}/";
    const VECTOR_READ_ONLY_LINE: &str = "LAB_NOTES_READ_ONLY=1";
    const VECTOR_SECRET_KEY: &str = "LAB_NOTES_ADMIN_TOKEN";

    /// The inputs of the minimal vector: a definition that declares none of the
    /// four lists. It exists so that the empty count is pinned across the two
    /// implementations too, and it carries a low container port because that is
    /// the case a later palier reads a sysctl off.
    const VECTOR_MINIMAL_SLUG: &str = "minimal";
    const VECTOR_MINIMAL_IMAGE_REPOSITORY: &str = "registry.lab.your-cloud.test/minimal";
    const VECTOR_MINIMAL_CONTAINER_PORT: u32 = 80;

    /// The two canonical documents, byte for byte. They are the bytes
    /// `internal/servicedefinition/definition_test.go` pins as the ones the
    /// Controller emits, copied literally rather than rebuilt here.
    const VECTOR_REFERENCE_DOCUMENT: &str = concat!(
        r#"{"schema_version":1,"slug":"lab-notes","#,
        r#""image_repository":"registry.lab.your-cloud.test/your-cloud/lab-notes","#,
        r#""container_port":8080,"volumes":["/srv/notes","/var/lib/lab-notes"],"#,
        r#""tmpfs":["/tmp"],"environment":["LAB_NOTES_TITLE=Your Cloud lab notes","#,
        r#""LAB_NOTES_ORIGIN=https://{origin_host}/","LAB_NOTES_READ_ONLY=1"],"#,
        r#""secret_keys":["LAB_NOTES_ADMIN_TOKEN"]}"#,
    );
    const VECTOR_MINIMAL_DOCUMENT: &str = concat!(
        r#"{"schema_version":1,"slug":"minimal","#,
        r#""image_repository":"registry.lab.your-cloud.test/minimal","#,
        r#""container_port":80,"volumes":[],"tmpfs":[],"environment":[],"secret_keys":[]}"#,
    );

    /// The two transcripts, byte for byte, copied literally from
    /// `internal/servicedefinition/definition_test.go`. The Controller side pins
    /// the very same values from its own encoder, so a single byte of drift in
    /// either implementation fails here rather than producing definitions the
    /// other side hashes differently — which, on a real machine, is an Auxiliary
    /// refusing a plan the Controller froze.
    const VECTOR_REFERENCE_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f736572766963652d646566696e6974696f6e2e7631",
        "0001000000096c61622d6e6f7465730000003172656769737472792e6c61622e",
        "796f75722d636c6f75642e746573742f796f75722d636c6f75642f6c61622d6e",
        "6f74657300001f90000000020000000a2f7372762f6e6f746573000000122f76",
        "61722f6c69622f6c61622d6e6f74657300000001000000042f746d7000000003",
        "000000244c41425f4e4f5445535f5449544c453d596f757220436c6f7564206c",
        "6162206e6f746573000000274c41425f4e4f5445535f4f524947494e3d687474",
        "70733a2f2f7b6f726967696e5f686f73747d2f000000154c41425f4e4f544553",
        "5f524541445f4f4e4c593d3100000001000000154c41425f4e4f5445535f4144",
        "4d494e5f544f4b454e",
    );
    const VECTOR_MINIMAL_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f736572766963652d646566696e6974696f6e2e7631",
        "0001000000076d696e696d616c0000002472656769737472792e6c61622e796f",
        "75722d636c6f75642e746573742f6d696e696d616c0000005000000000000000",
        "000000000000000000",
    );

    /// The two digests a plan of this milestone names as `definition_digest`, in
    /// the exact spelling that field requires.
    const VECTOR_REFERENCE_SHA256: &str =
        "c0f30d7c7f8635d2fb56445d7b75c6523b440d35de8e1867444c788e4b30f3ce";
    const VECTOR_MINIMAL_SHA256: &str =
        "faf14b5c09ce83169466632fe2d37063453fe924154b6cc265b62fdd6aebd95c";

    fn vector_reference() -> ServiceDefinitionDocument {
        ServiceDefinitionDocument {
            schema_version: SERVICE_DEFINITION_SCHEMA_VERSION,
            slug: VECTOR_SLUG.into(),
            image_repository: VECTOR_IMAGE_REPOSITORY.into(),
            container_port: VECTOR_CONTAINER_PORT,
            volumes: vec![VECTOR_DATA_VOLUME.into(), VECTOR_STATE_VOLUME.into()],
            tmpfs: vec![VECTOR_SCRATCH_TMPFS.into()],
            environment: vec![
                VECTOR_TITLE_LINE.into(),
                VECTOR_ORIGIN_LINE.into(),
                VECTOR_READ_ONLY_LINE.into(),
            ],
            secret_keys: vec![VECTOR_SECRET_KEY.into()],
        }
    }

    fn vector_minimal() -> ServiceDefinitionDocument {
        ServiceDefinitionDocument {
            schema_version: SERVICE_DEFINITION_SCHEMA_VERSION,
            slug: VECTOR_MINIMAL_SLUG.into(),
            image_repository: VECTOR_MINIMAL_IMAGE_REPOSITORY.into(),
            container_port: VECTOR_MINIMAL_CONTAINER_PORT,
            volumes: Vec::new(),
            tmpfs: Vec::new(),
            environment: Vec::new(),
            secret_keys: Vec::new(),
        }
    }

    /// Encodes a document without validating it, which is what a hostile case
    /// needs: the refusal under test must come from the decoding rather than
    /// from the encoder refusing to produce the bytes in the first place.
    fn hostile(document: &ServiceDefinitionDocument) -> String {
        serde_json::to_string(document).expect("a definition is representable as JSON")
    }

    fn decoded_hex(value: &str) -> Vec<u8> {
        assert!(value.len() % 2 == 0, "a hex vector has even length");
        (0..value.len() / 2)
            .map(|index| {
                u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                    .expect("a hex vector is hexadecimal")
            })
            .collect()
    }

    fn numbered_paths(prefix: &str, count: usize) -> Vec<String> {
        (0..count)
            .map(|index| format!("{prefix}-{index}"))
            .collect()
    }

    fn numbered_keys(prefix: &str, count: usize) -> Vec<String> {
        (0..count)
            .map(|index| format!("{prefix}_{index}"))
            .collect()
    }

    fn numbered_environment(count: usize) -> Vec<String> {
        numbered_keys("LINE", count)
            .into_iter()
            .map(|key| format!("{key}=value"))
            .collect()
    }

    fn with_extra_member(document: &str, member: &str) -> String {
        format!("{},{member}}}", document.trim_end_matches('}'))
    }

    /// The interoperability proof of the definition encoding.
    ///
    /// Every transcript, every digest and every canonical document is pinned
    /// literally here and in `internal/servicedefinition/definition_test.go`.
    /// Reading the two encoders against one another would not be a proof;
    /// producing the same bytes from both is.
    #[test]
    fn the_deterministic_definition_vectors_are_held_with_the_go_side() {
        for (name, document, canonical, transcript_hex, digest, transcript_length) in [
            (
                "reference definition",
                vector_reference(),
                VECTOR_REFERENCE_DOCUMENT,
                VECTOR_REFERENCE_TRANSCRIPT_HEX,
                VECTOR_REFERENCE_SHA256,
                297_usize,
            ),
            (
                "definition without lists",
                vector_minimal(),
                VECTOR_MINIMAL_DOCUMENT,
                VECTOR_MINIMAL_TRANSCRIPT_HEX,
                VECTOR_MINIMAL_SHA256,
                105_usize,
            ),
        ] {
            let encoded = document
                .encode()
                .unwrap_or_else(|_| panic!("{name}: the canonical document"));
            assert_eq!(encoded, canonical, "{name} canonical document drifted");
            // The declaration order of the fields is the canonical encoding
            // order, and serde is held to it rather than trusted with it: a
            // serialiser that sorted its keys would still read every definition
            // correctly and would silently stop agreeing with the Controller
            // about what a canonical document is.
            assert_eq!(hostile(&document), canonical);

            let transcript = document
                .transcript()
                .unwrap_or_else(|_| panic!("{name}: the transcript"));
            assert_eq!(
                transcript.len(),
                transcript_length,
                "{name} transcript length drifted"
            );
            assert_eq!(
                transcript,
                decoded_hex(transcript_hex),
                "{name} transcript drifted from the shared vector: {}",
                encode_lower_hex(&transcript)
            );
            assert!(
                transcript.starts_with(SERVICE_DEFINITION_TRANSCRIPT_DOMAIN),
                "{name} transcript does not open on its own domain separator"
            );

            assert_eq!(
                document.sha256().unwrap(),
                digest,
                "{name} digest drifted from the shared vector"
            );

            // The round trip is part of the vector rather than a test of its
            // own: a definition read back from its canonical bytes is the same
            // definition, down to the digest a plan pinned.
            let decoded = decode_service_definition_document(canonical.as_bytes())
                .unwrap_or_else(|_| panic!("{name} did not decode its own canonical bytes"));
            assert_eq!(decoded, document);
            assert_eq!(decoded.encode().unwrap(), canonical);
            assert_eq!(decoded.sha256().unwrap(), digest);
            assert_eq!(
                verify_service_definition_document(canonical.as_bytes(), digest).unwrap(),
                decoded
            );
        }

        assert_ne!(
            VECTOR_REFERENCE_SHA256, VECTOR_MINIMAL_SHA256,
            "the two vectors of this palier share a digest"
        );
    }

    /// The property the whole trajectory of the document rests on.
    ///
    /// The Auxiliary rehashes the bytes it receives before reading anything of
    /// the machine, and refuses them when the digest is not the
    /// `definition_digest` of the plan. That refusal is only worth something if
    /// no altered document can keep the digest, so the statement is made
    /// exhaustively rather than on a chosen byte: every single-byte alteration
    /// of the canonical reference either stops decoding or produces another
    /// digest, and never a second document under the first digest.
    #[test]
    fn altering_one_byte_of_a_canonical_definition_never_keeps_its_digest() {
        let original = VECTOR_REFERENCE_DOCUMENT.as_bytes();
        for position in 0..original.len() {
            for replacement in [b'a', b'z', b'0', b'9', b'-', b'/'] {
                if original[position] == replacement {
                    continue;
                }
                let mut altered = original.to_vec();
                altered[position] = replacement;

                let Ok(decoded) = decode_service_definition_document(&altered) else {
                    continue;
                };
                assert_ne!(
                    decoded.sha256().unwrap(),
                    VECTOR_REFERENCE_SHA256,
                    "byte {position} replaced by {} kept the digest of the reference",
                    char::from(replacement)
                );
                assert_eq!(
                    verify_service_definition_document(&altered, VECTOR_REFERENCE_SHA256),
                    Err(ProtocolError::InvalidInput),
                    "byte {position} replaced by {} passed verification",
                    char::from(replacement)
                );
            }
        }

        // And the original is still readable beside every one of those
        // alterations, which is the other half of what the proof states: an
        // altered definition is refused and the one that was frozen stays
        // exactly what it was.
        assert_eq!(
            decode_service_definition_document(original)
                .unwrap()
                .sha256()
                .unwrap(),
            VECTOR_REFERENCE_SHA256
        );
    }

    /// The central property of the transcript.
    ///
    /// A field that could move without moving the digest would be a field the
    /// Controller owns, since the Controller is the only thing between the human
    /// who approved a plan and the machine that performs it. The canonical
    /// document is read back at the end so that a field added to the schema and
    /// forgotten in the transcript fails here rather than in a later palier.
    #[test]
    fn every_field_of_a_definition_is_inside_the_hashed_bytes() {
        let reference = vector_reference().raw_transcript().unwrap();
        let mut covered: Vec<&str> = Vec::new();
        for (field, moved) in [
            (
                "schema_version",
                ServiceDefinitionDocument {
                    schema_version: SERVICE_DEFINITION_SCHEMA_VERSION + 1,
                    ..vector_reference()
                },
            ),
            (
                "slug",
                ServiceDefinitionDocument {
                    slug: "other-notes".into(),
                    ..vector_reference()
                },
            ),
            (
                "image_repository",
                ServiceDefinitionDocument {
                    image_repository: "registry.lab.your-cloud.test/other".into(),
                    ..vector_reference()
                },
            ),
            (
                "container_port",
                ServiceDefinitionDocument {
                    container_port: VECTOR_CONTAINER_PORT + 1,
                    ..vector_reference()
                },
            ),
            (
                "volumes",
                ServiceDefinitionDocument {
                    volumes: vec![VECTOR_DATA_VOLUME.into()],
                    ..vector_reference()
                },
            ),
            (
                "tmpfs",
                ServiceDefinitionDocument {
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "environment",
                ServiceDefinitionDocument {
                    environment: vec![VECTOR_TITLE_LINE.into()],
                    ..vector_reference()
                },
            ),
            (
                "secret_keys",
                ServiceDefinitionDocument {
                    secret_keys: Vec::new(),
                    ..vector_reference()
                },
            ),
        ] {
            assert_ne!(
                moved.raw_transcript().unwrap(),
                reference,
                "{field} is outside the hashed bytes"
            );
            covered.push(field);
        }

        let wire: serde_json::Value = serde_json::from_str(VECTOR_REFERENCE_DOCUMENT).unwrap();
        let mut names: Vec<String> = wire.as_object().unwrap().keys().cloned().collect();
        names.sort();
        let mut held: Vec<String> = covered.iter().map(|name| (*name).to_owned()).collect();
        held.sort();
        assert_eq!(
            names, held,
            "a field of the definition is never held against its digest"
        );
    }

    /// The decision the layout rests on.
    ///
    /// The order of a list is inside the hashed bytes, so a Controller, a
    /// transport or a Console that reordered a list would be handing an
    /// Auxiliary a document no approval names. Freezing what the author wrote —
    /// rather than a sorted rewriting of it — is what makes re-reading a frozen
    /// definition return the bytes that were frozen.
    #[test]
    fn two_definitions_differing_only_by_the_order_of_a_list_are_two_definitions() {
        for (name, reordered) in [
            (
                "the two volumes",
                ServiceDefinitionDocument {
                    volumes: vec![VECTOR_STATE_VOLUME.into(), VECTOR_DATA_VOLUME.into()],
                    ..vector_reference()
                },
            ),
            (
                "the environment lines",
                ServiceDefinitionDocument {
                    environment: vec![
                        VECTOR_READ_ONLY_LINE.into(),
                        VECTOR_ORIGIN_LINE.into(),
                        VECTOR_TITLE_LINE.into(),
                    ],
                    ..vector_reference()
                },
            ),
        ] {
            assert_ne!(
                reordered.sha256().unwrap(),
                VECTOR_REFERENCE_SHA256,
                "reordering {name} left the digest where it was"
            );
            assert_ne!(
                reordered.encode().unwrap(),
                VECTOR_REFERENCE_DOCUMENT,
                "reordering {name} left the canonical bytes where they were"
            );
        }
    }

    /// The one place where two spellings are accepted and freeze to one.
    ///
    /// A list nobody declared, a list spelled null and a list spelled empty
    /// describe the same state — no volume, no tmpfs, no line, no key — so they
    /// are one definition with one digest, and the canonical spelling of all
    /// three is the empty array. Nothing else in the document has a second
    /// accepted spelling.
    #[test]
    fn a_list_left_out_is_the_same_definition_as_an_empty_one() {
        for (name, document) in [
            (
                "the four lists left out",
                concat!(
                    r#"{"schema_version":1,"slug":"minimal","#,
                    r#""image_repository":"registry.lab.your-cloud.test/minimal","#,
                    r#""container_port":80}"#,
                ),
            ),
            (
                "the four lists spelled null",
                concat!(
                    r#"{"schema_version":1,"slug":"minimal","#,
                    r#""image_repository":"registry.lab.your-cloud.test/minimal","#,
                    r#""container_port":80,"volumes":null,"tmpfs":null,"#,
                    r#""environment":null,"secret_keys":null}"#,
                ),
            ),
            ("the four lists spelled empty", VECTOR_MINIMAL_DOCUMENT),
        ] {
            let decoded = decode_service_definition_document(document.as_bytes())
                .unwrap_or_else(|_| panic!("{name} was refused"));
            assert_eq!(
                decoded.encode().unwrap(),
                VECTOR_MINIMAL_DOCUMENT,
                "{name} froze to another spelling"
            );
            assert_eq!(
                decoded.sha256().unwrap(),
                VECTOR_MINIMAL_SHA256,
                "{name} carries another digest"
            );
        }
    }

    /// Keeps every refusal of the hostile tables below naming a malformation
    /// rather than an off-by-one.
    #[test]
    fn the_bounds_of_a_definition_are_themselves_accepted() {
        for (name, accepted) in [
            (
                "shortest slug",
                ServiceDefinitionDocument {
                    slug: "a".into(),
                    ..vector_reference()
                },
            ),
            (
                "longest slug",
                ServiceDefinitionDocument {
                    slug: "a".repeat(MAX_SERVICE_SLUG_CHARS),
                    ..vector_reference()
                },
            ),
            (
                "slug of digits",
                ServiceDefinitionDocument {
                    slug: "42".into(),
                    ..vector_reference()
                },
            ),
            (
                "lowest container port",
                ServiceDefinitionDocument {
                    container_port: MIN_CONTAINER_PORT,
                    ..vector_reference()
                },
            ),
            (
                "highest container port",
                ServiceDefinitionDocument {
                    container_port: MAX_CONTAINER_PORT,
                    ..vector_reference()
                },
            ),
            (
                "registry on a port",
                ServiceDefinitionDocument {
                    image_repository: "registry.lab.your-cloud.test:5000/your-cloud/lab-notes"
                        .into(),
                    ..vector_reference()
                },
            ),
            (
                "single path component",
                ServiceDefinitionDocument {
                    image_repository: "registry.lab.your-cloud.test/lab-notes".into(),
                    ..vector_reference()
                },
            ),
            (
                "repository carrying dots and underscores",
                ServiceDefinitionDocument {
                    image_repository: "registry.lab.your-cloud.test/your_cloud/lab.notes-2".into(),
                    ..vector_reference()
                },
            ),
            (
                "eight volumes and eight tmpfs",
                ServiceDefinitionDocument {
                    volumes: numbered_paths("/srv/volume", MAX_SERVICE_VOLUMES),
                    tmpfs: numbered_paths("/run/scratch", MAX_SERVICE_TMPFS),
                    ..vector_reference()
                },
            ),
            (
                "neighbours that do not open one another",
                ServiceDefinitionDocument {
                    volumes: vec!["/srv".into(), "/srvdata".into(), "/srv-notes".into()],
                    tmpfs: vec!["/srvx".into()],
                    ..vector_reference()
                },
            ),
            (
                "longest container path",
                ServiceDefinitionDocument {
                    volumes: vec![format!("/{}", "a".repeat(MAX_CONTAINER_PATH_BYTES - 1))],
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "path carrying dots inside a segment",
                ServiceDefinitionDocument {
                    volumes: vec!["/srv/notes.d/v1.2".into()],
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "thirty-two environment lines",
                ServiceDefinitionDocument {
                    environment: numbered_environment(MAX_SERVICE_ENVIRONMENT_LINES),
                    ..vector_reference()
                },
            ),
            (
                "sixteen secret keys",
                ServiceDefinitionDocument {
                    secret_keys: numbered_keys("SECRET", MAX_SERVICE_SECRET_KEYS),
                    ..vector_reference()
                },
            ),
            (
                "longest environment key",
                ServiceDefinitionDocument {
                    environment: vec![format!("A{}=1", "B".repeat(MAX_ENVIRONMENT_KEY_CHARS - 1))],
                    ..vector_reference()
                },
            ),
            (
                "longest environment value",
                ServiceDefinitionDocument {
                    environment: vec![format!("LONG={}", "x".repeat(MAX_ENVIRONMENT_VALUE_BYTES))],
                    ..vector_reference()
                },
            ),
            (
                "empty environment value",
                ServiceDefinitionDocument {
                    environment: vec!["EMPTY=".into()],
                    ..vector_reference()
                },
            ),
            (
                "value carrying separators",
                ServiceDefinitionDocument {
                    environment: vec![r#"SPELLING=a=b c;d "e" \f/g"#.into()],
                    ..vector_reference()
                },
            ),
            (
                "the origin interpolated twice",
                ServiceDefinitionDocument {
                    environment: vec!["BOTH=https://{origin_host}/ and {origin_host}".into()],
                    ..vector_reference()
                },
            ),
            (
                "no secret key at all",
                ServiceDefinitionDocument {
                    secret_keys: Vec::new(),
                    ..vector_reference()
                },
            ),
        ] {
            assert!(
                decode_service_definition_document(hostile(&accepted).as_bytes()).is_ok(),
                "{name} was refused"
            );
        }
    }

    /// The hostile table of the document: every named refusal of the contract,
    /// exercised by its own subject.
    #[test]
    fn decoding_refuses_every_definition_outside_the_contract() {
        assert!(decode_service_definition_document(VECTOR_REFERENCE_DOCUMENT.as_bytes()).is_ok());

        for (name, refused) in [
            (
                "schema version zero",
                ServiceDefinitionDocument {
                    schema_version: 0,
                    ..vector_reference()
                },
            ),
            (
                "schema version to come",
                ServiceDefinitionDocument {
                    schema_version: SERVICE_DEFINITION_SCHEMA_VERSION + 1,
                    ..vector_reference()
                },
            ),
            (
                "empty slug",
                ServiceDefinitionDocument {
                    slug: String::new(),
                    ..vector_reference()
                },
            ),
            (
                "slug of seventeen",
                ServiceDefinitionDocument {
                    slug: "a".repeat(MAX_SERVICE_SLUG_CHARS + 1),
                    ..vector_reference()
                },
            ),
            (
                "upper-case slug",
                ServiceDefinitionDocument {
                    slug: "Lab-Notes".into(),
                    ..vector_reference()
                },
            ),
            (
                "slug opening on a hyphen",
                ServiceDefinitionDocument {
                    slug: "-lab-notes".into(),
                    ..vector_reference()
                },
            ),
            (
                "slug carrying a dot",
                ServiceDefinitionDocument {
                    slug: "lab.notes".into(),
                    ..vector_reference()
                },
            ),
            (
                "slug carrying a slash",
                ServiceDefinitionDocument {
                    slug: "lab/notes".into(),
                    ..vector_reference()
                },
            ),
            (
                "slug carrying a space",
                ServiceDefinitionDocument {
                    slug: "lab notes".into(),
                    ..vector_reference()
                },
            ),
            (
                "slug climbing",
                ServiceDefinitionDocument {
                    slug: "../etc".into(),
                    ..vector_reference()
                },
            ),
            (
                "repository carrying a tag",
                ServiceDefinitionDocument {
                    image_repository: format!("{VECTOR_IMAGE_REPOSITORY}:latest"),
                    ..vector_reference()
                },
            ),
            (
                "repository carrying a digest",
                ServiceDefinitionDocument {
                    image_repository: format!(
                        "{VECTOR_IMAGE_REPOSITORY}@sha256:\
                         a4ed090f29823da5e296e2c2f8603664da71676156ea47c3f186cc73eec38db0"
                    ),
                    ..vector_reference()
                },
            ),
            (
                "repository carrying a tag behind a registry port",
                ServiceDefinitionDocument {
                    image_repository: "registry.lab.your-cloud.test:5000/lab-notes:1.0".into(),
                    ..vector_reference()
                },
            ),
            (
                "repository without a registry",
                ServiceDefinitionDocument {
                    image_repository: "your-cloud/lab-notes".into(),
                    ..vector_reference()
                },
            ),
            (
                "repository that is only a registry",
                ServiceDefinitionDocument {
                    image_repository: "registry.lab.your-cloud.test".into(),
                    ..vector_reference()
                },
            ),
            (
                "empty repository",
                ServiceDefinitionDocument {
                    image_repository: String::new(),
                    ..vector_reference()
                },
            ),
            (
                "upper-case repository",
                ServiceDefinitionDocument {
                    image_repository: "registry.lab.your-cloud.test/Lab-Notes".into(),
                    ..vector_reference()
                },
            ),
            (
                "repository with a scheme",
                ServiceDefinitionDocument {
                    image_repository: "https://registry.lab.your-cloud.test/lab-notes".into(),
                    ..vector_reference()
                },
            ),
            (
                "repository ending on a slash",
                ServiceDefinitionDocument {
                    image_repository: "registry.lab.your-cloud.test/lab-notes/".into(),
                    ..vector_reference()
                },
            ),
            (
                "repository with an empty component",
                ServiceDefinitionDocument {
                    image_repository: "registry.lab.your-cloud.test//lab-notes".into(),
                    ..vector_reference()
                },
            ),
            (
                "repository climbing",
                ServiceDefinitionDocument {
                    image_repository: "registry.lab.your-cloud.test/../lab-notes".into(),
                    ..vector_reference()
                },
            ),
            (
                "repository above its bound",
                ServiceDefinitionDocument {
                    image_repository: format!(
                        "registry.lab.your-cloud.test/{}",
                        "a".repeat(MAX_IMAGE_REPOSITORY_BYTES)
                    ),
                    ..vector_reference()
                },
            ),
            (
                "registry opening on a hyphen",
                ServiceDefinitionDocument {
                    image_repository: "-registry.lab.your-cloud.test/lab-notes".into(),
                    ..vector_reference()
                },
            ),
            (
                "registry carrying two dots",
                ServiceDefinitionDocument {
                    image_repository: "registry..lab.your-cloud.test/lab-notes".into(),
                    ..vector_reference()
                },
            ),
            (
                "registry port above five digits",
                ServiceDefinitionDocument {
                    image_repository: "registry.lab.your-cloud.test:500000/lab-notes".into(),
                    ..vector_reference()
                },
            ),
            (
                "container port zero",
                ServiceDefinitionDocument {
                    container_port: 0,
                    ..vector_reference()
                },
            ),
            (
                "container port above range",
                ServiceDefinitionDocument {
                    container_port: MAX_CONTAINER_PORT + 1,
                    ..vector_reference()
                },
            ),
            (
                "container port beyond sixteen bits",
                ServiceDefinitionDocument {
                    container_port: 70_000,
                    ..vector_reference()
                },
            ),
            (
                "nine volumes",
                ServiceDefinitionDocument {
                    volumes: numbered_paths("/srv/volume", MAX_SERVICE_VOLUMES + 1),
                    ..vector_reference()
                },
            ),
            (
                "nine tmpfs",
                ServiceDefinitionDocument {
                    tmpfs: numbered_paths("/run/scratch", MAX_SERVICE_TMPFS + 1),
                    ..vector_reference()
                },
            ),
            (
                "relative volume",
                ServiceDefinitionDocument {
                    volumes: vec!["srv/notes".into()],
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "volume climbing out",
                ServiceDefinitionDocument {
                    volumes: vec!["/srv/../../etc".into()],
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "volume carrying a single dot segment",
                ServiceDefinitionDocument {
                    volumes: vec!["/srv/./notes".into()],
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "volume carrying a double separator",
                ServiceDefinitionDocument {
                    volumes: vec!["/srv//notes".into()],
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "volume opening on a double separator",
                ServiceDefinitionDocument {
                    volumes: vec!["//srv/notes".into()],
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "volume ending on a separator",
                ServiceDefinitionDocument {
                    volumes: vec!["/srv/notes/".into()],
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "volume that is the root",
                ServiceDefinitionDocument {
                    volumes: vec!["/".into()],
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "empty volume",
                ServiceDefinitionDocument {
                    volumes: vec![String::new()],
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "upper-case volume",
                ServiceDefinitionDocument {
                    volumes: vec!["/srv/Notes".into()],
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "volume carrying a mount separator",
                ServiceDefinitionDocument {
                    volumes: vec!["/srv/notes:ro".into()],
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "volume carrying a space",
                ServiceDefinitionDocument {
                    volumes: vec!["/srv/lab notes".into()],
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "volume carrying a NUL",
                ServiceDefinitionDocument {
                    volumes: vec!["/srv/notes\0".into()],
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "volume outside ASCII",
                ServiceDefinitionDocument {
                    volumes: vec!["/srv/café".into()],
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "volume above its byte bound",
                ServiceDefinitionDocument {
                    volumes: vec![format!("/{}", "a".repeat(MAX_CONTAINER_PATH_BYTES))],
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "the same volume twice",
                ServiceDefinitionDocument {
                    volumes: vec![VECTOR_DATA_VOLUME.into(), VECTOR_DATA_VOLUME.into()],
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "a volume inside another volume",
                ServiceDefinitionDocument {
                    volumes: vec!["/srv".into(), "/srv/data".into()],
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "a volume containing a tmpfs",
                ServiceDefinitionDocument {
                    volumes: vec!["/srv".into()],
                    tmpfs: vec!["/srv/scratch".into()],
                    ..vector_reference()
                },
            ),
            (
                "a tmpfs containing a volume",
                ServiceDefinitionDocument {
                    volumes: vec!["/srv/notes/scratch".into()],
                    tmpfs: vec!["/srv/notes".into()],
                    ..vector_reference()
                },
            ),
            (
                "a tmpfs equal to a volume",
                ServiceDefinitionDocument {
                    volumes: vec![VECTOR_DATA_VOLUME.into()],
                    tmpfs: vec![VECTOR_DATA_VOLUME.into()],
                    ..vector_reference()
                },
            ),
            (
                "the same tmpfs twice",
                ServiceDefinitionDocument {
                    volumes: Vec::new(),
                    tmpfs: vec![VECTOR_SCRATCH_TMPFS.into(), VECTOR_SCRATCH_TMPFS.into()],
                    ..vector_reference()
                },
            ),
            (
                "thirty-three environment lines",
                ServiceDefinitionDocument {
                    environment: numbered_environment(MAX_SERVICE_ENVIRONMENT_LINES + 1),
                    secret_keys: Vec::new(),
                    ..vector_reference()
                },
            ),
            (
                "environment line without a separator",
                ServiceDefinitionDocument {
                    environment: vec!["LAB_NOTES_TITLE".into()],
                    ..vector_reference()
                },
            ),
            (
                "lower-case environment key",
                ServiceDefinitionDocument {
                    environment: vec!["lab_notes_title=x".into()],
                    ..vector_reference()
                },
            ),
            (
                "environment key opening on a digit",
                ServiceDefinitionDocument {
                    environment: vec!["1_TITLE=x".into()],
                    ..vector_reference()
                },
            ),
            (
                "environment key carrying a hyphen",
                ServiceDefinitionDocument {
                    environment: vec!["LAB-TITLE=x".into()],
                    ..vector_reference()
                },
            ),
            (
                "empty environment key",
                ServiceDefinitionDocument {
                    environment: vec!["=x".into()],
                    ..vector_reference()
                },
            ),
            (
                "environment key above its bound",
                ServiceDefinitionDocument {
                    environment: vec![format!("A{}=x", "B".repeat(MAX_ENVIRONMENT_KEY_CHARS))],
                    ..vector_reference()
                },
            ),
            (
                "the same environment key twice",
                ServiceDefinitionDocument {
                    environment: vec!["LAB_NOTES_TITLE=one".into(), "LAB_NOTES_TITLE=two".into()],
                    ..vector_reference()
                },
            ),
            (
                "a key that is an environment line and a secret at once",
                ServiceDefinitionDocument {
                    secret_keys: vec!["LAB_NOTES_TITLE".into()],
                    ..vector_reference()
                },
            ),
            (
                "environment value above its bound",
                ServiceDefinitionDocument {
                    environment: vec![format!(
                        "LONG={}",
                        "x".repeat(MAX_ENVIRONMENT_VALUE_BYTES + 1)
                    )],
                    ..vector_reference()
                },
            ),
            (
                "environment value carrying a tab",
                ServiceDefinitionDocument {
                    environment: vec!["TITLE=a\tb".into()],
                    ..vector_reference()
                },
            ),
            (
                "environment value carrying a break",
                ServiceDefinitionDocument {
                    environment: vec!["TITLE=a\nb".into()],
                    ..vector_reference()
                },
            ),
            (
                "environment value carrying a NUL",
                ServiceDefinitionDocument {
                    environment: vec!["TITLE=a\0b".into()],
                    ..vector_reference()
                },
            ),
            (
                "environment value outside ASCII",
                ServiceDefinitionDocument {
                    environment: vec!["TITLE=café".into()],
                    ..vector_reference()
                },
            ),
            (
                "environment value carrying DEL",
                ServiceDefinitionDocument {
                    environment: vec!["TITLE=a\u{7f}b".into()],
                    ..vector_reference()
                },
            ),
            (
                "a truncated placeholder",
                ServiceDefinitionDocument {
                    environment: vec!["ORIGIN=https://{origin_hos}/".into()],
                    ..vector_reference()
                },
            ),
            (
                "an unterminated placeholder",
                ServiceDefinitionDocument {
                    environment: vec!["ORIGIN=https://{origin_host".into()],
                    ..vector_reference()
                },
            ),
            (
                "an upper-case placeholder",
                ServiceDefinitionDocument {
                    environment: vec!["ORIGIN=https://{ORIGIN_HOST}/".into()],
                    ..vector_reference()
                },
            ),
            (
                "another placeholder name",
                ServiceDefinitionDocument {
                    environment: vec!["ORIGIN=https://{machine_id}/".into()],
                    ..vector_reference()
                },
            ),
            (
                "an opening brace on its own",
                ServiceDefinitionDocument {
                    environment: vec!["ORIGIN=a{b".into()],
                    ..vector_reference()
                },
            ),
            (
                "a closing brace on its own",
                ServiceDefinitionDocument {
                    environment: vec!["ORIGIN=a}b".into()],
                    ..vector_reference()
                },
            ),
            (
                "a brace pair around nothing",
                ServiceDefinitionDocument {
                    environment: vec!["ORIGIN={}".into()],
                    ..vector_reference()
                },
            ),
            (
                "a nested placeholder",
                ServiceDefinitionDocument {
                    environment: vec!["ORIGIN={{origin_host}}".into()],
                    ..vector_reference()
                },
            ),
            (
                "seventeen secret keys",
                ServiceDefinitionDocument {
                    environment: Vec::new(),
                    secret_keys: numbered_keys("SECRET", MAX_SERVICE_SECRET_KEYS + 1),
                    ..vector_reference()
                },
            ),
            (
                "lower-case secret key",
                ServiceDefinitionDocument {
                    secret_keys: vec!["lab_notes_token".into()],
                    ..vector_reference()
                },
            ),
            (
                "secret key carrying a separator",
                ServiceDefinitionDocument {
                    secret_keys: vec!["LAB_NOTES_TOKEN=x".into()],
                    ..vector_reference()
                },
            ),
            (
                "empty secret key",
                ServiceDefinitionDocument {
                    secret_keys: vec![String::new()],
                    ..vector_reference()
                },
            ),
            (
                "secret key opening on an underscore",
                ServiceDefinitionDocument {
                    secret_keys: vec!["_TOKEN".into()],
                    ..vector_reference()
                },
            ),
            (
                "the same secret key twice",
                ServiceDefinitionDocument {
                    secret_keys: vec![VECTOR_SECRET_KEY.into(), VECTOR_SECRET_KEY.into()],
                    ..vector_reference()
                },
            ),
        ] {
            assert_eq!(
                decode_service_definition_document(hostile(&refused).as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
            // A refused definition is a definition nothing transports and
            // nothing hashes: the two renderings are held here rather than only
            // the decoding, so no caller can freeze what no decoder would read.
            assert_eq!(
                refused.encode(),
                Err(ProtocolError::InvalidInput),
                "{name} was rendered"
            );
            assert_eq!(
                refused.transcript(),
                Err(ProtocolError::InvalidInput),
                "{name} was hashed"
            );
        }
    }

    /// Keeps one name designating exactly one door.
    ///
    /// The archive operations name a service by its `service_profile` field, and
    /// the third door shares that namespace with the profiles the product
    /// delivers. A definition that could take one of those four names would make
    /// a lookup succeed on both sides, and the ambiguity would then have to be
    /// resolved by a comparison someone remembered to write.
    #[test]
    fn the_four_reserved_slugs_are_refused_by_name() {
        assert_eq!(
            RESERVED_SERVICE_SLUGS,
            ["bentopdf", "vaultwarden", "probe", "entrypoint"]
        );
        for slug in RESERVED_SERVICE_SLUGS {
            let reserved = ServiceDefinitionDocument {
                slug: slug.into(),
                ..vector_reference()
            };
            assert_eq!(
                decode_service_definition_document(hostile(&reserved).as_bytes()),
                Err(ProtocolError::InvalidInput),
                "the reserved slug {slug} was accepted"
            );
        }

        // The reservation is on the exact names and on nothing around them: a
        // slug that merely contains one of them is a slug like any other,
        // because what the two namespaces compare is equality.
        for slug in ["bentopdf2", "my-vaultwarden", "probes", "entrypoints"] {
            let accepted = ServiceDefinitionDocument {
                slug: slug.into(),
                ..vector_reference()
            };
            assert!(
                decode_service_definition_document(hostile(&accepted).as_bytes()).is_ok(),
                "the slug {slug} was refused"
            );
        }
    }

    /// The surface no field bound can cover: what is refused before any value of
    /// the document is read.
    #[test]
    fn decoding_refuses_every_document_the_strict_decoding_refuses() {
        for (name, document) in [
            (
                "an unknown field",
                with_extra_member(VECTOR_REFERENCE_DOCUMENT, r#""host_path":"/etc/shadow""#),
            ),
            (
                "a field of a plan",
                with_extra_member(VECTOR_REFERENCE_DOCUMENT, r#""image_digest":"sha256:00""#),
            ),
            (
                "a field naming the account",
                with_extra_member(
                    VECTOR_REFERENCE_DOCUMENT,
                    r#""account":"your-cloud-user-lab-notes""#,
                ),
            ),
            (
                "a field naming a secret value",
                with_extra_member(
                    VECTOR_REFERENCE_DOCUMENT,
                    r#""secrets":{"TOKEN":"hunter2"}"#,
                ),
            ),
            (
                "a field naming the egress table",
                with_extra_member(
                    VECTOR_REFERENCE_DOCUMENT,
                    r#""egress_table":"inet your-cloud-egress""#,
                ),
            ),
            (
                "a repeated field",
                with_extra_member(VECTOR_REFERENCE_DOCUMENT, r#""slug":"other""#),
            ),
            (
                "a repeated list",
                with_extra_member(VECTOR_REFERENCE_DOCUMENT, r#""tmpfs":["/run"]"#),
            ),
            (
                "a field in another case",
                VECTOR_REFERENCE_DOCUMENT.replace(r#""slug":"#, r#""Slug":"#),
            ),
            (
                "a camel-case field name",
                VECTOR_REFERENCE_DOCUMENT.replace(r#""container_port":"#, r#""containerPort":"#),
            ),
            (
                "two documents in one",
                format!("{VECTOR_REFERENCE_DOCUMENT}{VECTOR_MINIMAL_DOCUMENT}"),
            ),
            ("trailing bytes", format!("{VECTOR_REFERENCE_DOCUMENT} ]")),
            (
                "an array of definitions",
                format!("[{VECTOR_REFERENCE_DOCUMENT}]"),
            ),
            ("an empty document", String::new()),
            ("a bare null", "null".to_owned()),
            (
                "a truncated document",
                VECTOR_REFERENCE_DOCUMENT.trim_end_matches('}').to_owned(),
            ),
            (
                "a missing slug",
                VECTOR_REFERENCE_DOCUMENT.replace(r#""slug":"lab-notes","#, ""),
            ),
            (
                "a missing repository",
                VECTOR_REFERENCE_DOCUMENT.replace(
                    r#""image_repository":"registry.lab.your-cloud.test/your-cloud/lab-notes","#,
                    "",
                ),
            ),
            (
                "a missing port",
                VECTOR_REFERENCE_DOCUMENT.replace(r#""container_port":8080,"#, ""),
            ),
            (
                "a string where a list is",
                VECTOR_REFERENCE_DOCUMENT.replace(r#""tmpfs":["/tmp"]"#, r#""tmpfs":"/tmp""#),
            ),
            (
                "an object where a list is",
                VECTOR_REFERENCE_DOCUMENT.replace(r#""tmpfs":["/tmp"]"#, r#""tmpfs":{"0":"/tmp"}"#),
            ),
            (
                "a number inside a list",
                VECTOR_REFERENCE_DOCUMENT.replace(r#""tmpfs":["/tmp"]"#, r#""tmpfs":[8080]"#),
            ),
            (
                "a null inside a list",
                VECTOR_REFERENCE_DOCUMENT.replace(r#""tmpfs":["/tmp"]"#, r#""tmpfs":[null]"#),
            ),
            (
                "a string where the port is",
                VECTOR_REFERENCE_DOCUMENT
                    .replace(r#""container_port":8080"#, r#""container_port":"8080""#),
            ),
            (
                "a fractional port",
                VECTOR_REFERENCE_DOCUMENT
                    .replace(r#""container_port":8080"#, r#""container_port":8080.5"#),
            ),
            (
                "an exponent port",
                VECTOR_REFERENCE_DOCUMENT
                    .replace(r#""container_port":8080"#, r#""container_port":8.08e3"#),
            ),
            (
                "a negative port",
                VECTOR_REFERENCE_DOCUMENT
                    .replace(r#""container_port":8080"#, r#""container_port":-1"#),
            ),
            (
                "a negative schema version",
                VECTOR_REFERENCE_DOCUMENT
                    .replace(r#""schema_version":1"#, r#""schema_version":-1"#),
            ),
            (
                "a null schema version",
                VECTOR_REFERENCE_DOCUMENT
                    .replace(r#""schema_version":1"#, r#""schema_version":null"#),
            ),
        ] {
            assert_eq!(
                decode_service_definition_document(document.as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }
    }

    /// The bound that exists so that no cost of parsing depends on what a
    /// document claims.
    ///
    /// The subject is a definition every field of which is inside its own bound
    /// and whose whole is not: thirty-two lines of five hundred and twelve bytes
    /// fit the cardinal and the value bounds and do not fit the document. It is
    /// refused by the byte bound at both ends — nothing renders it, and no
    /// decoder will read it.
    #[test]
    fn a_definition_is_refused_before_it_is_parsed_when_it_is_too_large() {
        let oversized = ServiceDefinitionDocument {
            environment: numbered_keys("LINE", MAX_SERVICE_ENVIRONMENT_LINES)
                .into_iter()
                .map(|key| format!("{key}={}", "x".repeat(MAX_ENVIRONMENT_VALUE_BYTES)))
                .collect(),
            ..vector_minimal()
        };
        assert!(
            oversized.holds_the_contract(),
            "every field of the subject must be inside its own bound"
        );

        let rendered = hostile(&oversized);
        assert!(
            rendered.len() > MAX_SERVICE_DEFINITION_BYTES,
            "the subject of this test must exceed the bound, and it is {} bytes",
            rendered.len()
        );
        assert_eq!(
            decode_service_definition_document(rendered.as_bytes()),
            Err(ProtocolError::InvalidInput),
            "a definition beyond the byte bound was decoded"
        );
        assert_eq!(
            oversized.encode(),
            Err(ProtocolError::InvalidInput),
            "a definition beyond the byte bound was rendered"
        );

        // A transcript and a digest are still computable, because they are taken
        // over the fields rather than over a rendering. Nothing transports them:
        // what cannot be encoded cannot be frozen.
        assert!(oversized.sha256().is_ok());
    }

    /// The exact limit of what a transport may do: reshape the JSON, and only
    /// that.
    ///
    /// The digest is rebuilt from the fields, so a reindented, reordered
    /// document is the same definition, and a document with one value changed is
    /// not.
    #[test]
    fn a_reindented_document_is_the_same_definition() {
        let reshaped = concat!(
            "{\n  \"secret_keys\": [\"LAB_NOTES_ADMIN_TOKEN\"],\n",
            "  \"environment\": [\n    \"LAB_NOTES_TITLE=Your Cloud lab notes\",\n",
            "    \"LAB_NOTES_ORIGIN=https://{origin_host}/\",\n",
            "    \"LAB_NOTES_READ_ONLY=1\"\n  ],\n",
            "  \"tmpfs\": [\"/tmp\"],\n",
            "  \"volumes\": [\"/srv/notes\", \"/var/lib/lab-notes\"],\n",
            "  \"container_port\": 8080,\n",
            "  \"image_repository\": \"registry.lab.your-cloud.test/your-cloud/lab-notes\",\n",
            "  \"slug\": \"lab-notes\",\n  \"schema_version\": 1\n}",
        );
        let decoded = decode_service_definition_document(reshaped.as_bytes())
            .expect("a reindented document is the same definition");
        assert_eq!(decoded.sha256().unwrap(), VECTOR_REFERENCE_SHA256);
        assert_eq!(decoded.encode().unwrap(), VECTOR_REFERENCE_DOCUMENT);
        assert_eq!(
            verify_service_definition_document(reshaped.as_bytes(), VECTOR_REFERENCE_SHA256)
                .unwrap(),
            decoded
        );
    }

    /// A definition is only ever accepted beside the digest it really has.
    #[test]
    fn verification_refuses_a_document_its_digest_does_not_name() {
        let upper_case_digest = VECTOR_REFERENCE_SHA256.to_ascii_uppercase();
        for (name, document, expected) in [
            (
                "the reference presented under the minimal digest",
                VECTOR_REFERENCE_DOCUMENT,
                VECTOR_MINIMAL_SHA256,
            ),
            (
                "the minimal presented under the reference digest",
                VECTOR_MINIMAL_DOCUMENT,
                VECTOR_REFERENCE_SHA256,
            ),
            (
                "an upper-case digest",
                VECTOR_REFERENCE_DOCUMENT,
                upper_case_digest.as_str(),
            ),
            ("a truncated digest", VECTOR_REFERENCE_DOCUMENT, "c0f3"),
            ("an empty digest", VECTOR_REFERENCE_DOCUMENT, ""),
        ] {
            assert_eq!(
                verify_service_definition_document(document.as_bytes(), expected),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }
    }

    /// A definition is not a plan, and no digest of one can ever be read as a
    /// digest of the other.
    ///
    /// The domain separator, the schema byte and the byte bound are all this
    /// palier's own. They are held here rather than merely written apart,
    /// because the whole point of a separate domain is that it stays separate.
    #[test]
    fn a_definition_shares_no_domain_and_no_bound_with_any_plan() {
        assert_eq!(
            SERVICE_DEFINITION_TRANSCRIPT_DOMAIN,
            b"your-cloud/service-definition.v1\0"
        );
        assert_ne!(
            SERVICE_DEFINITION_TRANSCRIPT_DOMAIN,
            crate::plan::PLAN_TRANSCRIPT_DOMAIN
        );
        assert_ne!(
            SERVICE_DEFINITION_TRANSCRIPT_DOMAIN,
            crate::plan_v2::PLAN_V2_TRANSCRIPT_DOMAIN
        );
        assert_ne!(
            SERVICE_DEFINITION_TRANSCRIPT_DOMAIN,
            crate::plan_v3::PLAN_V3_TRANSCRIPT_DOMAIN
        );
        assert_eq!(
            MAX_SERVICE_DEFINITION_BYTES,
            crate::plan::MAX_PLAN_DOCUMENT_BYTES * 2
        );

        // No plan decoder reads a definition, and this decoder reads no plan:
        // the two doors refuse one another, and the refusal is a decoding that
        // fails rather than a comparison someone has to remember to write.
        for document in [VECTOR_REFERENCE_DOCUMENT, VECTOR_MINIMAL_DOCUMENT] {
            assert_eq!(
                crate::plan::decode_plan_document(document.as_bytes()),
                Err(ProtocolError::InvalidInput)
            );
            assert_eq!(
                crate::plan_v2::decode_plan_v2_document(document.as_bytes()),
                Err(ProtocolError::InvalidInput)
            );
            assert_eq!(
                crate::plan_v3::decode_plan_v3_document(document.as_bytes()),
                Err(ProtocolError::InvalidInput)
            );
        }
    }

    /// The one property the named refusals rest on: they are the same contract.
    ///
    /// A form that bounded its inputs by a second reading of the grammars would
    /// drift from the document the Controller freezes, and the drift would show
    /// up as a definition a human was allowed to write and the Controller
    /// refused — or, worse, the other way round. So the two readings are held
    /// against one another on every subject of this module: a definition has no
    /// refusal exactly when it decodes.
    ///
    /// The subjects are the two vectors, every accepted bound, and one document
    /// per name of the refusal enumeration, so that a name added without a
    /// subject and a subject that stopped being refused both fail here.
    #[test]
    fn a_definition_has_no_named_refusal_exactly_when_it_is_inside_the_contract() {
        use ServiceDefinitionRefusal as Why;

        for (name, subject, expected) in refusal_subjects() {
            let named = subject.refusals();
            assert_eq!(
                named.is_empty(),
                decode_service_definition_document(hostile(&subject).as_bytes()).is_ok(),
                "{name}: the named refusals and the contract disagree ({named:?})"
            );
            assert_eq!(named, expected, "{name}: the named refusals drifted");
        }

        // Every name of the enumeration is exercised above. A name nothing
        // reaches is a sentence no human will ever read and a rule nothing
        // holds, so it fails here rather than surviving as decoration.
        let reached: Vec<Why> = refusal_subjects()
            .into_iter()
            .flat_map(|(_, subject, _)| subject.refusals())
            .map(|refusal| refusal.refusal)
            .collect();
        for name in [
            Why::UnknownSchemaVersion,
            Why::SlugGrammar,
            Why::SlugReserved,
            Why::ImageRepositoryPinned,
            Why::ImageRepositoryGrammar,
            Why::ContainerPortRange,
            Why::ListTooLong,
            Why::ContainerPathGrammar,
            Why::MountsOverlap,
            Why::EnvironmentLineShape,
            Why::KeyGrammar,
            Why::ValueGrammar,
            Why::KeyAlreadyDeclared,
            Why::DocumentTooLarge,
        ] {
            assert!(
                reached.contains(&name),
                "{name:?} is named by no subject of this module"
            );
        }

        // And the one reading a freeze depends on: which side of the form has to
        // ask for an origin later. It is a presence rather than a value, and it
        // is read off the lines rather than off a field.
        assert!(vector_reference().interpolates_origin_host());
        assert!(!vector_minimal().interpolates_origin_host());
        assert!(!ServiceDefinitionDocument {
            environment: vec!["PLAIN=origin_host".into()],
            ..vector_reference()
        }
        .interpolates_origin_host());
    }

    /// The subjects of the equivalence above: what each one is, and exactly the
    /// refusals it must name.
    fn refusal_subjects() -> Vec<(
        &'static str,
        ServiceDefinitionDocument,
        Vec<ServiceDefinitionFieldRefusal>,
    )> {
        use ServiceDefinitionField as Field;
        use ServiceDefinitionRefusal as Why;

        let at = |field, entry, refusal| ServiceDefinitionFieldRefusal {
            field,
            entry,
            refusal,
        };
        vec![
            ("the reference vector", vector_reference(), Vec::new()),
            ("the minimal vector", vector_minimal(), Vec::new()),
            (
                "eight volumes and eight tmpfs",
                ServiceDefinitionDocument {
                    volumes: numbered_paths("/srv/volume", MAX_SERVICE_VOLUMES),
                    tmpfs: numbered_paths("/run/scratch", MAX_SERVICE_TMPFS),
                    ..vector_reference()
                },
                Vec::new(),
            ),
            (
                "thirty-two lines and sixteen keys",
                ServiceDefinitionDocument {
                    environment: numbered_environment(MAX_SERVICE_ENVIRONMENT_LINES),
                    secret_keys: numbered_keys("SECRET", MAX_SERVICE_SECRET_KEYS),
                    ..vector_reference()
                },
                Vec::new(),
            ),
            (
                "a schema version to come",
                ServiceDefinitionDocument {
                    schema_version: SERVICE_DEFINITION_SCHEMA_VERSION + 1,
                    ..vector_reference()
                },
                vec![at(Field::SchemaVersion, None, Why::UnknownSchemaVersion)],
            ),
            (
                "an upper-case slug",
                ServiceDefinitionDocument {
                    slug: "Lab-Notes".into(),
                    ..vector_reference()
                },
                vec![at(Field::Slug, None, Why::SlugGrammar)],
            ),
            (
                "a reserved slug",
                ServiceDefinitionDocument {
                    slug: RESERVED_SERVICE_SLUGS[1].into(),
                    ..vector_reference()
                },
                vec![at(Field::Slug, None, Why::SlugReserved)],
            ),
            (
                "a repository carrying a tag",
                ServiceDefinitionDocument {
                    image_repository: format!("{VECTOR_IMAGE_REPOSITORY}:latest"),
                    ..vector_reference()
                },
                vec![at(Field::ImageRepository, None, Why::ImageRepositoryPinned)],
            ),
            (
                "a repository carrying a digest",
                ServiceDefinitionDocument {
                    image_repository: format!("{VECTOR_IMAGE_REPOSITORY}@sha256:0123"),
                    ..vector_reference()
                },
                vec![at(Field::ImageRepository, None, Why::ImageRepositoryPinned)],
            ),
            (
                "a repository without a registry",
                ServiceDefinitionDocument {
                    image_repository: "your-cloud/lab-notes".into(),
                    ..vector_reference()
                },
                vec![at(
                    Field::ImageRepository,
                    None,
                    Why::ImageRepositoryGrammar,
                )],
            ),
            (
                "a container port of zero",
                ServiceDefinitionDocument {
                    container_port: 0,
                    ..vector_reference()
                },
                vec![at(Field::ContainerPort, None, Why::ContainerPortRange)],
            ),
            (
                "nine volumes",
                ServiceDefinitionDocument {
                    volumes: numbered_paths("/srv/volume", MAX_SERVICE_VOLUMES + 1),
                    tmpfs: Vec::new(),
                    ..vector_reference()
                },
                vec![at(Field::Volumes, None, Why::ListTooLong)],
            ),
            (
                "seventeen secret keys",
                ServiceDefinitionDocument {
                    secret_keys: numbered_keys("SECRET", MAX_SERVICE_SECRET_KEYS + 1),
                    ..vector_reference()
                },
                vec![at(Field::SecretKeys, None, Why::ListTooLong)],
            ),
            (
                "a tmpfs that is not a container path",
                ServiceDefinitionDocument {
                    tmpfs: vec!["/srv/notes:ro".into()],
                    volumes: Vec::new(),
                    ..vector_reference()
                },
                vec![at(Field::Tmpfs, Some(0), Why::ContainerPathGrammar)],
            ),
            (
                "a tmpfs opening a declared volume",
                ServiceDefinitionDocument {
                    volumes: vec!["/srv/notes".into()],
                    tmpfs: vec!["/srv".into()],
                    ..vector_reference()
                },
                vec![at(Field::Tmpfs, Some(0), Why::MountsOverlap)],
            ),
            (
                "an environment entry that is not a line",
                ServiceDefinitionDocument {
                    environment: vec!["LAB_NOTES_TITLE".into()],
                    ..vector_reference()
                },
                vec![at(Field::Environment, Some(0), Why::EnvironmentLineShape)],
            ),
            (
                "a lower-case environment key",
                ServiceDefinitionDocument {
                    environment: vec!["lab_notes_title=x".into()],
                    ..vector_reference()
                },
                vec![at(Field::Environment, Some(0), Why::KeyGrammar)],
            ),
            (
                "a value carrying an unknown template",
                ServiceDefinitionDocument {
                    environment: vec!["LAB_NOTES_TITLE={machine_id}".into()],
                    ..vector_reference()
                },
                vec![at(Field::Environment, Some(0), Why::ValueGrammar)],
            ),
            (
                "a secret key that is already an environment line",
                ServiceDefinitionDocument {
                    environment: vec!["LAB_NOTES_TOKEN=x".into()],
                    secret_keys: vec!["LAB_NOTES_TOKEN".into()],
                    ..vector_reference()
                },
                vec![at(Field::SecretKeys, Some(0), Why::KeyAlreadyDeclared)],
            ),
            (
                "an environment key declared twice",
                ServiceDefinitionDocument {
                    environment: vec!["LAB_NOTES_TITLE=x".into(), "LAB_NOTES_TITLE=y".into()],
                    ..vector_reference()
                },
                vec![at(Field::Environment, Some(1), Why::KeyAlreadyDeclared)],
            ),
            (
                "every cardinal licit and the document still too wide",
                ServiceDefinitionDocument {
                    environment: (0..MAX_SERVICE_ENVIRONMENT_LINES)
                        .map(|index| {
                            format!("LINE_{index}={}", "x".repeat(MAX_ENVIRONMENT_VALUE_BYTES))
                        })
                        .collect(),
                    ..vector_reference()
                },
                vec![at(Field::Document, None, Why::DocumentTooLarge)],
            ),
            (
                "a document outside the contract in several places at once",
                ServiceDefinitionDocument {
                    slug: RESERVED_SERVICE_SLUGS[0].into(),
                    container_port: 0,
                    volumes: vec!["/srv/notes".into()],
                    tmpfs: vec!["/srv/notes".into()],
                    ..vector_reference()
                },
                vec![
                    at(Field::Slug, None, Why::SlugReserved),
                    at(Field::ContainerPort, None, Why::ContainerPortRange),
                    at(Field::Tmpfs, Some(0), Why::MountsOverlap),
                ],
            ),
        ]
    }
}
