//! What makes the embedded server bundle judgeable, and what a bundle is not.
//!
//! This module is the deciding half in its purest form: its inputs are bytes
//! already in hand — a manifest, a detached signature, an anchor and the
//! artefact itself — and its only output is one [`VerifiedBundle`] or one
//! precise [`BundleRefusal`]. It opens no file, spawns no process and reaches
//! no network, which is what lets every bound below be exercised without a
//! machine to install onto.
//!
//! **Nothing privileged runs before this module has answered.** The palier that
//! installs is handed a [`VerifiedBundle`], never a path and never a byte
//! slice, and [`verify`] is the only function in this crate that returns one.
//! So the question "could a `.deb` reach a privileged command without having
//! been judged" has exactly one place to look at rather than one per call site,
//! which is the same shape as the elevation witness of #54 and the placement
//! witness of #36.
//!
//! **The signature is checked before the manifest is parsed.** An unsigned
//! manifest is not a weaker claim, it is not a claim at all: letting the JSON
//! parser walk attacker-chosen bytes first would put a parser ahead of the
//! authentication it exists to serve. The order here is bounds, then
//! signature, then meaning.
//!
//! **The artefact is never trusted to describe itself.** `dpkg` would happily
//! read a `.deb` that no manifest ever mentioned, so size and digest are
//! compared against the signed manifest rather than read from the package. A
//! lone `.deb` is not treated as evidence of anything, which is exactly what
//! the architecture contract requires of the bounded distribution.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// The only kind of document this module will read as a bundle manifest.
///
/// It is compared before any other field so that a manifest written for
/// another purpose — the Console's own Linux candidate manifest, for one — is
/// refused as foreign rather than silently reinterpreted field by field.
pub const BUNDLE_KIND: &str = "your-cloud-server-bundle";

/// The one target this palier distributes, exactly as the architecture fixes
/// it.
///
/// `arm64` is not "not yet tested" here, it is refused: the contract states
/// that another architecture is announced as supported only after its own LAB
/// proof, and a constant that already accepted it would make that promise in
/// code before the proof existed.
pub const SUPPORTED_TARGET: &str = "debian-13-amd64";

/// The schema this module understands. A bundle announcing another one is
/// refused rather than read with today's meaning of today's field names.
pub const SCHEMA_VERSION: u64 = 1;

/// The manifest is a handful of short fields; anything larger is refused before
/// it is authenticated, so no oversized document is ever hashed or parsed.
pub const MAX_MANIFEST_BYTES: usize = 4096;

/// Ed25519 fixes both of these. They are named rather than inlined so the two
/// length refusals below read as bounds instead of magic numbers.
pub const ANCHOR_PUBLIC_KEY_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 64;

/// A SHA-256 digest, lowercase hexadecimal.
pub const DIGEST_ENCODED_BYTES: usize = 64;

/// The ceiling on the artefact itself. The server package carries one static Go
/// binary and three unit files; a bundle an order of magnitude past that is a
/// different object and is refused before it is read into memory.
pub const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

/// Why a bundle was not judged installable.
///
/// There is no single "invalid bundle" verdict. Which of the four values the
/// manifest binds diverged is the whole information a report has to carry, and
/// the LAB proof asserts each refusal by its own reason rather than by an exit
/// code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleRefusal {
    /// The manifest is longer than a manifest may be.
    ManifestTooLarge,
    /// The anchor is not an Ed25519 public key, by length or by point.
    AnchorNotAKey,
    /// The detached signature is not 64 bytes.
    SignatureMalformed,
    /// The signature does not verify against the anchor over these exact
    /// manifest bytes. Nothing below has been parsed when this is returned.
    SignatureNotByAnchor,
    /// The signed bytes are not the JSON object this module reads.
    ManifestUnreadable,
    /// The manifest carries a field this schema does not define. An unknown
    /// field is refused rather than ignored: a bundle that means more than the
    /// verifier can see is not a bundle this verifier may judge.
    ManifestUnknownField,
    /// The manifest announces a schema this module does not implement.
    SchemaNotSupported,
    /// The manifest is not a server bundle manifest at all.
    ForeignKind,
    /// The bundle targets something other than Debian 13 `amd64`.
    UnsupportedTarget,
    /// The bundle is not the version the Assistant was asked to install.
    UnexpectedVersion,
    /// The artefact is longer than an artefact may be.
    ArtifactTooLarge,
    /// The artefact's length is not the length the manifest binds.
    SizeMismatch,
    /// The artefact's SHA-256 is not the digest the manifest binds.
    DigestMismatch,
}

/// The manifest fields, once authenticated and read.
///
/// It is deliberately not public API: a caller holding a parsed manifest could
/// believe it holds a judged bundle. Only [`VerifiedBundle`] says that.
struct Manifest {
    version: String,
    target: String,
    size: u64,
    sha256: String,
}

/// The proof that one exact bundle was judged before any privilege was spent.
///
/// Like the elevation witness of #54 and the placement witness of #36 it
/// carries no bytes, it cannot be built by naming its fields, and [`verify`] is
/// the only function that returns one. It authorises nothing by itself — it
/// says only that these four values were bound by a signature the anchor
/// answers for, and that the artefact in hand is the one they describe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBundle {
    version: String,
    target: String,
    size: u64,
    sha256: String,
}

impl VerifiedBundle {
    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// The one gate. Nothing else in this crate builds a [`VerifiedBundle`].
///
/// `expected_version` is what the Assistant was built to install, not what the
/// manifest says: a bundle that authenticates perfectly but carries another
/// version is still the wrong bundle, and only the caller knows which one this
/// Assistant embeds.
///
/// The order of the checks is part of the contract and the tests assert it:
/// bounds first so nothing oversized is hashed, the signature next so no
/// unauthenticated byte reaches the parser, the meaning after that, and the
/// artefact's own digest last because it is the only step whose cost grows with
/// the bundle.
pub fn verify(
    anchor: &[u8],
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    expected_version: &str,
    artifact: &[u8],
) -> Result<VerifiedBundle, BundleRefusal> {
    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(BundleRefusal::ManifestTooLarge);
    }
    if artifact.len() > MAX_ARTIFACT_BYTES {
        return Err(BundleRefusal::ArtifactTooLarge);
    }
    let key = anchor_key(anchor)?;
    let signature = detached_signature(signature_bytes)?;
    key.verify(manifest_bytes, &signature)
        .map_err(|_| BundleRefusal::SignatureNotByAnchor)?;

    // Everything below reads bytes the anchor has answered for.
    let manifest = read_manifest(manifest_bytes)?;
    if manifest.target != SUPPORTED_TARGET {
        return Err(BundleRefusal::UnsupportedTarget);
    }
    if manifest.version != expected_version {
        return Err(BundleRefusal::UnexpectedVersion);
    }
    if manifest.size != artifact.len() as u64 {
        return Err(BundleRefusal::SizeMismatch);
    }
    if !digest_matches(&manifest.sha256, artifact) {
        return Err(BundleRefusal::DigestMismatch);
    }
    Ok(VerifiedBundle {
        version: manifest.version,
        target: manifest.target,
        size: manifest.size,
        sha256: manifest.sha256,
    })
}

fn anchor_key(anchor: &[u8]) -> Result<VerifyingKey, BundleRefusal> {
    let bytes: [u8; ANCHOR_PUBLIC_KEY_BYTES] = anchor
        .try_into()
        .map_err(|_| BundleRefusal::AnchorNotAKey)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| BundleRefusal::AnchorNotAKey)
}

fn detached_signature(signature_bytes: &[u8]) -> Result<Signature, BundleRefusal> {
    let bytes: [u8; SIGNATURE_BYTES] = signature_bytes
        .try_into()
        .map_err(|_| BundleRefusal::SignatureMalformed)?;
    Ok(Signature::from_bytes(&bytes))
}

/// Reads the authenticated bytes as the exact object this schema defines.
///
/// The five fields are required and no sixth is tolerated. Refusing an unknown
/// field is what keeps a future bundle — one that means something this build
/// cannot see — from being installed by a verifier that only checked the fields
/// it happened to know.
fn read_manifest(manifest_bytes: &[u8]) -> Result<Manifest, BundleRefusal> {
    let document: serde_json::Value =
        serde_json::from_slice(manifest_bytes).map_err(|_| BundleRefusal::ManifestUnreadable)?;
    let object = document
        .as_object()
        .ok_or(BundleRefusal::ManifestUnreadable)?;
    const FIELDS: [&str; 5] = ["schema_version", "kind", "version", "target", "sha256"];
    for name in object.keys() {
        if !FIELDS.contains(&name.as_str()) && name != "size" {
            return Err(BundleRefusal::ManifestUnknownField);
        }
    }

    let schema_version = object
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or(BundleRefusal::ManifestUnreadable)?;
    if schema_version != SCHEMA_VERSION {
        return Err(BundleRefusal::SchemaNotSupported);
    }
    let kind = text(object, "kind")?;
    if kind != BUNDLE_KIND {
        return Err(BundleRefusal::ForeignKind);
    }
    let sha256 = text(object, "sha256")?;
    if sha256.len() != DIGEST_ENCODED_BYTES
        || !sha256
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(BundleRefusal::ManifestUnreadable);
    }
    Ok(Manifest {
        version: text(object, "version")?.to_owned(),
        target: text(object, "target")?.to_owned(),
        size: object
            .get("size")
            .and_then(serde_json::Value::as_u64)
            .ok_or(BundleRefusal::ManifestUnreadable)?,
        sha256: sha256.to_owned(),
    })
}

fn text<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<&'a str, BundleRefusal> {
    object
        .get(name)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(BundleRefusal::ManifestUnreadable)
}

/// Compares the bound digest with the artefact's own, without ever building a
/// second hexadecimal string to compare against.
fn digest_matches(expected: &str, artifact: &[u8]) -> bool {
    let computed = Sha256::digest(artifact);
    if expected.len() != DIGEST_ENCODED_BYTES {
        return false;
    }
    let mut encoded = [0u8; DIGEST_ENCODED_BYTES];
    for (index, byte) in computed.iter().enumerate() {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        encoded[index * 2] = HEX[usize::from(byte >> 4)];
        encoded[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    encoded == expected.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const ARTIFACT: &[u8] = b"not a real .deb, but exactly these bytes";

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn hex_digest(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// One well-formed manifest for `ARTIFACT`, as JSON text.
    fn manifest_text() -> String {
        format!(
            concat!(
                "{{\"schema_version\":{},\"kind\":\"{}\",\"version\":\"0.0.3\",",
                "\"target\":\"{}\",\"size\":{},\"sha256\":\"{}\"}}"
            ),
            SCHEMA_VERSION,
            BUNDLE_KIND,
            SUPPORTED_TARGET,
            ARTIFACT.len(),
            hex_digest(ARTIFACT),
        )
    }

    /// Signs whatever text it is given, so a hostile case can sign its own
    /// alteration and prove the refusal is about meaning and not about the
    /// signature having been forgotten.
    fn signed(text: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let key = signing_key();
        let signature = key.sign(text.as_bytes());
        (
            key.verifying_key().to_bytes().to_vec(),
            text.as_bytes().to_vec(),
            signature.to_bytes().to_vec(),
        )
    }

    fn verify_text(text: &str) -> Result<VerifiedBundle, BundleRefusal> {
        let (anchor, manifest, signature) = signed(text);
        verify(&anchor, &manifest, &signature, "0.0.3", ARTIFACT)
    }

    /// The positive control. Everything below is this, minus one thing.
    #[test]
    fn a_signed_manifest_that_describes_the_artefact_is_verified() {
        let bundle = verify_text(&manifest_text()).expect("the positive control must be verified");

        assert_eq!(bundle.version(), "0.0.3");
        assert_eq!(bundle.target(), SUPPORTED_TARGET);
        assert_eq!(bundle.size(), ARTIFACT.len() as u64);
        assert_eq!(bundle.sha256(), hex_digest(ARTIFACT));
    }

    /// The property the whole palier rests on: an artefact whose digest is not
    /// the bound one is refused, whatever else is right about it.
    #[test]
    fn an_artefact_that_is_not_the_one_the_manifest_binds_is_refused() {
        let (anchor, manifest, signature) = signed(&manifest_text());
        let mut other = ARTIFACT.to_vec();
        // Same length, one byte different: the size check cannot be what
        // catches this, so the digest check must be.
        other[0] ^= 0x01;

        assert_eq!(
            verify(&anchor, &manifest, &signature, "0.0.3", &other),
            Err(BundleRefusal::DigestMismatch)
        );
    }

    #[test]
    fn an_artefact_of_another_length_is_refused_on_its_size() {
        let (anchor, manifest, signature) = signed(&manifest_text());
        let mut longer = ARTIFACT.to_vec();
        longer.push(b'!');

        assert_eq!(
            verify(&anchor, &manifest, &signature, "0.0.3", &longer),
            Err(BundleRefusal::SizeMismatch)
        );
    }

    /// A manifest altered after signing is refused, and it is refused *before*
    /// anything in it is read: the altered field is a target this build would
    /// otherwise have rejected with its own reason, and the signature answer is
    /// the one that comes back.
    #[test]
    fn an_altered_manifest_is_refused_on_its_signature_and_never_parsed() {
        let (anchor, _, signature) = signed(&manifest_text());
        let altered = manifest_text().replace(SUPPORTED_TARGET, "debian-13-arm64");

        assert_eq!(
            verify(&anchor, altered.as_bytes(), &signature, "0.0.3", ARTIFACT),
            Err(BundleRefusal::SignatureNotByAnchor)
        );
    }

    /// Even bytes that are not JSON at all come back as a signature refusal
    /// rather than a parser error: the parser never sees them.
    #[test]
    fn unauthenticated_bytes_never_reach_the_parser() {
        let (anchor, _, signature) = signed(&manifest_text());

        assert_eq!(
            verify(&anchor, b"\x00\xff not json", &signature, "0.0.3", ARTIFACT),
            Err(BundleRefusal::SignatureNotByAnchor)
        );
    }

    /// A manifest signed by a perfectly good key that is not the anchor is
    /// refused. This is the case a stolen-but-unauthorised signer produces.
    #[test]
    fn a_manifest_signed_by_another_key_is_refused() {
        let stranger = SigningKey::from_bytes(&[9u8; 32]);
        let text = manifest_text();
        let signature = stranger.sign(text.as_bytes());
        let anchor = signing_key().verifying_key().to_bytes();

        assert_eq!(
            verify(
                &anchor,
                text.as_bytes(),
                &signature.to_bytes(),
                "0.0.3",
                ARTIFACT
            ),
            Err(BundleRefusal::SignatureNotByAnchor)
        );
    }

    /// Each of these alterations is *signed by the anchor*, so the only thing
    /// that can refuse it is the meaning check it names.
    #[test]
    fn every_bound_value_is_refused_by_its_own_reason() {
        let cases: [(String, BundleRefusal); 5] = [
            (
                manifest_text().replace(SUPPORTED_TARGET, "debian-13-arm64"),
                BundleRefusal::UnsupportedTarget,
            ),
            (
                manifest_text().replace("\"0.0.3\"", "\"0.0.4\""),
                BundleRefusal::UnexpectedVersion,
            ),
            (
                manifest_text().replace(BUNDLE_KIND, "your-cloud-console-linux-candidate"),
                BundleRefusal::ForeignKind,
            ),
            (
                manifest_text().replace("\"schema_version\":1", "\"schema_version\":2"),
                BundleRefusal::SchemaNotSupported,
            ),
            (
                manifest_text().replace("{\"schema_version\"", "{\"extra\":1,\"schema_version\""),
                BundleRefusal::ManifestUnknownField,
            ),
        ];

        for (text, expected) in cases {
            assert_eq!(verify_text(&text), Err(expected), "manifest was: {text}");
        }
    }

    /// `arm64` is refused as a decision, not as an oversight. The architecture
    /// contract announces a second architecture only after its own LAB proof.
    #[test]
    fn arm64_is_refused_even_though_the_bundle_is_otherwise_perfect() {
        let text = manifest_text().replace(SUPPORTED_TARGET, "debian-13-arm64");

        assert_eq!(verify_text(&text), Err(BundleRefusal::UnsupportedTarget));
    }

    #[test]
    fn an_anchor_that_is_not_a_key_and_a_signature_that_is_not_one_are_refused() {
        let (anchor, manifest, signature) = signed(&manifest_text());

        assert_eq!(
            verify(&[0u8; 31], &manifest, &signature, "0.0.3", ARTIFACT),
            Err(BundleRefusal::AnchorNotAKey)
        );
        assert_eq!(
            verify(&anchor, &manifest, &signature[..63], "0.0.3", ARTIFACT),
            Err(BundleRefusal::SignatureMalformed)
        );
    }

    /// The two bounds are spent before any hashing or any signature check, so
    /// an oversized input is refused rather than processed.
    #[test]
    fn oversized_inputs_are_refused_before_anything_is_computed() {
        let (anchor, _, signature) = signed(&manifest_text());
        let oversized_manifest = vec![b'{'; MAX_MANIFEST_BYTES + 1];

        assert_eq!(
            verify(&anchor, &oversized_manifest, &signature, "0.0.3", ARTIFACT),
            Err(BundleRefusal::ManifestTooLarge)
        );
    }

    /// A digest field that is not 64 lowercase hexadecimal characters is
    /// refused as unreadable rather than compared loosely.
    #[test]
    fn a_digest_field_that_is_not_a_digest_is_refused() {
        let uppercased = manifest_text().replace(&hex_digest(ARTIFACT), &"A".repeat(64));

        assert_eq!(
            verify_text(&uppercased),
            Err(BundleRefusal::ManifestUnreadable)
        );
    }
}
