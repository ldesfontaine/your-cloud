//! Pre-KDF validation of a personal OpenSSH private key envelope.
//!
//! Everything here happens *before* any key derivation. A hostile or corrupt
//! file must be refused while it still costs nothing: deriving first and
//! checking afterwards would let a declared round count burn the whole
//! non-renewable TTL, and would ask the user for a passphrase that can never
//! be used. The format is the one documented by OpenSSH in `PROTOCOL.key`.

use super::algorithms::{IdentityKeyType, IdentitySignatureAlgorithm};

/// Largest personal key file opened. A real OpenSSH key is a few kibibytes;
/// this bound exists so an oversized file is refused before it is parsed.
pub const MAX_KEY_FILE_BYTES: usize = 64 * 1024;

/// The single accepted symmetric cipher of the key file.
pub const REQUIRED_CIPHER: &str = "aes256-ctr";

/// The single accepted key derivation function. Refusing `none` here is what
/// rejects an unencrypted private key.
pub const REQUIRED_KDF: &str = "bcrypt";

/// Smallest accepted RSA modulus. Ed25519 has no equivalent parameter.
pub const MIN_RSA_MODULUS_BITS: u32 = 3072;

/// Largest accepted bcrypt round count.
///
/// This bound is a sanity gate, not the security guarantee: the guarantee is
/// the non-renewable monotonic deadline enforced *during* the derivation.
///
/// It comes from a measurement, not from a guess. On the reference Console
/// host of the LAB — a deliberately modest two-vCPU Debian 13 machine —
/// `bcrypt_pbkdf` costs about 4.6 ms per round, identically for Ed25519 and
/// RSA 3072 because the derivation does not depend on the key type. This
/// bound therefore spends at most about ten seconds of the three hundred
/// second deadline, while staying two orders of magnitude above the OpenSSH
/// default of sixteen rounds so that a deliberately hardened personal key is
/// still opened. A declared `u32::MAX` would need months and is refused here,
/// before any derivation starts.
pub const MAX_BCRYPT_ROUNDS: u32 = 2048;

const AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";
const PEM_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PEM_END: &str = "-----END OPENSSH PRIVATE KEY-----";
const CIPHER_BLOCK_BYTES: usize = 16;
const MAX_SALT_BYTES: usize = 64;
const ED25519_POINT_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeRefusal {
    FileTooLarge,
    PemEnvelope,
    Base64,
    Magic,
    Truncated,
    TrailingData,
    Cipher,
    Kdf,
    KdfOptions,
    Rounds,
    KeyCount,
    PublicKey,
    IdentityKeyType,
    RsaTooSmall,
    EncryptedBlob,
}

/// What the envelope declares, once every pre-KDF check has passed. It carries
/// no key material and no passphrase: only the parameters needed to decide
/// whether the derivation may be attempted at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedEnvelope {
    pub key_type: IdentityKeyType,
    pub rounds: u32,
    pub rsa_modulus_bits: Option<u32>,
}

impl ValidatedEnvelope {
    pub fn accepted_signature_algorithms(&self) -> &'static [IdentitySignatureAlgorithm] {
        self.key_type.accepted_signature_algorithms()
    }
}

/// Validates the envelope without deriving anything.
///
/// Returning `Ok` means the derivation may be attempted; it does not mean the
/// passphrase is known, the key is usable, or a connection is authorised.
pub fn validate(bytes: &[u8]) -> Result<ValidatedEnvelope, EnvelopeRefusal> {
    if bytes.len() > MAX_KEY_FILE_BYTES {
        return Err(EnvelopeRefusal::FileTooLarge);
    }
    let body = pem_body(bytes).ok_or(EnvelopeRefusal::PemEnvelope)?;
    let decoded = decode_base64(&body).ok_or(EnvelopeRefusal::Base64)?;
    if !decoded.starts_with(AUTH_MAGIC) {
        return Err(EnvelopeRefusal::Magic);
    }

    let mut reader = WireReader::new(&decoded[AUTH_MAGIC.len()..]);
    let cipher = reader.read_string().ok_or(EnvelopeRefusal::Truncated)?;
    if cipher != REQUIRED_CIPHER.as_bytes() {
        return Err(EnvelopeRefusal::Cipher);
    }
    let kdf = reader.read_string().ok_or(EnvelopeRefusal::Truncated)?;
    if kdf != REQUIRED_KDF.as_bytes() {
        return Err(EnvelopeRefusal::Kdf);
    }
    let kdf_options = reader.read_string().ok_or(EnvelopeRefusal::Truncated)?;
    let rounds = bcrypt_rounds(kdf_options)?;

    // A personal key file carries exactly one key. Anything else is refused
    // rather than partially interpreted.
    let key_count = reader.read_u32().ok_or(EnvelopeRefusal::Truncated)?;
    if key_count != 1 {
        return Err(EnvelopeRefusal::KeyCount);
    }

    let public_key = reader.read_string().ok_or(EnvelopeRefusal::Truncated)?;
    let (key_type, rsa_modulus_bits) = public_identity(public_key)?;

    let encrypted = reader.read_string().ok_or(EnvelopeRefusal::Truncated)?;
    if encrypted.is_empty() || encrypted.len() % CIPHER_BLOCK_BYTES != 0 {
        return Err(EnvelopeRefusal::EncryptedBlob);
    }
    if reader.remaining() != 0 {
        return Err(EnvelopeRefusal::TrailingData);
    }

    Ok(ValidatedEnvelope {
        key_type,
        rounds,
        rsa_modulus_bits,
    })
}

fn bcrypt_rounds(options: &[u8]) -> Result<u32, EnvelopeRefusal> {
    let mut reader = WireReader::new(options);
    let salt = reader.read_string().ok_or(EnvelopeRefusal::KdfOptions)?;
    if salt.is_empty() || salt.len() > MAX_SALT_BYTES {
        return Err(EnvelopeRefusal::KdfOptions);
    }
    let rounds = reader.read_u32().ok_or(EnvelopeRefusal::KdfOptions)?;
    if reader.remaining() != 0 {
        return Err(EnvelopeRefusal::KdfOptions);
    }
    // Zero rounds would mean the file is not actually protected by the KDF it
    // declares. The upper bound keeps a declared count from consuming the TTL.
    if rounds == 0 || rounds > MAX_BCRYPT_ROUNDS {
        return Err(EnvelopeRefusal::Rounds);
    }
    Ok(rounds)
}

fn public_identity(blob: &[u8]) -> Result<(IdentityKeyType, Option<u32>), EnvelopeRefusal> {
    let mut reader = WireReader::new(blob);
    let raw_type = reader.read_string().ok_or(EnvelopeRefusal::PublicKey)?;
    let raw_type = std::str::from_utf8(raw_type).map_err(|_| EnvelopeRefusal::PublicKey)?;
    let key_type =
        IdentityKeyType::from_public_key_type(raw_type).ok_or(EnvelopeRefusal::IdentityKeyType)?;

    match key_type {
        IdentityKeyType::Ed25519 => {
            let point = reader.read_string().ok_or(EnvelopeRefusal::PublicKey)?;
            if point.len() != ED25519_POINT_BYTES || reader.remaining() != 0 {
                return Err(EnvelopeRefusal::PublicKey);
            }
            Ok((key_type, None))
        }
        IdentityKeyType::Rsa => {
            let _exponent = reader.read_string().ok_or(EnvelopeRefusal::PublicKey)?;
            let modulus = reader.read_string().ok_or(EnvelopeRefusal::PublicKey)?;
            if reader.remaining() != 0 {
                return Err(EnvelopeRefusal::PublicKey);
            }
            let bits = mpint_bits(modulus).ok_or(EnvelopeRefusal::PublicKey)?;
            if bits < MIN_RSA_MODULUS_BITS {
                return Err(EnvelopeRefusal::RsaTooSmall);
            }
            Ok((key_type, Some(bits)))
        }
    }
}

fn mpint_bits(value: &[u8]) -> Option<u32> {
    let first = value.iter().position(|byte| *byte != 0)?;
    let significant = &value[first..];
    let leading = significant.first()?.leading_zeros();
    u32::try_from(significant.len())
        .ok()?
        .checked_mul(8)?
        .checked_sub(leading)
}

fn pem_body(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.lines();
    if lines.next()?.trim_end() != PEM_BEGIN {
        return None;
    }
    let mut body = String::new();
    let mut closed = false;
    for line in lines.by_ref() {
        let line = line.trim_end();
        if line == PEM_END {
            closed = true;
            break;
        }
        if line.is_empty() {
            return None;
        }
        body.push_str(line);
    }
    if !closed {
        return None;
    }
    // Nothing may follow the end marker: a second concatenated document would
    // otherwise be silently ignored.
    if lines.any(|line| !line.trim().is_empty()) {
        return None;
    }
    Some(body)
}

/// Bounded, canonical base64 decoder.
///
/// The helper keeps a deliberately small dependency closure, audited down to
/// its shared objects, so this stays local rather than pulling a crate into a
/// binary that handles secrets. Non-canonical input fails closed.
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut padding: usize = 0;
    let mut output = Vec::new();
    for byte in input.bytes() {
        if byte == b'=' {
            padding += 1;
            continue;
        }
        if padding > 0 {
            // Data after padding is never canonical base64.
            return None;
        }
        let value = base64_value(byte)?;
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((accumulator >> bits) & 0xFF) as u8);
        }
    }
    // Canonical base64 ties the leftover bit count to the padding length, and
    // leaves the leftover bits themselves at zero.
    let expected_padding = match bits {
        0 => 0,
        4 => 2,
        2 => 1,
        _ => return None,
    };
    if padding != expected_padding {
        return None;
    }
    if bits > 0 && (accumulator & ((1_u32 << bits) - 1)) != 0 {
        return None;
    }
    Some(output)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

struct WireReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> WireReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u32(&mut self) -> Option<u32> {
        let end = self.offset.checked_add(4)?;
        let slice = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    fn read_string(&mut self) -> Option<&'a [u8]> {
        let length = usize::try_from(self.read_u32()?).ok()?;
        let end = self.offset.checked_add(length)?;
        let slice = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(slice)
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE64_ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn ssh_string(bytes: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(bytes.len())
            .expect("bounded")
            .to_be_bytes()
            .to_vec();
        out.extend_from_slice(bytes);
        out
    }

    fn encode_base64(bytes: &[u8]) -> String {
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let first = u32::from(chunk[0]);
            let second = u32::from(chunk.get(1).copied().unwrap_or(0));
            let third = u32::from(chunk.get(2).copied().unwrap_or(0));
            let triple = (first << 16) | (second << 8) | third;
            out.push(BASE64_ALPHABET[((triple >> 18) & 63) as usize] as char);
            out.push(BASE64_ALPHABET[((triple >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                out.push(BASE64_ALPHABET[((triple >> 6) & 63) as usize] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(BASE64_ALPHABET[(triple & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    fn ed25519_public_key() -> Vec<u8> {
        let mut blob = ssh_string(b"ssh-ed25519");
        blob.extend_from_slice(&ssh_string(&[7_u8; ED25519_POINT_BYTES]));
        blob
    }

    fn rsa_public_key(modulus_bits: usize) -> Vec<u8> {
        let mut modulus = vec![0_u8; modulus_bits / 8];
        modulus[0] = 0x80;
        let mut blob = ssh_string(b"ssh-rsa");
        blob.extend_from_slice(&ssh_string(&[0x01, 0x00, 0x01]));
        blob.extend_from_slice(&ssh_string(&modulus));
        blob
    }

    struct Envelope {
        magic: Vec<u8>,
        cipher: Vec<u8>,
        kdf: Vec<u8>,
        salt: Vec<u8>,
        rounds: u32,
        kdf_options_trailer: Vec<u8>,
        key_count: u32,
        public_key: Vec<u8>,
        encrypted: Vec<u8>,
        trailing: Vec<u8>,
    }

    impl Envelope {
        fn ed25519() -> Self {
            Self {
                magic: AUTH_MAGIC.to_vec(),
                cipher: REQUIRED_CIPHER.as_bytes().to_vec(),
                kdf: REQUIRED_KDF.as_bytes().to_vec(),
                salt: vec![3_u8; 16],
                rounds: 16,
                kdf_options_trailer: Vec::new(),
                key_count: 1,
                public_key: ed25519_public_key(),
                encrypted: vec![9_u8; 48],
                trailing: Vec::new(),
            }
        }

        fn body(&self) -> Vec<u8> {
            let mut options = ssh_string(&self.salt);
            options.extend_from_slice(&self.rounds.to_be_bytes());
            options.extend_from_slice(&self.kdf_options_trailer);

            let mut body = self.magic.clone();
            body.extend_from_slice(&ssh_string(&self.cipher));
            body.extend_from_slice(&ssh_string(&self.kdf));
            body.extend_from_slice(&ssh_string(&options));
            body.extend_from_slice(&self.key_count.to_be_bytes());
            body.extend_from_slice(&ssh_string(&self.public_key));
            body.extend_from_slice(&ssh_string(&self.encrypted));
            body.extend_from_slice(&self.trailing);
            body
        }

        fn pem(&self) -> Vec<u8> {
            let encoded = encode_base64(&self.body());
            let mut text = String::from(PEM_BEGIN);
            text.push('\n');
            for chunk in encoded.as_bytes().chunks(70) {
                text.push_str(std::str::from_utf8(chunk).expect("ascii"));
                text.push('\n');
            }
            text.push_str(PEM_END);
            text.push('\n');
            text.into_bytes()
        }
    }

    #[test]
    fn a_nominal_ed25519_envelope_is_accepted_without_deriving() {
        let validated = validate(&Envelope::ed25519().pem()).expect("nominal ed25519");
        assert_eq!(validated.key_type, IdentityKeyType::Ed25519);
        assert_eq!(validated.rounds, 16);
        assert_eq!(validated.rsa_modulus_bits, None);
        assert_eq!(
            validated.accepted_signature_algorithms(),
            [IdentitySignatureAlgorithm::Ed25519]
        );
    }

    #[test]
    fn a_nominal_rsa_3072_envelope_is_accepted_and_never_signs_with_sha1() {
        let mut envelope = Envelope::ed25519();
        envelope.public_key = rsa_public_key(3072);
        let validated = validate(&envelope.pem()).expect("nominal rsa 3072");
        assert_eq!(validated.key_type, IdentityKeyType::Rsa);
        assert_eq!(validated.rsa_modulus_bits, Some(3072));
        assert_eq!(
            validated.accepted_signature_algorithms(),
            [
                IdentitySignatureAlgorithm::RsaSha512,
                IdentitySignatureAlgorithm::RsaSha256
            ]
        );
    }

    #[test]
    fn an_unencrypted_key_is_refused_before_any_derivation() {
        let mut envelope = Envelope::ed25519();
        envelope.kdf = b"none".to_vec();
        assert_eq!(validate(&envelope.pem()), Err(EnvelopeRefusal::Kdf));

        let mut envelope = Envelope::ed25519();
        envelope.cipher = b"none".to_vec();
        assert_eq!(validate(&envelope.pem()), Err(EnvelopeRefusal::Cipher));
    }

    #[test]
    fn round_counts_outside_the_bound_are_refused_before_the_kdf() {
        for rounds in [0, MAX_BCRYPT_ROUNDS + 1, u32::MAX] {
            let mut envelope = Envelope::ed25519();
            envelope.rounds = rounds;
            assert_eq!(
                validate(&envelope.pem()),
                Err(EnvelopeRefusal::Rounds),
                "round count {rounds} must fail closed"
            );
        }
        for rounds in [1, MAX_BCRYPT_ROUNDS] {
            let mut envelope = Envelope::ed25519();
            envelope.rounds = rounds;
            assert!(
                validate(&envelope.pem()).is_ok(),
                "round count {rounds} sits on the accepted boundary"
            );
        }
    }

    #[test]
    fn an_rsa_key_below_the_minimum_modulus_is_refused() {
        for bits in [1024, 2048] {
            let mut envelope = Envelope::ed25519();
            envelope.public_key = rsa_public_key(bits);
            assert_eq!(
                validate(&envelope.pem()),
                Err(EnvelopeRefusal::RsaTooSmall),
                "an RSA {bits} modulus must fail closed"
            );
        }
    }

    #[test]
    fn refused_key_types_never_reach_the_kdf() {
        let mut envelope = Envelope::ed25519();
        envelope.public_key = ssh_string(b"ssh-dss");
        assert_eq!(
            validate(&envelope.pem()),
            Err(EnvelopeRefusal::IdentityKeyType)
        );

        let mut envelope = Envelope::ed25519();
        envelope.public_key = ssh_string(b"ecdsa-sha2-nistp256");
        assert_eq!(
            validate(&envelope.pem()),
            Err(EnvelopeRefusal::IdentityKeyType)
        );
    }

    #[test]
    fn foreign_formats_are_refused_without_implicit_detection() {
        for header in [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "PuTTY-User-Key-File-3: ssh-ed25519",
        ] {
            let document = format!("{header}\nAAAA\n-----END RSA PRIVATE KEY-----\n");
            assert_eq!(
                validate(document.as_bytes()),
                Err(EnvelopeRefusal::PemEnvelope),
                "{header} must fail closed"
            );
        }
    }

    #[test]
    fn a_wrong_magic_is_refused() {
        let mut envelope = Envelope::ed25519();
        envelope.magic = b"openssh-key-v2\0".to_vec();
        assert_eq!(validate(&envelope.pem()), Err(EnvelopeRefusal::Magic));
    }

    #[test]
    fn several_declared_keys_are_refused_rather_than_partially_read() {
        for key_count in [0, 2, u32::MAX] {
            let mut envelope = Envelope::ed25519();
            envelope.key_count = key_count;
            assert_eq!(
                validate(&envelope.pem()),
                Err(EnvelopeRefusal::KeyCount),
                "a declared count of {key_count} must fail closed"
            );
        }
    }

    #[test]
    fn trailing_and_truncated_payloads_are_refused() {
        let mut envelope = Envelope::ed25519();
        envelope.trailing = vec![0_u8; 8];
        assert_eq!(
            validate(&envelope.pem()),
            Err(EnvelopeRefusal::TrailingData)
        );

        let mut envelope = Envelope::ed25519();
        envelope.kdf_options_trailer = vec![0_u8; 4];
        assert_eq!(validate(&envelope.pem()), Err(EnvelopeRefusal::KdfOptions));

        let full = Envelope::ed25519().body();
        for cut in [1, 20, full.len() - 1] {
            let encoded = encode_base64(&full[..cut]);
            let document = format!("{PEM_BEGIN}\n{encoded}\n{PEM_END}\n");
            assert!(
                validate(document.as_bytes()).is_err(),
                "a payload truncated at {cut} must fail closed"
            );
        }
    }

    #[test]
    fn an_encrypted_blob_off_the_cipher_block_is_refused() {
        for length in [0, 15, 17, 47] {
            let mut envelope = Envelope::ed25519();
            envelope.encrypted = vec![9_u8; length];
            assert_eq!(
                validate(&envelope.pem()),
                Err(EnvelopeRefusal::EncryptedBlob),
                "an encrypted blob of {length} bytes must fail closed"
            );
        }
    }

    #[test]
    fn an_oversized_file_is_refused_before_parsing() {
        let oversized = vec![b'A'; MAX_KEY_FILE_BYTES + 1];
        assert_eq!(
            validate(&oversized),
            Err(EnvelopeRefusal::FileTooLarge),
            "the size bound precedes every parse"
        );
    }

    #[test]
    fn non_canonical_base64_is_refused() {
        for body in ["AAAA=AAA", "AA*A", "AAAAA===", "AAB="] {
            let document = format!("{PEM_BEGIN}\n{body}\n{PEM_END}\n");
            assert!(
                validate(document.as_bytes()).is_err(),
                "{body} must fail closed"
            );
        }
    }

    #[test]
    fn a_second_concatenated_document_is_refused() {
        let first = String::from_utf8(Envelope::ed25519().pem()).expect("ascii");
        let document = format!("{first}{first}");
        assert_eq!(
            validate(document.as_bytes()),
            Err(EnvelopeRefusal::PemEnvelope)
        );
    }
}
