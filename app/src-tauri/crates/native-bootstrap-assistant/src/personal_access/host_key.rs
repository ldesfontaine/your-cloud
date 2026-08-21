//! Exact host key attestation for the personal access.
//!
//! The approved perimeter carries the host key the user confirmed. This
//! module compares what the server presents against that exact key and
//! nothing else.
//!
//! There is deliberately **no trust-on-first-use path**: no function here
//! accepts an unknown key, remembers one, or reports "no key was approved" as
//! anything other than a refusal. There is likewise no write path — nothing
//! appends to `known_hosts`, because an assistant that records trust would
//! turn a single mistaken approval into a durable one.
//!
//! Two encodings meet here, and confusing them was a real gap. The approved
//! perimeter carries a SHA-256 *fingerprint* — `SHA256:` followed by the
//! base64 digest, exactly what OpenSSH prints — while a stored public key file
//! carries an OpenSSH *line*. [`attest_presented`] is the one the transport
//! uses: it takes the key the server actually presented, computes its
//! fingerprint and compares that to the perimeter. [`attest`] compares two
//! OpenSSH lines and stays available for the file-to-file case. Neither of
//! them ever accepts an unapproved key.
//!
//! Attesting the key is not by itself enough. A key type and the signature
//! algorithms it may use are different namespaces, so the algorithm the
//! transport actually negotiated is confronted with the positive list of the
//! attested key type. Without that check a server could present an approved
//! key and still have signed the exchange with an algorithm this palier
//! refuses.

use russh::keys::{HashAlg, PublicKey};

use super::algorithms::{HostKeyAlgorithm, HostKeyType};

/// Largest accepted OpenSSH public key line. A 3072-bit RSA key encodes to
/// roughly 570 bytes; this leaves room without accepting an unbounded field.
pub const MAX_HOST_KEY_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostKeyRefusal {
    /// The perimeter carried no approved key. This is a refusal, never an
    /// invitation to trust whatever answers.
    NoApprovedKey,
    ApprovedMalformed,
    OfferedMalformed,
    TooLong,
    /// The key type sits outside the positive list of [`super::algorithms`].
    AlgorithmRefused,
    /// A well-formed key that is not the approved one.
    KeyMismatch,
    /// The negotiated signature algorithm is not one this key type may use.
    SignatureAlgorithmMismatch,
}

/// Exact length of a rendered SHA-256 fingerprint: `SHA256:` and 43 base64
/// characters, the unpadded encoding of a 32-byte digest.
pub const HOST_KEY_FINGERPRINT_BYTES: usize = 7 + 43;

/// Confronts the key a server really presented with the approved fingerprint.
///
/// `negotiated_signature_algorithm` is the wire name the transport settled on
/// for the host key signature. It is checked against the positive list of the
/// attested key type, because a key type and a signature algorithm are two
/// different namespaces and only their pairing is meaningful.
pub fn attest_presented(
    approved_fingerprint: &str,
    presented: &PublicKey,
    negotiated_signature_algorithm: &str,
) -> Result<HostKeyType, HostKeyRefusal> {
    if approved_fingerprint.trim().is_empty() {
        return Err(HostKeyRefusal::NoApprovedKey);
    }
    // The perimeter already bounds this field; checking again keeps the module
    // usable on its own without inheriting someone else's validation.
    if approved_fingerprint.len() != HOST_KEY_FINGERPRINT_BYTES {
        return Err(HostKeyRefusal::ApprovedMalformed);
    }

    // The blob announces the *key type*: `ssh-ed25519` or `ssh-rsa`, never a
    // signature algorithm name.
    let presented_type = HostKeyType::from_key_type_name(presented.algorithm().as_str())
        .ok_or(HostKeyRefusal::AlgorithmRefused)?;
    if presented.fingerprint(HashAlg::Sha256).to_string() != approved_fingerprint {
        return Err(HostKeyRefusal::KeyMismatch);
    }

    let negotiated = HostKeyAlgorithm::from_wire_name(negotiated_signature_algorithm)
        .ok_or(HostKeyRefusal::AlgorithmRefused)?;
    if !presented_type
        .accepted_signature_algorithms()
        .contains(&negotiated)
    {
        return Err(HostKeyRefusal::SignatureAlgorithmMismatch);
    }
    Ok(presented_type)
}

/// Compares the presented host key with the approved one.
///
/// Returns the key type actually attested, so the caller records what was
/// verified rather than what it hoped for. The type is what a host key line
/// carries — `ssh-ed25519` or `ssh-rsa` — never a signature algorithm name.
pub fn attest(approved: &str, offered: &str) -> Result<HostKeyType, HostKeyRefusal> {
    if approved.trim().is_empty() {
        return Err(HostKeyRefusal::NoApprovedKey);
    }
    if approved.len() > MAX_HOST_KEY_BYTES || offered.len() > MAX_HOST_KEY_BYTES {
        return Err(HostKeyRefusal::TooLong);
    }
    let approved = parse(approved).ok_or(HostKeyRefusal::ApprovedMalformed)?;
    let offered = parse(offered).ok_or(HostKeyRefusal::OfferedMalformed)?;

    // The approved perimeter is checked against the positive list too: a
    // perimeter that somehow carried a refused algorithm must not become the
    // reason to accept it.
    let approved_type = HostKeyType::from_key_type_name(approved.algorithm)
        .ok_or(HostKeyRefusal::AlgorithmRefused)?;
    let offered_type = HostKeyType::from_key_type_name(offered.algorithm)
        .ok_or(HostKeyRefusal::AlgorithmRefused)?;

    if approved_type != offered_type || approved.material != offered.material {
        return Err(HostKeyRefusal::KeyMismatch);
    }
    Ok(offered_type)
}

struct HostKeyLine<'a> {
    algorithm: &'a str,
    material: &'a str,
}

/// Splits `algorithm material [comment]`. The comment is ignored on purpose:
/// it is arbitrary text and must never take part in the decision.
fn parse(line: &str) -> Option<HostKeyLine<'_>> {
    let mut fields = line.split_ascii_whitespace();
    let algorithm = fields.next()?;
    let material = fields.next()?;
    if algorithm.is_empty() || material.is_empty() {
        return None;
    }
    // The material is base64; anything else is not an OpenSSH key line.
    if !material
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/' || byte == b'=')
    {
        return None;
    }
    Some(HostKeyLine {
        algorithm,
        material,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::personal_access::algorithms::HostKeyAlgorithm;

    /// Lignes réelles relevées sur `lab-machine-1`, une Debian 13 du LAB.
    /// Elles sont conservées telles quelles parce qu'une ligne inventée
    /// n'exerce pas le piège : un vrai `ssh_host_rsa_key.pub` annonce le type
    /// `ssh-rsa`, jamais un nom d'algorithme de signature.
    const REAL_ED25519: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMQkSXT5BjDYk39c6d88pt38j5Hyu3sI2iHJrKxv2lpt root@lab-machine-1";
    const REAL_RSA: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCeAjEw1gh9mgA+LXxPohtXsmdg8gMeZa9cGZIEB3GzMmbCK8Zzld+BMw+WR2qT0PtLE2CT85GxIMB0RYui0CW+4QQiQxOENzCY4+tKRjK9NMlt2XT6unR4/JVBXIxwM4rAo8SmWgtc1FdPu/u6QkoqnCMG72b6CH3GEOkVI9KJ5xoqSvFZnVdZrAGXSS3WHBUqVtX7oTzFh+hwqDeTdqh5DH6hpVrp8NIKVUpjR4Kj3lUGzg6kxeEXCu5xhcMkMEOcojK4PAwSwvLTdcX5u7fer8tH4alEMbkOwBJrZU3kb/GcPrjWA1cfpYGBjAzkYgT7kvwCPgco+KQ7p4SALSDqK8TnzkTl08MkXSFQkP+1ED/ylKUC5mTsJd9AN7FVT4DlHAocHXkTLwYraV2INt/RiqacmapkGzJ2KWfWBRF8fbG0OPQ8Rf1IU671zm15X2jUUqoM0mb2SFvZrT+KSJ5XDkTrqQEBSLnLVAf1ErQ3FsdW3GiBfeN+J0yExY3VYBs= root@lab-machine-1";
    const REAL_ECDSA: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOzWb92mhSq78u3VB7S1WAk0C3xwfPyZfDo4D7xAe0u/Tbgrk+PRCTwXyWLoWhSw8Q6ypRmFVkqK6BcVJ3D+WOo= root@lab-machine-1";

    const OTHER_ED25519: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKx9BvQnW2sMdRfYuLpTcHo4EgZaN1jVkS7mXwPrDtCb";

    #[test]
    fn the_real_ed25519_host_key_of_a_lab_machine_is_attested() {
        assert_eq!(attest(REAL_ED25519, REAL_ED25519), Ok(HostKeyType::Ed25519));
    }

    /// Régression : une validation contre la liste des algorithmes de
    /// signature refuserait cette ligne, donc toute machine à clé RSA.
    #[test]
    fn the_real_rsa_host_key_announces_a_key_type_not_a_signature_algorithm() {
        assert_eq!(REAL_RSA.split_whitespace().next(), Some("ssh-rsa"));
        assert_eq!(
            HostKeyAlgorithm::from_wire_name("ssh-rsa"),
            None,
            "ssh-rsa n'est pas un algorithme de signature accepté"
        );
        assert_eq!(
            attest(REAL_RSA, REAL_RSA),
            Ok(HostKeyType::Rsa),
            "mais c'est un type de clé d'hôte parfaitement légitime"
        );
    }

    #[test]
    fn an_attested_key_type_names_its_signature_algorithms() {
        assert_eq!(
            HostKeyType::Rsa.accepted_signature_algorithms(),
            [HostKeyAlgorithm::RsaSha512, HostKeyAlgorithm::RsaSha256]
        );
        assert_eq!(
            HostKeyType::Ed25519.accepted_signature_algorithms(),
            [HostKeyAlgorithm::Ed25519]
        );
    }

    /// La machine du LAB sert aussi une clé ECDSA. Elle doit être refusée
    /// même si le serveur la propose réellement.
    #[test]
    fn the_real_ecdsa_host_key_of_the_same_machine_is_refused() {
        assert_eq!(
            attest(REAL_ECDSA, REAL_ECDSA),
            Err(HostKeyRefusal::AlgorithmRefused)
        );
    }

    #[test]
    fn a_trailing_comment_never_takes_part_in_the_decision() {
        let without = REAL_ED25519.rsplit_once(' ').expect("comment").0;
        assert_eq!(attest(without, REAL_ED25519), Ok(HostKeyType::Ed25519));
        assert_eq!(attest(REAL_ED25519, without), Ok(HostKeyType::Ed25519));
    }

    #[test]
    fn extra_whitespace_does_not_change_the_verdict() {
        let spaced = REAL_ED25519.replace(' ', "   ");
        assert_eq!(attest(REAL_ED25519, &spaced), Ok(HostKeyType::Ed25519));
    }

    #[test]
    fn a_different_key_of_the_same_type_is_refused() {
        assert_eq!(
            attest(REAL_ED25519, OTHER_ED25519),
            Err(HostKeyRefusal::KeyMismatch),
            "this is the man-in-the-middle case the attestation exists for"
        );
    }

    #[test]
    fn two_real_keys_of_the_same_machine_are_not_interchangeable() {
        assert_eq!(
            attest(REAL_ED25519, REAL_RSA),
            Err(HostKeyRefusal::KeyMismatch)
        );
    }

    /// The property that matters most: nothing here accepts an unknown key.
    #[test]
    fn an_absent_approved_key_is_a_refusal_not_a_first_use() {
        for approved in ["", "   ", "\n"] {
            assert_eq!(
                attest(approved, REAL_ED25519),
                Err(HostKeyRefusal::NoApprovedKey),
                "an empty perimeter must never authorise trust on first use"
            );
        }
    }

    #[test]
    fn refused_key_types_are_never_attested() {
        let material = REAL_ED25519.split_whitespace().nth(1).expect("material");
        for key_type in [
            "ssh-dss",
            "ecdsa-sha2-nistp256",
            "sk-ssh-ed25519@openssh.com",
            "ssh-ed25519-cert-v01@openssh.com",
            "rsa-sha2-512",
        ] {
            let line = format!("{key_type} {material}");
            assert_eq!(
                attest(&line, &line),
                Err(HostKeyRefusal::AlgorithmRefused),
                "{key_type} must fail closed even when both sides agree"
            );
        }
    }

    #[test]
    fn malformed_lines_are_refused_on_the_side_they_come_from() {
        assert_eq!(
            attest("ssh-ed25519", REAL_ED25519),
            Err(HostKeyRefusal::ApprovedMalformed)
        );
        assert_eq!(
            attest(REAL_ED25519, "ssh-ed25519"),
            Err(HostKeyRefusal::OfferedMalformed)
        );
        assert_eq!(
            attest(REAL_ED25519, "ssh-ed25519 not!base64"),
            Err(HostKeyRefusal::OfferedMalformed)
        );
    }

    fn public_key(line: &str) -> PublicKey {
        PublicKey::from_openssh(line).expect("real OpenSSH public key line")
    }

    fn fingerprint(line: &str) -> String {
        public_key(line).fingerprint(HashAlg::Sha256).to_string()
    }

    /// The bridge the perimeter actually needs: what the server presents is
    /// reduced to a fingerprint and compared with the approved one.
    #[test]
    fn the_presented_key_of_a_lab_machine_matches_its_own_fingerprint() {
        let key = public_key(REAL_ED25519);
        let approved = fingerprint(REAL_ED25519);
        assert_eq!(
            attest_presented(&approved, &key, "ssh-ed25519"),
            Ok(HostKeyType::Ed25519)
        );

        let rsa = public_key(REAL_RSA);
        let approved_rsa = fingerprint(REAL_RSA);
        for negotiated in ["rsa-sha2-512", "rsa-sha2-256"] {
            assert_eq!(
                attest_presented(&approved_rsa, &rsa, negotiated),
                Ok(HostKeyType::Rsa),
                "{negotiated} is a signature algorithm an RSA host key may use"
            );
        }
    }

    /// The perimeter renders exactly what OpenSSH renders, so the two sides
    /// compare as strings without any conversion in between.
    #[test]
    fn a_rendered_fingerprint_has_the_shape_the_perimeter_carries() {
        for line in [REAL_ED25519, REAL_RSA] {
            let rendered = fingerprint(line);
            assert_eq!(rendered.len(), HOST_KEY_FINGERPRINT_BYTES);
            assert!(rendered.starts_with("SHA256:"));
            assert!(rendered[7..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'));
        }
    }

    /// The man-in-the-middle case, on the encoding the transport really sees.
    #[test]
    fn a_presented_key_that_is_not_the_approved_one_is_refused() {
        let approved = fingerprint(REAL_ED25519);
        assert_eq!(
            attest_presented(&approved, &public_key(OTHER_ED25519), "ssh-ed25519"),
            Err(HostKeyRefusal::KeyMismatch)
        );
        assert_eq!(
            attest_presented(&approved, &public_key(REAL_RSA), "rsa-sha2-512"),
            Err(HostKeyRefusal::KeyMismatch),
            "two real keys of the same machine are not interchangeable"
        );
    }

    /// No trust on first use, on this path either.
    #[test]
    fn an_absent_approved_fingerprint_is_a_refusal_not_a_first_use() {
        let key = public_key(REAL_ED25519);
        for approved in ["", "   ", "\n"] {
            assert_eq!(
                attest_presented(approved, &key, "ssh-ed25519"),
                Err(HostKeyRefusal::NoApprovedKey)
            );
        }
        assert_eq!(
            attest_presented("SHA256:short", &key, "ssh-ed25519"),
            Err(HostKeyRefusal::ApprovedMalformed)
        );
    }

    /// The ECDSA key the same LAB machine really serves, refused on the key
    /// type before its fingerprint is ever compared.
    #[test]
    fn a_presented_key_of_a_refused_type_never_reaches_the_comparison() {
        let ecdsa = public_key(REAL_ECDSA);
        assert_eq!(
            attest_presented(&fingerprint(REAL_ECDSA), &ecdsa, "ssh-ed25519"),
            Err(HostKeyRefusal::AlgorithmRefused),
            "a server offering only ECDSA must be refused even about itself"
        );
    }

    /// The gap this pairing closes: an approved key presented alongside a
    /// signature algorithm that key type may not use.
    #[test]
    fn an_approved_key_with_a_foreign_signature_algorithm_is_refused() {
        let key = public_key(REAL_ED25519);
        let approved = fingerprint(REAL_ED25519);
        for negotiated in ["rsa-sha2-512", "rsa-sha2-256"] {
            assert_eq!(
                attest_presented(&approved, &key, negotiated),
                Err(HostKeyRefusal::SignatureAlgorithmMismatch),
                "an Ed25519 host key signs only as ssh-ed25519"
            );
        }
        for negotiated in ["ssh-rsa", "ecdsa-sha2-nistp256", "ssh-dss", ""] {
            assert_eq!(
                attest_presented(&approved, &key, negotiated),
                Err(HostKeyRefusal::AlgorithmRefused),
                "{negotiated} is outside the positive list entirely"
            );
        }

        let rsa = public_key(REAL_RSA);
        assert_eq!(
            attest_presented(&fingerprint(REAL_RSA), &rsa, "ssh-ed25519"),
            Err(HostKeyRefusal::SignatureAlgorithmMismatch)
        );
    }

    #[test]
    fn an_oversized_line_is_refused_before_parsing() {
        let oversized = format!("ssh-ed25519 {}", "A".repeat(MAX_HOST_KEY_BYTES));
        assert_eq!(
            attest(REAL_ED25519, &oversized),
            Err(HostKeyRefusal::TooLong)
        );
        assert_eq!(
            attest(&oversized, REAL_ED25519),
            Err(HostKeyRefusal::TooLong)
        );
    }
}
