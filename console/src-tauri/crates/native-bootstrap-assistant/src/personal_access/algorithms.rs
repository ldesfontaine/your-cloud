//! Positive algorithm lists for the personal SSH access.
//!
//! Host keys and personal identities are two separate lists on purpose. A host
//! key attests an approved target; an identity signs an authentication request.
//! Sharing one list would let a later change widen both surfaces at once.
//! Every unknown wire name fails closed: nothing is accepted by default.

/// Host key algorithms accepted when attesting an approved target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostKeyAlgorithm {
    Ed25519,
    RsaSha512,
    RsaSha256,
}

impl HostKeyAlgorithm {
    pub const ACCEPTED_WIRE_NAMES: [&'static str; 3] =
        ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"];

    pub fn from_wire_name(name: &str) -> Option<Self> {
        match name {
            "ssh-ed25519" => Some(Self::Ed25519),
            "rsa-sha2-512" => Some(Self::RsaSha512),
            "rsa-sha2-256" => Some(Self::RsaSha256),
            _ => None,
        }
    }
}

/// Signature algorithms accepted from the personal identity.
///
/// `ssh-rsa` is deliberately absent: it names an RSA signature over SHA-1. An
/// RSA *key* remains acceptable, but it may only sign as `rsa-sha2-512` or
/// `rsa-sha2-256`. Confusing the key type with the signature algorithm is the
/// exact mistake this split prevents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentitySignatureAlgorithm {
    Ed25519,
    RsaSha512,
    RsaSha256,
}

impl IdentitySignatureAlgorithm {
    pub const ACCEPTED_WIRE_NAMES: [&'static str; 3] =
        ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"];

    pub fn from_wire_name(name: &str) -> Option<Self> {
        match name {
            "ssh-ed25519" => Some(Self::Ed25519),
            "rsa-sha2-512" => Some(Self::RsaSha512),
            "rsa-sha2-256" => Some(Self::RsaSha256),
            _ => None,
        }
    }
}

/// Key types accepted for a target's host key.
///
/// This is a different namespace from [`HostKeyAlgorithm`], and confusing the
/// two is a real trap: a server's `ssh_host_rsa_key.pub` announces the *key
/// type* `ssh-rsa`, while `rsa-sha2-512` and `rsa-sha2-256` name the
/// *signature algorithms* that key may use. Validating a stored host key line
/// against the signature list would refuse every RSA host key in existence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostKeyType {
    Ed25519,
    Rsa,
}

impl HostKeyType {
    /// Wire name carried by the host key blob, as written in
    /// `/etc/ssh/ssh_host_*_key.pub`.
    pub fn from_key_type_name(name: &str) -> Option<Self> {
        match name {
            "ssh-ed25519" => Some(Self::Ed25519),
            "ssh-rsa" => Some(Self::Rsa),
            _ => None,
        }
    }

    /// Signature algorithms this host key type may use during negotiation.
    pub fn accepted_signature_algorithms(self) -> &'static [HostKeyAlgorithm] {
        match self {
            Self::Ed25519 => &[HostKeyAlgorithm::Ed25519],
            Self::Rsa => &[HostKeyAlgorithm::RsaSha512, HostKeyAlgorithm::RsaSha256],
        }
    }
}

/// Key types accepted inside a personal OpenSSH private key file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityKeyType {
    Ed25519,
    Rsa,
}

impl IdentityKeyType {
    /// Wire name carried by the public key blob of the key file. `ssh-rsa`
    /// here designates the RSA *key type*, not the SHA-1 signature algorithm.
    pub fn from_public_key_type(name: &str) -> Option<Self> {
        match name {
            "ssh-ed25519" => Some(Self::Ed25519),
            "ssh-rsa" => Some(Self::Rsa),
            _ => None,
        }
    }

    /// Signature algorithms this key type is allowed to use.
    pub fn accepted_signature_algorithms(self) -> &'static [IdentitySignatureAlgorithm] {
        match self {
            Self::Ed25519 => &[IdentitySignatureAlgorithm::Ed25519],
            Self::Rsa => &[
                IdentitySignatureAlgorithm::RsaSha512,
                IdentitySignatureAlgorithm::RsaSha256,
            ],
        }
    }
}

/// The only accepted compression. SSH compression is refused outright rather
/// than negotiated, so no transport can silently enable it.
pub const ACCEPTED_COMPRESSION: &str = "none";

pub fn compression_accepted(name: &str) -> bool {
    name == ACCEPTED_COMPRESSION
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Names that must never be accepted anywhere. `ssh-rsa` is the SHA-1
    /// signature, `ssh-dss` is DSA, the `sk-` prefixes are FIDO and the
    /// `-cert-v01` suffixes are certificates, which this palier does not use.
    const REFUSED_WIRE_NAMES: [&str; 10] = [
        "ssh-rsa",
        "ssh-dss",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "ssh-ed25519-cert-v01@openssh.com",
        "rsa-sha2-512-cert-v01@openssh.com",
        "ssh-rsa-cert-v01@openssh.com",
    ];

    #[test]
    fn host_key_and_identity_lists_stay_separate_and_closed() {
        for name in HostKeyAlgorithm::ACCEPTED_WIRE_NAMES {
            assert!(HostKeyAlgorithm::from_wire_name(name).is_some());
        }
        for name in IdentitySignatureAlgorithm::ACCEPTED_WIRE_NAMES {
            assert!(IdentitySignatureAlgorithm::from_wire_name(name).is_some());
        }
        for name in REFUSED_WIRE_NAMES {
            assert_eq!(
                HostKeyAlgorithm::from_wire_name(name),
                None,
                "host key algorithm {name} must fail closed"
            );
            assert_eq!(
                IdentitySignatureAlgorithm::from_wire_name(name),
                None,
                "identity signature algorithm {name} must fail closed"
            );
        }
    }

    #[test]
    fn an_rsa_key_never_signs_with_sha1() {
        let rsa = IdentityKeyType::from_public_key_type("ssh-rsa").expect("rsa key type");
        let accepted = rsa.accepted_signature_algorithms();
        assert_eq!(
            accepted,
            [
                IdentitySignatureAlgorithm::RsaSha512,
                IdentitySignatureAlgorithm::RsaSha256
            ]
        );
        assert_eq!(IdentitySignatureAlgorithm::from_wire_name("ssh-rsa"), None);
    }

    #[test]
    fn an_ed25519_key_signs_only_as_ed25519() {
        let key = IdentityKeyType::from_public_key_type("ssh-ed25519").expect("ed25519 key type");
        assert_eq!(
            key.accepted_signature_algorithms(),
            [IdentitySignatureAlgorithm::Ed25519]
        );
    }

    #[test]
    fn refused_key_types_never_produce_an_identity() {
        for name in [
            "ssh-dss",
            "ecdsa-sha2-nistp256",
            "sk-ssh-ed25519@openssh.com",
        ] {
            assert_eq!(IdentityKeyType::from_public_key_type(name), None);
        }
    }

    #[test]
    fn only_the_absence_of_compression_is_accepted() {
        assert!(compression_accepted("none"));
        for name in ["zlib", "zlib@openssh.com", "", "None", "none,zlib"] {
            assert!(!compression_accepted(name), "{name} must fail closed");
        }
    }
}
