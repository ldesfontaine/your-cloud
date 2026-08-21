//! Closed negotiation lists for the personal SSH transport.
//!
//! `russh` ships `Preferred::DEFAULT`, which is deliberately permissive: it
//! still offers ECDSA, the NIST curves and `Algorithm::Rsa { hash: None }` —
//! that last one being an RSA signature over SHA-1. Accepting that default
//! would silently widen the personal access far beyond what this palier
//! decided, so every negotiated field is rebuilt here from an explicit list
//! and a contract test forbids the default from creeping back.
//!
//! One trap deserves naming. The `kex` list also carries pseudo-algorithms
//! that enable OpenSSH strict key exchange and `ext-info`. `russh` filters
//! them by role but never adds them on its own: a hand-written list that
//! omits them silently loses strict key exchange, and with it the Terrapin
//! mitigation. They are therefore part of the accepted list, and a test keeps
//! them there.

use std::borrow::Cow;

use russh::keys::{Algorithm, HashAlg};
use russh::{cipher, compression, kex, mac, Preferred};

/// Key exchange: post-quantum hybrid first, then Curve25519. The OpenSSH
/// strict key exchange and `ext-info` markers are required, not optional.
const ACCEPTED_KEX: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
];

/// Host key and public key algorithms. `Algorithm::Rsa { hash: None }` is the
/// SHA-1 `ssh-rsa` signature and is deliberately absent: an RSA key remains
/// usable, but only through the SHA-2 identifiers.
const ACCEPTED_KEY: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    },
];

/// Ciphers: two AEAD constructions, then AES-256 in counter mode. No CBC, no
/// triple DES, no shorter key and no unencrypted transport.
const ACCEPTED_CIPHER: &[cipher::Name] = &[
    cipher::CHACHA20_POLY1305,
    cipher::AES_256_GCM,
    cipher::AES_256_CTR,
];

/// MACs: encrypt-then-MAC only. The AEAD ciphers above do not use this list;
/// it only matters when AES-256-CTR is negotiated.
const ACCEPTED_MAC: &[mac::Name] = &[mac::HMAC_SHA512_ETM, mac::HMAC_SHA256_ETM];

/// Compression is refused outright rather than negotiated.
///
/// This is stronger than a list exclusion: pinning `russh` with
/// `default-features = false` leaves the `flate2` feature off, so `ZLIB` and
/// `ZLIB_LEGACY` are not compiled into the binary at all. The same holds for
/// `TRIPLE_DES_CBC`, gated behind the `des` feature. Those names cannot even
/// be referenced here, which is why no test asserts their absence: the
/// manifest already makes them unreachable.
const ACCEPTED_COMPRESSION: &[compression::Name] = &[compression::NONE];

/// The negotiation lists used by every personal access connection.
pub fn preferred() -> Preferred {
    Preferred {
        kex: Cow::Borrowed(ACCEPTED_KEX),
        key: Cow::Borrowed(ACCEPTED_KEY),
        cipher: Cow::Borrowed(ACCEPTED_CIPHER),
        mac: Cow::Borrowed(ACCEPTED_MAC),
        compression: Cow::Borrowed(ACCEPTED_COMPRESSION),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::personal_access::algorithms::{HostKeyAlgorithm, IdentitySignatureAlgorithm};

    #[test]
    fn the_permissive_default_is_never_reused() {
        let chosen = preferred();
        let default = Preferred::DEFAULT;
        assert_ne!(chosen.kex.as_ref(), default.kex.as_ref());
        assert_ne!(chosen.key.as_ref(), default.key.as_ref());
        assert_ne!(chosen.cipher.as_ref(), default.cipher.as_ref());
        assert_ne!(chosen.mac.as_ref(), default.mac.as_ref());
    }

    /// Regression guard for a trap that costs the Terrapin mitigation: these
    /// markers must be configured, because `russh` never adds them itself.
    #[test]
    fn strict_key_exchange_and_ext_info_stay_configured() {
        let chosen = preferred();
        assert!(chosen
            .kex
            .contains(&kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT));
        assert!(chosen.kex.contains(&kex::EXTENSION_SUPPORT_AS_CLIENT));
    }

    #[test]
    fn no_server_side_extension_is_advertised_by_a_client() {
        let chosen = preferred();
        assert!(!chosen
            .kex
            .contains(&kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER));
        assert!(!chosen.kex.contains(&kex::EXTENSION_SUPPORT_AS_SERVER));
    }

    #[test]
    fn sha1_and_legacy_key_exchanges_are_absent() {
        let chosen = preferred();
        for refused in [
            kex::DH_G1_SHA1,
            kex::DH_G14_SHA1,
            kex::DH_GEX_SHA1,
            kex::ECDH_SHA2_NISTP256,
            kex::ECDH_SHA2_NISTP384,
            kex::ECDH_SHA2_NISTP521,
            kex::NONE,
        ] {
            assert!(
                !chosen.kex.contains(&refused),
                "{refused:?} must never be offered"
            );
        }
    }

    #[test]
    fn dsa_ecdsa_fido_and_sha1_rsa_are_absent_from_the_key_list() {
        let chosen = preferred();
        assert!(
            !chosen.key.contains(&Algorithm::Rsa { hash: None }),
            "an RSA algorithm without a hash is the SHA-1 ssh-rsa signature"
        );
        assert!(!chosen.key.contains(&Algorithm::Dsa));
        assert!(!chosen.key.contains(&Algorithm::SkEd25519));
        assert!(!chosen.key.contains(&Algorithm::SkEcdsaSha2NistP256));
        assert!(
            !chosen
                .key
                .iter()
                .any(|algorithm| matches!(algorithm, Algorithm::Ecdsa { .. })),
            "no NIST curve is accepted"
        );
    }

    #[test]
    fn weak_ciphers_and_macs_are_absent() {
        let chosen = preferred();
        for refused in [
            cipher::AES_128_CBC,
            cipher::AES_192_CBC,
            cipher::AES_256_CBC,
            cipher::AES_128_CTR,
            cipher::AES_192_CTR,
            cipher::NONE,
            cipher::CLEAR,
        ] {
            assert!(
                !chosen.cipher.contains(&refused),
                "{refused:?} must never be offered"
            );
        }
        for refused in [mac::HMAC_SHA1, mac::HMAC_SHA1_ETM, mac::NONE] {
            assert!(
                !chosen.mac.contains(&refused),
                "{refused:?} must never be offered"
            );
        }
    }

    /// With `flate2` off, `NONE` is the only compression that exists in the
    /// build, so this list cannot become permissive by editing alone.
    #[test]
    fn compression_is_exactly_none() {
        assert_eq!(preferred().compression.as_ref(), [compression::NONE]);
    }

    /// The pure lists decided by #51 and the transport lists must not drift:
    /// they describe the same decision on two different surfaces.
    #[test]
    fn the_transport_list_matches_the_decided_wire_names() {
        let chosen = preferred();
        let wire: Vec<String> = chosen
            .key
            .iter()
            .map(|algorithm| algorithm.to_string())
            .collect();
        let mut expected: Vec<&str> = HostKeyAlgorithm::ACCEPTED_WIRE_NAMES.to_vec();
        expected.sort_unstable();
        let mut observed: Vec<&str> = wire.iter().map(String::as_str).collect();
        observed.sort_unstable();
        assert_eq!(observed, expected);

        let mut identity: Vec<&str> = IdentitySignatureAlgorithm::ACCEPTED_WIRE_NAMES.to_vec();
        identity.sort_unstable();
        assert_eq!(
            observed, identity,
            "host key and identity lists share the same wire names at this palier"
        );
    }
}
