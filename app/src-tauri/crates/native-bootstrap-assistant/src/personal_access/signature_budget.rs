//! Finite signature budget for the personal SSH agent.
//!
//! An agent never exports the private key, so the risk is not theft: it is
//! being used as a signing oracle. Anything that can talk to the agent can ask
//! it to sign arbitrary bytes with the user's identity. This palier therefore
//! spends an explicitly bounded budget — exactly one authentication signature,
//! for one identity that the user selected — and refuses everything else.
//!
//! The refusal covers three distinct mistakes. A second signature request
//! means something beyond the single approved authentication is happening. A
//! different identity means the agent, or the transport, substituted a key the
//! user never chose. And an RSA request without a SHA-2 hash is the SHA-1
//! `ssh-rsa` signature that [`super::algorithms`] already refuses; retrying a
//! failed SHA-512 signature as SHA-256 would also silently spend a second
//! signature, which is why no retry exists here.
//!
//! The decision is kept free of transport types so it can be exercised without
//! a live agent. Turning an agent identity into an [`OfferedIdentity`] belongs
//! to the connection itself.

use russh::keys::{Algorithm, HashAlg};

/// Signatures allowed for one personal access operation.
pub const MAX_AUTHENTICATION_SIGNATURES: usize = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetRefusal {
    /// The single authentication signature was already spent.
    Exhausted,
    /// The agent offered an identity other than the selected one.
    IdentityChanged,
    /// Certificates are outside this palier.
    CertificateOffered,
    /// An RSA signature must name SHA-512 or SHA-256; Ed25519 must name none.
    HashAlgorithmRefused,
}

/// What the agent proposes to sign with, reduced to what the decision needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferedIdentity {
    pub algorithm: Algorithm,
    /// Stable identifier of the public key, as rendered by the caller.
    pub fingerprint: String,
    pub is_certificate: bool,
}

/// Tracks the single authentication signature of one operation.
#[derive(Clone, Debug)]
pub struct SignatureBudget {
    selected_fingerprint: String,
    remaining: usize,
}

impl SignatureBudget {
    /// Opens a budget bound to the identity the user selected.
    pub fn for_selected_identity(fingerprint: impl Into<String>) -> Self {
        Self {
            selected_fingerprint: fingerprint.into(),
            remaining: MAX_AUTHENTICATION_SIGNATURES,
        }
    }

    pub fn remaining(&self) -> usize {
        self.remaining
    }

    /// Decides whether this exact signature may be requested, and spends the
    /// budget when it may. A refusal never spends anything: the operation
    /// fails closed rather than degrading to a weaker signature.
    pub fn authorise(
        &mut self,
        offered: &OfferedIdentity,
        hash_alg: Option<HashAlg>,
    ) -> Result<(), BudgetRefusal> {
        if offered.is_certificate {
            return Err(BudgetRefusal::CertificateOffered);
        }
        if offered.fingerprint != self.selected_fingerprint {
            return Err(BudgetRefusal::IdentityChanged);
        }
        if !hash_algorithm_matches(&offered.algorithm, hash_alg) {
            return Err(BudgetRefusal::HashAlgorithmRefused);
        }
        // Checked last so that a refused request cannot exhaust the budget and
        // turn a hostile probe into a denial of the legitimate signature.
        if self.remaining == 0 {
            return Err(BudgetRefusal::Exhausted);
        }
        self.remaining -= 1;
        Ok(())
    }
}

fn hash_algorithm_matches(algorithm: &Algorithm, hash_alg: Option<HashAlg>) -> bool {
    match algorithm {
        // Ed25519 carries no hash identifier; naming one is not the algorithm
        // the user selected.
        Algorithm::Ed25519 => hash_alg.is_none(),
        // An RSA key stays usable, but only through the SHA-2 identifiers.
        Algorithm::Rsa { .. } => matches!(hash_alg, Some(HashAlg::Sha512) | Some(HashAlg::Sha256)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SELECTED: &str = "SHA256:0ur4Vv8h1nRhKZ9lPqYq2sBvXwGx7cJd1KfE0mTnRbA";
    const OTHER: &str = "SHA256:Zz9QaWxLm4Tn2VkJhRfCg7BdY6sXeUo1PtNvHcMi3Ek";

    fn ed25519(fingerprint: &str) -> OfferedIdentity {
        OfferedIdentity {
            algorithm: Algorithm::Ed25519,
            fingerprint: fingerprint.into(),
            is_certificate: false,
        }
    }

    fn rsa(fingerprint: &str) -> OfferedIdentity {
        OfferedIdentity {
            algorithm: Algorithm::Rsa { hash: None },
            fingerprint: fingerprint.into(),
            is_certificate: false,
        }
    }

    #[test]
    fn exactly_one_ed25519_signature_is_authorised() {
        let mut budget = SignatureBudget::for_selected_identity(SELECTED);
        assert_eq!(budget.remaining(), MAX_AUTHENTICATION_SIGNATURES);
        assert_eq!(budget.authorise(&ed25519(SELECTED), None), Ok(()));
        assert_eq!(budget.remaining(), 0);
    }

    #[test]
    fn a_second_signature_is_refused() {
        let mut budget = SignatureBudget::for_selected_identity(SELECTED);
        assert_eq!(budget.authorise(&ed25519(SELECTED), None), Ok(()));
        assert_eq!(
            budget.authorise(&ed25519(SELECTED), None),
            Err(BudgetRefusal::Exhausted),
            "the agent is a signing oracle: one authentication, one signature"
        );
        assert_eq!(
            budget.authorise(&ed25519(SELECTED), None),
            Err(BudgetRefusal::Exhausted)
        );
    }

    #[test]
    fn a_substituted_identity_is_refused() {
        let mut budget = SignatureBudget::for_selected_identity(SELECTED);
        assert_eq!(
            budget.authorise(&ed25519(OTHER), None),
            Err(BudgetRefusal::IdentityChanged)
        );
        assert_eq!(
            budget.remaining(),
            MAX_AUTHENTICATION_SIGNATURES,
            "a refusal must not spend the legitimate signature"
        );
    }

    #[test]
    fn a_certificate_is_refused_before_anything_else() {
        let mut budget = SignatureBudget::for_selected_identity(SELECTED);
        let certificate = OfferedIdentity {
            is_certificate: true,
            ..ed25519(SELECTED)
        };
        assert_eq!(
            budget.authorise(&certificate, None),
            Err(BudgetRefusal::CertificateOffered)
        );
        assert_eq!(budget.remaining(), MAX_AUTHENTICATION_SIGNATURES);
    }

    #[test]
    fn an_rsa_signature_must_name_a_sha2_hash() {
        for hash in [HashAlg::Sha512, HashAlg::Sha256] {
            let mut budget = SignatureBudget::for_selected_identity(SELECTED);
            assert_eq!(budget.authorise(&rsa(SELECTED), Some(hash)), Ok(()));
        }
        let mut budget = SignatureBudget::for_selected_identity(SELECTED);
        assert_eq!(
            budget.authorise(&rsa(SELECTED), None),
            Err(BudgetRefusal::HashAlgorithmRefused),
            "an RSA signature without a hash is the SHA-1 ssh-rsa signature"
        );
    }

    #[test]
    fn an_ed25519_signature_must_not_name_a_hash() {
        for hash in [HashAlg::Sha512, HashAlg::Sha256] {
            let mut budget = SignatureBudget::for_selected_identity(SELECTED);
            assert_eq!(
                budget.authorise(&ed25519(SELECTED), Some(hash)),
                Err(BudgetRefusal::HashAlgorithmRefused)
            );
        }
    }

    /// The documented failure mode: a SHA-512 signature that the server
    /// rejects must not be retried as SHA-256, because the retry spends a
    /// second signature from the same oracle.
    #[test]
    fn a_sha512_failure_is_never_retried_as_sha256() {
        let mut budget = SignatureBudget::for_selected_identity(SELECTED);
        assert_eq!(
            budget.authorise(&rsa(SELECTED), Some(HashAlg::Sha512)),
            Ok(())
        );
        assert_eq!(
            budget.authorise(&rsa(SELECTED), Some(HashAlg::Sha256)),
            Err(BudgetRefusal::Exhausted),
            "the downgrade retry is exactly what the budget exists to stop"
        );
    }

    #[test]
    fn a_refused_probe_never_denies_the_legitimate_signature() {
        let mut budget = SignatureBudget::for_selected_identity(SELECTED);
        // Whatever a hostile caller tries first, the approved signature stays
        // available afterwards.
        assert!(budget.authorise(&ed25519(OTHER), None).is_err());
        assert!(budget.authorise(&rsa(SELECTED), None).is_err());
        assert!(budget
            .authorise(
                &OfferedIdentity {
                    is_certificate: true,
                    ..ed25519(SELECTED)
                },
                None
            )
            .is_err());
        assert_eq!(budget.authorise(&ed25519(SELECTED), None), Ok(()));
    }

    #[test]
    fn refused_key_algorithms_never_reach_the_agent() {
        let mut budget = SignatureBudget::for_selected_identity(SELECTED);
        let dsa = OfferedIdentity {
            algorithm: Algorithm::Dsa,
            ..ed25519(SELECTED)
        };
        assert_eq!(
            budget.authorise(&dsa, None),
            Err(BudgetRefusal::HashAlgorithmRefused)
        );
        let fido = OfferedIdentity {
            algorithm: Algorithm::SkEd25519,
            ..ed25519(SELECTED)
        };
        assert_eq!(
            budget.authorise(&fido, None),
            Err(BudgetRefusal::HashAlgorithmRefused)
        );
    }
}
