//! The personal key as a signer, spending the same budget as the agent.
//!
//! When the agent is not retained, the private key is in this process rather
//! than behind a socket. That changes who holds the secret; it changes nothing
//! about how many signatures one personal access may produce, for which
//! identity, or with which hash. So this signer is deliberately *not* a second
//! authentication path: it implements the very trait
//! [`super::agent_client::BudgetedAgentSigner`] implements, spends the very
//! [`SignatureBudget`] that one spends, and is handed to the very transport call
//! the agent path uses. The session module cannot tell the two apart, which is
//! the point — every bound proved on the agent path is the bound this one runs.
//!
//! The one thing that differs is where the signature comes from: an agent is
//! asked, a key is used. Both go through [`SignatureBudget::authorise`] first,
//! and a refusal there never reaches the key.

use russh::keys::{agent::AgentIdentity, HashAlg, PublicKey};

use super::{
    agent_client::{offered_identity, SigningRefusal},
    key_unlock::PersonalKey,
    signature_budget::SignatureBudget,
};

/// The only way this process can obtain a signature from the opened key.
pub struct BudgetedKeySigner {
    key: PersonalKey,
    budget: SignatureBudget,
    public_key: PublicKey,
}

impl BudgetedKeySigner {
    /// Binds a budget to the key that was opened.
    ///
    /// The budget is bound to the key's own fingerprint, exactly as the agent
    /// path binds it to the fingerprint the user selected in the window: what
    /// is signed and what was approved cannot drift apart.
    pub fn over(key: PersonalKey) -> Self {
        let budget = SignatureBudget::for_selected_identity(key.fingerprint());
        let public_key = key.public_key().clone();
        Self {
            key,
            budget,
            public_key,
        }
    }

    /// The public key the transport must authenticate with.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn fingerprint(&self) -> &str {
        self.key.fingerprint()
    }

    pub fn remaining_signatures(&self) -> usize {
        self.budget.remaining()
    }
}

impl russh::Signer for BudgetedKeySigner {
    type Error = SigningRefusal;

    fn auth_sign(
        &mut self,
        key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        async move {
            // The identity the transport hands back is judged, never trusted,
            // and judged by the same rule the agent path uses: a substituted
            // key, a certificate, a second signature or an RSA request without
            // a SHA-2 hash is refused here and never reaches the key.
            let offered = offered_identity(key);
            self.budget
                .authorise(&offered, hash_alg)
                .map_err(SigningRefusal::Budget)?;
            sign_with_personal_key(&self.key, hash_alg, to_sign)
        }
    }
}

/// Signs the authentication request the transport handed over.
///
/// The answer is the request itself with the signature appended as one
/// length-prefixed `(algorithm, signature)` blob. That shape is not a choice:
/// it is exactly what an agent returns over the wire, and returning it means
/// the transport appends the same bytes on both paths rather than treating a
/// locally held key as a special case.
///
/// Only the two key types this palier accepts can sign, and each only with the
/// hash its own algorithm names — the pairing the budget has just authorised.
/// Anything else fails closed rather than falling back to a weaker signature.
fn sign_with_personal_key(
    key: &PersonalKey,
    hash_alg: Option<HashAlg>,
    mut to_sign: Vec<u8>,
) -> Result<Vec<u8>, SigningRefusal> {
    use russh::keys::ssh_key::{encoding::Encode, private::KeypairData};
    use signature::Signer as _;

    let signature = match (key.private().key_data(), hash_alg) {
        // Ed25519 names no hash; naming one is not the algorithm approved.
        (KeypairData::Ed25519(keypair), None) => keypair.try_sign(&to_sign),
        // An RSA key signs only as `rsa-sha2-512` or `rsa-sha2-256`. `None`
        // would be the SHA-1 `ssh-rsa` signature, which never gets here.
        (KeypairData::Rsa(keypair), Some(hash)) => (keypair, Some(hash)).try_sign(&to_sign),
        _ => return Err(SigningRefusal::LocalSignature),
    }
    .map_err(|_| SigningRefusal::LocalSignature)?;

    signature
        .encode_prefixed(&mut to_sign)
        .map_err(|_| SigningRefusal::LocalSignature)?;
    Ok(to_sign)
}
