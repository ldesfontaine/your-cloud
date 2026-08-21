//! Deriving the key from the passphrase, under the same deadline as the rest.
//!
//! The derivation is the one step of a personal access whose cost is chosen by
//! the file being opened rather than by this process. `bcrypt-pbkdf` is
//! deliberately slow, its round count comes from the envelope, and it cannot be
//! interrupted once it has started. Three decisions follow from that, and they
//! are the whole module.
//!
//! First, the round count was already bounded before the passphrase was even
//! asked for: [`super::openssh_key`] refuses anything above
//! [`super::openssh_key::MAX_BCRYPT_ROUNDS`], so what runs here is bounded by
//! construction and terminates.
//!
//! Second, the derivation runs on a thread of its own and the session waits for
//! it under the session's own deadline. Whichever ends first wins: a lease that
//! runs out during the derivation is an expiration, reported immediately,
//! rather than a session that silently overruns its bail. The thread is not
//! killed — nothing can safely kill a thread mid-derivation — it is *abandoned*,
//! and abandoning it is safe precisely because it owns everything it was given.
//!
//! Third, and for that reason, both the file and the passphrase are **moved**
//! into the derivation rather than borrowed. Whether the key is used, refused or
//! abandoned, exactly one owner exists and its drop wipes the passphrase's
//! protected allocation and the bytes read from the file. There is no path on
//! which a caller keeps a copy: a wrong passphrase leaves nothing behind to
//! retry with, which is what "no implicit retry and no state kept" means here.

use std::{
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use russh::keys::{Algorithm, HashAlg, PrivateKey, PublicKey};

use super::{
    algorithms::IdentityKeyType,
    key_file::{KeyFileRefusal, SelectedKeyFile},
    openssh_key::MIN_RSA_MODULUS_BITS,
};
use crate::secret::ProtectedSecret;

/// Longest the derivation thread may be waited for when the session lease is
/// longer than the bounded cost of the derivation itself.
///
/// It is not a second security bound — the lease is — but a ceiling on a step,
/// exactly like the agent's connect and list ceilings: the accepted round count
/// costs about nine seconds on the reference App host, and a derivation
/// still running well past that is a machine, or a file, this process has no
/// reason to keep waiting for.
const DERIVATION_CEILING: Duration = Duration::from_secs(30);

/// Name carried by the thread that pays for the rounds.
///
/// It is a named constant because it is observable: a process stopped inside
/// its derivation shows this thread in `/proc`, and that is how a contract
/// suite tells "the derivation had really started" from "something was killed
/// before it began". Naming it here keeps the observation and the thread it
/// observes from drifting apart.
pub(crate) const DERIVATION_THREAD_NAME: &str = "personal-key-derivation";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockRefusal {
    /// The file is no longer the one that was validated.
    File(KeyFileRefusal),
    /// The passphrase did not open the key. It is one refusal, deliberately:
    /// nothing here distinguishes a wrong passphrase from a corrupt payload,
    /// because both mean the same thing to a caller that may not retry.
    Passphrase,
    /// What the envelope declared and what the derivation produced disagree.
    KeyMismatch,
    /// The session deadline elapsed during the derivation.
    Expired,
    /// The derivation could not be started, or ended without answering.
    Unavailable,
}

/// The personal key, decrypted, in this process's memory and nowhere else.
///
/// It carries its own fingerprint because that is what the signature budget is
/// bound to, exactly as the agent path binds it to the fingerprint the user
/// picked in the window.
///
/// The key sits behind a box, and that is a measured decision rather than a
/// stylistic one. A move in Rust is a byte copy that leaves the source frame
/// untouched: nothing drops it, so nothing wipes it. An unboxed [`PrivateKey`]
/// travels by value from the derivation to the channel, out of the channel, up
/// through this module's caller, into the credential the consent carries and
/// finally into the signer — and a privileged core taken afterwards showed one
/// stale sixty-four byte `public || private` pair per move, eighteen of them,
/// long after the single live copy had been wiped by its own drop. Behind a
/// box, every one of those moves copies a pointer, the secret itself never
/// changes address, and the drop that wipes it wipes the only copy there was.
pub struct PersonalKey {
    key: Box<PrivateKey>,
    fingerprint: String,
}

/// A decrypted key never renders itself, not even in a panic message.
impl std::fmt::Debug for PersonalKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PersonalKey([REDACTED])")
    }
}

impl PersonalKey {
    /// SHA-256 fingerprint of the public key, as OpenSSH renders it.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn public_key(&self) -> &PublicKey {
        self.key.public_key()
    }

    pub fn algorithm(&self) -> Algorithm {
        self.key.algorithm()
    }

    pub(crate) fn private(&self) -> &PrivateKey {
        &self.key
    }
}

/// Opens the validated file with the passphrase, under the session deadline.
///
/// It is crate-visible because a [`ProtectedSecret`] is: nothing outside this
/// crate can build one, and the only thing that should is the native window
/// that captured it.
///
/// Both arguments are consumed. On every outcome — success, refusal, expiry —
/// the passphrase and the bytes read are owned by exactly one place and wiped
/// when it lets go of them.
pub(crate) fn unlock(
    selected: SelectedKeyFile,
    passphrase: ProtectedSecret,
    deadline: Instant,
) -> Result<PersonalKey, UnlockRefusal> {
    // The file must still be the file that was validated. This is the check the
    // whole module exists around, and it happens before a single round is paid
    // for: deriving first and noticing afterwards would spend the lease on a
    // file the user is no longer looking at.
    selected.confirm().map_err(UnlockRefusal::File)?;

    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .min(DERIVATION_CEILING);
    // An exhausted lease never starts a derivation at all. Both values are
    // dropped here, and wiped by that drop.
    if remaining.is_zero() {
        return Err(UnlockRefusal::Expired);
    }

    let (sender, receiver) = mpsc::sync_channel::<Result<PersonalKey, UnlockRefusal>>(1);
    // The thread owns the file and the passphrase from here on. A send that
    // finds nobody listening drops the derived key on the spot.
    let started = thread::Builder::new()
        .name(DERIVATION_THREAD_NAME.into())
        .spawn(move || {
            let outcome = derive(&selected, &passphrase);
            let _ = sender.send(outcome);
        });
    if started.is_err() {
        return Err(UnlockRefusal::Unavailable);
    }

    match receiver.recv_timeout(remaining) {
        Ok(outcome) => outcome,
        Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() >= deadline => {
            Err(UnlockRefusal::Expired)
        }
        Err(mpsc::RecvTimeoutError::Timeout) => Err(UnlockRefusal::Unavailable),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(UnlockRefusal::Unavailable),
    }
}

/// Hands the derivation a passphrase the contract suite holds as plain bytes.
///
/// The suite reads a synthetic passphrase from the perimeter's own file, and
/// the protected allocation the product uses is created *here* rather than by
/// it: nothing outside this crate can build one, and nothing outside this crate
/// should be able to. Compiled in only under the contract feature, exactly like
/// `Prepared::into_signer`, so a release build keeps a single way in — the
/// native window of #45.
#[cfg(feature = "personal-access-contract-test")]
pub fn unlock_with_passphrase(
    selected: SelectedKeyFile,
    passphrase: &[u8],
    deadline: Instant,
) -> Result<PersonalKey, UnlockRefusal> {
    let Ok(mut protected) = ProtectedSecret::new() else {
        return Err(UnlockRefusal::Unavailable);
    };
    if protected.copy_from(passphrase).is_err() {
        return Err(UnlockRefusal::Unavailable);
    }
    unlock(selected, protected, deadline)
}

/// The derivation itself, on the thread that owns its inputs.
fn derive(
    selected: &SelectedKeyFile,
    passphrase: &ProtectedSecret,
) -> Result<PersonalKey, UnlockRefusal> {
    let encrypted =
        PrivateKey::from_openssh(selected.bytes()).map_err(|_| UnlockRefusal::Passphrase)?;
    // The envelope was validated as encrypted before any of this; a payload
    // that turns out not to be is a disagreement, not a shortcut.
    if !encrypted.is_encrypted() {
        return Err(UnlockRefusal::KeyMismatch);
    }
    // Boxed on the very line that produces it, before anything reads it. Every
    // step below then borrows the one heap copy instead of moving the secret
    // once more, and the checks that follow — which are the reason this
    // function is not three lines long — cost no copy at all.
    let opened: Box<PrivateKey> = Box::new(
        encrypted
            .decrypt(passphrase.bytes())
            .map_err(|_| UnlockRefusal::Passphrase)?,
    );
    if opened.is_encrypted() {
        return Err(UnlockRefusal::KeyMismatch);
    }

    // What the envelope announced before the derivation and what the derivation
    // produced must be the same key. They are read from two different places —
    // the declared public blob and the decrypted payload — so a file that lies
    // about its own type or size to get past the pre-derivation bounds is
    // refused here rather than used.
    let envelope = selected.envelope();
    match (envelope.key_type, opened.algorithm()) {
        (IdentityKeyType::Ed25519, Algorithm::Ed25519) => {}
        (IdentityKeyType::Rsa, Algorithm::Rsa { .. }) => {
            let bits = rsa_modulus_bits(&opened).ok_or(UnlockRefusal::KeyMismatch)?;
            let declared = envelope
                .rsa_modulus_bits
                .ok_or(UnlockRefusal::KeyMismatch)?;
            if bits < MIN_RSA_MODULUS_BITS || declared < MIN_RSA_MODULUS_BITS {
                return Err(UnlockRefusal::KeyMismatch);
            }
        }
        _ => return Err(UnlockRefusal::KeyMismatch),
    }

    let fingerprint = opened.public_key().fingerprint(HashAlg::Sha256).to_string();
    Ok(PersonalKey {
        key: opened,
        fingerprint,
    })
}

/// Bit length of the modulus the decrypted key really carries.
///
/// It is read from the decrypted key rather than from the envelope: the
/// envelope's declaration is what got the file past the pre-derivation bound,
/// and a declaration is not an observation.
fn rsa_modulus_bits(key: &PrivateKey) -> Option<u32> {
    use russh::keys::ssh_key::public::KeyData;

    match key.public_key().key_data() {
        KeyData::Rsa(public) => Some(public.key_size()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The step ceiling is a ceiling on the derivation, never a renewal of the
    /// session lease: whichever is shorter is the one that is waited for.
    #[test]
    fn the_derivation_is_bounded_by_the_shorter_of_the_two() {
        assert_eq!(DERIVATION_CEILING, Duration::from_secs(30));
        let past = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            past.saturating_duration_since(Instant::now())
                .min(DERIVATION_CEILING),
            Duration::ZERO,
            "an exhausted lease leaves no derivation time at all"
        );
        let generous = Instant::now() + Duration::from_secs(300);
        assert_eq!(
            generous
                .saturating_duration_since(Instant::now())
                .min(DERIVATION_CEILING),
            DERIVATION_CEILING,
            "a generous lease is still capped by the step's own ceiling"
        );
    }

    /// Every refusal of this module is a refusal, never a partial success that
    /// a caller could mistake for one: none of them carries a key.
    #[test]
    fn no_refusal_of_the_derivation_can_carry_a_key() {
        for refusal in [
            UnlockRefusal::File(KeyFileRefusal::Substituted),
            UnlockRefusal::Passphrase,
            UnlockRefusal::KeyMismatch,
            UnlockRefusal::Expired,
            UnlockRefusal::Unavailable,
        ] {
            let outcome: Result<PersonalKey, UnlockRefusal> = Err(refusal);
            assert!(outcome.is_err());
        }
    }
}
