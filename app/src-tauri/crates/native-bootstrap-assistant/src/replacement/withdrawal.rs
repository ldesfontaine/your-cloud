//! What may be taken away once the new authority answered — and everything
//! that may not be, whoever asks.
//!
//! This module is the counterpart of the registry of #38, and it is deliberately
//! built on the same idea: *only what we put there, and only after we can see
//! what replaced it.* The registry refuses to remove what a run did not create;
//! this refuses to remove what the infrastructure did not install. Both exist
//! because the failure mode is the same — a cleanup that damages a machine it
//! merely happened to be run against.
//!
//! **The new authority is a parameter, not a step somebody ran earlier.**
//! [`withdraw`] asks for #39's `machine_identity::plan::PathVerified` by type.
//! That witness is only produced by the Controller having actually opened a
//! session with the machine's new identity and read the Auxiliary's diagnostic
//! back. "Could an old key be removed before the new one was proved" is
//! therefore answered by reading one signature, on one machine, and not by
//! auditing an ordering.
//!
//! **Provenance is derived, never declared.** A caller does not get to say "this
//! one is ours". [`classify`] decides it, from three facts read off the machine:
//! the file the entry stands in, whether the line is one this product would ever
//! have written — judged by #39's own `entry::judge`, not by a second parser —
//! and whether the fingerprint is one this infrastructure minted. A key that
//! fails any of the three is kept, and the report says which.
//!
//! **Everything kept is named.** [`Withdrawal::kept`] is not a debugging aid: a
//! removal list that says what it removed but not what it declined to touch
//! cannot be checked by the person whose personal key is in that file.
//!
//! **An epoch goes forward only.** [`supersede`] refuses an epoch that is not
//! strictly greater than the one in place, which is the same rule
//! `internal/approval` enforces twice on the machine — once on the anchor and
//! once on the anti-replay state — so that rolling an anchor back cannot
//! resurrect a spent series.

use crate::machine_identity::entry;
use crate::machine_identity::plan::{key_file, PathVerified};
use crate::personal_access::host_key::HOST_KEY_FINGERPRINT_BYTES;

/// One `authorized_keys` entry as it stands on a machine, read as root.
///
/// The line and the fingerprint travel together because they were read
/// together: the line is what a removal names, the fingerprint is what an epoch
/// is compared against, and separating them would let a report be assembled from
/// two different observations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedKey {
    /// The absolute path of the file the entry stands in.
    pub file: String,
    /// The entry, verbatim, exactly one line.
    pub line: String,
    /// The `SHA256:…` fingerprint of that entry's public key, as the machine's
    /// own `ssh-keygen` renders it.
    pub fingerprint: String,
}

/// What one observed entry is, as far as this infrastructure is concerned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyProvenance {
    /// This infrastructure installed it: it stands in the root-owned managed
    /// key file, it is an entry #39 would have written, and its fingerprint is
    /// one the infrastructure minted. It is the only thing that is ever
    /// removed.
    Managed,
    /// It stands in the managed file and it is a well-formed bounded entry,
    /// but this infrastructure never minted that fingerprint. Somebody else put
    /// it there, or a record was lost — either way it is not ours to take.
    Unrecognised,
    /// It stands in the managed file and it is not an entry this product would
    /// ever have written. It is kept, and the refusal carries what #39 said
    /// about it so a human can see why.
    Unmanaged { refusal: String },
    /// It does not stand in the managed file at all. It is somebody's own key,
    /// in somebody's own file, and nothing here will ever name it.
    Personal,
}

impl KeyProvenance {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::Unrecognised => "unrecognised",
            Self::Unmanaged { .. } => "unmanaged",
            Self::Personal => "personal",
        }
    }
}

/// Decides what one observed entry is. It is the only place a provenance comes
/// from.
///
/// `minted` is the set of fingerprints this infrastructure ever minted, both
/// epochs included. Passing only the old epoch would classify the *new* key as
/// unrecognised and hide it from the report, which is exactly the entry a reader
/// most needs to see.
pub fn classify(observed: &ObservedKey, minted: &[String]) -> KeyProvenance {
    if observed.file != key_file() {
        return KeyProvenance::Personal;
    }
    if let Err(refusal) = entry::judge(&format!("{}\n", observed.line.trim())) {
        return KeyProvenance::Unmanaged {
            refusal: format!("{refusal:?}"),
        };
    }
    if !minted.iter().any(|known| known == &observed.fingerprint) {
        return KeyProvenance::Unrecognised;
    }
    KeyProvenance::Managed
}

/// One entry this withdrawal is allowed to take away.
///
/// It is a distinct type from [`ObservedKey`] on purpose, exactly as #38's
/// `Removal` is distinct from its `Item`: an observation is a thing that was
/// seen, a removal is a thing that may be taken back, and only [`withdraw`]
/// turns one into the other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Removal {
    pub file: String,
    pub fingerprint: String,
}

/// One entry this withdrawal declined to touch, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kept {
    pub file: String,
    pub fingerprint: String,
    pub provenance: KeyProvenance,
}

/// Why nothing was withdrawn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WithdrawalRefusal {
    /// The verification was taken on another machine. Proving the new path
    /// elsewhere proves nothing here.
    VerifiedAnotherMachine { machine: String },
    /// Nothing was read off the machine. A withdrawal computed on an empty
    /// observation is a withdrawal computed on nothing.
    NothingObserved,
    /// The identity the withdrawal is supposed to be keeping is not among the
    /// entries observed. Removing the old key would leave the machine with no
    /// managed access at all.
    NewIdentityNotPresent { fingerprint: String },
    /// The fingerprint to keep, or one that was observed, is not a fingerprint.
    MalformedFingerprint { fingerprint: String },
    /// The entry to be removed is the one being kept. It is refused by its own
    /// name rather than filtered out silently, because a caller that asked for
    /// it has confused the two epochs.
    WouldRemoveTheNewIdentity,
}

/// What a withdrawal takes, what it leaves, and on which machine.
///
/// It cannot be built by naming its fields and [`withdraw`] is the only function
/// that returns one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Withdrawal {
    machine: String,
    removals: Vec<Removal>,
    kept: Vec<Kept>,
}

impl Withdrawal {
    pub fn machine(&self) -> &str {
        &self.machine
    }

    pub fn removals(&self) -> &[Removal] {
        &self.removals
    }

    /// Every entry that was left in place, with the reason. A withdrawal that
    /// could not say this could not be checked.
    pub fn kept(&self) -> &[Kept] {
        &self.kept
    }
}

/// The one gate. Nothing else in this crate builds a [`Withdrawal`].
///
/// `keeping` is the fingerprint of the new identity — the one the
/// [`PathVerified`] was earned with. `retiring` is the set of fingerprints the
/// old epoch minted. Anything that is not in `retiring` is kept, whatever else
/// is true about it, so a fingerprint nobody recorded is never removed by
/// omission.
pub fn withdraw(
    verified: &PathVerified,
    machine: &str,
    observed: &[ObservedKey],
    keeping: &str,
    retiring: &[String],
) -> Result<Withdrawal, WithdrawalRefusal> {
    if verified.machine() != machine {
        return Err(WithdrawalRefusal::VerifiedAnotherMachine {
            machine: verified.machine().to_owned(),
        });
    }
    if !is_fingerprint(keeping) {
        return Err(WithdrawalRefusal::MalformedFingerprint {
            fingerprint: keeping.to_owned(),
        });
    }
    if retiring.iter().any(|old| old == keeping) {
        return Err(WithdrawalRefusal::WouldRemoveTheNewIdentity);
    }
    if observed.is_empty() {
        return Err(WithdrawalRefusal::NothingObserved);
    }
    for entry in observed {
        if !is_fingerprint(&entry.fingerprint) {
            return Err(WithdrawalRefusal::MalformedFingerprint {
                fingerprint: entry.fingerprint.clone(),
            });
        }
    }

    let mut minted: Vec<String> = retiring.to_vec();
    minted.push(keeping.to_owned());

    let mut kept_new = false;
    let mut removals = Vec::new();
    let mut kept = Vec::new();
    for entry in observed {
        let provenance = classify(entry, &minted);
        if entry.fingerprint == keeping && provenance == KeyProvenance::Managed {
            kept_new = true;
        }
        let removable = provenance == KeyProvenance::Managed
            && entry.fingerprint != keeping
            && retiring.iter().any(|old| old == &entry.fingerprint);
        if removable {
            removals.push(Removal {
                file: entry.file.clone(),
                fingerprint: entry.fingerprint.clone(),
            });
            continue;
        }
        kept.push(Kept {
            file: entry.file.clone(),
            fingerprint: entry.fingerprint.clone(),
            provenance,
        });
    }
    if !kept_new {
        return Err(WithdrawalRefusal::NewIdentityNotPresent {
            fingerprint: keeping.to_owned(),
        });
    }
    Ok(Withdrawal {
        machine: machine.to_owned(),
        removals,
        kept,
    })
}

/// Why one approval epoch does not supersede another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochRefusal {
    /// Epoch zero is not an epoch, on either side.
    EpochIsZero,
    /// The new epoch is not strictly greater. An equal epoch would let the old
    /// approvals keep their series; a smaller one would roll the authority
    /// back.
    NotStrictlyGreater { installed: u64, proposed: u64 },
}

/// One approval epoch superseding another on one machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochRotation {
    superseded: u64,
    epoch: u64,
}

impl EpochRotation {
    pub fn epoch(self) -> u64 {
        self.epoch
    }

    pub fn superseded(self) -> u64 {
        self.superseded
    }
}

/// The one gate. Nothing else in this crate builds an [`EpochRotation`].
///
/// It restates, on the deciding side, the rule the machine already enforces
/// twice: `internal/approval` refuses an envelope whose epoch is older than the
/// anchor's, and refuses again one older than the epoch the anti-replay state
/// was consumed under. Deciding it here as well is not redundancy for its own
/// sake — it is what lets the Assistant refuse to *install* a rotation that the
/// machine would then refuse to honour, instead of discovering it afterwards.
pub fn supersede(installed: u64, proposed: u64) -> Result<EpochRotation, EpochRefusal> {
    if installed == 0 || proposed == 0 {
        return Err(EpochRefusal::EpochIsZero);
    }
    if proposed <= installed {
        return Err(EpochRefusal::NotStrictlyGreater {
            installed,
            proposed,
        });
    }
    Ok(EpochRotation {
        superseded: installed,
        epoch: proposed,
    })
}

fn is_fingerprint(value: &str) -> bool {
    value.len() == HOST_KEY_FINGERPRINT_BYTES && value.starts_with("SHA256:")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installation::preflight::{self, EndpointAttempt, Observation};
    use crate::machine_identity::entry::KEY_ALGORITHM;
    use crate::machine_identity::identity::{self, Declared, Enrolled};
    use crate::machine_identity::plan::{self, AuxiliaryReport, DIAGNOSTIC_OPERATION};
    use crate::personal_access::audit::Role;
    use crate::personal_access::elevation;
    use crate::personal_access::placement::{
        self, Approval, Availability, DeclaredEndpoint, Exposure,
    };

    const MACHINE: &str = "lab-machine-1";
    const OLD_KEY: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const NEW_KEY: &str = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const STRANGER: &str = "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    const HOST: &str = "SHA256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
    const BODY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIBQ4Yk1LabelledSyntheticKeyMaterial00";

    fn estate() -> Enrolled {
        identity::mint(&[Declared {
            machine: MACHINE.into(),
            fingerprint: NEW_KEY.into(),
        }])
        .expect("the estate fixture must mint")
    }

    /// A real [`PathVerified`], obtained the only way one can be obtained.
    fn verified(machine: &str) -> PathVerified {
        let attempts = [EndpointAttempt {
            name: machine.into(),
            confirmed_fingerprint: HOST.into(),
            observed: Observation::Presented {
                fingerprint: HOST.into(),
            },
        }];
        let cleared = preflight::clear(&attempts).expect("the preflight fixture must clear");
        let granted =
            elevation::elevated(0, b"0\n", b"").expect("the elevation fixture must be granted");
        let endpoint = DeclaredEndpoint {
            name: machine.into(),
            port: 22,
            exposure: Exposure::Private,
            availability: Availability::NormallyOn,
            relay_candidate: false,
        };
        let proposal = placement::propose(Role::Agent, &endpoint, &compatible(machine))
            .expect("the placement fixture must be proposable");
        let approved = placement::approve(
            &proposal,
            &Approval {
                role: Role::Agent,
                endpoint: machine.into(),
            },
        )
        .expect("the placement fixture must be approvable");
        let estate = identity::mint(&[Declared {
            machine: machine.into(),
            fingerprint: NEW_KEY.into(),
        }])
        .expect("the estate fixture must mint");
        let enrolment = plan::authorize(&cleared, &granted, &[approved], &estate, machine)
            .expect("the enrolment fixture must authorise");
        plan::verify(
            &estate,
            &enrolment,
            &AuxiliaryReport {
                machine: machine.into(),
                operation: DIAGNOSTIC_OPERATION.into(),
                changed: false,
                consumed_sequence: 1,
                identity_fingerprint: NEW_KEY.into(),
            },
        )
        .expect("the verification fixture must verify")
    }

    fn compatible(name: &str) -> crate::personal_access::audit::ObservedMachine {
        use crate::personal_access::audit::{
            Architecture, CgroupHierarchy, Distribution, InitSystem, Installation, Observed,
            ObservedMachine, SUPPORTED_DISTRIBUTION_ID, SUPPORTED_DISTRIBUTION_VERSION,
        };
        ObservedMachine {
            uid: Observed::Known(1001),
            hostname: Observed::Known(name.to_owned()),
            distribution: Observed::Known(Distribution {
                id: SUPPORTED_DISTRIBUTION_ID.into(),
                version_id: SUPPORTED_DISTRIBUTION_VERSION.into(),
            }),
            architecture: Observed::Known(Architecture::Amd64),
            init: Observed::Known(InitSystem::Systemd),
            cgroup: Observed::Known(CgroupHierarchy::V2),
            memory_kib: Observed::Known(991_164),
            processors: Observed::Known(1),
            free_disk_kib: Observed::Known(8_388_996),
            installation: Observed::Known(Installation::NotDeclared),
        }
    }

    /// One entry as #39 writes them, in the managed file.
    fn managed(fingerprint: &str) -> ObservedKey {
        ObservedKey {
            file: key_file(),
            line: entry::render(KEY_ALGORITHM, BODY)
                .expect("the entry fixture must render")
                .trim()
                .to_owned(),
            fingerprint: fingerprint.into(),
        }
    }

    /// The positive control: the old identity goes, the new one stays, and the
    /// report names both.
    #[test]
    fn the_old_identity_goes_only_once_the_new_one_answered_and_is_present() {
        let withdrawal = withdraw(
            &verified(MACHINE),
            MACHINE,
            &[managed(OLD_KEY), managed(NEW_KEY)],
            NEW_KEY,
            &[OLD_KEY.to_owned()],
        )
        .expect("the positive control must withdraw");

        assert_eq!(withdrawal.machine(), MACHINE);
        assert_eq!(
            withdrawal
                .removals()
                .iter()
                .map(|removal| removal.fingerprint.as_str())
                .collect::<Vec<_>>(),
            [OLD_KEY]
        );
        assert_eq!(withdrawal.kept().len(), 1);
        assert_eq!(withdrawal.kept()[0].fingerprint, NEW_KEY);
        assert_eq!(withdrawal.kept()[0].provenance, KeyProvenance::Managed);
        // The estate the new identity belongs to admits it, and nothing else.
        assert!(estate().admits(MACHINE, NEW_KEY).is_ok());
    }

    /// **A personal key is never removed.** It is not in the managed file, so
    /// it is never even a candidate — and the withdrawal says so rather than
    /// omitting it.
    #[test]
    fn a_personal_key_is_kept_and_named_whoever_asks() {
        let personal = ObservedKey {
            file: "/home/ycoperator/.ssh/authorized_keys".into(),
            line: format!("{KEY_ALGORITHM} {BODY} the operator's own key"),
            fingerprint: STRANGER.into(),
        };
        let withdrawal = withdraw(
            &verified(MACHINE),
            MACHINE,
            &[managed(OLD_KEY), managed(NEW_KEY), personal],
            NEW_KEY,
            // Even declared as retiring — the strongest form of the request —
            // it is not removed.
            &[OLD_KEY.to_owned(), STRANGER.to_owned()],
        )
        .expect("the withdrawal must still be computable");

        assert_eq!(
            withdrawal
                .removals()
                .iter()
                .map(|removal| removal.fingerprint.as_str())
                .collect::<Vec<_>>(),
            [OLD_KEY]
        );
        let kept = withdrawal
            .kept()
            .iter()
            .find(|kept| kept.fingerprint == STRANGER)
            .expect("the personal key must be named among the kept");
        assert_eq!(kept.provenance, KeyProvenance::Personal);
    }

    /// **A key nobody minted is never removed either**, even standing in the
    /// managed file and looking exactly like one of ours.
    #[test]
    fn a_key_this_infrastructure_never_minted_is_kept_and_named() {
        let withdrawal = withdraw(
            &verified(MACHINE),
            MACHINE,
            &[managed(OLD_KEY), managed(NEW_KEY), managed(STRANGER)],
            NEW_KEY,
            &[OLD_KEY.to_owned()],
        )
        .expect("the withdrawal must be computable");

        assert_eq!(withdrawal.removals().len(), 1);
        let kept = withdrawal
            .kept()
            .iter()
            .find(|kept| kept.fingerprint == STRANGER)
            .expect("the unrecognised key must be named among the kept");
        assert_eq!(kept.provenance, KeyProvenance::Unrecognised);
    }

    /// A line this product would never have written is kept, and #39's own
    /// refusal travels into the report rather than being restated here.
    #[test]
    fn an_entry_this_product_would_never_have_written_is_kept_with_its_reason() {
        let unmanaged = ObservedKey {
            file: key_file(),
            line: format!("{KEY_ALGORITHM} {BODY} an unrestricted entry"),
            fingerprint: OLD_KEY.into(),
        };
        let withdrawal = withdraw(
            &verified(MACHINE),
            MACHINE,
            &[unmanaged, managed(NEW_KEY)],
            NEW_KEY,
            &[OLD_KEY.to_owned()],
        )
        .expect("the withdrawal must be computable");

        assert!(withdrawal.removals().is_empty());
        let kept = &withdrawal.kept()[0];
        assert!(matches!(kept.provenance, KeyProvenance::Unmanaged { .. }));
        assert_eq!(kept.provenance.as_str(), "unmanaged");
    }

    /// **The verification is the gate, and it is per machine.** A path proved
    /// on another machine withdraws nothing here.
    #[test]
    fn a_verification_taken_on_another_machine_withdraws_nothing() {
        assert_eq!(
            withdraw(
                &verified("lab-app"),
                MACHINE,
                &[managed(OLD_KEY), managed(NEW_KEY)],
                NEW_KEY,
                &[OLD_KEY.to_owned()],
            ),
            Err(WithdrawalRefusal::VerifiedAnotherMachine {
                machine: "lab-app".into()
            })
        );
    }

    /// The new identity has to be *there*, not merely to have answered once:
    /// removing the old key off a file that does not carry the new one would
    /// leave the machine with no managed access at all.
    #[test]
    fn the_old_identity_is_not_removed_from_a_file_the_new_one_is_absent_from() {
        assert_eq!(
            withdraw(
                &verified(MACHINE),
                MACHINE,
                &[managed(OLD_KEY)],
                NEW_KEY,
                &[OLD_KEY.to_owned()],
            ),
            Err(WithdrawalRefusal::NewIdentityNotPresent {
                fingerprint: NEW_KEY.into()
            })
        );
    }

    /// Asking for the kept identity to be retired is a confusion of the two
    /// epochs, and it is refused by its own name rather than quietly ignored.
    #[test]
    fn retiring_the_identity_that_is_being_kept_is_refused_by_name() {
        assert_eq!(
            withdraw(
                &verified(MACHINE),
                MACHINE,
                &[managed(NEW_KEY)],
                NEW_KEY,
                &[NEW_KEY.to_owned()],
            ),
            Err(WithdrawalRefusal::WouldRemoveTheNewIdentity)
        );
    }

    /// A withdrawal computed on nothing is refused, and so is one computed on a
    /// value that is not a fingerprint.
    #[test]
    fn an_empty_or_malformed_observation_withdraws_nothing() {
        assert_eq!(
            withdraw(
                &verified(MACHINE),
                MACHINE,
                &[],
                NEW_KEY,
                &[OLD_KEY.to_owned()]
            ),
            Err(WithdrawalRefusal::NothingObserved)
        );
        assert_eq!(
            withdraw(
                &verified(MACHINE),
                MACHINE,
                &[managed("SHA256:short")],
                NEW_KEY,
                &[OLD_KEY.to_owned()],
            ),
            Err(WithdrawalRefusal::MalformedFingerprint {
                fingerprint: "SHA256:short".into()
            })
        );
    }

    /// The epoch goes forward, strictly, and zero is not an epoch. It is the
    /// rule the machine enforces twice, decided here before it is installed.
    #[test]
    fn an_epoch_supersedes_only_strictly_forward() {
        let rotation = supersede(1, 2).expect("the positive control must supersede");
        assert_eq!(rotation.epoch(), 2);
        assert_eq!(rotation.superseded(), 1);

        assert_eq!(
            supersede(2, 2),
            Err(EpochRefusal::NotStrictlyGreater {
                installed: 2,
                proposed: 2
            })
        );
        assert_eq!(
            supersede(2, 1),
            Err(EpochRefusal::NotStrictlyGreater {
                installed: 2,
                proposed: 1
            })
        );
        assert_eq!(supersede(0, 1), Err(EpochRefusal::EpochIsZero));
        assert_eq!(supersede(1, 0), Err(EpochRefusal::EpochIsZero));
    }

    /// The classification is taken on the file the architecture fixes, and that
    /// file is the root-owned one of #39 — never a home directory.
    #[test]
    fn the_managed_file_is_the_root_owned_one_the_architecture_fixes() {
        assert!(key_file().starts_with("/etc/your-cloud/"));
        assert!(!key_file().starts_with("/home"));
        assert_eq!(
            classify(&managed(NEW_KEY), &[NEW_KEY.to_owned()]),
            KeyProvenance::Managed
        );
        assert_eq!(
            classify(&managed(NEW_KEY), &[]),
            KeyProvenance::Unrecognised
        );
    }
}
