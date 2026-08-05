//! The four states a target may be left in, rebuilt from the machine rather
//! than replayed from what the run believed.
//!
//! A replacement is not atomic across a fleet, and the architecture says so
//! plainly: for each target the Assistant renders `ancien seul`, `chevauchement
//! borné`, `nouveau seul` or `inconnu`. A cut may therefore leave a partial
//! fleet — but never an invented success. This module is the part that has to
//! survive the laptop being closed mid-way.
//!
//! **Nothing is remembered across the cut.** [`reconstruct`] takes only what was
//! read off the machine on the *next* run: what the root-owned managed key file
//! holds, and what a direct session with each identity answered. There is no
//! journal, no resume token and no cached step number, because a run that
//! trusted its own record of where it stopped would trust a record written by a
//! process that was killed.
//!
//! **Two sources, and disagreement means unknown.** The file says what is
//! installed; the direct test says what actually works. They can differ for
//! entirely real reasons — an `sshd` that has not reloaded, a file written but
//! not yet effective, a key present and refused by a policy. When they differ,
//! the state is [`TargetState::Unknown`], never the more convenient of the two.
//! That is the single decision this module exists to take.
//!
//! **Unknown removes nothing.** [`next`] never proposes a withdrawal in
//! [`TargetState::Unknown`], and [`super::withdrawal::withdraw`] independently
//! demands the verification witness, so the property holds twice: once as a
//! proposal that is not made, once as a signature that cannot be satisfied.
//!
//! **"Neither identity works" is unknown, not "new only".** It is the reading a
//! hurried implementation gets wrong: the old key is gone, so the replacement
//! must have worked. It has not — it has produced a machine nothing can reach,
//! and calling that `nouveau seul` would report the worst outcome of the palier
//! as its success.

/// What a direct session opened with one identity answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attempt {
    /// The identity opened the forced command and it answered.
    Answered,
    /// The server refused the identity. A definite negative.
    Refused,
    /// No usable answer — the host was unreachable, or the attempt was cut.
    NoAnswer,
}

/// Everything one target was observed to hold, on the run that came after the
/// cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// The fingerprints the root-owned managed key file holds, or `None` when
    /// the file could not be read at all. `None` is not an empty file.
    pub managed_fingerprints: Option<Vec<String>>,
    /// The identity of the Controller being replaced.
    pub old_fingerprint: String,
    /// The identity of the Controller replacing it.
    pub new_fingerprint: String,
    pub old_identity: Attempt,
    pub new_identity: Attempt,
}

/// One of the four states the architecture fixes. There is no fifth, and the
/// enum carries no payload, so no call site can smuggle a nuance past a `match`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetState {
    /// Only the old authority reaches this machine. The replacement has not
    /// touched it.
    OldOnly,
    /// Both reach it. It is the window the plan opens deliberately, between
    /// verifying the new authority and withdrawing the old one, and nowhere
    /// else.
    BoundedOverlap,
    /// Only the new authority reaches it. This is the only state a target may
    /// end in.
    NewOnly,
    /// The two sources disagree, one of them could not be read, or nothing
    /// reaches the machine at all.
    Unknown,
}

impl TargetState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OldOnly => "old-only",
            Self::BoundedOverlap => "bounded-overlap",
            Self::NewOnly => "new-only",
            Self::Unknown => "unknown",
        }
    }
}

/// Rebuilds one target's state from what the machine answered.
///
/// It is total: every evidence produces one of the four, and the one it produces
/// when anything is missing or contradictory is [`TargetState::Unknown`].
pub fn reconstruct(evidence: &Evidence) -> TargetState {
    let Some(installed) = evidence.managed_fingerprints.as_ref() else {
        return TargetState::Unknown;
    };
    let old_installed = installed.iter().any(|key| key == &evidence.old_fingerprint);
    let new_installed = installed.iter().any(|key| key == &evidence.new_fingerprint);

    let old_works = match evidence.old_identity {
        Attempt::NoAnswer => return TargetState::Unknown,
        Attempt::Answered => true,
        Attempt::Refused => false,
    };
    let new_works = match evidence.new_identity {
        Attempt::NoAnswer => return TargetState::Unknown,
        Attempt::Answered => true,
        Attempt::Refused => false,
    };

    // The file and the wire have to agree. When they do not, what is true about
    // this machine is precisely the thing nobody knows.
    if old_installed != old_works || new_installed != new_works {
        return TargetState::Unknown;
    }
    match (old_works, new_works) {
        (true, false) => TargetState::OldOnly,
        (true, true) => TargetState::BoundedOverlap,
        (false, true) => TargetState::NewOnly,
        // Nothing reaches the machine. It is not a finished replacement.
        (false, false) => TargetState::Unknown,
    }
}

/// What the next run may do about one target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    /// Install and verify the new authority.
    InstallNewAuthority,
    /// Withdraw the old one. It is the only value that ever authorises a
    /// removal, and it comes from exactly one state.
    WithdrawOldAuthority,
    /// The target is finished.
    Nothing,
    /// Look again, and take nothing away. The reason travels so a report can
    /// name what is not known.
    ObserveOnly,
}

/// The step that follows one reconstructed state.
///
/// It is a total function of the state alone: there is no argument a caller
/// could pass to obtain a withdrawal from an unknown target.
pub fn next(state: TargetState) -> Next {
    match state {
        TargetState::OldOnly => Next::InstallNewAuthority,
        TargetState::BoundedOverlap => Next::WithdrawOldAuthority,
        TargetState::NewOnly => Next::Nothing,
        TargetState::Unknown => Next::ObserveOnly,
    }
}

/// One target and the state it was rebuilt into.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reconstructed {
    pub machine: String,
    pub state: TargetState,
}

/// Why a fleet could not be assembled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FleetRefusal {
    /// No target at all. A replacement of nothing is not a replacement.
    NothingDeclared,
    /// The same machine twice, so ordering rather than observation would decide
    /// which of its two states counted.
    DuplicateMachine { machine: String },
}

/// Every target of one replacement, each in exactly one state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fleet {
    targets: Vec<Reconstructed>,
}

impl Fleet {
    pub fn targets(&self) -> &[Reconstructed] {
        &self.targets
    }

    pub fn state_of(&self, machine: &str) -> Option<TargetState> {
        self.targets
            .iter()
            .find(|target| target.machine == machine)
            .map(|target| target.state)
    }

    /// Machines in a given state, by name. A report that can only count is a
    /// report nobody can act on.
    pub fn machines_in(&self, state: TargetState) -> Vec<&str> {
        self.targets
            .iter()
            .filter(|target| target.state == state)
            .map(|target| target.machine.as_str())
            .collect()
    }

    /// True only when every target is [`TargetState::NewOnly`]. It is the one
    /// condition a completed replacement may be claimed on.
    pub fn every_target_is_new_only(&self) -> bool {
        self.targets
            .iter()
            .all(|target| target.state == TargetState::NewOnly)
    }
}

/// The one gate. Nothing else in this crate builds a [`Fleet`].
pub fn assemble(targets: &[Reconstructed]) -> Result<Fleet, FleetRefusal> {
    if targets.is_empty() {
        return Err(FleetRefusal::NothingDeclared);
    }
    let mut seen: Vec<&str> = Vec::with_capacity(targets.len());
    for target in targets {
        if seen.contains(&target.machine.as_str()) {
            return Err(FleetRefusal::DuplicateMachine {
                machine: target.machine.clone(),
            });
        }
        seen.push(&target.machine);
    }
    Ok(Fleet {
        targets: targets.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const NEW: &str = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    fn evidence(installed: Option<&[&str]>, old: Attempt, new: Attempt) -> Evidence {
        Evidence {
            managed_fingerprints: installed
                .map(|keys| keys.iter().map(|key| (*key).to_owned()).collect()),
            old_fingerprint: OLD.into(),
            new_fingerprint: NEW.into(),
            old_identity: old,
            new_identity: new,
        }
    }

    /// The positive control of the four states: each one is rebuilt from a file
    /// and a wire that agree.
    #[test]
    fn the_four_states_are_rebuilt_from_a_file_and_a_wire_that_agree() {
        assert_eq!(
            reconstruct(&evidence(Some(&[OLD]), Attempt::Answered, Attempt::Refused)),
            TargetState::OldOnly
        );
        assert_eq!(
            reconstruct(&evidence(
                Some(&[OLD, NEW]),
                Attempt::Answered,
                Attempt::Answered
            )),
            TargetState::BoundedOverlap
        );
        assert_eq!(
            reconstruct(&evidence(Some(&[NEW]), Attempt::Refused, Attempt::Answered)),
            TargetState::NewOnly
        );
        assert_eq!(
            reconstruct(&evidence(Some(&[]), Attempt::Refused, Attempt::Refused)),
            TargetState::Unknown
        );
    }

    /// **The decision this module exists for.** The file and the wire
    /// disagreeing is unknown, not the more convenient of the two — in both
    /// directions.
    #[test]
    fn a_file_and_a_wire_that_disagree_produce_unknown_in_both_directions() {
        // Installed but refused: written, and not effective.
        assert_eq!(
            reconstruct(&evidence(
                Some(&[OLD, NEW]),
                Attempt::Answered,
                Attempt::Refused
            )),
            TargetState::Unknown
        );
        // Absent and working: something is admitting a key the managed file
        // does not carry.
        assert_eq!(
            reconstruct(&evidence(
                Some(&[NEW]),
                Attempt::Answered,
                Attempt::Answered
            )),
            TargetState::Unknown
        );
    }

    /// **The reading a hurried implementation gets wrong.** Nothing reaching
    /// the machine is unknown, never a finished replacement.
    #[test]
    fn a_machine_nothing_reaches_is_unknown_and_never_new_only() {
        let state = reconstruct(&evidence(Some(&[]), Attempt::Refused, Attempt::Refused));
        assert_eq!(state, TargetState::Unknown);
        assert_ne!(state, TargetState::NewOnly);
        assert_eq!(next(state), Next::ObserveOnly);
    }

    /// An unreadable file is not an empty one, and a cut attempt is not a
    /// refusal. Both produce unknown.
    #[test]
    fn an_unread_file_or_an_unanswered_attempt_produces_unknown() {
        assert_eq!(
            reconstruct(&evidence(None, Attempt::Refused, Attempt::Answered)),
            TargetState::Unknown
        );
        assert_eq!(
            reconstruct(&evidence(
                Some(&[NEW]),
                Attempt::NoAnswer,
                Attempt::Answered
            )),
            TargetState::Unknown
        );
        assert_eq!(
            reconstruct(&evidence(
                Some(&[OLD]),
                Attempt::Answered,
                Attempt::NoAnswer
            )),
            TargetState::Unknown
        );
    }

    /// **No removal in an unknown state**, and only one state ever proposes
    /// one. Both halves are read off the same total function.
    #[test]
    fn a_withdrawal_is_proposed_by_exactly_one_state_and_never_by_unknown() {
        assert_eq!(next(TargetState::Unknown), Next::ObserveOnly);
        assert_eq!(next(TargetState::OldOnly), Next::InstallNewAuthority);
        assert_eq!(next(TargetState::NewOnly), Next::Nothing);
        assert_eq!(
            next(TargetState::BoundedOverlap),
            Next::WithdrawOldAuthority
        );

        let proposing: Vec<TargetState> = [
            TargetState::OldOnly,
            TargetState::BoundedOverlap,
            TargetState::NewOnly,
            TargetState::Unknown,
        ]
        .into_iter()
        .filter(|state| next(*state) == Next::WithdrawOldAuthority)
        .collect();
        assert_eq!(proposing, [TargetState::BoundedOverlap]);
    }

    /// A fleet names its targets, and a partial one is legible machine by
    /// machine rather than as a count.
    #[test]
    fn a_partial_fleet_is_legible_machine_by_machine() {
        let fleet = assemble(&[
            Reconstructed {
                machine: "lab-machine-1".into(),
                state: TargetState::NewOnly,
            },
            Reconstructed {
                machine: "lab-console".into(),
                state: TargetState::Unknown,
            },
            Reconstructed {
                machine: "lab-relay".into(),
                state: TargetState::BoundedOverlap,
            },
        ])
        .expect("the positive control must assemble");

        assert!(!fleet.every_target_is_new_only());
        assert_eq!(fleet.machines_in(TargetState::Unknown), ["lab-console"]);
        assert_eq!(
            fleet.machines_in(TargetState::BoundedOverlap),
            ["lab-relay"]
        );
        assert_eq!(fleet.state_of("lab-machine-1"), Some(TargetState::NewOnly));
        assert_eq!(fleet.state_of("lab-machine-9"), None);

        let finished = assemble(&[Reconstructed {
            machine: "lab-machine-1".into(),
            state: TargetState::NewOnly,
        }])
        .expect("a finished fleet must assemble");
        assert!(finished.every_target_is_new_only());
    }

    /// An empty fleet is refused rather than read as finished, and the same
    /// machine twice is refused before anything is decided about it.
    #[test]
    fn an_empty_or_duplicated_fleet_is_refused() {
        assert_eq!(assemble(&[]), Err(FleetRefusal::NothingDeclared));
        assert_eq!(
            assemble(&[
                Reconstructed {
                    machine: "lab-machine-1".into(),
                    state: TargetState::NewOnly,
                },
                Reconstructed {
                    machine: "lab-machine-1".into(),
                    state: TargetState::Unknown,
                },
            ]),
            Err(FleetRefusal::DuplicateMachine {
                machine: "lab-machine-1".into()
            })
        );
    }
}
