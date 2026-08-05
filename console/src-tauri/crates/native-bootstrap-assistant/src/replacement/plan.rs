//! The ordered replacement, its witnesses, and the one gate a secured outcome
//! may ever be announced through.
//!
//! This module decides nothing another module already decided. That the user
//! asked, on a failure that is not ambiguous, is [`QualifiedIncident`]'s
//! statement; that the new Controller is new and the infrastructure is the same
//! is [`Succession`]'s; that one Console is bound to it freshly is
//! [`Association`]'s; that root was really reached is [`Elevation`]'s; that
//! every endpoint answered the new Controller is [`PreflightCleared`]'s.
//! [`authorize`] asks for all five by type and re-derives none of them.
//!
//! **Three orderings in [`STEPS`] are security properties**, and all three are
//! asserted on the shape of the constant rather than on a check somebody
//! remembered to write:
//!
//! * the reader is closed **before** the new Controller exists and reopened
//!   **after**, so no instant of the switch has two Controllers able to read;
//! * the new authority is verified **immediately before** the old one is
//!   withdrawn, so the overlap is one step wide rather than "short";
//! * on the compromise journey, the isolation is **first**, before anything is
//!   audited, installed or rotated.
//!
//! **The two journeys are two sequences.** [`ReplacementPlan::steps`] returns a
//! different constant depending on the qualification. A run cannot drift from a
//! hardware loss into a compromise, or the reverse, without the step it does or
//! does not have making it visible — which is what "perte matérielle et
//! suspicion de compromission distinguées par le parcours lui-même" means when
//! it is a property of the product instead of a sentence in a report.
//!
//! **A secured outcome has exactly one door.** [`conclude`] is the only function
//! that returns [`Secured`], and it demands every target in `nouveau seul`, the
//! reader rotated onto the new Controller alone, the sweep clean, and — on the
//! compromise journey — the isolation still holding. Everything else comes back
//! as a refusal naming what is missing. That is the whole of "aucun faux succès
//! sécurisé": the type does not exist unless all of it is true.

use crate::installation::association::Association;
use crate::installation::preflight::PreflightCleared;
use crate::personal_access::elevation::Elevation;
use crate::replacement::incident::{Qualification, QualifiedIncident};
use crate::replacement::inheritance::Swept;
use crate::replacement::reader::ReaderRotation;
use crate::replacement::succession::Succession;
use crate::replacement::transition::{Fleet, TargetState};

/// One step of the replacement, in the order the architecture fixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Cut the suspect host off, and verify it from somewhere that is not it.
    /// It exists on one journey only.
    IsolateSuspectHost,
    /// Read the redeclared machines and their managed markers. No network scan:
    /// the estate is what the user redeclares, not what answers a sweep.
    AuditRedeclaredMachines,
    /// Close the Relay reader. Nothing after it may find it open until it is
    /// reprovisioned.
    CloseRelayReader,
    /// Install the new Controller, with its new identifier.
    InstallNewController,
    /// Bind one Console to it, freshly, for this infrastructure only, importing
    /// no device, certificate or session.
    AssociateConsole,
    /// Reprovision the reader's client identity, its source address and its
    /// manifest, and reopen it — to the new Controller alone.
    ReprovisionRelayReader,
    /// A new approval epoch on every machine. The old one becomes definitively
    /// refusable, by the machine's own anchor and by its anti-replay state.
    RotateApprovalEpoch,
    /// Install the new per-machine SSH identities, beside the old ones.
    InstallNewIdentities,
    /// The new Controller walks each new path itself and reads the Auxiliary's
    /// diagnostic back. Nothing is removed before this answers.
    VerifyNewAuthority,
    /// Remove the old identities and anchors — and only those the run installed
    /// and recognises.
    WithdrawOldAuthority,
    /// Try, from the old Controller's own position, everything it could still
    /// use.
    SweepResidualAuthority,
    /// Archive the old association in the Console, revoking its device and its
    /// sessions if it is still reachable, and leave every personal account, key
    /// and access untouched.
    ArchiveOldAssociation,
}

impl Step {
    /// The name the ledger and the LAB report carry for this step.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IsolateSuspectHost => "isolate",
            Self::AuditRedeclaredMachines => "audit",
            Self::CloseRelayReader => "close-reader",
            Self::InstallNewController => "install",
            Self::AssociateConsole => "associate",
            Self::ReprovisionRelayReader => "reopen-reader",
            Self::RotateApprovalEpoch => "epoch",
            Self::InstallNewIdentities => "identities",
            Self::VerifyNewAuthority => "verify",
            Self::WithdrawOldAuthority => "withdraw",
            Self::SweepResidualAuthority => "sweep",
            Self::ArchiveOldAssociation => "archive",
        }
    }
}

/// The sequence a hardware loss follows. There is no host left to isolate, so
/// there is no step for it — its absence is the journey saying what it is.
pub const STEPS: [Step; 11] = [
    Step::AuditRedeclaredMachines,
    Step::CloseRelayReader,
    Step::InstallNewController,
    Step::AssociateConsole,
    Step::ReprovisionRelayReader,
    Step::RotateApprovalEpoch,
    Step::InstallNewIdentities,
    Step::VerifyNewAuthority,
    Step::WithdrawOldAuthority,
    Step::SweepResidualAuthority,
    Step::ArchiveOldAssociation,
];

/// The sequence a suspected compromise follows: the same one, with the
/// isolation first. It is a separate constant rather than an insertion, so that
/// "the isolation precedes everything" is read off the value instead of
/// computed.
pub const ISOLATED_STEPS: [Step; 12] = [
    Step::IsolateSuspectHost,
    Step::AuditRedeclaredMachines,
    Step::CloseRelayReader,
    Step::InstallNewController,
    Step::AssociateConsole,
    Step::ReprovisionRelayReader,
    Step::RotateApprovalEpoch,
    Step::InstallNewIdentities,
    Step::VerifyNewAuthority,
    Step::WithdrawOldAuthority,
    Step::SweepResidualAuthority,
    Step::ArchiveOldAssociation,
];

/// Why a replacement was not authorised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanRefusal {
    /// The association was taken with a Controller that is not the successor.
    AssociationForAnotherController { controller_id: String },
    /// The association names another infrastructure than the one the
    /// independent states agreed on.
    AssociationForAnotherInfrastructure { infrastructure_id: String },
    /// The preflight cleared a set that does not contain the host the new
    /// Controller is going to live on.
    NewHostNotCleared { endpoint: String },
    /// The preflight cleared the suspect host. On the compromise journey that
    /// is a host that is supposed to be cut off, and something reached it.
    SuspectHostWasReached { endpoint: String },
}

/// One authorised replacement of one Controller by one other.
///
/// It cannot be built by naming its fields and [`authorize`] is the only
/// function that returns one. Holding it is what a caller must be able to show
/// before it runs a single privileged command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplacementPlan {
    qualification: Qualification,
    old_controller_id: String,
    controller_id: String,
    infrastructure_id: String,
    new_host: String,
}

impl ReplacementPlan {
    pub fn qualification(&self) -> Qualification {
        self.qualification
    }

    pub fn old_controller_id(&self) -> &str {
        &self.old_controller_id
    }

    pub fn controller_id(&self) -> &str {
        &self.controller_id
    }

    pub fn infrastructure_id(&self) -> &str {
        &self.infrastructure_id
    }

    pub fn new_host(&self) -> &str {
        &self.new_host
    }

    /// The sequence this journey runs. The two qualifications return two
    /// different constants, and that is how they are told apart.
    pub fn steps(&self) -> &'static [Step] {
        match self.qualification {
            Qualification::HardwareLoss => &STEPS,
            Qualification::SuspectedCompromise => &ISOLATED_STEPS,
        }
    }
}

/// The one gate. Nothing else in this crate builds a [`ReplacementPlan`].
///
/// The `Elevation` parameter is never read: it is a proof obligation, not an
/// input. Asking for it by type is what makes "could this run without root
/// having been really reached" answerable by looking at one signature.
pub fn authorize(
    incident: &QualifiedIncident,
    succession: &Succession,
    association: &Association,
    _elevation: &Elevation,
    cleared: &PreflightCleared,
) -> Result<ReplacementPlan, PlanRefusal> {
    if association.controller_id() != succession.controller_id() {
        return Err(PlanRefusal::AssociationForAnotherController {
            controller_id: association.controller_id().to_owned(),
        });
    }
    if association.infrastructure_id() != succession.infrastructure_id() {
        return Err(PlanRefusal::AssociationForAnotherInfrastructure {
            infrastructure_id: association.infrastructure_id().to_owned(),
        });
    }
    if !cleared.covers(incident.new_host()) {
        return Err(PlanRefusal::NewHostNotCleared {
            endpoint: incident.new_host().to_owned(),
        });
    }
    if incident.qualification() == Qualification::SuspectedCompromise
        && cleared.covers(incident.suspect_host())
    {
        return Err(PlanRefusal::SuspectHostWasReached {
            endpoint: incident.suspect_host().to_owned(),
        });
    }
    Ok(ReplacementPlan {
        qualification: incident.qualification(),
        old_controller_id: incident.old_controller_id().to_owned(),
        controller_id: succession.controller_id().to_owned(),
        infrastructure_id: succession.infrastructure_id().to_owned(),
        new_host: incident.new_host().to_owned(),
    })
}

/// Whether the isolation established at qualification time still holds now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Containment {
    /// Re-verified, from somewhere that is not the suspect host.
    Held,
    /// Not re-verified, or re-verified as lost. The two are one value here
    /// because they lead to the same place: the replacement is not secured.
    Lost,
    /// The journey has no isolation to hold. It is the hardware loss, and it is
    /// a value rather than an option so that a caller must state which of the
    /// three it means.
    NotApplicable,
}

/// Why the replacement may not be announced as secured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConclusionRefusal {
    /// Some target's state could not be established. They are named.
    TargetsUnknown { machines: Vec<String> },
    /// Some target is not in `nouveau seul`. They are named, with their state.
    TargetsNotFinished { machines: Vec<String> },
    /// The reader came back for somebody who is not this plan's Controller.
    ReaderRotatedForAnotherController { controller_id: String },
    /// The suspect host is no longer known to be cut off. The architecture is
    /// explicit: while the old Controller can still act, Your Cloud does not
    /// claim to have restored the authority.
    SuspectHostNoLongerIsolated,
    /// A containment was stated for a journey that has none, or none was stated
    /// for a journey that requires one.
    ContainmentDoesNotMatchTheJourney { qualification: &'static str },
}

/// The proof that one replacement finished, entirely, and that the old
/// authority is gone.
///
/// It cannot be built by naming its fields and [`conclude`] is the only function
/// that returns one. Nothing else in this crate may be printed as a secured
/// replacement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secured {
    controller_id: String,
    targets: usize,
    reader_samples: usize,
    residues_checked: usize,
}

impl Secured {
    pub fn controller_id(&self) -> &str {
        &self.controller_id
    }

    pub fn targets(&self) -> usize {
        self.targets
    }

    /// How many times the reader was looked at while it was supposed to be
    /// closed, carried from the rotation so a report cannot inflate it.
    pub fn reader_samples(&self) -> usize {
        self.reader_samples
    }

    pub fn residues_checked(&self) -> usize {
        self.residues_checked
    }
}

/// The one gate. Nothing else in this crate builds a [`Secured`].
///
/// The refusals are ordered from "we do not know" to "we know it is not
/// finished" to "the old host may still act", because that is the order in
/// which a human needs to be told.
pub fn conclude(
    plan: &ReplacementPlan,
    fleet: &Fleet,
    rotation: &ReaderRotation,
    swept: &Swept,
    containment: Containment,
) -> Result<Secured, ConclusionRefusal> {
    match (plan.qualification(), containment) {
        (Qualification::HardwareLoss, Containment::NotApplicable) => {}
        (Qualification::SuspectedCompromise, Containment::Held) => {}
        (Qualification::SuspectedCompromise, Containment::Lost) => {
            return Err(ConclusionRefusal::SuspectHostNoLongerIsolated)
        }
        (qualification, _) => {
            return Err(ConclusionRefusal::ContainmentDoesNotMatchTheJourney {
                qualification: qualification.as_str(),
            })
        }
    }

    let unknown = fleet.machines_in(TargetState::Unknown);
    if !unknown.is_empty() {
        return Err(ConclusionRefusal::TargetsUnknown {
            machines: unknown.into_iter().map(str::to_owned).collect(),
        });
    }
    if !fleet.every_target_is_new_only() {
        let unfinished: Vec<String> = fleet
            .targets()
            .iter()
            .filter(|target| target.state != TargetState::NewOnly)
            .map(|target| format!("{}={}", target.machine, target.state.as_str()))
            .collect();
        return Err(ConclusionRefusal::TargetsNotFinished {
            machines: unfinished,
        });
    }
    if rotation.controller_id() != plan.controller_id() {
        return Err(ConclusionRefusal::ReaderRotatedForAnotherController {
            controller_id: rotation.controller_id().to_owned(),
        });
    }
    Ok(Secured {
        controller_id: plan.controller_id().to_owned(),
        targets: fleet.targets().len(),
        reader_samples: rotation.samples(),
        residues_checked: swept.checked(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installation::association::{self, AssociationOffer};
    use crate::installation::preflight::{self, EndpointAttempt, Observation};
    use crate::personal_access::elevation;
    use crate::replacement::incident::{
        self, Answer, Isolation, NewHost, Probe, Request, REQUIRED_SILENCE_SECONDS,
    };
    use crate::replacement::inheritance::{self, Grant, Kind, Residue};
    use crate::replacement::reader::{self, ReaderManifest, ReaderState, Socket, READER_PORT};
    use crate::replacement::succession::{self, IndependentState};
    use crate::replacement::transition::{Reconstructed, TargetState};

    const OLD: &str = "controller-old";
    const NEW: &str = "controller-new";
    const INFRASTRUCTURE: &str = "infrastructure-1";
    const SUSPECT: &str = "lab-console";
    const HOST: &str = "lab-machine-1";
    const KEY: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const OLD_ADDRESS: &str = "192.0.2.10";
    const NEW_ADDRESS: &str = "192.0.2.11";

    fn qualified(qualification: Qualification) -> QualifiedIncident {
        let probes = ["lab-machine-1", "lab-relay"].map(|vantage| Probe {
            vantage: vantage.into(),
            answer: Answer::Unreachable,
            continuous_seconds: REQUIRED_SILENCE_SECONDS,
        });
        incident::qualify(
            &Request {
                qualification,
                old_controller_id: OLD.into(),
                suspect_host: SUSPECT.into(),
                new_host: NewHost::Distinct {
                    endpoint: HOST.into(),
                },
                isolation: match qualification {
                    Qualification::HardwareLoss => Isolation::Unverified,
                    Qualification::SuspectedCompromise => Isolation::Verified {
                        by: "lab-switch".into(),
                    },
                },
                confirmed: true,
            },
            &probes,
        )
        .expect("the incident fixture must qualify")
    }

    fn succession(incident: &QualifiedIncident) -> Succession {
        let continuity = succession::concord(
            incident,
            &[
                IndependentState {
                    source: "lab-machine-1".into(),
                    infrastructure_id: Some(INFRASTRUCTURE.into()),
                },
                IndependentState {
                    source: "lab-relay".into(),
                    infrastructure_id: Some(INFRASTRUCTURE.into()),
                },
            ],
        )
        .expect("the continuity fixture must concur");
        succession::succeed(incident, &continuity, NEW, &[OLD.to_owned()])
            .expect("the succession fixture must succeed")
    }

    /// A real [`Association`], obtained the only way one can be obtained: #38's
    /// own one-time, window-bounded binding.
    fn association(controller_id: &str, infrastructure_id: &str) -> Association {
        association::bind(
            &AssociationOffer {
                infrastructure_id: infrastructure_id.into(),
                controller_id: controller_id.into(),
                sheet_id: "sheet-replacement".into(),
                issued_at_unix_seconds: 1_000,
                lifetime_seconds: 300,
            },
            infrastructure_id,
            &[],
            1_100,
        )
        .expect("the association fixture must bind")
    }

    fn elevation() -> Elevation {
        elevation::elevated(0, b"0\n", b"").expect("the elevation fixture must be granted")
    }

    fn cleared(names: &[&str]) -> PreflightCleared {
        let attempts: Vec<EndpointAttempt> = names
            .iter()
            .map(|name| EndpointAttempt {
                name: (*name).into(),
                confirmed_fingerprint: KEY.into(),
                observed: Observation::Presented {
                    fingerprint: KEY.into(),
                },
            })
            .collect();
        preflight::clear(&attempts).expect("the preflight fixture must clear")
    }

    fn plan(qualification: Qualification) -> ReplacementPlan {
        let incident = qualified(qualification);
        let succession = succession(&incident);
        authorize(
            &incident,
            &succession,
            &association(NEW, INFRASTRUCTURE),
            &elevation(),
            &cleared(&[HOST]),
        )
        .expect("the positive control must authorise")
    }

    fn rotation() -> ReaderRotation {
        let manifest = |controller_id: &str, address: &str| ReaderManifest {
            infrastructure_id: INFRASTRUCTURE.into(),
            authorized_controller_ids: vec![controller_id.into()],
            uri: reader::reader_uri(INFRASTRUCTURE, controller_id),
            source_address: address.into(),
            status: reader::STATUS_ACTIVE.into(),
            port: READER_PORT,
        };
        let closed = reader::read(&manifest(OLD, OLD_ADDRESS), Socket::NotListening)
            .expect("the closed sample must read");
        let after = reader::read(&manifest(NEW, NEW_ADDRESS), Socket::Listening)
            .expect("the reopened sample must read");
        reader::rotate(&[closed.clone(), closed], &after, OLD, NEW, OLD_ADDRESS)
            .expect("the rotation fixture must rotate")
    }

    fn swept() -> Swept {
        let residues: Vec<Residue> = Kind::EVERY
            .into_iter()
            .map(|kind| Residue {
                kind,
                name: format!("the old {}", kind.as_str()),
                grant: Grant::Refused,
            })
            .collect();
        inheritance::sweep(&residues).expect("the sweep fixture must sweep")
    }

    fn fleet(states: &[(&str, TargetState)]) -> Fleet {
        let targets: Vec<Reconstructed> = states
            .iter()
            .map(|(machine, state)| Reconstructed {
                machine: (*machine).into(),
                state: *state,
            })
            .collect();
        crate::replacement::transition::assemble(&targets).expect("the fleet fixture must assemble")
    }

    /// The positive control: five genuine witnesses authorise one replacement,
    /// and a finished fleet concludes it.
    #[test]
    fn five_witnesses_authorise_one_replacement_and_a_finished_fleet_secures_it() {
        let plan = plan(Qualification::HardwareLoss);
        assert_eq!(plan.controller_id(), NEW);
        assert_eq!(plan.old_controller_id(), OLD);
        assert_eq!(plan.infrastructure_id(), INFRASTRUCTURE);
        assert_eq!(plan.new_host(), HOST);
        assert_eq!(plan.steps(), STEPS);

        let secured = conclude(
            &plan,
            &fleet(&[(HOST, TargetState::NewOnly)]),
            &rotation(),
            &swept(),
            Containment::NotApplicable,
        )
        .expect("the positive control must conclude");
        assert_eq!(secured.controller_id(), NEW);
        assert_eq!(secured.targets(), 1);
        assert_eq!(secured.reader_samples(), 2);
        assert_eq!(secured.residues_checked(), Kind::EVERY.len());
    }

    /// **The three orderings that are security properties**, read off the
    /// constants rather than argued.
    #[test]
    fn the_reader_closes_around_the_switch_and_the_overlap_is_one_step_wide() {
        let position = |steps: &[Step], step: Step| {
            steps
                .iter()
                .position(|candidate| *candidate == step)
                .expect("every step is in the sequence")
        };
        for steps in [STEPS.as_slice(), ISOLATED_STEPS.as_slice()] {
            assert!(
                position(steps, Step::CloseRelayReader)
                    < position(steps, Step::InstallNewController)
            );
            assert!(
                position(steps, Step::InstallNewController)
                    < position(steps, Step::ReprovisionRelayReader)
            );
            // The overlap is exactly one step wide: the withdrawal is the very
            // next step after the verification, not merely later than it.
            assert_eq!(
                position(steps, Step::WithdrawOldAuthority),
                position(steps, Step::VerifyNewAuthority) + 1
            );
            assert!(
                position(steps, Step::WithdrawOldAuthority)
                    < position(steps, Step::SweepResidualAuthority)
            );
            assert_eq!(steps.last(), Some(&Step::ArchiveOldAssociation));
        }
        // The isolation precedes everything, and nothing else moved.
        assert_eq!(ISOLATED_STEPS[0], Step::IsolateSuspectHost);
        assert_eq!(&ISOLATED_STEPS[1..], STEPS.as_slice());
    }

    /// **The two journeys are two sequences.** The compromise carries a step the
    /// loss does not have, and it is the first one.
    #[test]
    fn the_two_journeys_run_two_different_sequences() {
        let loss = plan(Qualification::HardwareLoss);
        let compromise = plan(Qualification::SuspectedCompromise);

        assert_eq!(loss.steps(), STEPS);
        assert_eq!(compromise.steps(), ISOLATED_STEPS);
        assert!(!loss.steps().contains(&Step::IsolateSuspectHost));
        assert!(compromise.steps().contains(&Step::IsolateSuspectHost));
        assert_eq!(loss.steps().len() + 1, compromise.steps().len());
    }

    /// An association taken with another Controller, or for another
    /// infrastructure, authorises nothing here.
    #[test]
    fn an_association_for_another_controller_or_infrastructure_is_refused() {
        let incident = qualified(Qualification::HardwareLoss);
        let succession = succession(&incident);

        assert_eq!(
            authorize(
                &incident,
                &succession,
                &association("controller-third", INFRASTRUCTURE),
                &elevation(),
                &cleared(&[HOST]),
            ),
            Err(PlanRefusal::AssociationForAnotherController {
                controller_id: "controller-third".into()
            })
        );
        assert_eq!(
            authorize(
                &incident,
                &succession,
                &association(NEW, "infrastructure-2"),
                &elevation(),
                &cleared(&[HOST]),
            ),
            Err(PlanRefusal::AssociationForAnotherInfrastructure {
                infrastructure_id: "infrastructure-2".into()
            })
        );
    }

    /// The host the new Controller will live on has to have answered the
    /// preflight, and clearing other endpoints is not clearing this one.
    #[test]
    fn a_new_host_the_preflight_did_not_clear_authorises_nothing() {
        let incident = qualified(Qualification::HardwareLoss);
        assert_eq!(
            authorize(
                &incident,
                &succession(&incident),
                &association(NEW, INFRASTRUCTURE),
                &elevation(),
                &cleared(&["lab-machine-2"]),
            ),
            Err(PlanRefusal::NewHostNotCleared {
                endpoint: HOST.into()
            })
        );
    }

    /// **The isolation is checked against what the preflight actually
    /// reached.** A suspect host that answered the new Controller is a host
    /// that is not cut off, whatever the qualification claimed.
    #[test]
    fn a_suspect_host_the_preflight_reached_denies_the_compromise_journey() {
        let incident = qualified(Qualification::SuspectedCompromise);
        assert_eq!(
            authorize(
                &incident,
                &succession(&incident),
                &association(NEW, INFRASTRUCTURE),
                &elevation(),
                &cleared(&[HOST, SUSPECT]),
            ),
            Err(PlanRefusal::SuspectHostWasReached {
                endpoint: SUSPECT.into()
            })
        );
        // The very same clearance, on the hardware-loss journey, is fine: there
        // is no host that is supposed to be cut off.
        let loss = qualified(Qualification::HardwareLoss);
        assert!(authorize(
            &loss,
            &succession(&loss),
            &association(NEW, INFRASTRUCTURE),
            &elevation(),
            &cleared(&[HOST, SUSPECT]),
        )
        .is_ok());
    }

    /// **No false secured success.** An unknown target denies the conclusion
    /// and names itself, and so does one that is merely not finished — under a
    /// different name, because they are different situations.
    #[test]
    fn an_unknown_or_unfinished_target_denies_the_secured_outcome_by_name() {
        let plan = plan(Qualification::HardwareLoss);
        assert_eq!(
            conclude(
                &plan,
                &fleet(&[
                    (HOST, TargetState::NewOnly),
                    ("lab-relay", TargetState::Unknown)
                ]),
                &rotation(),
                &swept(),
                Containment::NotApplicable,
            ),
            Err(ConclusionRefusal::TargetsUnknown {
                machines: vec!["lab-relay".into()]
            })
        );
        assert_eq!(
            conclude(
                &plan,
                &fleet(&[
                    (HOST, TargetState::NewOnly),
                    ("lab-relay", TargetState::BoundedOverlap),
                ]),
                &rotation(),
                &swept(),
                Containment::NotApplicable,
            ),
            Err(ConclusionRefusal::TargetsNotFinished {
                machines: vec!["lab-relay=bounded-overlap".into()]
            })
        );
        assert_eq!(
            conclude(
                &plan,
                &fleet(&[(HOST, TargetState::OldOnly)]),
                &rotation(),
                &swept(),
                Containment::NotApplicable,
            ),
            Err(ConclusionRefusal::TargetsNotFinished {
                machines: vec![format!("{HOST}=old-only")]
            })
        );
    }

    /// **While the old host may still act, nothing is announced as restored.**
    /// It is the architecture's own sentence, as a refusal.
    #[test]
    fn a_compromise_whose_isolation_no_longer_holds_is_never_secured() {
        let plan = plan(Qualification::SuspectedCompromise);
        assert_eq!(
            conclude(
                &plan,
                &fleet(&[(HOST, TargetState::NewOnly)]),
                &rotation(),
                &swept(),
                Containment::Lost,
            ),
            Err(ConclusionRefusal::SuspectHostNoLongerIsolated)
        );
        // The positive control differs by that one value.
        assert!(conclude(
            &plan,
            &fleet(&[(HOST, TargetState::NewOnly)]),
            &rotation(),
            &swept(),
            Containment::Held,
        )
        .is_ok());
    }

    /// A containment that does not belong to the journey is refused rather than
    /// tolerated in either direction: a hardware loss does not get to claim a
    /// containment it never established, and a compromise does not get to
    /// declare the question inapplicable.
    #[test]
    fn a_containment_that_does_not_match_the_journey_is_refused() {
        assert_eq!(
            conclude(
                &plan(Qualification::HardwareLoss),
                &fleet(&[(HOST, TargetState::NewOnly)]),
                &rotation(),
                &swept(),
                Containment::Held,
            ),
            Err(ConclusionRefusal::ContainmentDoesNotMatchTheJourney {
                qualification: "hardware-loss"
            })
        );
        assert_eq!(
            conclude(
                &plan(Qualification::SuspectedCompromise),
                &fleet(&[(HOST, TargetState::NewOnly)]),
                &rotation(),
                &swept(),
                Containment::NotApplicable,
            ),
            Err(ConclusionRefusal::ContainmentDoesNotMatchTheJourney {
                qualification: "suspected-compromise"
            })
        );
    }

    /// A reader that came back for somebody else does not conclude this plan,
    /// even with every target finished.
    #[test]
    fn a_reader_rotated_for_another_controller_denies_the_conclusion() {
        let other = {
            let manifest = |controller_id: &str, address: &str| ReaderManifest {
                infrastructure_id: INFRASTRUCTURE.into(),
                authorized_controller_ids: vec![controller_id.into()],
                uri: reader::reader_uri(INFRASTRUCTURE, controller_id),
                source_address: address.into(),
                status: reader::STATUS_ACTIVE.into(),
                port: READER_PORT,
            };
            let closed: ReaderState =
                reader::read(&manifest(OLD, OLD_ADDRESS), Socket::NotListening)
                    .expect("the closed sample must read");
            let after = reader::read(
                &manifest("controller-third", NEW_ADDRESS),
                Socket::Listening,
            )
            .expect("the reopened sample must read");
            reader::rotate(&[closed], &after, OLD, "controller-third", OLD_ADDRESS)
                .expect("the foreign rotation must rotate on its own terms")
        };

        assert_eq!(
            conclude(
                &plan(Qualification::HardwareLoss),
                &fleet(&[(HOST, TargetState::NewOnly)]),
                &other,
                &swept(),
                Containment::NotApplicable,
            ),
            Err(ConclusionRefusal::ReaderRotatedForAnotherController {
                controller_id: "controller-third".into()
            })
        );
    }

    /// Every step carries a name, and the names are distinct: a ledger that
    /// mapped two steps onto one label could not say where a run stopped.
    #[test]
    fn every_step_carries_its_own_distinct_name() {
        let mut names: Vec<&str> = ISOLATED_STEPS.iter().map(|step| step.as_str()).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
    }
}
