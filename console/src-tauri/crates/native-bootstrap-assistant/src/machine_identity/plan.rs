//! The ordered enrolment, its witnesses, and the activation of approved roles.
//!
//! Two orderings in [`STEPS`] are security properties rather than conveniences,
//! and both are asserted on the shape of the constant instead of on a check
//! somebody remembered to write:
//!
//! * the artefact is installed **before** the forced key is reachable, so no
//!   window exists in which a key opens a command that is not there yet;
//! * the new path is verified **before** any role is activated, so a machine
//!   whose Auxiliary does not answer never has a service started on it.
//!
//! **The witnesses are the ones the earlier paliers already produce.**
//! [`authorize`] asks for the preflight clearance of #38, the elevation of #54,
//! the approved placements of #36 and the minted estate of this module, by
//! type. It re-derives none of them: "is this endpoint private", "was root
//! really reached" and "did every endpoint answer the Controller" each keep
//! exactly one home.
//!
//! **The Auxiliary is not a role that gets activated.** It is a one-shot mode
//! of the same artefact, and [`activate`] refuses it by name. That refusal is
//! the shape of the claim "the Auxiliary is never a service, a listener or a
//! general shell": without it, the claim would only be the absence of a unit.
//!
//! ## What "approved" means for the Agent
//!
//! Every machine this release manages receives an Agent, so
//! `personal_access::placement` proposes one on every endpoint it can audit.
//! That is *not* the same as activating one: [`activate`] still asks for the
//! Agent to appear in this machine's own `ApprovedPlacement` list, and refuses
//! it with [`ActivationRefusal::RoleNotApproved`] otherwise. "The Agent may be
//! proposed anywhere" and "somebody approved the Agent here" are two different
//! statements, and this module only ever acts on the second.

use crate::installation::preflight::PreflightCleared;
use crate::machine_identity::identity::{Enrolled, IdentityRefusal, MintedIdentity};
use crate::personal_access::audit::Role;
use crate::personal_access::elevation::Elevation;
use crate::personal_access::placement::ApprovedPlacement;

/// Where the machine's own key file lives: outside every directory the locked
/// account can modify, and beside the approval anchor the Auxiliary reads.
pub const KEY_FILE_DIRECTORY: &str = "/etc/your-cloud/authorized-keys";

/// The root-owned anchor of #37. It is named here because the enrolment
/// installs it, and because a step that installed it somewhere else would give
/// the machine a second place to look for who may approve.
pub const APPROVAL_ANCHOR: &str = "/etc/your-cloud/approval-anchor.json";

/// The root-owned anti-replay directory of #37.
pub const REPLAY_STATE_DIRECTORY: &str = "/var/lib/your-cloud-auxiliary";

/// The unit that runs the Agent's observation on an enrolled machine. The
/// package of #38 delivers it inactive; activating it is this palier's typed
/// operation.
pub const AGENT_UNIT: &str = "your-cloud-daemon.service";

/// The unit an approved Relay runs as.
pub const RELAY_UNIT: &str = "your-cloud-relay.service";

/// The key file this machine's `sshd` reads for the technical account.
pub fn key_file() -> String {
    format!(
        "{KEY_FILE_DIRECTORY}/{}",
        crate::machine_identity::account::AUXILIARY_ACCOUNT
    )
}

/// One step of the enrolment, in the order the architecture fixes.
///
/// Each step names what it will record in the ledger of #38, so a failure at
/// step *n* has an unambiguous list of what steps 1..n created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// The artefact reaches the machine and is installed. It is first, and that
    /// is the whole of "the binary is installed before the forced key is
    /// activated".
    InstallArtifact,
    /// The locked technical account.
    CreateAccount,
    /// The root-owned approval anchor: which key may approve on this machine,
    /// under which epoch.
    InstallApprovalAnchor,
    /// The root-owned anti-replay directory, empty. A machine that consumed
    /// nothing is what makes the first sequence the first.
    InstallReplayState,
    /// The `sudo` rule bounded to the one invocation.
    InstallElevationRule,
    /// The `authorized_keys` entry. Nothing before this step makes the identity
    /// usable, and nothing after it widens what the identity may do.
    ActivateForcedKey,
    /// The Controller opens the new path itself and reads the Auxiliary's
    /// read-only diagnostic back. Nothing is started before this answers.
    VerifyNewPath,
    /// The approved roles, and only those.
    ActivateApprovedRoles,
    /// Everything that let this run use the personal SSH access. The personal
    /// access itself is not touched: it stays under the user's control.
    DestroyTemporaryState,
}

/// The fixed sequence. It is a constant rather than a builder because an
/// enrolment whose order could be chosen is an enrolment whose ordering
/// guarantees are the caller's problem.
pub const STEPS: [Step; 9] = [
    Step::InstallArtifact,
    Step::CreateAccount,
    Step::InstallApprovalAnchor,
    Step::InstallReplayState,
    Step::InstallElevationRule,
    Step::ActivateForcedKey,
    Step::VerifyNewPath,
    Step::ActivateApprovedRoles,
    Step::DestroyTemporaryState,
];

impl Step {
    /// The name the ledger and the LAB report carry for this step.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InstallArtifact => "artifact",
            Self::CreateAccount => "account",
            Self::InstallApprovalAnchor => "anchor",
            Self::InstallReplayState => "replay",
            Self::InstallElevationRule => "elevation",
            Self::ActivateForcedKey => "key",
            Self::VerifyNewPath => "verify",
            Self::ActivateApprovedRoles => "roles",
            Self::DestroyTemporaryState => "destroy",
        }
    }
}

/// Why one machine's enrolment was not authorised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnrolmentRefusal {
    /// The preflight cleared a set that does not contain this machine. Clearing
    /// other endpoints is not clearing this one.
    MachineNotCleared { machine: String },
    /// The estate holds no identity for this machine, or holds one that is not
    /// its own.
    Identity(IdentityRefusal),
    /// No role was approved for this machine, so enrolling it would install an
    /// access to run nothing.
    NoApprovedRole { machine: String },
    /// A placement approved for another machine does not approve this one.
    PlacementForAnotherMachine { endpoint: String },
    /// The same role was approved twice for this machine.
    DuplicateRole { role: &'static str },
}

/// One authorised enrolment of one machine.
///
/// It cannot be built by naming its fields and [`authorize`] is the only
/// function that returns one. Holding it is what a caller must be able to show
/// before it runs a single privileged command on that machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrolment {
    machine: String,
    fingerprint: String,
    roles: Vec<Role>,
}

impl Enrolment {
    pub fn machine(&self) -> &str {
        &self.machine
    }

    /// The fingerprint of the identity this machine — and only this machine —
    /// admits.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn roles(&self) -> &[Role] {
        &self.roles
    }

    pub fn steps(&self) -> &'static [Step] {
        &STEPS
    }
}

/// The one gate. Nothing else in this crate builds an [`Enrolment`].
///
/// The `Elevation` parameter is never read: it is a proof obligation, not an
/// input. Asking for it by type is what makes "could this run without root
/// having been really reached" answerable by looking at one signature.
pub fn authorize(
    cleared: &PreflightCleared,
    _elevation: &Elevation,
    placements: &[ApprovedPlacement],
    enrolled: &Enrolled,
    machine: &str,
) -> Result<Enrolment, EnrolmentRefusal> {
    if !cleared.covers(machine) {
        return Err(EnrolmentRefusal::MachineNotCleared {
            machine: machine.to_owned(),
        });
    }
    let identity: &MintedIdentity = enrolled
        .identity_of(machine)
        .map_err(EnrolmentRefusal::Identity)?;

    let mut roles: Vec<Role> = Vec::with_capacity(placements.len());
    for placement in placements {
        if placement.endpoint() != machine {
            return Err(EnrolmentRefusal::PlacementForAnotherMachine {
                endpoint: placement.endpoint().to_owned(),
            });
        }
        if roles.contains(&placement.role()) {
            return Err(EnrolmentRefusal::DuplicateRole {
                role: placement.role().as_str(),
            });
        }
        roles.push(placement.role());
    }
    if roles.is_empty() {
        return Err(EnrolmentRefusal::NoApprovedRole {
            machine: machine.to_owned(),
        });
    }
    Ok(Enrolment {
        machine: machine.to_owned(),
        fingerprint: identity.fingerprint().to_owned(),
        roles,
    })
}

/// What the Auxiliary answered on the new path, as the Controller read it back.
///
/// It is the report of #37 and nothing more: an operation, a machine, a spent
/// sequence and the `changed` flag that palier fixes at `false`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuxiliaryReport {
    pub machine: String,
    pub operation: String,
    pub changed: bool,
    pub consumed_sequence: u64,
    /// The fingerprint of the identity that opened the session the report came
    /// back through.
    pub identity_fingerprint: String,
}

/// The one operation of #37. It reads and reports; it changes nothing.
pub const DIAGNOSTIC_OPERATION: &str = "diagnose_protocol_read_only";

/// Why a new path was not accepted as verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationRefusal {
    /// The report came back about another machine.
    AnotherMachine { machine: String },
    /// The session was opened with an identity this machine does not admit.
    Identity(IdentityRefusal),
    /// An operation that is not the read-only diagnostic of this palier.
    NotTheDiagnosticOperation { operation: String },
    /// The Auxiliary reported a mutation. It is refused by its own name: the
    /// architecture fixes `changed` at `false` for this palier, and a `true`
    /// means the machine ran something this palier never approved.
    AuxiliaryReportedAMutation,
    /// Nothing was consumed, so the anti-replay state does not say the path was
    /// really walked.
    NothingConsumed,
}

/// The proof that the Controller reached this machine through its new identity
/// and got the read-only diagnostic back.
///
/// It carries the machine name so [`activate`] can assert it is about to start
/// a unit on the machine that answered, and no other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathVerified {
    machine: String,
}

impl PathVerified {
    pub fn machine(&self) -> &str {
        &self.machine
    }
}

/// The one gate. Nothing else in this crate builds a [`PathVerified`].
pub fn verify(
    enrolled: &Enrolled,
    enrolment: &Enrolment,
    report: &AuxiliaryReport,
) -> Result<PathVerified, VerificationRefusal> {
    if report.machine != enrolment.machine {
        return Err(VerificationRefusal::AnotherMachine {
            machine: report.machine.clone(),
        });
    }
    enrolled
        .admits(&enrolment.machine, &report.identity_fingerprint)
        .map_err(VerificationRefusal::Identity)?;
    if report.changed {
        return Err(VerificationRefusal::AuxiliaryReportedAMutation);
    }
    if report.operation != DIAGNOSTIC_OPERATION {
        return Err(VerificationRefusal::NotTheDiagnosticOperation {
            operation: report.operation.clone(),
        });
    }
    if report.consumed_sequence == 0 {
        return Err(VerificationRefusal::NothingConsumed);
    }
    Ok(PathVerified {
        machine: enrolment.machine.clone(),
    })
}

/// Why a role was not activated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivationRefusal {
    /// The clearance is for another machine.
    VerifiedAnotherMachine { machine: String },
    /// Nobody approved this role on this machine.
    RoleNotApproved { role: &'static str },
    /// The Auxiliary is a one-shot mode of the artefact, never a service. It is
    /// refused by name so the claim is a refusal something can run into.
    AuxiliaryIsNeverAService,
    /// The Controller was activated by its own installation. An enrolment of a
    /// target never starts one.
    ControllerIsNotActivatedByAnEnrolment,
}

/// One unit this palier is allowed to start on one machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Activation {
    machine: String,
    unit: &'static str,
}

impl Activation {
    pub fn machine(&self) -> &str {
        &self.machine
    }

    pub fn unit(&self) -> &'static str {
        self.unit
    }
}

/// The one gate. Nothing else in this crate builds an [`Activation`].
///
/// [`PathVerified`] is a parameter rather than a flag: the only way to call
/// this function is to hold the proof that the new path answered, which is what
/// makes "the new path is verified before each role is activated" a property of
/// the signature.
pub fn activate(
    enrolment: &Enrolment,
    verified: &PathVerified,
    role: Role,
) -> Result<Activation, ActivationRefusal> {
    if verified.machine != enrolment.machine {
        return Err(ActivationRefusal::VerifiedAnotherMachine {
            machine: verified.machine.clone(),
        });
    }
    let unit = match role {
        Role::Auxiliary => return Err(ActivationRefusal::AuxiliaryIsNeverAService),
        Role::Controller => return Err(ActivationRefusal::ControllerIsNotActivatedByAnEnrolment),
        Role::Agent => AGENT_UNIT,
        Role::Relay => RELAY_UNIT,
    };
    if !enrolment.roles.contains(&role) {
        return Err(ActivationRefusal::RoleNotApproved {
            role: role.as_str(),
        });
    }
    Ok(Activation {
        machine: enrolment.machine.clone(),
        unit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installation::plan::{CONTROLLER_UNIT, DELIVERED_UNITS};
    use crate::installation::preflight::{self, EndpointAttempt, Observation};
    use crate::machine_identity::identity::{self, Declared};
    use crate::personal_access::audit::{
        Architecture, CgroupHierarchy, Distribution, InitSystem, Installation, Observed,
        ObservedMachine, SUPPORTED_DISTRIBUTION_ID, SUPPORTED_DISTRIBUTION_VERSION,
    };
    use crate::personal_access::elevation;
    use crate::personal_access::placement::{
        self, Approval, Availability, DeclaredEndpoint, Exposure,
    };

    const KEY_A: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const KEY_B: &str = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const HOST: &str = "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

    fn estate() -> Enrolled {
        identity::mint(&[
            Declared {
                machine: "lab-machine-1".into(),
                fingerprint: KEY_A.into(),
            },
            Declared {
                machine: "lab-machine-2".into(),
                fingerprint: KEY_B.into(),
            },
        ])
        .expect("the estate fixture must mint")
    }

    fn elevation() -> elevation::Elevation {
        elevation::elevated(0, b"0\n", b"").expect("the elevation fixture must be granted")
    }

    fn cleared(names: &[&str]) -> PreflightCleared {
        let attempts: Vec<EndpointAttempt> = names
            .iter()
            .map(|name| EndpointAttempt {
                name: (*name).into(),
                confirmed_fingerprint: HOST.into(),
                observed: Observation::Presented {
                    fingerprint: HOST.into(),
                },
            })
            .collect();
        preflight::clear(&attempts).expect("the preflight fixture must clear")
    }

    fn compatible_machine() -> ObservedMachine {
        ObservedMachine {
            uid: Observed::Known(1001),
            hostname: Observed::Known("lab-machine-1".into()),
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

    /// A real [`ApprovedPlacement`], obtained the only way one can be obtained:
    /// `propose` on observed facts, then `approve`.
    fn approved(role: Role, machine: &str) -> ApprovedPlacement {
        let endpoint = DeclaredEndpoint {
            name: machine.into(),
            port: 22,
            exposure: Exposure::Private,
            availability: Availability::NormallyOn,
            relay_candidate: role == Role::Relay,
        };
        let proposal = placement::propose(role, &endpoint, &compatible_machine())
            .expect("the placement fixture must be proposable");
        placement::approve(
            &proposal,
            &Approval {
                role,
                endpoint: endpoint.name.clone(),
            },
        )
        .expect("the placement fixture must be approvable")
    }

    fn approved_relay(machine: &str) -> ApprovedPlacement {
        approved(Role::Relay, machine)
    }

    fn enrolment() -> Enrolment {
        authorize(
            &cleared(&["lab-machine-1"]),
            &elevation(),
            &[approved_relay("lab-machine-1")],
            &estate(),
            "lab-machine-1",
        )
        .expect("the positive control must authorise")
    }

    fn report() -> AuxiliaryReport {
        AuxiliaryReport {
            machine: "lab-machine-1".into(),
            operation: DIAGNOSTIC_OPERATION.into(),
            changed: false,
            consumed_sequence: 1,
            identity_fingerprint: KEY_A.into(),
        }
    }

    /// The positive control: four witnesses authorise one machine's enrolment.
    #[test]
    fn the_witnesses_authorise_one_machine_and_carry_its_own_identity() {
        let enrolment = enrolment();
        assert_eq!(enrolment.machine(), "lab-machine-1");
        assert_eq!(enrolment.fingerprint(), KEY_A);
        assert_eq!(enrolment.roles(), [Role::Relay]);
        assert_eq!(enrolment.steps(), STEPS);
    }

    /// **The ordering that is a security property.** The artefact is installed
    /// before the forced key is reachable, and the path is verified before any
    /// role is activated. Both are read off the constant.
    #[test]
    fn the_binary_precedes_the_key_and_the_verification_precedes_every_role() {
        let position = |step: Step| {
            STEPS
                .iter()
                .position(|candidate| *candidate == step)
                .expect("every step is in the sequence")
        };
        assert!(position(Step::InstallArtifact) < position(Step::ActivateForcedKey));
        assert!(position(Step::VerifyNewPath) < position(Step::ActivateApprovedRoles));
        assert!(position(Step::InstallElevationRule) < position(Step::ActivateForcedKey));
        assert_eq!(STEPS[0], Step::InstallArtifact);
        assert_eq!(STEPS.last(), Some(&Step::DestroyTemporaryState));
        assert_eq!(STEPS.len(), 9);
    }

    /// Clearing other machines is not clearing this one, and an unenrolled
    /// machine has no identity to be enrolled with.
    #[test]
    fn a_machine_the_preflight_did_not_clear_is_never_enrolled() {
        assert_eq!(
            authorize(
                &cleared(&["lab-machine-2"]),
                &elevation(),
                &[approved_relay("lab-machine-1")],
                &estate(),
                "lab-machine-1",
            ),
            Err(EnrolmentRefusal::MachineNotCleared {
                machine: "lab-machine-1".into()
            })
        );
        assert_eq!(
            authorize(
                &cleared(&["lab-machine-9"]),
                &elevation(),
                &[approved_relay("lab-machine-9")],
                &estate(),
                "lab-machine-9",
            ),
            Err(EnrolmentRefusal::Identity(
                IdentityRefusal::UnknownMachine {
                    machine: "lab-machine-9".into()
                }
            ))
        );
    }

    /// An approval for another machine does not approve this one, and a machine
    /// nobody approved a role on is not enrolled to run nothing.
    #[test]
    fn an_approval_for_another_machine_or_for_nothing_is_refused() {
        assert_eq!(
            authorize(
                &cleared(&["lab-machine-1"]),
                &elevation(),
                &[approved_relay("lab-machine-2")],
                &estate(),
                "lab-machine-1",
            ),
            Err(EnrolmentRefusal::PlacementForAnotherMachine {
                endpoint: "lab-machine-2".into()
            })
        );
        assert_eq!(
            authorize(
                &cleared(&["lab-machine-1"]),
                &elevation(),
                &[],
                &estate(),
                "lab-machine-1",
            ),
            Err(EnrolmentRefusal::NoApprovedRole {
                machine: "lab-machine-1".into()
            })
        );
    }

    /// The verification is the positive control of the new path, and it is
    /// taken on the identity that opened it.
    #[test]
    fn the_new_path_is_verified_on_the_machines_own_identity() {
        let verified =
            verify(&estate(), &enrolment(), &report()).expect("the positive control must verify");
        assert_eq!(verified.machine(), "lab-machine-1");
    }

    /// **The crown refusal, on the verification path.** A session opened with
    /// another machine's identity does not verify this machine's path, and the
    /// refusal names the machine the key belongs to.
    #[test]
    fn a_session_opened_with_another_machines_identity_verifies_nothing() {
        assert_eq!(
            verify(
                &estate(),
                &enrolment(),
                &AuxiliaryReport {
                    identity_fingerprint: KEY_B.into(),
                    ..report()
                }
            ),
            Err(VerificationRefusal::Identity(
                IdentityRefusal::ForeignIdentity {
                    machine: "lab-machine-1".into(),
                    owner: "lab-machine-2".into(),
                }
            ))
        );
    }

    /// The Auxiliary of this palier reads and reports. A report claiming a
    /// mutation, or naming another operation, is refused by its own name.
    #[test]
    fn an_auxiliary_that_claims_to_have_changed_something_is_refused() {
        assert_eq!(
            verify(
                &estate(),
                &enrolment(),
                &AuxiliaryReport {
                    changed: true,
                    ..report()
                }
            ),
            Err(VerificationRefusal::AuxiliaryReportedAMutation)
        );
        assert_eq!(
            verify(
                &estate(),
                &enrolment(),
                &AuxiliaryReport {
                    operation: "install_container".into(),
                    ..report()
                }
            ),
            Err(VerificationRefusal::NotTheDiagnosticOperation {
                operation: "install_container".into()
            })
        );
        assert_eq!(
            verify(
                &estate(),
                &enrolment(),
                &AuxiliaryReport {
                    consumed_sequence: 0,
                    ..report()
                }
            ),
            Err(VerificationRefusal::NothingConsumed)
        );
    }

    /// A report about another machine verifies nothing about this one.
    #[test]
    fn a_report_about_another_machine_verifies_nothing() {
        assert_eq!(
            verify(
                &estate(),
                &enrolment(),
                &AuxiliaryReport {
                    machine: "lab-machine-2".into(),
                    ..report()
                }
            ),
            Err(VerificationRefusal::AnotherMachine {
                machine: "lab-machine-2".into()
            })
        );
    }

    /// The approved role is activated, on the machine that answered, and the
    /// unit is one of the three the package delivers.
    #[test]
    fn only_the_approved_role_is_activated_and_only_on_that_machine() {
        let enrolment = enrolment();
        let verified = verify(&estate(), &enrolment, &report()).expect("the fixture must verify");
        let activation =
            activate(&enrolment, &verified, Role::Relay).expect("the approved role must activate");
        assert_eq!(activation.machine(), "lab-machine-1");
        assert_eq!(activation.unit(), RELAY_UNIT);
        assert!(DELIVERED_UNITS.contains(&activation.unit()));
    }

    /// A role nobody approved is refused, and the Agent is refused that way and
    /// no other: #36 will happily propose one here, and a proposal nobody
    /// answered is still not an approval.
    #[test]
    fn a_role_nobody_approved_is_refused_including_the_agent() {
        let enrolment = enrolment();
        let verified = verify(&estate(), &enrolment, &report()).expect("the fixture must verify");
        assert_eq!(
            activate(&enrolment, &verified, Role::Agent),
            Err(ActivationRefusal::RoleNotApproved {
                role: Role::Agent.as_str()
            })
        );
        // The distinction this refusal rests on: the placement is proposable,
        // and this enrolment was still never handed the witness for it.
        assert!(placement::propose(
            Role::Agent,
            &DeclaredEndpoint {
                name: "lab-machine-1".into(),
                port: 22,
                exposure: Exposure::Private,
                availability: Availability::NormallyOn,
                relay_candidate: false,
            },
            &compatible_machine(),
        )
        .is_ok());
        assert!(!enrolment.roles().contains(&Role::Agent));
    }

    /// **The Agent, explicitly approved, is activated onto its own unit.** It
    /// is the criterion #39 could only half answer while #36 refused to place
    /// an Agent at all, and the witness it rests on is built the only way one
    /// can be: `propose`, then `approve`.
    #[test]
    fn an_explicitly_approved_agent_is_activated_onto_the_daemon_unit() {
        let enrolment = authorize(
            &cleared(&["lab-machine-1"]),
            &elevation(),
            &[
                approved(Role::Agent, "lab-machine-1"),
                approved_relay("lab-machine-1"),
            ],
            &estate(),
            "lab-machine-1",
        )
        .expect("an approved Agent authorises an enrolment");
        assert_eq!(enrolment.roles(), [Role::Agent, Role::Relay]);

        let verified = verify(&estate(), &enrolment, &report()).expect("the fixture must verify");
        let activation =
            activate(&enrolment, &verified, Role::Agent).expect("the approved Agent must activate");
        assert_eq!(activation.machine(), "lab-machine-1");
        assert_eq!(activation.unit(), AGENT_UNIT);
        assert!(DELIVERED_UNITS.contains(&activation.unit()));

        // And the clearance is still per machine: the same approved Agent does
        // not activate on the machine that did not answer.
        let elsewhere = authorize(
            &cleared(&["lab-machine-2"]),
            &elevation(),
            &[approved(Role::Agent, "lab-machine-2")],
            &estate(),
            "lab-machine-2",
        )
        .expect("the second machine must authorise");
        assert_eq!(
            activate(&elsewhere, &verified, Role::Agent),
            Err(ActivationRefusal::VerifiedAnotherMachine {
                machine: "lab-machine-1".into()
            })
        );
    }

    /// The Auxiliary is never a service, and the Controller is not started by
    /// an enrolment. Both are refusals with their own names.
    #[test]
    fn the_auxiliary_is_never_a_service_and_the_controller_is_not_enrolled_into_one() {
        let enrolment = enrolment();
        let verified = verify(&estate(), &enrolment, &report()).expect("the fixture must verify");
        assert_eq!(
            activate(&enrolment, &verified, Role::Auxiliary),
            Err(ActivationRefusal::AuxiliaryIsNeverAService)
        );
        assert_eq!(
            activate(&enrolment, &verified, Role::Controller),
            Err(ActivationRefusal::ControllerIsNotActivatedByAnEnrolment)
        );
        // The Controller's unit is #38's to start, and it is not one this
        // module maps a role onto.
        assert_ne!(AGENT_UNIT, CONTROLLER_UNIT);
        assert_ne!(RELAY_UNIT, CONTROLLER_UNIT);
    }

    /// A clearance taken on another machine does not authorise starting a unit
    /// here.
    #[test]
    fn a_verification_taken_on_another_machine_activates_nothing_here() {
        let other = authorize(
            &cleared(&["lab-machine-2"]),
            &elevation(),
            &[approved_relay("lab-machine-2")],
            &estate(),
            "lab-machine-2",
        )
        .expect("the second machine must authorise");
        let verified_elsewhere = verify(
            &estate(),
            &other,
            &AuxiliaryReport {
                machine: "lab-machine-2".into(),
                identity_fingerprint: KEY_B.into(),
                ..report()
            },
        )
        .expect("the second machine must verify");

        assert_eq!(
            activate(&enrolment(), &verified_elsewhere, Role::Relay),
            Err(ActivationRefusal::VerifiedAnotherMachine {
                machine: "lab-machine-2".into()
            })
        );
    }

    /// The key file is outside every directory the account may modify, and the
    /// anchor and the anti-replay state are the ones #37 fixed.
    #[test]
    fn the_installed_paths_are_the_ones_the_architecture_fixes() {
        assert_eq!(
            key_file(),
            "/etc/your-cloud/authorized-keys/your-cloud-auxiliary"
        );
        assert!(key_file().starts_with(KEY_FILE_DIRECTORY));
        assert_eq!(APPROVAL_ANCHOR, "/etc/your-cloud/approval-anchor.json");
        assert_eq!(REPLAY_STATE_DIRECTORY, "/var/lib/your-cloud-auxiliary");
        // Nothing lives in a home directory: the account owns none.
        assert!(!key_file().starts_with("/home"));
        assert!(!key_file().contains("/.ssh/"));
    }
}
