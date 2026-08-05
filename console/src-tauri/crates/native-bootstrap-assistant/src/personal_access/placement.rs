//! What may be proposed on an audited endpoint, and what a proposal is not.
//!
//! The module that reads a machine says only what it saw. This one turns that
//! observation into the single thing the user is asked to look at before
//! anything is ever mutated: a placement proposal, with the role, the machine,
//! what it will cohabit with, what it costs, what it can take down with it, and
//! the accounts, artefacts, flows and privileges it would eventually need.
//!
//! **A proposal is not an installation, and cannot become one here.** Nothing
//! in this crate applies a [`Proposal`]. It is a value with no method that acts,
//! it holds no handle to the session it was derived from, and the only thing
//! that can be done with it is show it and — if the user says so — turn it into
//! an [`ApprovedPlacement`], which is a witness and not an action either. The
//! palier that installs does not exist yet; when it does, the witness is what it
//! will have to be handed, exactly as the elevation witness is handed to
//! whatever publishes a verified access.
//!
//! **A role is refused precisely, or not at all.** There is no single "not
//! compatible" verdict. A distribution that is not the supported one, an
//! architecture that is not, a missing facility, a resource that does not
//! suffice and a fact that could not be verified are five different refusals,
//! and a machine failing several of them is told all of them rather than the
//! first.
//!
//! **An unverified fact never becomes a satisfied requirement.** Every
//! requirement below is checked against an [`Observed`], and the unknown branch
//! is a refusal carrying [`Unverified`] rather than a benefit of the doubt. That
//! is the whole difference between an audit and an assumption.

use super::audit::{
    Architecture, CgroupHierarchy, Distribution, InitSystem, Installation, Observed,
    ObservedMachine, Role, Unverified, SUPPORTED_DISTRIBUTION_ID, SUPPORTED_DISTRIBUTION_VERSION,
};

/// Whether the user declared the endpoint as reachable from outside.
///
/// It is declared, never observed: what makes a machine exposed is where its
/// address lives and what stands in front of it, and no read of the machine
/// itself can answer that honestly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exposure {
    Private,
    Exposed,
}

/// Whether the user declared the endpoint as normally powered on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    NormallyOn,
    Intermittent,
}

/// One endpoint, exactly as the user declared it.
///
/// This is the only way an endpoint enters the palier. There is no constructor
/// that derives one from a scan, a range, a lease file or a provider listing,
/// and there is none that derives one from an audit either: an audited machine
/// cannot name a second machine into existence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredEndpoint {
    /// The name the user gave it. It identifies the declaration, and nothing
    /// is ever dialled from it.
    pub name: String,
    pub port: u16,
    pub exposure: Exposure,
    pub availability: Availability,
    /// True only when the user explicitly declared this endpoint a Relay
    /// candidate. It defaults to nothing: a caller that does not set it has not
    /// declared it, which is the point.
    pub relay_candidate: bool,
}

/// What one role needs of a machine before it may be proposed on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoleRequirements {
    pub memory_kib: u64,
    pub processors: u32,
    pub free_disk_kib: u64,
}

/// The Controller's own floor, measured on a small machine rather than on the
/// LAB's most comfortable one.
pub const CONTROLLER_REQUIREMENTS: RoleRequirements = RoleRequirements {
    memory_kib: 524_288,
    processors: 1,
    free_disk_kib: 2_097_152,
};

/// The Relay's floor. It carries traffic rather than state, so it asks for less
/// memory and the same disk headroom for its own artefacts.
pub const RELAY_REQUIREMENTS: RoleRequirements = RoleRequirements {
    memory_kib: 262_144,
    processors: 1,
    free_disk_kib: 1_048_576,
};

pub fn requirements(role: Role) -> RoleRequirements {
    match role {
        Role::Relay => RELAY_REQUIREMENTS,
        // The Agent and the Auxiliary are not placed by this palier. They are
        // given the Controller's floor rather than a smaller one invented here,
        // so nothing is ever proposed on a machine that has not cleared the
        // strictest bound this module knows.
        _ => CONTROLLER_REQUIREMENTS,
    }
}

/// Which resource did not suffice, and by how much.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource {
    Memory,
    Processors,
    FreeDisk,
}

/// Which facility the target must have and does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Facility {
    /// systemd, which is what bounds a managed service's unit.
    Init,
    /// The unified cgroup hierarchy, which is what the bounds are written on.
    CgroupV2,
}

/// One precise reason a role may not be placed on an audited machine.
///
/// Every variant names the fact that produced it and, where there is one, the
/// value that was observed beside the value that was required. A refusal that
/// could not be read back into "what exactly is wrong with this machine" would
/// not be a refusal, it would be a shrug.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Incompatibility {
    /// The machine names a distribution that is not the supported target.
    Distribution { observed: Distribution },
    /// The machine names an architecture that is not the supported one.
    Architecture { observed: Architecture },
    /// The machine runs another init, or another cgroup hierarchy.
    Facility {
        facility: Facility,
        observed_init: Option<InitSystem>,
        observed_hierarchy: Option<CgroupHierarchy>,
    },
    /// The machine has less of a resource than the role needs.
    Resource {
        resource: Resource,
        observed: u64,
        required: u64,
    },
    /// The fact this check rests on was never established. It is its own
    /// variant on purpose: "this machine is too small" and "this machine never
    /// said how big it is" must not be answerable by the same sentence.
    Unverified { fact: &'static str, why: Unverified },
}

/// Why no proposal was produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlacementRefusal {
    /// The machine does not satisfy the role. Every reason is carried, not the
    /// first one found.
    Incompatible(Vec<Incompatibility>),
    /// The Controller was asked for on an endpoint the user declared exposed.
    ControllerOnExposedEndpoint,
    /// The Controller was asked for on an endpoint the user did not declare
    /// normally powered on.
    ControllerOnIntermittentEndpoint,
    /// The Controller was asked for on a machine already declaring a Relay.
    /// The default is not to put the private brain on the public door.
    ControllerBesideRelay,
    /// The Relay was asked for on an endpoint nobody declared a candidate.
    RelayOnUndeclaredCandidate,
    /// This palier proposes the Controller and the Relay, and nothing else.
    RoleOutsideThisPalier(Role),
    /// The approval names another role, or another endpoint, than the proposal
    /// it was given.
    RoleNotApproved,
}

/// Whether the proposed role would share its machine, and with what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cohabitation {
    /// No installation declares itself at the fixed path, so nothing of Your
    /// Cloud is known to share this machine.
    NoDeclaredInstallation,
    /// An installation declares these roles, and the proposed one would join
    /// them.
    WithDeclaredRoles(Vec<Role>),
}

/// What the loss of the host takes with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultDomain {
    /// Nothing else of Your Cloud is declared here, so losing the host loses
    /// the proposed role and nothing more of Your Cloud.
    OwnHost,
    /// Roles already declared here share the hardware fault domain: losing the
    /// host interrupts all of them at once. It is announced before approval,
    /// never discovered after it.
    SharedWithDeclaredRoles,
}

/// One fact the audit could not establish, named so a proposal can carry it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnverifiedFact {
    pub fact: &'static str,
    pub why: Unverified,
}

/// A flow the role would eventually need, announced before approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flow {
    pub description: &'static str,
    pub port: u16,
}

/// Everything the user sees before saying yes, and everything saying yes is
/// about.
///
/// It carries no session, no credential and no address: it is what a consent
/// window renders, so it holds exactly what a consent is given over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub role: Role,
    /// The declared endpoint's own name. The proposal names a declaration,
    /// never an address it could be dialled from.
    pub endpoint: String,
    pub cohabitation: Cohabitation,
    pub fault_domain: FaultDomain,
    /// What the role asks for.
    pub required: RoleRequirements,
    /// What the machine answered, so the margin is visible rather than implied.
    pub observed_memory_kib: u64,
    pub observed_processors: u32,
    pub observed_free_disk_kib: u64,
    /// The accounts the installation would create.
    pub accounts: &'static [&'static str],
    /// The artefacts it would write.
    pub artifacts: &'static [&'static str],
    /// The listeners and destinations it would need.
    pub flows: &'static [Flow],
    /// The privileges it would hold.
    pub privileges: &'static [&'static str],
    /// Facts the audit could not establish. They are carried into the proposal
    /// rather than dropped: a user approving a placement is entitled to see
    /// what was not known when it was proposed.
    pub unverified: Vec<UnverifiedFact>,
}

const CONTROLLER_ACCOUNTS: [&str; 1] = ["your-cloud-controller"];
const CONTROLLER_ARTIFACTS: [&str; 3] = [
    "/etc/your-cloud/roles",
    "/usr/local/lib/your-cloud/controller",
    "/var/lib/your-cloud/controller",
];
const CONTROLLER_FLOWS: [Flow; 1] = [Flow {
    description: "controller api, private network only",
    port: 8443,
}];
const CONTROLLER_PRIVILEGES: [&str; 1] = ["one systemd unit, no ambient capability"];

const RELAY_ACCOUNTS: [&str; 1] = ["your-cloud-relay"];
const RELAY_ARTIFACTS: [&str; 3] = [
    "/etc/your-cloud/roles",
    "/usr/local/lib/your-cloud/relay",
    "/var/lib/your-cloud/relay",
];
const RELAY_FLOWS: [Flow; 1] = [Flow {
    description: "public ingress terminated by the relay",
    port: 443,
}];
const RELAY_PRIVILEGES: [&str; 1] = ["one systemd unit, no ambient capability"];

/// Judges one role against one audited machine, and names every reason it does
/// not fit.
///
/// The order is fixed and the list is complete: a machine that is the wrong
/// distribution *and* too small is told both, because a user who fixes one and
/// comes back to be told the other has been audited twice for nothing.
pub fn compatibility(role: Role, machine: &ObservedMachine) -> Vec<Incompatibility> {
    let required = requirements(role);
    let mut refusals = Vec::new();

    match &machine.distribution {
        Observed::Known(distribution)
            if distribution.id == SUPPORTED_DISTRIBUTION_ID
                && distribution.version_id == SUPPORTED_DISTRIBUTION_VERSION => {}
        Observed::Known(distribution) => refusals.push(Incompatibility::Distribution {
            observed: distribution.clone(),
        }),
        Observed::Unknown(why) => refusals.push(unverified("distribution", *why)),
    }

    match &machine.architecture {
        Observed::Known(Architecture::Amd64) => {}
        Observed::Known(other) => refusals.push(Incompatibility::Architecture {
            observed: other.clone(),
        }),
        Observed::Unknown(why) => refusals.push(unverified("architecture", *why)),
    }

    match &machine.init {
        Observed::Known(InitSystem::Systemd) => {}
        Observed::Known(other) => refusals.push(Incompatibility::Facility {
            facility: Facility::Init,
            observed_init: Some(other.clone()),
            observed_hierarchy: None,
        }),
        Observed::Unknown(why) => refusals.push(unverified("init", *why)),
    }

    match &machine.cgroup {
        Observed::Known(CgroupHierarchy::V2) => {}
        Observed::Known(hierarchy) => refusals.push(Incompatibility::Facility {
            facility: Facility::CgroupV2,
            observed_init: None,
            observed_hierarchy: Some(*hierarchy),
        }),
        Observed::Unknown(why) => refusals.push(unverified("cgroup", *why)),
    }

    resource(
        &mut refusals,
        "memory",
        Resource::Memory,
        &machine.memory_kib,
        required.memory_kib,
    );
    resource(
        &mut refusals,
        "processors",
        Resource::Processors,
        &widen(&machine.processors),
        u64::from(required.processors),
    );
    resource(
        &mut refusals,
        "free disk",
        Resource::FreeDisk,
        &machine.free_disk_kib,
        required.free_disk_kib,
    );
    refusals
}

/// Widens a counted fact without touching the unknown branch. It exists so the
/// resource check below is written once rather than once per width.
fn widen(counted: &Observed<u32>) -> Observed<u64> {
    match counted {
        Observed::Known(value) => Observed::Known(u64::from(*value)),
        Observed::Unknown(why) => Observed::Unknown(*why),
    }
}

fn resource(
    refusals: &mut Vec<Incompatibility>,
    name: &'static str,
    resource: Resource,
    observed: &Observed<u64>,
    required: u64,
) {
    match observed {
        Observed::Known(value) if *value >= required => {}
        Observed::Known(value) => refusals.push(Incompatibility::Resource {
            resource,
            observed: *value,
            required,
        }),
        Observed::Unknown(why) => refusals.push(unverified(name, *why)),
    }
}

fn unverified(fact: &'static str, why: Unverified) -> Incompatibility {
    Incompatibility::Unverified { fact, why }
}

/// Produces the one proposal an audited endpoint supports, or refuses precisely.
///
/// The placement rules come before the machine's own facts: a Controller asked
/// for on an exposed endpoint is refused for being exposed, whatever the machine
/// answered, because the reason has nothing to do with what was audited and
/// telling the user about memory instead would be misleading.
pub fn propose(
    role: Role,
    endpoint: &DeclaredEndpoint,
    machine: &ObservedMachine,
) -> Result<Proposal, PlacementRefusal> {
    let declared_roles = match &machine.installation {
        Observed::Known(Installation::Declared(roles)) => roles.clone(),
        _ => Vec::new(),
    };

    match role {
        Role::Controller => {
            if endpoint.exposure != Exposure::Private {
                return Err(PlacementRefusal::ControllerOnExposedEndpoint);
            }
            if endpoint.availability != Availability::NormallyOn {
                return Err(PlacementRefusal::ControllerOnIntermittentEndpoint);
            }
            if declared_roles.contains(&Role::Relay) {
                return Err(PlacementRefusal::ControllerBesideRelay);
            }
        }
        Role::Relay => {
            if !endpoint.relay_candidate {
                return Err(PlacementRefusal::RelayOnUndeclaredCandidate);
            }
        }
        other => return Err(PlacementRefusal::RoleOutsideThisPalier(other)),
    }

    let refusals = compatibility(role, machine);
    if !refusals.is_empty() {
        return Err(PlacementRefusal::Incompatible(refusals));
    }

    // Past this point every fact a requirement rests on is known, so reading it
    // back cannot fail. The `unwrap_or` below is unreachable rather than
    // permissive: a fact that had been unknown would already have refused.
    let observed_memory_kib = *machine.memory_kib.known().unwrap_or(&0);
    let observed_processors = *machine.processors.known().unwrap_or(&0);
    let observed_free_disk_kib = *machine.free_disk_kib.known().unwrap_or(&0);

    let (cohabitation, fault_domain) = if declared_roles.is_empty() {
        (Cohabitation::NoDeclaredInstallation, FaultDomain::OwnHost)
    } else {
        (
            Cohabitation::WithDeclaredRoles(declared_roles),
            FaultDomain::SharedWithDeclaredRoles,
        )
    };

    let (accounts, artifacts, flows, privileges) = match role {
        Role::Relay => (
            &RELAY_ACCOUNTS[..],
            &RELAY_ARTIFACTS[..],
            &RELAY_FLOWS[..],
            &RELAY_PRIVILEGES[..],
        ),
        _ => (
            &CONTROLLER_ACCOUNTS[..],
            &CONTROLLER_ARTIFACTS[..],
            &CONTROLLER_FLOWS[..],
            &CONTROLLER_PRIVILEGES[..],
        ),
    };

    Ok(Proposal {
        role,
        endpoint: endpoint.name.clone(),
        cohabitation,
        fault_domain,
        required: requirements(role),
        observed_memory_kib,
        observed_processors,
        observed_free_disk_kib,
        accounts,
        artifacts,
        flows,
        privileges,
        unverified: unverified_facts(machine),
    })
}

/// Every fact of the observation that was not established, named.
///
/// A proposal may be produced while some fact is unknown — the hostname, the
/// uid, an existing installation — because no requirement rests on those. They
/// are still carried, because "we proposed this without knowing that" is
/// precisely what a user must be able to read before approving.
fn unverified_facts(machine: &ObservedMachine) -> Vec<UnverifiedFact> {
    let mut facts = Vec::new();
    let mut note = |fact: &'static str, why: Option<Unverified>| {
        if let Some(why) = why {
            facts.push(UnverifiedFact { fact, why });
        }
    };
    note("uid", machine.uid.unverified());
    note("hostname", machine.hostname.unverified());
    note("distribution", machine.distribution.unverified());
    note("architecture", machine.architecture.unverified());
    note("init", machine.init.unverified());
    note("cgroup", machine.cgroup.unverified());
    note("memory", machine.memory_kib.unverified());
    note("processors", machine.processors.unverified());
    note("free disk", machine.free_disk_kib.unverified());
    note("installation", machine.installation.unverified());
    facts
}

/// What the user answers a proposal with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    pub role: Role,
    pub endpoint: String,
}

/// The proof that one exact placement was approved.
///
/// Like the elevation witness of the previous palier it carries no output, it
/// cannot be built by naming its fields, and [`approve`] is the only function
/// that returns one. It authorises nothing at this palier — there is nothing
/// here to authorise — and that is the point: the palier that installs will
/// have to be handed one, so "could a role be installed without an approval"
/// has one place to look at rather than one per call site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedPlacement {
    role: Role,
    endpoint: String,
}

impl ApprovedPlacement {
    pub fn role(&self) -> Role {
        self.role
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

/// Turns one proposal into an approval, and refuses every answer that is not
/// about that proposal.
///
/// An approval naming another role, or the same role on another endpoint, is
/// [`PlacementRefusal::RoleNotApproved`]. A recommendation the user never
/// answered is therefore not merely "not installed": it has no witness at all,
/// so there is nothing a later palier could act on.
pub fn approve(
    proposal: &Proposal,
    approval: &Approval,
) -> Result<ApprovedPlacement, PlacementRefusal> {
    if approval.role != proposal.role || approval.endpoint != proposal.endpoint {
        return Err(PlacementRefusal::RoleNotApproved);
    }
    Ok(ApprovedPlacement {
        role: proposal.role,
        endpoint: proposal.endpoint.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every fact a requirement rests on, in the order the refusals name them.
    const FACT_NAMES: [&str; 6] = [
        "distribution",
        "architecture",
        "init",
        "cgroup",
        "memory",
        "processors",
    ];

    fn compatible() -> ObservedMachine {
        ObservedMachine {
            uid: Observed::Known(1001),
            hostname: Observed::Known("machine-1".into()),
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

    fn private_endpoint() -> DeclaredEndpoint {
        DeclaredEndpoint {
            name: "machine-1".into(),
            port: 22,
            exposure: Exposure::Private,
            availability: Availability::NormallyOn,
            relay_candidate: false,
        }
    }

    #[test]
    fn a_compatible_private_machine_carries_a_whole_controller_proposal() {
        let proposal = propose(Role::Controller, &private_endpoint(), &compatible())
            .expect("a compatible machine must be proposable");

        assert_eq!(proposal.role, Role::Controller);
        assert_eq!(proposal.endpoint, "machine-1");
        assert_eq!(proposal.cohabitation, Cohabitation::NoDeclaredInstallation);
        assert_eq!(proposal.fault_domain, FaultDomain::OwnHost);
        assert_eq!(proposal.required, CONTROLLER_REQUIREMENTS);
        assert_eq!(proposal.observed_memory_kib, 991_164);
        assert!(proposal.unverified.is_empty());
        // Everything the user must see before approving is really there.
        assert!(!proposal.accounts.is_empty());
        assert!(!proposal.artifacts.is_empty());
        assert!(!proposal.flows.is_empty());
        assert!(!proposal.privileges.is_empty());
    }

    /// The Controller is proposed on a private, normally powered on machine and
    /// nowhere else, and each refusal names which of the two failed.
    #[test]
    fn the_controller_is_refused_on_an_exposed_or_intermittent_endpoint() {
        let mut exposed = private_endpoint();
        exposed.exposure = Exposure::Exposed;
        assert_eq!(
            propose(Role::Controller, &exposed, &compatible()),
            Err(PlacementRefusal::ControllerOnExposedEndpoint)
        );

        let mut intermittent = private_endpoint();
        intermittent.availability = Availability::Intermittent;
        assert_eq!(
            propose(Role::Controller, &intermittent, &compatible()),
            Err(PlacementRefusal::ControllerOnIntermittentEndpoint)
        );
    }

    /// The default placement never puts the Controller on the machine that
    /// already declares the Relay.
    #[test]
    fn the_controller_is_refused_beside_a_declared_relay() {
        let mut machine = compatible();
        machine.installation = Observed::Known(Installation::Declared(vec![Role::Relay]));
        assert_eq!(
            propose(Role::Controller, &private_endpoint(), &machine),
            Err(PlacementRefusal::ControllerBesideRelay)
        );
    }

    /// The Relay is proposed only where the user declared a candidate, and the
    /// declaration is the whole difference between the two runs below.
    #[test]
    fn the_relay_is_only_proposed_on_an_explicitly_declared_candidate() {
        let mut endpoint = private_endpoint();
        endpoint.exposure = Exposure::Exposed;
        assert_eq!(
            propose(Role::Relay, &endpoint, &compatible()),
            Err(PlacementRefusal::RelayOnUndeclaredCandidate)
        );

        endpoint.relay_candidate = true;
        let proposal =
            propose(Role::Relay, &endpoint, &compatible()).expect("a declared candidate");
        assert_eq!(proposal.role, Role::Relay);
        assert_eq!(proposal.required, RELAY_REQUIREMENTS);
    }

    /// Cohabitation and the shared fault domain are announced by the proposal
    /// itself, before anything is approved.
    #[test]
    fn an_existing_installation_is_announced_as_cohabitation_and_shared_fault_domain() {
        let mut machine = compatible();
        machine.installation = Observed::Known(Installation::Declared(vec![Role::Agent]));
        let proposal = propose(Role::Controller, &private_endpoint(), &machine)
            .expect("a compatible machine that already runs an agent");
        assert_eq!(
            proposal.cohabitation,
            Cohabitation::WithDeclaredRoles(vec![Role::Agent])
        );
        assert_eq!(proposal.fault_domain, FaultDomain::SharedWithDeclaredRoles);
    }

    /// Each incompatibility is named, and a machine failing several is told all
    /// of them at once.
    #[test]
    fn each_incompatibility_is_refused_by_its_own_name() {
        let mut wrong = compatible();
        wrong.distribution = Observed::Known(Distribution {
            id: "ubuntu".into(),
            version_id: "24.04".into(),
        });
        wrong.architecture = Observed::Known(Architecture::Other("aarch64".into()));
        wrong.init = Observed::Known(InitSystem::Other("openrc".into()));
        wrong.cgroup = Observed::Known(CgroupHierarchy::Legacy);
        wrong.memory_kib = Observed::Known(1024);

        let Err(PlacementRefusal::Incompatible(refusals)) =
            propose(Role::Controller, &private_endpoint(), &wrong)
        else {
            panic!("an incompatible machine must be refused");
        };
        assert!(refusals.contains(&Incompatibility::Distribution {
            observed: Distribution {
                id: "ubuntu".into(),
                version_id: "24.04".into(),
            }
        }));
        assert!(refusals.contains(&Incompatibility::Architecture {
            observed: Architecture::Other("aarch64".into())
        }));
        assert!(refusals.contains(&Incompatibility::Facility {
            facility: Facility::Init,
            observed_init: Some(InitSystem::Other("openrc".into())),
            observed_hierarchy: None,
        }));
        assert!(refusals.contains(&Incompatibility::Facility {
            facility: Facility::CgroupV2,
            observed_init: None,
            observed_hierarchy: Some(CgroupHierarchy::Legacy),
        }));
        assert!(refusals.contains(&Incompatibility::Resource {
            resource: Resource::Memory,
            observed: 1024,
            required: CONTROLLER_REQUIREMENTS.memory_kib,
        }));
        assert_eq!(
            refusals.len(),
            5,
            "every reason is reported, none is hidden"
        );
    }

    /// A supported distribution at an unsupported version is still the wrong
    /// target, and says so with the version it read.
    #[test]
    fn a_supported_distribution_at_another_version_is_refused_as_the_distribution() {
        let mut older = compatible();
        older.distribution = Observed::Known(Distribution {
            id: SUPPORTED_DISTRIBUTION_ID.into(),
            version_id: "12".into(),
        });
        assert_eq!(
            compatibility(Role::Controller, &older),
            vec![Incompatibility::Distribution {
                observed: Distribution {
                    id: SUPPORTED_DISTRIBUTION_ID.into(),
                    version_id: "12".into(),
                }
            }]
        );
    }

    /// The central rule: a fact that was not established is refused as
    /// unverified, and never satisfies the requirement that rests on it.
    #[test]
    fn an_unverified_fact_is_never_an_optimistic_default() {
        let unknown = ObservedMachine::unanswered(Unverified::NotAnswered);
        let Err(PlacementRefusal::Incompatible(refusals)) =
            propose(Role::Controller, &private_endpoint(), &unknown)
        else {
            panic!("a machine that answered nothing must be refused");
        };
        assert_eq!(refusals.len(), FACT_NAMES.len() + 1);
        for fact in FACT_NAMES {
            assert!(
                refusals.contains(&Incompatibility::Unverified {
                    fact,
                    why: Unverified::NotAnswered
                }),
                "{fact} must be refused as unverified"
            );
        }
        assert!(refusals.contains(&Incompatibility::Unverified {
            fact: "free disk",
            why: Unverified::NotAnswered
        }));
    }

    /// A machine that is compatible while some fact it does not depend on is
    /// unknown carries that fact into the proposal rather than dropping it.
    #[test]
    fn a_proposal_carries_the_facts_that_were_never_established() {
        let mut machine = compatible();
        machine.hostname = Observed::Unknown(Unverified::NotProduced);
        machine.uid = Observed::Unknown(Unverified::Unreadable);
        let proposal = propose(Role::Controller, &private_endpoint(), &machine)
            .expect("no requirement rests on the hostname or the uid");
        assert_eq!(
            proposal.unverified,
            vec![
                UnverifiedFact {
                    fact: "uid",
                    why: Unverified::Unreadable
                },
                UnverifiedFact {
                    fact: "hostname",
                    why: Unverified::NotProduced
                },
            ]
        );
    }

    /// A recommendation the user did not approve produces no witness, and an
    /// approval that names something else produces none either.
    #[test]
    fn only_the_exact_approved_role_and_endpoint_produce_a_witness() {
        let proposal = propose(Role::Controller, &private_endpoint(), &compatible())
            .expect("a compatible machine");

        assert_eq!(
            approve(
                &proposal,
                &Approval {
                    role: Role::Relay,
                    endpoint: "machine-1".into(),
                }
            ),
            Err(PlacementRefusal::RoleNotApproved)
        );
        assert_eq!(
            approve(
                &proposal,
                &Approval {
                    role: Role::Controller,
                    endpoint: "machine-2".into(),
                }
            ),
            Err(PlacementRefusal::RoleNotApproved)
        );

        let approved = approve(
            &proposal,
            &Approval {
                role: Role::Controller,
                endpoint: "machine-1".into(),
            },
        )
        .expect("the exact proposal may be approved");
        assert_eq!(approved.role(), Role::Controller);
        assert_eq!(approved.endpoint(), "machine-1");
    }

    /// The two roles this palier places, and no third one by accident.
    #[test]
    fn no_other_role_is_placed_by_this_palier() {
        for role in [Role::Agent, Role::Auxiliary] {
            assert_eq!(
                propose(role, &private_endpoint(), &compatible()),
                Err(PlacementRefusal::RoleOutsideThisPalier(role))
            );
        }
    }
}
