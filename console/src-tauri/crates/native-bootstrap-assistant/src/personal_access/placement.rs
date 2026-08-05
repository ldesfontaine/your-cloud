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

/// The Agent's own floor, and the most modest of the three.
///
/// It is derived rather than chosen. The memory figure is the smallest whole
/// power-of-two mebibyte above the `MemoryMax=192M` its own unit already caps
/// the Daemon at — the same derivation the two floors above answer to, which is
/// why it lands on the Relay's figure without being copied from it. The disk
/// figure is the one place the Agent is really cheaper than everything else:
/// its local buffer is bounded at sixty-four kibibytes by the Daemon's own
/// limits, so what it needs room for is the shared artefact, its unit and its
/// journal, and nothing that grows with what the estate holds.
///
/// It asks for less than the Controller on every axis, which is the point: a
/// machine that could not host the private brain is still a machine Your Cloud
/// must be able to observe.
pub const AGENT_REQUIREMENTS: RoleRequirements = RoleRequirements {
    memory_kib: 262_144,
    processors: 1,
    free_disk_kib: 262_144,
};

pub fn requirements(role: Role) -> RoleRequirements {
    match role {
        Role::Relay => RELAY_REQUIREMENTS,
        Role::Agent => AGENT_REQUIREMENTS,
        // The Controller, and the Auxiliary — which is never placed at all and
        // is refused by `propose` before this is ever read. Giving it the
        // strictest floor this module knows rather than a smaller one invented
        // here keeps that refusal the only thing standing between it and a
        // machine.
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
    /// A role no placement ever proposes. The Auxiliary is the only one left:
    /// it is a one-shot mode of the same artefact rather than something that
    /// runs on a machine, so there is no placement to approve, and
    /// `machine_identity::plan::activate` refuses it as a service under its own
    /// name. The variant still carries the role it refused, so a caller that
    /// asks for something this module does not place is told which.
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

/// The account the Daemon's unit runs under. It is a systemd dynamic user, like
/// the Controller's, and is named here for the same reason: a user approving a
/// placement is told which name will appear on the machine, whether or not it
/// outlives the unit.
const AGENT_ACCOUNTS: [&str; 1] = ["your-cloud-daemon"];
const AGENT_ARTIFACTS: [&str; 3] = [
    "/etc/your-cloud/roles",
    "/etc/your-cloud/daemon.env",
    "/var/lib/private/your-cloud-daemon",
];
/// The Agent opens no listener. Its one flow is outbound, towards the Relay's
/// ingestion, and the proposal says so before anything is approved rather than
/// letting "an agent on every machine" be read as "a port on every machine".
const AGENT_FLOWS: [Flow; 1] = [Flow {
    description: "daemon to relay ingestion, outbound only",
    port: 8443,
}];
const AGENT_PRIVILEGES: [&str; 1] = ["one systemd unit, no ambient capability"];

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
        // **The Agent has no placement rule, and that absence is the rule.**
        // Every machine this release manages receives one, so there is no endpoint
        // it is the wrong choice for: an exposed machine is exactly as much in
        // need of being observed as a private one, an intermittent machine is
        // one whose absences the observation is there to record, and a machine
        // already declaring the Relay is a machine whose Relay somebody will
        // want the health of. The three refusals above are the Controller's
        // because they protect the *confidentiality and the continuity of the
        // control plane*; the Agent holds neither, so borrowing them would
        // refuse it for reasons that are not about it.
        //
        // What the Agent is still judged on is `compatibility` below — the same
        // distribution, architecture, init system and cgroup hierarchy the
        // audit of #36 knows how to read, against its own resource floor. No
        // fact is taken on trust for it that would not be taken on trust for
        // the Controller.
        Role::Agent => {}
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
        Role::Agent => (
            &AGENT_ACCOUNTS[..],
            &AGENT_ARTIFACTS[..],
            &AGENT_FLOWS[..],
            &AGENT_PRIVILEGES[..],
        ),
        // The Controller. The Auxiliary never reaches this point.
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

    /// The Auxiliary is the one role no placement proposes, and it is refused
    /// by its own name rather than by an absent branch.
    #[test]
    fn no_other_role_is_placed_by_this_palier() {
        assert_eq!(
            propose(Role::Auxiliary, &private_endpoint(), &compatible()),
            Err(PlacementRefusal::RoleOutsideThisPalier(Role::Auxiliary))
        );
        // And it is refused wherever it is asked for, so no endpoint
        // declaration lets it in through a side door.
        let mut anywhere = private_endpoint();
        anywhere.exposure = Exposure::Exposed;
        anywhere.availability = Availability::Intermittent;
        anywhere.relay_candidate = true;
        assert_eq!(
            propose(Role::Auxiliary, &anywhere, &compatible()),
            Err(PlacementRefusal::RoleOutsideThisPalier(Role::Auxiliary))
        );
    }

    /// **The Agent runs on every managed machine.** The three placement
    /// refusals the Controller answers to are refusals about the control plane,
    /// and none of them applies to an observer: the same machine that is too
    /// exposed, too intermittent and too busy running the Relay to host the
    /// Controller still gets an Agent proposed on it.
    #[test]
    fn the_agent_is_proposed_where_the_controller_is_refused() {
        let mut hostile = private_endpoint();
        hostile.exposure = Exposure::Exposed;
        hostile.availability = Availability::Intermittent;
        let mut machine = compatible();
        machine.installation = Observed::Known(Installation::Declared(vec![Role::Relay]));

        // The Controller, on that very endpoint and that very machine.
        assert_eq!(
            propose(Role::Controller, &hostile, &machine),
            Err(PlacementRefusal::ControllerOnExposedEndpoint)
        );

        let proposal = propose(Role::Agent, &hostile, &machine)
            .expect("every managed machine receives an Agent");
        assert_eq!(proposal.role, Role::Agent);
        assert_eq!(proposal.endpoint, "machine-1");
        assert_eq!(proposal.required, AGENT_REQUIREMENTS);
        // The cohabitation and the fault domain are announced for it exactly as
        // they are for the other roles.
        assert_eq!(
            proposal.cohabitation,
            Cohabitation::WithDeclaredRoles(vec![Role::Relay])
        );
        assert_eq!(proposal.fault_domain, FaultDomain::SharedWithDeclaredRoles);
        // And so is everything approving it is about.
        assert_eq!(proposal.accounts, ["your-cloud-daemon"]);
        assert!(!proposal.artifacts.is_empty());
        assert!(!proposal.flows.is_empty());
        assert!(!proposal.privileges.is_empty());
        assert!(proposal.unverified.is_empty());
    }

    /// The Agent's floor is its own, and it is more modest than the
    /// Controller's on every axis rather than on the one that happened to be
    /// measured.
    #[test]
    fn the_agent_asks_for_less_than_the_controller_on_every_axis() {
        assert!(AGENT_REQUIREMENTS.memory_kib < CONTROLLER_REQUIREMENTS.memory_kib);
        assert!(AGENT_REQUIREMENTS.free_disk_kib < CONTROLLER_REQUIREMENTS.free_disk_kib);
        assert!(AGENT_REQUIREMENTS.processors <= CONTROLLER_REQUIREMENTS.processors);
        assert_eq!(requirements(Role::Agent), AGENT_REQUIREMENTS);

        // A machine that clears the Agent's floor and nothing else hosts the
        // Agent, and is refused the two roles that ask for more disk.
        let mut small = compatible();
        small.memory_kib = Observed::Known(AGENT_REQUIREMENTS.memory_kib);
        small.free_disk_kib = Observed::Known(AGENT_REQUIREMENTS.free_disk_kib);
        assert_eq!(compatibility(Role::Agent, &small), Vec::new());
        assert!(
            compatibility(Role::Controller, &small).contains(&Incompatibility::Resource {
                resource: Resource::FreeDisk,
                observed: AGENT_REQUIREMENTS.free_disk_kib,
                required: CONTROLLER_REQUIREMENTS.free_disk_kib,
            })
        );
        assert!(
            compatibility(Role::Relay, &small).contains(&Incompatibility::Resource {
                resource: Resource::FreeDisk,
                observed: AGENT_REQUIREMENTS.free_disk_kib,
                required: RELAY_REQUIREMENTS.free_disk_kib,
            })
        );
    }

    /// Opening the Agent widened no other check. It is judged on the same four
    /// compatibility facts as everything else, and an unverified one is a
    /// refusal for it too.
    #[test]
    fn the_agent_is_judged_on_the_same_audited_facts_as_the_other_roles() {
        let mut wrong = compatible();
        wrong.distribution = Observed::Known(Distribution {
            id: "ubuntu".into(),
            version_id: "24.04".into(),
        });
        wrong.init = Observed::Known(InitSystem::Other("openrc".into()));
        wrong.cgroup = Observed::Known(CgroupHierarchy::Legacy);
        let Err(PlacementRefusal::Incompatible(refusals)) =
            propose(Role::Agent, &private_endpoint(), &wrong)
        else {
            panic!("an incompatible machine must be refused an Agent too");
        };
        assert_eq!(refusals.len(), 3);

        let unknown = ObservedMachine::unanswered(Unverified::NotAnswered);
        let Err(PlacementRefusal::Incompatible(refusals)) =
            propose(Role::Agent, &private_endpoint(), &unknown)
        else {
            panic!("a machine that answered nothing must be refused an Agent");
        };
        for fact in FACT_NAMES {
            assert!(
                refusals.contains(&Incompatibility::Unverified {
                    fact,
                    why: Unverified::NotAnswered
                }),
                "{fact} must be refused as unverified for the Agent"
            );
        }
    }

    /// An approved Agent produces a witness, which is what the palier that
    /// enrols machines has to be handed. The exactness of [`approve`] is not
    /// relaxed for it.
    #[test]
    fn an_agent_is_approved_exactly_like_every_other_role() {
        let proposal =
            propose(Role::Agent, &private_endpoint(), &compatible()).expect("a compatible machine");
        assert_eq!(
            approve(
                &proposal,
                &Approval {
                    role: Role::Agent,
                    endpoint: "machine-2".into(),
                }
            ),
            Err(PlacementRefusal::RoleNotApproved)
        );
        let approved = approve(
            &proposal,
            &Approval {
                role: Role::Agent,
                endpoint: "machine-1".into(),
            },
        )
        .expect("the exact proposal may be approved");
        assert_eq!(approved.role(), Role::Agent);
        assert_eq!(approved.endpoint(), "machine-1");
    }
}
