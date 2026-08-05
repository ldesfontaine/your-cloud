//! The LAB's way of reaching the replacement gates, and nothing more.
//!
//! The decisions of `replacement` are exercised by their own unit tests. What
//! this fixture adds is the only thing those tests cannot give: the *same*
//! functions, in a real process, judging a real `authorized_keys` file, a real
//! socket sample taken off a real listener, and the real answers a real `sshd`
//! gave to two identities in turn.
//!
//! It is a fixture and it stays one. It is built behind its own feature, it is
//! never part of the Console's `externalBin`, it replaces nothing and it holds
//! no privilege: it reads files, calls one gate and prints one verdict. Every
//! refusal is printed by its own name so the harness asserts the reason rather
//! than the exit code.
//!
//! **The harness never fabricates a witness.** Every witness this binary hands
//! to a gate is built the only way one can be built — `incident::qualify` on
//! probes the harness really took, `succession::concord` on states really read,
//! #38's `association::bind`, #38's `preflight::clear`, #54's
//! `elevation::elevated`, #39's `plan::verify`. There is no constructor here
//! that a shell script could call to skip one.

use std::process::ExitCode;
use your_cloud_native_bootstrap_assistant::installation::association::{self, AssociationOffer};
use your_cloud_native_bootstrap_assistant::installation::preflight::{
    self, EndpointAttempt, Observation, PreflightCleared,
};
use your_cloud_native_bootstrap_assistant::installation::rollback::{
    ItemKind, Ledger, Provenance, Unwind,
};
use your_cloud_native_bootstrap_assistant::machine_identity::entry;
use your_cloud_native_bootstrap_assistant::machine_identity::identity::{self, Declared, Enrolled};
use your_cloud_native_bootstrap_assistant::machine_identity::plan::{
    self as enrolment_plan, AuxiliaryReport, PathVerified, DIAGNOSTIC_OPERATION,
};
use your_cloud_native_bootstrap_assistant::personal_access::audit::{
    Architecture, CgroupHierarchy, Distribution, InitSystem, Installation, Observed,
    ObservedMachine, Role, SUPPORTED_DISTRIBUTION_ID, SUPPORTED_DISTRIBUTION_VERSION,
};
use your_cloud_native_bootstrap_assistant::personal_access::elevation;
use your_cloud_native_bootstrap_assistant::personal_access::placement::{
    self, Approval, Availability, DeclaredEndpoint, Exposure,
};
use your_cloud_native_bootstrap_assistant::replacement::incident::{
    self, Answer, Isolation, NewHost, Probe, Qualification, QualifiedIncident, Request,
};
use your_cloud_native_bootstrap_assistant::replacement::inheritance::{
    self, Carried, Grant, Kind, Origin, Residue,
};
use your_cloud_native_bootstrap_assistant::replacement::plan::{
    self, Containment, ReplacementPlan,
};
use your_cloud_native_bootstrap_assistant::replacement::reader::{
    self, ReaderManifest, ReaderState, Socket,
};
use your_cloud_native_bootstrap_assistant::replacement::succession::{
    self, Continuity, IndependentState, Succession,
};
use your_cloud_native_bootstrap_assistant::replacement::transition::{
    self, Attempt, Evidence, Fleet, Reconstructed, TargetState,
};
use your_cloud_native_bootstrap_assistant::replacement::withdrawal::{
    self, KeyProvenance, ObservedKey,
};

const USAGE: &str = "usage: steps | render-entry | qualify | concord | succeed | authorize \
                     | reader | rotate | admit | sweep | reconstruct | fleet | classify \
                     | withdraw | supersede | conclude | unwind";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = arguments.first().map(String::as_str) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let rest = &arguments[1..];
    match command {
        "steps" => steps(rest),
        "render-entry" => render_entry(rest),
        "qualify" => one(rest, "qualify", describe_incident),
        "concord" => one(rest, "concord", describe_continuity),
        "succeed" => one(rest, "succeed", describe_succession),
        "authorize" => one(rest, "authorize", describe_plan),
        "reader" => one(rest, "reader", describe_reader),
        "rotate" => one(rest, "rotate", describe_rotation),
        "admit" => one(rest, "admit", describe_admission),
        "sweep" => one(rest, "sweep", describe_sweep),
        "fleet" => one(rest, "fleet", describe_fleet),
        "conclude" => one(rest, "conclude", describe_conclusion),
        "reconstruct" => reconstruct(rest),
        "classify" => classify(rest),
        "withdraw" => withdraw(rest),
        "supersede" => supersede(rest),
        "unwind" => run_unwind(rest),
        _ => {
            eprintln!("unknown command {command}");
            ExitCode::from(2)
        }
    }
}

/// `steps QUALIFICATION` — the fixed sequence of one journey, in order, so the
/// harness asserts the ordering against the product rather than against a list
/// it wrote itself.
fn steps(arguments: &[String]) -> ExitCode {
    let [qualification] = arguments else {
        eprintln!("usage: steps QUALIFICATION");
        return ExitCode::from(2);
    };
    let sequence = match parse_qualification(qualification) {
        Ok(Qualification::HardwareLoss) => plan::STEPS.as_slice(),
        Ok(Qualification::SuspectedCompromise) => plan::ISOLATED_STEPS.as_slice(),
        Err(message) => {
            println!("REFUSED {message}");
            return ExitCode::from(2);
        }
    };
    let names: Vec<&str> = sequence.iter().map(|step| step.as_str()).collect();
    println!("{}", names.join(","));
    ExitCode::SUCCESS
}

/// `render-entry ALGORITHM KEY` — the bounded entry #39 writes.
///
/// The harness installs what this prints and never composes an entry itself:
/// the managed key file of the LAB is therefore the file the product writes,
/// which is what makes judging it afterwards mean anything.
fn render_entry(arguments: &[String]) -> ExitCode {
    let [algorithm, key] = arguments else {
        eprintln!("usage: render-entry ALGORITHM KEY");
        return ExitCode::from(2);
    };
    match entry::render(algorithm, key) {
        Ok(line) => {
            print!("{line}");
            ExitCode::SUCCESS
        }
        Err(refusal) => {
            println!("REFUSED {refusal:?}");
            ExitCode::from(1)
        }
    }
}

/// Every command that takes exactly one perimeter file goes through here, so an
/// acceptance and a refusal are never printed in two different shapes.
fn one(
    arguments: &[String],
    name: &str,
    describe: fn(&Perimeter) -> Result<String, String>,
) -> ExitCode {
    let [path] = arguments else {
        eprintln!("usage: {name} PERIMETER");
        return ExitCode::from(2);
    };
    report(read_perimeter(path).and_then(|perimeter| describe(&perimeter)))
}

/// One perimeter, as the harness writes it: one directive per line, fields
/// separated by tabs.
///
/// ```text
/// qualification    hardware-loss|suspected-compromise
/// old-controller   <id>
/// new-controller   <id>
/// suspect-host     <name>
/// new-host         distinct|reinstalled|as-it-stands   <endpoint>
/// isolation        verified <by> | unverified
/// confirmed        true|false
/// probe            <vantage>   answered|unreachable|no-answer   <seconds>
/// state            <source>    <infrastructure_id>|-
/// used             <controller_id>
/// cleared          <endpoint>
/// association      <controller_id>  <infrastructure_id>  <sheet_id>
/// reader-during    <controller_id>  <address>  <status>  <socket>
/// reader-after     <controller_id>  <address>  <status>  <socket>
/// reader-old-address  <address>
/// carried          <kind>  <name>  minted|inherited|independent
/// residue          <kind>  <name>  refused|still-grants|not-observed
/// target           <machine>  old-only|bounded-overlap|new-only|unknown
/// containment      held|lost|not-applicable
/// ```
#[derive(Default)]
struct Perimeter {
    qualification: Option<Qualification>,
    old_controller: String,
    new_controller: String,
    suspect_host: String,
    new_host: Option<NewHost>,
    isolation: Option<Isolation>,
    confirmed: bool,
    probes: Vec<Probe>,
    states: Vec<IndependentState>,
    used: Vec<String>,
    cleared: Vec<String>,
    association: Option<(String, String, String)>,
    reader_during: Vec<ReaderState>,
    reader_after: Option<ReaderState>,
    reader_old_address: String,
    carried: Vec<Carried>,
    residues: Vec<Residue>,
    targets: Vec<Reconstructed>,
    containment: Option<Containment>,
}

fn read_perimeter(path: &str) -> Result<Perimeter, String> {
    let text = std::fs::read_to_string(path).map_err(|error| format!("UnreadableInput {error}"))?;
    let mut perimeter = Perimeter::default();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split('\t').collect();
        match fields.as_slice() {
            ["qualification", value] => {
                perimeter.qualification = Some(parse_qualification(value)?);
            }
            ["old-controller", value] => perimeter.old_controller = (*value).to_owned(),
            ["new-controller", value] => perimeter.new_controller = (*value).to_owned(),
            ["suspect-host", value] => perimeter.suspect_host = (*value).to_owned(),
            ["new-host", kind, endpoint] => {
                let endpoint = (*endpoint).to_owned();
                perimeter.new_host = Some(match *kind {
                    "distinct" => NewHost::Distinct { endpoint },
                    "reinstalled" => NewHost::ReinstalledFromTrustedBase { endpoint },
                    "as-it-stands" => NewHost::SameHostAsItStands { endpoint },
                    other => return Err(format!("MalformedInput new-host {other}")),
                });
            }
            ["isolation", "unverified"] => perimeter.isolation = Some(Isolation::Unverified),
            ["isolation", "verified", by] => {
                perimeter.isolation = Some(Isolation::Verified {
                    by: (*by).to_owned(),
                });
            }
            ["confirmed", value] => perimeter.confirmed = *value == "true",
            ["probe", vantage, answer, seconds] => perimeter.probes.push(Probe {
                vantage: (*vantage).to_owned(),
                answer: match *answer {
                    "answered" => Answer::Answered,
                    "unreachable" => Answer::Unreachable,
                    "no-answer" => Answer::NoAnswer,
                    other => return Err(format!("MalformedInput probe {other}")),
                },
                continuous_seconds: seconds
                    .parse()
                    .map_err(|_| "MalformedInput probe seconds".to_owned())?,
            }),
            ["state", source, infrastructure] => perimeter.states.push(IndependentState {
                source: (*source).to_owned(),
                infrastructure_id: match *infrastructure {
                    "-" => None,
                    value => Some(value.to_owned()),
                },
            }),
            ["used", value] => perimeter.used.push((*value).to_owned()),
            ["cleared", value] => perimeter.cleared.push((*value).to_owned()),
            ["association", controller, infrastructure, sheet] => {
                perimeter.association = Some((
                    (*controller).to_owned(),
                    (*infrastructure).to_owned(),
                    (*sheet).to_owned(),
                ));
            }
            ["reader-during", controller, address, status, socket] => {
                perimeter
                    .reader_during
                    .push(read_reader(controller, address, status, socket)?);
            }
            ["reader-after", controller, address, status, socket] => {
                perimeter.reader_after = Some(read_reader(controller, address, status, socket)?);
            }
            ["reader-old-address", value] => perimeter.reader_old_address = (*value).to_owned(),
            ["carried", kind, name, origin] => perimeter.carried.push(Carried {
                kind: parse_kind(kind)?,
                name: (*name).to_owned(),
                origin: match *origin {
                    "minted" => Origin::MintedForTheNewController,
                    "inherited" => Origin::InheritedFromTheOldAssociation,
                    "independent" => Origin::IndependentOfEveryController,
                    other => return Err(format!("MalformedInput origin {other}")),
                },
            }),
            ["residue", kind, name, grant] => perimeter.residues.push(Residue {
                kind: parse_kind(kind)?,
                name: (*name).to_owned(),
                grant: match *grant {
                    "refused" => Grant::Refused,
                    "still-grants" => Grant::StillGrantsAuthority,
                    "not-observed" => Grant::NotObserved,
                    other => return Err(format!("MalformedInput grant {other}")),
                },
            }),
            ["target", machine, state] => perimeter.targets.push(Reconstructed {
                machine: (*machine).to_owned(),
                state: parse_state(state)?,
            }),
            ["containment", value] => {
                perimeter.containment = Some(match *value {
                    "held" => Containment::Held,
                    "lost" => Containment::Lost,
                    "not-applicable" => Containment::NotApplicable,
                    other => return Err(format!("MalformedInput containment {other}")),
                });
            }
            _ => return Err(format!("MalformedInput {line}")),
        }
    }
    Ok(perimeter)
}

/// The infrastructure identifier the perimeter's independent states agree on,
/// needed to render a reader URI. It is read from the states rather than
/// declared twice.
fn declared_infrastructure() -> String {
    std::env::var("YOUR_CLOUD_LAB_INFRASTRUCTURE").unwrap_or_else(|_| "infrastructure".to_owned())
}

fn read_reader(
    controller: &str,
    address: &str,
    status: &str,
    socket: &str,
) -> Result<ReaderState, String> {
    let infrastructure = declared_infrastructure();
    let controllers: Vec<String> = controller
        .split(',')
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    // The URI is derived from the first named Controller. A manifest naming two
    // is exactly what `reader::read` has to refuse, so the fixture must be able
    // to hand it one.
    let uri = reader::reader_uri(
        &infrastructure,
        controllers.first().map(String::as_str).unwrap_or_default(),
    );
    let manifest = ReaderManifest {
        infrastructure_id: infrastructure,
        authorized_controller_ids: controllers,
        uri,
        source_address: address.to_owned(),
        status: status.to_owned(),
        port: reader::READER_PORT,
    };
    let socket = match socket {
        "listening" => Socket::Listening,
        "not-listening" => Socket::NotListening,
        "not-observed" => Socket::NotObserved,
        other => return Err(format!("MalformedInput socket {other}")),
    };
    reader::read(&manifest, socket).map_err(|refusal| format!("{refusal:?}"))
}

fn parse_qualification(value: &str) -> Result<Qualification, String> {
    match value {
        "hardware-loss" => Ok(Qualification::HardwareLoss),
        "suspected-compromise" => Ok(Qualification::SuspectedCompromise),
        other => Err(format!("MalformedInput qualification {other}")),
    }
}

fn parse_kind(value: &str) -> Result<Kind, String> {
    Kind::EVERY
        .into_iter()
        .find(|kind| kind.as_str() == value)
        .ok_or_else(|| format!("MalformedInput kind {value}"))
}

fn parse_state(value: &str) -> Result<TargetState, String> {
    [
        TargetState::OldOnly,
        TargetState::BoundedOverlap,
        TargetState::NewOnly,
        TargetState::Unknown,
    ]
    .into_iter()
    .find(|state| state.as_str() == value)
    .ok_or_else(|| format!("MalformedInput state {value}"))
}

fn parse_attempt(value: &str) -> Result<Attempt, String> {
    match value {
        "answered" => Ok(Attempt::Answered),
        "refused" => Ok(Attempt::Refused),
        "no-answer" => Ok(Attempt::NoAnswer),
        other => Err(format!("MalformedInput attempt {other}")),
    }
}

fn qualified(perimeter: &Perimeter) -> Result<QualifiedIncident, String> {
    let request = Request {
        qualification: perimeter
            .qualification
            .ok_or_else(|| "MalformedInput qualification".to_owned())?,
        old_controller_id: perimeter.old_controller.clone(),
        suspect_host: perimeter.suspect_host.clone(),
        new_host: perimeter
            .new_host
            .clone()
            .ok_or_else(|| "MalformedInput new-host".to_owned())?,
        isolation: perimeter.isolation.clone().unwrap_or(Isolation::Unverified),
        confirmed: perimeter.confirmed,
    };
    incident::qualify(&request, &perimeter.probes).map_err(|refusal| format!("{refusal:?}"))
}

fn continuity(perimeter: &Perimeter) -> Result<Continuity, String> {
    succession::concord(&qualified(perimeter)?, &perimeter.states)
        .map_err(|refusal| format!("{refusal:?}"))
}

fn succession(perimeter: &Perimeter) -> Result<Succession, String> {
    succession::succeed(
        &qualified(perimeter)?,
        &continuity(perimeter)?,
        &perimeter.new_controller,
        &perimeter.used,
    )
    .map_err(|refusal| format!("{refusal:?}"))
}

/// The host key the preflight compares against. It is a value the harness pins
/// from the managed LAB channel and hands in; the fixture never invents one.
fn confirmed_host_key() -> String {
    std::env::var("YOUR_CLOUD_LAB_HOST_KEY")
        .unwrap_or_else(|_| "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned())
}

fn cleared(perimeter: &Perimeter) -> Result<PreflightCleared, String> {
    let key = confirmed_host_key();
    let attempts: Vec<EndpointAttempt> = perimeter
        .cleared
        .iter()
        .map(|name| EndpointAttempt {
            name: name.clone(),
            confirmed_fingerprint: key.clone(),
            observed: Observation::Presented {
                fingerprint: key.clone(),
            },
        })
        .collect();
    preflight::clear(&attempts).map_err(|refusal| format!("{refusal:?}"))
}

fn replacement_plan(perimeter: &Perimeter) -> Result<ReplacementPlan, String> {
    let (controller, infrastructure, sheet) = perimeter
        .association
        .clone()
        .ok_or_else(|| "MalformedInput association".to_owned())?;
    let association = association::bind(
        &AssociationOffer {
            infrastructure_id: infrastructure.clone(),
            controller_id: controller,
            sheet_id: sheet,
            issued_at_unix_seconds: 1_000,
            lifetime_seconds: 300,
        },
        &infrastructure,
        &[],
        1_100,
    )
    .map_err(|refusal| format!("AssociationRefused {refusal:?}"))?;
    // A real `Elevation`, obtained the only way one can be obtained.
    let granted = elevation::elevated(0, b"0\n", b"")
        .map_err(|refusal| format!("ElevationRefused {refusal:?}"))?;
    plan::authorize(
        &qualified(perimeter)?,
        &succession(perimeter)?,
        &association,
        &granted,
        &cleared(perimeter)?,
    )
    .map_err(|refusal| format!("{refusal:?}"))
}

fn fleet(perimeter: &Perimeter) -> Result<Fleet, String> {
    transition::assemble(&perimeter.targets).map_err(|refusal| format!("{refusal:?}"))
}

fn describe_incident(perimeter: &Perimeter) -> Result<String, String> {
    let incident = qualified(perimeter)?;
    Ok(format!(
        "QUALIFIED qualification={} old={} suspect={} new-host={} isolation-required={}",
        incident.qualification().as_str(),
        incident.old_controller_id(),
        incident.suspect_host(),
        incident.new_host(),
        incident.qualification().requires_isolation(),
    ))
}

fn describe_continuity(perimeter: &Perimeter) -> Result<String, String> {
    let continuity = continuity(perimeter)?;
    Ok(format!(
        "CONTINUED infrastructure={} sources={}",
        continuity.infrastructure_id(),
        continuity.sources().join(",")
    ))
}

fn describe_succession(perimeter: &Perimeter) -> Result<String, String> {
    let succession = succession(perimeter)?;
    Ok(format!(
        "SUCCEEDED controller={} old={} infrastructure={}",
        succession.controller_id(),
        succession.old_controller_id(),
        succession.infrastructure_id()
    ))
}

fn describe_plan(perimeter: &Perimeter) -> Result<String, String> {
    let plan = replacement_plan(perimeter)?;
    let names: Vec<&str> = plan.steps().iter().map(|step| step.as_str()).collect();
    Ok(format!(
        "AUTHORIZED controller={} host={} journey={} steps={}",
        plan.controller_id(),
        plan.new_host(),
        plan.qualification().as_str(),
        names.join(",")
    ))
}

fn describe_reader(perimeter: &Perimeter) -> Result<String, String> {
    let state = perimeter
        .reader_after
        .clone()
        .ok_or_else(|| "MalformedInput reader-after".to_owned())?;
    Ok(match state {
        ReaderState::Closed => "READER_CLOSED".to_owned(),
        ReaderState::OpenTo {
            controller_id,
            source_address,
        } => format!("READER_OPEN controller={controller_id} source={source_address}"),
    })
}

fn describe_rotation(perimeter: &Perimeter) -> Result<String, String> {
    let after = perimeter
        .reader_after
        .clone()
        .ok_or_else(|| "MalformedInput reader-after".to_owned())?;
    let rotation = reader::rotate(
        &perimeter.reader_during,
        &after,
        &perimeter.old_controller,
        &perimeter.new_controller,
        &perimeter.reader_old_address,
    )
    .map_err(|refusal| format!("{refusal:?}"))?;
    Ok(format!(
        "ROTATED controller={} samples={}",
        rotation.controller_id(),
        rotation.samples()
    ))
}

fn describe_admission(perimeter: &Perimeter) -> Result<String, String> {
    let clean = inheritance::admit(&perimeter.carried).map_err(|refusal| format!("{refusal:?}"))?;
    Ok(format!(
        "STARTED_CLEAN minted={} reused={}",
        clean.minted(),
        clean.reused()
    ))
}

fn describe_sweep(perimeter: &Perimeter) -> Result<String, String> {
    let swept =
        inheritance::sweep(&perimeter.residues).map_err(|refusal| format!("{refusal:?}"))?;
    Ok(format!("SWEPT checked={}", swept.checked()))
}

fn describe_fleet(perimeter: &Perimeter) -> Result<String, String> {
    let fleet = fleet(perimeter)?;
    let rendered: Vec<String> = fleet
        .targets()
        .iter()
        .map(|target| format!("{}={}", target.machine, target.state.as_str()))
        .collect();
    Ok(format!(
        "FLEET finished={} {}",
        fleet.every_target_is_new_only(),
        rendered.join(",")
    ))
}

fn describe_conclusion(perimeter: &Perimeter) -> Result<String, String> {
    let plan = replacement_plan(perimeter)?;
    let after = perimeter
        .reader_after
        .clone()
        .ok_or_else(|| "MalformedInput reader-after".to_owned())?;
    let rotation = reader::rotate(
        &perimeter.reader_during,
        &after,
        &perimeter.old_controller,
        &perimeter.new_controller,
        &perimeter.reader_old_address,
    )
    .map_err(|refusal| format!("{refusal:?}"))?;
    let swept =
        inheritance::sweep(&perimeter.residues).map_err(|refusal| format!("{refusal:?}"))?;
    let secured = plan::conclude(
        &plan,
        &fleet(perimeter)?,
        &rotation,
        &swept,
        perimeter
            .containment
            .ok_or_else(|| "MalformedInput containment".to_owned())?,
    )
    .map_err(|refusal| format!("{refusal:?}"))?;
    Ok(format!(
        "SECURED controller={} targets={} reader-samples={} residues={}",
        secured.controller_id(),
        secured.targets(),
        secured.reader_samples(),
        secured.residues_checked()
    ))
}

/// `reconstruct EVIDENCE` — one target's state, rebuilt from what the machine
/// answered.
///
/// ```text
/// old-fingerprint  <SHA256:…>
/// new-fingerprint  <SHA256:…>
/// managed          <SHA256:…>        one line per entry in the managed file
/// unreadable                          the managed file could not be read
/// old-attempt      answered|refused|no-answer
/// new-attempt      answered|refused|no-answer
/// ```
fn reconstruct(arguments: &[String]) -> ExitCode {
    let [path] = arguments else {
        eprintln!("usage: reconstruct EVIDENCE");
        return ExitCode::from(2);
    };
    let outcome = (|| {
        let text =
            std::fs::read_to_string(path).map_err(|error| format!("UnreadableInput {error}"))?;
        let mut evidence = Evidence {
            managed_fingerprints: Some(Vec::new()),
            old_fingerprint: String::new(),
            new_fingerprint: String::new(),
            old_identity: Attempt::NoAnswer,
            new_identity: Attempt::NoAnswer,
        };
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let fields: Vec<&str> = line.split('\t').collect();
            match fields.as_slice() {
                ["old-fingerprint", value] => evidence.old_fingerprint = (*value).to_owned(),
                ["new-fingerprint", value] => evidence.new_fingerprint = (*value).to_owned(),
                ["managed", value] => {
                    if let Some(keys) = evidence.managed_fingerprints.as_mut() {
                        keys.push((*value).to_owned());
                    }
                }
                ["unreadable"] => evidence.managed_fingerprints = None,
                ["old-attempt", value] => evidence.old_identity = parse_attempt(value)?,
                ["new-attempt", value] => evidence.new_identity = parse_attempt(value)?,
                _ => return Err(format!("MalformedInput {line}")),
            }
        }
        let state = transition::reconstruct(&evidence);
        let next = match transition::next(state) {
            transition::Next::InstallNewAuthority => "install-new-authority",
            transition::Next::WithdrawOldAuthority => "withdraw-old-authority",
            transition::Next::Nothing => "nothing",
            transition::Next::ObserveOnly => "observe-only",
        };
        Ok(format!("STATE {} next={next}", state.as_str()))
    })();
    report(outcome)
}

/// One observed key file, as the harness reads it off a machine: one entry per
/// line, `file<TAB>fingerprint<TAB>line`.
fn read_observed(path: &str) -> Result<Vec<ObservedKey>, String> {
    let text = std::fs::read_to_string(path).map_err(|error| format!("UnreadableInput {error}"))?;
    let mut observed = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.splitn(3, '\t').collect();
        let [file, fingerprint, entry] = fields.as_slice() else {
            return Err(format!("MalformedInput {line}"));
        };
        observed.push(ObservedKey {
            file: (*file).to_owned(),
            fingerprint: (*fingerprint).to_owned(),
            line: (*entry).to_owned(),
        });
    }
    Ok(observed)
}

fn provenance_name(provenance: &KeyProvenance) -> String {
    match provenance {
        KeyProvenance::Unmanaged { refusal } => format!("unmanaged({refusal})"),
        other => other.as_str().to_owned(),
    }
}

/// `classify OBSERVED MINTED` — what each observed entry is, before anything
/// is proposed for removal. `MINTED` is a comma-separated fingerprint list.
fn classify(arguments: &[String]) -> ExitCode {
    let [observed, minted] = arguments else {
        eprintln!("usage: classify OBSERVED MINTED");
        return ExitCode::from(2);
    };
    let minted: Vec<String> = minted
        .split(',')
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    let outcome = read_observed(observed).map(|entries| {
        entries
            .iter()
            .map(|entry| {
                format!(
                    "{} {}",
                    provenance_name(&withdrawal::classify(entry, &minted)),
                    entry.fingerprint
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    });
    report(outcome)
}

/// `withdraw MACHINE VERIFIED_MACHINE OBSERVED KEEPING RETIRING`
///
/// `VERIFIED_MACHINE` is the machine the `PathVerified` was earned on. Passing
/// a different one is how the harness reaches the negative control without the
/// fixture ever fabricating a witness.
fn withdraw(arguments: &[String]) -> ExitCode {
    let [machine, verified_machine, observed, keeping, retiring] = arguments else {
        eprintln!("usage: withdraw MACHINE VERIFIED_MACHINE OBSERVED KEEPING RETIRING");
        return ExitCode::from(2);
    };
    let outcome = (|| {
        let observed = read_observed(observed)?;
        let retiring: Vec<String> = retiring
            .split(',')
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect();
        let verified = path_verified(verified_machine, keeping)?;
        let withdrawal = withdrawal::withdraw(&verified, machine, &observed, keeping, &retiring)
            .map_err(|refusal| format!("{refusal:?}"))?;
        let removed: Vec<&str> = withdrawal
            .removals()
            .iter()
            .map(|removal| removal.fingerprint.as_str())
            .collect();
        let kept: Vec<String> = withdrawal
            .kept()
            .iter()
            .map(|kept| format!("{}:{}", provenance_name(&kept.provenance), kept.fingerprint))
            .collect();
        Ok(format!(
            "WITHDRAWN machine={} removed={} kept={}",
            withdrawal.machine(),
            removed.join(","),
            kept.join(",")
        ))
    })();
    report(outcome)
}

/// A real [`PathVerified`], obtained the only way one can be obtained: #38's
/// preflight, #54's elevation, #36's approval, #39's mint and #39's
/// verification of a report the Auxiliary really produced.
fn path_verified(machine: &str, fingerprint: &str) -> Result<PathVerified, String> {
    let key = confirmed_host_key();
    let attempts = [EndpointAttempt {
        name: machine.to_owned(),
        confirmed_fingerprint: key.clone(),
        observed: Observation::Presented { fingerprint: key },
    }];
    let cleared = preflight::clear(&attempts).map_err(|refusal| format!("{refusal:?}"))?;
    let granted = elevation::elevated(0, b"0\n", b"")
        .map_err(|refusal| format!("ElevationRefused {refusal:?}"))?;
    let endpoint = DeclaredEndpoint {
        name: machine.to_owned(),
        port: 22,
        exposure: Exposure::Private,
        availability: Availability::NormallyOn,
        relay_candidate: false,
    };
    let proposal = placement::propose(Role::Agent, &endpoint, &compatible_machine(machine))
        .map_err(|refusal| format!("PlacementRefused {refusal:?}"))?;
    let approved = placement::approve(
        &proposal,
        &Approval {
            role: Role::Agent,
            endpoint: machine.to_owned(),
        },
    )
    .map_err(|refusal| format!("ApprovalRefused {refusal:?}"))?;
    let estate: Enrolled = identity::mint(&[Declared {
        machine: machine.to_owned(),
        fingerprint: fingerprint.to_owned(),
    }])
    .map_err(|refusal| format!("{refusal:?}"))?;
    let enrolment = enrolment_plan::authorize(&cleared, &granted, &[approved], &estate, machine)
        .map_err(|refusal| format!("{refusal:?}"))?;
    enrolment_plan::verify(
        &estate,
        &enrolment,
        &AuxiliaryReport {
            machine: machine.to_owned(),
            operation: DIAGNOSTIC_OPERATION.to_owned(),
            changed: false,
            consumed_sequence: 1,
            identity_fingerprint: fingerprint.to_owned(),
        },
    )
    .map_err(|refusal| format!("{refusal:?}"))
}

/// A machine every requirement of #36 is comfortably met by. What this binary
/// needs from the placement is a genuine approval, not a second opinion on the
/// audit.
fn compatible_machine(name: &str) -> ObservedMachine {
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

/// `supersede INSTALLED PROPOSED` — the approval epoch, decided before it is
/// installed.
fn supersede(arguments: &[String]) -> ExitCode {
    let [installed, proposed] = arguments else {
        eprintln!("usage: supersede INSTALLED PROPOSED");
        return ExitCode::from(2);
    };
    let outcome = (|| {
        let installed: u64 = installed
            .parse()
            .map_err(|_| "MalformedInput installed".to_owned())?;
        let proposed: u64 = proposed
            .parse()
            .map_err(|_| "MalformedInput proposed".to_owned())?;
        withdrawal::supersede(installed, proposed)
            .map(|rotation| {
                format!(
                    "SUPERSEDED epoch={} superseded={}",
                    rotation.epoch(),
                    rotation.superseded()
                )
            })
            .map_err(|refusal| format!("{refusal:?}"))
    })();
    report(outcome)
}

/// `unwind FILE` — the ledger of #38, judged by #38's own rules.
///
/// A cut replacement is undone by the very registry the installation uses, with
/// the same three provenances and the same refusal to remove what it did not
/// create. There is no second ledger in this palier.
fn run_unwind(arguments: &[String]) -> ExitCode {
    let [path] = arguments else {
        eprintln!("usage: unwind FILE");
        return ExitCode::from(2);
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        println!("REFUSED UnreadableInput");
        return ExitCode::from(1);
    };
    let mut ledger = Ledger::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split('\t').collect();
        let [kind, name, provenance] = fields[..] else {
            println!("REFUSED MalformedInput");
            return ExitCode::from(2);
        };
        if kind == "TRANSFER" {
            ledger.authority_transferred();
            continue;
        }
        let (Some(kind), Some(provenance)) = (item_kind(kind), provenance_of(provenance)) else {
            println!("REFUSED UnknownLedgerEntry");
            return ExitCode::from(2);
        };
        ledger.record(kind, name, provenance);
    }
    match ledger.unwind() {
        Unwind::Complete(removals) => {
            println!("COMPLETE {}", names(&removals));
            ExitCode::SUCCESS
        }
        Unwind::Incomplete { removals, unknown } => {
            println!(
                "INCOMPLETE removals={} unknown={}",
                names(&removals),
                unknown.join(",")
            );
            ExitCode::from(1)
        }
        Unwind::AfterTransfer => {
            println!("AFTER_TRANSFER");
            ExitCode::from(1)
        }
    }
}

fn names(
    removals: &[your_cloud_native_bootstrap_assistant::installation::rollback::Removal],
) -> String {
    removals
        .iter()
        .map(|removal| removal.name.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn item_kind(name: &str) -> Option<ItemKind> {
    Some(match name {
        "PACKAGE" => ItemKind::Package,
        "ACCOUNT" => ItemKind::Account,
        "DIRECTORY" => ItemKind::Directory,
        "FILE" => ItemKind::File,
        "UNIT_STATE" => ItemKind::UnitState,
        "CREDENTIAL_SOURCE" => ItemKind::CredentialSource,
        "ASSOCIATION" => ItemKind::Association,
        _ => return None,
    })
}

fn provenance_of(name: &str) -> Option<Provenance> {
    Some(match name {
        "CREATED" => Provenance::Created,
        "FOUND" => Provenance::Found,
        "UNKNOWN" => Provenance::Unknown,
        _ => return None,
    })
}

/// Every verdict leaves through here, so an acceptance and a refusal are never
/// printed in two different shapes by two different call sites.
fn report(outcome: Result<String, String>) -> ExitCode {
    match outcome {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(refusal) => {
            println!("REFUSED {refusal}");
            ExitCode::from(1)
        }
    }
}
