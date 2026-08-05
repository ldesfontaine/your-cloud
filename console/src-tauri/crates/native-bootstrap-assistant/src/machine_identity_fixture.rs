//! The LAB's way of reaching the enrolment gates, and nothing more.
//!
//! The decisions of `machine_identity` are exercised by their own unit tests.
//! What this fixture adds is the only thing those tests cannot give: the *same*
//! functions, in a real process, judging the `authorized_keys` file, the
//! `sudoers` rule, the account and the `stat` chain that a real `sshd` and a
//! real `sudo` are about to decide on. Without it the LAB could only prove that
//! a shell script grepped a file, which would say nothing about the code that
//! ships.
//!
//! It is a fixture and it stays one. It is built behind its own feature, it is
//! never part of the Console's `externalBin`, it enrols nothing and it holds no
//! privilege: it reads files, calls one gate and prints one verdict. Every
//! refusal is printed by its own name so the harness asserts the reason rather
//! than the exit code.
//!
//! **The observed machine of the placement is a fixed compatible fixture.**
//! What this binary needs from #36 is a genuine `ApprovedPlacement`, built the
//! only way one can be built; whether a given machine's memory suffices is
//! #36's own suite's question, and re-deciding it here would give that property
//! a second home.

use std::process::ExitCode;
use your_cloud_native_bootstrap_assistant::installation::preflight::{
    self, EndpointAttempt, Observation,
};
use your_cloud_native_bootstrap_assistant::installation::rollback::{
    ItemKind, Ledger, Provenance, Unwind,
};
use your_cloud_native_bootstrap_assistant::machine_identity::account::{self, ObservedAccount};
use your_cloud_native_bootstrap_assistant::machine_identity::custody::{
    self, ObservedPath, PathKind,
};
use your_cloud_native_bootstrap_assistant::machine_identity::elevation_rule;
use your_cloud_native_bootstrap_assistant::machine_identity::entry;
use your_cloud_native_bootstrap_assistant::machine_identity::identity::{self, Declared, Enrolled};
use your_cloud_native_bootstrap_assistant::machine_identity::plan::{
    self, AuxiliaryReport, Enrolment, PathVerified,
};
use your_cloud_native_bootstrap_assistant::personal_access::audit::{
    Architecture, CgroupHierarchy, Distribution, InitSystem, Installation, Observed,
    ObservedMachine, Role, SUPPORTED_DISTRIBUTION_ID, SUPPORTED_DISTRIBUTION_VERSION,
};
use your_cloud_native_bootstrap_assistant::personal_access::elevation;
use your_cloud_native_bootstrap_assistant::personal_access::placement::{
    self, Approval, ApprovedPlacement, Availability, DeclaredEndpoint, Exposure,
};

const USAGE: &str = "usage: steps | admits | enrol | verify | activate | entry | render-entry \
                     | elevation | render-elevation | account | custody | unwind";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = arguments.first().map(String::as_str) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let rest = &arguments[1..];
    match command {
        "steps" => steps(),
        "admits" => admits(rest),
        "enrol" => enrol(rest),
        "verify" => verify(rest),
        "activate" => activate(rest),
        "entry" => judge_entry(rest),
        "render-entry" => render_entry(rest),
        "elevation" => judge_elevation(rest),
        "render-elevation" => {
            print!("{}", elevation_rule::render());
            ExitCode::SUCCESS
        }
        "account" => judge_account(rest),
        "custody" => judge_custody(rest),
        "unwind" => run_unwind(rest),
        _ => {
            eprintln!("unknown command {command}");
            ExitCode::from(2)
        }
    }
}

/// `steps` — the fixed sequence, in order, so the harness asserts the ordering
/// against the product rather than against a list it wrote itself.
fn steps() -> ExitCode {
    let names: Vec<&str> = plan::STEPS.iter().map(|step| step.as_str()).collect();
    println!("{}", names.join(","));
    ExitCode::SUCCESS
}

/// One perimeter, as the harness writes it: one directive per line, fields
/// separated by tabs.
///
/// ```text
/// machine    <name>                          the machine being enrolled
/// identity   <machine>  <SHA256:…>           one minted identity
/// cleared    <machine>                       one endpoint the preflight cleared
/// placement  <role>     <machine>            one approved placement
/// report     <machine>  <operation>  <changed>  <sequence>  <SHA256:…>
/// ```
struct Perimeter {
    machine: String,
    identities: Vec<Declared>,
    cleared: Vec<String>,
    placements: Vec<(Role, String)>,
    report: Option<AuxiliaryReport>,
}

fn read_perimeter(path: &str) -> Result<Perimeter, String> {
    let text = std::fs::read_to_string(path).map_err(|error| format!("UnreadableInput {error}"))?;
    let mut perimeter = Perimeter {
        machine: String::new(),
        identities: Vec::new(),
        cleared: Vec::new(),
        placements: Vec::new(),
        report: None,
    };
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split('\t').collect();
        match fields.as_slice() {
            ["machine", name] => perimeter.machine = (*name).to_owned(),
            ["identity", machine, fingerprint] => perimeter.identities.push(Declared {
                machine: (*machine).to_owned(),
                fingerprint: (*fingerprint).to_owned(),
            }),
            ["cleared", machine] => perimeter.cleared.push((*machine).to_owned()),
            ["placement", role, machine] => {
                perimeter
                    .placements
                    .push((parse_role(role)?, (*machine).to_owned()));
            }
            ["report", machine, operation, changed, sequence, fingerprint] => {
                perimeter.report = Some(AuxiliaryReport {
                    machine: (*machine).to_owned(),
                    operation: (*operation).to_owned(),
                    changed: *changed == "true",
                    consumed_sequence: sequence
                        .parse()
                        .map_err(|_| "MalformedInput sequence".to_owned())?,
                    identity_fingerprint: (*fingerprint).to_owned(),
                });
            }
            _ => return Err(format!("MalformedInput {line}")),
        }
    }
    Ok(perimeter)
}

fn parse_role(name: &str) -> Result<Role, String> {
    [Role::Controller, Role::Relay, Role::Agent, Role::Auxiliary]
        .into_iter()
        .find(|role| role.as_str() == name)
        .ok_or_else(|| format!("MalformedInput role {name}"))
}

/// A machine every requirement of #36 is comfortably met by. See the module
/// header: what this fixture needs is a genuine approval, not a second opinion
/// on the audit.
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

fn approved(role: Role, machine: &str) -> Result<ApprovedPlacement, String> {
    let endpoint = DeclaredEndpoint {
        name: machine.to_owned(),
        port: 22,
        exposure: Exposure::Private,
        availability: Availability::NormallyOn,
        relay_candidate: role == Role::Relay,
    };
    let proposal = placement::propose(role, &endpoint, &compatible_machine(machine))
        .map_err(|refusal| format!("PlacementRefused {refusal:?}"))?;
    placement::approve(
        &proposal,
        &Approval {
            role,
            endpoint: endpoint.name.clone(),
        },
    )
    .map_err(|refusal| format!("ApprovalRefused {refusal:?}"))
}

fn estate(perimeter: &Perimeter) -> Result<Enrolled, String> {
    identity::mint(&perimeter.identities).map_err(|refusal| format!("{refusal:?}"))
}

fn enrolment(perimeter: &Perimeter) -> Result<Enrolment, String> {
    let attempts: Vec<EndpointAttempt> = perimeter
        .cleared
        .iter()
        .map(|name| EndpointAttempt {
            name: name.clone(),
            confirmed_fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            observed: Observation::Presented {
                fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            },
        })
        .collect();
    let cleared = preflight::clear(&attempts).map_err(|refusal| format!("{refusal:?}"))?;
    // A real `Elevation`, obtained the only way one can be obtained.
    let granted = elevation::elevated(0, b"0\n", b"")
        .map_err(|refusal| format!("ElevationRefused {refusal:?}"))?;
    let mut placements = Vec::new();
    for (role, machine) in &perimeter.placements {
        placements.push(approved(*role, machine)?);
    }
    plan::authorize(
        &cleared,
        &granted,
        &placements,
        &estate(perimeter)?,
        &perimeter.machine,
    )
    .map_err(|refusal| format!("{refusal:?}"))
}

fn verified(perimeter: &Perimeter) -> Result<PathVerified, String> {
    let report = perimeter
        .report
        .clone()
        .ok_or_else(|| "MalformedInput report".to_owned())?;
    plan::verify(&estate(perimeter)?, &enrolment(perimeter)?, &report)
        .map_err(|refusal| format!("{refusal:?}"))
}

/// `admits PERIMETER MACHINE FINGERPRINT` — the crown decision, on its own.
fn admits(arguments: &[String]) -> ExitCode {
    let [path, machine, presented] = arguments else {
        eprintln!("usage: admits PERIMETER MACHINE FINGERPRINT");
        return ExitCode::from(2);
    };
    let outcome = read_perimeter(path)
        .and_then(|perimeter| estate(&perimeter))
        .and_then(|estate| {
            estate
                .admits(machine, presented)
                .map(|minted| {
                    format!(
                        "ADMITTED machine={} key={}",
                        minted.machine(),
                        minted.fingerprint()
                    )
                })
                .map_err(|refusal| format!("{refusal:?}"))
        });
    report(outcome)
}

/// `enrol PERIMETER`
fn enrol(arguments: &[String]) -> ExitCode {
    let [path] = arguments else {
        eprintln!("usage: enrol PERIMETER");
        return ExitCode::from(2);
    };
    let outcome = read_perimeter(path).and_then(|perimeter| {
        enrolment(&perimeter).map(|enrolment| {
            let roles: Vec<&str> = enrolment.roles().iter().map(|role| role.as_str()).collect();
            format!(
                "ENROLLED machine={} key={} roles={}",
                enrolment.machine(),
                enrolment.fingerprint(),
                roles.join(",")
            )
        })
    });
    report(outcome)
}

/// `verify PERIMETER`
fn verify(arguments: &[String]) -> ExitCode {
    let [path] = arguments else {
        eprintln!("usage: verify PERIMETER");
        return ExitCode::from(2);
    };
    let outcome = read_perimeter(path).and_then(|perimeter| {
        verified(&perimeter).map(|verified| format!("VERIFIED machine={}", verified.machine()))
    });
    report(outcome)
}

/// `activate PERIMETER ROLE`
fn activate(arguments: &[String]) -> ExitCode {
    let [path, role] = arguments else {
        eprintln!("usage: activate PERIMETER ROLE");
        return ExitCode::from(2);
    };
    let outcome = read_perimeter(path).and_then(|perimeter| {
        let role = parse_role(role)?;
        let enrolment = enrolment(&perimeter)?;
        let verified = verified(&perimeter)?;
        plan::activate(&enrolment, &verified, role)
            .map(|activation| {
                format!(
                    "ACTIVATED machine={} unit={}",
                    activation.machine(),
                    activation.unit()
                )
            })
            .map_err(|refusal| format!("{refusal:?}"))
    });
    report(outcome)
}

/// `entry FILE` — the `authorized_keys` file as it stands on the machine.
fn judge_entry(arguments: &[String]) -> ExitCode {
    let [path] = arguments else {
        eprintln!("usage: entry FILE");
        return ExitCode::from(2);
    };
    let outcome = std::fs::read_to_string(path)
        .map_err(|error| format!("UnreadableInput {error}"))
        .and_then(|file| {
            entry::judge(&file)
                .map(|bounded| format!("BOUNDED algorithm={}", bounded.algorithm()))
                .map_err(|refusal| format!("{refusal:?}"))
        });
    report(outcome)
}

/// `render-entry ALGORITHM KEY` — the entry the palier installs.
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

/// `elevation FILE` — the `sudoers` drop-in as it stands on the machine.
fn judge_elevation(arguments: &[String]) -> ExitCode {
    let [path] = arguments else {
        eprintln!("usage: elevation FILE");
        return ExitCode::from(2);
    };
    let outcome = std::fs::read_to_string(path)
        .map_err(|error| format!("UnreadableInput {error}"))
        .and_then(|file| {
            elevation_rule::judge(&file)
                .map(|bounded| {
                    format!(
                        "BOUNDED account={} command={}",
                        bounded.account(),
                        bounded.command()
                    )
                })
                .map_err(|refusal| format!("{refusal:?}"))
        });
    report(outcome)
}

/// `account FILE`, one line:
/// `name<TAB>uid<TAB>gid<TAB>shell<TAB>home<TAB>password_field[<TAB>groups]`.
///
/// The password field travels verbatim. It is a shadow field of a synthetic
/// locked account, so it carries no secret by construction — and the gate has
/// to see the real one to tell a locked account from a locked hash.
fn judge_account(arguments: &[String]) -> ExitCode {
    let [path] = arguments else {
        eprintln!("usage: account FILE");
        return ExitCode::from(2);
    };
    let outcome = std::fs::read_to_string(path)
        .map_err(|error| format!("UnreadableInput {error}"))
        .and_then(|text| {
            let observed = parse_account(text.lines().next().unwrap_or_default())?;
            account::judge(&observed)
                .map(|locked| format!("LOCKED account={} uid={}", locked.name(), locked.uid()))
                .map_err(|refusal| format!("{refusal:?}"))
        });
    report(outcome)
}

fn parse_account(line: &str) -> Result<ObservedAccount, String> {
    let fields: Vec<&str> = line.split('\t').collect();
    let [name, uid, gid, shell, home, password, ..] = fields.as_slice() else {
        return Err(format!("MalformedInput {line}"));
    };
    let groups: Vec<String> = fields
        .get(6)
        .map(|value| {
            value
                .split(',')
                .filter(|group| !group.trim().is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok(ObservedAccount {
        name: (*name).to_owned(),
        uid: uid.parse().map_err(|_| "MalformedInput uid".to_owned())?,
        gid: gid.parse().map_err(|_| "MalformedInput gid".to_owned())?,
        shell: (*shell).to_owned(),
        home: (*home).to_owned(),
        password_field: (*password).to_owned(),
        supplementary_groups: groups,
    })
}

/// `custody CHAIN ACCOUNT` — the `stat` chain, and the account file above.
///
/// One chain line per path: `path<TAB>uid<TAB>gid<TAB>mode<TAB>DIRECTORY|FILE|OTHER`.
fn judge_custody(arguments: &[String]) -> ExitCode {
    let [chain_path, account_path] = arguments else {
        eprintln!("usage: custody CHAIN ACCOUNT");
        return ExitCode::from(2);
    };
    let outcome = (|| {
        let account_text = std::fs::read_to_string(account_path)
            .map_err(|error| format!("UnreadableInput {error}"))?;
        let observed = parse_account(account_text.lines().next().unwrap_or_default())?;
        let locked = account::judge(&observed).map_err(|refusal| format!("{refusal:?}"))?;

        let chain_text = std::fs::read_to_string(chain_path)
            .map_err(|error| format!("UnreadableInput {error}"))?;
        let mut chain = Vec::new();
        for line in chain_text.lines().filter(|line| !line.trim().is_empty()) {
            let fields: Vec<&str> = line.split('\t').collect();
            let [path, uid, gid, mode, kind] = fields.as_slice() else {
                return Err(format!("MalformedInput {line}"));
            };
            chain.push(ObservedPath {
                path: (*path).to_owned(),
                uid: uid.parse().map_err(|_| "MalformedInput uid".to_owned())?,
                gid: gid.parse().map_err(|_| "MalformedInput gid".to_owned())?,
                mode: u32::from_str_radix(mode, 8).map_err(|_| "MalformedInput mode".to_owned())?,
                kind: match *kind {
                    "DIRECTORY" => PathKind::Directory,
                    "FILE" => PathKind::File,
                    _ => PathKind::Other,
                },
            });
        }
        custody::judge(&chain, &locked)
            .map(|custody| format!("CUSTODY leaf={}", custody.leaf()))
            .map_err(|refusal| format!("{refusal:?}"))
    })();
    report(outcome)
}

/// `unwind FILE` — the ledger of #38, judged by #38's own rules.
///
/// One recorded item per line: `kind<TAB>name<TAB>provenance`. It is the same
/// registry the Controller installation uses, and the same three provenances:
/// an interrupted enrolment is undone by the rules that palier already fixed.
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
