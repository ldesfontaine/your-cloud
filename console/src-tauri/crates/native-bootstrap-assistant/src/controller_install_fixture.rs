//! The LAB's way of reaching the installation gates, and nothing more.
//!
//! The decisions of `installation` are exercised by their own unit tests. What
//! this fixture adds is the only thing those tests cannot give: the *same*
//! functions, in a real process, judging a real `.deb` that a real `dpkg` is
//! about to install on a real machine. Without it the LAB could only prove that
//! a shell script compared two digests, which would say nothing about the code
//! that ships.
//!
//! It is a fixture and it stays one. It is built behind its own feature, it is
//! never part of the Console's `externalBin`, it performs no installation and it
//! holds no privilege: it reads files, calls one gate and prints one verdict.
//! Every refusal is printed by its own name so the harness asserts the reason
//! rather than the exit code.

use std::process::ExitCode;
use your_cloud_native_bootstrap_assistant::installation::{
    bundle,
    preflight::{self, EndpointAttempt, Observation},
    rollback::{ItemKind, Ledger, Provenance, Unwind},
};

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = arguments.first().map(String::as_str) else {
        eprintln!("usage: verify-bundle | preflight | unwind");
        return ExitCode::from(2);
    };
    match command {
        "verify-bundle" => verify_bundle(&arguments[1..]),
        "preflight" => run_preflight(&arguments[1..]),
        "unwind" => run_unwind(&arguments[1..]),
        _ => {
            eprintln!("unknown command {command}");
            ExitCode::from(2)
        }
    }
}

/// `verify-bundle ANCHOR MANIFEST SIGNATURE VERSION ARTIFACT`
///
/// The anchor and the signature are raw bytes on disk; the artefact is the very
/// `.deb` the next step would hand to `dpkg`.
fn verify_bundle(arguments: &[String]) -> ExitCode {
    let [anchor, manifest, signature, version, artifact] = arguments else {
        eprintln!("usage: verify-bundle ANCHOR MANIFEST SIGNATURE VERSION ARTIFACT");
        return ExitCode::from(2);
    };
    let (Ok(anchor), Ok(manifest), Ok(signature), Ok(artifact)) = (
        std::fs::read(anchor),
        std::fs::read(manifest),
        std::fs::read(signature),
        std::fs::read(artifact),
    ) else {
        eprintln!("REFUSED UnreadableInput");
        return ExitCode::from(1);
    };
    match bundle::verify(&anchor, &manifest, &signature, version, &artifact) {
        Ok(verified) => {
            println!(
                "VERIFIED version={} target={} size={} sha256={}",
                verified.version(),
                verified.target(),
                verified.size(),
                verified.sha256()
            );
            ExitCode::SUCCESS
        }
        Err(refusal) => {
            println!("REFUSED {refusal:?}");
            ExitCode::from(1)
        }
    }
}

/// `preflight FILE`, one endpoint per line:
/// `name<TAB>confirmed_fingerprint<TAB>presented_fingerprint|UNREACHABLE|NO_ANSWER`
fn run_preflight(arguments: &[String]) -> ExitCode {
    let [path] = arguments else {
        eprintln!("usage: preflight FILE");
        return ExitCode::from(2);
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        eprintln!("REFUSED UnreadableInput");
        return ExitCode::from(1);
    };
    let mut attempts = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split('\t').collect();
        let [name, confirmed, observed] = fields[..] else {
            eprintln!("REFUSED MalformedInput");
            return ExitCode::from(2);
        };
        attempts.push(EndpointAttempt {
            name: name.to_owned(),
            confirmed_fingerprint: confirmed.to_owned(),
            observed: match observed {
                "UNREACHABLE" => Observation::Unreachable,
                "NO_ANSWER" => Observation::NoAnswer,
                fingerprint => Observation::Presented {
                    fingerprint: fingerprint.to_owned(),
                },
            },
        });
    }
    match preflight::clear(&attempts) {
        Ok(cleared) => {
            println!("CLEARED {}", cleared.endpoints().join(","));
            ExitCode::SUCCESS
        }
        Err(refusal) => {
            println!("REFUSED {refusal:?}");
            ExitCode::from(1)
        }
    }
}

/// `unwind FILE`, one recorded item per line: `kind<TAB>name<TAB>provenance`.
///
/// It is what lets the harness show, on the machine itself, that a failure at
/// step *n* proposes exactly the removals of steps 1..n and never one more.
fn run_unwind(arguments: &[String]) -> ExitCode {
    let [path] = arguments else {
        eprintln!("usage: unwind FILE");
        return ExitCode::from(2);
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        eprintln!("REFUSED UnreadableInput");
        return ExitCode::from(1);
    };
    let mut ledger = Ledger::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split('\t').collect();
        let [kind, name, provenance] = fields[..] else {
            eprintln!("REFUSED MalformedInput");
            return ExitCode::from(2);
        };
        if kind == "TRANSFER" {
            ledger.authority_transferred();
            continue;
        }
        let Some(kind) = item_kind(kind) else {
            eprintln!("REFUSED UnknownKind");
            return ExitCode::from(2);
        };
        let Some(provenance) = provenance_of(provenance) else {
            eprintln!("REFUSED UnknownProvenance");
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
