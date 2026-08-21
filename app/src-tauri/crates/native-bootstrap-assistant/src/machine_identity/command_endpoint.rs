//! The command endpoint sheet: where a command goes, and which machine may
//! answer it.
//!
//! This is the artefact that closed the last gap of the command trajectory. The
//! Controller holds one operational identity per machine and knows how to launch
//! the Auxiliary through it — but it knew no address, no port, no account and no
//! host key, and nothing wrote them anywhere. Every proof of the estate replaced
//! this by a fixture. This module is the real one.
//!
//! **It lives outside the inventory, and that is a frontier rather than a
//! filing choice.** The inventory is readable *and writable* by the App; an
//! address the App could rewrite would be an App that chooses where a
//! command goes. The App names a machine. It never names an endpoint.
//!
//! **The host key is pinned at enrolment, never learnt from the network.** It
//! comes from the observation step a human confirmed during the audit, exactly
//! as for the personal access. The client that authenticates later derives its
//! `known_hosts` from this sheet and from nothing else, so a first contact can
//! never become trust — and a machine whose key changed is a refusal before any
//! byte of a wrapper, not a question asked to nobody.
//!
//! **Nothing here writes a file.** The module renders the exact bytes the
//! Controller will read and judges a sheet read back off a real machine; the
//! placement is the enrolment engine's, exactly as `entry` renders and judges an
//! `authorized_keys` entry without ever installing one.

use crate::machine_identity::{account::AUXILIARY_ACCOUNT, entry::KEY_ALGORITHM};

/// Where the enrolment writes the sheets, root-owned, beside the machine
/// environment files and the credentials the unit loads.
pub const COMMAND_ENDPOINT_DIRECTORY: &str = "/etc/your-cloud/command-endpoints";

/// The one sheet version this palier reads. It is the same number the
/// Controller's own reader requires, written on both sides of one boundary.
pub const COMMAND_ENDPOINT_SCHEMA_VERSION: u8 = 1;

/// Longest sheet this palier reads back. A real one is a little over two
/// hundred bytes; anything longer is not a longer sheet, it is a file this
/// palier does not read.
pub const MAX_COMMAND_ENDPOINT_BYTES: usize = 4096;

/// Longest host a sheet may name. It is the length a DNS name may reach, and it
/// bounds a value that reaches OpenSSH as one argument.
pub const MAX_COMMAND_ENDPOINT_HOST_BYTES: usize = 253;

/// What an Ed25519 host key blob looks like in base64, without decoding it.
///
/// The blob is a fixed shape — a four-byte length, the algorithm name, a
/// four-byte length, thirty-two key bytes — so its first fifteen bytes are
/// constant, and base64 turns that constant into a constant twenty-character
/// prefix. Fifty-one bytes encode to exactly sixty-eight characters.
///
/// Checking the prefix and the length is stronger than decoding and measuring:
/// it holds the algorithm name itself, not merely a size that happens to match.
/// It also keeps this crate's dependency graph where the architecture wants it
/// — a helper whose graph is held to a plain GTK or Win32 program does not gain
/// a base64 decoder to look at twenty characters.
const HOST_KEY_BASE64_PREFIX: &str = "AAAAC3NzaC1lZDI1NTE5";
const HOST_KEY_BASE64_BYTES: usize = 68;

/// Why a sheet was refused. Each name is a different thing to fix, and
/// collapsing any two would make two different failures read the same in a
/// proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointRefusal {
    /// The file is absent. A machine with no sheet is a machine this Controller
    /// cannot reach, and that is not the same as one whose sheet is wrong.
    Absent,
    /// The document is not the closed form: unknown field, unreadable, or past
    /// the bound before it was parsed.
    Malformed,
    /// The sheet names another machine than the one it is filed under.
    ForeignMachine { named: String },
    /// The account is not the locked technical one this product created. A
    /// sheet naming another account would send a forced command to something
    /// nobody bounded.
    UnexpectedAccount { named: String },
    /// The host is empty, too long, or shaped like something an option list
    /// could read as more than a destination.
    UnusableHost,
    /// The port is outside what a port is.
    UnusablePort { named: u32 },
    /// The pinned key is not an Ed25519 host key blob. A pin that pins nothing
    /// is worse than no pin, because it reads like one.
    UnusableHostKey,
    /// The sheet is well formed and pins a *different* key than the one the
    /// human confirmed at the audit. This is the refusal that matters most: it
    /// is what a substituted machine looks like from here.
    HostKeyChanged { pinned: String, expected: String },
}

/// One machine's endpoint, checked. It cannot be built by naming its fields:
/// [`judge`] is the only function that returns one, so a sheet nobody held
/// against the audit cannot be handed downstream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandEndpoint {
    machine: String,
    host: String,
    port: u16,
    host_key: String,
}

impl CommandEndpoint {
    pub fn machine(&self) -> &str {
        &self.machine
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The base64 key blob, as a `known_hosts` line carries it. The public half
    /// of a host key is public material; it is never a secret.
    pub fn host_key(&self) -> &str {
        &self.host_key
    }

    /// Where this machine's sheet lives, named by the machine and by nothing a
    /// caller composed.
    pub fn path(&self) -> String {
        format!("{COMMAND_ENDPOINT_DIRECTORY}/{}.json", self.machine)
    }
}

/// Renders the exact bytes the Controller will read.
///
/// The account is not a parameter: it is the one locked technical account this
/// product created, taken from the module that owns it. A sheet that could name
/// another account would be a sheet that could aim a forced command somewhere
/// nobody bounded — and the refusal of that would have to be written somewhere
/// else, which is exactly the sort of thing this product avoids by not making
/// it expressible.
///
/// The rendering is deliberately plain and stable: the fields in one order, no
/// spacing, so that what is written and what is read back can be compared byte
/// for byte rather than parsed twice.
pub fn render(machine: &str, host: &str, port: u16, host_key: &str) -> Option<String> {
    let checked = judge_fields(
        machine,
        machine,
        host,
        u32::from(port),
        AUXILIARY_ACCOUNT,
        host_key,
    )
    .ok()?;
    Some(format!(
        concat!(
            "{{\"schema_version\":{},\"machine_id\":\"{}\",\"host\":\"{}\",",
            "\"port\":{},\"account\":\"{}\",\"host_key\":\"{}\"}}"
        ),
        COMMAND_ENDPOINT_SCHEMA_VERSION,
        checked.machine,
        checked.host,
        checked.port,
        AUXILIARY_ACCOUNT,
        checked.host_key,
    ))
}

/// The `known_hosts` line this sheet derives to, in the bracketed form the
/// Controller writes at every launch.
///
/// It exists here so that what the enrolment pins and what the launch will dial
/// are one rendering rather than two: a second spelling of this line is a second
/// place where a port could be forgotten.
pub fn known_hosts_line(endpoint: &CommandEndpoint) -> String {
    format!(
        "[{}]:{} {KEY_ALGORITHM} {}\n",
        endpoint.host, endpoint.port, endpoint.host_key
    )
}

/// Reads a sheet back and holds it against the machine it is filed under and
/// against the host key the human confirmed at the audit.
///
/// `expected_host_key` is the audit's answer, and it is required rather than
/// optional: judging a sheet without it would be judging its shape, and shape
/// is not what a substituted machine gets wrong.
pub fn judge(
    machine: &str,
    document: Option<&str>,
    expected_host_key: &str,
) -> Result<CommandEndpoint, EndpointRefusal> {
    let Some(document) = document else {
        return Err(EndpointRefusal::Absent);
    };
    if document.len() > MAX_COMMAND_ENDPOINT_BYTES {
        return Err(EndpointRefusal::Malformed);
    }
    let parsed = read_sheet(document)?;
    let endpoint = judge_fields(
        machine,
        &parsed.machine_id,
        &parsed.host,
        parsed.port,
        &parsed.account,
        &parsed.host_key,
    )?;
    // The pin is held against the audit last, so a sheet that is wrong in an
    // ordinary way is refused for that ordinary reason rather than reported as
    // a substituted machine.
    if endpoint.host_key != expected_host_key {
        return Err(EndpointRefusal::HostKeyChanged {
            pinned: endpoint.host_key,
            expected: expected_host_key.to_owned(),
        });
    }
    Ok(endpoint)
}

struct SheetFields {
    machine_id: String,
    host: String,
    port: u32,
    account: String,
    host_key: String,
}

/// Reads the closed form, and refuses everything that is not exactly it.
///
/// The field set is compared rather than merely looked up: a document carrying
/// one this palier does not read is not a richer sheet, it is a document
/// written by something else. The comparison is done here rather than by a
/// derive so that this crate keeps the dependency graph the architecture holds
/// it to.
fn read_sheet(document: &str) -> Result<SheetFields, EndpointRefusal> {
    const FIELDS: [&str; 6] = [
        "schema_version",
        "machine_id",
        "host",
        "port",
        "account",
        "host_key",
    ];
    let value: serde_json::Value =
        serde_json::from_str(document).map_err(|_| EndpointRefusal::Malformed)?;
    let object = value.as_object().ok_or(EndpointRefusal::Malformed)?;
    if object.len() != FIELDS.len() || !FIELDS.iter().all(|field| object.contains_key(*field)) {
        return Err(EndpointRefusal::Malformed);
    }
    let string = |field: &str| -> Result<String, EndpointRefusal> {
        object
            .get(field)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or(EndpointRefusal::Malformed)
    };
    let schema_version = object
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or(EndpointRefusal::Malformed)?;
    if schema_version != u64::from(COMMAND_ENDPOINT_SCHEMA_VERSION) {
        return Err(EndpointRefusal::Malformed);
    }
    let port = object
        .get("port")
        .and_then(serde_json::Value::as_u64)
        .ok_or(EndpointRefusal::Malformed)?;
    Ok(SheetFields {
        machine_id: string("machine_id")?,
        host: string("host")?,
        port: u32::try_from(port).map_err(|_| EndpointRefusal::Malformed)?,
        account: string("account")?,
        host_key: string("host_key")?,
    })
}

fn judge_fields(
    filed_under: &str,
    machine_id: &str,
    host: &str,
    port: u32,
    account: &str,
    host_key: &str,
) -> Result<CommandEndpoint, EndpointRefusal> {
    if machine_id != filed_under || machine_id.is_empty() {
        return Err(EndpointRefusal::ForeignMachine {
            named: machine_id.to_owned(),
        });
    }
    if account != AUXILIARY_ACCOUNT {
        return Err(EndpointRefusal::UnexpectedAccount {
            named: account.to_owned(),
        });
    }
    if !usable_host(host) {
        return Err(EndpointRefusal::UnusableHost);
    }
    if port == 0 || port > u32::from(u16::MAX) {
        return Err(EndpointRefusal::UnusablePort { named: port });
    }
    if !usable_host_key(host_key) {
        return Err(EndpointRefusal::UnusableHostKey);
    }
    Ok(CommandEndpoint {
        machine: machine_id.to_owned(),
        host: host.to_owned(),
        port: port as u16,
        host_key: host_key.to_owned(),
    })
}

/// A host is a literal address or a name, and nothing an option list could read
/// as more than a destination. The leading dash is refused explicitly: a value
/// starting with one reaches a client as an option however carefully it is
/// quoted.
fn usable_host(host: &str) -> bool {
    if host.is_empty() || host.len() > MAX_COMMAND_ENDPOINT_HOST_BYTES || host.starts_with('-') {
        return false;
    }
    host.chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | ':'))
}

/// The one algorithm a pinned host key is read in, held to its own length. The
/// Controller writes these `known_hosts` lines itself; a second accepted
/// algorithm would only be a second thing to get wrong.
fn usable_host_key(host_key: &str) -> bool {
    host_key.len() == HOST_KEY_BASE64_BYTES
        && host_key.starts_with(HOST_KEY_BASE64_PREFIX)
        && host_key.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '=')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MACHINE: &str = "lab-machine-1";

    /// A well-formed blob: the constant prefix the algorithm name encodes to,
    /// then the key material, to the exact length one encodes to.
    fn host_key() -> String {
        format!("{HOST_KEY_BASE64_PREFIX}AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH")
    }

    #[test]
    fn a_sheet_is_rendered_and_read_back_as_the_same_endpoint() {
        let key = host_key();
        let document = render(MACHINE, "192.0.2.10", 22, &key).expect("a well-formed sheet");
        let endpoint = judge(MACHINE, Some(&document), &key).expect("its own sheet");

        assert_eq!(endpoint.machine(), MACHINE);
        assert_eq!(endpoint.host(), "192.0.2.10");
        assert_eq!(endpoint.port(), 22);
        assert_eq!(endpoint.host_key(), key);
        assert_eq!(
            endpoint.path(),
            "/etc/your-cloud/command-endpoints/lab-machine-1.json"
        );
        // The account is not a field a caller chose: it is the one locked
        // technical account, and the rendering names it from its own module.
        assert!(document.contains(AUXILIARY_ACCOUNT));
        // And the line the launch will derive is this one, spelled once.
        assert_eq!(
            known_hosts_line(&endpoint),
            format!("[192.0.2.10]:22 {KEY_ALGORITHM} {key}\n")
        );
    }

    /// The refusal that matters most: a machine whose key changed since the
    /// audit. It is named apart from every other refusal, because that is what
    /// a substituted machine looks like from here, and a proof has to be able
    /// to tell it from a misconfiguration.
    #[test]
    fn a_key_that_changed_since_the_audit_is_its_own_refusal() {
        let audited = host_key();
        let substituted =
            format!("{HOST_KEY_BASE64_PREFIX}AAAAIAkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJ");
        let document = render(MACHINE, "192.0.2.10", 22, &substituted).expect("a sheet");

        match judge(MACHINE, Some(&document), &audited) {
            Err(EndpointRefusal::HostKeyChanged { pinned, expected }) => {
                assert_eq!(pinned, substituted);
                assert_eq!(expected, audited);
            }
            other => panic!("a substituted machine was not named as such: {other:?}"),
        }
    }

    /// A machine with no sheet is not a machine whose sheet is wrong.
    #[test]
    fn an_absent_sheet_is_its_own_refusal() {
        assert_eq!(
            judge(MACHINE, None, &host_key()),
            Err(EndpointRefusal::Absent)
        );
    }

    /// Every other way a sheet can be wrong, each by its own name.
    #[test]
    fn every_other_refusal_is_named_apart() {
        let key = host_key();
        let sheet = |machine: &str, host: &str, port: u32, account: &str, host_key: &str| {
            format!(
                concat!(
                    "{{\"schema_version\":1,\"machine_id\":\"{}\",\"host\":\"{}\",",
                    "\"port\":{},\"account\":\"{}\",\"host_key\":\"{}\"}}"
                ),
                machine, host, port, account, host_key
            )
        };

        assert!(matches!(
            judge(
                MACHINE,
                Some(&sheet(
                    "lab-machine-2",
                    "192.0.2.10",
                    22,
                    AUXILIARY_ACCOUNT,
                    &key
                )),
                &key
            ),
            Err(EndpointRefusal::ForeignMachine { .. })
        ));
        assert!(matches!(
            judge(
                MACHINE,
                Some(&sheet(MACHINE, "192.0.2.10", 22, "root", &key)),
                &key
            ),
            Err(EndpointRefusal::UnexpectedAccount { .. })
        ));
        // A host shaped like an option, and one carrying a space: both reach a
        // client as one argument, and neither is a destination.
        for hostile in ["-oProxyCommand=touch /tmp/x", "192.0.2.10 evil", ""] {
            assert_eq!(
                judge(
                    MACHINE,
                    Some(&sheet(MACHINE, hostile, 22, AUXILIARY_ACCOUNT, &key)),
                    &key
                ),
                Err(EndpointRefusal::UnusableHost)
            );
        }
        for hostile in [0_u32, 65_536] {
            assert!(matches!(
                judge(
                    MACHINE,
                    Some(&sheet(
                        MACHINE,
                        "192.0.2.10",
                        hostile,
                        AUXILIARY_ACCOUNT,
                        &key
                    )),
                    &key
                ),
                Err(EndpointRefusal::UnusablePort { .. })
            ));
        }
        // A pin that is not an Ed25519 host key blob pins nothing.
        for hostile in ["pas du base64 !", "AAAA", "", &"A".repeat(68)] {
            assert_eq!(
                judge(
                    MACHINE,
                    Some(&sheet(
                        MACHINE,
                        "192.0.2.10",
                        22,
                        AUXILIARY_ACCOUNT,
                        hostile
                    )),
                    &key
                ),
                Err(EndpointRefusal::UnusableHostKey)
            );
        }
        // An unknown field is not a richer sheet; it is a document this palier
        // does not read.
        let widened = sheet(MACHINE, "192.0.2.10", 22, AUXILIARY_ACCOUNT, &key).replace(
            "{\"schema_version\"",
            "{\"surprise\":true,\"schema_version\"",
        );
        assert_eq!(
            judge(MACHINE, Some(&widened), &key),
            Err(EndpointRefusal::Malformed)
        );
        // And a document past its bound is refused before it is parsed.
        let long = format!(
            "{}{}",
            sheet(MACHINE, "192.0.2.10", 22, AUXILIARY_ACCOUNT, &key),
            " ".repeat(MAX_COMMAND_ENDPOINT_BYTES)
        );
        assert_eq!(
            judge(MACHINE, Some(&long), &key),
            Err(EndpointRefusal::Malformed)
        );
    }

    /// Rendering refuses what judging refuses: a sheet this module would not
    /// accept is a sheet it never writes.
    #[test]
    fn rendering_refuses_what_judging_refuses() {
        assert!(render(MACHINE, "-oProxyCommand=x", 22, &host_key()).is_none());
        assert!(render(MACHINE, "192.0.2.10", 0, &host_key()).is_none());
        assert!(render(MACHINE, "192.0.2.10", 22, "pas une clé").is_none());
        assert!(render("", "192.0.2.10", 22, &host_key()).is_none());
    }
}
