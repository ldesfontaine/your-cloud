//! The `authorized_keys` entry: one forced command, and every capability it
//! takes away.
//!
//! An entry is not a place to be generous. Everything OpenSSH offers by default
//! — a shell, a terminal, SFTP, a user `rc` file, X11, an environment, port and
//! agent forwarding — is a capability the Controller's identity has no use for
//! and an attacker holding that key would. This module renders the one entry
//! the palier installs and, more importantly, judges an entry read back off a
//! real machine.
//!
//! **The option list is positive.** An option that is neither the forced
//! command nor one of [`REQUIRED_OPTIONS`] is refused by name. A negative list
//! would be a list of the capabilities somebody thought of, and `authorized_keys`
//! grows options; `permitopen=`, `environment=` and `tunnel=` are refused here
//! because they are not on the list, not because they were enumerated.
//!
//! **`restrict` is written *and* every refusal is named.** `restrict` means
//! "everything, including options added later", which is exactly the guarantee
//! wanted — but what "everything" covered was decided when that `sshd` was
//! built. Naming `no-pty`, `no-user-rc`, `no-X11-forwarding`,
//! `no-agent-forwarding` and `no-port-forwarding` beside it makes the entry say
//! the same thing on an `sshd` whose `restrict` is older than this file.
//!
//! **The forced command is one constant, compared for equality.** There is no
//! parsing of arguments, no allowance for a prefix and no place a
//! `$SSH_ORIGINAL_COMMAND` could be appended: an entry whose command is not
//! byte for byte [`forced_command`] is refused. That is what makes "no free
//! argument" a property of a comparison rather than of a sanitiser.

use crate::installation::plan::PACKAGE_BINARY;

/// Where `sudo` lives on the distribution this palier supports. The forced
/// command names it absolutely, like everything else in the entry: a relative
/// name would be resolved by a `PATH` the entry does not control.
pub const SUDO_BINARY: &str = "/usr/bin/sudo";

/// The subject the Auxiliary is invoked with, and the only one. It is the same
/// pair the elevation rule authorises, taken from here rather than repeated, so
/// the two can never drift into authorising different invocations.
pub const AUXILIARY_SUBJECT: [&str; 2] = ["auxiliary", "approve"];

/// Every restriction the entry names beside `restrict`.
pub const REQUIRED_OPTIONS: [&str; 6] = [
    "restrict",
    "no-agent-forwarding",
    "no-port-forwarding",
    "no-pty",
    "no-user-rc",
    "no-X11-forwarding",
];

/// The one public key algorithm an operational identity is minted in.
///
/// It is a single value rather than a list because the Controller generates
/// these pairs itself: there is no legacy key to accommodate, and a second
/// accepted algorithm would only be a second thing to get wrong.
pub const KEY_ALGORITHM: &str = "ssh-ed25519";

/// Longest entry this palier reads. A real one is a little over a hundred
/// bytes; anything longer is not a longer entry, it is a file this palier does
/// not recognise.
pub const MAX_ENTRY_BYTES: usize = 1024;

/// The exact command the entry forces, built from the constants above.
///
/// `-n` is part of it: the account is locked and has no password, so a `sudo`
/// that could decide to prompt would hang a session instead of refusing one.
pub fn forced_command() -> String {
    format!(
        "{SUDO_BINARY} -n {PACKAGE_BINARY} {} {}",
        AUXILIARY_SUBJECT[0], AUXILIARY_SUBJECT[1]
    )
}

/// One `authorized_keys` entry that grants nothing but the forced command.
///
/// It cannot be built by naming its fields, and [`judge`] is the only function
/// that returns one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundedEntry {
    algorithm: String,
    key: String,
}

impl BoundedEntry {
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// The base64 body of the public key, as it stands in the file.
    pub fn key(&self) -> &str {
        &self.key
    }
}

/// Why an entry was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryRefusal {
    /// Nothing, only blank lines, or only comments.
    Empty,
    /// More than one key. A file with a second entry is a file with a second
    /// answer, and which of the two `sshd` used would be decided by whichever
    /// key the client happened to offer.
    SeveralEntries { count: usize },
    /// Longer than this palier reads.
    TooLarge { bytes: usize },
    /// The entry carries no options at all, so it forces nothing.
    NoOptions,
    /// One of [`REQUIRED_OPTIONS`] is absent.
    MissingRestriction { option: &'static str },
    /// No `command=` option: the key would open whatever the client asked for.
    NoForcedCommand,
    /// The forced command is not the one constant this palier installs.
    ForcedCommandNotExact { found: String },
    /// The forced command re-injects what the client asked for. It is refused
    /// by name rather than as a mere difference, because it is the one way a
    /// forced command can look forced and still be a free shell.
    ForcedCommandCarriesTheClientCommand,
    /// An option that is not on the positive list.
    UnknownOption { option: String },
    /// A public key algorithm this palier does not mint.
    UnsupportedAlgorithm { algorithm: String },
    /// The line is not `[options] algorithm key [comment]`.
    Malformed,
}

/// The entry this palier installs for one public key.
///
/// The key travels as the two fields `ssh-keygen` writes; nothing here reads a
/// private byte, and the comment `ssh-keygen` appends is deliberately dropped:
/// it would carry the generating host's name into every enrolled machine.
pub fn render(algorithm: &str, key: &str) -> Result<String, EntryRefusal> {
    if algorithm != KEY_ALGORITHM {
        return Err(EntryRefusal::UnsupportedAlgorithm {
            algorithm: algorithm.to_owned(),
        });
    }
    if key.is_empty() || !is_base64(key) {
        return Err(EntryRefusal::Malformed);
    }
    let options = REQUIRED_OPTIONS.join(",");
    let line = format!(
        "command=\"{}\",{options} {algorithm} {key}\n",
        forced_command()
    );
    if line.len() > MAX_ENTRY_BYTES {
        return Err(EntryRefusal::TooLarge { bytes: line.len() });
    }
    Ok(line)
}

/// The one gate. Nothing else in this crate builds a [`BoundedEntry`].
///
/// It judges the *file*, not a line: a second entry is refused here rather than
/// left for whoever reads the first one.
pub fn judge(file: &str) -> Result<BoundedEntry, EntryRefusal> {
    if file.len() > MAX_ENTRY_BYTES {
        return Err(EntryRefusal::TooLarge { bytes: file.len() });
    }
    let lines: Vec<&str> = file
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    match lines.len() {
        0 => return Err(EntryRefusal::Empty),
        1 => {}
        count => return Err(EntryRefusal::SeveralEntries { count }),
    }
    judge_line(lines[0])
}

fn judge_line(line: &str) -> Result<BoundedEntry, EntryRefusal> {
    let (options, remainder) = split_options(line)?;
    if options.is_empty() {
        return Err(EntryRefusal::NoOptions);
    }

    let mut command: Option<String> = None;
    for option in &options {
        if let Some(value) = option.strip_prefix("command=") {
            command = Some(unquote(value));
            continue;
        }
        if !REQUIRED_OPTIONS.contains(&option.as_str()) {
            return Err(EntryRefusal::UnknownOption {
                option: option.clone(),
            });
        }
    }
    let Some(command) = command else {
        return Err(EntryRefusal::NoForcedCommand);
    };
    if command.contains("SSH_ORIGINAL_COMMAND") {
        return Err(EntryRefusal::ForcedCommandCarriesTheClientCommand);
    }
    if command != forced_command() {
        return Err(EntryRefusal::ForcedCommandNotExact { found: command });
    }
    for required in REQUIRED_OPTIONS {
        if !options.iter().any(|option| option == required) {
            return Err(EntryRefusal::MissingRestriction { option: required });
        }
    }

    let mut fields = remainder.split_whitespace();
    let (Some(algorithm), Some(key)) = (fields.next(), fields.next()) else {
        return Err(EntryRefusal::Malformed);
    };
    if algorithm != KEY_ALGORITHM {
        return Err(EntryRefusal::UnsupportedAlgorithm {
            algorithm: algorithm.to_owned(),
        });
    }
    if !is_base64(key) {
        return Err(EntryRefusal::Malformed);
    }
    Ok(BoundedEntry {
        algorithm: algorithm.to_owned(),
        key: key.to_owned(),
    })
}

/// Splits the option list from the key, the way `sshd` does: options run until
/// the first space that is not inside a quoted value, and a comma inside quotes
/// does not end an option.
fn split_options(line: &str) -> Result<(Vec<String>, &str), EntryRefusal> {
    if line.starts_with(KEY_ALGORITHM) {
        return Ok((Vec::new(), line));
    }
    let bytes = line.as_bytes();
    let mut quoted = false;
    let mut escaped = false;
    let mut options = Vec::new();
    let mut current = String::new();
    for (index, byte) in bytes.iter().enumerate() {
        if escaped {
            current.push(*byte as char);
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if quoted => escaped = true,
            b'"' => {
                quoted = !quoted;
                current.push('"');
            }
            b',' if !quoted => {
                options.push(std::mem::take(&mut current));
            }
            b' ' | b'\t' if !quoted => {
                options.push(current);
                return Ok((options, line[index + 1..].trim_start()));
            }
            _ => current.push(*byte as char),
        }
    }
    Err(EntryRefusal::Malformed)
}

/// Removes one layer of quoting, if the value carries one.
fn unquote(value: &str) -> String {
    let trimmed = value.trim();
    match trimmed
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    {
        Some(inner) => inner.to_owned(),
        None => trimmed.to_owned(),
    }
}

fn is_base64(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/' || byte == b'='
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIBQ4Yk1LabelledSyntheticKeyMaterial00";

    fn installed() -> String {
        render(KEY_ALGORITHM, KEY).expect("the rendered entry must be renderable")
    }

    /// The positive control: what this palier writes is what this palier
    /// accepts, and it accepts nothing that grants more.
    #[test]
    fn the_entry_this_palier_writes_is_the_entry_it_accepts() {
        let entry = judge(&installed()).expect("the positive control must be accepted");
        assert_eq!(entry.algorithm(), KEY_ALGORITHM);
        assert_eq!(entry.key(), KEY);
    }

    /// Every capability is refused by name, one at a time, so a proof can say
    /// which restriction it lost rather than that something changed.
    #[test]
    fn removing_any_single_restriction_is_refused_by_its_own_name() {
        for missing in REQUIRED_OPTIONS {
            let kept: Vec<&str> = REQUIRED_OPTIONS
                .iter()
                .copied()
                .filter(|option| *option != missing)
                .collect();
            let line = format!(
                "command=\"{}\",{} {KEY_ALGORITHM} {KEY}\n",
                forced_command(),
                kept.join(",")
            );
            assert_eq!(
                judge(&line),
                Err(EntryRefusal::MissingRestriction { option: missing }),
                "{missing} must be refused by its own name"
            );
        }
    }

    /// The options a generous entry would carry are refused because they are
    /// not on the positive list, not because somebody enumerated them.
    #[test]
    fn an_option_outside_the_positive_list_is_refused_by_name() {
        for granted in [
            "environment=\"YOUR_CLOUD=1\"",
            "permitopen=\"127.0.0.1:5432\"",
            "permitlisten=\"127.0.0.1:8080\"",
            "tunnel=\"0\"",
            "pty",
            "agent-forwarding",
            "port-forwarding",
            "X11-forwarding",
            "user-rc",
        ] {
            let line = format!(
                "command=\"{}\",{},{granted} {KEY_ALGORITHM} {KEY}\n",
                forced_command(),
                REQUIRED_OPTIONS.join(",")
            );
            assert_eq!(
                judge(&line),
                Err(EntryRefusal::UnknownOption {
                    option: granted.into()
                }),
                "{granted} must be refused"
            );
        }
    }

    /// A forced command that hands the client's own command back is the one way
    /// an entry can look forced and be a free shell. It is refused by its own
    /// name.
    #[test]
    fn a_forced_command_that_re_injects_the_client_command_is_refused_by_name() {
        for hostile in [
            format!("{} $SSH_ORIGINAL_COMMAND", forced_command()),
            "/bin/sh -c \\\"$SSH_ORIGINAL_COMMAND\\\"".to_owned(),
        ] {
            let line = format!(
                "command=\"{hostile}\",{} {KEY_ALGORITHM} {KEY}\n",
                REQUIRED_OPTIONS.join(",")
            );
            assert_eq!(
                judge(&line),
                Err(EntryRefusal::ForcedCommandCarriesTheClientCommand),
                "{hostile} must be refused as a free command"
            );
        }
    }

    /// Anything that is not the one invocation is refused, including a shell, a
    /// relative path and one extra argument.
    #[test]
    fn a_command_that_is_not_the_one_invocation_is_refused() {
        for hostile in [
            "/bin/sh",
            "your-cloud auxiliary approve",
            "/usr/bin/sudo -n /usr/lib/your-cloud/your-cloud auxiliary approve --format=json",
            "/usr/bin/sudo /usr/lib/your-cloud/your-cloud auxiliary approve",
            "/usr/bin/sudo -n /usr/lib/your-cloud/your-cloud controller",
        ] {
            let line = format!(
                "command=\"{hostile}\",{} {KEY_ALGORITHM} {KEY}\n",
                REQUIRED_OPTIONS.join(",")
            );
            assert_eq!(
                judge(&line),
                Err(EntryRefusal::ForcedCommandNotExact {
                    found: hostile.into()
                }),
                "{hostile} must not pass for the one invocation"
            );
        }
    }

    /// An entry with no options at all, and one with restrictions but no
    /// command, are different failures and come back as different refusals.
    #[test]
    fn an_entry_without_options_or_without_a_command_is_refused() {
        assert_eq!(
            judge(&format!("{KEY_ALGORITHM} {KEY}\n")),
            Err(EntryRefusal::NoOptions)
        );
        assert_eq!(
            judge(&format!(
                "{} {KEY_ALGORITHM} {KEY}\n",
                REQUIRED_OPTIONS.join(",")
            )),
            Err(EntryRefusal::NoForcedCommand)
        );
    }

    /// A second entry is a second answer. The file is refused rather than the
    /// first line accepted.
    #[test]
    fn a_second_entry_in_the_file_denies_the_first_one() {
        let mut file = installed();
        file.push_str(&format!(
            "{KEY_ALGORITHM} {KEY} an-unrestricted-second-key\n"
        ));
        assert_eq!(judge(&file), Err(EntryRefusal::SeveralEntries { count: 2 }));
    }

    /// Comments and blank lines are not entries, and a file made only of them
    /// is empty rather than acceptable.
    #[test]
    fn a_file_of_comments_is_empty_rather_than_acceptable() {
        assert_eq!(judge("\n# nothing here\n\n"), Err(EntryRefusal::Empty));
    }

    /// The palier mints one algorithm, and reads one.
    #[test]
    fn an_algorithm_this_palier_does_not_mint_is_refused() {
        assert_eq!(
            render("ssh-rsa", KEY),
            Err(EntryRefusal::UnsupportedAlgorithm {
                algorithm: "ssh-rsa".into()
            })
        );
        let line = format!(
            "command=\"{}\",{} ssh-rsa {KEY}\n",
            forced_command(),
            REQUIRED_OPTIONS.join(",")
        );
        assert_eq!(
            judge(&line),
            Err(EntryRefusal::UnsupportedAlgorithm {
                algorithm: "ssh-rsa".into()
            })
        );
    }

    /// A comma inside the quoted command does not end the option, and the
    /// parser that reads the machine's file agrees with `sshd` on that.
    #[test]
    fn a_comma_inside_the_quoted_command_does_not_end_the_option() {
        let line = format!(
            "command=\"/usr/bin/sudo -n /usr/lib/your-cloud/your-cloud,auxiliary approve\",{} \
             {KEY_ALGORITHM} {KEY}\n",
            REQUIRED_OPTIONS.join(",")
        );
        assert_eq!(
            judge(&line),
            Err(EntryRefusal::ForcedCommandNotExact {
                found: "/usr/bin/sudo -n /usr/lib/your-cloud/your-cloud,auxiliary approve".into()
            })
        );
    }

    /// The forced command names absolute paths, and the invocation the
    /// elevation rule authorises is taken from the same constants.
    #[test]
    fn the_forced_command_is_absolute_and_shared_with_the_elevation_rule() {
        let command = forced_command();
        assert!(command.starts_with('/'));
        assert!(command.contains(PACKAGE_BINARY));
        assert!(command.ends_with("auxiliary approve"));
        assert!(!command.contains(';') && !command.contains('&') && !command.contains('|'));
    }

    /// A file longer than this palier reads is refused before it is parsed.
    #[test]
    fn a_file_longer_than_this_palier_reads_is_refused_before_it_is_parsed() {
        let oversized = "#".repeat(MAX_ENTRY_BYTES + 1);
        assert_eq!(
            judge(&oversized),
            Err(EntryRefusal::TooLarge {
                bytes: MAX_ENTRY_BYTES + 1
            })
        );
    }
}
