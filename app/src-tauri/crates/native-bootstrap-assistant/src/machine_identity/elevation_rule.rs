//! The `sudo` rule that lets the locked account run one command, and nothing
//! else.
//!
//! The account the forced command lands on holds no privilege of its own: it is
//! locked, it has no password and it owns nothing. The one thing it may do is
//! ask `root` to run the Auxiliary — for one exact argument vector, with the
//! environment reset, without being able to add a variable to it, and without a
//! password it does not have.
//!
//! **The command is compared for equality, arguments included.** A `sudoers`
//! entry that names a command *without* arguments authorises that command with
//! *any* arguments; that is the single most common way a bounded elevation
//! turns into a general one. This module refuses a rule whose command is not
//! byte for byte the invocation of [`super::entry`], so "no free argument" is a
//! comparison rather than a hope about how `sudo` matches.
//!
//! **`SETENV` is refused, and so is anything that preserves an environment.**
//! With `SETENV` the client chooses `LD_PRELOAD`; with `env_keep` the account's
//! environment does. Both are named refusals rather than a single "unsafe"
//! verdict, because a proof has to say which one it caught.
//!
//! **A general `sudo` rule is refused rather than narrowed.** `ALL`, a wildcard
//! and a run-as that is not exactly `root` come back as their own refusals. The
//! architecture is explicit that no general rule is ever created, and the only
//! way that claim can be checked on a real machine is by having something judge
//! the file that is really there.

use crate::installation::plan::PACKAGE_BINARY;
use crate::machine_identity::account::AUXILIARY_ACCOUNT;
use crate::machine_identity::entry::AUXILIARY_SUBJECT;

/// Where the rule lives. It is a fixed path in the drop-in directory rather
/// than an edit of `/etc/sudoers`: a run that rewrote the machine's own policy
/// file could not be undone by removing what it created.
pub const RULE_PATH: &str = "/etc/sudoers.d/60-your-cloud-auxiliary";

/// Longest rule this palier reads.
pub const MAX_RULE_BYTES: usize = 1024;

/// Tags a bounded rule may carry. `NOPASSWD` is required — the account has no
/// password, so a rule that asked for one would be a rule nothing can satisfy —
/// and `NOEXEC` is allowed because it only takes more away.
const ACCEPTED_TAGS: [&str; 2] = ["NOPASSWD", "NOEXEC"];

/// `Defaults` settings this palier requires for the account.
pub const REQUIRED_DEFAULTS: [&str; 4] = ["!setenv", "env_reset", "!log_input", "!log_stdin"];

/// The exact command the rule authorises, and the only one.
pub fn authorised_command() -> String {
    format!(
        "{PACKAGE_BINARY} {} {}",
        AUXILIARY_SUBJECT[0], AUXILIARY_SUBJECT[1]
    )
}

/// One elevation bounded to one invocation.
///
/// It cannot be built by naming its fields, and [`judge`] is the only function
/// that returns one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundedElevation {
    account: String,
    command: String,
}

impl BoundedElevation {
    pub fn account(&self) -> &str {
        &self.account
    }

    pub fn command(&self) -> &str {
        &self.command
    }
}

/// Why an elevation rule was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ElevationRefusal {
    /// Nothing, or only comments.
    Empty,
    /// Longer than this palier reads.
    TooLarge { bytes: usize },
    /// More than one user specification. A second rule is a second grant, and
    /// `sudo` uses the last match, not the first.
    SeveralRules { count: usize },
    /// The rule does not apply to the locked technical account.
    NotTheAuxiliaryAccount { name: String },
    /// The rule applies to a group. A group grows; an account does not.
    GroupRule { name: String },
    /// The file pulls in another file, so what it grants is written elsewhere.
    IncludeDirective { line: String },
    /// The file defines an alias, so the command it grants is named indirectly.
    AliasDefinition { line: String },
    /// The specification is not `account ALL=(root) TAGS: command`.
    Malformed { line: String },
    /// The host part is not `ALL`.
    HostIsNotAll { host: String },
    /// No `(runas)` at all: the rule relies on `sudo`'s default rather than
    /// saying who it elevates to.
    RunAsNotDeclared,
    /// The rule elevates to something other than `root`.
    RunAsIsNotRoot { runas: String },
    /// `SETENV` lets the caller choose a variable of the privileged process.
    SetenvGranted,
    /// A `Defaults` line preserves or re-admits an environment.
    EnvironmentPreserved { setting: String },
    /// A tag outside the accepted pair.
    UnknownTag { tag: String },
    /// The account has no password, so a rule requiring one grants nothing and
    /// hides that it grants nothing.
    PasswordRequired,
    /// `ALL`, or a wildcard, in the command.
    WildcardCommand { command: String },
    /// The command is not the one invocation this palier authorises.
    CommandNotExact { found: String },
    /// One of [`REQUIRED_DEFAULTS`] is absent.
    MissingDefault { setting: &'static str },
}

/// The rule this palier installs.
pub fn render() -> String {
    format!(
        "Defaults:{AUXILIARY_ACCOUNT} {}\n{AUXILIARY_ACCOUNT} ALL=(root) NOPASSWD: {}\n",
        REQUIRED_DEFAULTS.join(", "),
        authorised_command()
    )
}

/// The one gate. Nothing else in this crate builds a [`BoundedElevation`].
pub fn judge(file: &str) -> Result<BoundedElevation, ElevationRefusal> {
    if file.len() > MAX_RULE_BYTES {
        return Err(ElevationRefusal::TooLarge { bytes: file.len() });
    }
    let lines: Vec<&str> = file
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();

    let mut defaults: Vec<String> = Vec::new();
    let mut specifications: Vec<&str> = Vec::new();
    for line in lines {
        if line.starts_with("#include")
            || line.starts_with("@include")
            || line.starts_with("#includedir")
            || line.starts_with("@includedir")
        {
            return Err(ElevationRefusal::IncludeDirective {
                line: line.to_owned(),
            });
        }
        if line.starts_with('#') {
            continue;
        }
        if line.contains("_Alias") {
            return Err(ElevationRefusal::AliasDefinition {
                line: line.to_owned(),
            });
        }
        if let Some(rest) = line.strip_prefix("Defaults") {
            for setting in rest
                .trim_start_matches([':', '@', '>', '!'])
                .split(',')
                .map(str::trim)
                .filter(|setting| !setting.is_empty())
            {
                // The account name the `Defaults:` binding carries is not a
                // setting; everything after the first space is.
                let setting = setting.split_whitespace().last().unwrap_or(setting);
                defaults.push(setting.to_owned());
            }
            continue;
        }
        specifications.push(line);
    }

    match specifications.len() {
        0 => return Err(ElevationRefusal::Empty),
        1 => {}
        count => return Err(ElevationRefusal::SeveralRules { count }),
    }

    for setting in &defaults {
        if setting == "setenv" {
            return Err(ElevationRefusal::SetenvGranted);
        }
        if setting.starts_with("env_keep")
            || setting == "!env_reset"
            || setting.starts_with("env_file")
        {
            return Err(ElevationRefusal::EnvironmentPreserved {
                setting: setting.clone(),
            });
        }
    }
    for required in REQUIRED_DEFAULTS {
        if !defaults.iter().any(|setting| setting == required) {
            return Err(ElevationRefusal::MissingDefault { setting: required });
        }
    }

    judge_specification(specifications[0])
}

fn judge_specification(line: &str) -> Result<BoundedElevation, ElevationRefusal> {
    let malformed = || ElevationRefusal::Malformed {
        line: line.to_owned(),
    };
    let (account, rest) = line.split_once(char::is_whitespace).ok_or_else(malformed)?;
    if account.starts_with('%') {
        return Err(ElevationRefusal::GroupRule {
            name: account.to_owned(),
        });
    }
    if account != AUXILIARY_ACCOUNT {
        return Err(ElevationRefusal::NotTheAuxiliaryAccount {
            name: account.to_owned(),
        });
    }
    let (host, rest) = rest.trim().split_once('=').ok_or_else(malformed)?;
    if host.trim() != "ALL" {
        return Err(ElevationRefusal::HostIsNotAll {
            host: host.trim().to_owned(),
        });
    }
    let rest = rest.trim();
    let Some(rest) = rest.strip_prefix('(') else {
        return Err(ElevationRefusal::RunAsNotDeclared);
    };
    let (runas, rest) = rest.split_once(')').ok_or_else(malformed)?;
    if runas != "root" && runas != "root:root" {
        return Err(ElevationRefusal::RunAsIsNotRoot {
            runas: runas.to_owned(),
        });
    }

    let mut rest = rest.trim();
    let mut no_password = false;
    while let Some((candidate, remainder)) = rest.split_once(':') {
        let tag = candidate.trim();
        if tag.is_empty() || !tag.chars().all(|letter| letter.is_ascii_uppercase()) {
            break;
        }
        if tag == "SETENV" {
            return Err(ElevationRefusal::SetenvGranted);
        }
        if !ACCEPTED_TAGS.contains(&tag) {
            return Err(ElevationRefusal::UnknownTag {
                tag: tag.to_owned(),
            });
        }
        if tag == "NOPASSWD" {
            no_password = true;
        }
        rest = remainder.trim();
    }
    if !no_password {
        return Err(ElevationRefusal::PasswordRequired);
    }

    let command = rest.trim();
    if command.is_empty() {
        return Err(malformed());
    }
    if command == "ALL"
        || command.contains('*')
        || command.contains('?')
        || command.contains('[')
        || command.contains(',')
    {
        return Err(ElevationRefusal::WildcardCommand {
            command: command.to_owned(),
        });
    }
    if command != authorised_command() {
        return Err(ElevationRefusal::CommandNotExact {
            found: command.to_owned(),
        });
    }
    Ok(BoundedElevation {
        account: AUXILIARY_ACCOUNT.to_owned(),
        command: command.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_specification(specification: &str) -> String {
        format!(
            "Defaults:{AUXILIARY_ACCOUNT} {}\n{specification}\n",
            REQUIRED_DEFAULTS.join(", ")
        )
    }

    /// The positive control: what this palier writes is what this palier
    /// accepts.
    #[test]
    fn the_rule_this_palier_writes_is_the_rule_it_accepts() {
        let bounded = judge(&render()).expect("the positive control must be accepted");
        assert_eq!(bounded.account(), AUXILIARY_ACCOUNT);
        assert_eq!(bounded.command(), authorised_command());
        assert!(bounded.command().starts_with('/'));
    }

    /// The refusal the issue names: a broadened rule, in every shape a real
    /// `sudoers` file writes one.
    #[test]
    fn a_broadened_rule_is_refused_in_every_shape_it_is_written() {
        let broadened = [
            (
                format!("{AUXILIARY_ACCOUNT} ALL=(root) NOPASSWD: ALL"),
                ElevationRefusal::WildcardCommand {
                    command: "ALL".into(),
                },
            ),
            (
                format!(
                    "{AUXILIARY_ACCOUNT} ALL=(ALL) NOPASSWD: {}",
                    authorised_command()
                ),
                ElevationRefusal::RunAsIsNotRoot {
                    runas: "ALL".into(),
                },
            ),
            (
                format!("{AUXILIARY_ACCOUNT} ALL=(root) NOPASSWD: /usr/lib/your-cloud/*"),
                ElevationRefusal::WildcardCommand {
                    command: "/usr/lib/your-cloud/*".into(),
                },
            ),
            (
                format!(
                    "%{AUXILIARY_ACCOUNT} ALL=(root) NOPASSWD: {}",
                    authorised_command()
                ),
                ElevationRefusal::GroupRule {
                    name: format!("%{AUXILIARY_ACCOUNT}"),
                },
            ),
            (
                format!("root ALL=(root) NOPASSWD: {}", authorised_command()),
                ElevationRefusal::NotTheAuxiliaryAccount {
                    name: "root".into(),
                },
            ),
        ];
        for (specification, expected) in broadened {
            assert_eq!(
                judge(&with_specification(&specification)),
                Err(expected),
                "{specification} must be refused"
            );
        }
    }

    /// The one that matters most in practice: a command named without its
    /// arguments authorises it with *any* arguments, so it is not a narrower
    /// rule, it is a general one.
    #[test]
    fn a_command_without_its_exact_arguments_is_refused() {
        for hostile in [
            PACKAGE_BINARY,
            "/usr/lib/your-cloud/your-cloud auxiliary",
            "/usr/lib/your-cloud/your-cloud auxiliary approve --format=json",
            "/usr/lib/your-cloud/your-cloud controller",
            "/bin/sh",
        ] {
            assert_eq!(
                judge(&with_specification(&format!(
                    "{AUXILIARY_ACCOUNT} ALL=(root) NOPASSWD: {hostile}"
                ))),
                Err(ElevationRefusal::CommandNotExact {
                    found: hostile.into()
                }),
                "{hostile} must not pass for the one invocation"
            );
        }
    }

    /// `SETENV` is refused wherever it is written: on the specification, and as
    /// a `Defaults` flag.
    #[test]
    fn setenv_is_refused_as_a_tag_and_as_a_default() {
        assert_eq!(
            judge(&with_specification(&format!(
                "{AUXILIARY_ACCOUNT} ALL=(root) NOPASSWD: SETENV: {}",
                authorised_command()
            ))),
            Err(ElevationRefusal::SetenvGranted)
        );
        let file = format!(
            "Defaults:{AUXILIARY_ACCOUNT} env_reset, setenv, !log_input, !log_stdin, !setenv\n\
             {AUXILIARY_ACCOUNT} ALL=(root) NOPASSWD: {}\n",
            authorised_command()
        );
        assert_eq!(judge(&file), Err(ElevationRefusal::SetenvGranted));
    }

    /// An environment that survives the elevation is refused by the setting
    /// that let it through.
    #[test]
    fn an_environment_that_survives_the_elevation_is_refused() {
        for setting in [
            "env_keep+=LD_PRELOAD",
            "!env_reset",
            "env_file=/etc/environment",
        ] {
            let file = format!(
                "Defaults:{AUXILIARY_ACCOUNT} {}, {setting}\n\
                 {AUXILIARY_ACCOUNT} ALL=(root) NOPASSWD: {}\n",
                REQUIRED_DEFAULTS.join(", "),
                authorised_command()
            );
            assert_eq!(
                judge(&file),
                Err(ElevationRefusal::EnvironmentPreserved {
                    setting: setting.into()
                }),
                "{setting} must be refused"
            );
        }
    }

    /// Each required `Defaults` setting is refused by its own name when it is
    /// missing, so a proof says which guarantee it lost.
    #[test]
    fn removing_any_required_default_is_refused_by_its_own_name() {
        for missing in REQUIRED_DEFAULTS {
            let kept: Vec<&str> = REQUIRED_DEFAULTS
                .iter()
                .copied()
                .filter(|setting| *setting != missing)
                .collect();
            let file = format!(
                "Defaults:{AUXILIARY_ACCOUNT} {}\n{AUXILIARY_ACCOUNT} ALL=(root) NOPASSWD: {}\n",
                kept.join(", "),
                authorised_command()
            );
            assert_eq!(
                judge(&file),
                Err(ElevationRefusal::MissingDefault { setting: missing }),
                "{missing} must be refused by its own name"
            );
        }
    }

    /// A rule that asks for a password grants nothing, since the account has
    /// none, and hides that it grants nothing.
    #[test]
    fn a_rule_that_asks_a_locked_account_for_a_password_is_refused() {
        assert_eq!(
            judge(&with_specification(&format!(
                "{AUXILIARY_ACCOUNT} ALL=(root) {}",
                authorised_command()
            ))),
            Err(ElevationRefusal::PasswordRequired)
        );
    }

    /// A rule that does not say who it elevates to is refused rather than read
    /// with `sudo`'s default.
    #[test]
    fn a_rule_that_does_not_declare_its_run_as_is_refused() {
        assert_eq!(
            judge(&with_specification(&format!(
                "{AUXILIARY_ACCOUNT} ALL=NOPASSWD: {}",
                authorised_command()
            ))),
            Err(ElevationRefusal::RunAsNotDeclared)
        );
    }

    /// What the rule grants must be written in the rule. A file that includes
    /// another one, or names its command through an alias, is refused.
    #[test]
    fn a_rule_written_somewhere_else_is_refused() {
        assert_eq!(
            judge("@includedir /etc/sudoers.d\n"),
            Err(ElevationRefusal::IncludeDirective {
                line: "@includedir /etc/sudoers.d".into()
            })
        );
        let aliased = format!(
            "Cmnd_Alias YOUR_CLOUD = {}\n{AUXILIARY_ACCOUNT} ALL=(root) NOPASSWD: YOUR_CLOUD\n",
            authorised_command()
        );
        assert!(matches!(
            judge(&aliased),
            Err(ElevationRefusal::AliasDefinition { .. })
        ));
    }

    /// A second specification is a second grant, and `sudo` uses the last
    /// match rather than the first.
    #[test]
    fn a_second_specification_denies_the_first_one() {
        let file = format!(
            "Defaults:{AUXILIARY_ACCOUNT} {}\n\
             {AUXILIARY_ACCOUNT} ALL=(root) NOPASSWD: {}\n\
             {AUXILIARY_ACCOUNT} ALL=(root) NOPASSWD: /bin/sh\n",
            REQUIRED_DEFAULTS.join(", "),
            authorised_command()
        );
        assert_eq!(
            judge(&file),
            Err(ElevationRefusal::SeveralRules { count: 2 })
        );
    }

    /// An empty or oversized file is refused before anything is granted.
    #[test]
    fn an_empty_or_oversized_file_grants_nothing() {
        assert_eq!(judge("# nothing\n\n"), Err(ElevationRefusal::Empty));
        let oversized = "#".repeat(MAX_RULE_BYTES + 1);
        assert_eq!(
            judge(&oversized),
            Err(ElevationRefusal::TooLarge {
                bytes: MAX_RULE_BYTES + 1
            })
        );
    }

    /// The rule lives in the drop-in directory, so removing what this run
    /// created really removes the grant.
    #[test]
    fn the_rule_is_a_file_of_its_own_rather_than_an_edit_of_the_policy() {
        assert!(RULE_PATH.starts_with("/etc/sudoers.d/"));
        assert_ne!(RULE_PATH, "/etc/sudoers");
    }
}
