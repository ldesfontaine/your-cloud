//! The locked technical account the bounded identity lands on.
//!
//! The forced command has to run as somebody. That somebody is an account whose
//! only reachable use is the forced command itself: it cannot be logged into,
//! it has no password to guess or to reset, it owns nothing the enrolment
//! installed, and it is not the account of the Daemon, of the Relay or of the
//! Controller. Compromising one role does not hand over another.
//!
//! **Locked and passwordless are two facts, and both are required.** A shadow
//! field like `!$6$…` describes an account that is locked *and still carries a
//! hash*: unlocking it is one `usermod` away, and the hash is offline-crackable
//! in the meantime. This module accepts only the four fields that mean "no
//! password exists at all", and refuses a locked hash by its own name so a
//! proof can tell the two apart.
//!
//! **An empty field is not a passwordless account.** In `/etc/shadow` an empty
//! second field means authentication succeeds with *no* password. It is the
//! most dangerous of the values this module sees and it is refused as
//! [`AccountRefusal::NoPasswordRequired`], not accepted as "passwordless".
//!
//! **The shell is `/bin/sh`, and that is measured rather than preferred.**
//! `sshd` runs a forced command as `shell -c "<command>"`. An account whose
//! shell is `nologin` therefore never runs the forced command at all — the LAB
//! measured exactly that, and got `This account is currently not available.`
//! where the Auxiliary should have answered. What protects this account is not
//! a shell that refuses: it is a locked password, a single `authorized_keys`
//! entry that forces one command, and an entry that grants no PTY and no
//! session of any other shape. Naming one shell keeps the interpreter of that
//! one command fixed instead of leaving it to whatever `useradd` defaulted to.
//!
//! **The account has no home.** [`REQUIRED_HOME`] does not exist on the
//! machine, so `~/.ssh/rc`, `~/.ssh/environment` and a shell profile have
//! nowhere to live and nowhere to be created from. It is a second, independent
//! reason those files never run — the first being the entry's `no-user-rc` and
//! the server's `PermitUserEnvironment no`.
//!
//! Nothing here creates an account. It judges what the machine answered, which
//! is the only version of this fact worth having.

use crate::installation::plan::CONTROLLER_ACCOUNT;

/// The account the Auxiliary's forced command runs as.
///
/// It is a constant rather than a parameter for the reason the whole isolation
/// of #38 is: an enrolment that could be pointed at another account would have
/// a blast radius decided by its caller, and a LAB proof could then only speak
/// about the invocation it happened to run.
pub const AUXILIARY_ACCOUNT: &str = "your-cloud-auxiliary";

/// The other role accounts of the same estate. The Auxiliary shares none of
/// them; the Controller's is a systemd dynamic user and never exists as a
/// persistent account at all, and it is named here so that a machine which
/// somehow created one is still refused.
pub const ROLE_ACCOUNTS: [&str; 3] = [CONTROLLER_ACCOUNT, "your-cloud-daemon", "your-cloud-relay"];

/// The one shell `sshd` may run the forced command through. See the module
/// header: a `nologin` shell does not harden this account, it disables the
/// forced command.
pub const REQUIRED_SHELL: &str = "/bin/sh";

/// The home directory the account is given, and which the enrolment never
/// creates. Nothing the account could read at session start lives anywhere.
pub const REQUIRED_HOME: &str = "/nonexistent";

/// The four shadow fields that mean "this account has no password and cannot be
/// logged into".
const LOCKED_WITHOUT_PASSWORD: [&str; 4] = ["!", "!!", "*", "!*"];

/// Lowest identifier a system account may hold on the supported distribution.
/// An enrolment that allocated an ordinary user identifier would put the
/// technical account in the range a human account is created from.
pub const MAX_SYSTEM_UID: u32 = 999;

/// The account as the machine describes it: one line of `/etc/passwd` and the
/// second field of its `/etc/shadow` line, verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedAccount {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub shell: String,
    /// The home field of `/etc/passwd`. It names a directory the enrolment
    /// never creates.
    pub home: String,
    /// The second field of `/etc/shadow`, copied without interpretation.
    pub password_field: String,
    /// Supplementary groups, beside the account's own.
    pub supplementary_groups: Vec<String>,
}

/// Why an account was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountRefusal {
    /// Not the technical account this palier enrols.
    NotTheAuxiliaryAccount { name: String },
    /// The account is `root`, or shares its identifier.
    IsRoot,
    /// The account is one of the other roles'.
    SharesARoleAccount { role: String },
    /// The identifier is outside the system range.
    NotASystemAccount { uid: u32 },
    /// The shell is not the one `sshd` is expected to run the forced command
    /// through, so the one command this palier forces would be interpreted by
    /// something nobody chose.
    ShellIsNotTheFixedOne { shell: String },
    /// The account was given a home, so a startup file has somewhere to live.
    HomeIsNotTheAbsentOne { home: String },
    /// The account carries a password hash, locked or not.
    PasswordSet,
    /// The shadow field is empty: authentication succeeds with no password.
    NoPasswordRequired,
    /// The shadow field is neither a hash nor one of the locked forms.
    NotLocked { field: String },
    /// A supplementary group would give the account rights the enrolment did
    /// not grant it.
    SupplementaryGroup { group: String },
}

/// One locked, passwordless technical account.
///
/// It cannot be built by naming its fields, and [`judge`] is the only function
/// that returns one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockedAccount {
    name: String,
    uid: u32,
    gid: u32,
}

impl LockedAccount {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }

    pub fn gid(&self) -> u32 {
        self.gid
    }
}

/// The one gate. Nothing else in this crate builds a [`LockedAccount`].
pub fn judge(observed: &ObservedAccount) -> Result<LockedAccount, AccountRefusal> {
    if observed.name != AUXILIARY_ACCOUNT {
        if ROLE_ACCOUNTS.contains(&observed.name.as_str()) {
            return Err(AccountRefusal::SharesARoleAccount {
                role: observed.name.clone(),
            });
        }
        return Err(AccountRefusal::NotTheAuxiliaryAccount {
            name: observed.name.clone(),
        });
    }
    if observed.uid == 0 || observed.gid == 0 {
        return Err(AccountRefusal::IsRoot);
    }
    if observed.uid > MAX_SYSTEM_UID {
        return Err(AccountRefusal::NotASystemAccount { uid: observed.uid });
    }
    if observed.shell != REQUIRED_SHELL {
        return Err(AccountRefusal::ShellIsNotTheFixedOne {
            shell: observed.shell.clone(),
        });
    }
    if observed.home != REQUIRED_HOME {
        return Err(AccountRefusal::HomeIsNotTheAbsentOne {
            home: observed.home.clone(),
        });
    }
    if observed.password_field.contains('$') {
        return Err(AccountRefusal::PasswordSet);
    }
    if observed.password_field.is_empty() {
        return Err(AccountRefusal::NoPasswordRequired);
    }
    if !LOCKED_WITHOUT_PASSWORD.contains(&observed.password_field.as_str()) {
        return Err(AccountRefusal::NotLocked {
            field: observed.password_field.clone(),
        });
    }
    if let Some(group) = observed.supplementary_groups.first() {
        return Err(AccountRefusal::SupplementaryGroup {
            group: group.clone(),
        });
    }
    Ok(LockedAccount {
        name: observed.name.clone(),
        uid: observed.uid,
        gid: observed.gid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locked() -> ObservedAccount {
        ObservedAccount {
            name: AUXILIARY_ACCOUNT.into(),
            uid: 991,
            gid: 991,
            shell: REQUIRED_SHELL.into(),
            home: REQUIRED_HOME.into(),
            password_field: "!".into(),
            supplementary_groups: Vec::new(),
        }
    }

    /// The positive control: the account the enrolment creates is accepted.
    #[test]
    fn the_account_this_palier_creates_is_locked_and_passwordless() {
        let account = judge(&locked()).expect("the positive control must be accepted");
        assert_eq!(account.name(), AUXILIARY_ACCOUNT);
        assert_eq!(account.uid(), 991);
        assert_eq!(account.gid(), 991);
    }

    /// Every shadow field that means "no password exists" is accepted, and
    /// nothing else is.
    #[test]
    fn only_the_fields_that_mean_no_password_exists_are_accepted() {
        for field in LOCKED_WITHOUT_PASSWORD {
            let observed = ObservedAccount {
                password_field: field.into(),
                ..locked()
            };
            assert!(
                judge(&observed).is_ok(),
                "{field} means no password exists and must be accepted"
            );
        }
    }

    /// A locked hash is locked *and* carries a password. It is refused by its
    /// own name, because unlocking it is one command away.
    #[test]
    fn a_locked_hash_is_refused_as_a_password_rather_than_accepted_as_locked() {
        for field in ["!$6$salt$hash", "$6$salt$hash", "!!$y$j9T$abc"] {
            assert_eq!(
                judge(&ObservedAccount {
                    password_field: field.into(),
                    ..locked()
                }),
                Err(AccountRefusal::PasswordSet),
                "{field} carries a password"
            );
        }
    }

    /// The most dangerous field of all is the empty one, and it is refused as
    /// what it is rather than read as "no password".
    #[test]
    fn an_empty_shadow_field_is_refused_as_an_absent_authentication() {
        assert_eq!(
            judge(&ObservedAccount {
                password_field: String::new(),
                ..locked()
            }),
            Err(AccountRefusal::NoPasswordRequired)
        );
    }

    /// The interpreter of the one forced command is fixed. `nologin` is refused
    /// here too, and the LAB says why: `sshd` runs the forced command through
    /// the shell, so `nologin` disables the Auxiliary instead of hardening it.
    #[test]
    fn a_shell_other_than_the_fixed_one_is_refused_including_nologin() {
        for shell in [
            "/bin/bash",
            "/usr/sbin/nologin",
            "/bin/false",
            "/usr/bin/zsh",
        ] {
            assert_eq!(
                judge(&ObservedAccount {
                    shell: shell.into(),
                    ..locked()
                }),
                Err(AccountRefusal::ShellIsNotTheFixedOne {
                    shell: shell.into()
                })
            );
        }
    }

    /// A home is somewhere a startup file can live. The account is given one
    /// that does not exist, and any other value is refused.
    #[test]
    fn a_home_the_account_could_read_a_startup_file_from_is_refused() {
        for home in [
            "/home/your-cloud-auxiliary",
            "/var/lib/your-cloud-auxiliary",
            "/",
        ] {
            assert_eq!(
                judge(&ObservedAccount {
                    home: home.into(),
                    ..locked()
                }),
                Err(AccountRefusal::HomeIsNotTheAbsentOne { home: home.into() })
            );
        }
    }

    /// The Auxiliary is not the Daemon, the Relay or the Controller, and the
    /// refusal says which role was being reused.
    #[test]
    fn the_account_of_another_role_is_refused_by_the_role_it_belongs_to() {
        for role in ROLE_ACCOUNTS {
            assert_eq!(
                judge(&ObservedAccount {
                    name: role.into(),
                    ..locked()
                }),
                Err(AccountRefusal::SharesARoleAccount { role: role.into() })
            );
        }
    }

    /// `root` is refused whether it arrives by name or by identifier.
    #[test]
    fn root_is_refused_by_identifier_as_well_as_by_name() {
        assert_eq!(
            judge(&ObservedAccount { uid: 0, ..locked() }),
            Err(AccountRefusal::IsRoot)
        );
        assert_eq!(
            judge(&ObservedAccount { gid: 0, ..locked() }),
            Err(AccountRefusal::IsRoot)
        );
        assert_eq!(
            judge(&ObservedAccount {
                name: "root".into(),
                ..locked()
            }),
            Err(AccountRefusal::NotTheAuxiliaryAccount {
                name: "root".into()
            })
        );
    }

    /// An ordinary user identifier puts the technical account in the range
    /// humans are created from.
    #[test]
    fn an_ordinary_user_identifier_is_refused() {
        assert_eq!(
            judge(&ObservedAccount {
                uid: MAX_SYSTEM_UID + 1,
                ..locked()
            }),
            Err(AccountRefusal::NotASystemAccount {
                uid: MAX_SYSTEM_UID + 1
            })
        );
    }

    /// A supplementary group is a right the enrolment did not grant, and it is
    /// refused by the group that carries it.
    #[test]
    fn a_supplementary_group_is_refused_by_name() {
        for group in ["sudo", "adm", "docker"] {
            assert_eq!(
                judge(&ObservedAccount {
                    supplementary_groups: vec![group.into()],
                    ..locked()
                }),
                Err(AccountRefusal::SupplementaryGroup {
                    group: group.into()
                })
            );
        }
    }
}
