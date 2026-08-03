//! Admissibility of the personal SSH agent endpoint.
//!
//! An SSH agent is a signing oracle. Pointing the helper at the wrong one does
//! not leak the private key — the agent never exports it — but it does decide
//! *which identity* the target ends up authenticating. An access attested
//! against an attacker's identity would be an access the user does not
//! actually hold, so the endpoint is chosen under a closed rule rather than
//! taken from the environment as-is.
//!
//! The decision is kept separate from the system read: the caller performs the
//! `stat` or the pipe lookup, this module judges the result. That keeps the
//! rule testable without a live agent.

/// The single environment variable consulted on Linux. It is read once, and
/// no other variable can name an endpoint.
pub const LINUX_ENDPOINT_VARIABLE: &str = "SSH_AUTH_SOCK";

/// The single named pipe accepted on Windows for `v0.1.0`.
pub const WINDOWS_PIPE_NAME: &str = r"\\.\pipe\openssh-ssh-agent";

/// Largest accepted endpoint path. A Unix socket path is itself bounded by
/// `sun_path`, which is 108 bytes on Linux including the terminator.
pub const MAX_ENDPOINT_PATH_BYTES: usize = 107;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointRefusal {
    Missing,
    Empty,
    NotAbsolute,
    PathTooLong,
    InteriorNul,
    RelativeComponent,
    NotASocket,
    ForeignOwner,
    GroupOrWorldWritable,
    ForeignParentDirectory,
    ReplaceableParentDirectory,
    UnexpectedPipeName,
}

/// Permission bit meaning "only the owner may unlink an entry here".
const STICKY: u32 = 0o1000;

/// What the caller observed about the candidate socket and its directory.
///
/// The parent matters as much as the socket. A real `ssh-agent` places a
/// `0600` socket inside a `0700` directory of its own precisely because the
/// socket's own mode does not stop another account from unlinking it and
/// binding a replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservedSocket {
    pub is_socket: bool,
    pub owner_uid: u32,
    /// Permission bits of the socket itself, as reported by `stat`.
    pub mode: u32,
    pub parent_owner_uid: u32,
    /// Permission bits of the containing directory, sticky bit included.
    pub parent_mode: u32,
}

/// Judges a Linux agent endpoint.
///
/// `declared` is the raw value of [`LINUX_ENDPOINT_VARIABLE`], `observed` what
/// the caller's `stat` returned, and `current_uid` the effective user.
pub fn accept_linux_endpoint(
    declared: Option<&str>,
    observed: ObservedSocket,
    current_uid: u32,
) -> Result<(), EndpointRefusal> {
    let path = declared.ok_or(EndpointRefusal::Missing)?;
    check_path_shape(path)?;
    if !observed.is_socket {
        return Err(EndpointRefusal::NotASocket);
    }
    // A socket owned by anyone else is another user's agent, or a plant.
    if observed.owner_uid != current_uid {
        return Err(EndpointRefusal::ForeignOwner);
    }
    // Group or world writability would let a second account replace the
    // listener between the check and the connection.
    if observed.mode & 0o022 != 0 {
        return Err(EndpointRefusal::GroupOrWorldWritable);
    }
    // A directory owned by someone else can be rearranged under us.
    if observed.parent_owner_uid != current_uid && observed.parent_owner_uid != 0 {
        return Err(EndpointRefusal::ForeignParentDirectory);
    }
    // A writable directory allows unlink-and-rebind whatever the socket's own
    // mode says. The sticky bit is what makes a shared directory such as
    // `/tmp` acceptable, since only the owner may then remove the entry.
    if observed.parent_mode & 0o022 != 0 && observed.parent_mode & STICKY == 0 {
        return Err(EndpointRefusal::ReplaceableParentDirectory);
    }
    Ok(())
}

fn check_path_shape(path: &str) -> Result<(), EndpointRefusal> {
    if path.is_empty() {
        return Err(EndpointRefusal::Empty);
    }
    if path.len() > MAX_ENDPOINT_PATH_BYTES {
        return Err(EndpointRefusal::PathTooLong);
    }
    if path.contains('\0') {
        return Err(EndpointRefusal::InteriorNul);
    }
    if !path.starts_with('/') {
        return Err(EndpointRefusal::NotAbsolute);
    }
    // `..` would let a path that looks anchored escape elsewhere.
    if path
        .split('/')
        .any(|component| component == ".." || component == ".")
    {
        return Err(EndpointRefusal::RelativeComponent);
    }
    Ok(())
}

/// Judges a Windows agent endpoint. Only the fixed OpenSSH pipe is admissible;
/// attesting the process that serves it belongs to the transport pass.
pub fn accept_windows_pipe(declared: &str) -> Result<(), EndpointRefusal> {
    if declared == WINDOWS_PIPE_NAME {
        Ok(())
    } else {
        Err(EndpointRefusal::UnexpectedPipeName)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: u32 = 1000;

    fn owned_socket() -> ObservedSocket {
        ObservedSocket {
            is_socket: true,
            owner_uid: OWNER,
            mode: 0o600,
            parent_owner_uid: OWNER,
            parent_mode: 0o700,
        }
    }

    #[test]
    fn a_socket_owned_by_the_current_user_is_accepted() {
        assert_eq!(
            accept_linux_endpoint(Some("/run/user/1000/keyring/ssh"), owned_socket(), OWNER),
            Ok(())
        );
    }

    /// Shape observed from a live `ssh-agent` on Debian 13: a `0600` socket in
    /// a `0700` private directory under the world-writable `/tmp`.
    #[test]
    fn the_shape_a_real_ssh_agent_produces_is_accepted() {
        let observed = ObservedSocket {
            is_socket: true,
            owner_uid: OWNER,
            mode: 0o600,
            parent_owner_uid: OWNER,
            parent_mode: 0o700,
        };
        assert_eq!(
            accept_linux_endpoint(Some("/tmp/ssh-XCHONwh95oKd/agent.6737"), observed, OWNER),
            Ok(())
        );
    }

    #[test]
    fn a_directory_another_account_could_rearrange_is_refused() {
        // A socket dropped straight into a non-sticky world-writable directory
        // can be unlinked and rebound by anyone, whatever its own mode.
        let exposed = ObservedSocket {
            parent_owner_uid: 0,
            parent_mode: 0o777,
            ..owned_socket()
        };
        assert_eq!(
            accept_linux_endpoint(Some("/shared/agent.sock"), exposed, OWNER),
            Err(EndpointRefusal::ReplaceableParentDirectory)
        );

        // `/tmp` itself is world-writable but sticky, so only the owner may
        // remove the entry.
        let sticky = ObservedSocket {
            parent_owner_uid: 0,
            parent_mode: 0o1777,
            ..owned_socket()
        };
        assert_eq!(
            accept_linux_endpoint(Some("/tmp/agent.sock"), sticky, OWNER),
            Ok(())
        );

        let foreign_parent = ObservedSocket {
            parent_owner_uid: OWNER + 1,
            parent_mode: 0o700,
            ..owned_socket()
        };
        assert_eq!(
            accept_linux_endpoint(Some("/home/other/agent.sock"), foreign_parent, OWNER),
            Err(EndpointRefusal::ForeignParentDirectory)
        );
    }

    #[test]
    fn an_absent_or_empty_variable_yields_no_endpoint() {
        assert_eq!(
            accept_linux_endpoint(None, owned_socket(), OWNER),
            Err(EndpointRefusal::Missing)
        );
        assert_eq!(
            accept_linux_endpoint(Some(""), owned_socket(), OWNER),
            Err(EndpointRefusal::Empty)
        );
    }

    #[test]
    fn a_path_that_is_not_a_plain_absolute_path_is_refused() {
        for (path, expected) in [
            ("run/user/1000/ssh", EndpointRefusal::NotAbsolute),
            ("./ssh", EndpointRefusal::NotAbsolute),
            ("/run/../tmp/ssh", EndpointRefusal::RelativeComponent),
            ("/run/./ssh", EndpointRefusal::RelativeComponent),
            ("/run/ssh\0/evil", EndpointRefusal::InteriorNul),
        ] {
            assert_eq!(
                accept_linux_endpoint(Some(path), owned_socket(), OWNER),
                Err(expected),
                "{path:?} must fail closed"
            );
        }
        let long = format!("/{}", "a".repeat(MAX_ENDPOINT_PATH_BYTES));
        assert_eq!(
            accept_linux_endpoint(Some(&long), owned_socket(), OWNER),
            Err(EndpointRefusal::PathTooLong)
        );
    }

    #[test]
    fn an_endpoint_that_is_not_a_socket_is_refused() {
        let regular = ObservedSocket {
            is_socket: false,
            ..owned_socket()
        };
        assert_eq!(
            accept_linux_endpoint(Some("/run/user/1000/ssh"), regular, OWNER),
            Err(EndpointRefusal::NotASocket)
        );
    }

    #[test]
    fn another_users_agent_is_never_borrowed() {
        let foreign = ObservedSocket {
            owner_uid: OWNER + 1,
            ..owned_socket()
        };
        assert_eq!(
            accept_linux_endpoint(Some("/run/user/1001/ssh"), foreign, OWNER),
            Err(EndpointRefusal::ForeignOwner)
        );
        let root_owned = ObservedSocket {
            owner_uid: 0,
            ..owned_socket()
        };
        assert_eq!(
            accept_linux_endpoint(Some("/run/ssh"), root_owned, OWNER),
            Err(EndpointRefusal::ForeignOwner)
        );
    }

    #[test]
    fn a_socket_a_second_account_could_replace_is_refused() {
        for mode in [0o620, 0o602, 0o666, 0o777] {
            let writable = ObservedSocket {
                mode,
                ..owned_socket()
            };
            assert_eq!(
                accept_linux_endpoint(Some("/run/user/1000/ssh"), writable, OWNER),
                Err(EndpointRefusal::GroupOrWorldWritable),
                "mode {mode:o} must fail closed"
            );
        }
        for mode in [0o600, 0o644, 0o755] {
            let tight = ObservedSocket {
                mode,
                ..owned_socket()
            };
            assert_eq!(
                accept_linux_endpoint(Some("/run/user/1000/ssh"), tight, OWNER),
                Ok(()),
                "mode {mode:o} is not writable by another account"
            );
        }
    }

    #[test]
    fn only_the_fixed_openssh_pipe_is_accepted_on_windows() {
        assert_eq!(accept_windows_pipe(WINDOWS_PIPE_NAME), Ok(()));
        for hostile in [
            r"\\.\pipe\openssh-ssh-agent-evil",
            r"\\.\pipe\OpenSSH-SSH-Agent",
            r"\\attacker\pipe\openssh-ssh-agent",
            r"\\.\pipe\ssh-agent",
            "",
        ] {
            assert_eq!(
                accept_windows_pipe(hostile),
                Err(EndpointRefusal::UnexpectedPipeName),
                "{hostile:?} must fail closed"
            );
        }
    }

    #[test]
    fn only_one_environment_variable_can_ever_name_an_endpoint() {
        assert_eq!(LINUX_ENDPOINT_VARIABLE, "SSH_AUTH_SOCK");
    }
}
