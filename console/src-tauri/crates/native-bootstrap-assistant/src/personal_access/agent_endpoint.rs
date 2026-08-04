//! Admissibility of the personal SSH agent endpoint.
//!
//! An SSH agent is a signing oracle. Pointing the helper at the wrong one does
//! not leak the private key — the agent never exports it — but it does decide
//! *which identity* the target ends up authenticating. An access attested
//! against an attacker's identity would be an access the user does not
//! actually hold, so the endpoint is chosen under a closed rule rather than
//! taken from the environment as-is.
//!
//! The decision is kept separate from the system read: [`accept_linux_endpoint`]
//! judges an [`ObservedSocket`] without touching the filesystem, which keeps
//! every rule testable without a live agent, while [`observe_linux_endpoint`]
//! performs the one environment read and the two `lstat` calls that produce
//! such an observation on a real machine.
//!
//! Windows is split the same way. [`accept_windows_endpoint`] judges an
//! [`ObservedPipeServer`] and touches nothing; the module `agent_pipe` opens
//! the fixed pipe and produces such an observation from the live system, one
//! platform over. A named pipe is squattable by name alone, so the name is
//! worth nothing on its own — but the *object* behind the name is not a
//! filesystem entry and yet does carry an owner, written by the kernel from the
//! token of whoever created it. That owner is what carries the decision, and it
//! is the same question the Linux side asks of the socket. Where the serving
//! process can also be opened, its image and its own account are required to
//! agree; where it cannot — which is every account that is not an
//! administrator — the owner decides alone.

/// The single environment variable consulted on Linux. It is read once, and
/// no other variable can name an endpoint.
pub const LINUX_ENDPOINT_VARIABLE: &str = "SSH_AUTH_SOCK";

/// The single named pipe accepted on Windows at this palier.
pub const WINDOWS_PIPE_NAME: &str = r"\\.\pipe\openssh-ssh-agent";

/// The image, relative to this machine's system directory, that must be the
/// one serving the pipe: the OpenSSH Authentication Agent Windows ships.
///
/// It is kept relative on purpose. The absolute expectation is built from
/// `GetSystemDirectoryW` on the machine itself, so no drive letter and no
/// `Windows` directory name is ever assumed by this crate.
pub const WINDOWS_AGENT_IMAGE: &str = r"OpenSSH\ssh-agent.exe";

/// The account the agent runs as, and therefore the account that must own the
/// pipe object it created.
///
/// The OpenSSH Authentication Agent is registered as a `LocalSystem` service,
/// whose SID is fixed and identical on every Windows machine. A copy of the
/// same binary started by an ordinary account is therefore refused here even
/// though its image is genuine, which is exactly the point: the image says
/// *which* program serves the pipe, the account says *whose*.
///
/// The same SID answers two different questions, and both are asked below. As
/// the owner of the pipe object it says who *created* the endpoint, which is
/// readable by any account that may open the pipe at all. As the user of the
/// server's token it says who is *running* it, which needs a handle on that
/// process and is therefore only readable by an administrator.
pub const WINDOWS_AGENT_ACCOUNT: &str = "S-1-5-18";

/// Largest accepted endpoint path. A Unix socket path is itself bounded by
/// `sun_path`, which is 108 bytes on Linux including the terminator.
pub const MAX_ENDPOINT_PATH_BYTES: usize = 107;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointRefusal {
    Missing,
    Empty,
    /// The variable holds bytes that are not a valid string. A real endpoint
    /// path never is, and refusing keeps a lossy conversion from inventing one.
    NotUnicode,
    NotAbsolute,
    PathTooLong,
    InteriorNul,
    RelativeComponent,
    NotASocket,
    ForeignOwner,
    GroupOrWorldWritable,
    ForeignParentDirectory,
    ReplaceableParentDirectory,
    /// The path or its parent could not be observed at all.
    NotObservable,
    UnexpectedPipeName,
    /// The fixed pipe name answered nothing at all.
    PipeUnavailable,
    /// What answered under that name is not a named pipe.
    NotANamedPipe,
    /// Nothing could be learned about the endpoint at all: no server named, no
    /// owner readable on the pipe object, or a process handle that was obtained
    /// and then answered nothing. Being unable to look is a refusal, never a
    /// reason to proceed.
    ServerNotAttestable,
    /// The pipe object was created by an account that is not the one the
    /// OpenSSH agent service runs under.
    ForeignPipeOwner,
    /// The pipe is served by an image that is not the system OpenSSH agent.
    ForeignPipeServer,
    /// The system OpenSSH agent image is served by the wrong account.
    ForeignServerAccount,
    /// The pipe stopped being served by the attested process while it was
    /// being attested.
    ServerReplaced,
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

/// Reads the one environment variable and observes what it names.
///
/// This is the whole system side of the Linux endpoint: one `getenv`, one
/// `lstat` on the socket and one on its parent directory. `lstat` rather than
/// `stat` is deliberate — a symlink is reported as a symlink and therefore
/// refused as "not a socket", instead of letting the link's target smuggle in
/// a directory whose ownership was never examined.
///
/// The accepted path is returned so the caller connects to exactly what was
/// judged, never to a second reading of the variable.
#[cfg(target_os = "linux")]
pub fn observe_linux_endpoint() -> Result<String, EndpointRefusal> {
    let declared = std::env::var_os(LINUX_ENDPOINT_VARIABLE).ok_or(EndpointRefusal::Missing)?;
    let declared = declared.to_str().ok_or(EndpointRefusal::NotUnicode)?;
    // SAFETY: geteuid cannot fail and touches no memory.
    let current_uid = unsafe { libc::geteuid() };
    observe_declared_endpoint(declared, current_uid)
}

/// The observation itself, separated from the environment read so the system
/// side can be exercised against a real socket without mutating the process
/// environment while other tests run.
#[cfg(target_os = "linux")]
pub fn observe_declared_endpoint(
    declared: &str,
    current_uid: u32,
) -> Result<String, EndpointRefusal> {
    // The shape is checked first: everything below builds a C string from this
    // path, and only a bounded, absolute, NUL-free path may reach that step.
    check_path_shape(declared)?;
    let parent = parent_directory(declared).ok_or(EndpointRefusal::NotAbsolute)?;

    let socket = lstat(declared).ok_or(EndpointRefusal::NotObservable)?;
    let parent = lstat(parent).ok_or(EndpointRefusal::NotObservable)?;
    let observed = ObservedSocket {
        is_socket: socket.st_mode & libc::S_IFMT == libc::S_IFSOCK,
        owner_uid: socket.st_uid,
        mode: socket.st_mode & 0o7777,
        parent_owner_uid: parent.st_uid,
        parent_mode: parent.st_mode & 0o7777,
    };
    accept_linux_endpoint(Some(declared), observed, current_uid)?;
    Ok(declared.to_owned())
}

/// The directory containing `path`, for an already shape-checked absolute path.
fn parent_directory(path: &str) -> Option<&str> {
    let (parent, last) = path.rsplit_once('/')?;
    if last.is_empty() {
        // A trailing slash names a directory, never a socket.
        return None;
    }
    Some(if parent.is_empty() { "/" } else { parent })
}

#[cfg(target_os = "linux")]
fn lstat(path: &str) -> Option<libc::stat> {
    use std::{ffi::CString, mem::MaybeUninit};

    let path = CString::new(path).ok()?;
    let mut status = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: path is a live NUL-terminated string and status is valid, aligned
    // storage of exactly the size lstat writes.
    if unsafe { libc::lstat(path.as_ptr(), status.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: lstat returned success, so the storage is fully initialised.
    Some(unsafe { status.assume_init() })
}

/// What the caller observed about the process serving the candidate pipe.
///
/// Every field is a raw observation, never a verdict already taken: the two
/// paths are compared here rather than by whoever read them, so the comparison
/// itself is a rule this module owns and can be exercised without Windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservedPipeServer<'a> {
    /// The opened handle really is a named pipe rather than some other object
    /// reachable under the `\\.\pipe\` namespace.
    pub is_named_pipe: bool,
    /// Identifier the kernel reports for the process serving *this* instance.
    pub server_process_id: u32,
    /// String SID of the account that owns the pipe object itself, read from
    /// the handle already in hand.
    ///
    /// This is the fact every account can obtain: opening the pipe at all
    /// carries `READ_CONTROL`, and the owner of a kernel object is written by
    /// the kernel from the token of whoever created it. It is therefore what
    /// the decision below rests on.
    pub server_object_owner_sid: &'a str,
    /// What the serving process said about itself, when a handle on it could be
    /// obtained at all.
    ///
    /// `None` where it could not. Windows grants a handle on a `LocalSystem`
    /// process to `SYSTEM` and to administrators only, so an ordinary account —
    /// the account `ssh-agent` exists for — never obtains one. That is a
    /// missing *supplement*, not a missing attestation, and it is the only
    /// thing this type lets be missing.
    pub server_process: Option<ObservedServerProcess<'a>>,
    /// Fully normalised path of [`WINDOWS_AGENT_IMAGE`] under this machine's
    /// own system directory, read from the machine rather than assumed.
    pub system_agent_image_path: &'a str,
    /// The same process was still serving the same live pipe once every answer
    /// above had been collected.
    pub still_serving: bool,
}

/// What a handle on the serving process yielded, where one could be opened.
///
/// Both fields are read through the same handle, so either of them coming back
/// empty means the handle answered nothing rather than that the query was not
/// permitted — which is why an empty field here is a refusal while the whole
/// structure being absent is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservedServerProcess<'a> {
    /// Fully normalised image path of that process.
    pub image_path: &'a str,
    /// String SID of the account that process runs as.
    pub account_sid: &'a str,
}

/// Judges a Windows agent endpoint.
///
/// Only the fixed OpenSSH pipe is admissible, and only when the object behind
/// it was created by the account the OpenSSH agent service runs under. That
/// owner is the load-bearing check and it is never optional. Where a handle on
/// the serving process can also be obtained, two further facts are required of
/// it — the image it runs and the account it runs as — and any disagreement
/// there is fatal.
///
/// **What this attests.** The endpoint this session is connected to is a named
/// pipe object created by `LocalSystem`. The pipe namespace is flat and any
/// account may create a name into it, but no account may create an object owned
/// by a SID its token does not carry: an ordinary user's squatter is owned by
/// that user, and even an administrator's is owned by `Administrators`. So the
/// owner separates the service from an impostor, which the name alone never
/// did. Where the process could be opened as well, the bytes of this session
/// are additionally known to be answered by the file stored at the system
/// OpenSSH path, executed as `LocalSystem`.
///
/// **What this does not attest.** The owner says who *created* the object, not
/// which file is executing. On a machine where the serving process cannot be
/// opened — the ordinary case for a user who is not an administrator — this
/// decision does not distinguish the OpenSSH agent from another `LocalSystem`
/// service that took the name first. It also says nothing about *past* holders
/// of the name, nor that the identifier reported for the server was never
/// recycled; see [`ObservedPipeServer::still_serving`], which is how much of
/// that residue is closed and no more. An administrator holding
/// `SeRestorePrivilege` can stamp `LocalSystem` on an object it creates, so
/// this decision does not defend against an administrator — but an
/// administrator can replace the agent's own image, so nothing at this layer
/// could.
pub fn accept_windows_endpoint(
    declared: &str,
    observed: ObservedPipeServer<'_>,
) -> Result<(), EndpointRefusal> {
    if declared != WINDOWS_PIPE_NAME {
        return Err(EndpointRefusal::UnexpectedPipeName);
    }
    if !observed.is_named_pipe {
        return Err(EndpointRefusal::NotANamedPipe);
    }
    // A missing answer is never an acceptable one: an identifier of zero, an
    // unreadable owner, or a machine that cannot name its own agent image all
    // mean the same thing, which is that nothing was attested.
    if observed.server_process_id == 0
        || observed.server_object_owner_sid.is_empty()
        || observed.system_agent_image_path.is_empty()
    {
        return Err(EndpointRefusal::ServerNotAttestable);
    }
    if observed.server_object_owner_sid != WINDOWS_AGENT_ACCOUNT {
        return Err(EndpointRefusal::ForeignPipeOwner);
    }
    // Absent, this supplement costs nothing. Present, it is held to the same
    // standard as before: a handle that was opened and then answered nothing is
    // a failed attestation, not an absent one.
    if let Some(process) = observed.server_process {
        if process.image_path.is_empty() || process.account_sid.is_empty() {
            return Err(EndpointRefusal::ServerNotAttestable);
        }
        if !same_windows_path(process.image_path, observed.system_agent_image_path) {
            return Err(EndpointRefusal::ForeignPipeServer);
        }
        if process.account_sid != WINDOWS_AGENT_ACCOUNT {
            return Err(EndpointRefusal::ForeignServerAccount);
        }
    }
    if !observed.still_serving {
        return Err(EndpointRefusal::ServerReplaced);
    }
    Ok(())
}

/// Compares two already normalised Windows paths.
///
/// Both sides are expected to come out of `GetFinalPathNameByHandleW`, which
/// resolves short `8.3` names, symbolic links, junctions and mount points and
/// renders the name the volume itself stores. What remains between two such
/// paths is the case, which the filesystem does not distinguish.
///
/// The fold is ASCII-only and deliberately so: a byte this process cannot fold
/// with certainty is a byte it refuses to declare equal, which fails closed on
/// a system directory whose name is not plain ASCII.
fn same_windows_path(observed: &str, expected: &str) -> bool {
    observed.eq_ignore_ascii_case(expected)
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

    const SYSTEM_AGENT: &str = r"C:\Windows\System32\OpenSSH\ssh-agent.exe";

    /// The shape an administrator observes: the owner, plus the two facts a
    /// handle on the serving process yields.
    fn attested_server() -> ObservedPipeServer<'static> {
        ObservedPipeServer {
            is_named_pipe: true,
            server_process_id: 608,
            server_object_owner_sid: WINDOWS_AGENT_ACCOUNT,
            server_process: Some(ObservedServerProcess {
                image_path: SYSTEM_AGENT,
                account_sid: WINDOWS_AGENT_ACCOUNT,
            }),
            system_agent_image_path: SYSTEM_AGENT,
            still_serving: true,
        }
    }

    /// The shape an account with no administrative right observes: the owner,
    /// and nothing about the process, because Windows refuses it a handle on a
    /// `LocalSystem` service. Measured on Windows Server 2025 under a plain
    /// member of `Users`: `OpenProcess` fails with `ERROR_ACCESS_DENIED` for
    /// `PROCESS_QUERY_INFORMATION` and for `PROCESS_QUERY_LIMITED_INFORMATION`
    /// alike, while the owner of the pipe object reads back as `S-1-5-18`.
    fn attested_without_privilege() -> ObservedPipeServer<'static> {
        ObservedPipeServer {
            server_process: None,
            ..attested_server()
        }
    }

    /// An unprivileged squatter: a real pipe, alive, named right, and created
    /// by an ordinary account.
    const SQUATTER: &str = "S-1-5-21-1830930052-45202436-2080648262-1002";

    #[test]
    fn only_the_fixed_openssh_pipe_is_accepted_on_windows() {
        assert_eq!(
            accept_windows_endpoint(WINDOWS_PIPE_NAME, attested_server()),
            Ok(())
        );
        assert_eq!(
            accept_windows_endpoint(WINDOWS_PIPE_NAME, attested_without_privilege()),
            Ok(()),
            "an account that cannot open the server process still holds an endpoint",
        );
        for hostile in [
            r"\\.\pipe\openssh-ssh-agent-evil",
            r"\\.\pipe\OpenSSH-SSH-Agent",
            r"\\attacker\pipe\openssh-ssh-agent",
            r"\\.\pipe\ssh-agent",
            "",
        ] {
            assert_eq!(
                accept_windows_endpoint(hostile, attested_server()),
                Err(EndpointRefusal::UnexpectedPipeName),
                "{hostile:?} must fail closed"
            );
        }
    }

    /// The name is the cheap half. A listener that took the right name but is
    /// served by anything other than the system agent is refused, and so is a
    /// server nothing could be learned about.
    #[test]
    fn a_pipe_served_by_anything_but_the_system_openssh_agent_is_refused() {
        for (case, observed, expected) in [
            (
                "not a pipe at all",
                ObservedPipeServer {
                    is_named_pipe: false,
                    ..attested_server()
                },
                EndpointRefusal::NotANamedPipe,
            ),
            (
                "no server named",
                ObservedPipeServer {
                    server_process_id: 0,
                    ..attested_server()
                },
                EndpointRefusal::ServerNotAttestable,
            ),
            (
                "the owner of the pipe object unreadable",
                ObservedPipeServer {
                    server_object_owner_sid: "",
                    ..attested_server()
                },
                EndpointRefusal::ServerNotAttestable,
            ),
            (
                "no system agent on this machine",
                ObservedPipeServer {
                    system_agent_image_path: "",
                    ..attested_server()
                },
                EndpointRefusal::ServerNotAttestable,
            ),
            (
                "a handle on the server that then answered no image",
                ObservedPipeServer {
                    server_process: Some(ObservedServerProcess {
                        image_path: "",
                        account_sid: WINDOWS_AGENT_ACCOUNT,
                    }),
                    ..attested_server()
                },
                EndpointRefusal::ServerNotAttestable,
            ),
            (
                "a handle on the server that then answered no account",
                ObservedPipeServer {
                    server_process: Some(ObservedServerProcess {
                        image_path: SYSTEM_AGENT,
                        account_sid: "",
                    }),
                    ..attested_server()
                },
                EndpointRefusal::ServerNotAttestable,
            ),
            (
                "an impostor of its own",
                ObservedPipeServer {
                    server_process: Some(ObservedServerProcess {
                        image_path: r"C:\Users\victim\AppData\Local\Temp\ssh-agent.exe",
                        account_sid: WINDOWS_AGENT_ACCOUNT,
                    }),
                    ..attested_server()
                },
                EndpointRefusal::ForeignPipeServer,
            ),
            (
                "the genuine image somewhere else",
                ObservedPipeServer {
                    server_process: Some(ObservedServerProcess {
                        image_path: r"C:\Tools\OpenSSH\ssh-agent.exe",
                        account_sid: WINDOWS_AGENT_ACCOUNT,
                    }),
                    ..attested_server()
                },
                EndpointRefusal::ForeignPipeServer,
            ),
            (
                "the genuine image under an ordinary account",
                ObservedPipeServer {
                    server_process: Some(ObservedServerProcess {
                        image_path: SYSTEM_AGENT,
                        account_sid: "S-1-5-21-1000-1000-1000-1001",
                    }),
                    ..attested_server()
                },
                EndpointRefusal::ForeignServerAccount,
            ),
            (
                "the network service, which is not LocalSystem",
                ObservedPipeServer {
                    server_process: Some(ObservedServerProcess {
                        image_path: SYSTEM_AGENT,
                        account_sid: "S-1-5-20",
                    }),
                    ..attested_server()
                },
                EndpointRefusal::ForeignServerAccount,
            ),
            (
                "the server left while it was being attested",
                ObservedPipeServer {
                    still_serving: false,
                    ..attested_server()
                },
                EndpointRefusal::ServerReplaced,
            ),
        ] {
            assert_eq!(
                accept_windows_endpoint(WINDOWS_PIPE_NAME, observed),
                Err(expected),
                "{case} must fail closed"
            );
        }
    }

    /// The filesystem does not distinguish the case of a path, so neither may
    /// the comparison; everything else must still differ.
    /// The whole point of the owner: it is the one fact an account without any
    /// administrative right can still read, and it must still refuse a
    /// squatter. Every case below is a live, well-named pipe whose server is
    /// simply beyond reach — which is exactly the position an ordinary user is
    /// in, and where a rule that gave up would be a name comparison in
    /// disguise.
    #[test]
    fn without_a_handle_on_the_server_the_owner_alone_still_refuses_a_squatter() {
        for (case, owner) in [
            ("an ordinary account that took the name first", SQUATTER),
            ("an elevated administrator's squatter", "S-1-5-32-544"),
            ("the network service", "S-1-5-20"),
            ("the local service", "S-1-5-19"),
            ("everyone", "S-1-1-0"),
        ] {
            assert_eq!(
                accept_windows_endpoint(
                    WINDOWS_PIPE_NAME,
                    ObservedPipeServer {
                        server_object_owner_sid: owner,
                        ..attested_without_privilege()
                    }
                ),
                Err(EndpointRefusal::ForeignPipeOwner),
                "{case} must fail closed"
            );
        }
        assert_eq!(
            accept_windows_endpoint(
                WINDOWS_PIPE_NAME,
                ObservedPipeServer {
                    server_object_owner_sid: "",
                    ..attested_without_privilege()
                }
            ),
            Err(EndpointRefusal::ServerNotAttestable),
            "an owner that could not be read leaves nothing to judge",
        );
    }

    /// The owner is required of the privileged path too. Reading the image and
    /// the token must never excuse an object somebody else created — the two
    /// checks accumulate, they do not stand in for one another.
    #[test]
    fn a_readable_server_process_never_excuses_a_foreign_owner() {
        assert_eq!(
            accept_windows_endpoint(
                WINDOWS_PIPE_NAME,
                ObservedPipeServer {
                    server_object_owner_sid: SQUATTER,
                    ..attested_server()
                }
            ),
            Err(EndpointRefusal::ForeignPipeOwner),
        );
    }

    #[test]
    fn the_system_image_is_compared_without_case_and_without_charity() {
        let shouting = ObservedPipeServer {
            server_process: Some(ObservedServerProcess {
                image_path: r"C:\WINDOWS\SYSTEM32\OPENSSH\SSH-AGENT.EXE",
                account_sid: WINDOWS_AGENT_ACCOUNT,
            }),
            ..attested_server()
        };
        assert_eq!(accept_windows_endpoint(WINDOWS_PIPE_NAME, shouting), Ok(()));

        for near_miss in [
            r"C:\Windows\System32\OpenSSH\ssh-agent.exe ",
            r"C:\Windows\System32\OpenSSH\ssh-agent.ex",
            r"C:\Windows\System32\OpenSSH\ssh-agent.exe.exe",
            r"D:\Windows\System32\OpenSSH\ssh-agent.exe",
            r"C:\Windows\System32\OpenSSH\..\OpenSSH\ssh-agent.exe",
        ] {
            assert_eq!(
                accept_windows_endpoint(
                    WINDOWS_PIPE_NAME,
                    ObservedPipeServer {
                        server_process: Some(ObservedServerProcess {
                            image_path: near_miss,
                            account_sid: WINDOWS_AGENT_ACCOUNT,
                        }),
                        ..attested_server()
                    }
                ),
                Err(EndpointRefusal::ForeignPipeServer),
                "{near_miss:?} must fail closed"
            );
        }
    }

    #[test]
    fn the_attested_windows_server_is_named_once_and_for_all() {
        assert_eq!(WINDOWS_PIPE_NAME, r"\\.\pipe\openssh-ssh-agent");
        assert_eq!(WINDOWS_AGENT_IMAGE, r"OpenSSH\ssh-agent.exe");
        assert_eq!(WINDOWS_AGENT_ACCOUNT, "S-1-5-18");
        assert!(
            !WINDOWS_AGENT_IMAGE.contains(':'),
            "the expectation must stay relative to the machine's system directory"
        );
    }

    #[test]
    fn only_one_environment_variable_can_ever_name_an_endpoint() {
        assert_eq!(LINUX_ENDPOINT_VARIABLE, "SSH_AUTH_SOCK");
    }

    #[test]
    fn the_parent_directory_of_an_endpoint_is_derived_without_touching_the_filesystem() {
        assert_eq!(
            parent_directory("/tmp/ssh-abc/agent.1"),
            Some("/tmp/ssh-abc")
        );
        assert_eq!(parent_directory("/agent.sock"), Some("/"));
        assert_eq!(
            parent_directory("/tmp/ssh-abc/"),
            None,
            "a trailing slash names a directory, never a socket"
        );
        assert_eq!(parent_directory("agent.sock"), None);
    }

    #[cfg(target_os = "linux")]
    mod system {
        use super::*;
        use std::{
            fs,
            os::unix::{fs::PermissionsExt, net::UnixListener},
            path::PathBuf,
        };

        /// A private directory of this test process, named after the running
        /// process and the case so parallel tests never collide.
        fn private_directory(case: &str) -> PathBuf {
            let directory = std::env::temp_dir()
                .join(format!("your-cloud-endpoint-{}-{case}", std::process::id()));
            let _ = fs::remove_dir_all(&directory);
            fs::create_dir(&directory).expect("private directory");
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("private mode");
            directory
        }

        fn current_uid() -> u32 {
            // SAFETY: geteuid cannot fail and touches no memory.
            unsafe { libc::geteuid() }
        }

        /// The shape a live `ssh-agent` produces, observed for real: a socket
        /// this user owns, inside a `0700` directory this user owns.
        #[test]
        fn a_real_socket_in_a_private_directory_is_observed_and_accepted() {
            let directory = private_directory("accepted");
            let path = directory.join("agent.sock");
            let listener = UnixListener::bind(&path).expect("bound socket");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("socket mode");
            let declared = path.to_str().expect("ascii path").to_owned();

            assert_eq!(
                observe_declared_endpoint(&declared, current_uid()),
                Ok(declared.clone()),
                "the accepted path is returned so the caller never re-reads the variable"
            );

            drop(listener);
            let _ = fs::remove_dir_all(&directory);
        }

        #[test]
        fn a_regular_file_a_symlink_and_an_absent_path_all_fail_closed() {
            let directory = private_directory("refused");
            let uid = current_uid();

            let regular = directory.join("not-a-socket");
            fs::write(&regular, b"").expect("regular file");
            assert_eq!(
                observe_declared_endpoint(regular.to_str().unwrap(), uid),
                Err(EndpointRefusal::NotASocket)
            );

            let socket = directory.join("agent.sock");
            let listener = UnixListener::bind(&socket).expect("bound socket");
            let link = directory.join("agent.link");
            std::os::unix::fs::symlink(&socket, &link).expect("symlink");
            assert_eq!(
                observe_declared_endpoint(link.to_str().unwrap(), uid),
                Err(EndpointRefusal::NotASocket),
                "lstat reports the link itself, so no link may stand in for a socket"
            );

            let absent = directory.join("never-created");
            assert_eq!(
                observe_declared_endpoint(absent.to_str().unwrap(), uid),
                Err(EndpointRefusal::NotObservable)
            );

            assert_eq!(
                observe_declared_endpoint(socket.to_str().unwrap(), uid + 1),
                Err(EndpointRefusal::ForeignOwner),
                "a socket this user does not own is another account's agent"
            );

            drop(listener);
            let _ = fs::remove_dir_all(&directory);
        }

        /// A socket this user owns is still refused when the directory holding
        /// it can be rearranged by someone else.
        #[test]
        fn a_replaceable_directory_is_refused_even_around_a_real_socket() {
            let directory = private_directory("exposed");
            let path = directory.join("agent.sock");
            let listener = UnixListener::bind(&path).expect("bound socket");
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o777))
                .expect("exposed mode");

            assert_eq!(
                observe_declared_endpoint(path.to_str().unwrap(), current_uid()),
                Err(EndpointRefusal::ReplaceableParentDirectory)
            );

            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("restore mode");
            drop(listener);
            let _ = fs::remove_dir_all(&directory);
        }
    }
}
