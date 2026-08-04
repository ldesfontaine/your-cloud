//! Real opening of the Windows agent pipe, and attestation of its server.
//!
//! On Linux the agent endpoint is a filesystem entry, and what makes it
//! trustworthy is written on the entry itself: its type, its owner, the
//! directory holding it. A Windows named pipe carries none of that. Its name
//! lives in a flat namespace any account may create into, so
//! `\\.\pipe\openssh-ssh-agent` is not a place the OpenSSH agent owns — it is
//! a name it happened to take, and that another process can take first or take
//! beside it. Comparing the name alone therefore attests nothing at all.
//!
//! What can be attested is the *process* answering on the instance this
//! session is connected to. Three questions are asked of it, in this order,
//! and any one of them failing ends the endpoint:
//!
//! * which process serves this very instance — `GetNamedPipeServerProcessId`
//!   on the handle already opened, never a second lookup by name;
//! * which image that process is running — `QueryFullProcessImageNameW`,
//!   normalised through the filesystem and compared to
//!   [`WINDOWS_AGENT_IMAGE`] under this machine's own system directory;
//! * which account it is running as — the user of its token, compared to
//!   [`WINDOWS_AGENT_ACCOUNT`].
//!
//! **What this proves.** The bytes of this session are answered by the file
//! stored at the system OpenSSH path, executed by a process running as
//! `LocalSystem`. Both halves are needed and neither is enough: a genuine
//! `ssh-agent.exe` copied elsewhere is refused by the path, and the genuine
//! system image launched by an ordinary account — through a symbolic link, for
//! instance, which normalises back to the system path — is refused by the
//! account.
//!
//! **What this does not prove.** Reading the image path of a `LocalSystem`
//! service requires a handle on that process, which Windows grants to
//! `SYSTEM` and to administrators. Where the helper cannot obtain one the
//! attestation is impossible, and an impossible attestation is refused rather
//! than skipped: on such a machine this endpoint is simply unavailable. Nor
//! does it prove anything about *past* holders of the name; it describes the
//! server of the instance in hand, at the instant it was asked, plus the
//! re-check below.

use std::{
    io,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle},
    ptr::{null, null_mut},
    time::{Duration, Instant},
};

use tokio::{net::windows::named_pipe::NamedPipeClient, time::timeout};
use windows_sys::Win32::{
    Foundation::{
        GetLastError, LocalFree, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, GENERIC_READ,
        GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, MAX_PATH,
    },
    Security::{
        Authorization::ConvertSidToStringSidW, GetTokenInformation, TokenUser, PSID, TOKEN_QUERY,
        TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateFileW, GetFileType, GetFinalPathNameByHandleW, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OVERLAPPED, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_PIPE, OPEN_EXISTING, VOLUME_NAME_DOS,
    },
    System::{
        Pipes::{GetNamedPipeServerProcessId, PeekNamedPipe, WaitNamedPipeW},
        SystemInformation::GetSystemDirectoryW,
        Threading::{
            OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
            PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

use super::{
    agent_client::{AgentRefusal, PersonalAgent},
    agent_endpoint::{
        accept_windows_endpoint, EndpointRefusal, ObservedPipeServer, WINDOWS_AGENT_IMAGE,
        WINDOWS_PIPE_NAME,
    },
    signature_budget::OfferedIdentity,
};

/// Largest path this module will read back from the system, in UTF-16 units.
/// Windows caps an extended path at this many characters, terminator included.
const MAX_WIDE_PATH: usize = 32_768;

/// Longest the agent may take to answer the single identity listing. It is the
/// same ceiling the Linux session applies, for the same reason: an agent that
/// never answers must cost a bounded wait rather than the whole lease.
const AGENT_LIST_TIMEOUT: Duration = Duration::from_secs(2);

/// Longest the fixed name may take to offer an instance to connect to. It is
/// the ceiling the Linux session gives the socket connection, for the same
/// reason.
const AGENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// How often the name is tried again while it is held by nobody.
const PIPE_RETRY_INTERVAL: Duration = Duration::from_millis(20);

/// A connected agent pipe whose server has been attested.
///
/// The handle it carries is the one that was attested, and the only way to use
/// it is to turn it into the asynchronous stream the agent client reads: there
/// is deliberately no way to obtain an unattested pipe from this module, and
/// no second `CreateFileW` between the attestation and the conversation.
pub struct AttestedPipe {
    handle: OwnedHandle,
    server_process_id: u32,
    server_image_path: String,
    server_account_sid: String,
}

impl AttestedPipe {
    /// Identifier of the process serving this instance.
    pub fn server_process_id(&self) -> u32 {
        self.server_process_id
    }

    /// Normalised image path that process is running.
    pub fn server_image_path(&self) -> &str {
        &self.server_image_path
    }

    /// String SID of the account that process runs as.
    pub fn server_account_sid(&self) -> &str {
        &self.server_account_sid
    }

    /// Hands the attested handle to the asynchronous runtime.
    ///
    /// It must be called from inside a runtime with I/O enabled, which is what
    /// registers the handle for completion notifications.
    pub fn into_stream(self) -> io::Result<NamedPipeClient> {
        // SAFETY: the handle was opened here with FILE_FLAG_OVERLAPPED, has
        // never been read or written, and ownership passes with it.
        unsafe { NamedPipeClient::from_raw_handle(self.handle.into_raw_handle()) }
    }
}

/// Opens the one admissible Windows endpoint and attests its server.
pub fn observe_windows_endpoint() -> Result<AttestedPipe, EndpointRefusal> {
    observe_declared_pipe(WINDOWS_PIPE_NAME)
}

/// The observation itself, separated from the fixed name so the rule that only
/// one name is ever opened can be exercised against every other one.
///
/// A name that is not [`WINDOWS_PIPE_NAME`] is refused *before* anything is
/// opened: this function never touches a pipe the decision would refuse.
pub fn observe_declared_pipe(declared: &str) -> Result<AttestedPipe, EndpointRefusal> {
    if declared != WINDOWS_PIPE_NAME {
        return Err(EndpointRefusal::UnexpectedPipeName);
    }
    let handle = open_pipe(declared)?;
    let pipe = handle.as_raw_handle();

    // SAFETY: pipe is a live handle this function owns.
    let is_named_pipe = unsafe { GetFileType(pipe) } == FILE_TYPE_PIPE;
    let server_process_id = server_process_id(pipe).unwrap_or(0);
    let server = open_server_process(server_process_id);
    let server_image_path = server
        .as_ref()
        .and_then(|server| image_path(server.as_raw_handle()))
        .unwrap_or_default();
    let server_account_sid = server
        .as_ref()
        .and_then(|server| account_sid(server.as_raw_handle()))
        .unwrap_or_default();
    let system_agent_image_path = system_agent_image_path().unwrap_or_default();
    // Asked last, so it covers every query above: if the attested process had
    // died — the only way its identifier could be recycled — the instance it
    // served would be gone and this peek would fail.
    let still_serving = serves_the_same_process(pipe, server_process_id);

    accept_windows_endpoint(
        declared,
        ObservedPipeServer {
            is_named_pipe,
            server_process_id,
            server_image_path: &server_image_path,
            system_agent_image_path: &system_agent_image_path,
            server_account_sid: &server_account_sid,
            still_serving,
        },
    )?;

    Ok(AttestedPipe {
        handle,
        server_process_id,
        server_image_path,
        server_account_sid,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentPipeRefusal {
    Endpoint(EndpointRefusal),
    Agent(AgentRefusal),
    /// The session lease ran out before the agent answered.
    Expired,
}

/// Opens the attested pipe and asks the agent, once, what it holds.
///
/// This is the Windows counterpart of the Linux session's agent step, and it
/// hands back exactly the same two values, over the same bounded framing and
/// the same budget-bearing client. Unlike the Unix socket there is no connect
/// wait to bound: opening a named pipe either finds a server or does not.
pub async fn open_personal_agent(
    deadline: Instant,
) -> Result<(PersonalAgent<NamedPipeClient>, Vec<OfferedIdentity>), AgentPipeRefusal> {
    let attested = observe_windows_endpoint().map_err(AgentPipeRefusal::Endpoint)?;
    let stream = attested
        .into_stream()
        .map_err(|_| AgentPipeRefusal::Agent(AgentRefusal::ConnectionFailed))?;

    let mut agent = PersonalAgent::over(stream);
    let bail = deadline
        .saturating_duration_since(Instant::now())
        .min(AGENT_LIST_TIMEOUT);
    // An exhausted lease never starts the listing at all.
    if bail.is_zero() {
        return Err(AgentPipeRefusal::Expired);
    }
    let identities = match timeout(bail, agent.list_identities()).await {
        Ok(listed) => listed.map_err(AgentPipeRefusal::Agent)?,
        Err(_elapsed) if Instant::now() >= deadline => return Err(AgentPipeRefusal::Expired),
        Err(_elapsed) => return Err(AgentPipeRefusal::Agent(AgentRefusal::ProtocolFailed)),
    };
    Ok((agent, identities))
}

/// Opens the attested pipe on a runtime of its own and reports what the agent
/// holds.
///
/// It exists so the contract suite can exercise the whole Windows path — pipe
/// attested, handle handed to the runtime, bounded framing, one real agent
/// request — without a transport, since the frozen target the transport needs
/// has no Windows enumeration behind it yet.
///
/// Compiled in only under the contract feature: a release build keeps exactly
/// one way to reach the agent, which is [`open_personal_agent`].
#[cfg(feature = "windows-agent-pipe-contract-test")]
#[doc(hidden)]
pub fn list_identities_once(deadline: Instant) -> Result<Vec<OfferedIdentity>, AgentPipeRefusal> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| AgentPipeRefusal::Agent(AgentRefusal::ConnectionFailed))?;
    runtime.block_on(async {
        let (agent, identities) = open_personal_agent(deadline).await?;
        // The pipe is released inside the runtime that registered it.
        drop(agent);
        Ok(identities)
    })
}

/// Connects to the pipe, in overlapped mode so the runtime can drive it.
///
/// The OpenSSH agent serves one instance at a time and creates the next one
/// only after the previous has been taken, so the name is briefly held by
/// nobody between two clients. That window is waited out, and nothing else is:
/// only "no instance right now" and "every instance busy" are retried, for at
/// most [`AGENT_CONNECT_TIMEOUT`]. A refused access, in particular, is final.
fn open_pipe(name: &str) -> Result<OwnedHandle, EndpointRefusal> {
    let wide_name = wide(name).ok_or(EndpointRefusal::InteriorNul)?;
    let deadline = Instant::now() + AGENT_CONNECT_TIMEOUT;
    loop {
        // SAFETY: wide_name is a live NUL-terminated wide string; every other
        // argument is a constant or a null pointer the call accepts.
        let raw = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        if !raw.is_null() && raw != INVALID_HANDLE_VALUE {
            // SAFETY: raw is a fresh handle nothing else owns.
            return Ok(unsafe { OwnedHandle::from_raw_handle(raw) });
        }
        // SAFETY: the call reads the failure this thread just produced.
        let failure = unsafe { GetLastError() };
        if failure != ERROR_FILE_NOT_FOUND && failure != ERROR_PIPE_BUSY {
            return Err(EndpointRefusal::PipeUnavailable);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(EndpointRefusal::PipeUnavailable);
        }
        if failure == ERROR_PIPE_BUSY {
            // SAFETY: wide_name is a live NUL-terminated wide string.
            let _ = unsafe { WaitNamedPipeW(wide_name.as_ptr(), millis(left)) };
        } else {
            std::thread::sleep(PIPE_RETRY_INTERVAL.min(left));
        }
    }
}

/// Milliseconds a bounded Win32 wait accepts, never the "wait forever" value.
fn millis(duration: Duration) -> u32 {
    u32::try_from(duration.as_millis())
        .unwrap_or(u32::MAX - 1)
        .max(1)
}

/// The process serving *this* instance, as the kernel recorded it.
fn server_process_id(pipe: HANDLE) -> Option<u32> {
    let mut process_id = 0_u32;
    // SAFETY: pipe is a live handle and process_id is valid output storage.
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut process_id) } == 0 || process_id == 0 {
        return None;
    }
    Some(process_id)
}

/// Opens the serving process for query only.
///
/// The wider right is tried first because it implies the narrower one and is
/// what an administrator holds over a `LocalSystem` service; the narrower one
/// is the fallback. Neither grants memory access, and no other right is asked
/// for: this process needs to read two facts, not to touch the agent.
fn open_server_process(process_id: u32) -> Option<OwnedHandle> {
    if process_id == 0 {
        return None;
    }
    for rights in [PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION] {
        // SAFETY: the call takes no memory and reports failure by a null handle.
        let raw = unsafe { OpenProcess(rights, 0, process_id) };
        if !raw.is_null() && raw != INVALID_HANDLE_VALUE {
            // SAFETY: raw is a fresh handle nothing else owns.
            return Some(unsafe { OwnedHandle::from_raw_handle(raw) });
        }
    }
    None
}

/// The normalised image path a process is running.
fn image_path(process: HANDLE) -> Option<String> {
    let mut buffer = vec![0_u16; MAX_WIDE_PATH];
    let mut length = u32::try_from(buffer.len()).ok()?;
    // SAFETY: process is a live handle opened for query, and buffer is writable
    // storage of exactly the announced length.
    let queried = unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            buffer.as_mut_ptr(),
            &mut length,
        )
    };
    let length = usize::try_from(length).ok()?;
    if queried == 0 || length == 0 || length >= buffer.len() {
        return None;
    }
    buffer.truncate(length);
    normalised_path(&String::from_utf16(&buffer).ok()?)
}

/// The account a process runs as, rendered as a string SID.
fn account_sid(process: HANDLE) -> Option<String> {
    let mut token = null_mut();
    // SAFETY: process is a live handle opened for query and token is valid
    // output storage.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 || token.is_null() {
        return None;
    }
    // SAFETY: token is a fresh handle nothing else owns.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };

    let mut needed = 0_u32;
    // SAFETY: the sizing call writes only the required length.
    let _ = unsafe {
        GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut needed)
    };
    let bytes = usize::try_from(needed).ok()?;
    if bytes < size_of::<TOKEN_USER>() {
        return None;
    }
    // Held as words so the storage is aligned for the structure written into it.
    let mut storage = vec![0_u64; bytes.div_ceil(size_of::<u64>())];
    // SAFETY: storage is writable, aligned and at least `needed` bytes long.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            storage.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return None;
    }
    // SAFETY: the call succeeded, so the storage holds a complete TOKEN_USER.
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    string_sid(user.User.Sid)
}

/// Renders a SID the way Windows itself writes it.
fn string_sid(sid: PSID) -> Option<String> {
    if sid.is_null() {
        return None;
    }
    let mut text = null_mut();
    // SAFETY: sid points inside live storage and text is valid output storage.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return None;
    }
    let mut length = 0_usize;
    // SAFETY: the call returned a NUL-terminated wide string.
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: length is the number of units before the terminator.
    let rendered = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).ok();
    // SAFETY: text is exactly what ConvertSidToStringSidW allocated.
    let _ = unsafe { LocalFree(text.cast()) };
    rendered
}

/// Whether the attested process still serves this live instance.
fn serves_the_same_process(pipe: HANDLE, attested: u32) -> bool {
    if server_process_id(pipe) != Some(attested) {
        return false;
    }
    let mut available = 0_u32;
    // SAFETY: pipe is a live handle; the call reads nothing out of it and only
    // reports how much is waiting.
    unsafe { PeekNamedPipe(pipe, null_mut(), 0, null_mut(), &mut available, null_mut()) != 0 }
}

/// Where this machine says the OpenSSH agent lives.
pub fn system_agent_image_path() -> Option<String> {
    let mut buffer = vec![0_u16; MAX_PATH as usize];
    // SAFETY: buffer is writable storage of exactly the announced length.
    let written = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    let written = usize::try_from(written).ok()?;
    if written == 0 || written >= buffer.len() {
        return None;
    }
    buffer.truncate(written);
    let directory = String::from_utf16(&buffer).ok()?;
    let image = WINDOWS_AGENT_IMAGE;
    normalised_path(&format!(r"{directory}\{image}"))
}

/// The name the volume itself stores for a path.
///
/// The path is opened for its attributes only — no read, no write, and every
/// share mode granted so opening it never disturbs whoever holds it — and the
/// kernel is then asked what that handle really points at. This is what makes
/// the comparison robust: short `8.3` names, symbolic links, junctions and
/// mount points all collapse into the one name the filesystem stores.
///
/// A path that cannot be opened has no normalised form, and therefore fails
/// the comparison rather than passing it in some degraded shape.
pub fn normalised_path(path: &str) -> Option<String> {
    let wide = wide(path)?;
    // SAFETY: wide is a live NUL-terminated wide string; every other argument
    // is a constant or a null pointer the call accepts.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return None;
    }
    // SAFETY: raw is a fresh handle nothing else owns.
    let file = unsafe { OwnedHandle::from_raw_handle(raw) };

    let mut buffer = vec![0_u16; MAX_WIDE_PATH];
    // SAFETY: file is live and buffer is writable storage of the announced size.
    let written = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    let written = usize::try_from(written).ok()?;
    if written == 0 || written >= buffer.len() {
        return None;
    }
    buffer.truncate(written);
    let full = String::from_utf16(&buffer).ok()?;
    // The extended prefix says nothing about which file this is; dropping it on
    // every path keeps both sides of the comparison in the same shape.
    Some(full.strip_prefix(r"\\?\").unwrap_or(&full).to_owned())
}

fn wide(value: &str) -> Option<Vec<u16>> {
    if value.contains('\0') {
        return None;
    }
    let mut encoded: Vec<u16> = value.encode_utf16().collect();
    encoded.push(0);
    Some(encoded)
}

/// The hostile pipe server the Windows agent pipe contract runs against.
///
/// It takes the exact name the helper opens, as the first and only instance,
/// so that the client necessarily lands on it; everything else about it is
/// wrong. Its purpose is to be refused, and to report that nothing was ever
/// asked of it: a helper that attests before speaking sends no byte.
#[cfg(feature = "windows-agent-pipe-contract-test")]
#[doc(hidden)]
pub fn hostile_agent_pipe_fixture_main() -> u8 {
    use std::io::{Read, Write};

    use windows_sys::Win32::{
        Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX},
        System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, PIPE_TYPE_BYTE, PIPE_WAIT},
    };

    const FIXTURE_FAILED: u8 = 1;
    /// A single instance, so a second server cannot answer instead of this one.
    const ONE_INSTANCE: u32 = 1;
    const BUFFER_BYTES: u32 = 4096;
    const DEFAULT_TIMEOUT_MILLIS: u32 = 0;

    let Some(name) = wide(WINDOWS_PIPE_NAME) else {
        return FIXTURE_FAILED;
    };
    // SAFETY: name is a live NUL-terminated wide string and the security
    // argument is the null pointer the call accepts.
    let raw = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            ONE_INSTANCE,
            BUFFER_BYTES,
            BUFFER_BYTES,
            DEFAULT_TIMEOUT_MILLIS,
            null(),
        )
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return FIXTURE_FAILED;
    }
    // SAFETY: raw is a fresh handle nothing else owns.
    let server = unsafe { OwnedHandle::from_raw_handle(raw) };

    // The suite waits for this line before it lets the helper open anything.
    let mut output = std::io::stdout();
    if output.write_all(b"READY\n").is_err() || output.flush().is_err() {
        return FIXTURE_FAILED;
    }

    // SAFETY: server is a live pipe handle and no overlapped structure is used.
    let _ = unsafe { ConnectNamedPipe(server.as_raw_handle(), null_mut()) };

    // SAFETY: the file takes ownership of a handle nothing else holds.
    let mut connected = unsafe { std::fs::File::from_raw_handle(server.into_raw_handle()) };
    let mut received = 0_usize;
    let mut chunk = [0_u8; 512];
    while let Ok(read) = connected.read(&mut chunk) {
        if read == 0 {
            break;
        }
        received += read;
    }
    if writeln!(output, "RECEIVED {received}").is_err() || output.flush().is_err() {
        return FIXTURE_FAILED;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Nothing but the one name reaches `CreateFileW`.
    #[test]
    fn no_other_name_is_ever_opened() {
        for hostile in [
            r"\\.\pipe\openssh-ssh-agent-evil",
            r"\\attacker\pipe\openssh-ssh-agent",
            r"C:\Windows\System32\OpenSSH\ssh-agent.exe",
            "",
        ] {
            let refusal = observe_declared_pipe(hostile)
                .err()
                .expect("a name that is not the fixed one cannot be observed");
            assert_eq!(refusal, EndpointRefusal::UnexpectedPipeName, "{hostile:?}");
        }
    }

    /// The machine names its own system directory; nothing here assumes one.
    #[test]
    fn the_expected_image_is_read_from_this_machine() {
        let expected = system_agent_image_path().expect("a Windows machine has a system directory");
        assert!(
            expected
                .to_ascii_lowercase()
                .ends_with(&WINDOWS_AGENT_IMAGE.to_ascii_lowercase()),
            "{expected} must end at the OpenSSH agent"
        );
    }

    #[test]
    fn a_path_that_cannot_be_opened_has_no_normalised_form() {
        assert_eq!(
            normalised_path(r"C:\Windows\System32\OpenSSH\this-file-does-not-exist.exe"),
            None
        );
        assert_eq!(normalised_path("with\0interior"), None);
    }
}
