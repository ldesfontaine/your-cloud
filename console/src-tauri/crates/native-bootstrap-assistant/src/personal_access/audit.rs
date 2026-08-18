//! What one declared endpoint answers about itself, read and nothing else.
//!
//! This module is the observing end of "audit then propose". It is deliberately
//! the smallest thing that can answer the questions a placement depends on, and
//! it is built around four rules that the rest of the palier leans on.
//!
//! **One endpoint, and only the one that was declared.** Nothing here discovers
//! a machine. There is no enumeration, no address range, no provider account and
//! no listener of any kind: the only thing this module can be handed is a
//! session somebody else already opened towards a target the user named, and the
//! only thing it does with it is ask for output. An endpoint nobody declared has
//! no entry point through which it could ever be reached.
//!
//! **Reading only.** Every command below is a constant of type
//! [`FixedCommand`] — the very type the elevation of the previous palier uses,
//! so a command that is not one of these constants still has no way of reaching
//! a channel. Each of them reads: `uname` asks the kernel its own machine name,
//! `df` asks a filesystem its free blocks, `head` copies the first bytes of a
//! fixed list of paths. None of them creates, opens for writing, renames,
//! deletes, installs, enables or configures anything, and [`READ_ONLY_PROGRAMS`]
//! is the list a test can hold them against.
//!
//! **Three channels, which is the session's whole budget.** An audit is a suite
//! of reads and they go through [`super::session::LiveSession::run_channel`],
//! the one place this crate opens a channel at all. The budget did not have to
//! move: the audit fits in the three channels a session may open, because seven
//! of the ten facts below come from files and `head` reads a whole list of files
//! in one command. An audit therefore spends the session it was given and never
//! elevates — it has no channel left to elevate with, which is the bound rather
//! than a promise.
//!
//! **Nothing doubtful is completed.** Every fact is an [`Observed`], and the
//! variant for "the audit could not establish it" carries why. There is no
//! default, no optimistic fallback and no inference from one fact to another: a
//! machine that did not answer its memory has an unknown memory, and a role
//! whose requirement cannot be checked against an unknown is refused for that
//! reason rather than accepted on the assumption that it would have fitted.

use super::elevation::FixedCommand;

/// Longest prefix of each audited file that is copied back.
///
/// It bounds the whole bundle far below the session's own per-stream ceiling,
/// and it is chosen for the longest of the files rather than the shortest: the
/// three lines this palier reads out of `/proc/meminfo` are the first three, and
/// the identity lines of `/proc/self/status` are the first ten.
pub const MAX_FILE_BYTES: usize = 320;

/// The paths the single file channel reads, in the order it reads them.
///
/// Every one of them is a fixed absolute path, and the list is a constant: no
/// name, no address and nothing else that crossed a process boundary ever
/// becomes a path here.
pub const AUDIT_FILES: [&str; 8] = [
    // The account the audit itself runs as. `head` reads its own process, so
    // this is the uid the session really has rather than the one it asked for.
    "/proc/self/status",
    "/etc/hostname",
    "/etc/os-release",
    // The init system, read as process one's own name.
    "/proc/1/comm",
    // This file exists on the unified hierarchy and on no other, so its mere
    // presence is the cgroup version.
    "/sys/fs/cgroup/cgroup.controllers",
    "/proc/meminfo",
    "/sys/devices/system/cpu/online",
    // Where an existing installation declares the roles it runs. It is the only
    // path of the list that a fresh machine does not have.
    "/etc/your-cloud/roles",
];

/// The architecture channel.
/// Combien de canaux une observation complète ouvre : les trois commandes
/// ci-dessous, jouées une fois chacune par [`observe`]. La constante est
/// déclarée à côté d'elles pour qu'une commande ajoutée sans son canal fasse
/// rougir un test ici, avant de heurter un budget en cours de session.
pub const OBSERVATION_CHANNELS: usize = 3;

pub const ARCHITECTURE: FixedCommand = FixedCommand::fixed("/usr/bin/uname -m");

/// The filesystem channel. `-k` fixes the unit at one kibibyte whatever the
/// far side's `BLOCKSIZE` says, and `-P` fixes the layout at one line per
/// filesystem so a long device name cannot wrap the numbers onto a second line.
///
/// `/var` is asked for rather than `/`: it is where a managed service's images,
/// state and logs land, so it is the free space a placement is about. On a
/// machine that does not separate it, the answer is the root filesystem's, which
/// is the same truthful answer.
pub const FILESYSTEM: FixedCommand = FixedCommand::fixed("/usr/bin/df -k -P /var");

/// The file channel: the first [`MAX_FILE_BYTES`] of each path of
/// [`AUDIT_FILES`], each under its own header.
///
/// `-v` is what makes one command readable as eight answers: it prints the
/// `==> path <==` header even for a single file, so the reader below never has
/// to guess where one file ends and the next begins. A path the far side could
/// not open simply has no header, and the exit status says that at least one
/// did not — which is how absence is read as absence rather than as silence.
pub const FACT_FILES: FixedCommand = FixedCommand::fixed(
    "/usr/bin/head -v -c 320 /proc/self/status /etc/hostname /etc/os-release /proc/1/comm \
     /sys/fs/cgroup/cgroup.controllers /proc/meminfo /sys/devices/system/cpu/online \
     /etc/your-cloud/roles",
);

/// Every command an audit may ever run, in the order it runs them.
pub const AUDIT_COMMANDS: [FixedCommand; 3] = [ARCHITECTURE, FILESYSTEM, FACT_FILES];

/// The three programs the commands above are allowed to be, absolute.
///
/// It is a positive list, and it is the whole claim of "strictly read only":
/// each of these three programs reads and writes nothing, so a command built on
/// one of them cannot mutate the audited machine whatever its arguments are.
/// A test holds [`AUDIT_COMMANDS`] against it, which is how a fourth program —
/// or one of these three replaced by something that writes — fails closed
/// instead of shipping.
pub const READ_ONLY_PROGRAMS: [&str; 3] = ["/usr/bin/uname", "/usr/bin/df", "/usr/bin/head"];

/// Why a fact was not established. It is never a value, and never a default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unverified {
    /// The channel that would have answered it did not run, or did not finish.
    NotAnswered,
    /// The channel ran and the far side did not produce this fact at all: the
    /// file has no header, or the command printed nothing.
    NotProduced,
    /// Something came back and it is not in a shape this palier recognises. It
    /// is kept apart from [`Self::NotProduced`] on purpose: silence and noise
    /// are different observations, and only one of them says the machine
    /// answered.
    Unreadable,
}

/// One fact, either read or explicitly not read.
///
/// It exists so that "unknown" has to be handled at every place a fact is used,
/// rather than being representable as a zero, an empty string or a `false` that
/// reads like an answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observed<T> {
    Known(T),
    Unknown(Unverified),
}

impl<T> Observed<T> {
    pub fn known(&self) -> Option<&T> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown(_) => None,
        }
    }

    /// Why this fact is unknown, when it is. `None` means it was read.
    pub fn unverified(&self) -> Option<Unverified> {
        match self {
            Self::Known(_) => None,
            Self::Unknown(reason) => Some(*reason),
        }
    }

    pub fn is_known(&self) -> bool {
        matches!(self, Self::Known(_))
    }
}

/// The distribution as the machine names itself, never as it was guessed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Distribution {
    /// `ID` of `os-release`, lowercased by the file's own convention.
    pub id: String,
    /// `VERSION_ID` of `os-release`. A rolling distribution that publishes none
    /// leaves this empty, which is not the same as an unread `os-release`.
    pub version_id: String,
}

/// The one server target this palier supports, spelled as `os-release` does.
pub const SUPPORTED_DISTRIBUTION_ID: &str = "debian";
pub const SUPPORTED_DISTRIBUTION_VERSION: &str = "13";

/// The processor architecture, as the audited kernel names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Architecture {
    /// The one architecture this palier supports. Both spellings mean it: the
    /// kernel says `x86_64`, Debian's own packages say `amd64`, and refusing one
    /// of the two would refuse the very machine the other describes.
    Amd64,
    /// Anything else, kept as the machine spelled it so a refusal can name it.
    Other(String),
}

/// The init system, read as the name of process one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InitSystem {
    Systemd,
    Other(String),
}

/// Which cgroup hierarchy the machine mounts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CgroupHierarchy {
    /// The unified hierarchy, which is the only one this palier bounds a
    /// service under.
    V2,
    /// Anything the unified hierarchy's own controller file does not describe.
    Legacy,
}

/// A role an installation declares it already runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Controller,
    Relay,
    Agent,
    Auxiliary,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Controller => "controller",
            Self::Relay => "relay",
            Self::Agent => "agent",
            Self::Auxiliary => "auxiliary",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        [Self::Controller, Self::Relay, Self::Agent, Self::Auxiliary]
            .into_iter()
            .find(|role| role.as_str() == name)
    }
}

/// Most roles one declaration file may name. Four exist; a file naming more is
/// not a longer machine, it is a file this palier does not recognise.
const MAX_DECLARED_ROLES: usize = 4;

/// What an existing installation says about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Installation {
    /// The fixed path could not be read at all. Nothing on this machine
    /// declares an installation to this audit, and the audit claims exactly
    /// that rather than claiming the machine is clean.
    NotDeclared,
    /// The fixed path was read, and these are the roles it names. An empty list
    /// is a real answer: a declaration that runs nothing.
    Declared(Vec<Role>),
}

/// Everything one audit observed, fact by fact.
///
/// It is a value and it announces nothing, exactly like the probe report of the
/// palier that opened the session. Whoever wants a verdict out of it asks the
/// placement module, which is where "compatible" is decided once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedMachine {
    /// The uid the audit itself ran as. It is not an authorisation — this
    /// palier elevates nothing — only a fact a placement must show.
    pub uid: Observed<u32>,
    pub hostname: Observed<String>,
    pub distribution: Observed<Distribution>,
    pub architecture: Observed<Architecture>,
    pub init: Observed<InitSystem>,
    pub cgroup: Observed<CgroupHierarchy>,
    /// Total memory of the machine, in kibibytes, as `/proc/meminfo` states it.
    pub memory_kib: Observed<u64>,
    pub processors: Observed<u32>,
    /// Free space of `/var`, in kibibytes.
    pub free_disk_kib: Observed<u64>,
    pub installation: Observed<Installation>,
}

impl ObservedMachine {
    /// The machine nothing was ever asked of. Every entry is unknown for the
    /// same stated reason, which is what a caller must start from when a
    /// channel refused before it ran.
    pub fn unanswered(reason: Unverified) -> Self {
        Self {
            uid: Observed::Unknown(reason),
            hostname: Observed::Unknown(reason),
            distribution: Observed::Unknown(reason),
            architecture: Observed::Unknown(reason),
            init: Observed::Unknown(reason),
            cgroup: Observed::Unknown(reason),
            memory_kib: Observed::Unknown(reason),
            processors: Observed::Unknown(reason),
            free_disk_kib: Observed::Unknown(reason),
            installation: Observed::Unknown(reason),
        }
    }
}

/// One `exec` channel's answer, as the session reports it.
///
/// The audit reads channels rather than sockets, so this is the whole of its
/// input surface. It is borrowed rather than owned because the session already
/// bounded both streams and there is no reason to copy them again.
#[derive(Clone, Copy, Debug)]
pub struct ChannelAnswer<'a> {
    pub exit_status: u32,
    pub stdout: &'a [u8],
    pub stderr: &'a [u8],
}

/// Reads the architecture channel.
///
/// A failing status makes the fact unknown rather than wrong: a `uname` that
/// did not run says nothing about the machine it did not run on.
pub fn read_architecture(answer: ChannelAnswer<'_>) -> Observed<Architecture> {
    let Some(text) = single_token(answer) else {
        return Observed::Unknown(unanswered_or(answer, Unverified::NotProduced));
    };
    Observed::Known(match text.as_str() {
        "x86_64" | "amd64" => Architecture::Amd64,
        _ => Architecture::Other(text),
    })
}

/// Reads the free space of the filesystem channel.
///
/// The POSIX layout is one header line and one line per filesystem, whose
/// fourth field is the free space in the unit `-k` fixed. Anything else — no
/// second line, a wrapped line, a field that is not a plain decimal — is
/// unreadable rather than approximated.
pub fn read_free_disk(answer: ChannelAnswer<'_>) -> Observed<u64> {
    let Some(text) = ascii_text(answer.stdout) else {
        return Observed::Unknown(unanswered_or(answer, Unverified::Unreadable));
    };
    if answer.exit_status != 0 {
        return Observed::Unknown(Unverified::NotAnswered);
    }
    let Some(line) = text.lines().nth(1) else {
        return Observed::Unknown(Unverified::NotProduced);
    };
    let fields: Vec<&str> = line.split_whitespace().collect();
    // Six fields exactly: device, blocks, used, available, capacity, mount
    // point. A mount point containing a space would produce more, and this
    // palier reads `/var`, which does not.
    if fields.len() != 6 {
        return Observed::Unknown(Unverified::Unreadable);
    }
    match decimal(fields[3]) {
        Some(free) => Observed::Known(free),
        None => Observed::Unknown(Unverified::Unreadable),
    }
}

/// The file channel, split back into the files it carried.
///
/// A path is present here only if the far side really printed its header, so a
/// missing entry is an unopened file rather than an empty one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileBundle {
    /// Whether the channel produced a single recognised file. When it did not,
    /// every file below is missing for that reason rather than for its own.
    ///
    /// It is not the exit status: a channel that read seven of its eight files
    /// exits non-zero and has answered, and that is the ordinary case — a fresh
    /// machine has no installation to declare. What separates "answered" from
    /// "did not" is whether any header came back at all, and a real `head` that
    /// ran always returns at least the first of its files.
    answered: bool,
    files: Vec<(String, String)>,
}

impl FileBundle {
    /// What the far side printed for one path, when it printed it.
    pub fn get(&self, path: &str) -> Option<&str> {
        self.files
            .iter()
            .find(|(name, _)| name == path)
            .map(|(_, body)| body.as_str())
    }

    /// Why a path that is not here is not here.
    fn missing(&self) -> Unverified {
        if self.answered {
            Unverified::NotProduced
        } else {
            Unverified::NotAnswered
        }
    }
}

/// Splits the file channel back into its files.
///
/// The header the far side prints is the only separator, and a path is accepted
/// only if it is one of [`AUDIT_FILES`]: a machine that invents a header for a
/// path nobody asked for has that header ignored rather than believed. A path
/// whose header appears twice is dropped entirely — which of the two bodies is
/// the file cannot be told, and this palier does not choose.
pub fn read_files(answer: ChannelAnswer<'_>) -> FileBundle {
    let Some(text) = ascii_text(answer.stdout) else {
        return FileBundle::default();
    };
    let mut bundle = FileBundle::default();
    let mut duplicated: Vec<String> = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in text.lines() {
        if let Some(path) = header_path(line) {
            if let Some(entry) = current.take() {
                push_once(&mut bundle.files, &mut duplicated, entry);
            }
            if AUDIT_FILES.contains(&path) {
                current = Some((path.to_owned(), String::new()));
            }
            continue;
        }
        if let Some((_, body)) = current.as_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    if let Some(entry) = current.take() {
        push_once(&mut bundle.files, &mut duplicated, entry);
    }
    bundle.answered = !bundle.files.is_empty();
    bundle
}

/// Keeps the first body of a path, and removes every body of a path that came
/// back twice.
fn push_once(
    files: &mut Vec<(String, String)>,
    duplicated: &mut Vec<String>,
    entry: (String, String),
) {
    if duplicated.contains(&entry.0) {
        return;
    }
    if files.iter().any(|(path, _)| *path == entry.0) {
        files.retain(|(path, _)| *path != entry.0);
        duplicated.push(entry.0);
        return;
    }
    files.push(entry);
}

/// The path of a `head -v` header line, when the line is one.
fn header_path(line: &str) -> Option<&str> {
    let inner = line.strip_prefix("==> ")?.strip_suffix(" <==")?;
    if inner.is_empty() {
        return None;
    }
    Some(inner)
}

/// Assembles the three channels into one observation.
///
/// Every fact is derived from exactly one source, and a source that did not
/// answer produces an unknown with its own reason. Nothing is cross-filled: an
/// unread `os-release` is never repaired from the hostname, and an unread
/// `meminfo` is never repaired from the processor count.
pub fn assemble(
    architecture: Observed<Architecture>,
    free_disk_kib: Observed<u64>,
    files: &FileBundle,
) -> ObservedMachine {
    ObservedMachine {
        uid: read_uid(files),
        hostname: read_hostname(files),
        distribution: read_distribution(files),
        architecture,
        init: read_init(files),
        cgroup: read_cgroup(files),
        memory_kib: read_memory(files),
        processors: read_processors(files),
        free_disk_kib,
        installation: read_installation(files),
    }
}

/// The real uid of the process that read its own status, which is the account
/// the whole audit ran as.
fn read_uid(files: &FileBundle) -> Observed<u32> {
    let Some(body) = files.get("/proc/self/status") else {
        return Observed::Unknown(files.missing());
    };
    let Some(line) = body.lines().find_map(|line| line.strip_prefix("Uid:")) else {
        return Observed::Unknown(Unverified::Unreadable);
    };
    match line
        .split_whitespace()
        .next()
        .and_then(decimal)
        .and_then(|uid| u32::try_from(uid).ok())
    {
        Some(uid) => Observed::Known(uid),
        None => Observed::Unknown(Unverified::Unreadable),
    }
}

fn read_hostname(files: &FileBundle) -> Observed<String> {
    let Some(body) = files.get("/etc/hostname") else {
        return Observed::Unknown(files.missing());
    };
    match printable_token(body) {
        Some(name) => Observed::Known(name),
        None => Observed::Unknown(Unverified::Unreadable),
    }
}

/// Reads `ID` and `VERSION_ID` of `os-release`, and nothing else of it.
///
/// The file's own grammar allows both quoted and bare values, so both are
/// accepted and the quotes are removed. A file without an `ID` is unreadable:
/// every distribution this palier could support publishes one, and inventing it
/// from `PRETTY_NAME` would be exactly the guess this module refuses to make.
fn read_distribution(files: &FileBundle) -> Observed<Distribution> {
    let Some(body) = files.get("/etc/os-release") else {
        return Observed::Unknown(files.missing());
    };
    let Some(id) = os_release_value(body, "ID") else {
        return Observed::Unknown(Unverified::Unreadable);
    };
    let version_id = os_release_value(body, "VERSION_ID").unwrap_or_default();
    Observed::Known(Distribution { id, version_id })
}

fn read_init(files: &FileBundle) -> Observed<InitSystem> {
    let Some(body) = files.get("/proc/1/comm") else {
        return Observed::Unknown(files.missing());
    };
    match printable_token(body) {
        Some(name) if name == "systemd" => Observed::Known(InitSystem::Systemd),
        Some(name) => Observed::Known(InitSystem::Other(name)),
        None => Observed::Unknown(Unverified::Unreadable),
    }
}

/// The unified hierarchy publishes its controllers in this file and the legacy
/// one has no such file at all, so the header's presence is the answer. An
/// empty controller list is still the unified hierarchy — mounted, with nothing
/// delegated — and is reported as such.
fn read_cgroup(files: &FileBundle) -> Observed<CgroupHierarchy> {
    match files.get("/sys/fs/cgroup/cgroup.controllers") {
        Some(_) => Observed::Known(CgroupHierarchy::V2),
        // The file channel answered and this path had no header: the file is
        // not there, which on this hierarchy question is itself the fact.
        None if files.answered => Observed::Known(CgroupHierarchy::Legacy),
        None => Observed::Unknown(Unverified::NotAnswered),
    }
}

fn read_memory(files: &FileBundle) -> Observed<u64> {
    let Some(body) = files.get("/proc/meminfo") else {
        return Observed::Unknown(files.missing());
    };
    let Some(line) = body.lines().find_map(|line| line.strip_prefix("MemTotal:")) else {
        return Observed::Unknown(Unverified::Unreadable);
    };
    let mut fields = line.split_whitespace();
    match (fields.next().and_then(decimal), fields.next()) {
        // The unit is part of the fact. A `meminfo` that stopped writing `kB`
        // is a `meminfo` this reader no longer understands.
        (Some(total), Some("kB")) => Observed::Known(total),
        _ => Observed::Unknown(Unverified::Unreadable),
    }
}

/// Counts the processors the kernel lists as online.
///
/// The file is a range list — `0`, `0-3`, `0,2-3` — and it is read as one: a
/// machine with holes in its numbering has as many processors as the ranges
/// describe, not as many as its highest index suggests.
fn read_processors(files: &FileBundle) -> Observed<u32> {
    let Some(body) = files.get("/sys/devices/system/cpu/online") else {
        return Observed::Unknown(files.missing());
    };
    let Some(list) = printable_token(body) else {
        return Observed::Unknown(Unverified::Unreadable);
    };
    let mut total: u64 = 0;
    for range in list.split(',') {
        let (first, last) = match range.split_once('-') {
            Some((first, last)) => (decimal(first), decimal(last)),
            None => (decimal(range), decimal(range)),
        };
        match (first, last) {
            (Some(first), Some(last)) if first <= last => total += last - first + 1,
            _ => return Observed::Unknown(Unverified::Unreadable),
        }
    }
    match u32::try_from(total) {
        Ok(count) if count > 0 => Observed::Known(count),
        _ => Observed::Unknown(Unverified::Unreadable),
    }
}

/// Reads the roles an existing installation declares.
///
/// A path with no header is [`Installation::NotDeclared`] rather than an
/// unknown: the channel answered, the header of every other file arrived, so
/// this one really could not be opened. What that states is precise and
/// deliberately narrow — nothing declares an installation at the fixed path —
/// and it is not the wider claim that the machine carries none.
fn read_installation(files: &FileBundle) -> Observed<Installation> {
    let Some(body) = files.get("/etc/your-cloud/roles") else {
        return match files.answered {
            true => Observed::Known(Installation::NotDeclared),
            false => Observed::Unknown(Unverified::NotAnswered),
        };
    };
    let mut roles: Vec<Role> = Vec::new();
    for line in body.lines() {
        let name = line.trim();
        if name.is_empty() {
            continue;
        }
        match Role::parse(name) {
            // A name this palier does not know is not skipped: a declaration
            // naming something unrecognised describes an installation this
            // audit cannot account for, and accounting for part of it would be
            // worse than saying so.
            None => return Observed::Unknown(Unverified::Unreadable),
            Some(role) if roles.contains(&role) => {
                return Observed::Unknown(Unverified::Unreadable)
            }
            Some(role) => roles.push(role),
        }
        if roles.len() > MAX_DECLARED_ROLES {
            return Observed::Unknown(Unverified::Unreadable);
        }
    }
    Observed::Known(Installation::Declared(roles))
}

/// One line of printable ASCII, with nothing else on it.
fn printable_token(body: &str) -> Option<String> {
    let mut lines = body.lines().filter(|line| !line.trim().is_empty());
    let only = lines.next()?.trim();
    if lines.next().is_some() || only.is_empty() || only.len() > MAX_FILE_BYTES {
        return None;
    }
    printable(only).then(|| only.to_owned())
}

/// The single word one command printed, when that is all it printed.
fn single_token(answer: ChannelAnswer<'_>) -> Option<String> {
    if answer.exit_status != 0 {
        return None;
    }
    let text = ascii_text(answer.stdout)?;
    printable_token(&text)
}

/// A stream that is entirely printable ASCII, tabs and newlines included.
///
/// Anything else means the far side is not answering under the fixed locale
/// this palier reads it under, and a stream that cannot be recognised is never
/// interpreted generously.
fn ascii_text(stream: &[u8]) -> Option<String> {
    if !stream.is_ascii() {
        return None;
    }
    let text = std::str::from_utf8(stream).ok()?;
    text.chars()
        .all(|character| character == '\n' || character == '\t' || !character.is_control())
        .then(|| text.to_owned())
}

fn printable(text: &str) -> bool {
    text.chars().all(|character| !character.is_control())
}

/// A plain decimal number, and nothing that merely starts like one.
fn decimal(text: &str) -> Option<u64> {
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// The value of one `os-release` key, unquoted.
fn os_release_value(body: &str, key: &str) -> Option<String> {
    for line in body.lines() {
        let Some(rest) = line.trim().strip_prefix(key) else {
            continue;
        };
        let Some(value) = rest.strip_prefix('=') else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|inner| inner.strip_suffix('"'))
            .unwrap_or(value);
        if value.len() > MAX_FILE_BYTES || !printable(value) {
            return None;
        }
        return Some(value.to_owned());
    }
    None
}

/// A channel that failed says nothing; a channel that succeeded and printed
/// nothing usable says something else. The two are told apart here so every
/// reader above tells them apart the same way.
fn unanswered_or(answer: ChannelAnswer<'_>, produced: Unverified) -> Unverified {
    if answer.exit_status == 0 {
        produced
    } else {
        Unverified::NotAnswered
    }
}

/// Runs the whole audit on a session somebody else opened.
///
/// This is the only acting function of the module and it acts on nothing: it
/// opens no socket, resolves no name and creates no session. It asks the live
/// session for three channels, in order, through the very
/// [`super::session::LiveSession::run_channel`] the elevation of the previous
/// palier goes through — the same budget, the same bounds, the same guard, the
/// same explicit closure by whoever owns the session.
///
/// A channel that refuses does not end the audit. The facts it would have
/// carried become unknown with their own reason and the remaining channels
/// still run, because a machine that answered two questions out of three has
/// answered two questions and a placement is entitled to see which.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn observe(
    live: &mut super::session::LiveSession,
    deadline: std::time::Instant,
    guard: &(dyn Fn() -> super::session::GuardVerdict + Sync),
) -> ObservedMachine {
    use super::session::ChannelReport;

    let run = |live: &mut super::session::LiveSession, command| -> Option<ChannelReport> {
        live.run_channel(command, None, deadline, guard).ok()
    };

    let architecture = run(live, ARCHITECTURE);
    let filesystem = run(live, FILESYSTEM);
    let files = run(live, FACT_FILES);

    let architecture = match &architecture {
        Some(report) => read_architecture(answer_of(report)),
        None => Observed::Unknown(Unverified::NotAnswered),
    };
    let free_disk_kib = match &filesystem {
        Some(report) => read_free_disk(answer_of(report)),
        None => Observed::Unknown(Unverified::NotAnswered),
    };
    let bundle = match &files {
        Some(report) => read_files(answer_of(report)),
        None => FileBundle::default(),
    };
    assemble(architecture, free_disk_kib, &bundle)
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn answer_of(report: &super::session::ChannelReport) -> ChannelAnswer<'_> {
    ChannelAnswer {
        exit_status: report.exit_status,
        stdout: &report.stdout,
        stderr: &report.stderr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le nombre de canaux déclaré est celui des commandes d'observation, et
    /// une commande ajoutée sans son canal rougit ici plutôt que de heurter un
    /// budget au milieu d'une session. Le compte ne peut pas être dérivé du
    /// corps d'`observe` par une suite — il est donc tenu par l'énumération
    /// exhaustive des commandes que ce module expose pour l'observation.
    #[test]
    fn the_observation_channel_count_matches_the_commands_it_plays() {
        let commands = [ARCHITECTURE, FILESYSTEM, FACT_FILES];
        assert_eq!(OBSERVATION_CHANNELS, commands.len());
        // Trois commandes distinctes : un doublon dirait que le compte couvre
        // deux fois la même question.
        for (index, left) in commands.iter().enumerate() {
            for right in commands.iter().skip(index + 1) {
                assert_ne!(left.as_str(), right.as_str());
            }
        }
    }

    fn answer<'a>(exit_status: u32, stdout: &'a str) -> ChannelAnswer<'a> {
        ChannelAnswer {
            exit_status,
            stdout: stdout.as_bytes(),
            stderr: b"",
        }
    }

    /// A real bundle, in the exact shape `head -v` writes it.
    fn bundle(files: &[(&str, &str)]) -> String {
        let mut text = String::new();
        for (path, body) in files {
            text.push_str(&format!("==> {path} <==\n{body}\n"));
        }
        text
    }

    fn nominal_files() -> String {
        bundle(&[
            (
                "/proc/self/status",
                "Name:\thead\nUid:\t1001\t1001\t1001\t1001",
            ),
            ("/etc/hostname", "machine-1"),
            (
                "/etc/os-release",
                "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\nVERSION_ID=\"13\"",
            ),
            ("/proc/1/comm", "systemd"),
            (
                "/sys/fs/cgroup/cgroup.controllers",
                "cpuset cpu io memory pids",
            ),
            (
                "/proc/meminfo",
                "MemTotal:         991164 kB\nMemFree: 1 kB",
            ),
            ("/sys/devices/system/cpu/online", "0-1"),
        ])
    }

    /// Every audit command is one of three reading programs, absolute, and with
    /// nothing in it a remote login shell could turn into a second command.
    #[test]
    fn every_audit_command_is_an_absolute_read_only_constant() {
        assert_eq!(AUDIT_COMMANDS.len(), 3);
        for command in AUDIT_COMMANDS {
            let text = command.as_str();
            let program = text.split(' ').next().expect("a command has a program");
            assert!(
                READ_ONLY_PROGRAMS.contains(&program),
                "{program} is not one of the read-only programs"
            );
            assert!(text.starts_with('/'), "{text} is not an absolute path");
            for forbidden in [
                ';', '&', '|', '\n', '\r', '`', '$', '<', '>', '(', ')', '\'', '"', '*', '?', '\\',
            ] {
                assert!(
                    !text.contains(forbidden),
                    "{text} carries the shell character {forbidden:?}"
                );
            }
        }
    }

    /// The file channel names exactly the paths the readers below look for, and
    /// the bound it copies each of them under is the one declared here.
    #[test]
    fn the_file_channel_reads_the_declared_paths_and_nothing_else() {
        let command = FACT_FILES.as_str();
        assert!(command.contains(&format!("-c {MAX_FILE_BYTES}")));
        for path in AUDIT_FILES {
            assert!(path.starts_with('/'), "{path} is not absolute");
            assert!(
                command.contains(path),
                "{path} is declared and never asked for"
            );
        }
        // The whole bundle stays under the bound the session reads one stream
        // under, headers included. A ninth file would break this assertion
        // rather than be truncated on the wire.
        let ceiling = AUDIT_FILES.len() * (MAX_FILE_BYTES + 64);
        assert!(
            ceiling <= super::super::session::MAX_PROBE_STREAM_BYTES,
            "the bundle must fit in one bounded stream, not overflow it"
        );
    }

    #[test]
    fn a_nominal_machine_is_read_fact_by_fact() {
        let files = read_files(answer(0, &nominal_files()));
        let machine = assemble(
            read_architecture(answer(0, "x86_64\n")),
            read_free_disk(answer(
                0,
                "Filesystem 1024-blocks Used Available Capacity Mounted-on\n\
                 /dev/vda1 10113424 1263772 8388996 14% /\n",
            )),
            &files,
        );

        assert_eq!(machine.uid, Observed::Known(1001));
        assert_eq!(machine.hostname, Observed::Known("machine-1".into()));
        assert_eq!(
            machine.distribution,
            Observed::Known(Distribution {
                id: "debian".into(),
                version_id: "13".into(),
            })
        );
        assert_eq!(machine.architecture, Observed::Known(Architecture::Amd64));
        assert_eq!(machine.init, Observed::Known(InitSystem::Systemd));
        assert_eq!(machine.cgroup, Observed::Known(CgroupHierarchy::V2));
        assert_eq!(machine.memory_kib, Observed::Known(991_164));
        assert_eq!(machine.processors, Observed::Known(2));
        assert_eq!(machine.free_disk_kib, Observed::Known(8_388_996));
        assert_eq!(
            machine.installation,
            Observed::Known(Installation::NotDeclared)
        );
    }

    /// The kernel's spelling and Debian's own spelling name one architecture.
    #[test]
    fn both_spellings_of_the_supported_architecture_are_the_same_architecture() {
        assert_eq!(
            read_architecture(answer(0, "x86_64\n")),
            Observed::Known(Architecture::Amd64)
        );
        assert_eq!(
            read_architecture(answer(0, "amd64\n")),
            Observed::Known(Architecture::Amd64)
        );
        assert_eq!(
            read_architecture(answer(0, "aarch64\n")),
            Observed::Known(Architecture::Other("aarch64".into()))
        );
    }

    /// A channel that failed leaves the fact unknown for that reason, and a
    /// channel that succeeded over nothing usable leaves it unknown for the
    /// other. Neither ever becomes a value.
    #[test]
    fn a_fact_that_was_not_answered_is_never_completed() {
        assert_eq!(
            read_architecture(answer(1, "")),
            Observed::Unknown(Unverified::NotAnswered)
        );
        assert_eq!(
            read_architecture(answer(0, "")),
            Observed::Unknown(Unverified::NotProduced)
        );
        assert_eq!(
            read_architecture(answer(0, "x86_64\nextra\n")),
            Observed::Unknown(Unverified::NotProduced)
        );
        assert_eq!(
            read_free_disk(answer(1, "")),
            Observed::Unknown(Unverified::NotAnswered)
        );
        assert_eq!(
            read_free_disk(answer(0, "Filesystem\n")),
            Observed::Unknown(Unverified::NotProduced)
        );
        assert_eq!(
            read_free_disk(answer(0, "Filesystem\n/dev/vda1 1 2 x 4% /\n")),
            Observed::Unknown(Unverified::Unreadable)
        );

        let nothing = ObservedMachine::unanswered(Unverified::NotAnswered);
        for reason in [
            nothing.uid.unverified(),
            nothing.hostname.unverified(),
            nothing.distribution.unverified(),
            nothing.architecture.unverified(),
            nothing.init.unverified(),
            nothing.cgroup.unverified(),
            nothing.memory_kib.unverified(),
            nothing.processors.unverified(),
            nothing.free_disk_kib.unverified(),
            nothing.installation.unverified(),
        ] {
            assert_eq!(reason, Some(Unverified::NotAnswered));
        }
    }

    /// A channel that never ran leaves every file of the bundle unknown for
    /// that reason, and never turns an unread hierarchy into a legacy one.
    #[test]
    fn an_unanswered_file_channel_never_becomes_an_answer() {
        let machine = assemble(
            Observed::Unknown(Unverified::NotAnswered),
            Observed::Unknown(Unverified::NotAnswered),
            &FileBundle::default(),
        );
        assert_eq!(
            machine.cgroup,
            Observed::Unknown(Unverified::NotAnswered),
            "an unread hierarchy must never be reported as the legacy one"
        );
        assert_eq!(
            machine.installation,
            Observed::Unknown(Unverified::NotAnswered)
        );
        assert_eq!(machine.uid, Observed::Unknown(Unverified::NotAnswered));
    }

    /// A file the far side never printed is missing rather than empty, and the
    /// two facts that read a *presence* say so rather than inventing one.
    #[test]
    fn a_file_without_a_header_is_an_unopened_file() {
        let without_cgroup = bundle(&[("/proc/1/comm", "systemd")]);
        let files = read_files(answer(1, &without_cgroup));
        assert_eq!(files.get("/sys/fs/cgroup/cgroup.controllers"), None);
        assert_eq!(
            read_cgroup(&files),
            Observed::Known(CgroupHierarchy::Legacy),
            "the unified hierarchy publishes this file and the legacy one does not"
        );
        assert_eq!(
            read_memory(&files),
            Observed::Unknown(Unverified::NotProduced)
        );
    }

    /// A file channel that printed nothing has answered nothing, whatever its
    /// exit status says, and nothing of the machine is inferred from silence.
    #[test]
    fn a_file_channel_that_printed_nothing_answered_nothing() {
        for status in [0, 1] {
            let files = read_files(answer(status, ""));
            assert_eq!(files, FileBundle::default());
            assert_eq!(
                read_cgroup(&files),
                Observed::Unknown(Unverified::NotAnswered)
            );
            assert_eq!(
                read_installation(&files),
                Observed::Unknown(Unverified::NotAnswered)
            );
        }
    }

    /// A header for a path nobody asked for is ignored, and a path answered
    /// twice is dropped rather than arbitrated.
    #[test]
    fn an_invented_or_repeated_header_never_becomes_a_fact() {
        let hostile = bundle(&[
            ("/etc/shadow", "root:x:"),
            ("/etc/hostname", "first"),
            ("/etc/hostname", "second"),
            ("/proc/1/comm", "systemd"),
        ]);
        let files = read_files(answer(0, &hostile));
        assert_eq!(files.get("/etc/shadow"), None);
        assert_eq!(files.get("/etc/hostname"), None);
        assert_eq!(files.get("/proc/1/comm"), Some("systemd\n"));
    }

    /// A machine that declares roles is read as declaring them, and a
    /// declaration this palier cannot account for is unknown rather than
    /// partially believed.
    #[test]
    fn a_declared_installation_is_read_whole_or_not_at_all() {
        let declared = read_files(answer(
            0,
            &bundle(&[("/etc/your-cloud/roles", "relay\nagent")]),
        ));
        assert_eq!(
            read_installation(&declared),
            Observed::Known(Installation::Declared(vec![Role::Relay, Role::Agent]))
        );

        let empty = read_files(answer(0, &bundle(&[("/etc/your-cloud/roles", "")])));
        assert_eq!(
            read_installation(&empty),
            Observed::Known(Installation::Declared(Vec::new()))
        );

        for hostile in ["controller\ncontroller", "controller\nsomething-else"] {
            let files = read_files(answer(0, &bundle(&[("/etc/your-cloud/roles", hostile)])));
            assert_eq!(
                read_installation(&files),
                Observed::Unknown(Unverified::Unreadable),
                "{hostile} must not be read as a partial installation"
            );
        }
    }

    /// Output that is not the ASCII the fixed locale produces is refused whole.
    #[test]
    fn a_stream_outside_printable_ascii_is_never_parsed() {
        let hostile = ChannelAnswer {
            exit_status: 0,
            stdout: b"x86_64\xff\n",
            stderr: b"",
        };
        assert_eq!(
            read_architecture(hostile),
            Observed::Unknown(Unverified::NotProduced)
        );
        assert_eq!(read_files(hostile), FileBundle::default());
    }

    #[test]
    fn processor_ranges_are_counted_rather_than_read_as_an_index() {
        for (list, expected) in [
            ("0", Observed::Known(1)),
            ("0-1", Observed::Known(2)),
            ("0,2-3", Observed::Known(3)),
            ("0-", Observed::Unknown(Unverified::Unreadable)),
            ("3-0", Observed::Unknown(Unverified::Unreadable)),
            ("many", Observed::Unknown(Unverified::Unreadable)),
        ] {
            let files = read_files(answer(
                0,
                &bundle(&[("/sys/devices/system/cpu/online", list)]),
            ));
            assert_eq!(read_processors(&files), expected, "{list}");
        }
    }

    #[test]
    fn memory_is_only_read_in_the_unit_it_is_written_in() {
        for (line, expected) in [
            ("MemTotal:  991164 kB", Observed::Known(991_164)),
            (
                "MemTotal:  991164 MB",
                Observed::Unknown(Unverified::Unreadable),
            ),
            (
                "MemTotal:  many kB",
                Observed::Unknown(Unverified::Unreadable),
            ),
            ("MemFree:  1 kB", Observed::Unknown(Unverified::Unreadable)),
        ] {
            let files = read_files(answer(0, &bundle(&[("/proc/meminfo", line)])));
            assert_eq!(read_memory(&files), expected, "{line}");
        }
    }
}
