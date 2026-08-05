//! Opening the one personal key file the user selected, and nothing else.
//!
//! This is the observing half of [`super::openssh_key`], which decides without
//! acting. Everything here is an operation on the file system, and each one is
//! written so that the bytes the decision was taken on are the bytes the
//! derivation will consume:
//!
//! * the path comes from the native selector of the helper's own window, never
//!   from the WebView, and it is required to be absolute;
//! * the file is opened **once**, without following a symbolic link, and every
//!   later read and every later observation goes through that one descriptor;
//! * the file is never written, never truncated and never created: the open
//!   flags carry no write intent at all, which is what "the personal file stays
//!   bit for bit unchanged" rests on;
//! * the identity of what was opened — device, inode, links, mode, owner, size
//!   and both timestamps — is recorded at the open, confirmed again once the
//!   read has reached its end, and confirmed a third time before the key
//!   derivation is paid for.
//!
//! That third confirmation is the whole point of the module. A path is not a
//! file: between the moment the selector answered and the moment the passphrase
//! has been typed, anything may have replaced what that path names. The bytes
//! in hand would still decrypt — they are the ones that were validated — but
//! they would no longer be the file the user is looking at. So the substitution
//! is refused rather than silently preferred, and [`SelectedKeyFile::confirm`]
//! is the single line that refuses it.
//!
//! The bytes read are kept in a buffer that wipes itself on every exit. They
//! are ciphertext, not the key, but they are the user's file and this process
//! has no reason to leave a copy of it behind once it is done.

use std::{
    fs::File,
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic,
};

use super::openssh_key::{self, EnvelopeRefusal, ValidatedEnvelope, MAX_KEY_FILE_BYTES};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyFileRefusal {
    /// The selector answered something that is not an absolute path.
    NotAbsolute,
    /// The final component is a symbolic link. It is refused rather than
    /// followed: a link is an instruction to read somewhere else, and this
    /// process only reads what was named.
    SymbolicLink,
    /// The path names something that is not a regular file.
    NotRegularFile,
    /// The file could not be opened, or could not be read whole.
    Unreadable,
    /// The file announces, or delivers, more than the bound allows.
    TooLarge,
    /// What the path names is no longer what was opened and validated.
    Substituted,
    Envelope(EnvelopeRefusal),
}

/// Everything that identifies one file, as the kernel reports it.
///
/// Size and both timestamps are part of it deliberately: an inode that keeps
/// its number while its content is rewritten in place is exactly the case a
/// device-and-inode comparison alone would miss.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    links: u64,
    mode: u32,
    owner: u32,
    group: u32,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileIdentity {
    fn of(file: &File) -> Result<Self, KeyFileRefusal> {
        let metadata = file.metadata().map_err(|_| KeyFileRefusal::Unreadable)?;
        if !metadata.is_file() {
            return Err(KeyFileRefusal::NotRegularFile);
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            links: metadata.nlink(),
            mode: metadata.mode(),
            owner: metadata.uid(),
            group: metadata.gid(),
            size: metadata.size(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

/// A bounded buffer that wipes itself on every exit.
///
/// The bytes it holds are an encrypted key file: not the private key, but the
/// user's own material all the same. It is deliberately not the protected
/// allocation of [`crate::secret`], which is sized and locked for a passphrase;
/// what is promised here is erasure, and erasure is what is implemented.
pub(crate) struct WipedBytes {
    bytes: Vec<u8>,
    kept: usize,
}

impl WipedBytes {
    /// Reserves, and initialises, exactly `capacity` bytes. The reservation is
    /// never grown afterwards.
    fn reserved(capacity: usize) -> Self {
        Self {
            bytes: vec![0_u8; capacity],
            kept: 0,
        }
    }

    fn reservation(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Narrows the logical view to what was really read. The tail stays
    /// allocated, and is wiped with the rest on drop.
    fn keep(&mut self, len: usize) {
        self.kept = len;
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.kept]
    }
}

impl Drop for WipedBytes {
    fn drop(&mut self) {
        // The whole reserved capacity is wiped, not only the logical length: a
        // read that overshot and was refused still touched those bytes.
        let capacity = self.bytes.capacity();
        let pointer = self.bytes.as_mut_ptr();
        for offset in 0..capacity {
            unsafe {
                // The allocation is live until this Vec is dropped below, and
                // volatile stores keep the wipe from being optimised away.
                std::ptr::write_volatile(pointer.add(offset), 0);
            }
        }
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl std::fmt::Debug for WipedBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WipedBytes([REDACTED])")
    }
}

/// One personal key file, opened once, validated, and still open.
///
/// It keeps its descriptor for as long as it exists so that the identity it
/// recorded can be confirmed against the file itself and not merely against the
/// path — a path can be made to name anything, a descriptor cannot.
pub struct SelectedKeyFile {
    file: File,
    path: PathBuf,
    identity: FileIdentity,
    bytes: WipedBytes,
    envelope: ValidatedEnvelope,
}

/// The path a user chose is their own business and never travels anywhere.
impl std::fmt::Debug for SelectedKeyFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SelectedKeyFile([REDACTED])")
    }
}

impl SelectedKeyFile {
    /// What the envelope declared, once every pre-derivation check passed.
    pub fn envelope(&self) -> ValidatedEnvelope {
        self.envelope
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Confirms that what will be used is still what was validated.
    ///
    /// Three questions, because a substitution happens in three ways and no
    /// single one of them catches the others. The path is asked whether it
    /// still leads to this very inode: a rename over the name leaves the
    /// descriptor perfectly valid while the user's selection now means
    /// something else. The descriptor is asked whether its own metadata still
    /// match. And the content is compared, because metadata alone would miss a
    /// file rewritten in place.
    pub fn confirm(&self) -> Result<(), KeyFileRefusal> {
        let named =
            std::fs::symlink_metadata(&self.path).map_err(|_| KeyFileRefusal::Unreadable)?;
        if named.file_type().is_symlink() {
            return Err(KeyFileRefusal::SymbolicLink);
        }
        if named.dev() != self.identity.device || named.ino() != self.identity.inode {
            return Err(KeyFileRefusal::Substituted);
        }

        let opened = FileIdentity::of(&self.file)?;
        if opened != self.identity {
            return Err(KeyFileRefusal::Substituted);
        }

        // And then the bytes themselves, read again from the same descriptor.
        // Metadata are a poor witness of content: a file rewritten in place
        // keeps its inode, and on a file system whose timestamps have only
        // second resolution it keeps those too. Comparing the bytes is cheap
        // here — the whole file is at most 64 KiB — and it is the only
        // comparison that answers the question actually being asked.
        let mut current = WipedBytes::reserved(MAX_KEY_FILE_BYTES + 1);
        let read = read_bounded_at(&self.file, current.reservation())?;
        current.keep(read);
        if current.as_slice() != self.bytes.as_slice() {
            return Err(KeyFileRefusal::Substituted);
        }
        Ok(())
    }
}

/// Fills `buffer` from `file` until end of file, and answers how much arrived.
///
/// It is a loop rather than one `read_to_end` because the buffer must be the
/// one reserved above: a helper that may reallocate would leave an unwiped copy
/// of the user's file behind.
fn read_bounded(mut file: &File, buffer: &mut [u8]) -> Result<usize, KeyFileRefusal> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..]) {
            Ok(0) => return Ok(filled),
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(KeyFileRefusal::Unreadable),
        }
    }
    Ok(filled)
}

/// Reads the whole file from `file`, from its start, without moving any cursor.
///
/// The positional read matters: the descriptor is the one held for the whole
/// life of the selection, and re-reading it must not depend on, or disturb, a
/// shared offset.
fn read_bounded_at(file: &File, buffer: &mut [u8]) -> Result<usize, KeyFileRefusal> {
    use std::os::unix::fs::FileExt;

    let mut filled = 0;
    while filled < buffer.len() {
        match file.read_at(&mut buffer[filled..], filled as u64) {
            Ok(0) => return Ok(filled),
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(KeyFileRefusal::Unreadable),
        }
    }
    Ok(filled)
}

/// Opens the selected file and validates its envelope, deriving nothing.
///
/// Returning `Ok` means a passphrase may now be asked for. It does not mean the
/// passphrase is known, the key is usable, or a connection is authorised.
pub fn open_and_validate(path: &Path) -> Result<SelectedKeyFile, KeyFileRefusal> {
    if !path.is_absolute() {
        return Err(KeyFileRefusal::NotAbsolute);
    }

    // Read only, no creation, no truncation, no controlling terminal, and the
    // final component is never followed. `O_CLOEXEC` matters even though this
    // process runs no child: the descriptor must not become inheritable by
    // anything the transport starts underneath it.
    let file = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(path)
        .map_err(|error| match error.raw_os_error() {
            Some(libc::ELOOP) => KeyFileRefusal::SymbolicLink,
            // A directory opened read-only succeeds on some systems and fails
            // with EISDIR on others; both end up refused, here or at the fstat.
            Some(libc::EISDIR) => KeyFileRefusal::NotRegularFile,
            _ => KeyFileRefusal::Unreadable,
        })?;

    let identity = FileIdentity::of(&file)?;
    // The announced size is judged before a single byte is read.
    if identity.size > MAX_KEY_FILE_BYTES as u64 {
        return Err(KeyFileRefusal::TooLarge);
    }

    // One byte past the bound is read on purpose: a file that grew between the
    // fstat and the read must be refused rather than silently truncated. The
    // buffer is reserved and filled in place rather than grown, so no earlier
    // allocation holding a copy of these bytes can be left behind unwiped.
    let mut bytes = WipedBytes::reserved(MAX_KEY_FILE_BYTES + 1);
    let read = read_bounded(&file, bytes.reservation())?;
    if read > MAX_KEY_FILE_BYTES {
        return Err(KeyFileRefusal::TooLarge);
    }
    bytes.keep(read);

    // The identity is revalidated during the opening itself: what was read must
    // come from the file that was measured, whole and unchanged.
    let after = FileIdentity::of(&file)?;
    if after != identity || after.size != read as u64 {
        return Err(KeyFileRefusal::Substituted);
    }

    let envelope = openssh_key::validate(bytes.as_slice()).map_err(KeyFileRefusal::Envelope)?;
    let selected = SelectedKeyFile {
        file,
        path: path.to_path_buf(),
        identity,
        bytes,
        envelope,
    };
    // And the name must still lead to it, which is the check a path-based open
    // can never make afterwards.
    selected.confirm()?;
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The buffer exposes only what was read, and keeps the rest reserved so
    /// the wipe covers every byte the read could have touched.
    #[test]
    fn the_read_buffer_exposes_only_what_was_kept() {
        let mut bytes = WipedBytes::reserved(64);
        assert_eq!(bytes.as_slice(), b"");
        bytes.reservation()[..16].copy_from_slice(b"synthetic-canary");
        bytes.keep(16);
        assert_eq!(bytes.as_slice(), b"synthetic-canary");
        assert_eq!(bytes.bytes.len(), 64, "the reservation is never shrunk");
        assert_eq!(format!("{bytes:?}"), "WipedBytes([REDACTED])");
    }

    /// A selected key file is never a value that can be compared or copied, so
    /// every case below reads the refusal rather than the whole result.
    fn refusal(path: &str) -> KeyFileRefusal {
        open_and_validate(Path::new(path))
            .err()
            .unwrap_or_else(|| panic!("{path} must never be opened as a personal key"))
    }

    #[test]
    fn a_relative_path_is_refused_before_anything_is_opened() {
        assert_eq!(refusal("relative/key"), KeyFileRefusal::NotAbsolute);
    }

    /// Neither a directory, nor a device, nor a name that leads nowhere is a
    /// key file, and each is refused for its own reason.
    #[test]
    fn only_a_regular_file_is_ever_opened_as_a_personal_key() {
        assert_eq!(refusal("/"), KeyFileRefusal::NotRegularFile);
        assert_eq!(refusal("/dev/zero"), KeyFileRefusal::NotRegularFile);
        assert_eq!(
            refusal("/nonexistent-your-cloud-personal-key"),
            KeyFileRefusal::Unreadable
        );
    }
}
