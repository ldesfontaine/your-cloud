use std::{fmt, io, ptr::NonNull, slice, sync::atomic};

pub(crate) const MAX_SECRET_BYTES: usize = 4_096;

pub(crate) struct ProtectedSecret {
    allocation: ProtectedAllocation,
    len: usize,
}

impl ProtectedSecret {
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            allocation: ProtectedAllocation::new()?,
            len: 0,
        })
    }

    pub(crate) fn copy_from(&mut self, source: &[u8]) -> io::Result<()> {
        if let Err(error) = validate_len(source.len()) {
            self.clear();
            return Err(error);
        }
        self.clear();
        unsafe {
            // The protected allocation is live for the lifetime of self, and
            // validate_len keeps the copy inside its dedicated region.
            std::ptr::copy_nonoverlapping(
                source.as_ptr(),
                self.allocation.ptr().as_ptr(),
                source.len(),
            );
        }
        self.len = source.len();
        Ok(())
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        unsafe {
            // len is changed only through the checked setters in this module.
            slice::from_raw_parts(self.allocation.ptr().as_ptr(), self.len)
        }
    }

    pub(crate) fn raw_mut(&mut self) -> &mut [u8] {
        self.clear();
        unsafe {
            // The OS allocation has exactly MAX_SECRET_BYTES initialized bytes
            // and is exclusively borrowed through self for this call.
            slice::from_raw_parts_mut(self.allocation.ptr().as_ptr(), MAX_SECRET_BYTES)
        }
    }

    pub(crate) fn set_len(&mut self, len: usize) -> io::Result<()> {
        if let Err(error) = validate_len(len) {
            self.clear();
            return Err(error);
        }
        unsafe {
            // Direct native input can have touched more bytes than its final
            // logical length. Erase the complete tail before exposing bytes().
            volatile_zero(
                self.allocation.ptr().as_ptr().add(len),
                MAX_SECRET_BYTES - len,
            );
        }
        self.len = len;
        Ok(())
    }

    pub(crate) fn clear(&mut self) {
        unsafe {
            volatile_zero(self.allocation.ptr().as_ptr(), MAX_SECRET_BYTES);
        }
        self.len = 0;
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Le canari mémoire de `#45`, exposé au crate.
    ///
    /// Il était privé à ce module tant que seul lui avait à prouver un
    /// effacement. Depuis que l'ordonnanceur détient un secret le temps d'une
    /// séquence, la destruction qu'il promet doit se prouver **en mémoire** et
    /// non seulement en logique — et la prouver ailleurs demanderait d'inventer
    /// un second canari, donc une seconde définition de ce que « effacé » veut
    /// dire. Il reste `#[cfg(test)]` : rien de tout cela n'entre dans un
    /// binaire livré.
    #[cfg(test)]
    pub(crate) fn observe_wipe_for_test(&mut self, observer: impl FnOnce(&[u8]) + Send + 'static) {
        self.allocation.wipe_observer = Some(Box::new(observer));
    }
}

/// A protected secret owns its mapping exclusively: nothing else holds the
/// pointer, and every accessor borrows through `self`. Moving that ownership to
/// another thread is therefore sound, and it is what the bounded key derivation
/// needs — the passphrase is handed to the thread that derives, so that thread
/// alone owns it and wipes it whether the derivation is used or abandoned.
///
/// `Sync` is deliberately not claimed: two threads must never share one secret.
unsafe impl Send for ProtectedSecret {}

impl fmt::Debug for ProtectedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedSecret([REDACTED])")
    }
}

fn validate_len(len: usize) -> io::Result<()> {
    if len <= MAX_SECRET_BYTES {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native secret exceeds protected capacity",
        ))
    }
}

unsafe fn volatile_zero(pointer: *mut u8, len: usize) {
    for offset in 0..len {
        unsafe {
            // Volatile stores prevent the compiler from removing the wipe as a
            // dead write immediately before the region is released.
            std::ptr::write_volatile(pointer.add(offset), 0);
        }
    }
    atomic::compiler_fence(atomic::Ordering::SeqCst);
}

struct ProtectedAllocation {
    pointer: NonNull<u8>,
    #[cfg(test)]
    wipe_observer: Option<Box<dyn FnOnce(&[u8]) + Send>>,
}

impl ProtectedAllocation {
    fn new() -> io::Result<Self> {
        Ok(Self {
            pointer: os::allocate()?,
            #[cfg(test)]
            wipe_observer: None,
        })
    }

    fn ptr(&self) -> NonNull<u8> {
        self.pointer
    }
}

impl Drop for ProtectedAllocation {
    fn drop(&mut self) {
        unsafe {
            volatile_zero(self.pointer.as_ptr(), MAX_SECRET_BYTES);
        }
        #[cfg(test)]
        if let Some(observer) = self.wipe_observer.take() {
            let wiped = unsafe {
                // The observer runs after the volatile wipe and before the OS
                // mapping is unlocked or released.
                slice::from_raw_parts(self.pointer.as_ptr(), MAX_SECRET_BYTES)
            };
            observer(wiped);
        }
        unsafe {
            os::release(self.pointer);
        }
    }
}

#[cfg(target_os = "linux")]
mod os {
    use super::{volatile_zero, MAX_SECRET_BYTES};
    use std::{ffi::c_void, io, ptr::NonNull};

    pub(super) fn allocate() -> io::Result<NonNull<u8>> {
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                MAX_SECRET_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(stage_error("mmap"));
        }
        let Some(pointer) = NonNull::new(raw.cast::<u8>()) else {
            unsafe {
                let _ = libc::munmap(raw, MAX_SECRET_BYTES);
            }
            return Err(io::Error::other("mmap returned a null address"));
        };

        if unsafe { libc::mlock(raw, MAX_SECRET_BYTES) } != 0 {
            let error = stage_error("mlock");
            unsafe {
                let _ = libc::munmap(raw, MAX_SECRET_BYTES);
            }
            return Err(error);
        }
        if unsafe { libc::madvise(raw, MAX_SECRET_BYTES, libc::MADV_DONTDUMP) } != 0 {
            let error = stage_error("madvise(MADV_DONTDUMP)");
            unsafe {
                volatile_zero(pointer.as_ptr(), MAX_SECRET_BYTES);
                let _ = libc::munlock(raw, MAX_SECRET_BYTES);
                let _ = libc::munmap(raw, MAX_SECRET_BYTES);
            }
            return Err(error);
        }

        Ok(pointer)
    }

    pub(super) unsafe fn release(pointer: NonNull<u8>) {
        let raw = pointer.as_ptr().cast::<c_void>();
        unsafe {
            let _ = libc::munlock(raw, MAX_SECRET_BYTES);
            let _ = libc::munmap(raw, MAX_SECRET_BYTES);
        }
    }

    fn stage_error(stage: &'static str) -> io::Error {
        let source = io::Error::last_os_error();
        io::Error::new(source.kind(), format!("{stage} failed: {source}"))
    }
}

#[cfg(target_os = "windows")]
mod os {
    use super::{volatile_zero, MAX_SECRET_BYTES};
    use std::{ffi::c_void, io, ptr::NonNull};
    use windows_sys::Win32::System::{
        ErrorReporting::{WerRegisterExcludedMemoryBlock, WerUnregisterExcludedMemoryBlock},
        Memory::{
            VirtualAlloc, VirtualFree, VirtualLock, VirtualUnlock, MEM_COMMIT, MEM_RELEASE,
            MEM_RESERVE, PAGE_READWRITE,
        },
    };

    pub(super) fn allocate() -> io::Result<NonNull<u8>> {
        let raw = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                MAX_SECRET_BYTES,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        let Some(pointer) = NonNull::new(raw.cast::<u8>()) else {
            return Err(stage_error("VirtualAlloc"));
        };

        if unsafe { VirtualLock(raw, MAX_SECRET_BYTES) } == 0 {
            let error = stage_error("VirtualLock");
            unsafe {
                let _ = VirtualFree(raw, 0, MEM_RELEASE);
            }
            return Err(error);
        }

        let wer_result =
            unsafe { WerRegisterExcludedMemoryBlock(raw.cast_const(), MAX_SECRET_BYTES as u32) };
        if wer_result < 0 {
            unsafe {
                volatile_zero(pointer.as_ptr(), MAX_SECRET_BYTES);
                let _ = VirtualUnlock(raw, MAX_SECRET_BYTES);
                let _ = VirtualFree(raw, 0, MEM_RELEASE);
            }
            return Err(io::Error::other(format!(
                "WerRegisterExcludedMemoryBlock failed with HRESULT {wer_result:#010x}"
            )));
        }

        Ok(pointer)
    }

    pub(super) unsafe fn release(pointer: NonNull<u8>) {
        let raw = pointer.as_ptr().cast::<c_void>();
        unsafe {
            let _ = WerUnregisterExcludedMemoryBlock(raw.cast_const());
            let _ = VirtualUnlock(raw, MAX_SECRET_BYTES);
            let _ = VirtualFree(raw, 0, MEM_RELEASE);
        }
    }

    fn stage_error(stage: &'static str) -> io::Error {
        let source = io::Error::last_os_error();
        io::Error::new(source.kind(), format!("{stage} failed: {source}"))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod os {
    use std::{io, ptr::NonNull};

    pub(super) fn allocate() -> io::Result<NonNull<u8>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "protected native secret memory is unsupported on this platform",
        ))
    }

    pub(super) unsafe fn release(_pointer: NonNull<u8>) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    #[test]
    fn length_bound_is_checked_without_touching_an_allocation() {
        assert!(validate_len(MAX_SECRET_BYTES).is_ok());
        assert_eq!(
            validate_len(MAX_SECRET_BYTES + 1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn copy_and_direct_input_stay_inside_the_fixed_capacity() {
        let mut secret = ProtectedSecret::new().expect("protected allocation");
        secret.copy_from(&[0x5a; 32]).expect("bounded copy");
        assert_eq!(secret.len(), 32);
        assert!(!secret.is_empty());

        secret.raw_mut()[..4].copy_from_slice(&[1, 2, 3, 4]);
        secret.set_len(4).expect("bounded direct input");
        assert!(secret.bytes().iter().copied().eq([1, 2, 3, 4]));

        let oversized = [0_u8; MAX_SECRET_BYTES + 1];
        assert_eq!(
            secret.copy_from(&oversized).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(secret.is_empty());
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn debug_is_always_redacted() {
        let mut secret = ProtectedSecret::new().expect("protected allocation");
        secret.copy_from(b"synthetic-canary").expect("bounded copy");

        assert_eq!(format!("{secret:?}"), "ProtectedSecret([REDACTED])");
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn drop_observer_sees_the_entire_allocation_wiped() {
        let wipe_observed = Arc::new(AtomicBool::new(false));
        let observer_flag = Arc::clone(&wipe_observed);
        let mut secret = ProtectedSecret::new().expect("protected allocation");
        secret.copy_from(&[0xa5; 64]).expect("bounded copy");
        secret.observe_wipe_for_test(move |bytes| {
            observer_flag.store(bytes.iter().all(|byte| *byte == 0), Ordering::SeqCst);
        });

        drop(secret);

        assert!(wipe_observed.load(Ordering::SeqCst));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_mapping_is_locked_and_excluded_from_core_dumps() {
        let secret = ProtectedSecret::new().expect("protected allocation");
        let address = secret.allocation.ptr().as_ptr() as usize;
        let smaps = std::fs::read_to_string("/proc/self/smaps").expect("read process mappings");
        let mapping = smaps_mapping_for_address(&smaps, address).expect("find protected mapping");
        let locked_kib = mapping
            .lines()
            .find_map(|line| line.strip_prefix("Locked:"))
            .and_then(|value| value.split_ascii_whitespace().next())
            .and_then(|value| value.parse::<usize>().ok())
            .expect("read locked size");
        let flags = mapping
            .lines()
            .find_map(|line| line.strip_prefix("VmFlags:"))
            .expect("read mapping flags");

        assert!(locked_kib >= MAX_SECRET_BYTES / 1_024);
        assert!(flags.split_ascii_whitespace().any(|flag| flag == "lo"));
        assert!(flags.split_ascii_whitespace().any(|flag| flag == "dd"));
    }

    #[cfg(target_os = "linux")]
    fn smaps_mapping_for_address(smaps: &str, address: usize) -> Option<&str> {
        let mut mapping_start = None;
        for (offset, line) in smaps.split_inclusive('\n').scan(0, |offset, line| {
            let current = *offset;
            *offset += line.len();
            Some((current, line))
        }) {
            let Some((start, end)) = line
                .split_ascii_whitespace()
                .next()
                .and_then(|range| range.split_once('-'))
                .and_then(|(start, end)| {
                    Some((
                        usize::from_str_radix(start, 16).ok()?,
                        usize::from_str_radix(end, 16).ok()?,
                    ))
                })
            else {
                continue;
            };
            if let Some(found) = mapping_start {
                return Some(&smaps[found..offset]);
            }
            if (start..end).contains(&address) {
                mapping_start = Some(offset);
            }
        }
        mapping_start.map(|start| &smaps[start..])
    }
}
