#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HardeningError;

#[cfg(target_os = "linux")]
pub(crate) fn apply() -> Result<(), HardeningError> {
    let parent_before = unsafe { libc::getppid() };
    if !stable_parent(parent_before, parent_before) {
        return Err(HardeningError);
    }

    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
        return Err(HardeningError);
    }

    let parent_after = unsafe { libc::getppid() };
    if !stable_parent(parent_before, parent_after) {
        return Err(HardeningError);
    }

    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
        return Err(HardeningError);
    }

    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) } != 0 {
        return Err(HardeningError);
    }

    if unsafe { libc::syscall(libc::SYS_close_range, 3_u32, libc::c_uint::MAX, 0_u32) } != 0 {
        return Err(HardeningError);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn stable_parent(parent_before: libc::pid_t, parent_after: libc::pid_t) -> bool {
    parent_before > 1 && parent_before == parent_after
}

#[cfg(target_os = "windows")]
pub(crate) fn apply() -> Result<(), HardeningError> {
    use windows_sys::Win32::{
        Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE},
        System::App::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
    };

    // The parent supplies exactly these anonymous-pipe endpoints. Removing their
    // inherit flag before reading the protocol prevents a future child from
    // prolonging the session by retaining one of those endpoints.
    for standard_handle in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let handle = unsafe { GetStdHandle(standard_handle) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(HardeningError);
        }
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(HardeningError);
        }
    }

    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub(crate) fn apply() -> Result<(), HardeningError> {
    // Unsupported targets never reach a prepared release artifact.
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn parent_must_exist_and_remain_identical() {
        assert!(stable_parent(42, 42));
        assert!(!stable_parent(1, 1));
        assert!(!stable_parent(42, 43));
    }
}
