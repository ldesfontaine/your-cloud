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

#[cfg(not(target_os = "linux"))]
pub(crate) fn apply() -> Result<(), HardeningError> {
    // Windows process containment and anti-dump protections belong to the next native UI lot.
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
