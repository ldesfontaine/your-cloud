mod crash_canary;
mod hardening;
mod secret;

use crash_canary::CANARY_BYTES;
use secret::ProtectedSecret;
use std::{
    hint::black_box,
    io::{self, Write},
    sync::atomic::{compiler_fence, Ordering},
};

const EXIT_INVALID_INVOCATION: i32 = 64;
const EXIT_UNAVAILABLE: i32 = 69;

fn main() {
    let mut arguments = std::env::args();
    let _executable = arguments.next();
    let mode = arguments.next();
    if arguments.next().is_some() {
        std::process::exit(EXIT_INVALID_INVOCATION);
    }

    let result = match mode.as_deref() {
        #[cfg(target_os = "linux")]
        Some("--linux-dumpable") => run_linux_dumpable(),
        #[cfg(target_os = "linux")]
        Some("--controlled-crash") => run_linux_controlled_crash(),
        #[cfg(target_os = "windows")]
        Some("--windows-wer-crash") => run_windows_wer_crash(),
        _ => std::process::exit(EXIT_INVALID_INVOCATION),
    };

    if result.is_err() {
        std::process::exit(EXIT_UNAVAILABLE);
    }
}

fn protected_payload() -> io::Result<(ProtectedSecret, Box<[u8; CANARY_BYTES]>)> {
    let pid = std::process::id();
    let mut secret = ProtectedSecret::new()?;
    let secret_storage = secret.raw_mut();
    for index in 0..CANARY_BYTES {
        unsafe {
            // The canary is derived directly into the protected mapping so the
            // fixture never owns a second contiguous copy of it.
            std::ptr::write_volatile(
                secret_storage.as_mut_ptr().add(index),
                crash_canary::secret_byte(pid, index),
            );
        }
    }
    secret.set_len(CANARY_BYTES)?;

    let mut dump_control = Box::new([0_u8; CANARY_BYTES]);
    for index in 0..CANARY_BYTES {
        unsafe {
            // This non-secret control must remain in an ordinary dumpable heap
            // mapping, proving that the dump and scanner contain live memory.
            std::ptr::write_volatile(
                dump_control.as_mut_ptr().add(index),
                crash_canary::control_byte(pid, index),
            );
        }
    }
    compiler_fence(Ordering::SeqCst);
    black_box(secret.bytes());
    black_box(dump_control.as_ref());
    Ok((secret, dump_control))
}

fn announce_ready() -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(b"READY\n")?;
    stdout.flush()
}

#[cfg(target_os = "linux")]
fn run_linux_dumpable() -> io::Result<()> {
    let parent = unsafe { libc::getppid() };
    if parent <= 1
        || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0
        || unsafe { libc::getppid() } != parent
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) } != 0
        || unsafe { libc::prctl(libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY) } != 0
    {
        return Err(io::Error::other("controlled dump setup failed"));
    }

    let (secret, dump_control) = protected_payload()?;
    announce_ready()?;
    loop {
        unsafe {
            black_box(std::ptr::read_volatile(secret.bytes().as_ptr()));
            black_box(std::ptr::read_volatile(dump_control.as_ptr()));
        }
        std::thread::park_timeout(std::time::Duration::from_secs(1));
    }
}

#[cfg(target_os = "linux")]
fn run_linux_controlled_crash() -> io::Result<()> {
    hardening::apply().map_err(|_| io::Error::other("hardening failed"))?;
    if unsafe { libc::prctl(libc::PR_GET_DUMPABLE) } != 0 {
        return Err(io::Error::other("process remains dumpable"));
    }
    let mut core_limit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut core_limit) } != 0
        || core_limit.rlim_cur != 0
        || core_limit.rlim_max != 0
    {
        return Err(io::Error::other("core limit remains enabled"));
    }

    let (secret, dump_control) = protected_payload()?;
    announce_ready()?;
    black_box(secret.bytes());
    black_box(dump_control.as_ref());
    std::process::abort();
}

#[cfg(target_os = "windows")]
fn run_windows_wer_crash() -> io::Result<()> {
    if unsafe { GetErrorMode() } & SEM_NOGPFAULTERRORBOX != 0 {
        return Err(io::Error::other(
            "inherited process error mode disables Windows Error Reporting",
        ));
    }
    hardening::apply().map_err(|_| io::Error::other("hardening failed"))?;
    let (secret, dump_control) = protected_payload()?;
    announce_ready()?;
    black_box(secret.bytes());
    black_box(dump_control.as_ref());

    unsafe {
        // RaiseFailFastException bypasses application handlers and explicitly enters Windows
        // Error Reporting without relying on undefined Rust memory access. The generated address
        // keeps the synthetic crash attributable to this exact call site.
        RaiseFailFastException(
            std::ptr::null(),
            std::ptr::null(),
            FAIL_FAST_GENERATE_EXCEPTION_ADDRESS,
        );
    }
    std::process::abort();
}

#[cfg(target_os = "windows")]
const FAIL_FAST_GENERATE_EXCEPTION_ADDRESS: u32 = 1;
#[cfg(target_os = "windows")]
const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn GetErrorMode() -> u32;
    fn RaiseFailFastException(
        exception_record: *const std::ffi::c_void,
        context_record: *const std::ffi::c_void,
        flags: u32,
    );
}
