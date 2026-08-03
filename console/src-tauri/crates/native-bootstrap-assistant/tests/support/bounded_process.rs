//! Bounded process handling shared by the Linux contract suites.
//!
//! Every wait here has a deadline and every capture has a ceiling, because a
//! contract suite that can hang is a contract suite that stops being run. The
//! helpers were written for the process contract and are shared rather than
//! copied: a second suite reproducing them approximately would eventually
//! disagree with the first about what "bounded" means, and the disagreement
//! would surface as a flaky proof rather than as an error.
//!
//! Each suite includes this file with `#[path]`, the same way the crash canary
//! is shared between the fixture and its suite, so nothing here becomes a test
//! target of its own. A suite that uses only part of it is expected: the
//! module is a toolbox, not an interface.

#![allow(dead_code)]

use std::{
    fs::File,
    io::{self, Read},
    os::fd::AsRawFd,
    process::{Child, ExitStatus, Output},
    thread,
    time::{Duration, Instant},
};

/// Longest a killed subprocess may take to be reaped.
pub const REAP_TIMEOUT: Duration = Duration::from_secs(2);

/// Longest a closed pipe may take to report its end of file.
pub const PIPE_EOF_TIMEOUT: Duration = Duration::from_secs(1);

/// Largest capture accepted from one subprocess stream.
pub const MAX_CAPTURED_OUTPUT: usize = 64 * 1024;

/// Answers whether a descriptor is already at end of file, without blocking
/// past `timeout`. A descriptor that is readable is not at end of file.
pub fn read_eof_bounded(reader: &mut File, timeout: Duration) -> io::Result<bool> {
    let deadline = Instant::now() + timeout;
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Ok(true),
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
    }
}

/// Waits for a subprocess and drains both its pipes, all under bounds.
pub fn collect_output_bounded(mut child: Child, timeout: Duration) -> io::Result<Output> {
    let status = wait_bounded(&mut child, timeout)?;
    let stdout = read_pipe_to_eof_bounded(
        &mut child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("child stdout was not piped"))?,
        PIPE_EOF_TIMEOUT,
    )?;
    let stderr = read_pipe_to_eof_bounded(
        &mut child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("child stderr was not piped"))?,
        PIPE_EOF_TIMEOUT,
    )?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

/// Reads one pipe to its end of file, refusing both an unbounded wait and an
/// unbounded capture.
pub fn read_pipe_to_eof_bounded<R>(reader: &mut R, timeout: Duration) -> io::Result<Vec<u8>>
where
    R: Read + AsRawFd,
{
    let descriptor = reader.as_raw_fd();
    // SAFETY: reader owns a valid descriptor for the duration of both fcntl calls.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: reader still owns the descriptor and O_NONBLOCK is a valid status flag.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }

    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::other("pipe EOF deadline overflow"))?;
    let mut output = Vec::new();
    let mut buffer = [0_u8; 4_096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(output),
            Ok(length) => {
                if output.len().saturating_add(length) > MAX_CAPTURED_OUTPUT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "child output exceeded the bounded capture size",
                    ));
                }
                output.extend_from_slice(&buffer[..length]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child output did not reach EOF before the deadline",
                ));
            }
            Err(error) => return Err(error),
        }
    }
}

/// Waits for a subprocess to stop, and kills it rather than waiting forever.
pub fn wait_bounded(child: &mut Child, timeout: Duration) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let cleanup = terminate_and_reap_bounded(child, REAP_TIMEOUT);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("subprocess did not stop before the deadline; cleanup: {cleanup:?}"),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Kills a subprocess and proves it was reaped, both under a bound.
pub fn terminate_and_reap_bounded(child: &mut Child, timeout: Duration) -> io::Result<ExitStatus> {
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    if let Err(kill_error) = child.kill() {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        return Err(kill_error);
    }

    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::other("process reap deadline overflow"))?;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "killed subprocess was not reaped before the deadline",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}
