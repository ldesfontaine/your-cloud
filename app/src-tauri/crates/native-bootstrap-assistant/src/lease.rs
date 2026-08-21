use std::{
    fs::File,
    io::{self, Read},
    sync::{
        atomic::{AtomicU8, Ordering},
        mpsc, Arc, Condvar, Mutex,
    },
    thread,
    time::Duration,
};

const ACTIVE: u8 = 0;
const CANCELLED: u8 = 1;
const PROTOCOL_INVALID: u8 = 2;
const INPUT_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn DuplicateHandle(
        source_process: *mut std::ffi::c_void,
        source: *mut std::ffi::c_void,
        target_process: *mut std::ffi::c_void,
        target: *mut *mut std::ffi::c_void,
        desired_access: u32,
        inherit: i32,
        options: u32,
    ) -> i32;
    fn PeekNamedPipe(
        named_pipe: *mut std::ffi::c_void,
        buffer: *mut std::ffi::c_void,
        buffer_size: u32,
        bytes_read: *mut u32,
        total_bytes_available: *mut u32,
        bytes_left_this_message: *mut u32,
    ) -> i32;
}

#[cfg(target_os = "windows")]
const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeaseResolution {
    Active,
    Cancelled,
    ProtocolInvalid,
}

/// A unique, unbuffered duplicate of the inherited stdin pipe. The same file
/// reads the public scope and is then moved into the lease monitor, so no byte
/// can be stranded in `std::io::Stdin`'s private buffer between those phases.
pub(crate) struct UnbufferedStandardInput {
    file: File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TransportPeerIdentity {
    process_id: u32,
}

impl UnbufferedStandardInput {
    #[cfg(target_os = "linux")]
    pub(crate) fn open() -> Result<Self, ()> {
        use std::os::fd::FromRawFd;

        // SAFETY: fcntl only duplicates descriptor 0. A non-negative result is
        // a new uniquely owned descriptor suitable for File::from_raw_fd.
        let duplicate = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(());
        }
        Ok(Self {
            // SAFETY: duplicate is a fresh descriptor owned by this value.
            file: unsafe { File::from_raw_fd(duplicate) },
        })
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn open() -> Result<Self, ()> {
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::{
            Foundation::INVALID_HANDLE_VALUE,
            System::{
                Console::{GetStdHandle, STD_INPUT_HANDLE},
                Threading::GetCurrentProcess,
            },
        };

        // SAFETY: querying the process standard-input and pseudo-process handles
        // transfers no ownership.
        let source = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if source.is_null() || source == INVALID_HANDLE_VALUE {
            return Err(());
        }
        let process = unsafe { GetCurrentProcess() };
        let mut duplicate = std::ptr::null_mut();
        // SAFETY: source and process are live handles. `duplicate` is valid
        // output storage and becomes uniquely owned only when the call succeeds.
        if unsafe {
            DuplicateHandle(
                process,
                source,
                process,
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
            || duplicate.is_null()
            || duplicate == INVALID_HANDLE_VALUE
        {
            return Err(());
        }
        Ok(Self {
            // SAFETY: DuplicateHandle returned a fresh uniquely owned handle.
            file: unsafe { File::from_raw_handle(duplicate) },
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    pub(crate) fn open() -> Result<Self, ()> {
        Err(())
    }

    /// Binds the inherited stdin lease to the process that created its peer.
    /// A forged OS parent relation is insufficient when the transport was
    /// created by a different process.
    pub(crate) fn authenticate_parent_process(&self, expected_parent_pid: u32) -> Result<(), ()> {
        let peer = self.transport_peer_identity()?;
        (peer.process_id == expected_parent_pid)
            .then_some(())
            .ok_or(())
    }

    #[cfg(target_os = "linux")]
    fn transport_peer_identity(&self) -> Result<TransportPeerIdentity, ()> {
        use std::{mem::size_of, os::fd::AsRawFd};

        let mut credentials = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut length = libc::socklen_t::try_from(size_of::<libc::ucred>()).map_err(|_| ())?;
        // SAFETY: file owns a live descriptor and both credential output pointers
        // remain valid for the exact declared ucred size.
        let result = unsafe {
            libc::getsockopt(
                self.file.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        };
        if result != 0
            || usize::try_from(length).ok() != Some(size_of::<libc::ucred>())
            || credentials.pid <= 0
            || credentials.uid != unsafe { libc::geteuid() }
            || credentials.gid != unsafe { libc::getegid() }
        {
            return Err(());
        }
        Ok(TransportPeerIdentity {
            process_id: u32::try_from(credentials.pid).map_err(|_| ())?,
        })
    }

    #[cfg(target_os = "windows")]
    fn transport_peer_identity(&self) -> Result<TransportPeerIdentity, ()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{
            Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE},
            System::Pipes::GetNamedPipeClientProcessId,
        };

        let handle = self.file.as_raw_handle();
        // The child owns the server/read end returned by CreatePipe. Only its
        // client/writer peer identifies the App that created the lease.
        if unsafe { GetFileType(handle) } != FILE_TYPE_PIPE {
            return Err(());
        }
        let mut process_id = 0_u32;
        // SAFETY: handle is the live stdin pipe handle and process_id is valid
        // writable storage for the peer process identifier.
        if unsafe { GetNamedPipeClientProcessId(handle, &mut process_id) } == 0 || process_id == 0 {
            return Err(());
        }
        Ok(TransportPeerIdentity { process_id })
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn transport_peer_identity(&self) -> Result<TransportPeerIdentity, ()> {
        Err(())
    }
}

impl Read for UnbufferedStandardInput {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

#[derive(Default)]
struct LeaseLifecycle {
    closing: bool,
    finished: bool,
}

struct LeaseInner {
    state: AtomicU8,
    lifecycle: Mutex<LeaseLifecycle>,
    changed: Condvar,
}

impl LeaseInner {
    fn pending() -> Self {
        Self {
            state: AtomicU8::new(ACTIVE),
            lifecycle: Mutex::new(LeaseLifecycle::default()),
            changed: Condvar::new(),
        }
    }

    #[cfg(test)]
    fn finished_for_test() -> Self {
        Self {
            state: AtomicU8::new(ACTIVE),
            lifecycle: Mutex::new(LeaseLifecycle {
                closing: false,
                finished: true,
            }),
            changed: Condvar::new(),
        }
    }

    fn finish(&self, state: u8) {
        self.state.store(state, Ordering::SeqCst);
        let mut lifecycle = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        lifecycle.finished = true;
        self.changed.notify_all();
    }

    fn wait_until_closing_or_next_probe(&self) -> bool {
        let lifecycle = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if lifecycle.closing {
            return true;
        }
        let (lifecycle, _) = self
            .changed
            .wait_timeout(lifecycle, INPUT_POLL_INTERVAL)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        lifecycle.closing
    }
}

/// The parent keeps stdin open for the whole native prompt. EOF is the
/// cancellation lease; any byte after the single public scope is a protocol
/// violation, never an update to that scope.
#[derive(Clone)]
pub(crate) struct LeaseState {
    inner: Arc<LeaseInner>,
}

impl LeaseState {
    pub(crate) fn watch_standard_input(input: UnbufferedStandardInput) -> Result<Self, ()> {
        Self::spawn_monitor(move |inner, started| watch_standard_input(input, inner, started))
    }

    fn spawn_monitor(
        monitor: impl FnOnce(Arc<LeaseInner>, mpsc::SyncSender<()>) + Send + 'static,
    ) -> Result<Self, ()> {
        let inner = Arc::new(LeaseInner::pending());
        let worker_inner = Arc::clone(&inner);
        let (started, ready) = mpsc::sync_channel(0);
        thread::Builder::new()
            .name("bootstrap-parent-lease".into())
            .spawn(move || monitor(worker_inner, started))
            .map_err(|_| ())?;
        ready.recv().map_err(|_| ())?;
        Ok(Self { inner })
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.inner.state.load(Ordering::SeqCst) == CANCELLED
    }

    pub(crate) fn is_protocol_invalid(&self) -> bool {
        self.inner.state.load(Ordering::SeqCst) == PROTOCOL_INVALID
    }

    /// Linearizes the prompt result with the stdin lease. The monitor performs
    /// one last non-blocking probe after observing `closing`, then acknowledges
    /// that no input present at that probe can still change the terminal result.
    pub(crate) fn close_and_resolve(&self) -> LeaseResolution {
        let mut lifecycle = self
            .inner
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        lifecycle.closing = true;
        self.inner.changed.notify_all();
        while !lifecycle.finished {
            lifecycle = self
                .inner
                .changed
                .wait(lifecycle)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        match self.inner.state.load(Ordering::SeqCst) {
            CANCELLED => LeaseResolution::Cancelled,
            PROTOCOL_INVALID => LeaseResolution::ProtocolInvalid,
            _ => LeaseResolution::Active,
        }
    }

    #[cfg(test)]
    pub(crate) fn active_for_test() -> Self {
        Self {
            inner: Arc::new(LeaseInner::finished_for_test()),
        }
    }

    #[cfg(test)]
    fn watch_with_probe_for_test(
        probe: impl FnMut() -> InputProbe + Send + 'static,
    ) -> Result<Self, ()> {
        Self::spawn_monitor(move |inner, started| monitor_input(inner, started, probe))
    }

    #[cfg(test)]
    pub(crate) fn cancel_for_test(&self) {
        self.inner.state.store(CANCELLED, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn invalidate_for_test(&self) {
        self.inner.state.store(PROTOCOL_INVALID, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InputProbe {
    Pending,
    Resolved(u8),
}

#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WindowsPipeState {
    OpenEmpty,
    Readable,
    ClosedOrInvalid,
}

#[cfg(any(target_os = "windows", test))]
fn classify_windows_pipe(peek_succeeded: i32, available: u32) -> WindowsPipeState {
    if peek_succeeded == 0 {
        WindowsPipeState::ClosedOrInvalid
    } else if available == 0 {
        WindowsPipeState::OpenEmpty
    } else {
        WindowsPipeState::Readable
    }
}

fn monitor_input(
    inner: Arc<LeaseInner>,
    started: mpsc::SyncSender<()>,
    mut probe: impl FnMut() -> InputProbe,
) {
    let initial = probe();
    if let InputProbe::Resolved(state) = initial {
        inner.finish(state);
    }
    let _ = started.send(());
    if matches!(initial, InputProbe::Resolved(_)) {
        return;
    }

    loop {
        if inner.wait_until_closing_or_next_probe() {
            // This probe is the lease's linearization point with the prompt
            // outcome. Input already observable here always wins.
            match probe() {
                InputProbe::Resolved(state) => inner.finish(state),
                InputProbe::Pending => inner.finish(ACTIVE),
            }
            return;
        }
        if let InputProbe::Resolved(state) = probe() {
            inner.finish(state);
            return;
        }
    }
}

#[cfg(target_os = "linux")]
fn watch_standard_input(
    mut input: UnbufferedStandardInput,
    inner: Arc<LeaseInner>,
    started: mpsc::SyncSender<()>,
) {
    use std::os::fd::AsRawFd;

    let descriptor = input.file.as_raw_fd();
    monitor_input(inner, started, move || {
        probe_linux_input(&mut input, descriptor)
    });
}

#[cfg(target_os = "linux")]
fn probe_linux_input(reader: &mut impl Read, descriptor: std::os::fd::RawFd) -> InputProbe {
    let mut descriptor = libc::pollfd {
        fd: descriptor,
        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };
    loop {
        // SAFETY: descriptor points to one valid pollfd for the duration of the call.
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if result > 0 {
            if descriptor.revents & libc::POLLNVAL != 0 {
                return InputProbe::Resolved(CANCELLED);
            }
            if descriptor.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                return InputProbe::Resolved(read_control_byte(reader));
            }
            return InputProbe::Resolved(CANCELLED);
        }
        if result == 0 {
            return InputProbe::Pending;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return InputProbe::Resolved(CANCELLED);
        }
    }
}

#[cfg(target_os = "windows")]
fn watch_standard_input(
    mut input: UnbufferedStandardInput,
    inner: Arc<LeaseInner>,
    started: mpsc::SyncSender<()>,
) {
    use std::os::windows::io::AsRawHandle;

    let handle = input.file.as_raw_handle();
    monitor_input(inner, started, move || {
        probe_windows_input(&mut input, handle)
    });
}

#[cfg(target_os = "windows")]
fn probe_windows_input(
    reader: &mut impl Read,
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> InputProbe {
    let mut available = 0_u32;
    // SAFETY: handle is the live stdin pipe handle. No output buffer is supplied; only the
    // valid `available` pointer is written by PeekNamedPipe.
    let peeked = unsafe {
        PeekNamedPipe(
            handle,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        )
    };
    match classify_windows_pipe(peeked, available) {
        WindowsPipeState::ClosedOrInvalid => InputProbe::Resolved(CANCELLED),
        WindowsPipeState::OpenEmpty => InputProbe::Pending,
        WindowsPipeState::Readable => InputProbe::Resolved(read_control_byte(reader)),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn watch_standard_input(
    _input: UnbufferedStandardInput,
    inner: Arc<LeaseInner>,
    started: mpsc::SyncSender<()>,
) {
    monitor_input(inner, started, || InputProbe::Pending);
}

fn read_control_byte(reader: &mut impl Read) -> u8 {
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return CANCELLED,
            Ok(_) => return PROTOCOL_INVALID,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return CANCELLED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, io::Cursor};

    #[cfg(target_os = "linux")]
    use std::{
        os::fd::{FromRawFd, OwnedFd},
        os::unix::net::UnixStream,
    };

    #[cfg(target_os = "linux")]
    fn input_from_unix_stream(stream: UnixStream) -> UnbufferedStandardInput {
        let descriptor = OwnedFd::from(stream);
        UnbufferedStandardInput {
            file: File::from(descriptor),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unix_transport_accepts_only_the_process_that_created_its_peer() {
        let (child_end, _parent_end) = UnixStream::pair().unwrap();
        let input = input_from_unix_stream(child_end);
        let creator_pid = unsafe { libc::getpid() };
        let creator_pid = u32::try_from(creator_pid).unwrap();
        let unrelated_pid = if creator_pid == u32::MAX {
            creator_pid - 1
        } else {
            creator_pid + 1
        };

        assert_eq!(input.authenticate_parent_process(creator_pid), Ok(()));
        assert_eq!(input.authenticate_parent_process(unrelated_pid), Err(()));
    }

    #[cfg(target_os = "linux")]
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CloneParentProbe {
        child_socket: libc::c_int,
        peer_socket: libc::c_int,
        report: libc::c_int,
    }

    #[cfg(target_os = "linux")]
    type CloneParentWire = [i64; 5];

    #[cfg(target_os = "linux")]
    fn write_clone_parent_wire(descriptor: libc::c_int, wire: &CloneParentWire) -> bool {
        let bytes = std::mem::size_of_val(wire);
        (unsafe { libc::write(descriptor, wire.as_ptr().cast(), bytes) })
            == isize::try_from(bytes).unwrap_or(-1)
    }

    #[cfg(target_os = "linux")]
    extern "C" fn observe_clone_parent_transport(raw: *mut libc::c_void) -> libc::c_int {
        let probe = unsafe { &*(raw.cast::<CloneParentProbe>()) };
        let input = UnbufferedStandardInput {
            // SAFETY: the clone owns its descriptor-table copy of child_socket.
            file: unsafe { File::from_raw_fd(probe.child_socket) },
        };
        let parent = unsafe { libc::getppid() };
        let identity = input.transport_peer_identity().ok();
        let authenticated = u32::try_from(parent)
            .ok()
            .is_some_and(|pid| input.authenticate_parent_process(pid).is_ok());
        let record: CloneParentWire = [
            2,
            i64::from(unsafe { libc::getpid() }),
            i64::from(parent),
            i64::from(
                identity
                    .and_then(|peer| libc::pid_t::try_from(peer.process_id).ok())
                    .unwrap_or(0),
            ),
            if authenticated { 1 } else { 0 },
        ];
        let written = write_clone_parent_wire(probe.report, &record);
        unsafe {
            libc::close(probe.peer_socket);
            libc::close(probe.report);
        }
        if written {
            0
        } else {
            1
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn transport_peer_rejects_clone_parent_spoof() {
        const STACK_BYTES: usize = 1024 * 1024;

        let mut report = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(report.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let stack = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                STACK_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(stack, libc::MAP_FAILED);
        let app_pid = unsafe { libc::getpid() };
        let attacker_pid = unsafe { libc::fork() };
        assert!(attacker_pid >= 0);

        if attacker_pid == 0 {
            unsafe { libc::close(report[0]) };
            let mut sockets = [-1; 2];
            if unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    sockets.as_mut_ptr(),
                )
            } != 0
            {
                unsafe { libc::_exit(2) };
            }
            let mut probe = CloneParentProbe {
                child_socket: sockets[0],
                peer_socket: sockets[1],
                report: report[1],
            };
            let stack_top = unsafe { (stack.cast::<u8>()).add(STACK_BYTES) };
            let helper_pid = unsafe {
                libc::clone(
                    observe_clone_parent_transport,
                    stack_top.cast(),
                    libc::CLONE_PARENT | libc::SIGCHLD,
                    (&mut probe as *mut CloneParentProbe).cast(),
                )
            };
            let record: CloneParentWire = [1, i64::from(helper_pid), 0, 0, 0];
            let written = write_clone_parent_wire(report[1], &record);
            unsafe {
                libc::close(sockets[0]);
                libc::close(sockets[1]);
                libc::close(report[1]);
                libc::_exit(if helper_pid <= 0 || !written { 1 } else { 0 });
            }
        }

        unsafe { libc::close(report[1]) };
        // SAFETY: the parent owns the report read descriptor after closing its
        // writer. Both short-lived children close their copies before exit.
        let mut reader = unsafe { File::from_raw_fd(report[0]) };
        let wire_bytes = std::mem::size_of::<CloneParentWire>();
        let bytes =
            read_clone_parent_report_bounded(&mut reader, 2 * wire_bytes, Duration::from_secs(2));
        let records = decode_clone_parent_wires(&bytes);
        let helper_pid = records
            .iter()
            .find(|record| record[0] == 1)
            .and_then(|record| libc::pid_t::try_from(record[1]).ok());

        let attacker_status = wait_clone_child_bounded(attacker_pid, Duration::from_secs(2));
        let helper_status =
            helper_pid.and_then(|pid| wait_clone_child_bounded(pid, Duration::from_secs(2)));
        let unmapped = unsafe { libc::munmap(stack, STACK_BYTES) };
        assert_eq!(bytes.len(), 2 * wire_bytes);
        let spawned = records.iter().find(|record| record[0] == 1).unwrap();
        let observed = records.iter().find(|record| record[0] == 2).unwrap();
        assert!(spawned[1] > 0);
        assert_eq!(observed[1], spawned[1]);
        assert_eq!(observed[2], i64::from(app_pid));
        assert_eq!(observed[3], i64::from(attacker_pid));
        assert_ne!(observed[3], observed[2]);
        assert_eq!(observed[4], 0);
        assert!(attacker_status.is_some_and(|status| libc::WIFEXITED(status)));
        assert_eq!(
            attacker_status.map(|status| libc::WEXITSTATUS(status)),
            Some(0)
        );
        assert!(helper_status.is_some_and(|status| libc::WIFEXITED(status)));
        assert_eq!(
            helper_status.map(|status| libc::WEXITSTATUS(status)),
            Some(0)
        );
        assert_eq!(unmapped, 0);
    }

    #[cfg(target_os = "linux")]
    fn read_clone_parent_report_bounded(
        reader: &mut File,
        expected_bytes: usize,
        timeout: Duration,
    ) -> Vec<u8> {
        use std::{os::fd::AsRawFd, time::Instant};

        let deadline = Instant::now() + timeout;
        let mut bytes = Vec::with_capacity(expected_bytes);
        while bytes.len() < expected_bytes && Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let wait_millis = i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX);
            let mut descriptor = libc::pollfd {
                fd: reader.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut descriptor, 1, wait_millis) };
            if ready == 0 {
                break;
            }
            if ready < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            let mut buffer = [0_u8; 80];
            let wanted = (expected_bytes - bytes.len()).min(buffer.len());
            match reader.read(&mut buffer[..wanted]) {
                Ok(0) => break,
                Ok(read) => bytes.extend_from_slice(&buffer[..read]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        bytes
    }

    #[cfg(target_os = "linux")]
    fn decode_clone_parent_wires(bytes: &[u8]) -> Vec<CloneParentWire> {
        let wire_bytes = std::mem::size_of::<CloneParentWire>();
        bytes
            .chunks_exact(wire_bytes)
            .map(|chunk| {
                let mut wire = [0_i64; 5];
                for (field, encoded) in wire.iter_mut().zip(chunk.chunks_exact(8)) {
                    let mut octets = [0_u8; 8];
                    octets.copy_from_slice(encoded);
                    *field = i64::from_ne_bytes(octets);
                }
                wire
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    fn wait_clone_child_bounded(pid: libc::pid_t, timeout: Duration) -> Option<libc::c_int> {
        use std::time::Instant;

        let deadline = Instant::now() + timeout;
        let mut status = 0;
        loop {
            match unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } {
                observed if observed == pid => return Some(status),
                0 if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                0 => break,
                _ => return None,
            }
        }

        let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
        let kill_deadline = Instant::now() + Duration::from_millis(500);
        loop {
            match unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } {
                observed if observed == pid => return Some(status),
                0 if Instant::now() < kill_deadline => thread::sleep(Duration::from_millis(5)),
                _ => return None,
            }
        }
    }

    #[test]
    fn eof_cancels_and_any_additional_byte_invalidates_the_scope() {
        assert_eq!(
            read_control_byte(&mut Cursor::new(Vec::<u8>::new())),
            CANCELLED
        );
        assert_eq!(
            read_control_byte(&mut Cursor::new(vec![0_u8])),
            PROTOCOL_INVALID
        );
    }

    #[test]
    fn startup_observes_prebuffered_control_input_before_returning() {
        for (state, expected) in [
            (CANCELLED, LeaseResolution::Cancelled),
            (PROTOCOL_INVALID, LeaseResolution::ProtocolInvalid),
        ] {
            let lease =
                LeaseState::watch_with_probe_for_test(move || InputProbe::Resolved(state)).unwrap();
            assert_eq!(lease.close_and_resolve(), expected);
        }
    }

    #[test]
    fn closure_performs_a_final_probe_before_committing_the_prompt_result() {
        for (state, expected) in [
            (CANCELLED, LeaseResolution::Cancelled),
            (PROTOCOL_INVALID, LeaseResolution::ProtocolInvalid),
        ] {
            let mut probes = VecDeque::from([InputProbe::Pending, InputProbe::Resolved(state)]);
            let lease = LeaseState::watch_with_probe_for_test(move || {
                probes.pop_front().unwrap_or(InputProbe::Pending)
            })
            .unwrap();
            assert_eq!(lease.close_and_resolve(), expected);
        }

        let lease = LeaseState::watch_with_probe_for_test(|| InputProbe::Pending).unwrap();
        assert_eq!(lease.close_and_resolve(), LeaseResolution::Active);
    }

    #[test]
    fn windows_peek_classification_distinguishes_open_empty_and_eof() {
        assert_eq!(classify_windows_pipe(1, 0), WindowsPipeState::OpenEmpty);
        assert_eq!(classify_windows_pipe(1, 1), WindowsPipeState::Readable);
        assert_eq!(
            classify_windows_pipe(0, 0),
            WindowsPipeState::ClosedOrInvalid
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn peek_named_pipe_reports_open_empty_then_broken_after_writer_close() {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::System::Pipes::CreatePipe;

        let mut read = std::ptr::null_mut();
        let mut write = std::ptr::null_mut();
        // SAFETY: both output pointers are valid and null security attributes request defaults.
        assert_ne!(
            unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) },
            0
        );
        // SAFETY: CreatePipe returned two fresh uniquely owned handles.
        let read = unsafe { OwnedHandle::from_raw_handle(read) };
        // SAFETY: CreatePipe returned two fresh uniquely owned handles.
        let write = unsafe { OwnedHandle::from_raw_handle(write) };

        let mut available = 0_u32;
        // SAFETY: read is a live pipe handle and available is valid output storage.
        let open_empty = unsafe {
            PeekNamedPipe(
                read.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(
            classify_windows_pipe(open_empty, available),
            WindowsPipeState::OpenEmpty
        );

        drop(write);
        available = 0;
        // SAFETY: read remains a live local handle; its peer has been closed.
        let after_eof = unsafe {
            PeekNamedPipe(
                read.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(
            classify_windows_pipe(after_eof, available),
            WindowsPipeState::ClosedOrInvalid
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_transport_accepts_only_the_process_that_created_the_pipe_client() {
        use std::os::windows::io::{FromRawHandle, IntoRawHandle, OwnedHandle};
        use windows_sys::Win32::System::{Pipes::CreatePipe, Threading::GetCurrentProcessId};

        let mut read = std::ptr::null_mut();
        let mut write = std::ptr::null_mut();
        // SAFETY: both output pointers are valid and null security attributes request defaults.
        assert_ne!(
            unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) },
            0
        );
        // SAFETY: CreatePipe returned two fresh uniquely owned handles.
        let read = unsafe { OwnedHandle::from_raw_handle(read) };
        // SAFETY: CreatePipe returned two fresh uniquely owned handles and the
        // writer stays alive throughout both peer checks.
        let _write = unsafe { OwnedHandle::from_raw_handle(write) };
        let input = UnbufferedStandardInput {
            // SAFETY: ownership transfers exactly once from OwnedHandle to File.
            file: unsafe { File::from_raw_handle(read.into_raw_handle()) },
        };
        let creator_pid = unsafe { GetCurrentProcessId() };
        let forged_parent_pid = if creator_pid == u32::MAX {
            creator_pid - 1
        } else {
            creator_pid + 1
        };

        assert_eq!(input.authenticate_parent_process(creator_pid), Ok(()));
        assert_eq!(
            input.authenticate_parent_process(forged_parent_pid),
            Err(())
        );
    }

    #[test]
    fn test_state_never_confuses_cancel_and_protocol_failure() {
        let cancelled = LeaseState::active_for_test();
        cancelled.cancel_for_test();
        assert!(cancelled.is_cancelled());
        assert!(!cancelled.is_protocol_invalid());

        let invalid = LeaseState::active_for_test();
        invalid.invalidate_for_test();
        assert!(!invalid.is_cancelled());
        assert!(invalid.is_protocol_invalid());
    }
}
