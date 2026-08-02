#![cfg(any(target_os = "linux", target_os = "windows"))]

#[path = "../src/crash_canary.rs"]
mod crash_canary;

use crash_canary::CANARY_BYTES;
use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader, Read},
    path::{Path, PathBuf},
    process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use std::os::unix::process::{CommandExt, ExitStatusExt};

#[cfg(target_os = "windows")]
use std::{ffi::OsString, os::windows::process::CommandExt};

static SCRATCH_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const FIXTURE_TIMEOUT: Duration = Duration::from_secs(30);
const READINESS_TIMEOUT: Duration = Duration::from_secs(5);
const KILL_REAP_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(target_os = "windows")]
const REG_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(target_os = "windows")]
const CREATE_DEFAULT_ERROR_MODE: u32 = 0x0400_0000;
#[cfg(target_os = "windows")]
const AEDEBUG_AUTO_EXCLUSION_KEY: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug\AutoExclusionList";
#[cfg(all(target_os = "windows", target_pointer_width = "64"))]
const NATIVE_REGISTRY_VIEW: &str = "/reg:64";
#[cfg(all(target_os = "windows", target_pointer_width = "32"))]
const NATIVE_REGISTRY_VIEW: &str = "/reg:32";

#[test]
#[cfg(target_os = "linux")]
fn default_gcore_excludes_the_protected_mapping() {
    let scratch = ScratchDirectory::new("linux-gcore");
    let mut fixture = spawn_fixture("--linux-dumpable", scratch.path());
    let (mut stdout, mut stderr) = wait_for_ready(&mut fixture);

    let pid = fixture.child().id();
    let protected_canary = materialize(pid, crash_canary::secret_byte);
    let dump_control = materialize(pid, crash_canary::control_byte);
    let prefix = scratch.path().join("controlled-gcore");
    let core_path = PathBuf::from(format!("{}.{}", prefix.display(), pid));

    let mut gcore_command = Command::new("gcore");
    gcore_command
        .arg("-o")
        .arg(&prefix)
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut gcore = GuardedChild::spawn_in_new_process_group(&mut gcore_command)
        .expect("spawn gcore in a dedicated process group");
    let gcore_status = gcore.wait_bounded(FIXTURE_TIMEOUT);
    assert!(gcore_status.success(), "default gcore must succeed");
    assert!(core_path.is_file(), "gcore must create the expected core");
    assert!(
        fs::metadata(&core_path).expect("inspect gcore file").len() > 0,
        "gcore must create a non-empty core"
    );
    assert!(
        file_contains(&core_path, &dump_control).expect("scan dump control"),
        "the ordinary heap control must be present in the core"
    );
    assert!(
        !file_contains(&core_path, &protected_canary).expect("scan protected canary"),
        "MADV_DONTDUMP must exclude the protected mapping from default gcore"
    );
    fs::remove_file(&core_path).expect("remove synthetic core");

    fixture.kill_and_wait();
    assert_no_canary_output(&mut stdout, &mut stderr, &protected_canary, &dump_control);
}

#[test]
#[cfg(target_os = "linux")]
fn hardened_abort_produces_no_core_file() {
    let scratch = ScratchDirectory::new("linux-crash");
    let mut fixture = spawn_fixture("--controlled-crash", scratch.path());
    let (mut stdout, mut stderr) = wait_for_ready(&mut fixture);

    let pid = fixture.child().id();
    let protected_canary = materialize(pid, crash_canary::secret_byte);
    let dump_control = materialize(pid, crash_canary::control_byte);
    let status = fixture.wait_bounded(FIXTURE_TIMEOUT);
    assert_eq!(status.signal(), Some(libc::SIGABRT));
    assert!(
        !status.core_dumped(),
        "the hardened process must not report a produced core"
    );
    assert_no_canary_output(&mut stdout, &mut stderr, &protected_canary, &dump_control);
    assert_eq!(
        fs::read_dir(scratch.path())
            .expect("inspect isolated crash directory")
            .count(),
        0,
        "the hardened crash must leave no core file"
    );
}

#[test]
#[cfg(target_os = "windows")]
fn wer_full_user_dump_excludes_the_registered_mapping() {
    let scratch = ScratchDirectory::new("windows-wer");
    let executable = fixture_path();
    let executable_name = executable
        .file_name()
        .expect("fixture executable name")
        .to_os_string();
    let mut debugger_exclusion = AutomaticDebuggerExclusion::create(&executable_name);
    let mut registry = WerLocalDumpRegistration::create(&executable_name, scratch.path());

    let mut fixture = spawn_fixture("--windows-wer-crash", scratch.path());
    drop(fixture.child_mut().stdin.take());
    let (mut stdout, mut stderr) = wait_for_ready(&mut fixture);

    let pid = fixture.child().id();
    let protected_canary = materialize(pid, crash_canary::secret_byte);
    let dump_control = materialize(pid, crash_canary::control_byte);
    let status = fixture.wait_bounded(FIXTURE_TIMEOUT);
    assert!(
        !status.success(),
        "the WER fail-fast fixture must terminate abnormally"
    );
    assert_no_canary_output(&mut stdout, &mut stderr, &protected_canary, &dump_control);

    let dump = wait_for_stable_dump(scratch.path(), FIXTURE_TIMEOUT);
    let mut signature = [0_u8; 4];
    File::open(&dump)
        .and_then(|mut file| file.read_exact(&mut signature))
        .expect("read minidump signature");
    assert_eq!(&signature, b"MDMP", "WER must create a minidump file");
    assert!(
        file_contains(&dump, &dump_control).expect("scan dump control"),
        "DumpType=2 must contain the ordinary heap control"
    );
    assert!(
        !file_contains(&dump, &protected_canary).expect("scan protected canary"),
        "WER must omit the registered protected allocation"
    );
    fs::remove_file(&dump).expect("remove synthetic WER dump");
    registry.remove_and_prove_absent();
    debugger_exclusion.remove_and_prove_absent();
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_your-cloud-secret-crash-fixture"))
}

fn spawn_fixture(mode: &str, working_directory: &Path) -> GuardedChild {
    let mut command = Command::new(fixture_path());
    command
        .arg(mode)
        .current_dir(working_directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(target_os = "windows")]
    command.creation_flags(CREATE_DEFAULT_ERROR_MODE);

    let child = command.spawn().expect("spawn secret crash fixture");
    GuardedChild::new(child)
}

fn wait_for_ready(fixture: &mut GuardedChild) -> (BufReader<ChildStdout>, ChildStderr) {
    let stdout = fixture.child_mut().stdout.take().expect("fixture stdout");
    let stderr = fixture.child_mut().stderr.take().expect("fixture stderr");
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader_thread = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let result = reader.read_line(&mut line).map(|_| line);
        let _ = sender.send((reader, result));
    });

    let received = match receiver.recv_timeout(READINESS_TIMEOUT) {
        Ok(received) => received,
        Err(error) => {
            fixture.kill_and_wait();
            reader_thread
                .join()
                .expect("readiness reader must stop after fixture termination");
            panic!("fixture readiness exceeded its bound: {error}");
        }
    };
    reader_thread.join().expect("join readiness reader");
    let (reader, line) = received;
    assert_eq!(
        line.expect("read fixture readiness"),
        "READY\n",
        "fixture must announce readiness exactly"
    );
    (reader, stderr)
}

fn assert_no_canary_output(
    stdout: &mut BufReader<ChildStdout>,
    stderr: &mut ChildStderr,
    protected_canary: &[u8],
    dump_control: &[u8],
) {
    let mut remaining_stdout = Vec::new();
    stdout
        .read_to_end(&mut remaining_stdout)
        .expect("read remaining fixture stdout");
    let mut all_stderr = Vec::new();
    stderr
        .read_to_end(&mut all_stderr)
        .expect("read fixture stderr");
    for output in [&remaining_stdout, &all_stderr] {
        assert!(!contains_subslice(output, protected_canary));
        assert!(!contains_subslice(output, dump_control));
    }
}

fn materialize(pid: u32, byte_at: fn(u32, usize) -> u8) -> Vec<u8> {
    (0..CANARY_BYTES).map(|index| byte_at(pid, index)).collect()
}

fn file_contains(path: &Path, needle: &[u8]) -> io::Result<bool> {
    let mut reader = BufReader::with_capacity(1024 * 1024, File::open(path)?);
    let mut chunk = [0_u8; 64 * 1024];
    let mut overlap = Vec::with_capacity(needle.len().saturating_sub(1));
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            return Ok(false);
        }
        let mut window = Vec::with_capacity(overlap.len() + read);
        window.extend_from_slice(&overlap);
        window.extend_from_slice(&chunk[..read]);
        if contains_subslice(&window, needle) {
            return Ok(true);
        }
        let retained = needle.len().saturating_sub(1).min(window.len());
        overlap.clear();
        overlap.extend_from_slice(&window[window.len() - retained..]);
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

struct ScratchDirectory {
    path: PathBuf,
}

impl ScratchDirectory {
    fn new(label: &str) -> Self {
        let sequence = SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "your-cloud-secret-crash-contract-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create isolated scratch directory");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct GuardedChild {
    child: Child,
    reaped: bool,
    #[cfg(target_os = "linux")]
    process_group: Option<libc::pid_t>,
}

impl GuardedChild {
    fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
            #[cfg(target_os = "linux")]
            process_group: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn spawn_in_new_process_group(command: &mut Command) -> io::Result<Self> {
        // Ubuntu's gcore entrypoint can be a wrapper which starts gdb. A dedicated group keeps
        // that descendant inside the same bounded cleanup and observation scope as the wrapper.
        command.process_group(0);
        let child = command.spawn()?;
        let process_group = libc::pid_t::try_from(child.id())
            .ok()
            .filter(|process_group| *process_group > 1)
            .ok_or_else(|| io::Error::other("child PID cannot identify a safe process group"))?;
        Ok(Self {
            child,
            reaped: false,
            process_group: Some(process_group),
        })
    }

    fn child(&self) -> &Child {
        &self.child
    }

    fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    fn wait_bounded(&mut self, timeout: Duration) -> ExitStatus {
        self.try_wait_bounded(timeout).unwrap_or_else(|error| {
            panic!("child did not finish cleanly within its bound: {error}")
        })
    }

    fn try_wait_bounded(&mut self, timeout: Duration) -> io::Result<ExitStatus> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::other("child deadline overflow"))?;
        loop {
            match self.child.try_wait()? {
                Some(status) => {
                    self.reaped = true;
                    if self.process_scope_is_empty()? {
                        return Ok(status);
                    }

                    let descendant_error =
                        io::Error::other("child exited while its process group remained active");
                    return match self.terminate_and_reap_bounded(KILL_REAP_TIMEOUT) {
                        Ok(()) => Err(descendant_error),
                        Err(cleanup_error) => Err(io::Error::other(format!(
                            "{descendant_error}; bounded descendant cleanup failed: {cleanup_error}"
                        ))),
                    };
                }
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                None => {
                    let timeout_error =
                        io::Error::new(io::ErrorKind::TimedOut, "child execution timed out");
                    return match self.terminate_and_reap_bounded(KILL_REAP_TIMEOUT) {
                        Ok(()) => Err(timeout_error),
                        Err(cleanup_error) => Err(io::Error::other(format!(
                            "{timeout_error}; bounded cleanup failed: {cleanup_error}"
                        ))),
                    };
                }
            }
        }
    }

    fn kill_and_wait(&mut self) {
        self.terminate_and_reap_bounded(KILL_REAP_TIMEOUT)
            .unwrap_or_else(|error| panic!("child cleanup exceeded its bound: {error}"));
    }

    fn terminate_and_reap_bounded(&mut self, timeout: Duration) -> io::Result<()> {
        if self.cleanup_is_complete() {
            return Ok(());
        }
        self.request_termination()?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::other("child cleanup deadline overflow"))?;
        loop {
            if !self.reaped {
                match self.child.try_wait()? {
                    Some(_) => self.reaped = true,
                    None => {}
                }
            }
            if self.reaped && self.process_scope_is_empty()? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "terminated child or one of its grouped descendants remained observable",
                ));
            }
            self.request_termination()?;
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn cleanup_is_complete(&self) -> bool {
        self.reaped && {
            #[cfg(target_os = "linux")]
            {
                self.process_group.is_none()
            }
            #[cfg(not(target_os = "linux"))]
            {
                true
            }
        }
    }

    fn request_termination(&mut self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(process_group) = self.process_group {
            let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
            if result != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ESRCH) {
                    self.process_group = None;
                } else {
                    return Err(error);
                }
            }
        }

        if !self.reaped {
            match self.child.kill() {
                Ok(()) => {}
                Err(error) => match self.child.try_wait()? {
                    Some(_) => self.reaped = true,
                    None => return Err(error),
                },
            }
        }
        Ok(())
    }

    fn process_scope_is_empty(&mut self) -> io::Result<bool> {
        #[cfg(target_os = "linux")]
        if let Some(process_group) = self.process_group {
            // Signal 0 observes every live member without changing it. Clear the remembered PGID
            // immediately after ESRCH so a later PID reuse can never become a cleanup target.
            let result = unsafe { libc::kill(-process_group, 0) };
            if result == 0 {
                return Ok(false);
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                self.process_group = None;
            } else if error.raw_os_error() == Some(libc::EPERM) {
                return Ok(false);
            } else {
                return Err(error);
            }
        }
        Ok(true)
    }
}

impl Drop for GuardedChild {
    fn drop(&mut self) {
        if !self.cleanup_is_complete() {
            let cleanup = self.terminate_and_reap_bounded(KILL_REAP_TIMEOUT);
            if let Err(error) = cleanup {
                if !thread::panicking() {
                    panic!("child Drop could not prove bounded cleanup: {error}");
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn wait_for_stable_dump(directory: &Path, timeout: Duration) -> PathBuf {
    let deadline = Instant::now() + timeout;
    let mut stable_length = None;
    let mut stable_since = None;
    let mut stable_observations = 0_u8;
    loop {
        let dumps = fs::read_dir(directory)
            .expect("inspect WER dump directory")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("dmp"))
            })
            .collect::<Vec<_>>();
        assert!(dumps.len() <= 1, "WER must create at most one bounded dump");
        if let Some(dump) = dumps.first() {
            let length = fs::metadata(dump).expect("inspect WER dump").len();
            if length > 0 && stable_length == Some(length) {
                stable_observations = stable_observations.saturating_add(1);
                if stable_observations >= 6
                    && stable_since
                        .is_some_and(|since: Instant| since.elapsed() >= Duration::from_secs(1))
                {
                    return dump.clone();
                }
            } else if length > 0 {
                stable_length = Some(length);
                stable_since = Some(Instant::now());
                stable_observations = 1;
            } else {
                stable_length = None;
                stable_since = None;
                stable_observations = 0;
            }
        } else {
            stable_length = None;
            stable_since = None;
            stable_observations = 0;
        }
        assert!(
            Instant::now() < deadline,
            "WER dump was not produced in time"
        );
        thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(target_os = "windows")]
struct AutomaticDebuggerExclusion {
    executable_name: OsString,
    active: bool,
}

#[cfg(target_os = "windows")]
impl AutomaticDebuggerExclusion {
    fn create(executable_name: &std::ffi::OsStr) -> Self {
        // LocalDumps cannot collect a crash while an automatic postmortem debugger owns it.
        // AutoExclusionList is the application-scoped Windows mechanism for handing this one
        // synthetic crash back to WER without mutating the runner's global debugger setting.
        let executable_name = executable_name.to_os_string();
        let existing = run_reg([
            OsString::from("query"),
            OsString::from(AEDEBUG_AUTO_EXCLUSION_KEY),
            OsString::from("/v"),
            executable_name.clone(),
            OsString::from(NATIVE_REGISTRY_VIEW),
        ]);
        assert!(
            !existing.success(),
            "the fixture-specific automatic-debugger exclusion must not pre-exist"
        );

        let mut registration = Self {
            executable_name,
            active: false,
        };
        let created = run_reg([
            OsString::from("add"),
            OsString::from(AEDEBUG_AUTO_EXCLUSION_KEY),
            OsString::from("/v"),
            registration.executable_name.clone(),
            OsString::from("/t"),
            OsString::from("REG_DWORD"),
            OsString::from("/d"),
            OsString::from("1"),
            OsString::from("/f"),
            OsString::from(NATIVE_REGISTRY_VIEW),
        ]);
        assert!(created.success(), "exclude only the fixture from AeDebug");
        registration.active = true;
        registration
    }

    fn remove_and_prove_absent(&mut self) {
        let removed = run_reg([
            OsString::from("delete"),
            OsString::from(AEDEBUG_AUTO_EXCLUSION_KEY),
            OsString::from("/v"),
            self.executable_name.clone(),
            OsString::from("/f"),
            OsString::from(NATIVE_REGISTRY_VIEW),
        ]);
        assert!(
            removed.success(),
            "remove fixture-specific automatic-debugger exclusion"
        );

        let query = run_reg([
            OsString::from("query"),
            OsString::from(AEDEBUG_AUTO_EXCLUSION_KEY),
            OsString::from("/v"),
            self.executable_name.clone(),
            OsString::from(NATIVE_REGISTRY_VIEW),
        ]);
        assert!(
            !query.success(),
            "fixture-specific automatic-debugger exclusion must be absent after cleanup"
        );
        self.active = false;
    }
}

#[cfg(target_os = "windows")]
impl Drop for AutomaticDebuggerExclusion {
    fn drop(&mut self) {
        if self.active {
            let cleanup = try_run_reg([
                OsString::from("delete"),
                OsString::from(AEDEBUG_AUTO_EXCLUSION_KEY),
                OsString::from("/v"),
                self.executable_name.clone(),
                OsString::from("/f"),
                OsString::from(NATIVE_REGISTRY_VIEW),
            ]);
            if !matches!(cleanup, Ok(status) if status.success()) && !thread::panicking() {
                panic!("bounded fallback could not remove the fixture-specific automatic-debugger exclusion");
            }
        }
    }
}

#[cfg(target_os = "windows")]
struct WerLocalDumpRegistration {
    key: OsString,
    active: bool,
}

#[cfg(target_os = "windows")]
impl WerLocalDumpRegistration {
    fn create(executable_name: &std::ffi::OsStr, dump_folder: &Path) -> Self {
        let mut key =
            OsString::from(r"HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\");
        key.push(executable_name);

        let existing = run_reg([OsString::from("query"), key.clone()]);
        assert!(
            !existing.success(),
            "the fixture-specific WER key must not pre-exist"
        );

        let registration = Self { key, active: true };
        let created = run_reg([
            OsString::from("add"),
            registration.key.clone(),
            OsString::from("/v"),
            OsString::from("DumpFolder"),
            OsString::from("/t"),
            OsString::from("REG_EXPAND_SZ"),
            OsString::from("/d"),
            dump_folder.as_os_str().to_os_string(),
            OsString::from("/f"),
        ]);
        assert!(created.success(), "configure WER DumpFolder");
        registration.add_dword("DumpType", "2");
        registration.add_dword("DumpCount", "1");
        registration
    }

    fn add_dword(&self, name: &str, value: &str) {
        let output = run_reg([
            OsString::from("add"),
            self.key.clone(),
            OsString::from("/v"),
            OsString::from(name),
            OsString::from("/t"),
            OsString::from("REG_DWORD"),
            OsString::from("/d"),
            OsString::from(value),
            OsString::from("/f"),
        ]);
        assert!(output.success(), "configure WER DWORD {name}");
    }

    fn remove_and_prove_absent(&mut self) {
        let removed = run_reg([
            OsString::from("delete"),
            self.key.clone(),
            OsString::from("/f"),
        ]);
        assert!(removed.success(), "remove fixture-specific WER key");

        let query = run_reg([OsString::from("query"), self.key.clone()]);
        assert!(
            !query.success(),
            "fixture-specific WER key must be absent after cleanup"
        );
        self.active = false;
    }
}

#[cfg(target_os = "windows")]
impl Drop for WerLocalDumpRegistration {
    fn drop(&mut self) {
        if self.active {
            let cleanup = try_run_reg([
                OsString::from("delete"),
                self.key.clone(),
                OsString::from("/f"),
            ]);
            if !matches!(cleanup, Ok(status) if status.success()) && !thread::panicking() {
                panic!("bounded fallback could not remove the fixture-specific WER key");
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn run_reg<const N: usize>(arguments: [OsString; N]) -> ExitStatus {
    try_run_reg(arguments).expect("execute reg.exe within its process bound")
}

#[cfg(target_os = "windows")]
fn try_run_reg<const N: usize>(arguments: [OsString; N]) -> io::Result<ExitStatus> {
    let child = Command::new("reg.exe")
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    GuardedChild::new(child).try_wait_bounded(REG_TIMEOUT)
}
