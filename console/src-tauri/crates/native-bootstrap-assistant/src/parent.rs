use std::path::Path;

use crate::lease::UnbufferedStandardInput;

const CONSOLE_EXECUTABLE_NAME: &str = "your-cloud-console.exe";
const HELPER_EXECUTABLE_NAME: &str = "your-cloud-native-bootstrap-assistant.exe";
const LINUX_CONSOLE_PATH: &str = "/usr/bin/your-cloud-console";
/// Partagé avec `installation::embedded` : la position que ce module atteste
/// est celle dont la résolution du lot embarqué dérive, et une seule constante
/// garantit qu'elles ne peuvent pas se désynchroniser.
pub(crate) const LINUX_HELPER_PATH: &str = "/usr/bin/your-cloud-native-bootstrap-assistant";
const LINUX_INSTALL_DIRECTORY: &str = "/usr/bin";

pub(crate) struct ParentGuard {
    #[cfg(any(debug_assertions, feature = "native-prompt-contract-test"))]
    _non_shipping_contract_build: (),
    #[cfg(all(
        not(debug_assertions),
        not(feature = "native-prompt-contract-test"),
        target_os = "linux"
    ))]
    _linux: linux::Guard,
    #[cfg(all(
        not(debug_assertions),
        not(feature = "native-prompt-contract-test"),
        target_os = "windows"
    ))]
    _windows: windows::Guard,
}

// Development binaries and the explicitly featured process-contract fixture are
// not installed under the release paths, so only the installed-path checks are
// bypassed here. The transport peer remains authenticated in every build. Shipping
// builds enable neither branch; no protocol input can opt into this path bypass.
#[cfg(all(
    any(debug_assertions, feature = "native-prompt-contract-test"),
    target_os = "linux"
))]
pub(crate) fn verify(input: &UnbufferedStandardInput) -> Result<ParentGuard, ()> {
    let parent_pid = unsafe { libc::getppid() };
    if parent_pid <= 1 {
        return Err(());
    }
    input.authenticate_parent_process(u32::try_from(parent_pid).map_err(|_| ())?)?;
    Ok(ParentGuard {
        _non_shipping_contract_build: (),
    })
}

#[cfg(all(
    any(debug_assertions, feature = "native-prompt-contract-test"),
    target_os = "windows"
))]
pub(crate) fn verify(input: &UnbufferedStandardInput) -> Result<ParentGuard, ()> {
    input.authenticate_parent_process(windows::current_parent_pid()?)?;
    Ok(ParentGuard {
        _non_shipping_contract_build: (),
    })
}

#[cfg(all(
    any(debug_assertions, feature = "native-prompt-contract-test"),
    not(any(target_os = "linux", target_os = "windows"))
))]
pub(crate) fn verify(_input: &UnbufferedStandardInput) -> Result<ParentGuard, ()> {
    Err(())
}

#[cfg(all(
    not(debug_assertions),
    not(feature = "native-prompt-contract-test"),
    target_os = "linux"
))]
pub(crate) fn verify(input: &UnbufferedStandardInput) -> Result<ParentGuard, ()> {
    linux::verify(input).map(|guard| ParentGuard { _linux: guard })
}

#[cfg(all(
    not(debug_assertions),
    not(feature = "native-prompt-contract-test"),
    target_os = "windows"
))]
pub(crate) fn verify(input: &UnbufferedStandardInput) -> Result<ParentGuard, ()> {
    windows::verify(input).map(|guard| ParentGuard { _windows: guard })
}

#[cfg(all(
    not(debug_assertions),
    not(feature = "native-prompt-contract-test"),
    not(any(target_os = "linux", target_os = "windows"))
))]
pub(crate) fn verify(_input: &UnbufferedStandardInput) -> Result<ParentGuard, ()> {
    Err(())
}

fn exact_linux_layout(parent: &Path, helper: &Path, directory: &Path) -> bool {
    parent == Path::new(LINUX_CONSOLE_PATH)
        && helper == Path::new(LINUX_HELPER_PATH)
        && directory == Path::new(LINUX_INSTALL_DIRECTORY)
}

fn secure_unix_node(expected_kind: bool, uid: u32, mode: u32) -> bool {
    expected_kind && uid == 0 && mode & 0o022 == 0 && mode & 0o111 != 0
}

fn exact_windows_layout(parent: &Path, helper: &Path) -> bool {
    helper.file_name() == Some(std::ffi::OsStr::new(HELPER_EXECUTABLE_NAME))
        && helper
            .parent()
            .is_some_and(|directory| directory.join(CONSOLE_EXECUTABLE_NAME) == parent)
}

fn secure_windows_node(expected_kind: bool, attributes: u32) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

    expected_kind && attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
}

#[cfg(test)]
const fn development_bypass_allowed(debug_assertions_enabled: bool) -> bool {
    debug_assertions_enabled
}

#[cfg(all(
    target_os = "linux",
    any(
        all(not(debug_assertions), not(feature = "native-prompt-contract-test")),
        test
    )
))]
mod linux {
    use std::{
        fs::{self, File, Metadata},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::MetadataExt,
        },
        path::{Path, PathBuf},
    };

    use super::{
        exact_linux_layout, secure_unix_node, UnbufferedStandardInput, LINUX_CONSOLE_PATH,
        LINUX_HELPER_PATH, LINUX_INSTALL_DIRECTORY,
    };

    pub(super) struct Guard {
        _parent_pidfd: File,
        _parent_process_executable: File,
        _installed_parent_executable: File,
        _running_helper_executable: File,
        _installed_helper_executable: File,
        _installation_directory: File,
    }

    pub(super) fn verify(input: &UnbufferedStandardInput) -> Result<Guard, ()> {
        let expected_parent = Path::new(LINUX_CONSOLE_PATH);
        let expected_helper = Path::new(LINUX_HELPER_PATH);
        let expected_directory = Path::new(LINUX_INSTALL_DIRECTORY);
        if !exact_linux_layout(expected_parent, expected_helper, expected_directory) {
            return Err(());
        }

        let current_executable = std::env::current_exe().map_err(|_| ())?;
        let proc_self_executable = fs::read_link("/proc/self/exe").map_err(|_| ())?;
        if current_executable != expected_helper || proc_self_executable != expected_helper {
            return Err(());
        }

        let installation_directory = open_secure_directory(expected_directory)?;
        let installed_helper_executable = open_secure_regular(expected_helper)?;
        let running_helper_executable = File::open("/proc/self/exe").map_err(|_| ())?;
        let running_helper_metadata = running_helper_executable.metadata().map_err(|_| ())?;
        if !secure_regular(&running_helper_metadata)
            || !same_file(
                &running_helper_metadata,
                &installed_helper_executable.metadata().map_err(|_| ())?,
            )
            || fs::read_link("/proc/self/exe").map_err(|_| ())? != expected_helper
        {
            return Err(());
        }

        let parent_before = unsafe { libc::getppid() };
        if parent_before <= 1 {
            return Err(());
        }
        let parent_pidfd = open_pidfd(parent_before)?;
        if !process_is_alive(&parent_pidfd)? {
            return Err(());
        }
        input.authenticate_parent_process(u32::try_from(parent_before).map_err(|_| ())?)?;

        let proc_parent_executable = PathBuf::from(format!("/proc/{parent_before}/exe"));
        if fs::read_link(&proc_parent_executable).map_err(|_| ())? != expected_parent {
            return Err(());
        }
        let parent_process_executable = File::open(&proc_parent_executable).map_err(|_| ())?;
        let parent_process_metadata = parent_process_executable.metadata().map_err(|_| ())?;
        let installed_parent_executable = open_secure_regular(expected_parent)?;
        if !secure_regular(&parent_process_metadata)
            || !same_file(
                &parent_process_metadata,
                &installed_parent_executable.metadata().map_err(|_| ())?,
            )
            || fs::read_link(&proc_parent_executable).map_err(|_| ())? != expected_parent
        {
            return Err(());
        }

        let parent_after = unsafe { libc::getppid() };
        if parent_after != parent_before || !process_is_alive(&parent_pidfd)? {
            return Err(());
        }

        Ok(Guard {
            _parent_pidfd: parent_pidfd,
            _parent_process_executable: parent_process_executable,
            _installed_parent_executable: installed_parent_executable,
            _running_helper_executable: running_helper_executable,
            _installed_helper_executable: installed_helper_executable,
            _installation_directory: installation_directory,
        })
    }

    fn open_pidfd(pid: libc::pid_t) -> Result<File, ()> {
        let raw_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
        if raw_fd < 0 || raw_fd > i32::MAX as libc::c_long {
            return Err(());
        }

        Ok(unsafe { File::from_raw_fd(raw_fd as i32) })
    }

    fn process_is_alive(pidfd: &File) -> Result<bool, ()> {
        let mut descriptor = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        match result {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(()),
        }
    }

    fn open_secure_regular(path: &Path) -> Result<File, ()> {
        let before = fs::symlink_metadata(path).map_err(|_| ())?;
        if !secure_regular(&before) {
            return Err(());
        }

        let file = File::open(path).map_err(|_| ())?;
        let opened = file.metadata().map_err(|_| ())?;
        let after = fs::symlink_metadata(path).map_err(|_| ())?;
        if !secure_regular(&opened)
            || !secure_regular(&after)
            || !same_file(&before, &opened)
            || !same_file(&opened, &after)
        {
            return Err(());
        }
        Ok(file)
    }

    fn open_secure_directory(path: &Path) -> Result<File, ()> {
        let before = fs::symlink_metadata(path).map_err(|_| ())?;
        if !secure_directory(&before) {
            return Err(());
        }

        let directory = File::open(path).map_err(|_| ())?;
        let opened = directory.metadata().map_err(|_| ())?;
        let after = fs::symlink_metadata(path).map_err(|_| ())?;
        if !secure_directory(&opened)
            || !secure_directory(&after)
            || !same_file(&before, &opened)
            || !same_file(&opened, &after)
        {
            return Err(());
        }
        Ok(directory)
    }

    fn secure_regular(metadata: &Metadata) -> bool {
        secure_unix_node(
            metadata.file_type().is_file(),
            metadata.uid(),
            metadata.mode(),
        )
    }

    fn secure_directory(metadata: &Metadata) -> bool {
        secure_unix_node(
            metadata.file_type().is_dir(),
            metadata.uid(),
            metadata.mode(),
        )
    }

    fn same_file(left: &Metadata, right: &Metadata) -> bool {
        left.dev() == right.dev() && left.ino() == right.ino()
    }
}

#[cfg(target_os = "windows")]
#[cfg_attr(
    any(debug_assertions, feature = "native-prompt-contract-test"),
    allow(dead_code)
)]
mod windows {
    use std::{
        ffi::c_void,
        ffi::OsString,
        fs::{File, Metadata, OpenOptions},
        mem::size_of,
        os::windows::{
            ffi::OsStringExt,
            fs::{MetadataExt, OpenOptionsExt},
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        path::{Path, PathBuf},
    };

    use windows_sys::Win32::{
        Foundation::{HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT},
        System::{
            Com::{CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_APARTMENTTHREADED},
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            Threading::{
                GetCurrentProcessId, OpenProcess, QueryFullProcessImageNameW, WaitForSingleObject,
                PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            },
        },
        UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath, KF_FLAG_DEFAULT},
    };

    use super::{exact_windows_layout, secure_windows_node, UnbufferedStandardInput};

    const MAX_WINDOWS_PATH_UNITS: usize = 32_767;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;

    pub(super) struct Guard {
        _com: ComGuard,
        _parent_process: OwnedHandle,
        _parent_executable: File,
        _helper_executable: File,
        _installation_directory: File,
    }

    pub(super) fn verify(input: &UnbufferedStandardInput) -> Result<Guard, ()> {
        let com = ComGuard::new()?;
        let helper_path = std::env::current_exe().map_err(|_| ())?;
        let installation_directory = helper_path.parent().ok_or(())?;
        let program_files = known_program_files()?;
        if !path_is_below(installation_directory, &program_files) {
            return Err(());
        }
        let expected_parent_path = installation_directory.join(super::CONSOLE_EXECUTABLE_NAME);
        if !exact_windows_layout(&expected_parent_path, &helper_path) {
            return Err(());
        }

        let helper_executable = open_without_reparse(&helper_path, NodeKind::Regular)?;
        let directory = open_without_reparse(installation_directory, NodeKind::Directory)?;

        let current_pid = unsafe { GetCurrentProcessId() };
        let parent_pid_before = parent_pid(current_pid)?;
        if parent_pid_before == 0 || parent_pid_before == current_pid {
            return Err(());
        }
        input.authenticate_parent_process(parent_pid_before)?;

        let raw_parent = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                parent_pid_before,
            )
        };
        let parent_process = owned_handle(raw_parent)?;
        if !process_is_alive(&parent_process) {
            return Err(());
        }

        let observed_parent_path = process_image_path(&parent_process)?;
        if observed_parent_path != expected_parent_path
            || !exact_windows_layout(&observed_parent_path, &helper_path)
        {
            return Err(());
        }
        let parent_executable = open_without_reparse(&observed_parent_path, NodeKind::Regular)?;

        let parent_pid_after = parent_pid(current_pid)?;
        if parent_pid_after != parent_pid_before || !process_is_alive(&parent_process) {
            return Err(());
        }

        Ok(Guard {
            _com: com,
            _parent_process: parent_process,
            _parent_executable: parent_executable,
            _helper_executable: helper_executable,
            _installation_directory: directory,
        })
    }

    pub(super) fn current_parent_pid() -> Result<u32, ()> {
        let current_pid = unsafe { GetCurrentProcessId() };
        let observed = parent_pid(current_pid)?;
        if observed == 0 || observed == current_pid {
            return Err(());
        }
        Ok(observed)
    }

    struct ComGuard;

    impl ComGuard {
        fn new() -> Result<Self, ()> {
            let result =
                unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) };
            (result >= 0).then_some(Self).ok_or(())
        }
    }

    impl Drop for ComGuard {
        fn drop(&mut self) {
            unsafe { CoUninitialize() };
        }
    }

    fn known_program_files() -> Result<PathBuf, ()> {
        let mut raw = std::ptr::null_mut();
        let result = unsafe {
            SHGetKnownFolderPath(
                &FOLDERID_ProgramFiles,
                KF_FLAG_DEFAULT as u32,
                std::ptr::null_mut(),
                &mut raw,
            )
        };
        if result < 0 || raw.is_null() {
            return Err(());
        }
        let length = (0..MAX_WINDOWS_PATH_UNITS)
            .find(|offset| unsafe { *raw.add(*offset) } == 0)
            .ok_or(());
        let path = match length {
            Ok(length) if length > 0 => {
                let units = unsafe { std::slice::from_raw_parts(raw, length) };
                Ok(PathBuf::from(OsString::from_wide(units)))
            }
            _ => Err(()),
        };
        unsafe { CoTaskMemFree(raw.cast::<c_void>()) };
        path
    }

    pub(super) fn path_is_below(path: &Path, trusted_root: &Path) -> bool {
        path.strip_prefix(trusted_root)
            .is_ok_and(|relative| relative.components().next().is_some())
    }

    #[derive(Clone, Copy)]
    enum NodeKind {
        Regular,
        Directory,
    }

    fn open_without_reparse(path: &Path, kind: NodeKind) -> Result<File, ()> {
        let path_metadata = std::fs::symlink_metadata(path).map_err(|_| ())?;
        if !metadata_allowed(&path_metadata, kind) {
            return Err(());
        }

        let file = OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| ())?;
        if !metadata_allowed(&file.metadata().map_err(|_| ())?, kind)
            || !metadata_allowed(&std::fs::symlink_metadata(path).map_err(|_| ())?, kind)
        {
            return Err(());
        }
        Ok(file)
    }

    fn metadata_allowed(metadata: &Metadata, kind: NodeKind) -> bool {
        let expected_kind = match kind {
            NodeKind::Regular => metadata.file_type().is_file(),
            NodeKind::Directory => metadata.file_type().is_dir(),
        };
        secure_windows_node(expected_kind, metadata.file_attributes())
    }

    fn parent_pid(current_pid: u32) -> Result<u32, ()> {
        let raw_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        let snapshot = owned_handle(raw_snapshot)?;
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..PROCESSENTRY32W::default()
        };
        if unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) } == 0 {
            return Err(());
        }

        loop {
            if entry.th32ProcessID == current_pid {
                return Ok(entry.th32ParentProcessID);
            }
            if unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) } == 0 {
                return Err(());
            }
        }
    }

    fn process_image_path(process: &OwnedHandle) -> Result<PathBuf, ()> {
        let mut buffer = vec![0_u16; MAX_WINDOWS_PATH_UNITS];
        let mut length = u32::try_from(buffer.len()).map_err(|_| ())?;
        if unsafe {
            QueryFullProcessImageNameW(
                process.as_raw_handle(),
                PROCESS_NAME_WIN32,
                buffer.as_mut_ptr(),
                &mut length,
            )
        } == 0
        {
            return Err(());
        }
        let length = usize::try_from(length).map_err(|_| ())?;
        if length == 0 || length > buffer.len() {
            return Err(());
        }
        Ok(PathBuf::from(OsString::from_wide(&buffer[..length])))
    }

    fn process_is_alive(process: &OwnedHandle) -> bool {
        (unsafe { WaitForSingleObject(process.as_raw_handle(), 0) }) == WAIT_TIMEOUT
    }

    fn owned_handle(raw: HANDLE) -> Result<OwnedHandle, ()> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(());
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_policy_requires_exact_installed_paths() {
        assert!(exact_linux_layout(
            Path::new(LINUX_CONSOLE_PATH),
            Path::new(LINUX_HELPER_PATH),
            Path::new(LINUX_INSTALL_DIRECTORY),
        ));
        assert!(!exact_linux_layout(
            Path::new("/tmp/your-cloud-console"),
            Path::new(LINUX_HELPER_PATH),
            Path::new(LINUX_INSTALL_DIRECTORY),
        ));
    }

    #[test]
    fn unix_policy_requires_root_and_rejects_mutable_nodes() {
        assert!(secure_unix_node(true, 0, 0o100755));
        assert!(!secure_unix_node(false, 0, 0o100755));
        assert!(!secure_unix_node(true, 1000, 0o100755));
        assert!(!secure_unix_node(true, 0, 0o100775));
        assert!(!secure_unix_node(true, 0, 0o100757));
        assert!(!secure_unix_node(true, 0, 0o100644));
    }

    #[test]
    fn windows_policy_requires_exact_siblings() {
        let helper =
            Path::new("/Program Files/Your Cloud/your-cloud-native-bootstrap-assistant.exe");
        let parent = Path::new("/Program Files/Your Cloud/your-cloud-console.exe");
        assert!(exact_windows_layout(parent, helper));
        assert!(!exact_windows_layout(
            Path::new("/Elsewhere/your-cloud-console.exe"),
            helper,
        ));
        assert!(!exact_windows_layout(
            parent,
            Path::new("/Program Files/Your Cloud/renamed-helper.exe"),
        ));
    }

    #[test]
    fn windows_policy_rejects_reparse_points() {
        assert!(secure_windows_node(true, 0x20));
        assert!(!secure_windows_node(false, 0x20));
        assert!(!secure_windows_node(true, 0x400));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_release_layout_must_be_below_program_files() {
        let program_files = Path::new(r"C:\Program Files");
        assert!(windows::path_is_below(
            Path::new(r"C:\Program Files\Your Cloud"),
            program_files,
        ));
        assert!(!windows::path_is_below(
            Path::new(r"C:\Users\lucas\Your Cloud"),
            program_files,
        ));
        assert!(!windows::path_is_below(program_files, program_files));
    }

    #[test]
    fn development_bypass_is_a_debug_only_compilation_policy() {
        assert!(development_bypass_allowed(true));
        assert!(!development_bypass_allowed(false));
    }
}
