use std::{
    ffi::{c_void, OsStr},
    fs::File,
    io, iter,
    mem::{self, ManuallyDrop},
    os::windows::{ffi::OsStrExt, io::FromRawHandle},
    path::Path,
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GENERIC_READ, HANDLE,
        INVALID_HANDLE_VALUE,
    },
    Security::{
        AclSizeInformation,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
        },
        EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE, ACL,
        ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED,
        TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
    },
    System::{
        SystemServices::ACCESS_ALLOWED_ACE_TYPE,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

const FILE_ALL_ACCESS_MASK: u32 = 0x001f_01ff;

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> io::Result<Self> {
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(handle))
    }

    fn into_file(self) -> File {
        let handle = self.0;
        let _owned = ManuallyDrop::new(self);
        unsafe { File::from_raw_handle(handle) }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

pub fn protect_directory(path: &Path) -> io::Result<()> {
    let handle = open_security_handle(path, true, true)?;
    apply_private_acl(handle.0, true)?;
    validate_private_acl(handle.0, true)
}

pub fn validate_private_directory(path: &Path) -> io::Result<()> {
    let handle = open_security_handle(path, true, false)?;
    validate_private_acl(handle.0, true)
}

pub fn protect_file(path: &Path) -> io::Result<()> {
    let handle = open_security_handle(path, false, true)?;
    apply_private_acl(handle.0, false)?;
    validate_private_acl(handle.0, false)
}

pub fn open_private_file(path: &Path, maximum: u64) -> io::Result<File> {
    let handle = open_security_handle(path, false, false)?;
    let information = file_information(handle.0)?;
    let size = u64::from(information.nFileSizeHigh) << 32 | u64::from(information.nFileSizeLow);
    if information.nNumberOfLinks != 1 || size == 0 || size > maximum {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private file metadata is not acceptable",
        ));
    }
    validate_private_acl(handle.0, false)?;
    Ok(handle.into_file())
}

fn open_security_handle(
    path: &Path,
    directory: bool,
    writable_acl: bool,
) -> io::Result<OwnedHandle> {
    let path = wide(path.as_os_str());
    let mut access = READ_CONTROL;
    if !directory {
        access |= GENERIC_READ;
    }
    if writable_acl {
        access |= WRITE_DAC;
    }
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
    if directory {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
    }
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    let handle = OwnedHandle::new(handle)?;
    let information = file_information(handle.0)?;
    let is_directory = information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    let is_reparse_point = information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    if is_reparse_point || is_directory != directory {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private path is not the expected regular object",
        ));
    }
    Ok(handle)
}

fn file_information(handle: HANDLE) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(information)
}

fn apply_private_acl(handle: HANDLE, directory: bool) -> io::Result<()> {
    let user_sid = current_user_sid_string()?;
    let ace_flags = if directory { "OICI" } else { "" };
    let sddl = format!("D:P(A;{ace_flags};FA;;;{user_sid})(A;{ace_flags};FA;;;SY)");
    apply_acl_sddl(handle, &sddl)
}

fn apply_acl_sddl(handle: HANDLE, sddl: &str) -> io::Result<()> {
    let sddl = wide(OsStr::new(&sddl));
    let mut security_descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut security_descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let allocation = LocalAllocation(security_descriptor);
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = null_mut();
    if unsafe { GetSecurityDescriptorDacl(allocation.0, &mut present, &mut dacl, &mut defaulted) }
        == 0
        || present == 0
        || dacl.is_null()
    {
        return Err(io::Error::last_os_error());
    }
    let result = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if result != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    Ok(())
}

fn validate_private_acl(handle: HANDLE, directory: bool) -> io::Result<()> {
    let current_user = current_user_sid()?;
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut security_descriptor = null_mut();
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut security_descriptor,
        )
    };
    if result != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let allocation = LocalAllocation(security_descriptor);
    if owner.is_null() || unsafe { EqualSid(owner, current_user.as_ptr()) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private object owner differs from the current user",
        ));
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    if unsafe { GetSecurityDescriptorControl(allocation.0, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
        || dacl.is_null()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private object DACL is absent or inherited",
        ));
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            &mut information as *mut _ as *mut c_void,
            mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
        || information.AceCount != 2
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private object DACL does not contain exactly two entries",
        ));
    }
    let system_sid = sid_from_string("S-1-5-18")?;
    let expected_flags = if directory {
        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
    } else {
        0
    };
    let mut user_seen = false;
    let mut system_seen = false;
    for index in 0..information.AceCount {
        let mut raw_ace = null_mut();
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(io::Error::last_os_error());
        }
        let ace = unsafe { &*(raw_ace as *const ACCESS_ALLOWED_ACE) };
        if u32::from(ace.Header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || ace.Header.AceFlags != expected_flags
            || ace.Mask != FILE_ALL_ACCESS_MASK
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private object contains an unexpected access entry",
            ));
        }
        let sid = &ace.SidStart as *const u32 as PSID;
        if unsafe { EqualSid(sid, current_user.as_ptr()) } != 0 {
            user_seen = true;
        } else if unsafe { EqualSid(sid, system_sid.as_ptr()) } != 0 {
            system_seen = true;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private object grants access to an unexpected identity",
            ));
        }
    }
    if !user_seen || !system_seen {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private object lacks an expected access entry",
        ));
    }
    Ok(())
}

struct SidBuffer(Vec<u32>);

impl SidBuffer {
    fn as_ptr(&self) -> PSID {
        self.0.as_ptr() as PSID
    }
}

fn current_user_sid() -> io::Result<SidBuffer> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle::new(token)?;
    let mut size = 0_u32;
    unsafe {
        GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut size);
    }
    if size == 0
        || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
    {
        return Err(io::Error::last_os_error());
    }
    let word_count = (size as usize).div_ceil(mem::size_of::<usize>());
    let mut token_information = vec![0_usize; word_count];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            token_information.as_mut_ptr() as *mut c_void,
            size,
            &mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let token_user = unsafe { &*(token_information.as_ptr() as *const TOKEN_USER) };
    let sid_length = unsafe { windows_sys::Win32::Security::GetLengthSid(token_user.User.Sid) };
    if sid_length == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sid = vec![0_u32; (sid_length as usize).div_ceil(mem::size_of::<u32>())];
    if unsafe {
        windows_sys::Win32::Security::CopySid(
            sid_length,
            sid.as_mut_ptr() as PSID,
            token_user.User.Sid,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(SidBuffer(sid))
}

fn current_user_sid_string() -> io::Result<String> {
    sid_to_string(current_user_sid()?.as_ptr())
}

fn sid_from_string(value: &str) -> io::Result<SidBuffer> {
    let value = wide(OsStr::new(value));
    let mut sid = null_mut();
    if unsafe {
        windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW(
            value.as_ptr(),
            &mut sid,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let allocation = LocalAllocation(sid);
    let sid_length = unsafe { windows_sys::Win32::Security::GetLengthSid(sid) };
    if sid_length == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut copied = vec![0_u32; (sid_length as usize).div_ceil(mem::size_of::<u32>())];
    if unsafe {
        windows_sys::Win32::Security::CopySid(sid_length, copied.as_mut_ptr() as PSID, sid)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    drop(allocation);
    Ok(SidBuffer(copied))
}

fn sid_to_string(sid: PSID) -> io::Result<String> {
    let mut rendered = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut rendered) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let allocation = LocalAllocation(rendered as *mut c_void);
    let mut length = 0;
    unsafe {
        while *rendered.add(length) != 0 {
            length += 1;
        }
    }
    let value = unsafe { String::from_utf16(&std::slice::from_raw_parts(rendered, length)) }
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid SID string"))?;
    drop(allocation);
    Ok(value)
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::Write};

    #[test]
    fn private_acl_refuses_world_access_hardlinks_and_reparse_points() {
        let root = tempfile::tempdir().unwrap();
        let vault = root.path().join("vault");
        fs::create_dir(&vault).unwrap();
        protect_directory(&vault).unwrap();
        validate_private_directory(&vault).unwrap();

        let secret = vault.join("secret.bin");
        let mut file = File::create(&secret).unwrap();
        file.write_all(b"secret").unwrap();
        drop(file);
        protect_file(&secret).unwrap();
        assert!(open_private_file(&secret, 64).is_ok());

        let handle = open_security_handle(&secret, false, true).unwrap();
        apply_acl_sddl(handle.0, "D:P(A;;FA;;;WD)").unwrap();
        assert!(validate_private_acl(handle.0, false).is_err());
        drop(handle);
        protect_file(&secret).unwrap();

        let hardlink = vault.join("secret-link.bin");
        fs::hard_link(&secret, &hardlink).unwrap();
        assert!(open_private_file(&secret, 64).is_err());
        fs::remove_file(&hardlink).unwrap();

        let reparse = vault.join("secret-reparse.bin");
        if std::os::windows::fs::symlink_file(&secret, &reparse).is_ok() {
            assert!(open_private_file(&reparse, 64).is_err());
        }
    }
}
