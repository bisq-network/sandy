//! Locks that coordinate concurrent sandy processes of one user.
//!
//! sandy used named mutexes in the `Local\` namespace. That namespace is per logon session, and
//! in session 0, which services and SSH sessions run in, it is the namespace that every user's
//! session 0 processes share. Another local user could therefore hold sandy's mutex, which sandy
//! waits for without a limit, or create the coordination object with permissions of their own.
//!
//! These locks are byte ranges of files below `%LOCALAPPDATA%\sandy`. The user's local
//! application data grants access to the user, SYSTEM and the administrators only, and nothing
//! to AppContainers, so the sandboxed program cannot reach them either. The kernel releases a
//! byte range lock when its process dies, so a run that crashed leaves no lock behind; the file
//! stays, which costs nothing because a lock, not the file, says that a run is active.

use std::fs;
use std::io;
use std::os::windows::fs::{FileExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;

use sandy_core::SandboxError;
use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_SHARE_READ, FILE_SHARE_WRITE, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    LockFileEx, UnlockFileEx,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

/// Files that serialize one step of a run, like a mutex.
pub const LOCKS: &str = "locks";
/// Files that hold the policy of the runs in one AppContainer.
pub const RUNS: &str = "runs";

/// The byte that serializes a step: holding it exclusively means that no other sandy process of
/// this user is in the same step.
pub const SERIALIZE: u32 = 0;

/// The byte that marks a run as active. Every run holds it shared, so an exclusive lock on it
/// succeeds exactly while no run holds it.
pub const ACTIVE: u32 = 1;

/// Where the content of a file starts. The bytes below it carry the locks, and a write must not
/// touch a locked byte: Windows refuses a write to a range another handle holds, and refuses to
/// shorten a file past one.
pub const CONTENT: u64 = 8;

/// The most content a file may claim to hold. A fingerprint is a few hundred bytes; the bound
/// keeps a corrupt header from asking for a huge buffer.
const MAX_CONTENT: usize = 1 << 20;

/// A lock on one byte of a per-user file, held until drop.
pub struct UserLock {
    file: fs::File,
    byte: u32,
}

impl UserLock {
    /// Locks `byte` of `<LOCALAPPDATA>\sandy\<kind>\<name>`. Without `wait` a byte another
    /// process holds gives `Ok(None)` instead of waiting.
    pub fn take(
        kind: &str,
        name: &str,
        byte: u32,
        exclusive: bool,
        wait: bool,
    ) -> Result<Option<UserLock>, SandboxError> {
        let path = path(kind, name)?;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            // No FILE_SHARE_DELETE: nothing may replace the file while runs coordinate on it.
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&path)
            .map_err(|error| SandboxError::io(format!("cannot open {}", path.display()), error))?;
        let lock = UserLock { file, byte };
        let mut flags = 0;
        if exclusive {
            flags |= LOCKFILE_EXCLUSIVE_LOCK;
        }
        if !wait {
            flags |= LOCKFILE_FAIL_IMMEDIATELY;
        }
        let mut overlapped = at(byte);
        // SAFETY: the handle is an open file and overlapped is a writable OVERLAPPED that
        // outlives this synchronous call.
        let ok = unsafe { LockFileEx(lock.file.as_raw_handle(), flags, 0, 1, 0, &mut overlapped) };
        if ok != 0 {
            return Ok(Some(lock));
        }
        let error = io::Error::last_os_error();
        if !wait && error.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
            return Ok(None);
        }
        Err(SandboxError::io(
            format!("cannot lock {}", path.display()),
            error,
        ))
    }

    /// Takes a lock that always waits, so the caller needs no `Option`.
    pub fn wait_for(
        kind: &str,
        name: &str,
        byte: u32,
        exclusive: bool,
    ) -> Result<UserLock, SandboxError> {
        UserLock::take(kind, name, byte, exclusive, true)?
            .ok_or_else(|| SandboxError::new("a waiting lock reported a conflict"))
    }

    /// The content of the file, which starts at `CONTENT`: a 4 byte little-endian length and
    /// that many bytes. Empty when the file is new or was never written.
    pub fn read(&self) -> Result<Vec<u8>, SandboxError> {
        let mut header = [0u8; 4];
        if self.read_at(&mut header, CONTENT)? < header.len() {
            return Ok(Vec::new());
        }
        let len = u32::from_le_bytes(header) as usize;
        if len > MAX_CONTENT {
            return Ok(Vec::new());
        }
        let mut content = vec![0u8; len];
        if self.read_at(&mut content, CONTENT + 4)? < content.len() {
            return Ok(Vec::new());
        }
        Ok(content)
    }

    /// Replaces the content. The file is not shortened, so a shorter write leaves bytes behind
    /// that the length in the header excludes.
    pub fn write(&self, content: &[u8]) -> Result<(), SandboxError> {
        let mut bytes = (content.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(content);
        let mut written = 0;
        while written < bytes.len() {
            written += self
                .file
                .seek_write(&bytes[written..], CONTENT + written as u64)
                .map_err(|error| SandboxError::io("cannot write a lock file", error))?;
        }
        Ok(())
    }

    fn read_at(&self, buffer: &mut [u8], offset: u64) -> Result<usize, SandboxError> {
        let mut read = 0;
        while read < buffer.len() {
            match self
                .file
                .seek_read(&mut buffer[read..], offset + read as u64)
            {
                Ok(0) => break,
                Ok(bytes) => read += bytes,
                Err(error) => {
                    return Err(SandboxError::io("cannot read a lock file", error));
                }
            }
        }
        Ok(read)
    }
}

impl Drop for UserLock {
    fn drop(&mut self) {
        let mut overlapped = at(self.byte);
        // SAFETY: as in `take`; the range is the one this process locked.
        unsafe { UnlockFileEx(self.file.as_raw_handle(), 0, 1, 0, &mut overlapped) };
    }
}

/// `%LOCALAPPDATA%\sandy\<kind>\<name>`, with the directory created if it is missing.
fn path(kind: &str, name: &str) -> Result<PathBuf, SandboxError> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let local = OsString::from_wide(&super::local_app_data()?);
    let directory = PathBuf::from(local).join("sandy").join(kind);
    fs::create_dir_all(&directory).map_err(|error| {
        SandboxError::io(format!("cannot create {}", directory.display()), error)
    })?;
    Ok(directory.join(name))
}

fn at(byte: u32) -> OVERLAPPED {
    // SAFETY: the structure is plain data; zero is a valid value for every field.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.Anonymous.Anonymous.Offset = byte;
    overlapped
}
