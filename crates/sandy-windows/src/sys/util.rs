use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use sandy_core::SandboxError;
use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, GetLengthSid, IsValidSid, PSID, WELL_KNOWN_SID_TYPE,
};

pub fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().collect()
}

pub fn wide_nul(text: &OsStr) -> Vec<u16> {
    let mut wide = wide(text);
    wide.push(0);
    wide
}

pub fn last_error(context: impl Into<String>) -> SandboxError {
    SandboxError::io(context, io::Error::last_os_error())
}

pub fn win32_error(context: impl Into<String>, code: u32) -> SandboxError {
    SandboxError::io(context, io::Error::from_raw_os_error(code as i32))
}

pub fn hresult_error(context: impl Into<String>, hresult: i32) -> SandboxError {
    SandboxError::io(context, hresult_to_io(hresult))
}

/// Maps `HRESULT_FROM_WIN32` values back to the Win32 error, so the message is readable.
pub fn hresult_to_io(hresult: i32) -> io::Error {
    let code = hresult as u32;
    if code & 0xFFFF_0000 == 0x8007_0000 {
        io::Error::from_raw_os_error((code & 0xFFFF) as i32)
    } else {
        io::Error::other(format!("HRESULT {code:#010x}"))
    }
}

/// Memory that a Windows API allocated with `LocalAlloc`.
pub struct LocalBox(pub HLOCAL);

impl Drop for LocalBox {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API documented to allocate with LocalAlloc, and
            // it is freed exactly once.
            unsafe { LocalFree(self.0) };
        }
    }
}

const MAX_SID_WORDS: usize = 17;

/// A SID in memory owned by sandy. The words keep the 4-byte alignment of the `SID` structure.
#[derive(Clone, PartialEq, Eq)]
pub struct Sid {
    words: [u32; MAX_SID_WORDS],
    len: usize,
}

impl Sid {
    /// Copies the SID at `psid`.
    ///
    /// # Safety
    /// `psid` must be null or point to readable memory that starts with a SID.
    pub unsafe fn copy_from(psid: PSID) -> io::Result<Sid> {
        // SAFETY: the caller guarantees that a non-null psid points to a SID; IsValidSid checks
        // its revision and sub-authority count before GetLengthSid trusts them.
        if psid.is_null() || unsafe { IsValidSid(psid) } == 0 {
            return Err(io::Error::other("invalid SID"));
        }
        // SAFETY: psid is a valid SID (checked above).
        let len = unsafe { GetLengthSid(psid) } as usize;
        Sid::from_bytes(
            // SAFETY: GetLengthSid returned the length of the SID that starts at psid.
            unsafe { std::slice::from_raw_parts(psid.cast::<u8>(), len) },
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> io::Result<Sid> {
        if bytes.len() > MAX_SID_WORDS * 4 {
            return Err(io::Error::other("SID too long"));
        }
        let mut sid = Sid {
            words: [0; MAX_SID_WORDS],
            len: bytes.len(),
        };
        // SAFETY: the destination has room for MAX_SID_WORDS * 4 bytes (checked above) and does
        // not overlap the source.
        unsafe {
            ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                sid.words.as_mut_ptr().cast::<u8>(),
                bytes.len(),
            )
        };
        Ok(sid)
    }

    pub fn well_known(kind: WELL_KNOWN_SID_TYPE) -> io::Result<Sid> {
        let mut sid = Sid {
            words: [0; MAX_SID_WORDS],
            len: 0,
        };
        let mut size = (MAX_SID_WORDS * 4) as u32;
        // SAFETY: the buffer is SECURITY_MAX_SID_SIZE (68) bytes, aligned for a SID, and size
        // tells the function its length.
        let ok = unsafe {
            CreateWellKnownSid(
                kind,
                ptr::null_mut(),
                sid.words.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        sid.len = size as usize;
        Ok(sid)
    }

    /// Pointer for APIs that take a `PSID`. They only read through it; it stays valid while
    /// `self` is neither moved nor dropped.
    pub fn as_psid(&self) -> PSID {
        self.words.as_ptr().cast_mut().cast()
    }

    pub fn bytes(&self) -> &[u8] {
        // SAFETY: len is at most the size of words (checked on construction), and u8 has no
        // alignment or validity requirements.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.len) }
    }
}

/// Prints the SID in the `S-1-...` form, the form `icacls` and `CheckNetIsolation` use.
impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.bytes();
        if bytes.len() < 8 {
            return f.write_str("S-?");
        }
        let authority = bytes[2..8]
            .iter()
            .fold(0u64, |value, &byte| (value << 8) | u64::from(byte));
        write!(f, "S-{}-{authority}", bytes[0])?;
        for chunk in bytes[8..].as_chunks::<4>().0 {
            let sub = u32::from_le_bytes(*chunk);
            write!(f, "-{sub}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::ALL_APPLICATION_PACKAGES;
    use windows_sys::Win32::Security::{WinBuiltinAnyPackageSid, WinLowLabelSid};

    #[test]
    fn well_known_sids_match_the_constants() {
        let any_package = Sid::well_known(WinBuiltinAnyPackageSid).unwrap();
        assert_eq!(any_package.bytes(), ALL_APPLICATION_PACKAGES);
        assert_eq!(any_package.to_string(), "S-1-15-2-1");
        assert_eq!(
            Sid::well_known(WinLowLabelSid).unwrap().to_string(),
            "S-1-16-4096"
        );
    }

    #[test]
    fn maps_win32_hresults() {
        let error = hresult_to_io(0x8007_0005_u32 as i32);
        assert_eq!(error.raw_os_error(), Some(5));
    }
}
