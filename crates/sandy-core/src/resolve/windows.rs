//! File identity and the names of a file on Windows, which the resolver compares instead of
//! spellings (see "Links and file identity" in docs/DESIGN.md). Each call opens the object for
//! its attributes only, which reads no data and conflicts with no other open, and closes it again.

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    ERROR_HANDLE_EOF, ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA,
    ERROR_NOT_READY, ERROR_NOT_SUPPORTED, HANDLE, INVALID_HANDLE_VALUE, MAX_PATH,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_ID_INFO, FILE_INFO_BY_HANDLE_CLASS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileAttributeTagInfo, FileIdInfo,
    FileStandardInfo, FindClose, FindFirstFileNameW, FindNextFileNameW, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetVolumePathNameW,
};

use super::Entry;

/// Identity of a file: the serial number of its volume and its file ID. Two names of one file,
/// a hard link for example, share it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct FileId {
    volume: u64,
    file: u128,
}

/// The identity of the object at `path`. With `follow` false, of a junction or symbolic link at
/// `path` itself, else of what it leads to.
pub(super) fn file_id(path: &Path, follow: bool) -> io::Result<FileId> {
    identity(&open(path, follow)?)
}

/// `path` as a walk sees it, without following a link at it.
pub(super) fn entry(path: &Path) -> io::Result<Entry> {
    let handle = open(path, false)?;
    // SAFETY: both are plain structures, for which zero is a valid value, and each is the one
    // its class fills.
    let (tag, standard) = unsafe {
        let mut tag: FILE_ATTRIBUTE_TAG_INFO = std::mem::zeroed();
        query(&handle, FileAttributeTagInfo, &mut tag)?;
        let mut standard: FILE_STANDARD_INFO = std::mem::zeroed();
        query(&handle, FileStandardInfo, &mut standard)?;
        (tag, standard)
    };
    let directory = tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    // Junctions and symbolic links are name surrogates, which std::fs counts as symbolic links.
    let link = tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        && tag.ReparseTag & NAME_SURROGATE != 0;
    Ok(Entry {
        id: identity(&handle)?,
        is_dir: directory && !link,
        linked: !directory && !link && standard.NumberOfLinks > 1,
    })
}

/// The bit of a reparse tag that `IsReparseTagNameSurrogate` tests.
const NAME_SURROGATE: u32 = 0x2000_0000;

/// Every name of the file at `path` (`FindFirstFileNameW`), each as the path its volume is
/// mounted at plus the name on the volume. Measured on Windows 11: for a verbatim path the
/// volume path is verbatim too, so the names compare with the canonical policy paths.
pub(super) fn names(path: &Path) -> io::Result<Vec<PathBuf>> {
    let path = wide(path)?;
    let mut volume = vec![0u16; path.len().max(MAX_PATH as usize) + 1];
    // SAFETY: path is NUL-terminated, and volume holds the number of characters passed.
    if unsafe { GetVolumePathNameW(path.as_ptr(), volume.as_mut_ptr(), volume.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let volume = PathBuf::from(until_nul(&volume));
    // A name on the volume starts with a backslash, which `join` would read as the root of the
    // drive rather than of a volume mounted at a folder.
    let full = |name: &[u16]| {
        let start = name.iter().take_while(|c| **c == u16::from(b'\\')).count();
        volume.join(until_nul(&name[start..]))
    };

    let mut buffer = vec![0u16; MAX_PATH as usize];
    let find = loop {
        let mut length = buffer.len() as u32;
        // SAFETY: path is NUL-terminated, and buffer holds `length` characters.
        let find =
            unsafe { FindFirstFileNameW(path.as_ptr(), 0, &mut length, buffer.as_mut_ptr()) };
        if find != INVALID_HANDLE_VALUE {
            break Find(find);
        }
        grow(&mut buffer, length, io::Error::last_os_error())?;
    };
    let mut names = vec![full(&buffer)];
    loop {
        let mut length = buffer.len() as u32;
        // SAFETY: the enumeration is open, and buffer holds `length` characters.
        if unsafe { FindNextFileNameW(find.0, &mut length, buffer.as_mut_ptr()) } != 0 {
            names.push(full(&buffer));
            continue;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) {
            return Ok(names);
        }
        grow(&mut buffer, length, error)?;
    }
}

/// Whether `error` says that no object is at the path, rather than that sandy cannot tell which
/// one is: the path or a directory on it does not exist, or the drive holds no medium.
pub(super) fn no_object(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(ERROR_NOT_READY as i32)
}

/// An enumeration of `FindFirstFileNameW`, closed on drop.
struct Find(HANDLE);

impl Drop for Find {
    fn drop(&mut self) {
        // SAFETY: the handle came from FindFirstFileNameW and is closed only here.
        unsafe { FindClose(self.0) };
    }
}

/// Makes `buffer` hold `length` characters when `error` says that it was too small, which the
/// functions that fill it report together with the length they need; else returns `error`.
fn grow(buffer: &mut Vec<u16>, length: u32, error: io::Error) -> io::Result<()> {
    let length = length as usize;
    if error.raw_os_error() != Some(ERROR_MORE_DATA as i32) || length <= buffer.len() {
        return Err(error);
    }
    buffer.resize(length, 0);
    Ok(())
}

/// `path` opened for its attributes only. That needs no right on the object where its
/// directory may be listed. FILE_FLAG_BACKUP_SEMANTICS is required to open directories and grants
/// no extra rights to callers without the backup privilege. With `follow` false, a junction or
/// symbolic link at `path` is opened itself.
fn open(path: &Path, follow: bool) -> io::Result<File> {
    let link = if follow {
        0
    } else {
        FILE_FLAG_OPEN_REPARSE_POINT
    };
    File::options()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | link)
        .open(path)
}

/// The identity of the object behind `handle`: `FILE_ID_INFO`, or on a file system without
/// 128-bit file IDs the older `BY_HANDLE_FILE_INFORMATION`. Such a file system refuses the newer
/// class for every file of its volume, so no file is compared in both forms. When neither
/// answers, the error goes to the caller, which refuses.
fn identity(handle: &File) -> io::Result<FileId> {
    // SAFETY: the structure is plain data, for which zero is a valid value, and it is the one
    // FileIdInfo fills.
    let id = unsafe {
        let mut info: FILE_ID_INFO = std::mem::zeroed();
        query(handle, FileIdInfo, &mut info).map(|()| info)
    };
    match id {
        Ok(info) => {
            return Ok(FileId {
                volume: info.VolumeSerialNumber,
                file: u128::from_le_bytes(info.FileId.Identifier),
            });
        }
        Err(error) if !unsupported(&error) => return Err(error),
        Err(_) => {}
    }
    // SAFETY: the structure is plain data, for which zero is a valid value.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the handle is open and info is a writable BY_HANDLE_FILE_INFORMATION.
    if unsafe { GetFileInformationByHandle(handle.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileId {
        volume: u64::from(info.dwVolumeSerialNumber),
        file: u128::from(u64::from(info.nFileIndexHigh) << 32 | u64::from(info.nFileIndexLow)),
    })
}

/// Whether `error` says that the file system does not know an information class.
fn unsupported(error: &io::Error) -> bool {
    [
        ERROR_INVALID_PARAMETER,
        ERROR_INVALID_FUNCTION,
        ERROR_NOT_SUPPORTED,
    ]
    .iter()
    .any(|code| error.raw_os_error() == Some(*code as i32))
}

/// Fills `info` with the information class `class` of the object behind `handle`.
///
/// # Safety
///
/// `T` must be the plain structure that `class` fills, valid for every bit pattern.
unsafe fn query<T>(
    handle: &File,
    class: FILE_INFO_BY_HANDLE_CLASS,
    info: &mut T,
) -> io::Result<()> {
    // SAFETY: info is writable for its own size, which is passed, and the caller guarantees
    // that it is the structure the class fills.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle(),
            class,
            (info as *mut T).cast(),
            size_of::<T>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `path` as a NUL-terminated wide string. A NUL inside would make Windows read a shorter path,
/// another file, so such a path is refused, as `std::fs` refuses it.
fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the path contains a NUL character",
        ));
    }
    wide.push(0);
    Ok(wide)
}

/// The characters of `buffer` up to its first NUL.
fn until_nul(buffer: &[u16]) -> OsString {
    let end = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
    OsString::from_wide(&buffer[..end])
}
