//! The dynamic loader a program names in its ELF header (`PT_INTERP`). The kernel opens that
//! file for execution during `execve`, so it needs an execute right of its own. The minimal
//! system set names the loaders of the FHS layout; this reads the one the program actually uses,
//! which is how a distribution outside that layout (NixOS, Guix) is covered.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Where a loader may come from. The header of the program file is untrusted input, so sandy
/// grants execute on the path it names only inside these prefixes:
///
/// - `/usr`, `/lib`, `/lib64`: the FHS locations of the system's loaders, which belong to root.
///   The set already names the usual files; a host with another libc or another name has it
///   here.
/// - `/nix/store`, `/gnu/store`: the package stores of NixOS and Guix, which do not follow the
///   FHS and hold the loader of every program there. They belong to root and are read-only.
///
/// Nothing else, because a program that names its own loader would otherwise gain execute on a
/// file that no policy rule covers, for example one it wrote itself.
const SYSTEM_PREFIXES: &[&str] = &["/usr", "/lib", "/lib64", "/nix/store", "/gnu/store"];

/// Whether `path` is a loader sandy may grant execute on. `path` must be canonical, so that a
/// symbolic link under a system prefix cannot point out of it.
pub fn is_system_loader(path: &Path) -> bool {
    SYSTEM_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// The `PT_INTERP` entry of `program`, as written in the file. `None` when the program is not a
/// 64-bit little-endian ELF file (a script, a static program, or a file for another CPU), which
/// leaves the execution to `execve` and its own error.
pub fn interpreter(program: &Path) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;

    /// The longest path the kernel accepts.
    const PATH_MAX: u64 = 4096;
    const PT_INTERP: u32 = 3;

    /// One entry of a program header table.
    const ENTRY: usize = 56;

    fn word(bytes: &[u8], at: usize) -> u64 {
        let mut value = [0u8; 8];
        value.copy_from_slice(&bytes[at..at + 8]);
        u64::from_le_bytes(value)
    }

    // Without O_NONBLOCK, opening a named pipe waits for a writer, and sandy would hang. Only a
    // regular file can be a program the kernel executes.
    let mut file = File::options()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(program)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut header = [0u8; 64];
    file.read_exact(&mut header).ok()?;
    let little_endian_64 = header[..6] == [0x7f, b'E', b'L', b'F', 2, 1];
    if !little_endian_64 {
        return None;
    }
    let offset = word(&header, 0x20);
    let entry_size = u16::from_le_bytes([header[0x36], header[0x37]]);
    let count = usize::from(u16::from_le_bytes([header[0x38], header[0x39]]));
    // A file that gives another entry size is not one sandy reads.
    if usize::from(entry_size) != ENTRY || count == 0 || count > 128 {
        return None;
    }
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut table = vec![0u8; ENTRY * count];
    file.read_exact(&mut table).ok()?;
    let interp = table
        .chunks_exact(ENTRY)
        .find(|entry| u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]) == PT_INTERP)?;
    let at = word(interp, 8);
    let size = word(interp, 32);
    if size == 0 || size > PATH_MAX {
        return None;
    }
    file.seek(SeekFrom::Start(at)).ok()?;
    let mut path = vec![0u8; size as usize];
    file.read_exact(&mut path).ok()?;
    // The entry is NUL-terminated and may be padded.
    let end = path.iter().position(|&byte| byte == 0)?;
    let path = Path::new(std::ffi::OsStr::from_bytes(&path[..end]));
    path.is_absolute().then(|| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 64-bit little-endian ELF file with one program header, which names `interp`.
    fn elf_with_interpreter(path: &Path, interp: &str) {
        let mut bytes = vec![0u8; 64 + 56];
        bytes[..6].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1]);
        bytes[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        bytes[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        bytes[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
        let interp = format!("{interp}\0");
        let at = bytes.len() as u64;
        bytes[64..68].copy_from_slice(&3u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&at.to_le_bytes());
        bytes[96..104].copy_from_slice(&(interp.len() as u64).to_le_bytes());
        bytes.extend_from_slice(interp.as_bytes());
        std::fs::write(path, bytes).unwrap();
    }

    fn temporary(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sandy-loader-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn the_interpreter_of_an_elf_program_is_read() {
        let program = temporary("program");
        elf_with_interpreter(&program, "/nix/store/abc/lib/ld-linux-x86-64.so.2");
        assert_eq!(
            interpreter(&program),
            Some(PathBuf::from("/nix/store/abc/lib/ld-linux-x86-64.so.2"))
        );
        let _ = std::fs::remove_file(&program);
    }

    /// A script, a file that is no ELF file at all, and a program without a `PT_INTERP` entry
    /// (statically linked) have no loader to grant.
    #[test]
    fn files_without_an_interpreter_are_left_to_execve() {
        let script = temporary("script");
        std::fs::write(&script, b"#!/bin/sh\nexit 0\n").unwrap();
        assert_eq!(interpreter(&script), None);
        let mut header = vec![0u8; 64 + 56];
        header[..6].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1]);
        header[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        header[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        header[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
        let static_program = temporary("static");
        std::fs::write(&static_program, &header).unwrap();
        assert_eq!(interpreter(&static_program), None);
        let _ = std::fs::remove_file(&script);
        let _ = std::fs::remove_file(&static_program);
    }

    /// A named pipe is no program. Reading its header must not wait for a writer that never
    /// comes.
    #[test]
    fn a_named_pipe_has_no_loader_and_does_not_block() {
        let pipe = temporary("pipe");
        let _ = std::fs::remove_file(&pipe);
        let path = std::ffi::CString::new(pipe.to_str().unwrap()).unwrap();
        // SAFETY: the path is NUL-terminated.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o700) }, 0);
        let (send, receive) = std::sync::mpsc::channel();
        let reader = pipe.clone();
        std::thread::spawn(move || send.send(interpreter(&reader)));
        let result = receive.recv_timeout(std::time::Duration::from_secs(5));
        let _ = std::fs::remove_file(&pipe);
        assert_eq!(result, Ok(None));
    }

    /// A 32-bit program is killed by the filter anyway, and its header has another layout, so
    /// sandy does not read it.
    #[test]
    fn a_32_bit_program_has_no_loader_to_grant() {
        let program = temporary("program32");
        let mut bytes = vec![0u8; 64 + 56];
        bytes[..6].copy_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1]);
        std::fs::write(&program, bytes).unwrap();
        assert_eq!(interpreter(&program), None);
        let _ = std::fs::remove_file(&program);
    }

    #[test]
    fn only_loaders_in_system_locations_count() {
        for path in [
            "/usr/lib64/ld-linux-x86-64.so.2",
            "/lib/ld-musl-x86_64.so.1",
            "/nix/store/abc-glibc/lib/ld-linux-x86-64.so.2",
            "/gnu/store/abc-glibc/lib/ld.so",
        ] {
            assert!(is_system_loader(Path::new(path)), "{path}");
        }
        for path in [
            "/home/user/loader",
            "/tmp/ld.so",
            "/usr-of-mine/ld.so",
            "/nix/other/ld.so",
            "/srv/app/lib/ld-linux-x86-64.so.2",
        ] {
            assert!(!is_system_loader(Path::new(path)), "{path}");
        }
    }
}
