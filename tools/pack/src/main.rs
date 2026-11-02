//! Packs the files of a release archive with fixed metadata: sorted entries under one directory,
//! the given time on every entry, owner 0, permissions 0755 or 0644 from the executable bit only.
//! The output then depends only on the files and the arguments, not on the host, its tools or
//! the time of the build.
//!
//!   sandy-pack ARCHIVE DIRECTORY MTIME FILE...
//!
//! ARCHIVE ends with .tar.gz or .zip; DIRECTORY is the name of the directory every FILE goes
//! into, by its file name; MTIME is in seconds since the epoch, such as SOURCE_DATE_EPOCH.

mod tar;
mod zip;

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

/// One member of an archive: the directory, or a file in it.
#[derive(Debug)]
pub struct Entry {
    /// Path inside the archive, with a trailing slash for the directory.
    pub name: String,
    /// Permission bits, 0o755 or 0o644.
    pub mode: u32,
    /// The contents of a file; `None` for the directory.
    pub data: Option<Vec<u8>>,
}

/// The directory entry followed by the files, sorted by name.
pub fn entries(directory: &str, files: &[(String, Vec<u8>, bool)]) -> Result<Vec<Entry>, String> {
    if directory.is_empty() || directory.contains('/') {
        return Err(format!("{directory:?} is not a single directory name"));
    }
    let mut members: Vec<Entry> = files
        .iter()
        .map(|(name, data, executable)| Entry {
            name: format!("{directory}/{name}"),
            mode: if *executable { 0o755 } else { 0o644 },
            data: Some(data.clone()),
        })
        .collect();
    members.sort_by(|a, b| a.name.cmp(&b.name));
    if members.windows(2).any(|pair| pair[0].name == pair[1].name) {
        return Err("two files have the same name".into());
    }
    members.insert(
        0,
        Entry {
            name: format!("{directory}/"),
            mode: 0o755,
            data: None,
        },
    );
    Ok(members)
}

fn read(path: &str) -> Result<(String, Vec<u8>, bool), String> {
    let name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{path}: no file name"))?
        .to_string();
    let data = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    Ok((name, data, executable(path)?))
}

#[cfg(unix)]
fn executable(path: &str) -> Result<bool, String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|e| format!("{path}: {e}"))?
        .permissions()
        .mode();
    Ok(mode & 0o111 != 0)
}

#[cfg(not(unix))]
fn executable(path: &str) -> Result<bool, String> {
    Ok(path.ends_with(".exe"))
}

fn run(args: &[String]) -> Result<(), String> {
    let [archive, directory, mtime, files @ ..] = args else {
        return Err("usage: sandy-pack ARCHIVE DIRECTORY MTIME FILE...".into());
    };
    let mtime: u64 = mtime
        .parse()
        .map_err(|_| format!("{mtime:?} is not a time in seconds"))?;
    let files = files
        .iter()
        .map(|path| read(path))
        .collect::<Result<Vec<_>, _>>()?;
    let members = entries(directory, &files)?;
    let bytes = if archive.ends_with(".tar.gz") {
        tar::gzipped(&members, mtime)?
    } else if archive.ends_with(".zip") {
        zip::archive(&members, mtime)?
    } else {
        return Err(format!("{archive}: not a .tar.gz or .zip name"));
    };
    let mut out = fs::File::create(archive).map_err(|e| format!("{archive}: {e}"))?;
    out.write_all(&bytes).map_err(|e| format!("{archive}: {e}"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("sandy-pack: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_directory_comes_first_and_the_files_sorted() {
        let files = vec![
            ("sandy".to_string(), b"bin".to_vec(), true),
            ("README.md".to_string(), b"doc".to_vec(), false),
        ];
        let members = entries("sandy-1.0.0", &files).unwrap();
        let names: Vec<_> = members.iter().map(|m| (m.name.as_str(), m.mode)).collect();
        assert_eq!(
            names,
            [
                ("sandy-1.0.0/", 0o755),
                ("sandy-1.0.0/README.md", 0o644),
                ("sandy-1.0.0/sandy", 0o755)
            ]
        );
    }

    #[test]
    fn a_nested_or_empty_directory_and_duplicate_files_are_refused() {
        let file = ("a".to_string(), Vec::new(), false);
        assert!(entries("a/b", std::slice::from_ref(&file)).is_err());
        assert!(entries("", std::slice::from_ref(&file)).is_err());
        assert!(entries("d", &[file.clone(), file]).is_err());
    }
}
