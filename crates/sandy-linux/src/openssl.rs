//! The `.include` directives of the OpenSSL configuration. OpenSSL drops an include it cannot
//! read without reporting anything and then runs with weaker built-in defaults, so a policy that
//! covers `openssl.cnf` but not everything it includes changes what the program does without
//! saying so. sandy cannot grant the targets on its own, because an administrator can include
//! files from anywhere, so it reports them and leaves the decision to whoever writes the policy.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// An include target that the program cannot read, with the configuration file that names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingInclude {
    pub config: PathBuf,
    pub target: PathBuf,
}

/// How many configuration files are parsed at most, so a tree of includes cannot keep sandy
/// busy. A distribution uses two or three.
const MAX_FILES: usize = 32;

/// The include targets of `configs`, and of the files they include, that the user can read but
/// `readable` says the program cannot. A configuration file the program cannot read at all is
/// not parsed: OpenSSL then reads none of it, which is a policy decision, not a silent change.
pub fn missing_includes(
    configs: &[PathBuf],
    readable: &dyn Fn(&Path) -> bool,
) -> Vec<MissingInclude> {
    let mut missing = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut pending: Vec<PathBuf> = configs.iter().rev().cloned().collect();
    while let Some(config) = pending.pop() {
        if seen.len() >= MAX_FILES {
            break;
        }
        let Ok(config) = config.canonicalize() else {
            continue;
        };
        if !readable(&config) || !seen.insert(config.clone()) {
            continue;
        }
        let Some(text) = read_regular(&config) else {
            continue;
        };
        for target in includes(&text) {
            // A relative target is read against the current directory, as OpenSSL does without
            // OPENSSL_CONF_INCLUDE. A target that does not exist is skipped: OpenSSL skips it
            // outside the sandbox as well, so nothing changes inside it.
            let Ok(target) = target.canonicalize() else {
                continue;
            };
            if !user_can_read(&target) {
                continue;
            }
            if readable(&target) {
                pending.extend(nested(&target));
            } else {
                missing.push(MissingInclude {
                    config: config.clone(),
                    target,
                });
            }
        }
    }
    missing
}

/// The paths of the `.include` lines of a configuration file, as written. OpenSSL takes the rest
/// of the line after the directive, an optional `=` and the whitespace around it, and treats `#`
/// as the start of a comment. The directive must be followed by whitespace or `=`, so that
/// another word starting with it is no include.
fn includes(text: &str) -> Vec<PathBuf> {
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or_default().trim();
            let rest = line.strip_prefix(".include")?;
            let rest = match rest.chars().next() {
                Some('=') => rest,
                Some(first) if first.is_whitespace() => rest.trim_start(),
                _ => return None,
            };
            let path = rest.strip_prefix('=').unwrap_or(rest).trim();
            (!path.is_empty()).then(|| PathBuf::from(path))
        })
        .collect()
}

/// Whether the user can read the target at all. One that is out of reach outside the sandbox is
/// out of reach inside it for the same reason, so it is not reported.
fn user_can_read(target: &Path) -> bool {
    match target.metadata() {
        Ok(metadata) if metadata.is_dir() => std::fs::read_dir(target).is_ok(),
        Ok(_) => open_regular(target).is_some(),
        Err(_) => false,
    }
}

/// Opens `path` for reading if it is a regular file. O_NONBLOCK, because a named pipe in an
/// include directory would otherwise keep `check` waiting for a writer.
fn open_regular(path: &Path) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::File::options()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    file.metadata().ok()?.is_file().then_some(file)
}

fn read_regular(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut text = String::new();
    open_regular(path)?.read_to_string(&mut text).ok()?;
    Some(text)
}

/// The configuration files inside an include target that is a directory. OpenSSL includes the
/// files with a `.cnf` or `.conf` name directly in it and ignores subdirectories.
fn nested(target: &Path) -> Vec<PathBuf> {
    let Ok(metadata) = target.metadata() else {
        return Vec::new();
    };
    if !metadata.is_dir() {
        return vec![target.to_path_buf()];
    }
    let Ok(entries) = std::fs::read_dir(target) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            let suffix = path.extension().unwrap_or_default();
            suffix == "cnf" || suffix == "conf"
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sandy-openssl-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap()
    }

    #[test]
    fn include_lines_are_read_like_openssl_reads_them() {
        let text = "\
            [section]\n\
            .include /a/absolute\n\
            .include = /with/equals\n\
            .include=/without/space\n\
               .include /indented # trailing comment\n\
            # .include /commented\n\
            .includex /not/a/directive\n\
            .pragma includedir:/other\n\
            .include\n";
        assert_eq!(
            includes(text),
            [
                PathBuf::from("/a/absolute"),
                PathBuf::from("/with/equals"),
                PathBuf::from("/without/space"),
                PathBuf::from("/indented"),
            ]
        );
    }

    #[test]
    fn an_include_the_program_cannot_read_is_reported() {
        let dir = directory("missing");
        let config = dir.join("openssl.cnf");
        let covered = dir.join("covered.cnf");
        let hidden = dir.join("hidden.cnf");
        std::fs::write(
            &config,
            format!(
                ".include {}\n.include {}\n.include {}\n",
                covered.display(),
                hidden.display(),
                dir.join("absent.cnf").display()
            ),
        )
        .unwrap();
        std::fs::write(&covered, "[covered]\n").unwrap();
        std::fs::write(&hidden, "[hidden]\n").unwrap();
        let readable = |path: &Path| path != hidden;
        assert_eq!(
            missing_includes(std::slice::from_ref(&config), &readable),
            [MissingInclude {
                config: config.clone(),
                target: hidden,
            }]
        );
        // Nothing is reported when every target is readable, and nothing when the configuration
        // itself is out of reach, because OpenSSL then reads none of it.
        assert_eq!(
            missing_includes(std::slice::from_ref(&config), &|_| true),
            []
        );
        assert_eq!(missing_includes(&[config], &|_| false), []);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A named pipe among the configuration files is skipped. Opening it would wait for a
    /// writer, and `check` would never end.
    #[test]
    fn a_named_pipe_in_an_include_directory_does_not_block() {
        let dir = directory("pipe");
        let config = dir.join("openssl.cnf");
        let included = dir.join("parts");
        std::fs::create_dir_all(&included).unwrap();
        std::fs::write(&config, format!(".include {}\n", included.display())).unwrap();
        let pipe = std::ffi::CString::new(included.join("pipe.cnf").to_str().unwrap()).unwrap();
        // SAFETY: the path is NUL-terminated.
        assert_eq!(unsafe { libc::mkfifo(pipe.as_ptr(), 0o600) }, 0);
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || send.send(missing_includes(&[config], &|_| true)));
        let result = receive.recv_timeout(std::time::Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(result, Ok(Vec::new()));
    }

    /// A directory include covers the configuration files in it, and those can include further
    /// files, which are checked as well.
    #[test]
    fn includes_of_included_files_and_directories_are_followed() {
        let dir = directory("nested");
        let config = dir.join("openssl.cnf");
        let included = dir.join("parts");
        std::fs::create_dir_all(&included).unwrap();
        let part = included.join("part.cnf");
        let deep = dir.join("deep.cnf");
        std::fs::write(&config, format!(".include {}\n", included.display())).unwrap();
        std::fs::write(&part, format!(".include {}\n", deep.display())).unwrap();
        std::fs::write(&deep, "[deep]\n").unwrap();
        std::fs::write(included.join("ignored.txt"), ".include /nowhere\n").unwrap();
        let readable = |path: &Path| path != deep;
        assert_eq!(
            missing_includes(&[config], &readable),
            [MissingInclude {
                config: part,
                target: deep,
            }]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
