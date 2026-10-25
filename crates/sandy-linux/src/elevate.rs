//! `sandy setup --elevate` on Linux: setup with root's rights, asked for with pkexec, whose
//! authentication agent asks for an administrator's password once. Root never runs a file that
//! someone other than root can change:
//!
//! - When only root can change sandy's own file (`setup::root_only`), pkexec runs that file with
//!   the same arguments.
//! - Otherwise, with `--install-copy`, pkexec runs `INSTALL_COPY`, a fixed shell script that
//!   uses only system tools at absolute paths. It copies the image of the sandy that asks,
//!   `/proc/PID/exe`, never the file at its path, to `setup::copy_path`; checks that the copy
//!   has the same bytes, and that the sandy that asks is still its parent, so that the process
//!   ID named that sandy during both reads; and only then runs the copy's
//!   `setup --install-copy`. Every value reaches the script as a positional parameter, never as
//!   script text. With `--remove`, pkexec runs the installed copy's
//!   `setup --remove --install-copy`.
//! - Otherwise sandy refuses.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use sandy_core::{SandboxError, SetupOptions, SetupOutcome};

use crate::namespace;
use crate::setup::{self, FALLBACK};

const PKEXEC: &str = "/usr/bin/pkexec";
/// pkexec's status when the user dismissed the authentication dialog.
const DISMISSED: i32 = 126;
/// pkexec's status when the rights were not given: not authorized, no authentication agent, or
/// another error of pkexec.
const NOT_AUTHORIZED: i32 = 127;

/// The script root runs for a portable sandy with `--install-copy`. `$1` is the process ID of
/// the sandy that asks, which waits for pkexec, and `$2` its version. pkexec runs the shell in
/// its own process, so that sandy is the shell's parent; a process ID that is not the parent is
/// refused before anything is written, and one whose process ended in between leaves no copy
/// behind. The script's own failures exit with 125, so they never read as pkexec's 126 and 127.
const INSTALL_COPY: &str = r#"fail() { echo "sandy: setup --elevate: $1" >&2; exit 125; }
caller=$1 version=$2
case $caller in ''|*[!0-9]*) fail 'not a process ID' ;; esac
case $version in ''|.*|*[!0-9A-Za-z.+-]*) fail 'not a version' ;; esac
parent() {
  while read -r key value; do [ "$key" = PPid: ] && break; done <"/proc/$$/status"
  [ "$value" = "$caller" ]
}
parent || fail 'the process that asked is not the parent of this shell'
dir=/usr/local/libexec/sandy/$version copy=/usr/local/libexec/sandy/$version/sandy
tmp=$dir/.sandy-setup.sandy.$$ wrote=
umask 022
/usr/bin/mkdir -p "$dir" || fail "cannot create $dir"
trap '/usr/bin/rm -f "$tmp"' EXIT
if ! /usr/bin/cmp -s "/proc/$caller/exe" "$copy"; then
  /usr/bin/rm -f "$tmp" && /usr/bin/cat "/proc/$caller/exe" >"$tmp" &&
    /usr/bin/chmod 0755 "$tmp" && /usr/bin/mv -f "$tmp" "$copy" || fail "cannot write $copy"
  wrote=1
fi
if ! /usr/bin/cmp -s "/proc/$caller/exe" "$copy" || ! parent; then
  [ -z "$wrote" ] || /usr/bin/rm -f "$copy"
  fail "$copy is not the image of the sandy that asked, or that sandy ended"
fi
"$copy" setup --install-copy
status=$?
[ "$status" -lt 126 ] || exit 125
exit "$status"
"#;

/// The name the script runs under (`$0`).
const SCRIPT_NAME: &str = "sandy-setup";

/// How root's rights reach setup.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Route {
    /// pkexec runs sandy's own file with the same arguments.
    Own(PathBuf),
    /// pkexec runs `INSTALL_COPY`.
    InstallCopy,
    /// pkexec runs the installed copy's `setup --remove --install-copy`.
    RemoveCopy(PathBuf),
}

/// `setup --elevate` and `setup --remove --elevate`. `args` are sandy's arguments without
/// `--elevate`.
pub fn elevate(
    remove: bool,
    options: SetupOptions,
    args: &[OsString],
) -> Result<SetupOutcome, SandboxError> {
    if setup::is_root() {
        return if remove {
            setup::remove(options)
        } else {
            setup::setup(options)
        };
    }
    // Decided without rights, so a host that needs nothing, or where setup cannot help, asks
    // for no password.
    if remove {
        if !setup::something_to_remove(options) {
            return Ok(SetupOutcome::Done("nothing to remove".to_string()));
        }
    } else if let Some(reason) = setup::disabled(&namespace::support(&namespace::Purpose::Any)) {
        return Ok(SetupOutcome::Refused(format!("{reason}; {FALLBACK}")));
    } else if let Some(reason) = setup::unrestricted() {
        return Ok(SetupOutcome::Done(format!("nothing to do: {reason}")));
    }
    let own = match setup::own_path() {
        Ok(own) => own,
        Err(reason) => return Ok(SetupOutcome::Refused(format!("{reason}; {FALLBACK}"))),
    };
    let copy = setup::copy_path();
    let route = route(
        &own,
        setup::root_only(&own, false),
        remove,
        options.install_copy,
        &copy,
        setup::root_only(&copy, !remove),
    );
    let route = match route {
        Ok(route) => route,
        Err(reason) => return Ok(SetupOutcome::Refused(format!("{reason}; {FALLBACK}"))),
    };
    let sudo = sudo_command(&route, &own, args);
    let command = command_line(&route, args, std::process::id());
    let status = match Command::new(&command[0]).args(&command[1..]).status() {
        Ok(status) => status,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(SetupOutcome::Refused(format!(
                "{PKEXEC} is not installed, so sandy cannot ask for root's rights; {FALLBACK}; \
                 to set up without pkexec, run: {sudo}"
            )));
        }
        Err(error) => return Err(SandboxError::io(format!("cannot run {PKEXEC}"), error)),
    };
    outcome(status.code(), &sudo)
}

/// The route for a sandy at `own` whose root-only check gave `own_root_only`; `copy_root_only`
/// is the check of the copy, which for `setup` may still be missing.
fn route(
    own: &Path,
    own_root_only: Result<(), String>,
    remove: bool,
    install_copy: bool,
    copy: &Path,
    copy_root_only: Result<(), String>,
) -> Result<Route, String> {
    let reason = match own_root_only {
        Ok(()) => return Ok(Route::Own(own.to_path_buf())),
        Err(reason) => reason,
    };
    if !install_copy {
        return Err(format!(
            "--elevate runs sandy with root's rights only from a file that only root can \
             change, and {reason}; `sandy setup --elevate --install-copy` installs a root-owned \
             copy of this sandy as {} instead, or install sandy from a package",
            copy.display()
        ));
    }
    match (remove, copy_root_only) {
        (false, Ok(())) => Ok(Route::InstallCopy),
        (true, Ok(())) => Ok(Route::RemoveCopy(copy.to_path_buf())),
        (_, Err(reason)) => Err(format!(
            "root would run the copy {}, but {reason}",
            copy.display()
        )),
    }
}

/// The command that runs `route` with root's rights, asked for by this process, `caller`.
fn command_line(route: &Route, args: &[OsString], caller: u32) -> Vec<OsString> {
    let mut command = vec![OsString::from(PKEXEC)];
    match route {
        Route::Own(own) => {
            command.push(own.into());
            command.extend(args.iter().cloned());
        }
        Route::InstallCopy => command.extend(
            [
                "/bin/sh",
                "-c",
                INSTALL_COPY,
                SCRIPT_NAME,
                &caller.to_string(),
                env!("CARGO_PKG_VERSION"),
            ]
            .map(OsString::from),
        ),
        Route::RemoveCopy(copy) => {
            command.push(copy.into());
            command.extend(["setup", "--remove", "--install-copy"].map(OsString::from));
        }
    }
    command
}

/// What to run instead when pkexec cannot ask: the same step with sudo.
fn sudo_command(route: &Route, own: &Path, args: &[OsString]) -> String {
    let mut words: Vec<OsString> = vec!["sudo".into()];
    match route {
        Route::Own(own) => {
            words.push(own.into());
            words.extend(args.iter().cloned());
        }
        Route::InstallCopy => {
            words.push(own.into());
            words.extend(["setup", "--install-copy"].map(OsString::from));
        }
        Route::RemoveCopy(copy) => {
            words.push(copy.into());
            words.extend(["setup", "--remove", "--install-copy"].map(OsString::from));
        }
    }
    words
        .iter()
        .map(|word| shell_word(word))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `word` as a shell reads it back: as it is when it holds only harmless characters, else in
/// single quotes.
fn shell_word(word: &OsStr) -> String {
    let text = word.to_string_lossy();
    let plain = !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._+-=:,@%".contains(&byte));
    if plain {
        text.into_owned()
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

/// The outcome for pkexec's exit status `code`, `None` for a signal. The elevated sandy writes
/// its own message, so `Done` and its `Refused` carry none.
fn outcome(code: Option<i32>, sudo: &str) -> Result<SetupOutcome, SandboxError> {
    match code {
        Some(0) => Ok(SetupOutcome::Done(String::new())),
        Some(3) => Ok(SetupOutcome::Refused(String::new())),
        Some(DISMISSED) => Ok(SetupOutcome::Refused(format!(
            "the authentication was dismissed; {FALLBACK}; to set up without pkexec, run: {sudo}"
        ))),
        Some(NOT_AUTHORIZED) => Ok(SetupOutcome::Refused(format!(
            "pkexec did not give root's rights: no authentication agent runs for this session, \
             or this user may not have them; {FALLBACK}; to set up without pkexec, run: {sudo}"
        ))),
        Some(code) => Err(SandboxError::new(format!(
            "setup with root's rights ended with status {code}"
        ))),
        None => Err(SandboxError::new(
            "setup with root's rights was ended by a signal",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWN: &str = "/usr/bin/sandy";
    const PORTABLE: &str = "/home/user/tools/sandy";
    const COPY: &str = "/usr/local/libexec/sandy/2.1.0/sandy";

    fn decide(
        own: &str,
        own_root_only: bool,
        remove: bool,
        install_copy: bool,
        copy_root_only: bool,
    ) -> Result<Route, String> {
        let check = |ok: bool| {
            if ok {
                Ok(())
            } else {
                Err("it belongs to user 1000, not to root".to_string())
            }
        };
        route(
            Path::new(own),
            check(own_root_only),
            remove,
            install_copy,
            Path::new(COPY),
            check(copy_root_only),
        )
    }

    #[test]
    fn a_root_owned_sandy_runs_itself() {
        for (remove, install_copy) in [(false, false), (true, false), (false, true), (true, true)] {
            assert_eq!(
                decide(OWN, true, remove, install_copy, false),
                Ok(Route::Own(PathBuf::from(OWN)))
            );
        }
    }

    /// Root never runs the portable file: only the script, then the root-owned copy.
    #[test]
    fn a_portable_sandy_goes_through_the_copy_or_is_refused() {
        assert_eq!(
            decide(PORTABLE, false, false, true, true),
            Ok(Route::InstallCopy)
        );
        assert_eq!(
            decide(PORTABLE, false, true, true, true),
            Ok(Route::RemoveCopy(PathBuf::from(COPY)))
        );
        let refused = decide(PORTABLE, false, false, false, true).unwrap_err();
        assert!(refused.contains("--install-copy"), "{refused}");
        assert!(refused.contains("package"), "{refused}");
        let refused = decide(PORTABLE, false, false, true, false).unwrap_err();
        assert!(refused.contains(COPY), "{refused}");
        assert!(decide(PORTABLE, false, true, true, false).is_err());
    }

    #[test]
    fn the_command_lines_name_only_root_owned_files_and_fixed_text() {
        let args: Vec<OsString> = ["setup", "--policy", "/etc/a b.toml", "--remove"]
            .map(OsString::from)
            .to_vec();
        assert_eq!(
            command_line(&Route::Own(PathBuf::from(OWN)), &args, 42),
            [
                PKEXEC,
                OWN,
                "setup",
                "--policy",
                "/etc/a b.toml",
                "--remove"
            ]
            .map(OsString::from)
        );
        assert_eq!(
            command_line(&Route::InstallCopy, &args, 42),
            [
                PKEXEC,
                "/bin/sh",
                "-c",
                INSTALL_COPY,
                SCRIPT_NAME,
                "42",
                env!("CARGO_PKG_VERSION")
            ]
            .map(OsString::from)
        );
        assert_eq!(
            command_line(&Route::RemoveCopy(PathBuf::from(COPY)), &args, 42),
            [PKEXEC, COPY, "setup", "--remove", "--install-copy"].map(OsString::from)
        );
        // The script installs where setup looks, and uses no tool by its name alone.
        assert!(INSTALL_COPY.contains(setup::COPY_DIRECTORY));
        for line in INSTALL_COPY.lines() {
            for word in line.split_whitespace() {
                for tool in ["mkdir", "rm", "cmp", "cat", "chmod", "mv"] {
                    assert_ne!(word, tool, "{line}");
                }
            }
        }
    }

    #[test]
    fn the_sudo_command_is_quoted_for_a_shell() {
        let args: Vec<OsString> = ["setup", "--policy", "/etc/it's here.toml"]
            .map(OsString::from)
            .to_vec();
        assert_eq!(
            sudo_command(&Route::Own(PathBuf::from(OWN)), Path::new(OWN), &args),
            r"sudo /usr/bin/sandy setup --policy '/etc/it'\''s here.toml'"
        );
        assert_eq!(
            sudo_command(&Route::InstallCopy, Path::new(PORTABLE), &args),
            "sudo /home/user/tools/sandy setup --install-copy"
        );
        assert_eq!(
            sudo_command(
                &Route::RemoveCopy(PathBuf::from(COPY)),
                Path::new(PORTABLE),
                &args
            ),
            format!("sudo {COPY} setup --remove --install-copy")
        );
    }

    /// pkexec passes the elevated sandy's status through, and answers 126 and 127 itself; those
    /// two mean that nothing ran with root's rights.
    #[test]
    fn pkexec_statuses_map_to_setup_statuses() {
        let sudo = "sudo /usr/bin/sandy setup";
        assert_eq!(
            outcome(Some(0), sudo).unwrap(),
            SetupOutcome::Done(String::new())
        );
        assert_eq!(
            outcome(Some(3), sudo).unwrap(),
            SetupOutcome::Refused(String::new())
        );
        for code in [DISMISSED, NOT_AUTHORIZED] {
            match outcome(Some(code), sudo).unwrap() {
                SetupOutcome::Refused(message) => {
                    assert!(message.contains(sudo), "{message}");
                    assert!(message.contains("ip = \"private\""), "{message}");
                }
                other => panic!("{code}: {other:?}"),
            }
        }
        for code in [Some(1), Some(125), Some(2), None] {
            assert!(outcome(code, sudo).is_err(), "{code:?}");
        }
    }
}
