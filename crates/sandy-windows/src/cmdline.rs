//! The command line of the target.
//!
//! Windows passes a process one string. The C runtime of the target splits it into arguments with
//! the rules of `CommandLineToArgvW`. This module quotes each argument so that the target receives
//! exactly the arguments sandy was given. Strings are UTF-16 code units, as in the Windows API.

use std::fmt;
use std::path::Path;

/// `CreateProcessW` accepts at most this many UTF-16 units, including the terminating NUL.
pub const MAX_COMMAND_LINE: usize = 32_767;

const NUL: u16 = 0;
const TAB: u16 = b'\t' as u16;
const LF: u16 = b'\n' as u16;
const VT: u16 = 0x0B;
const SPACE: u16 = b' ' as u16;
const QUOTE: u16 = b'"' as u16;
const BACKSLASH: u16 = b'\\' as u16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandLineError {
    /// File names cannot contain `"`, and the first token of a command line has no escape.
    ProgramContainsQuote,
    ContainsNul,
    TooLong,
}

impl fmt::Display for CommandLineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CommandLineError::ProgramContainsQuote => "the program path contains a double quote",
            CommandLineError::ContainsNul => "an argument contains a NUL character",
            CommandLineError::TooLong => "the command line is longer than 32767 characters",
        })
    }
}

impl std::error::Error for CommandLineError {}

/// Builds the NUL-terminated command line for `CreateProcessW`.
pub fn command_line(program: &[u16], args: &[Vec<u16>]) -> Result<Vec<u16>, CommandLineError> {
    if program.contains(&QUOTE) {
        return Err(CommandLineError::ProgramContainsQuote);
    }
    if program.contains(&NUL) || args.iter().any(|arg| arg.contains(&NUL)) {
        return Err(CommandLineError::ContainsNul);
    }
    // The first token ends at the next quote and knows no escapes, so it is always quoted.
    let mut line = Vec::with_capacity(program.len() + 2);
    line.push(QUOTE);
    line.extend_from_slice(program);
    line.push(QUOTE);
    for arg in args {
        line.push(SPACE);
        push_quoted(&mut line, arg);
    }
    line.push(NUL);
    if line.len() > MAX_COMMAND_LINE {
        return Err(CommandLineError::TooLong);
    }
    Ok(line)
}

/// Appends `arg` so that `CommandLineToArgvW` and the Microsoft C runtime read it back unchanged.
/// Backslashes are literal unless they precede a quote; then each one must be doubled.
fn push_quoted(line: &mut Vec<u16>, arg: &[u16]) {
    let plain = !arg.is_empty()
        && !arg
            .iter()
            .any(|&unit| matches!(unit, SPACE | TAB | LF | VT | QUOTE));
    if plain {
        line.extend_from_slice(arg);
        return;
    }
    line.push(QUOTE);
    let mut backslashes = 0;
    for &unit in arg {
        if unit == BACKSLASH {
            backslashes += 1;
            continue;
        }
        let escaped = if unit == QUOTE {
            2 * backslashes + 1
        } else {
            backslashes
        };
        line.extend(std::iter::repeat_n(BACKSLASH, escaped));
        line.push(unit);
        backslashes = 0;
    }
    line.extend(std::iter::repeat_n(BACKSLASH, 2 * backslashes));
    line.push(QUOTE);
}

/// `CreateProcessW` starts `cmd.exe` for `.bat` and `.cmd` files, and `cmd.exe` parses the command
/// line with other rules. Arguments could then run commands. sandy refuses such programs; a
/// policy can run `cmd.exe` explicitly instead.
pub fn is_batch_file(program: &Path) -> bool {
    program.extension().is_some_and(|extension| {
        extension.eq_ignore_ascii_case("bat") || extension.eq_ignore_ascii_case("cmd")
    })
}

/// `std::fs::canonicalize` returns verbatim paths (`\\?\C:\dir\file`). The target sees the path
/// as its own name, and programs expect the ordinary form. This returns the ordinary form when it
/// names the same file, and the verbatim path otherwise: Windows normalizes ordinary paths
/// (trailing dots and spaces, device names, the `MAX_PATH` limit), and verbatim paths skip that.
pub fn without_verbatim_prefix(path: &[u16]) -> &[u16] {
    const MAX_PATH: usize = 260;
    let Some(rest) = path.strip_prefix(&[BACKSLASH, BACKSLASH, b'?' as u16, BACKSLASH]) else {
        return path;
    };
    let is_drive_path = rest.len() >= 3
        && char::from_u32(u32::from(rest[0])).is_some_and(|c| c.is_ascii_alphabetic())
        && rest[1] == b':' as u16
        && rest[2] == BACKSLASH;
    let ordinary = is_drive_path
        && rest.len() < MAX_PATH
        && !rest.contains(&(b'/' as u16))
        && rest[3..]
            .split(|&unit| unit == BACKSLASH)
            .all(plain_component);
    if ordinary { rest } else { path }
}

/// A path component that Win32 path normalization leaves unchanged.
fn plain_component(component: &[u16]) -> bool {
    const DEVICES: [&str; 6] = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];
    let Ok(text) = String::from_utf16(component) else {
        return false;
    };
    let stem = text.split('.').next().unwrap_or("").trim_end();
    let numbered_device = stem.len() == 4
        && stem.is_ascii()
        && (stem[..3].eq_ignore_ascii_case("COM") || stem[..3].eq_ignore_ascii_case("LPT"))
        && stem.as_bytes()[3].is_ascii_digit();
    !text.is_empty()
        && !text.ends_with(['.', ' '])
        && !DEVICES
            .iter()
            .any(|device| stem.eq_ignore_ascii_case(device))
        && !numbered_device
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn simplified(path: &str) -> String {
        String::from_utf16(without_verbatim_prefix(&wide(path))).unwrap()
    }

    #[test]
    fn removes_the_verbatim_prefix_when_safe() {
        assert_eq!(
            simplified(r"\\?\C:\Program Files\app.exe"),
            r"C:\Program Files\app.exe"
        );
        assert_eq!(simplified(r"C:\a.exe"), r"C:\a.exe");
        assert_eq!(simplified(r"\\?\C:\a€\b.exe"), r"C:\a€\b.exe");
    }

    #[test]
    fn keeps_the_verbatim_prefix_when_the_meaning_would_change() {
        for path in [
            r"\\?\UNC\server\share\a.exe",
            r"\\?\Volume{0b1c}\a.exe",
            r"\\?\C:\dir.\a.exe",
            r"\\?\C:\dir \a.exe",
            r"\\?\C:\nul.txt\a.exe",
            r"\\?\C:\x\COM1.exe",
            r"\\?\C:\x\..\a.exe",
            r"\\?\C:\x\\a.exe",
            r"\\?\C:\x/y.exe",
        ] {
            assert_eq!(simplified(path), path);
        }
        let long = format!(r"\\?\C:\{}.exe", "x".repeat(260));
        assert_eq!(simplified(&long), long);
    }

    /// The parser of `CommandLineToArgvW` and the Microsoft C runtime, written from the rules in
    /// "Parsing C command-line arguments" (Microsoft Learn).
    fn parse(line: &[u16]) -> Vec<Vec<u16>> {
        let line = line.strip_suffix(&[NUL]).expect("NUL-terminated");
        let mut i = 0;
        let mut program = Vec::new();
        if line.first() == Some(&QUOTE) {
            i = 1;
            while i < line.len() && line[i] != QUOTE {
                program.push(line[i]);
                i += 1;
            }
            i += 1;
        } else {
            while i < line.len() && line[i] != SPACE && line[i] != TAB {
                program.push(line[i]);
                i += 1;
            }
        }
        let mut argv = vec![program];
        loop {
            while i < line.len() && (line[i] == SPACE || line[i] == TAB) {
                i += 1;
            }
            if i >= line.len() {
                return argv;
            }
            let mut arg = Vec::new();
            let mut quoted = false;
            while i < line.len() {
                let unit = line[i];
                if !quoted && (unit == SPACE || unit == TAB) {
                    break;
                }
                if unit == BACKSLASH {
                    let start = i;
                    while i < line.len() && line[i] == BACKSLASH {
                        i += 1;
                    }
                    let count = i - start;
                    if line.get(i) == Some(&QUOTE) {
                        arg.extend(std::iter::repeat_n(BACKSLASH, count / 2));
                        if count % 2 == 1 {
                            arg.push(QUOTE);
                            i += 1;
                        }
                    } else {
                        arg.extend(std::iter::repeat_n(BACKSLASH, count));
                    }
                    continue;
                }
                if unit == QUOTE {
                    if quoted && line.get(i + 1) == Some(&QUOTE) {
                        arg.push(QUOTE);
                        i += 2;
                    } else {
                        quoted = !quoted;
                        i += 1;
                    }
                    continue;
                }
                arg.push(unit);
                i += 1;
            }
            argv.push(arg);
        }
    }

    fn round_trip(args: &[Vec<u16>]) {
        let program = wide(r"C:\Program Files\app\app.exe");
        let line = command_line(&program, args).unwrap();
        let parsed = parse(&line);
        assert_eq!(parsed[0], program);
        assert_eq!(
            &parsed[1..],
            args,
            "line {:?}",
            String::from_utf16_lossy(&line)
        );
    }

    #[test]
    fn plain_arguments_stay_unquoted() {
        let line = command_line(&wide(r"C:\a.exe"), &[wide("-x"), wide(r"C:\dir\")]).unwrap();
        assert_eq!(
            String::from_utf16(&line).unwrap(),
            "\"C:\\a.exe\" -x C:\\dir\\\0"
        );
    }

    #[test]
    fn adversarial_arguments_survive() {
        let cases = [
            "",
            " ",
            "\t",
            "\"",
            "\"\"",
            "\\",
            "\\\\",
            "a\\",
            "a b\\",
            "a b\\\\",
            "\\\"",
            "\\\\\"",
            "a\\\"b",
            "a\\\\\"b c",
            "\" & calc.exe & \"",
            "%PATH%",
            "^&|<>()",
            "\\\\server\\share\\",
            "x\ny",
            "x\u{0B}y",
            "ünïcödé",
            "emoji 😀",
            "end with quote\"",
            "-flag=\"value with space\"",
        ];
        for case in cases {
            round_trip(&[wide(case)]);
        }
        let all: Vec<Vec<u16>> = cases.iter().map(|case| wide(case)).collect();
        round_trip(&all);
    }

    #[test]
    fn every_short_argument_survives() {
        let alphabet = [b'a' as u16, SPACE, TAB, QUOTE, BACKSLASH, 0x00E9];
        let mut arg = Vec::new();
        fn visit(alphabet: &[u16], arg: &mut Vec<u16>, depth: usize) {
            round_trip(&[arg.clone(), arg.clone()]);
            if depth == 0 {
                return;
            }
            for &unit in alphabet {
                arg.push(unit);
                visit(alphabet, arg, depth - 1);
                arg.pop();
            }
        }
        visit(&alphabet, &mut arg, 5);
    }

    #[test]
    fn unpaired_surrogates_pass_through() {
        round_trip(&[vec![0xD800, SPACE, 0xDC00]]);
    }

    #[test]
    fn rejects_quote_in_program() {
        assert_eq!(
            command_line(&wide("C:\\a\".exe"), &[]),
            Err(CommandLineError::ProgramContainsQuote)
        );
    }

    #[test]
    fn rejects_nul() {
        assert_eq!(
            command_line(&wide("C:\\a.exe"), &[vec![b'a' as u16, NUL]]),
            Err(CommandLineError::ContainsNul)
        );
        assert_eq!(
            command_line(&[b'a' as u16, NUL], &[]),
            Err(CommandLineError::ContainsNul)
        );
    }

    #[test]
    fn enforces_the_length_limit() {
        let program = wide("C:\\a.exe");
        let fixed = program.len() + 2 + 1 + 1;
        let fits = vec![b'x' as u16; MAX_COMMAND_LINE - fixed];
        assert_eq!(
            command_line(&program, std::slice::from_ref(&fits))
                .unwrap()
                .len(),
            MAX_COMMAND_LINE
        );
        let too_long = vec![b'x' as u16; MAX_COMMAND_LINE - fixed + 1];
        assert_eq!(
            command_line(&program, &[too_long]),
            Err(CommandLineError::TooLong)
        );
    }

    #[test]
    fn detects_batch_files() {
        assert!(is_batch_file(Path::new("C:/x/run.bat")));
        assert!(is_batch_file(Path::new("C:/x/RUN.CMD")));
        assert!(!is_batch_file(Path::new("C:/x/run.exe")));
        assert!(!is_batch_file(Path::new("C:/x/bat")));
    }
}
