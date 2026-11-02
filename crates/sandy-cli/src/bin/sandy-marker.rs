//! Executable of the application bundles that the macOS LaunchServices escape tests start.
//!
//! It creates the file whose path the bundle names in `Contents/Resources/marker` and exits. A
//! native executable rather than a script, because a bundle with a script executable did not
//! start on some Apple silicon hosts.

use std::fs;
use std::io;

fn main() -> io::Result<()> {
    let executable = std::env::current_exe()?;
    // The executable is at Contents/MacOS/marker.
    let contents = executable
        .parent()
        .and_then(|path| path.parent())
        .ok_or_else(|| io::Error::other("the marker executable is not inside an app bundle"))?;
    let marker = fs::read_to_string(contents.join("Resources/marker"))?;
    fs::write(marker, b"")
}
