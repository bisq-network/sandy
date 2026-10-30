//! Native application executable used by the macOS LaunchServices escape tests.

use std::fs;
use std::io;

fn main() -> io::Result<()> {
    let executable = std::env::current_exe()?;
    let app = executable
        .parent()
        .and_then(|path| path.parent())
        .and_then(|path| path.parent())
        .ok_or_else(|| io::Error::other("marker executable is not inside an app bundle"))?;
    let name = app
        .file_stem()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("Sandy"))
        .and_then(|name| name.strip_suffix("Marker"))
        .ok_or_else(|| io::Error::other("unexpected marker app name"))?
        .to_ascii_lowercase();
    fs::write(
        app.parent().unwrap_or(app).join(format!("{name}-marker")),
        [],
    )
}
