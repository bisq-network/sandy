//! Unit tests that fork and let the child allocate or start threads run in a process of their
//! own. libtest runs tests on many threads of one process, and a child that `fork` makes from one
//! of them inherits every lock another thread held at that moment, with no thread left to release
//! it: a child that takes such a lock, a mutex of the standard library for example, waits for
//! ever. That hung about 1 in 100 runs of this test binary. A forking test calls `in_own_process`
//! first and returns when it says no: the test then ran again, alone, in a new process of this
//! binary, where libtest's main thread only waits for it.

use std::process::Command;

/// Holds the name of the test that a new process runs, so that the test goes on there instead of
/// starting yet another process.
const TEST: &str = "SANDY_TEST_OWN_PROCESS";

/// Whether the calling test runs in a process of its own. If it does not, this runs it in one,
/// fails when it fails there, and returns false, and the caller returns at once.
pub(crate) fn in_own_process() -> bool {
    let name = std::thread::current()
        .name()
        .expect("libtest names the thread of each test after the test")
        .to_string();
    if std::env::var_os(TEST).is_some_and(|test| test == name.as_str()) {
        return true;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args([&name, "--exact", "--test-threads=1", "--nocapture"])
        .env(TEST, &name)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // What the test wrote, such as a skip, reaches libtest's capture here, as it would have
    // without the new process.
    eprint!("{stderr}");
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "{name} failed in a process of its own:\n{stdout}{stderr}"
    );
    false
}
