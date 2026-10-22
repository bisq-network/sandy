//! `process.children = "none"`: the program cannot start other processes.

mod common;

use common::*;

#[test]
fn children_none_denies_starting_programs() {
    #[cfg(windows)]
    if appcontainer_children_blocked() {
        return;
    }
    let fixture = Fixture::new("children");
    let program = fixture.copy_probe("bin");

    // Control: the same policy without the option starts the program.
    let lines = probe_inside(&fixture.access_args(), &[("exec", &program)]);
    lines[0].assert_ok();

    let mut args = fixture.access_args();
    args.extend(["--children".to_string(), "none".to_string()]);
    let lines = probe_inside(&args, &[("exec", &program)]);
    lines[0].assert_blocked();
}
