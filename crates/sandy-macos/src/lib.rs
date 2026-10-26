//! macOS backend of sandy: a Seatbelt profile generated from the policy, applied in-process with
//! `sandbox_init_with_parameters`, after which the target replaces sandy. `docs/macos.md`
//! describes the mechanisms.
//!
//! Profile generation and planning are pure and build on every platform, so their unit tests run
//! everywhere. Only the code that calls macOS is limited to macOS.

pub mod binary;
pub mod detect;
pub mod plan;
pub mod profile;
pub mod system;
pub mod trust;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::MacosBackend;
