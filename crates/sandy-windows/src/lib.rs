//! Windows backend of sandy.
//!
//! The target runs in an AppContainer and a job object. See `docs/windows.md` for the mechanisms
//! and their limits.
//!
//! The modules below build on every platform, so their unit tests run everywhere. Only `sys`
//! calls the Windows API, and `WindowsBackend` exists only on Windows.

pub mod access;
pub mod cmdline;
pub mod envblock;
pub mod name;
pub mod plan;

#[cfg(windows)]
mod sys;

#[cfg(windows)]
pub use sys::WindowsBackend;
