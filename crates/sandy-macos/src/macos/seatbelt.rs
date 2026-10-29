//! Run-time access to the Seatbelt functions of libsandbox. They are private API, so sandy loads
//! them with dlopen and dlsym: on a macOS without them, `plan` reports the missing symbol
//! instead of sandy failing to start. The signatures follow Chromium's sandbox/mac/seatbelt.cc.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::ptr;

use crate::plan::ProfileError;
use crate::profile::Profile;

const LIBRARY: &CStr = c"/usr/lib/libsandbox.1.dylib";

type InitWithParameters = unsafe extern "C" fn(
    profile: *const c_char,
    flags: u64,
    parameters: *const *const c_char,
    errorbuf: *mut *mut c_char,
) -> c_int;
type FreeError = unsafe extern "C" fn(errorbuf: *mut c_char);
type Check =
    unsafe extern "C" fn(pid: libc::pid_t, operation: *const c_char, filter: c_int, ...) -> c_int;
type CreateParams = unsafe extern "C" fn() -> *mut c_void;
type SetParam =
    unsafe extern "C" fn(params: *mut c_void, key: *const c_char, value: *const c_char) -> c_int;
type FreeParams = unsafe extern "C" fn(params: *mut c_void);
type CompileString = unsafe extern "C" fn(
    profile: *const c_char,
    params: *mut c_void,
    errorbuf: *mut *mut c_char,
) -> *mut c_void;
type FreeProfile = unsafe extern "C" fn(profile: *mut c_void);

#[derive(Debug, Clone, Copy)]
pub struct Seatbelt {
    init_with_parameters: InitWithParameters,
    free_error: FreeError,
    check: Check,
    create_params: CreateParams,
    set_param: SetParam,
    free_params: FreeParams,
    compile_string: CompileString,
    free_profile: FreeProfile,
}

impl Seatbelt {
    /// Loads libsandbox and resolves every function sandy uses, or says which one is missing.
    pub fn load() -> Result<Seatbelt, String> {
        // SAFETY: LIBRARY is a valid C string. sandy never calls dlclose, so the resolved function
        // pointers stay valid for the life of the process. RTLD_GLOBAL lets the RTLD_DEFAULT
        // lookups below search libsandbox as well as libSystem.
        let handle = unsafe { libc::dlopen(LIBRARY.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };
        if handle.is_null() {
            return Err(format!(
                "dlopen({}): {}",
                LIBRARY.to_string_lossy(),
                last_dl_error()
            ));
        }
        // SAFETY: each type alias states the C signature of the symbol of that name, as declared
        // by Chromium's sandbox/mac/seatbelt.cc.
        unsafe {
            Ok(Seatbelt {
                init_with_parameters: symbol(c"sandbox_init_with_parameters")?,
                free_error: symbol(c"sandbox_free_error")?,
                check: symbol(c"sandbox_check")?,
                create_params: symbol(c"sandbox_create_params")?,
                set_param: symbol(c"sandbox_set_param")?,
                free_params: symbol(c"sandbox_free_params")?,
                compile_string: symbol(c"sandbox_compile_string")?,
                free_profile: symbol(c"sandbox_free_profile")?,
            })
        }
    }

    /// Compiles `profile` without applying it, to learn whether this macOS accepts it. Only the
    /// compiler's message is a verdict on the profile; the library's other failures report no
    /// cause and come from running out of memory.
    pub fn compile(&self, profile: &Profile) -> Result<(), ProfileError> {
        let text = profile_text(profile).map_err(ProfileError::Failed)?;
        let strings = parameter_strings(profile).map_err(ProfileError::Failed)?;
        // SAFETY: no arguments.
        let params = unsafe { (self.create_params)() };
        if params.is_null() {
            return Err(ProfileError::Failed(
                "sandbox_create_params failed".to_string(),
            ));
        }
        // Frees `params` before `strings` goes out of scope: the parameter object refers to the
        // strings without copying them.
        let params = Params {
            pointer: params,
            free: self.free_params,
        };
        for pair in strings.chunks(2) {
            // SAFETY: params is a live parameter object; both strings are NUL-terminated and
            // outlive it.
            let result =
                unsafe { (self.set_param)(params.pointer, pair[0].as_ptr(), pair[1].as_ptr()) };
            if result != 0 {
                return Err(ProfileError::Failed(format!(
                    "sandbox_set_param({}) failed",
                    pair[0].to_string_lossy()
                )));
            }
        }
        let mut error: *mut c_char = ptr::null_mut();
        // SAFETY: text is NUL-terminated, params is live, error is a valid out pointer.
        let compiled = unsafe { (self.compile_string)(text.as_ptr(), params.pointer, &mut error) };
        if compiled.is_null() {
            return Err(match self.message(error) {
                Some(message) => ProfileError::Rejected(message),
                None => ProfileError::Failed(
                    "sandbox_compile_string failed without a message".to_string(),
                ),
            });
        }
        // SAFETY: compiled came from sandbox_compile_string and is freed once.
        unsafe { (self.free_profile)(compiled) };
        Ok(())
    }

    /// Applies `profile` to the current process. The sandbox cannot be removed afterwards and
    /// every process the current one starts inherits it.
    pub fn apply(&self, profile: &Profile) -> Result<(), String> {
        let text = profile_text(profile)?;
        let strings = parameter_strings(profile)?;
        let mut pointers: Vec<*const c_char> = strings.iter().map(|s| s.as_ptr()).collect();
        pointers.push(ptr::null());
        let mut error: *mut c_char = ptr::null_mut();
        // SAFETY: text and every parameter string are NUL-terminated and outlive the call; the
        // array alternates names and values and ends with NULL, as the function requires. Flags 0
        // means that text is profile source, not the name of a built-in profile.
        let result =
            unsafe { (self.init_with_parameters)(text.as_ptr(), 0, pointers.as_ptr(), &mut error) };
        if result != 0 {
            return Err(self.take_error(error, "sandbox_init_with_parameters failed"));
        }
        if !self.is_sandboxed() {
            return Err(
                "sandbox_init_with_parameters reported success, but sandbox_check says the \
                 process is not sandboxed"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Whether the current process runs in a Seatbelt sandbox.
    pub fn is_sandboxed(&self) -> bool {
        // SAFETY: a null operation asks only whether the process is sandboxed; no variadic
        // arguments follow for filter type 0 (SANDBOX_FILTER_NONE).
        unsafe { (self.check)(libc::getpid(), ptr::null(), 0) == 1 }
    }

    fn take_error(&self, error: *mut c_char, fallback: &str) -> String {
        self.message(error).unwrap_or_else(|| fallback.to_string())
    }

    /// The message the library left in `error`, which it frees; `None` when it left none.
    fn message(&self, error: *mut c_char) -> Option<String> {
        if error.is_null() {
            return None;
        }
        // SAFETY: the sandbox library sets error to a NUL-terminated string that the caller
        // frees with sandbox_free_error, exactly once.
        unsafe {
            let message = CStr::from_ptr(error).to_string_lossy().into_owned();
            (self.free_error)(error);
            Some(message)
        }
    }
}

struct Params {
    pointer: *mut c_void,
    free: FreeParams,
}

impl Drop for Params {
    fn drop(&mut self) {
        // SAFETY: pointer came from sandbox_create_params and is freed once.
        unsafe { (self.free)(self.pointer) };
    }
}

/// Resolves `name` in libsandbox or libSystem.
///
/// # Safety
///
/// `F` must be an `extern "C"` function pointer type that matches the C signature of `name`.
unsafe fn symbol<F: Copy>(name: &CStr) -> Result<F, String> {
    assert_eq!(size_of::<F>(), size_of::<*mut c_void>());
    // SAFETY: name is a valid C string.
    let pointer = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    if pointer.is_null() {
        return Err(format!(
            "dlsym({}): {}",
            name.to_string_lossy(),
            last_dl_error()
        ));
    }
    // SAFETY: pointer is the non-null address of `name`, and the caller guarantees that F is a
    // function pointer type with its signature. Both have the size of a pointer (checked above).
    Ok(unsafe { std::mem::transmute_copy::<*mut c_void, F>(&pointer) })
}

fn last_dl_error() -> String {
    // SAFETY: dlerror returns null or a NUL-terminated string that stays valid until the next
    // dl* call on this thread; it is copied at once.
    let error = unsafe { libc::dlerror() };
    if error.is_null() {
        "unknown error".to_string()
    } else {
        // SAFETY: see above.
        unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned()
    }
}

fn profile_text(profile: &Profile) -> Result<CString, String> {
    CString::new(profile.text.as_str()).map_err(|_| "the profile contains a NUL byte".to_string())
}

/// Names and values, alternating, as C strings.
fn parameter_strings(profile: &Profile) -> Result<Vec<CString>, String> {
    let mut strings = Vec::with_capacity(profile.parameters.len() * 2);
    for (name, value) in &profile.parameters {
        strings.push(
            CString::new(name.as_str())
                .map_err(|_| format!("parameter name {name:?} contains NUL"))?,
        );
        strings.push(
            CString::new(value.as_os_str().as_bytes())
                .map_err(|_| format!("path {} contains a NUL byte", value.display()))?,
        );
    }
    Ok(strings)
}
