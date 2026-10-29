//! Test helper: runs a program that sees a lower Landlock ABI than the kernel has, so the tests
//! can exercise the code paths of an older kernel on this one.
//!
//! Usage: `sandy-abi-cap ABI PROGRAM [ARGUMENT]...`
//!
//! A seccomp filter notifies this process for the one call that asks for the ABI,
//! `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`, and lets every other
//! call through unchanged. The answer is the capped version. A filter is inherited, so the
//! program, everything it starts and sandy inside it see the same cap:
//! `sandy-abi-cap 2 cargo test` runs a whole suite against the ABI 1 and 2 code paths.
//!
//! The kernel is not changed. sandy then handles only the rights of the capped version, and that
//! is what brings the older behaviour back: under cap 1 a rename between directories fails with
//! `EXDEV`, and under caps 1 and 2 `truncate` fails with `EPERM` from sandy's seccomp rules
//! instead of `EACCES` from Landlock. What it cannot bring back is a kernel without an errata
//! fix, or an older system call table, so a real old kernel is still the only way to see those.
//!
//! It sets `PR_SET_NO_NEW_PRIVS` on itself, which the program inherits: a check that needs a
//! setuid program outside the sandbox cannot run under the cap.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let abi = arguments.next().and_then(|abi| abi.parse::<i64>().ok());
    let program = arguments.next();
    let (Some(abi), Some(program)) = (abi, program) else {
        eprintln!("usage: sandy-abi-cap ABI PROGRAM [ARGUMENT]...");
        return ExitCode::from(2);
    };
    match cap::run(abi, &program, arguments.collect()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("sandy-abi-cap: {error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(target_os = "linux")]
mod cap {
    use std::io;
    use std::mem::{offset_of, size_of};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::process::{Command, ExitCode};

    /// `LANDLOCK_CREATE_RULESET_VERSION`: the flag of the call that only reports the ABI.
    const VERSION: u32 = 1;
    /// The `_IOC` type of the seccomp notification requests, `'!'`.
    const SECCOMP_IOC: u32 = 0x21;
    /// How long the supervisor waits for a notification before it looks at the program again.
    const POLL_MILLIS: libc::c_int = 100;

    pub fn run(abi: i64, program: &str, arguments: Vec<String>) -> io::Result<ExitCode> {
        let listener = install_filter()?;
        let mut child = Command::new(program).args(arguments).spawn()?;
        let sizes = notification_sizes()?;
        // The kernel reports the size of its own structures, which the request numbers carry.
        let receive = request(0, sizes.seccomp_notif);
        let send = request(1, sizes.seccomp_notif_resp);
        let mut notification = Buffer::new(sizes.seccomp_notif);
        let mut response = Buffer::new(sizes.seccomp_notif_resp);
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(ExitCode::from(exit_code(status)));
            }
            if !waits(&listener) {
                continue;
            }
            let notification = notification.get::<libc::seccomp_notif>();
            // SAFETY: the buffer has the size the kernel reported for this request.
            if unsafe { libc::ioctl(listener.as_raw_fd(), receive, notification) } < 0 {
                // The caller was killed or its call was interrupted before it could be answered.
                continue;
            }
            // SAFETY: the ioctl filled the structure.
            let (id, call) = unsafe { ((*notification).id, (*notification).data.args) };
            let response = response.get::<libc::seccomp_notif_resp>();
            // SAFETY: the buffer is at least as large as the structure and is zeroed.
            unsafe {
                (*response).id = id;
                // The filter passes only the version flag, and the query takes no attribute.
                if call[0] == 0 && call[1] == 0 {
                    (*response).val = abi;
                } else {
                    (*response).flags = libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32;
                }
                libc::ioctl(listener.as_raw_fd(), send, response);
            }
        }
    }

    /// A filter that notifies this process for the ABI query and allows everything else.
    fn install_filter() -> io::Result<OwnedFd> {
        let version_flag = (offset_of!(libc::seccomp_data, args) + 2 * size_of::<u64>()) as u32;
        let mut filter = [
            load(offset_of!(libc::seccomp_data, nr) as u32),
            equals(libc::SYS_landlock_create_ruleset as u32, 0, 3),
            load(version_flag),
            equals(VERSION, 0, 1),
            ret(libc::SECCOMP_RET_USER_NOTIF),
            ret(libc::SECCOMP_RET_ALLOW),
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: prctl takes values, and the filter program outlives the call that installs it.
        let listener = unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
                &program as *const libc::sock_fprog,
            )
        };
        if listener < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: seccomp returned a new descriptor that this process owns.
        Ok(unsafe { OwnedFd::from_raw_fd(listener as libc::c_int) })
    }

    fn notification_sizes() -> io::Result<libc::seccomp_notif_sizes> {
        let mut sizes = libc::seccomp_notif_sizes {
            seccomp_notif: 0,
            seccomp_notif_resp: 0,
            seccomp_data: 0,
        };
        // SAFETY: the kernel writes the three sizes into the structure.
        let read = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_GET_NOTIF_SIZES,
                0,
                &mut sizes as *mut libc::seccomp_notif_sizes,
            )
        };
        if read < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(sizes)
    }

    /// Whether a notification is waiting. A short wait, so the supervisor also notices when the
    /// program has ended.
    fn waits(listener: &OwnedFd) -> bool {
        let mut watched = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll reads and writes the one structure passed.
        unsafe { libc::poll(&mut watched, 1, POLL_MILLIS) > 0 }
    }

    /// A buffer for one of the kernel's notification structures. The kernel may use a larger
    /// structure than this build knows, so the size comes from the kernel; the 64-bit elements
    /// keep the buffer aligned for the fields.
    struct Buffer(Vec<u64>);

    impl Buffer {
        fn new(size: u16) -> Buffer {
            Buffer(vec![0; usize::from(size).div_ceil(size_of::<u64>())])
        }

        /// The zeroed buffer as the structure the ioctl expects.
        fn get<T>(&mut self) -> *mut T {
            self.0.fill(0);
            self.0.as_mut_ptr().cast()
        }
    }

    /// A `SECCOMP_IOWR(number, structure)` request number, as linux/seccomp.h builds it: both
    /// the request and the response ioctl read and write their structure. The type of an ioctl
    /// request differs between the C libraries, so the cast is the last step.
    fn request(number: u32, size: u16) -> libc::Ioctl {
        const READ_WRITE: u32 = 3;
        (READ_WRITE << 30 | u32::from(size) << 16 | SECCOMP_IOC << 8 | number) as libc::Ioctl
    }

    fn load(offset: u32) -> libc::sock_filter {
        statement((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, offset)
    }

    fn ret(value: u32) -> libc::sock_filter {
        statement((libc::BPF_RET | libc::BPF_K) as u16, value)
    }

    /// Continues with the next instruction when the loaded word is `value`, and jumps `otherwise`
    /// instructions ahead when it is not.
    fn equals(value: u32, then: u8, otherwise: u8) -> libc::sock_filter {
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: then,
            jf: otherwise,
            k: value,
        }
    }

    fn statement(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    fn exit_code(status: std::process::ExitStatus) -> u8 {
        use std::os::unix::process::ExitStatusExt;
        match (status.code(), status.signal()) {
            (Some(code), _) => code as u8,
            (None, Some(signal)) => 128 + signal as u8,
            (None, None) => 1,
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod cap {
    use std::io;
    use std::process::ExitCode;

    pub fn run(_abi: i64, _program: &str, _arguments: Vec<String>) -> io::Result<ExitCode> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the Landlock ABI cap works only on Linux",
        ))
    }
}
