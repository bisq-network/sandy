# Windows backend

sandy runs the program in an AppContainer and in a job object. An AppContainer is the sandbox of
Windows Store apps: the process gets a token with an AppContainer SID, runs at low integrity, and
every access check also has to grant access to that SID or to one of its capabilities. Microsoft
treats the AppContainer as a security boundary that it services with security updates [MSRC].

Status: the code builds for `x86_64-pc-windows-msvc` and `x86_64-pc-windows-gnu`, and its
platform-independent parts are unit-tested. **Nothing has run on a real Windows host yet.** Wine
does not implement AppContainers, so Wine runs prove nothing about isolation. Statements below
that depend on Windows behavior come from the cited sources; the escape tests in
`crates/sandy-cli/tests/escape_windows.rs` check them once they run on Windows.

## Requirements and mechanisms

| Requirement | Mechanism | Unavailable when |
|---|---|---|
| `FilesystemConfined` | One capability per policy path, with an access control entry (ACE) on the path | `system = "none"` |
| `MetadataConfined` | No `WRITE_DAC`, `WRITE_OWNER`, `FILE_WRITE_ATTRIBUTES` or `FILE_WRITE_EA` outside read-write paths | never |
| `NoPrivilegeEscalation` | AppContainer token, inherited by every child; job object without breakaway | no AppContainer |
| `ProcessMemoryIsolated` | Processes outside the AppContainer grant its SID no access | no AppContainer |
| `InheritedHandlesClosed` | `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` with the three standard handles | never |
| `EnvironmentControlled` | Environment block built from the policy, plus `SystemRoot` | never |
| `IpNetworkDenied` | No network capabilities, no loopback exemption | AppContainer exempt from loopback isolation; firewall service not running |
| `UnixSocketsDenied` | No write access to any socket file | the policy has read-write paths |
| `SignalsIsolated` | Own console; AppContainer access checks; job UI restrictions | no AppContainer |

Every requirement also needs `windows.appcontainer_name` (or `--appcontainer NAME`). Without it,
or with an invalid name, the plan reports the requirements that need the AppContainer as
unavailable. A name has at most 64 characters from `A-Z a-z 0-9 - _ .` and space
[CreateAppContainerProfile].

## The AppContainer

`sandy run` creates the AppContainer profile of the name for the current user on first use, with
`CreateAppContainerProfile`. If the profile exists, sandy derives its SID with
`DeriveAppContainerSidFromAppContainerName`. Microsoft documents a profile as the precondition for
creating a process in an AppContainer [Legacy apps], and Chromium's sandbox notes that process
creation fails without one [Chromium policy].

The profile creates a folder for the AppContainer below `%LOCALAPPDATA%\Packages\<name>`. The
program can read, write and execute files there. The folder belongs to this AppContainer name
only and keeps its content between runs.

### What every AppContainer can read (the system set)

Windows grants read and execute access on `C:\Windows`, `C:\Program Files` and many registry
keys to the group ALL APPLICATION PACKAGES (`S-1-15-2-1`). Every AppContainer is a member.
`system = "minimal"` on Windows is this set. Windows defines it; sandy cannot shrink it. It
contains no user profile data in a default installation, but software can grant this group
access anywhere.

`system = "none"` is unavailable. A Less Privileged AppContainer (LPAC,
`PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY`) drops ALL APPLICATION PACKAGES, but
`C:\Windows` and `C:\Program Files` also grant read and execute to ALL RESTRICTED APPLICATION
PACKAGES (`S-1-15-2-2`) [STIG], which LPAC processes keep. sandy does not use LPAC: it would not
make `system = "none"` possible, and ordinary programs need extra capabilities under LPAC; for
example `cmd.exe` needs `lpacCom` and `registryRead` [LaunchAppContainer].

## File grants

### What sandy grants

| Level | Rights | Never contains |
|---|---|---|
| read | `FILE_GENERIC_READ` (read data, list, attributes, extended attributes, permissions) | `FILE_EXECUTE`, any write right |
| read-exec | `FILE_GENERIC_READ`, `FILE_GENERIC_EXECUTE` | any write right |
| read-write | `FILE_GENERIC_READ`, `FILE_GENERIC_WRITE`, `DELETE`, `FILE_DELETE_CHILD` | `FILE_EXECUTE`, `WRITE_DAC`, `WRITE_OWNER` |

On a directory the ACE has the flags object inherit and container inherit, so files and
directories below it receive the same rights. The program file gets read and execute.

Without `FILE_EXECUTE`, Windows does not load a file as a program or library. The program can
still read the bytes of a file; this backend, like the others, does not prevent code that the
program maps into its own memory.

The AppContainer access check grants no implicit owner rights in its second pass [Forshaw
access check]. The program therefore cannot change the DACL of files it creates, although the
user's SID owns them. The escape test `read_write_paths_are_not_executable` checks this.

AppContainer processes run at low integrity, and files without a label count as medium. sandy
sets no integrity label: the AppContainer access check ignores the integrity level of objects at
medium and below [Forshaw 2014], and Chromium's network sandbox writes to unlabeled directories
with a capability ACE alone [Chromium network]. If writes in read-write paths fail on Windows,
this assumption is wrong.

### One capability per path

sandy does not grant access to the AppContainer SID. For every policy path it derives a
capability SID (`S-1-15-3-1024-...`, `DeriveCapabilitySidsFromName`) from the name

```text
sandy.grant.<r|rx|rw>.<volume serial>.<file ID>.<AppContainer name>
```

adds one ACE for that SID, and starts the program with the capabilities of the current policy
only. Chromium grants its install directory to capability SIDs in the same way [Chromium
install]. The file ID names the object, not the path: a renamed directory keeps its grant, and a
new object at the old path needs a new one.

The consequences:

- **Grants stay on disk.** sandy never removes them. A run checks for its ACE and changes nothing
  when the ACE exists.
- **Old grants grant nothing.** When a path leaves the policy, or its level changes, no later
  process holds the old capability. The escape test
  `a_path_removed_from_the_policy_is_denied_at_the_next_run` checks this.
- **Concurrent runs do not conflict.** No run removes an ACE that another run needs. Adding an
  ACE means reading the DACL, adding the entry and writing the whole DACL back, so sandy holds a
  named mutex of the logon session (`Local\sandy-dacl-changes`) while it changes a DACL.
  Without it, two runs that add different ACEs to the same object, such as one program in two
  AppContainers, could overwrite each other's ACE. The program cannot hold this mutex, because
  an AppContainer has its own `Local\` namespace. Changes by other tools, such as `icacls`,
  are not serialized.
- **System paths need no change.** If the DACL of a path already grants the level to ALL
  APPLICATION PACKAGES, for example `C:\Windows\System32\cmd.exe`, sandy adds nothing. Users
  usually cannot change these DACLs.

### How sandy changes a DACL

sandy reads the DACL with `GetNamedSecurityInfoW`, merges its ACE with `SetEntriesInAclW`, and
writes it with `SetNamedSecurityInfoW`. It passes `PROTECTED_DACL_SECURITY_INFORMATION` or
`UNPROTECTED_DACL_SECURITY_INFORMATION` according to the current DACL, because without one of
them the protection of the DACL can get lost [Kanthak]. For a directory, Windows then copies the
inheritable ACE to every existing child, except children with a protected DACL
[SetNamedSecurityInfoW]. Those children stay inaccessible to the program.

Microsoft does not document whether this propagation follows junctions and symbolic links. A
program that could write below a directory in an earlier run could have planted a link to a
directory of the user. Before sandy adds an inheritable ACE, it therefore walks the directory and
refuses the run if it finds a junction or symbolic link (`is_symlink` covers every name-surrogate
reparse point). Hard links cannot be found this way; creating one needs write access to the
target, which the AppContainer lacks outside its paths.

A path whose DACL the user cannot change makes `sandy run` fail with an error that names the
path, unless Windows already grants the level to all AppContainers. A path without DACL (NULL
DACL, everyone has full access) also makes the run fail; adding an ACE would take the user's
access away.

### Removing the changes

Old grants grant nothing, so removing them is cleanup, not a security step.

- File grants: `icacls PATH` lists the grants as `*S-1-15-3-1024-...`. `icacls PATH /remove:g
  *SID` removes one. The SID cannot be mapped back to its name, and other software (for example
  Chromium) also uses capability SIDs, so remove only SIDs you know belong to sandy.
- The AppContainer profile and its folder: `DeleteAppContainerProfile`, for example from
  PowerShell:

  ```powershell
  Add-Type -Namespace Win32 -Name UserEnv -MemberDefinition '[DllImport("userenv.dll", CharSet = CharSet.Unicode)] public static extern int DeleteAppContainerProfile(string name);'
  [Win32.UserEnv]::DeleteAppContainerProfile("example.app")
  ```
- The loopback exemption: see below.

Proposed CLI change: `sandy setup --remove` with a policy could compute the capability SIDs of
its paths, remove those ACEs, the loopback exemption and the profile.

## Network

With `ip = "none"` the program gets no network capabilities. With `ip = "all"` it gets
`internetClientServer` (which includes `internetClient`) and `privateNetworkClientServer`
[Capabilities]. Windows Firewall enforces these rules through the Windows Filtering Platform. The
plan reports `IpNetworkDenied` as unavailable when the firewall service (`MpsSvc`) does not run:
whether isolation holds without it is not documented, and Microsoft does not support stopping
it.

A child process could once bypass the isolation through firewall rules that matched only an
executable path [Project Zero 2021]. Microsoft later published an update for it as
CVE-2021-41338 [CVE-2021-41338].

### Loopback

AppContainer network isolation blocks loopback traffic between the AppContainer and processes
outside it, in both directions [IPC] [Loopback]. The blocking filter sits in the receive and
accept layer, so a blocked connection times out instead of failing at once [Project Zero 2021].

- **Program connects to a listener outside:** needs the loopback exemption of the AppContainer
  (`NetworkIsolationSetAppContainerConfig`, the API behind `CheckNetIsolation LoopbackExempt
  -a`). `sandy setup` installs it.
- **Process outside connects to a listener of the program:** blocked, also with the exemption.
  Microsoft documents only a debugging mode for it (`CheckNetIsolation LoopbackExempt -is`, which
  must keep running) [IPC]. sandy does not support it.
- **Listening itself** works without capabilities; only the incoming connections are dropped
  [Project Zero 2021].

The exemption is bound to the AppContainer SID and does not need any network capability: an
exempt AppContainer can reach `127.0.0.1` with no capabilities at all [Project Zero 2021]. The
plan therefore refuses `ip = "none"` for an exempt AppContainer. Use separate AppContainer names
for policies with and without IP networking.

### The setup step

`sandy setup` makes the loopback exemption of the policy's AppContainer match the policy. Run it
once per machine as administrator:

```text
sandy setup --appcontainer example.app --ip all     # add the exemption
sandy setup --appcontainer example.app              # remove it (ip = "none")
```

The exemption list is machine-wide. `NetworkIsolationSetAppContainerConfig` replaces the whole
list, so sandy reads it first and writes it back with one entry added or removed
[NetworkIsolationSetAppContainerConfig]. Two administrators changing the list at the same moment
can lose one change. `CheckNetIsolation LoopbackExempt -d -n=example.app` also removes the
exemption.

## Unix sockets

Windows has AF_UNIX sockets. Connecting needs write permission on the socket file, which is a
file system object with an ACL [AF_UNIX]. The program can therefore connect only to sockets whose
file it may write:

- Without read-write paths it can write no socket file, and `UnixSocketsDenied` is enforced.
- In read-write paths, a socket that a process outside the sandbox created inherits the ACE of
  the directory, and the program can connect to it. sandy cannot tell socket files from other
  files. `UnixSocketsDenied` is therefore unavailable for policies with read-write paths; such
  policies need `unix_sockets = "all"`.

With `unix_sockets = "all"`, the program still reaches only sockets it may write, not "every Unix
socket the user can reach". Abstract AF_UNIX addresses do not seem to work on current Windows
[PostgreSQL]. Whether AppContainer processes can use AF_UNIX at all is not documented; the escape
test `unix_sockets_in_writable_paths_are_reachable` finds out.

Named pipes are not Unix sockets, but the same access check protects them: the default DACL of a
pipe grants nothing to AppContainers [CreateNamedPipeW] [Implementing an AppContainer].

## Processes, privileges and signals

- **Job object.** sandy creates the program suspended, assigns it to a job, then resumes it. The
  job has kill-on-close and die-on-unhandled-exception, and allows no breakaway, so every child
  stays in the job. When sandy exits or dies, the job closes and its processes end. When the
  program exits, sandy ends the processes it left behind, so they do not outlive it.
- **UI restrictions.** The job sets all documented UI restrictions: desktops, display settings,
  `ExitWindows`, global atoms, USER handles of other processes, the clipboard (read and write),
  and system parameters [UI restrictions]. Low integrity already blocks window messages, hooks
  and input to windows of higher integrity (UIPI) [Integrity].
- **Privilege escalation.** Children inherit the AppContainer token [Legacy apps]. The token
  normally keeps only `SeChangeNotifyPrivilege` and `SeIncreaseWorkingSetPrivilege` [Chromium
  design]. sandy relies on the AppContainer
  boundary that Microsoft services [MSRC] against elevation through system services. Starting
  a program with `requireAdministrator` or calling `runas` from an AppContainer is not tested.
- **Other processes.** A process created outside the AppContainer has a default DACL that grants
  nothing to the AppContainer SID, so the program cannot open it, read its memory or terminate it
  [Implementing an AppContainer]. The escape test `cannot_open_processes_outside` checks
  `PROCESS_VM_READ` and `PROCESS_TERMINATE`.
- **Console.** A process on the console of sandy could send Ctrl+C and Ctrl+Break to every
  process on that console; the console host applies no check to `GenerateConsoleCtrlEvent`
  [Synacktiv] [Terminal]. On Windows 10 2004 to 21H1, it could also write keystrokes into the
  console input, which the shell reads after sandy exits (CVE-2021-41346) [Synacktiv]; newer
  builds block this for low integrity [Console security], but other console calls have no check
  [Synacktiv]. sandy therefore gives the program its own console without a window
  (`CREATE_NO_WINDOW`) and never passes it a console handle. When a standard handle of sandy is a
  console, sandy relays it through a pipe.
- **Ctrl+C.** sandy handles Ctrl+C and Ctrl+Break by ending the job. The program exits with
  `STATUS_CONTROL_C_EXIT` (`0xC000013A`), the status of a console program that Ctrl+C ended; it
  cannot handle Ctrl+C itself.

`SignalsIsolated` on Windows means: no console control events, no process handles and no window
messages that reach processes outside the sandbox.

## Handles, environment and command line

- **Handles.** `bInheritHandles` is TRUE, but `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` limits
  inheritance to three handles [UpdateProcThreadAttribute]. sandy duplicates each standard
  handle as an inheritable handle. A missing standard handle becomes the NUL device, and a
  console becomes a relayed pipe.
- **Environment.** sandy builds the block from the policy, sorted by name, case-insensitive,
  "without regard to locale" [Environment]. It adds one variable when the policy does not set it:
  `SystemRoot`, from `GetSystemWindowsDirectoryW`. System DLLs need it; without it, for example,
  Winsock initialization fails.
- **Command line.** sandy quotes each argument so that `CommandLineToArgvW` and the C runtime
  read it back unchanged [Parsing arguments], and refuses command lines longer than 32,767
  characters [CreateProcessW]. It refuses `.bat` and `.cmd` programs: `CreateProcessW` runs them
  in `cmd.exe`, which parses arguments with other rules, so arguments could run commands
  [BatBadBut]. Run `cmd.exe /c` explicitly instead.
- **Program path.** `std::fs::canonicalize` returns `\\?\C:\...` paths. sandy passes the
  ordinary form when it names the same file, so the program sees an ordinary path as its own
  name.

## Known limitations

1. `system = "none"` is unavailable (see above).
2. `unix_sockets = "none"` is unavailable with read-write paths (see above).
3. Loopback connections from outside to the program are not possible, also with `ip = "all"`.
4. The program can write its AppContainer profile folder.
5. Children of a directory that have a protected DACL do not receive the grant.
6. sandy refuses to grant a directory that contains junctions or symbolic links.
7. Ctrl+C ends the program; it cannot handle it.
8. The program does not see a console. Programs that read passwords from `CONIN$` read from their
   own invisible console and wait forever.
9. A volume without ACLs (FAT, exFAT) cannot hold grants; sandy fails when a policy path lies
   there. Whether the AppContainer can access such volumes outside the policy depends on the
   security descriptor of the volume device and is not verified.
10. sandy cannot remove its grants (see "Removing the changes").

## Open questions for the first Windows run

- Can a process start in an AppContainer with `CREATE_NO_WINDOW` (own console host)?
- Do writes in read-write paths work without a low integrity label?
- Can AppContainer processes use AF_UNIX at all?
- Does `NetworkIsolationGetAppContainerConfig` work without administrator rights? The plan
  needs it for `ip = "none"`.
- The shared test `ip_networking_is_denied_by_default` expects that `tcp-listen` fails. On
  Windows, listening probably succeeds and only incoming connections are dropped.
- Does a current directory outside the policy prevent the program from starting?

## Sources

- [AF_UNIX] AF_UNIX comes to Windows: https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/
- [BatBadBut] Rust security advisory CVE-2024-24576: https://blog.rust-lang.org/2024/04/09/cve-2024-24576.html
- [Capabilities] App capability declarations: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/app-capability-declarations
- [Chromium design] Sandbox design: https://chromium.googlesource.com/chromium/src/+/main/docs/design/sandbox.md
- [Chromium install] configure_app_container_sandbox.cc: https://chromium.googlesource.com/chromium/src/+/main/chrome/installer/setup/configure_app_container_sandbox.cc
- [Chromium network] network_sandbox.cc: https://chromium.googlesource.com/chromium/src/+/main/content/browser/network_sandbox.cc
- [Chromium policy] sandbox_policy.h (create_profile): https://chromium.googlesource.com/chromium/src/+/refs/tags/100.0.4896.60/sandbox/win/src/sandbox_policy.h
- [Console security] Console buffer security and access rights: https://learn.microsoft.com/en-us/windows/console/console-buffer-security-and-access-rights
- [CreateAppContainerProfile] https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile
- [CreateNamedPipeW] https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew
- [CreateProcessW] https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
- [CVE-2021-41338] https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-41338
- [Environment] Changing environment variables: https://learn.microsoft.com/en-us/windows/win32/procthread/changing-environment-variables
- [Forshaw 2014] Internet Explorer EPM sandbox escape: https://projectzero.google/2014/12/internet-explorer-epm-sandbox-escape.html
- [Forshaw access check] Windows Security Internals, access check implementation: https://github.com/tyranid/windows-security-internals/blob/main/chapter_7/chapter_7_access_check_impl.psm1
- [Implementing an AppContainer] https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer
- [Integrity] Windows Integrity Mechanism Design: https://learn.microsoft.com/en-us/previous-versions/dotnet/articles/bb625963(v=msdn.10)
- [IPC] Interprocess communication (loopback): https://learn.microsoft.com/en-us/windows/apps/develop/communication/interprocess-communication
- [Kanthak] SetNamedSecurityInfo drops SE_DACL_PROTECTED: https://seclists.org/fulldisclosure/2012/Jun/317
- [LaunchAppContainer] Microsoft SandboxSecurityTools: https://github.com/microsoft/SandboxSecurityTools/blob/HEAD/LaunchAppContainer/README.md
- [Legacy apps] AppContainer for legacy applications: https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-for-legacy-applications-
- [Loopback] How to enable loopback and troubleshoot network isolation: https://learn.microsoft.com/en-us/previous-versions/windows/apps/hh780593(v=win.10)
- [MSRC] Windows security servicing criteria: https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria
- [NetworkIsolationSetAppContainerConfig] https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-networkisolationsetappcontainerconfig
- [Parsing arguments] Parsing C command-line arguments: https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments
- [PostgreSQL] Abstract Unix sockets on Windows: https://www.postgresql.org/message-id/E1pNSBf-001AfT-Af%40gemulon.postgresql.org
- [Project Zero 2021] Understanding network access in Windows AppContainers: https://projectzero.google/2021/08/understanding-network-access-windows-app.html
- [SetNamedSecurityInfoW] https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow
- [STIG] Windows 10 default permissions of Program Files: https://www.stigviewer.com/stigs/microsoft_windows_10/2025-02-25/finding/V-220717
- [Synacktiv] Escaping AppJailLauncher: https://www.synacktiv.com/sites/default/files/2021-10/AppJailLauncher.pdf
- [Terminal] Console host sources (`src/server`): https://github.com/microsoft/terminal
- [UI restrictions] JOBOBJECT_BASIC_UI_RESTRICTIONS: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_ui_restrictions
- [UpdateProcThreadAttribute] https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
