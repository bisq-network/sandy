# Windows backend

sandy runs the program in an AppContainer and in a job object. An AppContainer is the sandbox of
Windows Store apps: the process gets a token with an AppContainer SID, runs at low integrity, and
every access check also has to grant access to that SID or to one of its capabilities. Microsoft
treats the AppContainer as a security boundary that it services with security updates [MSRC].

Status: the shared escape tests (`crates/sandy-cli/tests/escape.rs`) and the Windows escape
tests (`escape_windows.rs`) pass on Windows 11 build 26200, both elevated and with a filtered
(non-elevated, medium integrity) token; see "Verified on Windows 11". Statements that no test
checks come from the cited sources. Wine does not implement AppContainers, so Wine runs prove
nothing about isolation.

## Requirements and mechanisms

| Requirement | Mechanism | Unavailable when |
|---|---|---|
| `FilesystemConfined` | One capability per policy path, with an access control entry (ACE) on the path | `system = "none"` |
| `MetadataConfined` | No `WRITE_DAC`, `WRITE_OWNER`, `FILE_WRITE_ATTRIBUTES` or `FILE_WRITE_EA` outside read-write paths | never |
| `NoPrivilegeEscalation` | AppContainer token, inherited by every child; job object without breakaway | no AppContainer |
| `ProcessMemoryIsolated` | Processes outside the AppContainer grant its SID no access | no AppContainer |
| `InheritedHandlesClosed` | `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` with the three standard handles | never |
| `EnvironmentControlled` | Environment block built from the policy, plus `SystemRoot` and `LOCALAPPDATA` | never |
| `IpNetworkDenied` | No network capabilities, no loopback exemption | AppContainer exempt from loopback isolation; firewall service not running |
| `UnixSocketsDenied` | No write access to socket files outside read-write paths | no AppContainer |
| `SignalsIsolated` | Own console; AppContainer access checks; job UI restrictions | no AppContainer |
| `ExposedPortsRelayed` | Listening socket created outside the AppContainer; `sandy __relay` in the program's AppContainer and a job of its own | no AppContainer; outer job with UI restrictions; sandy cannot grant read and execute on `sandy.exe`; `sandy.exe` lies in a read-write path |
| `ChildProcessesDenied` | The program's job admits one active process (`JOB_OBJECT_LIMIT_ACTIVE_PROCESS` = 1); the relays run without a console and with `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED` | outer job with UI restrictions; no AppContainer |
| `ChildProcessesContained` | Every child joins the program's job, which allows no breakaway; sandy ends the job when the program exits, and kill-on-close ends it when sandy dies | outer job with UI restrictions; no AppContainer |
| `ForwardedPortsRelayed` | `sandy __forward` in the program's AppContainer and a job of its own listens on the program's port and passes each connection over an AF_UNIX socket to sandy, which connects to the target; no loopback exemption | as for `ExposedPortsRelayed`; AF_UNIX missing; socket paths longer than 107 bytes |

Every requirement also needs `windows.appcontainer_name` (or `--appcontainer NAME`). Without it,
or with an invalid name, the plan reports the requirements that need the AppContainer as
unavailable. A name has at most 64 characters from `A-Z a-z 0-9 - _ .` and space
[CreateAppContainerProfile].

## The AppContainer

`sandy run` creates the AppContainer profile of the name for the current user on first use, with
`CreateAppContainerProfile`. Microsoft documents a profile as the precondition for creating a
process in an AppContainer [Legacy apps], and Chromium's sandbox notes that process creation
fails without one [Chromium policy]. Later runs derive the SID with
`DeriveAppContainerSidFromAppContainerName` and do not call `CreateAppContainerProfile` again: on
Windows 11, calling it for an existing profile while other runs started processes in the same
AppContainer made it fail with `E_UNEXPECTED`, and made a concurrent `CreateProcessW` fail with
`ERROR_FILE_NOT_FOUND`. sandy recognizes a registered profile by the key
`HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\<SID>`,
which Windows creates for it. The location is not documented; if it changes, sandy calls
`CreateAppContainerProfile` on every run again, which reports an existing profile. A named mutex
(`Local\sandy-appcontainer-profiles`) keeps two first runs from creating the profile at once.

The profile creates a folder for the AppContainer below `%LOCALAPPDATA%\Packages\<name>`. The
program can read, write and execute files there; Windows points its `TEMP` and `TMP` to the
`AC\Temp` folder there. The folder belongs to this AppContainer name only and keeps its content
between runs.

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

### The AppContainer profile folder

Windows gives every AppContainer a private folder, `%LOCALAPPDATA%\Packages\<name>\AC`, and
redirects the program's `LOCALAPPDATA`, `TEMP` and `TMP` there [Implementing an AppContainer].
The folder is always present, the program can write it, and it survives runs: Windows creates it
and sandy cannot remove it without breaking the program's `TEMP`.

Windows creates the folder with an inheritable allow entry that grants the AppContainer SID full
access, including `FILE_EXECUTE`. That would let the program write a file there and then execute
it, which the writable-never-executable rule forbids for policy paths. On every run sandy removes
`FILE_EXECUTE` from that allow entry (`SetNamedSecurityInfoW` re-propagates it to existing files
too), so the program can use the folder for data but cannot run what it writes. A deny entry does
not work here: the AppContainer access check ignores a deny ACE for the package SID, measured on
Windows 11; reducing the allow entry is what the check honors. The change is idempotent.

The folder holds no user data. It is the program's own scratch space, writable in every policy,
also one with no writable path. `escape_windows` and `review_windows` confirm that the program
can write and read it but cannot execute a file in it (`load-library` is denied while `read`
succeeds).

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
sets no integrity label. Microsoft: "if a resource has a mandatory label of Medium IL or lower
and the DACL grants access through to the AppContainer (through a Package SID or Capability
SID) then the AppContainer can read, write, or execute depending on the access granted" [Implementing
an AppContainer]. The escape tests write, create and delete in read-write paths on Windows 11.

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

- File grants, including the relay grant on `sandy.exe`: `icacls PATH` lists the grants as `*S-1-15-3-1024-...`. `icacls PATH /remove:g
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
  -a`), which `sandy setup` installs, or a forwarded port, which needs no administrator step
  (see "Forwarded ports").
- **Process outside connects to a listener of the program:** blocked, also with the exemption;
  an exposed port relays it (see "Exposed ports").
  Microsoft documents only a debugging mode for it (`CheckNetIsolation LoopbackExempt -is`, which
  must keep running) [IPC]. sandy does not support it.
- **Listening itself** works without capabilities; only the incoming connections are dropped
  [Project Zero 2021]. On Windows 11, `tcp-listen` inside the sandbox succeeds, and an outside
  client that connects to it times out, with and without the exemption.

The exemption is bound to the AppContainer SID and does not need any network capability: an
exempt AppContainer can reach `127.0.0.1` with no capabilities at all [Project Zero 2021]. The
plan therefore refuses `ip = "none"` for an exempt AppContainer. Use separate AppContainer names
for policies with and without IP networking.

### Local servers in the sandbox

A program in the sandbox cannot accept loopback TCP connections from processes outside it, also
with `ip = "all"` and the exemption. Options, tested on Windows 11 build 26200:

| Option | Result | Cost |
|---|---|---|
| `CheckNetIsolation LoopbackExempt -is -n=NAME` (debugging mode) | Does not help: connections still time out while it runs | Needs a running elevated helper; meant for debugging |
| AF_UNIX socket in a read-write path | Works: the program listens, outside clients connect (`unix_socket_server_in_a_writable_path_is_reachable_from_outside`) | Clients must speak AF_UNIX; no change to sandy |
| Listening TCP socket created outside the AppContainer and inherited | Works, even with `ip = "none"`: the program accepted a connection from an outside client | The program would have to accept on an inherited socket instead of its own |
| Relay inside the AppContainer: a process holding the inherited listening socket forwards each connection over loopback to the server process in the same AppContainer | Works with `ip = "none"` and `ip = "all"`, with and without exemption | Implemented as `network.expose`, see "Exposed ports" |
| Firewall rule for the package SID | Not tested; the AppContainer filters sit in the Windows Service Hardening sublayer, which ordinary firewall rules do not override [Project Zero 2021] | Administrator rights |

Processes in the same AppContainer reach each other over loopback in every configuration
measured, also with `ip = "none"` and without exemption. `network.expose` builds on this fact.

Because of the same fact, two sandboxes that use the same AppContainer name can talk over
loopback, also when their policies differ (for example one with `ip = "all"`). Processes in one
AppContainer can also open each other's processes. A program with a weaker policy could therefore
take over a program with a stronger policy that runs at the same time under the same name.

sandy enforces one policy per name at a time (`crates/sandy-windows/src/sys/singleton.rs`):

- While a program runs, sandy holds a named file mapping in the `Local\` object namespace that
  stores a fingerprint of the resolved policy: the path rules (including the program's own read
  and execute rule), the system set, `ip`, `unix_sockets`, the exposed ports, `signals` and
  `path_metadata`. Arguments, working directory and environment are not part of it. A named mutex
  serializes the check.
- A second run under the same name with the same fingerprint may run at the same time. A run with
  a different fingerprint is refused with exit status 125 and the reason, until every run of the
  first policy has ended.
- An AppContainer process sees its own object namespace, so the program cannot open or change the
  mapping. The kernel removes the mapping when the last run that holds it exits, also after a
  crash, so no stale state blocks later runs. Runs with different policies one after the other
  stay allowed.

Use one AppContainer name per policy anyway: file grants and the loopback exemption belong to the
name, and two policies that share a name cannot run at the same time.

### Exposed ports

For each entry of `network.expose`, sandy relays connections from `listen` to the program's
port:

1. sandy binds a TCP socket to `listen` outside the AppContainer and makes it inheritable.
2. Before the program, sandy starts `sandy.exe __relay <handle> <target>` in the program's
   AppContainer and in a job of its own (the relay job: kill-on-close, the same limits as the
   program's job), created suspended and assigned to that job like the program, but without a
   console and unable to create processes (see "Child processes"). The handle list holds only
   the socket, a pipe as standard input (sandy keeps the other end), the NUL device as standard
   output and the program's standard error. The environment holds only `SystemRoot` and
   `LOCALAPPDATA`.
3. The relay's token has no network capability and one file capability: read and execute on
   `sandy.exe`, granted with the same ACE mechanism as policy paths.
4. sandy closes its own handle of the socket, starts the program and waits only for the
   program. The relay ends as "How the relays end" describes. If sandy dies, kill-on-close ends
   it.

The relay accepts on the socket because a socket keeps the security context of the process that
created it. It reaches the program over loopback because both run in the same AppContainer. It
connects only to the program's address, `target()`, and it connects from inside the
AppContainer, so loopback isolation applies to it as to the program: without the exemption, a
relay cannot reach a listener outside the sandbox, also when the policy exposes that listener's
port number (`relays_reach_only_the_program`).

The relay runs in the program's AppContainer, so the program can open and control the relay
process: processes in one AppContainer can open each other. That gives the program no more than
the exposed listener itself, which `network.expose` grants anyway, and read and execute access to
`sandy.exe`, which is not secret. The relay's token has no network capability and no access to
policy paths.

The grant on `sandy.exe` needs the right to change its DACL. A user who cannot change the DACL
of an installed `sandy.exe`, for example under `C:\Program Files`, can let an administrator run
`sandy setup` with the same policy, including `--expose`, once; the grant is per AppContainer
name. Without the grant, the plan reports `ExposedPortsRelayed` as unavailable. The plan also
refuses when `sandy.exe` lies in a read-write path: the program could replace the file that the
relays execute (writable-and-executable rule), and sandy must stay out of the program's reach in
any case.

### Forwarded ports

For each entry of `network.forward`, the program reaches the loopback service `to` by connecting
to `port` on its own loopback address, without the loopback exemption:

1. sandy creates a directory with a random name below `%LOCALAPPDATA%\sandy\forward` and adds one
   inherit-only entry to it that lets the relays' capability (read and execute on `sandy.exe`)
   open the files in it with read and write data access. `%LOCALAPPDATA%` grants nothing to
   AppContainers, so the program, which does not hold that capability, cannot open them.
2. sandy binds one AF_UNIX socket per port in that directory, named after the port, and serves
   each on a thread: it connects every accepted connection to `to` over TCP.
3. Before the program, sandy starts `sandy.exe __forward <listen> <socket>` in the program's
   AppContainer and the relay job, like an exposed-port relay but without a socket: the relay
   creates the program's listener on `listen` itself and writes "ready" to its standard output
   (a pipe to sandy) once it listens. sandy starts the program only after that line, so the
   program's first connection cannot come too early.
4. The relay passes each connection it accepts to the AF_UNIX socket.

Why this works: a listener that sandy creates outside the AppContainer is outside it, and the
program's connection to it is blocked like any connection to a loopback listener outside. A
listener that the relay creates inside the AppContainer takes the program's connection, because
processes in one AppContainer reach each other over loopback. AF_UNIX is not subject to loopback
isolation; AppContainer processes can connect to an AF_UNIX socket outside when they may write
its file (`unix_sockets_in_writable_paths_are_reachable`).

Like the exposed-port relay, the forward relay runs in the program's AppContainer, so the program
can open and control it. That gives the program no more than `to`, which `network.forward`
grants anyway, plus read and execute access to `sandy.exe`. The socket path must fit into the
107 bytes of `sun_path` (UTF-8); the plan checks the longest path under the directory and reports
`ForwardedPortsRelayed` as unavailable otherwise. sandy removes the directory when the run ends;
Windows deletes a socket file also while its socket still listens.

### How the relays end

The relays follow docs/DESIGN.md "Forwarded ports" rule 5. When the program exits:

1. sandy ends the program's job at once, so the processes the program left behind end and
   nothing in the sandbox can make a new connection.
2. sandy closes each relay's standard input. The relay then stops waiting for connections,
   still accepts those that already wait in its listen backlog (their handshake is complete, so
   the client counts them as made), closes its listener, waits up to one second for the accepted
   connections to finish, and ends. It checks for the stop at least every 50 ms, so it never has
   to close its listener under a thread that waits in `accept`.
3. One second after the program's end, sandy ends the relay job, stops its own forward sockets
   the same way and removes the socket directory.

A program that connects, sends and exits at once therefore does not lose its data
(`forward_relay_delivers_data_sent_just_before_exit`), and a relay takes no new connection after
the program's end (`relay_stops_listening_as_soon_as_the_program_ends`).

### The setup step

`sandy setup` makes the loopback exemption of the policy's AppContainer match the policy. With
`--expose`, it also grants the relays read and execute on `sandy.exe` (see "Exposed ports"). Run
it once per machine as administrator:

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
file it may write: sockets in its read-write paths and in its AppContainer profile folder.
`UnixSocketsDenied` guarantees that the program cannot connect to Unix sockets outside its
read-write paths (a lower bound, see DESIGN.md), so the backend enforces it through the ACL.

Inside read-write paths the program can connect to every socket, also to one that a process
outside the sandbox created there. AppContainer processes can use AF_UNIX; the escape test
`unix_sockets_in_writable_paths_are_reachable` shows it. With `unix_sockets = "all"`, the program
still reaches only sockets it may write, not "every Unix socket the user can reach". Abstract
AF_UNIX addresses do not seem to work on current Windows [PostgreSQL].

Named pipes are not Unix sockets, but the same access check protects them: the default DACL of a
pipe grants nothing to AppContainers [CreateNamedPipeW] [Implementing an AppContainer].

## Processes, privileges and signals

- **Job object.** sandy creates the program suspended, assigns it to a job, then resumes it. The
  job has kill-on-close and die-on-unhandled-exception, and allows no breakaway, so every child
  stays in the job. When sandy exits or dies, the job closes and its processes end. When the
  program exits, sandy ends the processes it left behind, so they do not outlive it. The relays
  of exposed and forwarded ports run in a second job with the same limits, which sandy ends at
  most one second later (see "How the relays end").
- **Child processes.** With `process.children = "none"` the program's job has an active-process
  limit of 1. The program is that one process; every child it creates would join the job (the
  job allows no breakaway), so Windows refuses it: `CreateProcess` fails with
  `ERROR_NOT_ENOUGH_QUOTA` (1816), and `cmd.exe` reports "Access is denied". The program holds no
  handle to the job, so it cannot raise the limit. Threads are not affected. The program's
  console host (conhost) also runs in the job, but Windows does not count it against the limit
  (measured on Windows 11). The relays never need a console or a child: sandy starts them
  detached (`DETACHED_PROCESS`) and with `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY` set to
  `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`, which Windows fixes when the process is created.
  The program can open the relays (one AppContainer), so this keeps them from being a way
  around the rule. Why not the same policy for the program: a console program with it cannot
  start its own console host and ends with `STATUS_DLL_INIT_FAILED` (`0xC0000142`) before it
  runs. Why not a job limit for the relays: with two relays, the program could end one to free a
  slot and use the other. Processes that a service outside starts on request are not children
  of the program; an AppContainer cannot activate out-of-process COM servers
  (`out_of_process_com_service_activation_is_blocked`), and sandy refuses `children = "none"`
  together with `unix_sockets = "all"`.
- **Contained child processes.** `process.children = "contained"` needs nothing beyond the job
  described above: the program's children join the job, sandy ends the job when the program
  exits, and the job closes when sandy dies. The program holds no handle to the job, and the
  AppContainer cannot open sandy, so it can neither leave the job nor end sandy early. `allowed`
  behaves the same on Windows; `contained` states the guarantee in the policy, so that the same
  policy is refused on platforms that cannot give it. The policy rules for `contained`
  (`unix_sockets = "none"`, `signals = "isolated"`) apply on Windows too.
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
  inheritance to three handles [UpdateProcThreadAttribute]. A relay of an exposed port inherits
  its listening socket in addition. sandy duplicates each standard
  handle as an inheritable handle. A missing standard handle becomes the NUL device, and a
  console becomes a relayed pipe. A standard handle that is a socket gives the program network
  access through that socket, also with `ip = "none"`: AppContainer network isolation applies to
  sockets the AppContainer creates, not to sockets created outside it (verified on Windows 11
  with a listening socket). This holds on every platform for inherited sockets.
- **Environment.** sandy builds the block from the policy, sorted by name, case-insensitive,
  "without regard to locale" [Environment]. It sets two variables, which replace policy values:
  - `SystemRoot`, from `GetSystemWindowsDirectoryW`. System DLLs need it; without it, for
    example, Winsock initialization fails.
  - `LOCALAPPDATA`, from `SHGetKnownFolderPath`. sandy loads `shell32.dll` for it at run time:
    `shell32.dll` loads `user32.dll`, which cannot initialize in some sessions (limitation 13),
    and the relays run `sandy.exe` in the AppContainer. Without the variable, `CreateProcessW` fails for an
    AppContainer process with `ERROR_ENVVAR_NOT_FOUND` (203). Windows replaces it with
    `<LOCALAPPDATA>\Packages\<name>\AC` and sets `TEMP` and `TMP` to the `Temp` folder below,
    also when the policy sets them. Microsoft documents the redirection [Implementing an
    AppContainer]; that the variable is required is not documented, it was observed on Windows 11
    build 26200.
- **Command line.** sandy quotes each argument so that `CommandLineToArgvW` and the C runtime
  read it back unchanged [Parsing arguments], and refuses command lines longer than 32,767
  characters [CreateProcessW]. It refuses `.bat` and `.cmd` programs: `CreateProcessW` runs them
  in `cmd.exe`, which parses arguments with other rules, so arguments could run commands
  [BatBadBut]. Run `cmd.exe /c` explicitly instead.
- **Program path.** `std::fs::canonicalize` returns `\\?\C:\...` paths. sandy passes the
  ordinary form when it names the same file, so the program sees an ordinary path as its own
  name.

## Supported Windows versions

- **Required:** Windows 10 version 1809 (build 17763) or later, or Windows Server 2019 or
  later. Earlier builds do not export `DeriveCapabilitySidsFromName`, and none of them receives
  security updates any more. sandy resolves that function at run time, so `sandy check` still
  starts on older builds and reports why it cannot enforce the policy.
- **Network isolation:** `IpNetworkDenied` also needs the fix for CVE-2021-41338, a bypass of the
  AppContainer firewall rules. The plan refuses builds without it: 17763 before .2237, 18362
  (never fixed), 18363 before .1854, 19041 to 19043 before .1288, 20348 before .288 and 22000
  before .258 [CVE-2021-41338]. The table lives in `crates/sandy-windows/src/version.rs`.
- **Expected to work, not tested:** Windows 10 1809 (LTSC 2019), 21H2 (LTSC 2021) and 22H2.
- **Tested:** Windows 11 build 26200 (VM, all tests), Windows Server 2022 and Windows Server
  2025 (GitHub Actions; all tests except `executes_only_executable_paths`, see limitation 11).
- **Nested jobs:** when sandy runs inside a job with UI restrictions, Windows refuses to put the
  program into sandy's own job (`ERROR_NOT_SUPPORTED`, measured on Windows 11), and the plan
  reports `NoPrivilegeEscalation` and `SignalsIsolated` as unavailable. Inside a job without UI
  restrictions, with or without breakaway, the jobs nest. sandy never breaks away from the outer
  job. Microsoft documents a stricter rule ("neither job sets UI limits") [Nested jobs], which
  the measurements on Windows 11, Server 2022 and Server 2025 do not show; Windows 10 is
  untested.

## Known limitations

1. `system = "none"` is unavailable (see above).
2. Loopback TCP connections from outside to the program are not possible, also with `ip = "all"`
   (see "Local servers in the sandbox").
3. The program can write its AppContainer profile folder (which holds `TEMP`), and can connect
   to Unix sockets in it and in its read-write paths. It cannot execute a file it writes there
   (see "The AppContainer profile folder"). The folder is private scratch space, holds no user
   data, and persists across runs.
4. Windows sets `LOCALAPPDATA`, `TEMP` and `TMP` of the program; policy values for them have no
   effect.
5. Children of a directory that have a protected DACL do not receive the grant.
6. sandy refuses to grant a directory that contains junctions or symbolic links.
7. Ctrl+C ends the program; it cannot handle it.
8. The program does not see a console. Programs that read passwords from `CONIN$` read from their
   own invisible console and wait forever.
9. A volume without ACLs (FAT, exFAT) cannot hold grants; sandy fails when a policy path lies
   there. Whether the AppContainer can access such volumes outside the policy depends on the
   security descriptor of the volume device and is not verified.
10. sandy cannot remove its grants (see "Removing the changes").
11. On the GitHub Actions images `windows-2022` and `windows-2025` (Windows Server 2022 and 2025
    Datacenter), a process in an AppContainer cannot start child processes: `CreateProcessW`
    fails with `ERROR_ACCESS_DENIED` for every program, while the console host still starts.
    This holds for sandy and for a minimal launcher without job, capabilities or special flags,
    from the runner's process tree and from a scheduled task, elevated and not elevated. Ruled
    out: file ACLs, the working directory, the console, job objects, process mitigation
    policies, Defender, attack surface reduction, AppLocker, Code Integrity and UAC. The cause in
    the configuration of these images is not known. On Windows 11 build 26200 child processes
    work. The shared test `executes_only_executable_paths` therefore cannot pass on these
    runners.
12. `std::fs::canonicalize` and `GetFinalPathNameByHandleW` with DOS names fail with
    `ERROR_ACCESS_DENIED` inside an AppContainer (Windows 11 and Server 2025); NT names work.
    Programs that canonicalize their paths need a fallback such as `std::path::absolute`.
13. In a session whose window station does not admit AppContainers, such as an SSH session,
    `user32.dll` cannot initialize in an AppContainer process, and a program that loads it ends
    with `STATUS_DLL_INIT_FAILED` (`0xC0000142`) before its first instruction. Measured on
    Windows 11 over SSH; the same programs start from an interactive scheduled task. Programs
    without `user32.dll`, and the relays, are not affected.
14. If sandy itself is killed during a run with forwarded ports, its socket directory below
    `%LOCALAPPDATA%\sandy\forward` stays behind. Its sockets have no listener, so nobody can
    connect through them; the directory can be deleted. sandy does not remove such directories
    of other runs, because one of them may belong to a run that is still active.

## Verified on Windows 11

Host: Windows 11 build 26200 (VM), binaries built for `x86_64-pc-windows-gnu`. The tests run in
an elevated SSH session and without administrator rights. Latest elevated run: `sandy_windows` 63
of 63, `sandy_relay` 8 of 8, `escape` 10 of 10 (the Unix socket test is Unix-only),
`escape_windows` 32 of 32, `expose` 3 of 3, `forward` 2 of 2, `children` 1 of 1,
`review_windows` 3 of 3. Earlier
non-administrator runs used a scheduled task with `/RL LIMITED` (medium integrity, Administrators
deny-only). The latest one used `runas /trustlevel:0x20000` (Administrators deny-only, high
integrity), because the VM had no interactive logon session for an `/IT` task: every test
passed except two outside controls of `review_windows` (BITS activation and listing
`C:\Users\Public`), which that token may not do, so those tests correctly refuse to judge.

Facts these runs established:

- A program starts in an AppContainer with `CREATE_NO_WINDOW` and gets its own console.
- Writes, deletes and directory creation in read-write paths work without an integrity label.
- AppContainer processes can use AF_UNIX.
- `NetworkIsolationGetAppContainerConfig` works without administrator rights.
- Listening on loopback succeeds without capabilities; incoming connections time out, also with
  the exemption. Outbound connections to the internet fail with `WSAEACCES` (10013).
- A working directory outside the policy does not prevent the start; the program cannot list it.
- `DeleteAppContainerProfile` from the PowerShell snippet above removes a profile and its
  folder.
- The program cannot open other processes of the user (`PROCESS_VM_READ`, `PROCESS_TERMINATE`),
  write to the registry autostart key, open a named pipe with the default DACL, or receive
  inherited handles other than the standard ones.
- A process in the AppContainer can open a relay in the same AppContainer with
  `PROCESS_VM_READ` and `PROCESS_TERMINATE`, but not `sandy.exe` outside it.
- A relay without network capabilities reaches the program over loopback. Without the loopback
  exemption it cannot reach a listener outside; with the exemption it can, like the program.
- A user without the right to change the DACL of `sandy.exe` gets `ExposedPortsRelayed` as
  unavailable; after `sandy setup` with the policy, run as administrator, the plan enforces it.
- A program in an AppContainer without the loopback exemption reaches a loopback service outside
  through `network.forward`, while its direct connection to a listener outside times out.
- An AF_UNIX stream socket works through the standard library's `TcpStream` for reading,
  writing and the half close; `sun_path` is read as UTF-8; a socket file and its directory can be
  deleted while the socket listens, after which connections fail.
- The program cannot connect to the forward socket (`WSAEACCES`); the relay and the user can.
- With `children = "none"` the program and `cmd.exe` start, and starting `whoami.exe` fails;
  the relays report `NoChildProcessCreation` through `GetProcessMitigationPolicy` and still relay.

## Sources

- [AF_UNIX] AF_UNIX comes to Windows: https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/
- [BatBadBut] Rust security advisory CVE-2024-24576: https://blog.rust-lang.org/2024/04/09/cve-2024-24576.html
- [Capabilities] App capability declarations: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/app-capability-declarations
- [Chromium design] Sandbox design: https://chromium.googlesource.com/chromium/src/+/main/docs/design/sandbox.md
- [Chromium install] configure_app_container_sandbox.cc: https://chromium.googlesource.com/chromium/src/+/main/chrome/installer/setup/configure_app_container_sandbox.cc
- [Chromium policy] sandbox_policy.h (create_profile): https://chromium.googlesource.com/chromium/src/+/refs/tags/100.0.4896.60/sandbox/win/src/sandbox_policy.h
- [Console security] Console buffer security and access rights: https://learn.microsoft.com/en-us/windows/console/console-buffer-security-and-access-rights
- [CreateAppContainerProfile] https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile
- [CreateNamedPipeW] https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew
- [CreateProcessW] https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
- [CVE-2021-41338] https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-41338
- [Environment] Changing environment variables: https://learn.microsoft.com/en-us/windows/win32/procthread/changing-environment-variables
- [Forshaw access check] Windows Security Internals, access check implementation: https://github.com/tyranid/windows-security-internals/blob/main/chapter_7/chapter_7_access_check_impl.psm1
- [Implementing an AppContainer] https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer
- [Integrity] Windows Integrity Mechanism Design: https://learn.microsoft.com/en-us/previous-versions/dotnet/articles/bb625963(v=msdn.10)
- [IPC] Interprocess communication (loopback): https://learn.microsoft.com/en-us/windows/apps/develop/communication/interprocess-communication
- [Nested jobs] https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs
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
