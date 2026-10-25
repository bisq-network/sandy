# Windows backend

sandy runs the program in an AppContainer and in a job object. An AppContainer is the sandbox of
Windows Store apps: the process gets a token with an AppContainer SID, runs at low integrity, and
every access check also has to grant access to that SID or to one of its capabilities. Microsoft
treats the AppContainer as a security boundary that it services with security updates [MSRC].

Status: the shared escape tests (`crates/sandy-cli/tests/escape.rs`) and the Windows escape
tests (`escape_windows.rs`) pass on Windows 11 build 26200, both elevated and with a filtered
(non-elevated) token; see "Verified on Windows 11". Statements that no test checks come from the
cited sources. Wine does not implement AppContainers, so Wine runs prove nothing about
isolation.

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
| `InboundIpDenied` | The `internetClient` capability only; loopback isolation | firewall service not running; no fix for CVE-2021-41338 |
| `UnixSocketsDenied` | No write access to socket files outside read-write paths | no AppContainer |
| `SignalsIsolated` | Own console; AppContainer access checks; job UI restrictions | no AppContainer |
| `ExposedPortsRelayed` | Listening socket created outside the AppContainer; `sandy __relay` in the program's AppContainer and a job of its own | no AppContainer; outer job with UI restrictions; sandy cannot grant read and execute on `sandy.exe`; `sandy.exe` lies in a read-write path |
| `ChildProcessesDenied` | The program's job admits one active process (`JOB_OBJECT_LIMIT_ACTIVE_PROCESS` = 1); the relays run without a console and with `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED` | outer job with UI restrictions; no AppContainer |
| `EndsWithParent` | sandy finds its parent in a process snapshot, checks its creation time, waits for it next to the program, and ends the program's job when it ends | outer job with UI restrictions; no AppContainer |
| `ChildProcessesContained` | Every child joins the program's job, which allows no breakaway; sandy ends the job when the program exits, and kill-on-close ends it when sandy dies | outer job with UI restrictions; no AppContainer |
| `ForwardedPortsRelayed` | `sandy __forward` in the program's AppContainer and a job of its own listens on the program's port and passes each connection over an AF_UNIX socket to sandy, which connects to the target; no loopback exemption | as for `ExposedPortsRelayed`; AF_UNIX missing; socket paths longer than 107 bytes |
| `Win32kDenied` | `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` with `PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON` for the program and the relays, read back with `GetProcessMitigationPolicy` before they run (only with `windows.win32k = "deny"`) | Windows refuses to set or report the mitigation |

Every requirement also needs `windows.appcontainer_name` (or `--appcontainer NAME`). Without it,
or with an invalid name, the plan reports the requirements that need the AppContainer as
unavailable. A name has at most 64 characters from `A-Z a-z 0-9 - _ .` and space
[CreateAppContainerProfile]. sandy refuses three shapes beyond that:

- a name that starts or ends with a space, or ends with a period. Windows drops those from a
  path component, so the name and the folder it reaches would be different things;
- a name made of periods only, which names a directory;
- a name shaped like the family name of an application package, `Publisher.App` plus an
  underscore and a 13 character publisher ID, which is a hash in Crockford's base32: digits and
  the letters other than i, l, o and u, in either case. Windows derives a package SID from a
  family name the way it derives an AppContainer SID from a name, so such a name would be the
  identity of that package: sandy would change the permissions of its folder and share its
  sandbox. The check is on the shape, so it also refuses a family name of a package that is not
  installed.

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
`CreateAppContainerProfile` on every run again, which reports an existing profile. A lock file
(`%LOCALAPPDATA%\sandy\locks\appcontainer-profiles`) keeps two first runs of the user from
creating the profile at once.

sandy asks Windows for the folder of the AppContainer with `GetAppContainerFolderPath` on the
SID string instead of building `%LOCALAPPDATA%\Packages\<name>\AC` itself, because the name and
the path are not the same function of the name.

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

No writable path may overlap this set (rule 6 in `DESIGN.md`), and none may be a place where the
program could write a file that it may then execute (rule 3). The plan reports
`FilesystemConfined` unavailable, and `grant` refuses, when a `read_write` path:

- contains or lies inside the Windows directory (`GetSystemWindowsDirectoryW`) or a program files
  directory (`FOLDERID_ProgramFiles`, `FOLDERID_ProgramFilesX86`);
- has a DACL that gives `FILE_EXECUTE` to ALL APPLICATION PACKAGES, to ALL RESTRICTED
  APPLICATION PACKAGES, to the AppContainer of the policy or to one of its network
  capabilities, on the path itself or through an entry that files or directories created in it
  inherit (`access::may_grant`). Effective access is the union of all allow entries, so the
  execute right would join the write right of sandy's capability. A writable data folder below
  `C:\Program Files` inherits exactly such an entry;
- has entries of a type the evaluator does not know, because then it cannot tell. An entry with
  a condition (`ACCESS_ALLOWED_CALLBACK_ACE_TYPE`) is known but its condition is not read, so it
  counts as granting here and never as a grant sandy may skip.

The grant capabilities are not on that list. A grant capability is derived from the identity of
the object it is granted on, so it can appear on that object and nowhere else; a file that is
writable and executable through a second name is the link question of "Links and identity".

`check` reads the permissions of the path itself. When `run` adds the entry, it also walks the
tree below the path and refuses a descendant whose own permissions may give one of them execute,
in the same walk that refuses junctions. The walk runs only where sandy changes something, so it
does not slow down a plan, and `check` can report a policy as enforceable that `run` then
refuses for a file below the path. What outside software adds after the walk is not seen; the
program cannot add it, because it holds no right to change permissions outside its profile
folder.

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
access, which contains `FILE_EXECUTE`, `WRITE_DAC` and `WRITE_OWNER`. Execute would let the
program write a file there and then run it, which the writable-never-executable rule forbids for
policy paths. The other two would let it write the file's own permissions and grant execute
back, to ALL APPLICATION PACKAGES for example, which every AppContainer belongs to. sandy
reduces the entry to the rights of a `read_write` policy path, so all three are gone
(`SetNamedSecurityInfoW` re-propagates the reduced entry to existing files too). A deny entry
does not work here: the AppContainer access check ignores a deny ACE for the package SID,
measured on Windows 11; reducing the allow entry is what the check honors, for `WRITE_DAC` as
much as for `FILE_EXECUTE` (measured on build 26200).

The change is idempotent: a run writes only while the entry still carries one of the three
rights. sandy 1.3.2 removed `FILE_EXECUTE` alone, so the first run of a later version reduces
such a profile once more. That run also walks the folder and refuses a junction or symbolic link
below it, because it re-propagates the entry and the program can write there
(`review_windows::reducing_an_old_profile_entry_refuses_a_junction_in_the_folder`).

The folder holds no user data. It is the program's own scratch space, writable in every policy,
also one with no writable path. `escape_windows` and `review_windows` confirm that the program
can write and read it, cannot execute a file in it (`load-library` is denied while `read`
succeeds), and cannot grant itself execute back.

What the reduction does not repair: a program that ran under sandy 1.3.2 could write an explicit
entry of its own on a file in the folder, and re-propagation does not remove explicit entries.
It cannot write new ones afterwards. `sandy setup --remove` deletes the profile and with it any
entry left there.

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
and the DACL grants access through to the AppContainer (through a Package SID or Capability SID)
then the AppContainer can read, write, or execute depending on the access granted" [Implementing
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

- **Grants stay on disk.** A run never removes them; `sandy setup --remove` does (see "Removing
  the changes"). A run checks for its ACE and changes nothing when the ACE exists.
- **Old grants grant nothing.** When a path leaves the policy, or its level changes, no later
  process holds the old capability. The escape test
  `a_path_removed_from_the_policy_is_denied_at_the_next_run` checks this.
- **Concurrent runs do not conflict.** No run removes an ACE that another run needs. Adding an
  ACE means reading the DACL, adding the entry and writing the whole DACL back, so sandy holds
  a lock on `%LOCALAPPDATA%\sandy\locks\dacl-changes` while it changes a DACL.
  Without it, two runs that add different ACEs to the same object, such as one program in two
  AppContainers, could overwrite each other's ACE. The program cannot hold this lock: it is a
  file below `%LOCALAPPDATA%\sandy\locks`, which an AppContainer cannot open
  (`the_program_cannot_reach_the_coordination_files`). Changes by other tools, such as `icacls`,
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
reparse point). Hard links cannot be found this way. Measured on Windows 11 build 26200: an
AppContainer program cannot create a hard link to a file it may not write (`ERROR_ACCESS_DENIED`),
so it cannot give a file outside its writable paths a second name itself; a hard link that
already exists weighs on the resolver instead (see "Links and identity").

Measured once on Windows 11 build 26200: the propagation follows neither. After
`SetNamedSecurityInfoW` added an inheritable entry to a directory, a junction below it carried
the entry on the junction itself and nothing reached the directory it led to, and a directory
symbolic link carried nothing into its target either. The walk stays, because the behaviour is
not documented. `sandy setup --remove` does not walk: it only takes an entry away.

A path whose DACL the user cannot change makes `sandy run` fail with an error that names the
path, unless Windows already grants the level to all AppContainers. A path without DACL (NULL
DACL, everyone has full access) also makes the run fail; adding an ACE would take the user's
access away.

`sandy check` asks the same question for every policy path (`acl::grantable`, which opens the
path for `WRITE_DAC` and changes nothing) and reports FilesystemConfined as unavailable with the
path and the reason, so it does not report as enforced what `run` then refuses. A path whose
entry is already in place needs no change and passes. The owner of a file holds `WRITE_DAC`
whatever the DACL says, unless an OWNER RIGHTS entry (`S-1-3-4`) replaces the owner's rights,
so only such paths and paths the user does not own can fail this way
(`check_reports_a_path_whose_permissions_the_user_cannot_change`). A token with
`SeRestorePrivilege` enabled may change every DACL; then `check` and `run` both pass.

### Links and identity

The resolver compares files and not only paths: one directory reachable under two paths counts
as one, and a file with a second name inside a writable path counts as writable (see "Links and
file identity" in [DESIGN.md](DESIGN.md)). On Windows the identity of a file is the serial
number of its volume and its file ID (`FILE_ID_INFO`, or `BY_HANDLE_FILE_INFORMATION` on a file
system without 128-bit file IDs), read with the object opened for its attributes only. An object
whose identity sandy cannot read counts as the one it is compared with, so the check refuses
instead of passing it. The warning for a directory on `PATH` follows the spellings instead, the
one given and the canonical one, so it names only an overlap sandy sees. Such an object is, for
example, a directory behind a junction that a less trusted process made: an elevated process
does not follow it (`ERROR_UNTRUSTED_MOUNT_POINT`), and package managers of the user make such
junctions (`scoop\apps\<app>\current`). Junctions count as symbolic links, as `std::fs` counts
them. On Windows:

- A policy path, sandy's executable or the policy file reached through a junction or a
  symbolic link inside a writable path is refused, as a symbolic link there is on Linux and
  macOS: the program could point the entry elsewhere before the next start. Windows resolves
  `.` and `..` by their spelling before it looks a path up, also in the target of a relative
  symbolic link (measured on Windows 11 build 26200: `link\..\x` is `x` beside the link), and
  the resolver walks a path the same way
  (`escape_windows::refuses_a_policy_path_resolved_through_a_link_in_a_writable_path`,
  `refuses_a_policy_file_a_writable_path_reaches`,
  `refuses_a_sandy_executable_a_writable_path_reaches`).
- A hard link between a `read_write` and a `read_exec` path, or one that gives the program
  file, sandy's own executable or the policy file a second name inside a writable path, is
  refused (`escape::a_hard_link_between_writable_and_executable_paths_is_refused`,
  `escape::a_hard_link_of_the_program_into_a_writable_path_is_refused`). This weighs more here
  than on Linux and macOS: the rights live in the one security descriptor of the file, so the
  inheritable ACE of the writable parent would land on the file and stay there after the run. A
  file lists its own names (`FindFirstFileNameW`), so sandy asks the program file, the files
  that `read_exec` paths name, its own executable and the policy file directly, and walks the
  writable trees only for a `read_exec` directory. That keeps an ordinary run from walking every
  writable tree: the programs in `System32` have a second name in the component store
  (`WinSxS`), measured for `cmd.exe`.
- The sandboxed program cannot make such a second name itself: an AppContainer process is
  refused a hard link to a file it may not write, a junction that leaves its writable paths, and
  a symbolic link of any kind (it holds no `SeCreateSymbolicLinkPrivilege`), all measured on
  Windows 11 build 26200 (`the_program_cannot_plant_a_link_reaching_outside_its_writable_paths`).
  The check runs at the start, so a second name that a process outside the sandbox makes while
  the program runs is not seen, as on the other platforms.
- `sandy` is checked under the name it was started under, which `current_exe` reports on
  Windows, so a junction or symbolic link on the way counts.
- The backend's own checks, the system directories of rule 6 and the trusted user locations of
  rule 12, go through the same comparison (`PathIdentity`). Windows names these locations
  without the verbatim prefix (`\\?\`) that canonical paths carry; the identity of the
  directories on the way compares them all the same, and it also sees a location whose path
  leads through a junction inside a writable path, which neither its own spelling nor the one
  with its links resolved shows. A writable path spelled through a junction or a directory
  symbolic link is refused like the folder it leads to
  (`a_writable_path_through_a_junction_is_refused_like_its_target` and
  `a_writable_path_through_a_directory_symbolic_link_is_refused_like_its_target`, into the
  Startup folder and into `C:\Windows\Temp`). A path through a network share is refused for
  reasons of its own (see "Network and share paths" below).
- A grant is an entry on the object, so it travels with the object. A file renamed out of a
  granted directory, on the same volume, keeps the entry it inherited from that directory: a
  rename does not touch the security descriptor, and Windows recomputes inherited entries only
  when something propagates from the new parent. The program holds the capability of the
  directory for as long as the directory is in the policy, and an AppContainer token keeps
  `SeChangeNotifyPrivilege`, so no traverse check stops it from opening the file at its new
  place by the full path. Linux and macOS bind the rule to the path, where the moved file is
  denied at once. `escape_windows::a_file_moved_out_of_a_granted_directory_keeps_its_grant`
  records this. Closing it would mean a new capability per run and a fresh propagation over
  every policy path on every run.

`sandy check` prints a warning for the grant that travels with a file when the policy grants a
directory.

### Network and share paths

sandy refuses a policy path that resolves to a network share, at every access level:
`\\server\share\...`, an administrative share such as `\\localhost\C$\...`, and a mapped
network drive, which `canonicalize` turns into the path of its share (`\\?\UNC\...`).
`FilesystemConfined` is then unavailable, and the message asks for the local path instead.

Such a grant never worked for the program. Measured on Windows 11, a program in its AppContainer
got "Network access is denied" (`ERROR_NETWORK_ACCESS_DENIED`, 65) when it read a file or listed
the directory through `\\localhost\C$\...` and through a share made with `net share`, with
`ip = "none"` and with `ip = "all"`, which grants `internetClientServer` and
`privateNetworkClientServer`. What the grant did instead was harmful: the entry sandy added
through the share landed on the folder behind it, so the program read the file by its local
path; and the checks of rules 6 and 12 compared spellings then, so rule 6 did not see
`C:\Windows` behind `\\localhost\C$\Windows\Temp`. They compare file identity now, and a share
of the local disk reports the identity of the folder behind it (measured), but the refusal
stays, because the program cannot use such a grant. A share on another machine was not tested;
the refusal covers it the same way. `network_and_share_paths_are_refused` checks the refusal,
with the local path of the same folder as the control.

### Trusted user locations

Rule 12 of [DESIGN.md](DESIGN.md): a writable policy path may not reach a location of this user
that programs outside the sandbox read or execute later. It weighs here as much as on the other
platforms: a file the program creates keeps the entries it inherits from its parent, so the user
keeps read, write and execute on it although the AppContainer has no `FILE_EXECUTE`, and a
process of the user outside the sandbox runs it.
`review_windows::profile_folder_is_a_persistent_writable_but_not_executable_store` records
that for the profile folder: inside the sandbox the planted image does not load, outside it
does. A deny entry for the package SID would not help, because the AppContainer access check
ignores it (`acl::check_writable`), and rewriting the user's own DACLs is not something sandy
does.

The locations that are refused are in `sys::trusted_locations`:

| Location | Protected | Why |
|---|---|---|
| the user profile (`FOLDERID_Profile`, `USERPROFILE`) | itself | holds the locations below; a writable folder below it stays allowed |
| `FOLDERID_Startup`, `FOLDERID_CommonStartup` | the tree | Windows runs what is there at the next logon |
| `Documents\WindowsPowerShell`, `Documents\PowerShell` | the tree | the profile scripts of PowerShell 5 and PowerShell 7 |
| `%LOCALAPPDATA%\Microsoft\WindowsApps` | the tree | the app execution aliases, which the default `PATH` holds |
| `<profile>\.ssh` | the tree | `ProxyCommand` and `LocalCommand` in the configuration run programs |
| `<profile>\.cargo\config.toml`, `<profile>\.cargo\config`, and both in `CARGO_HOME` | the file | `build.rustc`, `build.rustc-wrapper` and target runners name programs that the next cargo command runs; the list is shared with Linux and macOS (`sandy_core::trust::cargo_configs`) |
| `%LOCALAPPDATA%\sandy` | the tree | sandy's own state: the policy of each running AppContainer, the lock files and the forwarded-port sockets |

The profile folder comes from the known folder and from `USERPROFILE`, because a service that
starts sandy with a minimal environment sets no variable. A location that does not exist counts,
because the program could create it. Paths are compared by file identity, as rules 3 and 4 compare
them (see "Links and identity").

Every absolute directory on sandy's `PATH` (`sys::path_locations`) is such a location too, and
rule 12 warns about it instead of refusing it, because a writable path that holds one is
ordinary work: a package cache whose `bin` folder is on `PATH`, for example. `sandy check`
exits 0 and prints a `warning:` line on standard error that names the writable path and the
folder. A folder below one of them is on no `PATH` and says nothing. A writable path that
reaches a refused location as well stays refused, `%LOCALAPPDATA%\Microsoft\WindowsApps` for
example, which the default `PATH` holds: the warning never replaces a refusal.

sandy's own folder is not a place a program runs from, but sandy reads it: a program that could
write there could rewrite the policy recorded for its own AppContainer, so that a run with
another policy joins the sandbox while it runs, or hold a lock byte that makes every later run of
the user wait. The user's local application data grants nothing to AppContainers, so only a
policy that makes the folder writable could open it, and that is refused
(`refuses_a_writable_path_into_sandys_state_folder`). A writable `%LOCALAPPDATA%` was refused
before already, because it holds `WindowsApps`.

The list is a heuristic and can never be complete: no list knows which files the programs of
this user trust. Among the things it does not cover are the registry autostart keys, which the
program cannot reach anyway (`escape_windows::cannot_add_a_registry_autostart_entry`), and a
hard link that already gives one of these files a second name inside a writable path.

### What the program can see

The sandbox refuses access, it does not hide what exists. Paths outside the policy answer:

| Path | Answer |
|---|---|
| An existing file outside the policy | `ERROR_ACCESS_DENIED` |
| An existing directory outside the policy | `ERROR_ACCESS_DENIED` |
| A name that does not exist next to it | `ERROR_FILE_NOT_FOUND`, `ERROR_PATH_NOT_FOUND` |

So the program can tell whether a path exists, and from the names it guesses it learns what the
user has. Hiding paths would need a separate view of the file system, which `DESIGN.md` names a
non-goal. The file case is recorded in
`review_windows::an_existing_path_outside_the_policy_is_told_apart_from_a_missing_one`.

Processes are different: the AppContainer gives the program a narrower view than the file system
does. The program cannot open the user's processes (see "Other processes"), and it cannot list
them either. Every enumerator that reads the whole process list outside the sandbox returns,
inside the AppContainer, only the pid 0 placeholder and the program's own AppContainer processes:
the program itself, its console host, and the relays of `expose` or `forward`, which run
`sandy.exe` in the same AppContainer. Measured on build 26200 for a Toolhelp snapshot
(`CreateToolhelp32Snapshot`), `EnumProcesses`, `NtQuerySystemInformation(SystemProcessInformation)`
and `WTSEnumerateProcessesW`; all four agree, and the control outside the sandbox lists the whole
machine. The low box (AppContainer) token filters the system process list, so this does not
depend on how the program was started: the same filtered list of three came back under the test
VM's network logon (its SSH session), under a scheduled task run as the user with an S4U
(batch-like) logon, and under a scheduled task run as SYSTEM. Process isolation is documented for
the AppContainer [AppContainer isolation], and the filtered list has been reported since Windows 8
[MalwareTech]; sandy supports Windows 10 1809 and later, where the mechanism predates the floor,
but the measurement here is on build 26200 only. The listing is recorded in
`review_windows::the_sandbox_process_list_holds_only_its_own_processes` and
`wts_process_enumeration_is_also_filtered`.

Two narrower facts about processes still reach the program:

- **A guessed process id.** The filtered list does not hide whether a given id is live. `OpenProcess`
  on an id outside the AppContainer answers `ERROR_ACCESS_DENIED` (5), and on an id that no process
  has answers `ERROR_INVALID_PARAMETER` (87), so by trying ids the program can still tell which are
  in use, as it can tell an existing path from a missing one. sandy cannot change this: the answer
  is the kernel's, and Windows gives the program no system-call filter to intercept it. Recorded in
  `review_windows::a_guessed_process_id_still_tells_existence_apart_from_absence`.
- **The session number.** The sandbox does not move the program into a session of its own, so
  `ProcessIdToSessionId` tells it the Terminal Services session it shares with sandy. This is the
  session number alone, nothing about other processes. Recorded in
  `review_windows::the_sandbox_runs_in_sandys_session`.

Two further routes to other processes could not be measured in the test VM's non-interactive
sessions. Window enumeration (`EnumWindows`, `FindWindow`) needs `user32.dll`, which cannot
initialize in an AppContainer in such a session (limitation 13); under `windows.win32k = "deny"`
the win32k system calls that back those functions are gone outright, so a program cannot enumerate
windows at all. WMI reaches a process list through COM, which also does not load in an AppContainer
in these sessions (see `com_services_outside_the_sandbox_are_unreachable`), and the COM boundary
denies the sandbox where COM does load. Both belong on an interactive session to measure, like the
ConPTY question (see the release notes). Performance-counter data (Perflib through the registry,
and PDH on top of it) was not measured.

### Removing the changes

Old grants grant nothing, so removing them is cleanup, not a security step.

`sandy setup --remove`, with the policy whose changes should go, does all of it:

- the loopback exemption of the AppContainer (administrator rights, and only when it is there);
- the access control entry of every policy path, and of `sandy.exe` for the relays. Only the
  capability SIDs sandy derives for this AppContainer and these objects are removed. Other
  software (Chromium, for example) uses capability SIDs too, and a capability SID cannot be
  mapped back to its name, so removing anything else would be guesswork;
- the AppContainer profile and its folder, with whatever the program left in its `TEMP`.

It is idempotent, it refuses while a run of that AppContainer is active, and it reaches nothing
that has left the policy: an entry on an object that is no longer a policy path stays, because
nothing records where it is. The same holds for the entry a run adds on the program file, unless
a policy path covers the program: `setup` takes no program, so name the file with
`--read-exec PROGRAM` for the removal, which derives the same capability. By hand, `icacls PATH` lists the entries as `*S-1-15-3-1024-...`
and `icacls PATH /remove:g *SID` removes one; the profile goes with
`DeleteAppContainerProfile`, for example from PowerShell:

```powershell
Add-Type -Namespace Win32 -Name UserEnv -MemberDefinition '[DllImport("userenv.dll", CharSet = CharSet.Unicode)] public static extern int DeleteAppContainerProfile(string name);'
[Win32.UserEnv]::DeleteAppContainerProfile("example.app")
```

The socket directories of forwarded ports clean themselves up: each run holds a lock file in
its own directory, opened without `FILE_SHARE_DELETE`, and every run with a forwarded port first
removes the directories whose lock file it can open exclusively, which only the directories of
ended runs are. A directory without a lock file stays, because a run creates the file just after
its directory (`the_sweep_leaves_a_socket_directory_without_a_lock_file`). sandy 1.3.2 created no
lock file, so the directories it left behind stay too; they hold no listener and can be deleted.

## Network

With `ip = "none"` the program gets no network capabilities. With `ip = "all"` it gets
`internetClientServer` (which includes `internetClient`) and `privateNetworkClientServer`
[Capabilities]. With `ip = "client"` it gets `internetClient` alone. Windows Firewall enforces
these rules through the Windows Filtering Platform. The plan reports `IpNetworkDenied` and
`InboundIpDenied` as unavailable when the firewall service (`MpsSvc`) does not run: whether
isolation holds without it is not documented, and Microsoft does not support stopping it.

Turning the firewall profiles off is a different matter, and an ordinary one: a third-party
firewall registered with Security Center, or a group policy, turns the Defender Firewall
profiles off while `MpsSvc` keeps running. Measured on Windows 11 build 26200, isolation holds
there. With `Set-NetFirewallProfile -All -Enabled False`, a connection from the program to a
host outside the machine still failed at once with `WSAEACCES` (10013), while the same
connection from outside the sandbox succeeded as the positive control; the profiles were then
restored to the state they had. The filters that carry the AppContainer rules sit in the
Windows Service Hardening sublayer, which the profiles do not switch. `sandy check` therefore
reads the service and not the profiles.

### Client networking

`internetClient` allows connections out to the internet and none in. Windows has no capability
for connections out into home and work networks alone: `privateNetworkClientServer` also lets the
hosts of such a network connect in. So under `ip = "client"` the program reaches no host of a
network that Windows counts as a private or domain network: one whose profile type is Private,
as Windows sets it for a home network, or a domain network. Names still resolve there, because
`getaddrinfo` asks the DNS Client service, which runs outside the AppContainer. `sandy check`
says so in a warning, and `ip = "all"` reaches those hosts.

Measured on Windows 11 build 26200, from the VM to the host of its virtual network, with the
firewall profiles off, because with them on Windows drops every connection from another host to a
program without a firewall rule, outside the sandbox too. The profiles and the profile type of
the network were restored afterwards.

| | profile type Private | profile type Public |
|---|---|---|
| `ip = "all"` | everything works, also a connection and datagrams from the host to ports of the program | the same |
| `ip = "client"`, out | `connect` to the host fails at once with `WSAEACCES` (10013); a DNS query of the program to the host's DNS server gets no answer; `getaddrinfo` of a name only that server knows works | `connect` to the host and a DNS query of the program to it work |
| `ip = "client"`, in | a connection to a port the program listens on, and a datagram to a port it bound, do not arrive | the same; a datagram from the host also does not arrive at the port the program had just sent a DNS query from, because it comes from another port of the host |

Outside the sandbox every inbound case arrived. Processes of the same machine are loopback
traffic, which loopback isolation drops in every setting (see "Loopback"); that is what
`ip_client_takes_no_connections` and `ip_client_datagrams_from_others` check, because the test
suite has no second host.

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
| Listening TCP socket created outside the AppContainer and passed on a standard handle | Worked, even with `ip = "none"`: the program accepted a connection from an outside client. sandy now refuses such a handle, so this needs `ip = "all"` | The program would have to accept on an inherited socket instead of its own |
| Relay inside the AppContainer: a process holding the inherited listening socket forwards each connection over loopback to the server process in the same AppContainer | Works with `ip = "none"` and `ip = "all"`, with and without exemption | Implemented as `network.expose`, see "Exposed ports" |
| Firewall rule for the package SID | Not tested; the AppContainer filters sit in the Windows Service Hardening sublayer, which ordinary firewall rules do not override [Project Zero 2021] | Administrator rights |

Processes in the same AppContainer reach each other over loopback in every configuration
measured, also with `ip = "none"` and without exemption. `network.expose` builds on this fact.

Because of the same fact, two sandboxes in the same AppContainer can talk over loopback, also
when their policies differ (for example one with `ip = "all"`). Processes in one AppContainer can
also open each other's processes. A program with a weaker policy could therefore take over a
program with a stronger policy that runs at the same time in the same AppContainer.

sandy enforces one policy per AppContainer at a time
(`crates/sandy-windows/src/sys/singleton.rs`):

- The identity is the AppContainer SID, not the name from the policy. Windows derives the SID
  from the name without regard to case, and so do the capability names and the profile folder,
  so `sandy.X` and `SANDY.x` are one sandbox (measured on build 26200: all spellings of a name
  give one SID). Keying on the name would let the two spellings run different policies side by
  side.
- While a program runs, sandy holds a shared byte range lock on a file named after the SID below
  `%LOCALAPPDATA%\sandy\runs`, which stores a fingerprint of the resolved policy: the path rules
  (including the program's own read and execute rule), the system set, `ip`, `unix_sockets`, the
  exposed and forwarded ports, `signals`, `children`, `end_with_parent`, `path_metadata` and
  `win32k`.
  Arguments, working directory and environment are not part of it. A second byte of the same
  file serializes the check.
- A second run in the same AppContainer with the same fingerprint may run at the same time. A run
  with a different fingerprint is refused with exit status 125 and the reason, until every run of
  the first policy has ended.
- The user's local application data grants nothing to AppContainers, so the program can neither
  read nor change the file (`the_program_cannot_reach_the_coordination_files`), and a policy
  that makes `%LOCALAPPDATA%\sandy` writable is refused (see "Trusted user locations"). The kernel
  releases the lock when the run that holds it exits, also after a crash, so no stale state
  blocks later runs. Runs with different policies one after the other stay allowed.
- A killed sandy frees the AppContainer only together with its program: kill-on-close ends the
  program's job when sandy dies (`a_killed_run_leaves_no_program_behind`).
- sandy 1.3.2 coordinated through a named kernel object instead. A run of 1.3.2 and a run of a
  later version do not see each other, so do not run both versions in one AppContainer at the
  same time.
- A file and not a named kernel object, because `Local\` is per logon session and in session 0,
  which services and SSH sessions run in, it is shared by every user's session 0 processes:
  another local user could hold sandy's mutex, which sandy waits for without a limit, or create
  the state object with permissions of their own. The locks that serialize sandy's permission
  changes and profile creation moved to `%LOCALAPPDATA%\sandy\locks` for the same reason. They
  no longer serialize two users who grant on the same file, which `Local\` did only in session 0
  anyway.

Use one AppContainer name per policy anyway: file grants and the loopback exemption belong to the
AppContainer, and two policies that share one cannot run at the same time.

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

`sandy setup` makes the loopback exemption of the policy's AppContainer match the policy: present
with `ip = "client"` and `ip = "all"`, absent with `ip = "none"`. With `--expose`, it also grants
the relays read and execute on `sandy.exe` (see "Exposed ports"). Run it once per machine as
administrator:

```text
sandy setup --appcontainer example.app --ip all     # add the exemption (also --ip client)
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
  of the program. The COM route to such a service is closed for the two services tested, BITS
  and the Schedule service (`com_services_outside_the_sandbox_are_unreachable`), and sandy
  refuses `children = "none"` together with `unix_sockets = "all"`. It is not closed by Windows
  in general: a COM server whose launch permission admits ALL APPLICATION PACKAGES is reachable
  by design, and DcomLaunch starts it outside the job. A default Windows 11 has no such server
  (`no_dcom_server_admits_all_application_packages`), and no policy key would close it, so on a
  host that has one the guarantee has to be measured again.
- **Contained child processes.** `process.children = "contained"` needs nothing beyond the job
  described above: the program's children join the job, sandy ends the job when the program
  exits, and the job closes when sandy dies. The program holds no handle to the job, and the
  AppContainer cannot open sandy, so it can neither leave the job nor end sandy early. `allowed`
  behaves the same on Windows; `contained` states the guarantee in the policy, so that the same
  policy is refused on platforms that cannot give it. The policy rules for `contained`
  (`unix_sockets = "none"`, `signals = "isolated"`) apply on Windows too.
- **The status record.** sandy is always the parent on Windows, so the caller's process handle
  names sandy and not the program, and exit code 125 means both "sandy refused" and "the
  program exited with 125". `--status-fd` reports what the exit code cannot, without changing
  any exit code: sandy writes `pid N` once the program runs, then `exited N`, or `failed` when
  sandy itself failed or refused. The number is an inheritable handle the caller passes to
  sandy, which clears its inherit flag at once; the program's own
  `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` names only its three standard handles, so the handle
  never reaches the program or a relay. A program that sandy ended because the parent ended is
  reported as `exited 1`, which is the exit code the job gets.
- **Ending with the parent.** With `process.end_with_parent = true`, sandy finds its parent's
  process ID in a process snapshot (`CreateToolhelp32Snapshot`), opens the process for waiting,
  and checks that it was created before sandy and still runs. Windows records only the parent's
  process ID, which another process can have once the parent has ended, and a process created
  after sandy cannot be its parent. An equal creation time counts as older; Windows 11 records
  creation times in 100 ns units (measured: 40 processes started in a row had 40 distinct
  times). This is an ordering test on the wall clock, so a system clock set back between the
  start of the parent and the start of sandy makes sandy refuse a running parent, and an early
  death of the parent, a clock set back and a reused process ID together could let an unrelated
  process pass. With `--parent-pid`, the recorded parent must also be the named process.
  `--parent-start` adds the caller's own creation time (`GetProcessTimes`, read after
  `OpenProcess`), and sandy then requires that exact value instead of the ordering test: no
  clock change alters a recorded creation time, and a process that got the ID later has another
  one. The named process then need not be the one Windows recorded as sandy's parent, so a
  wrapper such as `cmd /c` or `powershell` between the caller and sandy is allowed. sandy waits
  for the program and the parent together; when the parent ends, sandy ends the program's job
  (exit code 1) and finishes as after any end of the program. If ending the job fails, sandy
  reports the error, and closing the job ends the program. If the parent has already ended, sandy
  refuses to start the program; any other failure to open it is reported as such. The
  AppContainer cannot open sandy, so the program cannot keep sandy from doing this.
- **UI restrictions.** The job sets all documented UI restrictions: desktops, display settings,
  `ExitWindows`, global atoms, USER handles of other processes, the clipboard (read and write),
  and system parameters [UI restrictions]. Low integrity already blocks window messages, hooks
  and input to windows of higher integrity (UIPI) [Integrity].
- **Privilege escalation.** Children inherit the AppContainer token [Legacy apps]. The token
  normally keeps only `SeChangeNotifyPrivilege` and `SeIncreaseWorkingSetPrivilege` [Chromium
  design]. sandy relies on the AppContainer boundary that Microsoft services [MSRC] against
  elevation through system services. Starting a program with `requireAdministrator` or calling
  `runas` from an AppContainer is not tested.
- **Other processes.** A process created outside the AppContainer has a default DACL that grants
  nothing to the AppContainer SID, so the program cannot open it, read its memory or terminate it
  [Implementing an AppContainer]. The escape test `cannot_open_processes_outside` checks
  `PROCESS_VM_READ` and `PROCESS_TERMINATE`. The AppContainer token also filters the system
  process list, so the program cannot even list the user's processes; it sees only its own (see
  "What the program can see").
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

Windows has no pseudo-terminal device for `run` to refuse, as Linux and macOS do with
`signals = "isolated"` (DESIGN.md rule 13). A pseudoconsole (ConPTY) reads its input from an
ordinary anonymous pipe. The write end of such a pipe, handed to the program as a standard
stream, is a pipe like any other: `GetFileType` reports `FILE_TYPE_PIPE` for it, the same as for
the pipe of `program | sandy`, and nothing in the handle marks it as a console's input. sandy
therefore cannot tell it apart and cannot refuse it, and does not: rule 13 leaves the standard
streams to the caller and accepts a connected pipe (the caller that creates the ConPTY and hands
the program its input end chose that channel, as it chooses any pipe).

What such a write could do is a separate question: whether the bytes of a Ctrl+C (`0x03`) or a
Ctrl+Break reach the processes attached to the pseudoconsole as a console control event, which
would signal them without the check that `signals = "isolated"` applies. This could not be
measured here. A pseudoconsole does not run in the test VM's non-interactive SSH session: a
`CreatePseudoConsole` succeeds, but the console host it starts pumps no input or output to a
child (measured: a `cmd /c echo` attached to a ConPTY produced no output), the same window
station limitation as limitation 13. The question is open (see the release notes); by the ConPTY
design the delivery is expected, because a terminal's Ctrl+C reaches a ConPTY child exactly by
the terminal writing `0x03` to that input pipe. If a measurement on an interactive session
confirms it, it belongs in the exceptions table with a `check` warning for `signals = "isolated"`,
because sandy cannot distinguish or refuse the pipe.

## Win32k

`windows.win32k = "deny"` starts the program, and every process it starts, with the system calls
of win32k disabled (`PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON`,
set through the process attribute list sandy already builds and inherited by every child, as
Windows inherits an always-on mitigation). win32k is the part of the Windows kernel that serves
windows, input and drawing; `user32.dll` and `gdi32.dll` call it. It is a large, historically
bug-prone attack surface, and a command-line program needs none of it. The default is `"allow"`,
which changes nothing. The relays get the mitigation too, because the program can open them
(they run in its AppContainer) and would otherwise make the calls through them. sandy reads the
mitigation back with `GetProcessMitigationPolicy` before it lets each process run and refuses the
run if Windows did not apply it; `check` reports the requirement as enforced, or unavailable if
the mitigation cannot be set or read.

The key costs the program every library that needs win32k. **Many console programs load
`user32.dll`, whose initializer calls win32k, so they end at startup** with
`STATUS_DLL_INIT_FAILED` (`0xC0000142`) before their first instruction, whether in the sandbox or
not. This is the same failure as limitation 13 and cannot be told apart from it at a glance. Only
a program that loads no GUI library runs under the key.

Measured on the Windows 11 VM (build 26200), each program started outside the sandbox with the
mitigation and without it, so the AppContainer plays no part in the result:

| Starts with `win32k = "deny"` | Ends at startup with `win32k = "deny"` |
|---|---|
| `cmd.exe`, `hostname.exe`, `tar.exe`, `curl.exe`, `findstr.exe`, `sort.exe`, `more.com`, `xcopy.exe`, `reg.exe`, `icacls.exe`, `ipconfig.exe`, `attrib.exe`, `sandy.exe`, the `sandy-probe` test helper (a Rust console program built for `x86_64-pc-windows-gnu`) | Windows PowerShell 5 (`powershell.exe`), `whoami.exe`, `robocopy.exe`, `certutil.exe`, `tasklist.exe`, `cscript.exe`, `ssh.exe`, `timeout.exe`, `git.exe` |

PowerShell 7 (`pwsh`), `python` and `node` were not installed on the VM and were not measured;
nothing was installed to measure them. The rule to expect is simple: a plain console filter or
archiver tends to start, while anything that links `user32.dll` (much of the .NET and scripting
world, and tools that show progress UI) does not. Turn the key on only for a program you have
checked starts with it.

The key is Windows-only. On Linux and macOS a policy with `windows.win32k = "deny"` is accepted,
and the requirement is reported as enforced with the note that there is nothing to deny, because
those kernels have no win32k. This is how the other platform keys behave (`linux.path_metadata`
on Windows and macOS, for example): the key is never silently ignored, it maps to a requirement
every platform answers.

## Handles, environment and command line

- **Handles.** `bInheritHandles` is TRUE, but `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` limits
  inheritance to three handles [UpdateProcThreadAttribute]. A relay of an exposed port inherits
  its listening socket in addition. sandy duplicates each standard
  handle as an inheritable handle. A missing standard handle becomes the NUL device, and a
  console becomes a relayed pipe. A standard handle that is a socket would give the program
  network access through that socket, also with `ip = "none"`: AppContainer network isolation
  applies to sockets the AppContainer creates, not to sockets created outside it (verified on
  Windows 11 with a listening socket). This holds on every platform for inherited sockets, so
  `run` looks at the three standard handles before it duplicates them and accepts a socket only
  when the policy lets the program create one like it. Otherwise it refuses with exit code 125,
  naming the handle and the socket: an IP socket with `ip = "none"`, a listening or datagram IP
  socket with `ip = "client"` (a socket created outside keeps the rights of its creator in the
  firewall, so a disconnected datagram socket would receive from every host), an unconnected,
  datagram or listening AF_UNIX socket with `unix_sockets = "none"`, and under every policy a raw
  IP socket and a socket of any other family. Only an administrator can create a raw socket;
  sandy refuses an inherited one also when it runs as one, so that a policy means the same on
  every platform.
  The capabilities of `ip = "all"` cover IP networking only, and sandy grants no device capability
  such as `bluetooth`. Windows 11 creates an AF_BTH socket also in a virtual machine without a
  Bluetooth radio (measured), and before this rule sandy started the program with one on a standard
  handle under `ip = "all"`. A connected AF_UNIX stream socket is accepted, because it reaches only
  the peer it already has. Winsock tells a socket from a file, a pipe and a console: `GetFileType`
  reports `FILE_TYPE_PIPE` for a socket and a named pipe alike, while `getsockopt` with
  `SO_PROTOCOL_INFOW` answers only for a socket and names its family, type and protocol.
  `SO_ACCEPTCONN` exists only for sockets that can listen, so a datagram socket is named by what
  Windows does tell about it: it has no peer. `sandy check` cannot report any of this, because the
  handles it is given are not the handles of the later `run`.
- **Environment.** sandy builds the block from the policy, sorted by name, case-insensitive,
  "without regard to locale" [Environment]. It sets two variables, which replace policy values:
  - `SystemRoot`, from `GetSystemWindowsDirectoryW`. System DLLs need it; without it, for
    example, Winsock initialization fails.
  - `LOCALAPPDATA`, from `SHGetKnownFolderPath`. sandy loads `shell32.dll` for it at run time:
    `shell32.dll` loads `user32.dll`, which cannot initialize in some sessions (limitation 13),
    and the relays run `sandy.exe` in the AppContainer. Without the variable, `CreateProcessW`
    fails for an AppContainer process with `ERROR_ENVVAR_NOT_FOUND` (203). Windows replaces it
    with `<LOCALAPPDATA>\Packages\<name>\AC` and sets `TEMP` and `TMP` to the `Temp` folder
    below, also when the policy sets them. Microsoft documents the redirection [Implementing an
    AppContainer]; that the variable is required is not documented, it was observed on Windows 11
    build 26200.
- **Command line.** sandy quotes each argument so that `CommandLineToArgvW` and the C runtime
  read it back unchanged [Parsing arguments], and refuses command lines longer than 32,767
  characters [CreateProcessW]. It refuses `.bat` and `.cmd` programs: `CreateProcessW` runs them
  in `cmd.exe`, which parses arguments with other rules, so arguments could run commands
  [BatBadBut]. Run `cmd.exe /c` explicitly instead.
- **Program path.** `std::fs::canonicalize` returns `\\?\C:\...` paths. sandy passes the
  ordinary form to `CreateProcessW` when it names the same file. The first token of the command
  line, the program's `argv[0]`, is the program as the caller wrote it (`TargetCommand::arg0`), as
  on Linux and macOS, so multi-call programs see the name they were started under.

## Supported Windows versions

- **Required:** Windows 10 version 1809 (build 17763) or later, or Windows Server 2019 or
  later. Earlier builds do not export `DeriveCapabilitySidsFromName`, and none of them receives
  security updates any more. sandy resolves that function at run time, so `sandy check` still
  starts on older builds and reports why it cannot enforce the policy.
- **Network isolation:** `IpNetworkDenied` and `InboundIpDenied` also need the fix for
  CVE-2021-41338, a bypass of the AppContainer firewall rules. The plan refuses builds without
  it: 17763 before .2237, 18362 (never fixed), 18363 before .1854, 19041 to 19043 before .1288,
  20348 before .288 and 22000 before .258 [CVE-2021-41338]. The table lives in
  `crates/sandy-windows/src/version.rs`.
- **Expected to work, not tested:** Windows 10 1809 (LTSC 2019), 21H2 (LTSC 2021) and 22H2.
- **Tested:** Windows 11 build 26200 (VM, all tests), Windows Server 2022 and Windows Server
  2025 (GitHub Actions; all tests except the four that need AppContainer child processes, see
  limitation 11).
- **Nested jobs:** when sandy runs inside a job with UI restrictions, Windows refuses to put the
  program into sandy's own job (`ERROR_NOT_SUPPORTED`, measured on Windows 11), and the plan
  reports `NoPrivilegeEscalation` and `SignalsIsolated` as unavailable. Inside a job without UI
  restrictions, with or without breakaway, the jobs nest. sandy never breaks away from the outer
  job. Microsoft documents a stricter rule ("neither job sets UI limits") [Nested jobs], which
  the measurements on Windows 11, Server 2022 and Server 2025 do not show; Windows 10 is
  untested.

  A job sandy runs in can itself lie in a job, and `QueryInformationJobObject` reports the limits
  of the immediate job only: in a chain whose outer job has UI restrictions and whose immediate
  job has none, the restrictions read as 0 while the assignment still fails (measured on Windows
  11 build 26200). `sandy check` therefore tries the nesting (`Backend::verify`): it creates a job
  with the program's UI restrictions, starts a suspended process of `sandy.exe`, which joins
  sandy's job chain as the program would, assigns it to that job and terminates it again before
  it runs an instruction. The trial runs only for the case nothing else can answer, an immediate
  job without UI restrictions, so outside a job `check` touches nothing. `run` does not try: it
  finds out when it assigns the program.

## Diagnostic mode

`run --explain` is not available on Windows: sandy refuses the option here instead of reporting
nothing, which would read as "nothing was denied". The question it answers, "which grant does
this program need", is in [DESIGN.md](DESIGN.md), "Diagnostic mode", and the Linux
implementation is in [linux.md](linux.md).

Windows does not log an access denial by default. Object access auditing is off in the default
audit policy (measured on the Windows 11 VM: `auditpol /get /subcategory:"File System"` answers
`No Auditing`), and turning it on needs administrator rights (`auditpol /set /subcategory:"File
System"`), a SACL on each object sandy would have to write (which needs `SeSecurityPrivilege`),
and the Security event log to read the records, which also needs administrator rights. A
diagnostic that needs all three is not a diagnostic an integrator can run, and sandy must not
write SACLs on a user's directories to get it. There is no unprivileged alternative that
reports what the AppContainer denied: a denied access returns `ERROR_ACCESS_DENIED` to the
program and leaves no trace the program or sandy can read back.

`check --explain-path` is Linux only as well. What decides a path here is the access control
list of each object plus the AppContainer's capabilities, not a rule list sandy keeps, so an
answer would be a second opinion that can disagree with what the kernel does. A wrong answer
about a path is worse than none, so the backend answers nothing and sandy refuses the option.

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
6. sandy refuses to grant a directory that contains junctions or symbolic links, and a writable
   directory with a file below it that AppContainers may execute.
7. Ctrl+C ends the program; it cannot handle it.
8. The program's console is its own and has no window, and it never gets a console handle of
   sandy's. Programs that read passwords from `CONIN$` read from that console, which nobody
   types into, and wait forever. sandy writes the program's output to its own console as it
   is, except bytes that are not UTF-8, so escape sequences reach that console, which acts on
   them when virtual terminal processing is on, for example by setting the clipboard
   (DESIGN.md, "Non-goals").
9. A volume without ACLs (FAT, exFAT) cannot hold grants; sandy fails when a policy path lies
   there. Whether the AppContainer can access such volumes outside the policy depends on the
   security descriptor of the volume device and is not verified.
10. sandy removes the grants of a policy only through `sandy setup --remove`, and only those
    of the paths that policy names (see "Removing the changes").
11. On the GitHub Actions images `windows-2022` and `windows-2025` (Windows Server 2022 and 2025
    Datacenter), a process in an AppContainer cannot start child processes: `CreateProcessW`
    fails with `ERROR_ACCESS_DENIED` for every program, while the console host still starts.
    This holds for sandy and for a minimal launcher without job, capabilities or special flags,
    from the runner's process tree and from a scheduled task, elevated and not elevated. Ruled
    out: file ACLs, the working directory, the console, job objects, process mitigation
    policies, Defender, attack surface reduction, AppLocker, Code Integrity and UAC. The cause in
    the configuration of these images is not known. On Windows 11 build 26200 child processes
    work. Four checks therefore cannot run on these runners and record the skip
    `appcontainer-children`: `executes_only_executable_paths`,
    `children_none_denies_starting_programs`,
    `children_contained_ends_what_the_program_leaves_behind` and
    `children_none_denies_starting_a_system_program`. They belong in the expected-skip list of
    the runner, so that losing another check there is noticed. The execute right itself stays
    checkable without a child process: `load-library` maps an image inside the program's own
    process and needs `FILE_EXECUTE`, and `read_write_paths_are_not_executable` uses a copy
    in the `read_exec` path as the positive control (measured on Windows 11: that copy maps,
    the one in the read-write path does not).
12. `std::fs::canonicalize` and `GetFinalPathNameByHandleW` with DOS names fail with
    `ERROR_ACCESS_DENIED` inside an AppContainer (Windows 11 and Server 2025); NT names work.
    Programs that canonicalize their paths need a fallback such as `std::path::absolute`.
13. In a session whose window station does not admit AppContainers, such as an SSH session,
    `user32.dll` cannot initialize in an AppContainer process, and a program that loads it ends
    with `STATUS_DLL_INIT_FAILED` (`0xC0000142`) before its first instruction. Measured on
    Windows 11 over SSH; the same programs start from an interactive scheduled task. Programs
    without `user32.dll`, and the relays, are not affected.
14. If sandy itself is killed during a run with forwarded ports, its socket directory below
    `%LOCALAPPDATA%\sandy\forward` stays behind until the next run with a forwarded port
    removes it. Its sockets have no listener while it is there, so nobody can connect through
    them. A directory that sandy 1.3.2 left behind stays (see "Removing the changes").
15. A policy path on a network share, also through a mapped drive, is refused; name the local
    path (see "Network and share paths").
16. With `ip = "client"` the program reaches no host of a private or domain network (see
    "Client networking").
17. The program can lock a file it may only read: `LockFileEx` needs only a handle opened for
    reading, and Windows locks are mandatory, so while the program holds an exclusive lock, other
    processes can neither lock the file nor read or write it (measured on Windows 11:
    `ERROR_LOCK_VIOLATION`). The lock gives the program no access of its own. The test is
    `a_lock_on_a_readable_file_holds_off_other_processes`.

## Verified on Windows 11

Host: Windows 11 build 26200 (VM), binaries built for `x86_64-pc-windows-gnu`. The tests run in
an elevated SSH session and without administrator rights. Latest elevated run, every test
passing: `sandy_core` 65, `sandy_relay` 12, `sandy_windows` 77, `sandy` 14, `escape` 27,
`escape_windows` 63, `expose` 5, `forward` 3, `children` 5, `parent` 5, `check` 11, `runner` 3,
`review_windows` 11. The
COM check of `review_windows` is skipped there: the SSH session is session 0, where `ole32.dll`
does not load in an AppContainer (limitation 13), so a denial would not be the COM boundary.
Earlier non-administrator runs used a scheduled task with `/RL LIMITED` (medium integrity,
Administrators deny-only). The latest one used `runas /trustlevel:0x20000` (Administrators
deny-only, high integrity), because the VM had no interactive logon session for an `/IT` task:
every test passed except two outside controls of `review_windows` (BITS activation and listing
`C:\Users\Public`), which that token may not do, so those tests correctly refuse to judge.

Facts these runs established:

- A program starts in an AppContainer with `CREATE_NO_WINDOW` and gets its own console.
- Writes, deletes and directory creation in read-write paths work without an integrity label.
- AppContainer processes can use AF_UNIX.
- A UDP socket and a listening TCP socket passed as the standard input of `sandy run` are
  refused with exit code 125 before the program starts, and the outside control shows both
  working without the sandbox (`a_socket_on_standard_input_gives_no_network_access`).
- An AF_BTH (Bluetooth RFCOMM) socket passed as the standard input of `sandy run` is refused
  with `ip = "all"` and with `ip = "none"`, while a pipe and a connected TCP socket with
  `ip = "all"` start the program (`a_socket_of_another_family_on_standard_input_is_refused`).
- A raw ICMP socket, which the elevated test session can create, passed as the standard input of
  `sandy run` is refused with `ip = "all"` and with `ip = "none"`; before this rule sandy
  started the program with it under `ip = "all"` (`a_raw_ip_socket_on_standard_input_is_refused`).
- `NetworkIsolationGetAppContainerConfig` works without administrator rights.
- Listening on loopback succeeds without capabilities; incoming connections time out, also with
  the exemption. Outbound connections to the internet fail with `WSAEACCES` (10013).
- With `ip = "client"` the program connects to a loopback listener outside through the
  exemption and gets the answer of a DNS server on loopback; a connection to its listener and
  datagrams to its sockets from processes outside the AppContainer do not arrive, also a
  datagram from a third party after the program sent to another peer (`ip_client_connects_out`,
  `ip_client_takes_no_connections`, `ip_client_datagrams_from_others`). The measurements with a
  second host are in "Network".
- A working directory outside the policy does not prevent the start; the program cannot list it.
- `DeleteAppContainerProfile` from the PowerShell snippet above removes a profile and its
  folder.
- The program cannot open other processes of the user (`PROCESS_VM_READ`, `PROCESS_TERMINATE`),
  write to the registry autostart key, open a named pipe with the default DACL, or receive
  inherited handles other than the standard ones.
- The program cannot list the user's processes. A Toolhelp snapshot, `EnumProcesses`,
  `NtQuerySystemInformation(SystemProcessInformation)` and `WTSEnumerateProcessesW` each return,
  inside the AppContainer, only the pid 0 placeholder and the program's own AppContainer processes
  (itself and its console host), while the control outside lists the whole machine (107 processes
  in the latest run). The same filtered list came back under the SSH (network) logon, a scheduled
  task with an S4U logon as the user, and a scheduled task as SYSTEM, so the filter is the low box
  token, not the logon type. `OpenProcess` still tells an existing process id outside the
  AppContainer (`ERROR_ACCESS_DENIED`) from one no process has (`ERROR_INVALID_PARAMETER`), and
  `ProcessIdToSessionId` reports the session the program shares with sandy.
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
- The AppContainer access check honors a reduced `WRITE_DAC` for the package SID, not only a
  reduced `FILE_EXECUTE`: after the reduction the program cannot open its own profile folder or
  a file in it for `WRITE_DAC`, and cannot grant ALL APPLICATION PACKAGES execute on it.
- `DeriveAppContainerSidFromAppContainerName` ignores the case of the name: `sandy.Case-Test`,
  `sandy.case-test` and `SANDY.CASE-TEST` give one SID.
- `GetAppContainerFolderPath` on the SID string returns `...\Packages\<name>\AC` for a
  registered profile.
- IP isolation holds with the Defender Firewall profiles off. With all three profiles disabled
  and `MpsSvc` running, a connection from the program to a host outside the machine still
  failed with `WSAEACCES`, while the same connection succeeded outside the sandbox.
- A connection from the program to this machine's own address outside loopback times out, with
  the profiles on and off: that is the loopback filter, which answers with a timeout, not the
  capability filter, which answers with `WSAEACCES`.
- The program cannot open a process of the user for `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`,
  `PROCESS_DUP_HANDLE`, `PROCESS_CREATE_THREAD`, `PROCESS_SET_INFORMATION`, `PROCESS_SET_QUOTA`,
  `PROCESS_SUSPEND_RESUME`, `PROCESS_QUERY_INFORMATION` or `PROCESS_ALL_ACCESS`, nor one of its
  threads for `THREAD_TERMINATE`, `THREAD_SUSPEND_RESUME`, `THREAD_GET_CONTEXT`,
  `THREAD_SET_CONTEXT`, `THREAD_SET_INFORMATION`, `THREAD_QUERY_INFORMATION` or
  `THREAD_ALL_ACCESS`, while the owner outside the sandbox can.
- No `AppID` under `HKLM\SOFTWARE\Classes\AppID` has a launch permission that allows ALL
  APPLICATION PACKAGES, so no DCOM server is reachable that way on a default install.
- The administrator's SSH session has `SeBackupPrivilege`, `SeRestorePrivilege` and
  `SeTakeOwnershipPrivilege` enabled, so sandy there may change every DACL, also one that gives
  OWNER RIGHTS read access only. A test about a DACL the user cannot change runs sandy without
  privileges (`check_reports_a_path_whose_permissions_the_user_cannot_change`).
- `SetNamedSecurityInfoW` did not carry an inheritable entry through a junction or a directory
  symbolic link into its target (see "How sandy changes a DACL").
- An AppContainer program cannot create a hard link to a file outside its writable paths, a
  junction that points out of them, or a symbolic link of any kind (the token holds no
  `SeCreateSymbolicLinkPrivilege`), while the file owner can do all three outside the sandbox
  (`the_program_cannot_plant_a_link_reaching_outside_its_writable_paths`). It can still hard-link
  or junction within its writable paths.
- Windows resolves `..` in the target of a relative symbolic link by its spelling, and a
  verbatim path with `..` after a junction does not resolve. `FindFirstFileNameW` gives
  `C:\Windows\System32\cmd.exe` a second name in `WinSxS`. Through `\\localhost\C$`,
  `FILE_ID_INFO` reports the volume serial number and file ID of the local folder, and
  `FindFirstFileNameW` fails with `ERROR_NOT_SUPPORTED` (see "Links and identity").
- The elevated SSH session does not follow a junction that the sandboxed program made, or one
  that scoop made for the user: opening a path through it fails with
  `ERROR_UNTRUSTED_MOUNT_POINT` (448), while a junction that the session made itself is
  followed (`warns_only_about_path_directories_a_writable_path_really_holds`).
- The AppContainer token holds only `SeChangeNotifyPrivilege` and `SeIncreaseWorkingSetPrivilege`,
  with and without `children = "none"`, while the elevated session outside holds two dozen; it
  can enable no privilege beyond those two.
- `setup --remove` leaves the entry of a run on the program file, and removes it when the
  removal names the program with `--read-exec`
  (`setup_remove_takes_back_the_program_entry_only_when_named`).
- `ITaskService::Connect` reaches the Schedule service from outside the sandbox, so the
  task-scheduler probe is a real control. `CLSID_TaskScheduler` is an in-process class, which is
  why activating it with `CLSCTX_LOCAL_SERVER` fails everywhere and proves nothing.
- With `windows.win32k = "deny"`, `GetProcessMitigationPolicy` reports `DisallowWin32kSystemCalls`
  set for the program, for every process it spawns, for its console host, and for the relays; a
  win32k call (`CreateCompatibleDC` through `gdi32.dll`) then fails, and without the key it works.
  Programs that load `user32.dll` (`whoami.exe`, Windows PowerShell 5, and the others in the
  table under "Win32k") end with `STATUS_DLL_INIT_FAILED`; plain console programs (`cmd.exe`,
  `tar.exe`, `curl.exe`, the Rust `sandy-probe`) run.
- A pseudoconsole does not attach a child in the SSH session: `CreatePseudoConsole` returns
  `S_OK`, but a `cmd /c echo` started with the pseudoconsole attribute produced no output on the
  pipe and received no input, so the ConPTY Ctrl+C route could not be measured there (see
  "Processes, privileges and signals").

## Sources

- [AF_UNIX] AF_UNIX comes to Windows: https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/
- [AppContainer isolation] https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation
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
- [MalwareTech] Advanced desktop application sandboxing via AppContainer: https://malwaretech.com/2015/09/advanced-desktop-application-sandboxing.html
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
