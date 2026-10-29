# sandy Windows backend on Windows 10: support analysis

## Answer

1. **Expected to work from Windows 10 version 1809 (build 17763) through 22H2 (build 19045).** This includes LTSC 2019 (1809) and LTSC 2021 (21H2). Nothing was run on a Windows 10 host. The evidence is Microsoft Learn, the Chromium sources, Project Zero, the import table of a fresh build, and CI on Server 2022 (build 20348).
2. **On 1507 to 1803, `sandy.exe` cannot enforce the policy.**
   - It needs `DeriveCapabilitySidsFromName`, from `api-ms-win-security-base-l1-2-2.dll` (host: KernelBase).
   - Chromium's test code says Windows 10 versions older than 1809 do not implement this function. A Microsoft sample that calls it directly gives build 15063 (1703) as its minimum, so the exact first build is **unverified**.
   - The research found a load-time import, which would have stopped the process before `main` ran. sandy now resolves the function at run time (`crates/sandy-windows/src/sys/host.rs`), so `sandy.exe` starts on such a build and `sandy check` reports the requirements that need the function as unavailable, with the reason.
3. **Every other API, flag and attribute the backend uses exists since Windows 8 or earlier.** The other version-dependent points are about security fixes and side features, not about missing APIs.
4. **Security floor.** CVE-2021-41338 (a bypass of the AppContainer firewall rules) was fixed in October 2021 for 1507, 1607, 1809, 1909, 2004, 20H2 and 21H1. 1511, 1703, 1709, 1803 and 1903 never got the fix. A host without the fix cannot enforce `IpNetworkDenied`.
5. **In October 2026, only these Windows 10 hosts get security updates:** 22H2 with ESU, LTSC 2021, LTSC 2019 and IoT LTSC 2021. sandy should support exactly these hosts and refuse the others.

## How I checked

- **Code.** I read `crates/sandy-windows/src/**`, `docs/windows.md`, the Windows section of `docs/DESIGN.md`, the probe and `escape_windows.rs`. No repository file was changed during the research (`git status` was clean).
- **Build.** I built `cargo build --release --target x86_64-pc-windows-gnu -p sandy-cli --bins` with rustc 1.98.1 into a temporary directory outside the repository. I then dumped the import table of `sandy.exe` with `llvm-readobj --coff-imports`. The build was temporary and is not kept; the commands above reproduce it.
- **Linking.** windows-sys 0.61.2 links every function through `windows-link` 0.2.1 with `kind = "raw-dylib"`. These are ordinary load-time imports with no delay-loading. So every imported export must exist on the host, or the binary does not load.
- **CI.** I read the log of a CI run on `windows-2022` (Server 2022, build 20348). The log was a temporary download and is not kept. The closest earlier evidence is Windows 11 build 26200 and Server 2025.

## 1. APIs, flags, attributes, SIDs and undocumented mechanisms

"Checked" means I fetched the Microsoft Learn page in this session. "Not re-fetched" means the minimum version is from memory of Microsoft Learn. All of those are Windows XP or 2000 era and not in question.

### 1a. Functions imported by `sandy.exe` (backend part)

| Function | DLL in import table | Minimum client (Microsoft Learn) | Windows 10 note |
|---|---|---|---|
| [CreateAppContainerProfile](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile) | userenv.dll | Windows 8 (checked) | none |
| [DeriveAppContainerSidFromAppContainerName](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-deriveappcontainersidfromappcontainername) | userenv.dll | Windows 8 (checked) | none |
| [DeriveCapabilitySidsFromName](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-derivecapabilitysidsfromname) | api-ms-win-security-base-l1-2-2.dll (host: KernelBase) | Page says "Windows XP", which is wrong | **Only import that blocks old builds.** Chromium says Windows 10 before 1809 does not implement it ([sid_unittest.cc](https://chromium.googlesource.com/chromium/src/+/a3dafb8/base/win/sid_unittest.cc)). The Microsoft [CustomCapability sample](https://github.com/Microsoft/Windows-universal-samples/tree/main/Samples/CustomCapability) calls it directly and lists build 15063. A kernelbase export list of pre-release build 10130 ([NirSoft](https://windows10dll.nirsoft.net/kernelbase_dll.html)) does not contain it. Unverified on real 1607 to 1803 hosts. |
| [NetworkIsolationGetAppContainerConfig](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-networkisolationgetappcontainerconfig) / [...Set...](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-networkisolationsetappcontainerconfig) | api-ms-win-net-isolation-l1-1-0.dll (host: firewallapi) | Windows 8 (checked) | Reading without admin rights was verified on Windows 11 only. |
| [UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute), InitializeProcThreadAttributeList, DeleteProcThreadAttributeList | kernel32 | Vista (checked) | none |
| [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw), ResumeThread, TerminateProcess, GetExitCodeProcess, GetCurrentProcess | kernel32 | XP (not re-fetched) | none |
| CreateJobObjectW, [SetInformationJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-setinformationjobobject), [AssignProcessToJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject), TerminateJobObject | kernel32 | XP (checked for Assign) | Nesting rules of Windows 8 and later apply. See 2.6. |
| [GetFileInformationByHandleEx](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex) with [FileIdInfo](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ne-minwinbase-file_info_by_handle_class) | kernel32 | FileIdInfo: "not supported before Windows 8" (checked) | The [FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info) page says client "None supported". That is a documentation error. |
| CreateFileW, GetFileType, CreatePipe, DuplicateHandle, SetHandleInformation, CreateMutexW, ReleaseMutex, WaitForSingleObject, GetProcessHeap, HeapFree, LocalFree, GetSystemWindowsDirectoryW | kernel32 | XP or 2000 (not re-fetched) | `Local\` mutexes: an AppContainer has its own namespace since Windows 8. |
| GetConsoleMode, GetStdHandle, SetConsoleCtrlHandler | kernel32 | 2000 (not re-fetched) | See 2.7. |
| GetNamedSecurityInfoW, SetNamedSecurityInfoW, SetEntriesInAclW, GetAce, GetAclInformation, GetSecurityDescriptorControl, IsValidSid, GetLengthSid, FreeSid, CreateWellKnownSid | advapi32 | XP (not re-fetched) | none known |
| OpenSCManagerW, OpenServiceW, QueryServiceStatus, CloseServiceHandle | advapi32 | XP (not re-fetched) | none |
| RegOpenKeyExW, RegCloseKey | advapi32 | 2000 (not re-fetched) | none |
| [SHGetKnownFolderPath](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath) (FOLDERID_LocalAppData, KF_FLAG_DEFAULT) | shell32 | Vista (checked) | none |
| CoTaskMemFree | combase.dll | Microsoft Learn names ole32 (2000). combase.dll exists since Windows 8. | none |
| Rust std: [WaitOnAddress](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitonaddress), WakeByAddressSingle, WakeByAddressAll | api-ms-win-core-synch-l1-2-0 | Windows 8 (checked) | none |

**Note on API set names.** On Windows 10 the loader ignores the part of an API set name after the last hyphen ([Geoff Chappell](https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm)). So `...-l1-2-2.dll` resolves to KernelBase on every Windows 10 build. What decides the outcome is whether KernelBase exports `DeriveCapabilitySidsFromName`.

### 1b. Flags, attributes and structures

| Item | Minimum | Note |
|---|---|---|
| PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, [SECURITY_CAPABILITIES](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_capabilities) | Windows 8 (checked) | |
| PROC_THREAD_ATTRIBUTE_HANDLE_LIST | Vista (checked) | Handles must be inheritable and not pseudo handles. |
| [EXTENDED_STARTUPINFO_PRESENT, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CREATE_NO_WINDOW, STARTF_USESTDHANDLES](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags) | XP or Vista (checked) | |
| [JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, ..._DIE_ON_UNHANDLED_EXCEPTION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information) | XP (checked) | |
| [JOBOBJECT_BASIC_UI_RESTRICTIONS](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_ui_restrictions) (8 flags) | XP (checked) | They block job nesting. See 2.6. |
| PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY (LPAC) | not used | Chromium: LPAC APIs are unsupported below 1703 ([features.cc](https://chromium.googlesource.com/chromium/src/+/main/sandbox/features.cc)). |

### 1c. SIDs and capabilities

| Item | Minimum | Note |
|---|---|---|
| [WinCapabilityInternetClientServerSid, WinCapabilityPrivateNetworkClientServerSid, WinBuiltinAnyPackageSid](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-well_known_sid_type) | Windows 8 ("not available" before; checked) | |
| ALL APPLICATION PACKAGES `S-1-15-2-1` | Windows 8 | |
| ALL RESTRICTED APPLICATION PACKAGES `S-1-15-2-2` (named in the plan text only) | LPAC era | The Windows 10 [STIG](https://www.stigviewer.com/stigs/microsoft_windows_10/2025-02-25/finding/V-220717) confirms it on Program Files. |
| Hash-based capability SIDs `S-1-15-3-1024-...` | Windows 10 naming scheme | Derived as SHA-256 of the upper-cased name ([ntdoc](https://ntdoc.m417z.com/rtlderivecapabilitysidsfromname), Chromium [sid.cc](https://chromium.googlesource.com/chromium/src/+/main/base/win/sid.cc)). |

### 1d. Undocumented mechanisms

| Mechanism | Windows 10 status |
|---|---|
| `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\<SID>` | The `Mappings` subkey is undocumented. A Windows 8 era Microsoft page names the parent key `...\CurrentVersion\AppContainer` as the place where app IDs are stored ([hh780593](https://learn.microsoft.com/en-us/previous-versions/windows/apps/hh780593(v=win.10))). The Windows 10 layout is expected to be the same but is unverified. sandy has a safe fallback. |
| `LOCALAPPDATA` must be in the environment block | The failure without it (error 203) is undocumented. Microsoft's own [microsoft/mxc PR 1158](https://github.com/microsoft/mxc/pull/1158) says it requires "SystemRoot + LOCALAPPDATA". The redirection of `LOCALAPPDATA`, `TEMP` and `TMP` **is** documented ([Launch an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)). |
| Service name `MpsSvc` | Stable since Vista. |
| An exempt AppContainer reaches loopback without capabilities | [Project Zero 2021](https://projectzero.google/2021/08/understanding-network-access-windows-app.html), analyzed on Windows 10 21H1. |

## 2. Version-dependent behavior

### 2.1 Load-time imports
This is the main version gate (see 1a).
- **Fact:** `sandy.exe` statically imports `DeriveCapabilitySidsFromName`.
- **Lead:** Chromium loads it dynamically and says builds before 1809 lack it.
- **Lead:** Chromium's AppContainer sandbox itself requires 1809 (`IsAppContainerSandboxSupported`). Its reasons are LPAC and process mitigations, which sandy does not use.
- **Unresolved:** whether 1703 to 1803 export the function. The Microsoft sample conflicts with Chromium.

### 2.2 AF_UNIX
- First in Insider build 17063 ([Microsoft devblog](https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/)). The first release with it is 1803 (build 17134).
- Connecting needs write permission on the socket file. Abstract addresses, datagram sockets, socketpair and ancillary data are unsupported.
- On builds before 1803, `UnixSocketsDenied` holds trivially because AF_UNIX does not exist. The proposed AF_UNIX server workaround is unavailable there.
- On 1809 and later this is expected to work but is unverified on Windows 10. It was verified on Windows 11 and on Server 2022 CI, which passed the three AF_UNIX escape tests.

### 2.3 Loopback isolation, the exemption, and inbound loopback
- The blocking filter is in the receive and accept layer (ALE_AUTH_RECV_ACCEPT), in the Windows Service Hardening sublayer. That sublayer is "used to group Windows Service Hardening rules which apply regardless of the normal firewall configuration" ([Project Zero 2021](https://projectzero.google/2021/08/understanding-network-access-windows-app.html)). So turning off the firewall profiles while MpsSvc keeps running should not remove AppContainer isolation. This is inferred and should be tested.
- **Inbound loopback** to an AppContainer has been blocked since Windows 8. A listener on loopback "is prevented from receiving any incoming packets" ([hh780593](https://learn.microsoft.com/en-us/previous-versions/windows/apps/hh780593(v=win.10))). Microsoft's [IPC page](https://learn.microsoft.com/en-us/windows/apps/develop/communication/interprocess-communication) offers only `CheckNetIsolation LoopbackExempt -is`, which must keep running. Package-to-package `LoopbackAccessRules` need 1703 and a package identity, so sandy cannot use them ([uap4](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-uap4-loopbackaccessrules)).
- The behavior is expected to be identical on Windows 10. It is unverified there.

### 2.4 A listening socket inherited into the AppContainer
- **Mechanism (Project Zero, Windows 8 to 11):** "the TCP/IP driver will capture the security context of the creating process and store that for later use by the firewall."
- **Result:** a socket that sandy creates outside the AppContainer carries sandy's security context. The AppContainer filters do not apply to it, and the incoming SYN is classified against the listener's context. This matches the Windows 11 measurement. It is expected on Windows 10 but unverified.
- Sockets are inheritable by default ([WSASocketW](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketw)).
- **Unverified risk:** with a non-IFS layered service provider (LSP), a `SOCKET` may not be a real kernel handle. The handle list and `DuplicateHandle` then may not work.
- **Security consequence on every version:** the socket gives the program an inbound channel even with `ip = "none"`. Bind it to 127.0.0.1 only, and present it in the plan as a deliberate exception.

### 2.5 Firewall service and CVE-2021-41338
The CVE record ([cve.org API](https://cveawg.mitre.org/api/cve/CVE-2021-41338)) gives these fixed builds:

| Version | Fixed from |
|---|---|
| 1507 | 10240.19086 |
| 1607 | 14393.4704 |
| 1809 | 17763.2237 |
| 1909 | 18363.1854 |
| 2004, 20H2, 21H1 | 1904x.1288 |
| 1511, 1703, 1709, 1803, 1903 | never fixed |

21H2 and 22H2 were released after the fix (inferred from release dates). Also, [CVE-2018-0821](https://cveawg.mitre.org/api/cve/CVE-2018-0821) is an AppContainer elevation of privilege that affected 1507 to 1709, fixed in February 2018.

### 2.6 Job objects
- **Not version-dependent within Windows 10:** the UI restriction flags exist since XP.
- **Nested jobs exist since Windows 8, with a limit.** A process already in a job can join another job only if "it cannot have UI limits set" ([AssignProcessToJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject), [Nested jobs](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs)).
- **Consequence:** if sandy itself runs inside a job that does not allow breakaway, `AssignProcessToJobObject` fails. Examples are some CI agents, service hosts and IDE launchers. sandy then reports "cannot put the program into the job object". This fails closed, but `sandy check` does not predict it.

### 2.7 Console
- **Status quo.** sandy never shares its console. The program gets its own hidden console through `CREATE_NO_WINDOW`, and the standard handles are relayed through pipes.
- **sandy's own console.** On 22H2 it is normally classic conhost. With Windows Terminal it is ConPTY (`CreatePseudoConsole` needs 1809, not re-fetched). Console detection (`GetFileType` plus `GetConsoleMode`) and the UTF-16 relay work with both. Expected, unverified on Windows 10.
- **[Synacktiv 2021](https://www.synacktiv.com/sites/default/files/2021-10/AppJailLauncher.pdf):** before 1803 an AppContainer process "can't create connection" to a console. From 1803 to 1909 an integrity check blocked writes to console input. From 2004 to 21H1 writes were possible (CVE-2021-41346, fixed in builds .1288, Microsoft's [wrong-way verbs](https://learn.microsoft.com/en-us/windows/console/console-buffer-security-and-access-rights)). sandy is not affected because it never shares the console.
- **Open question:** whether a console program in an AppContainer can start with its own `CREATE_NO_WINDOW` console before 1803 is unverified. This matters only if support below 1809 is ever pursued.

### 2.8 LOCALAPPDATA and the profile registry mapping
- **LOCALAPPDATA:** sandy sets it unconditionally, so the requirement is harmless on any version.
- **Mappings key:** if the key is missing on some Windows 10 build, sandy calls `CreateAppContainerProfile` on every run. That call returns `ERROR_ALREADY_EXISTS`, which sandy handles. That path reintroduces the concurrency failure observed on Windows 11. Whether that failure happens on Windows 10 is unknown.
- **Corroboration (inference):** Chromium also serializes profile registration with a named mutex. It uses the undocumented `AppContainerRegisterSid` instead of `CreateAppContainerProfile` ([app_container_base.cc](https://chromium.googlesource.com/chromium/src/+/main/sandbox/win/src/app_container_base.cc)).

### 2.9 LPAC
Not needed. sandy's requirements use the normal AppContainer. `system = "none"` stays unavailable because LPAC keeps the `S-1-15-2-2` grants. LPAC also needs 1703 or later.

### 2.10 CI evidence on Server 2022 (build 20348)
- `sandy check`: every requirement enforced.
- Unit tests: 46 of 46. `escape_windows`: 21 of 21.
- `escape`: 9 of 10. `executes_only_executable_paths` failed with "Access is denied (os error 5)". The sandboxed probe could not start a copy of itself from a read-exec path under `C:\Users\runneradmin\AppData\Local\Temp`.
- The same failure occurs on windows-2025 but not on the Windows 11 VM. The cause is unknown. It is a functional failure, not an escape, and Windows 10 may show it too.
- Build 20348 is a newer codebase than 19045, so these results are supporting evidence only.

## 3. Rust toolchain

- **Rust 1.98.1** (the pinned toolchain): `x86_64-pc-windows-msvc` and `x86_64-pc-windows-gnu` both need "Windows 10 or higher for client, Server 2016 or higher for server". This is from the local 1.98.1 rustc book; online: [windows-msvc](https://doc.rust-lang.org/rustc/platform-support/windows-msvc.html), [platform support](https://doc.rust-lang.org/rustc/platform-support.html). The floor was set in Rust 1.78 ([blog](https://blog.rust-lang.org/2024/02/26/Windows-7/)). No specific Windows 10 build is named. The std imports in the build are Windows 8 level.
- **gnu target:** links `msvcrt.dll`, which is part of Windows.
- **msvc target:** links the C runtime dynamically by default ([Rust reference](https://doc.rust-lang.org/reference/linkage.html#static-and-dynamic-c-runtimes)). It then needs `vcruntime140.dll` from the VC++ redistributable unless built with `+crt-static`. This is from the reference; I did not build an msvc binary.
- **windows-sys 0.61.2:** `rust-version = 1.71`. It documents no OS floor. Each function is imported with `raw-dylib`, so the OS floor equals the newest function sandy calls. Today that is `DeriveCapabilitySidsFromName`.

## 4. Windows 10 support status (as of 2026-10-22)

| Edition | Support status |
|---|---|
| Home, Pro, Enterprise, Education 22H2 | Ended October 14, 2025 ([lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro)). All other general-availability versions ended earlier. |
| Consumer ESU | Microsoft's [ESU page](https://www.microsoft.com/en-us/windows/extended-security-updates) now says updates continue "through October 12, 2027". From memory, earlier announcements said October 13, 2026; I did not re-check this. |
| Commercial ESU | Up to three years after end of support, so to October 2028. $61 per device in year one, doubling each year. Requires 22H2 ([ESU](https://learn.microsoft.com/en-us/windows/whats-new/extended-security-updates)). |
| LTSC 2021 (21H2, 19044) | Ends January 12, 2027 ([page](https://learn.microsoft.com/en-us/lifecycle/products/windows-10-enterprise-ltsc-2021)) |
| IoT LTSC 2021 | Ends January 13, 2032 ([page](https://learn.microsoft.com/en-us/lifecycle/products/windows-10-iot-enterprise-ltsc-2021)) |
| LTSC 2019 (1809, 17763) | Ends January 9, 2029 ([page](https://learn.microsoft.com/en-us/lifecycle/products/windows-10-enterprise-ltsc-2019)) |
| LTSB 2016 (1607) | Ended October 13, 2026 ([lifecycle](https://learn.microsoft.com/lifecycle/products/windows-10-2016-ltsb)). A paid ESU exists per [Windows Central](https://www.windowscentral.com/microsoft/windows-11/microsoft-preps-esu-for-windows-10-ltsb-releases-retiring-in-2026) (secondary source). |

## 5. Conclusion and recommended checks

### Per version

| Version (build) | Does `sandy.exe` load? | CVE-2021-41338 fixed | Serviced in Oct 2026 |
|---|---|---|---|
| 1507 (10240) to 1607 (14393) | probably not (2.1) | 1507 and 1607 only | no (LTSB 2016 just ended) |
| 1511, 1703, 1709, 1803 | probably not; 1703 is disputed | never | no |
| 1809 (17763) | expected yes | from .2237 | LTSC 2019 |
| 1903 (18362) | expected yes | never | no |
| 1909, 2004, 20H2, 21H1 | expected yes | from .1854 or .1288 | no |
| 21H2 (19044), 22H2 (19045) | expected yes | yes | LTSC 2021; 22H2 with ESU |

### Features that differ on Windows 10 (1809 or later)
None are missing. Expected differences are:
- sandy's own console is classic conhost unless Windows Terminal is used.
- AF_UNIX, loopback, the exemption and the inherited socket are expected to behave as on Windows 11. All are unverified on Windows 10.

### What sandy should do (fail closed)
1. **Make the `DeriveCapabilitySidsFromName` dependency explicit.** Choose one of two options:
   - **(a) Resolve it at run time** with `GetProcAddress` on `kernelbase.dll`, as Chromium did. Report `FilesystemConfined` (and so every run) as unavailable with a clear reason when it is missing. This is the simplest option.
   - **(b) Compute the SID** as Chromium does today: `S-1-15-3-1024` plus the eight 32-bit words of SHA-256 over the UTF-16LE bytes of the upper-cased name. sandy's names are ASCII, so ASCII upper-casing matches. The grants persist on disk, so the computed SID must equal the API result forever. Add a unit test that compares both on hosts that have the API.

   Option (a) is enough if the floor is 1809. Option (b) only matters if pre-1809 support is wanted, and I do not recommend that (point 2).
2. **Add an OS build check to `detect()`.**
   - Read the build with `RtlGetVersion`. `GetVersionExW` reports 6.2 to programs without a Windows 8.1/10 manifest ([GetVersionExW](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexw), not re-fetched).
   - Read the update revision from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UBR`. This value is undocumented but widely used.
   - Refuse every requirement below build 17763. Refuse below the CVE-2021-41338 fix level (17763.2237, 18363.1854, 1904x.1288), and on 18362. This is a coarse "serviced host" floor, not a CVE database.
3. **Detect job nesting.**
   - Call `IsProcessInJob(GetCurrentProcess(), NULL, ...)`.
   - If sandy is in a job, read the limits of its job with `QueryInformationJobObject(NULL, JobObjectExtendedLimitInformation)`.
   - Without `BREAKAWAY_OK` or `SILENT_BREAKAWAY_OK`, report `NoPrivilegeEscalation` and `SignalsIsolated` as unavailable, with the reason. Breaking away from an outer job escapes its owner's limits, so do not do that silently.
4. **Keep the MpsSvc check.** Firewall profiles that are turned off do not matter (2.3).
5. **AF_UNIX:** check availability only when a feature needs it, such as a future server socket. Use `socket(AF_UNIX, SOCK_STREAM, 0)`.
6. **A future `listen = [...]` option:** check that the socket is a real kernel handle (unverified LSP risk, 2.4). Bind to loopback only.
7. **Small fixes found on the way, both done since:**
   - `plan.rs` said the environment block is "plus SystemRoot" while the code also adds `LOCALAPPDATA`; it now names both.
   - `docs/windows.md` said the `LOCALAPPDATA`/`TEMP`/`TMP` redirection is undocumented. Microsoft Learn "Launch an AppContainer" documents it, and the text now cites it.

## 6. Minimal test plan for Windows 10 22H2

**Setup.**
- Fully updated 19045 VM. Record `ver` and `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v UBR`.
- Keep the firewall service at its default. Use an administrator account with UAC.
- Build `--target x86_64-pc-windows-gnu` binaries and test executables (`cargo test --no-run`). Copy only the binaries, as `.worktrees/ci-logs/VM-ACCESS-windows.md` requires. Set `SANDY_TEST_BIN_DIR`.

**Steps, with pass criteria:**
1. **Load check.** `sandy.exe --help` and `sandy.exe check --appcontainer sandy.escape-tests` start, and every requirement is "enforced". This proves the import resolves on 19045.
2. **Test suites.** Run the `sandy_windows` (46), `escape` (10) and `escape_windows` (21) tests twice:
   - in an elevated session;
   - from a scheduled task with `/RL LIMITED`.

   Record every failure. Note especially `executes_only_executable_paths`, which fails on the Server 2022 and 2025 CI images.
3. **Profile and environment.**
   - After the first run, `reg query` the `Mappings\<SID>` key, using the SID that `sandy check` derives. The key must exist.
   - Inside the sandbox, the probe `env LOCALAPPDATA` must end in `\Packages\<name>\AC`. `TEMP` and `TMP` must point to `...\AC\Temp`.
4. **Loopback.** As administrator, run `sandy setup --appcontainer sandy.escape-tests.loopback --ip all`. Then run the three loopback tests in `escape_windows.rs`. Check that `sandy check` reads the exemptions under a `/RL LIMITED` token.
5. **Firewall profiles off.** Run `netsh advfirewall set allprofiles state off`, then `ip_networking_is_denied_by_default`. The connection must still be denied. Restore the profiles afterwards.
6. **AF_UNIX.** The three AF_UNIX tests pass.
7. **Console.** Run `sandy run ... cmd.exe /c echo` with non-ASCII text from:
   - a classic conhost window;
   - Windows Terminal, if installed;
   - redirected input and output;
   - SSH.

   The output must be correct. Ctrl+C must end the program with 0xC000013A, and the shell must still work afterwards. `console_control_events_stay_inside` must pass.
8. **Nested job.** Start sandy from a harness that puts itself into a job without breakaway. Expected today: a clean refusal "cannot put the program into the job object".
9. **Inherited listening socket.** Repeat the Windows 11 experiment: stdin of sandy is an inheritable socket listening on 127.0.0.1, with `ip = "none"`. An outside client must connect. `tcp-connect` from inside must still be denied.
10. **Optional:** repeat steps 1 and 2 on LTSC 2019 (17763), and run step 1 on a 1607 or 1803 image. This settles the `DeriveCapabilitySidsFromName` question. Expected on the older image: a loader error.

## Files

- `crates/sandy-windows/src/sys/acl.rs` (`capability_sid`, which calls `DeriveCapabilitySidsFromName`; it is resolved at run time in `sys/host.rs`)
- `crates/sandy-windows/src/sys/mod.rs` (`detect()`, where the new host checks belong)
- `crates/sandy-windows/src/plan.rs` (environment plan text)
- `docs/windows.md` (redirection wording; no Windows 10 or Server 2022 results yet)
- The release build of `sandy.exe` used for the import table and the downloaded log of CI run 39763844540 were temporary files outside the repository and are not kept. Section "How I checked" gives the commands that reproduce them.
