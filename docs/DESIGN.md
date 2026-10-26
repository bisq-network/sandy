# sandy design

sandy runs a program inside an operating system sandbox. A policy lists what the program may do;
everything else is denied. sandy supports Linux, macOS and Windows.

## Goals

- Contain a program that may be compromised, for example through a memory safety bug in code that
  parses untrusted input. After the compromise, the program must not be able to read or change
  user files outside its policy, gain privileges, or leave the sandbox through another process.
- One policy model and one command line on all supported platforms.
- Fail closed. If the host cannot enforce any restriction the policy requests, sandy does not
  start the program. There is no best-effort mode. The few requirements a platform gives only in
  part are written down and named by `sandy check` (see "Requirements and the enforcement
  plan").
- Unprivileged use. `sandy run` needs no root or administrator rights.
- One-time host preparation. What needs admin rights once is allowed, as `sandy setup`: the
  Windows loopback exemption, and on Linux under Ubuntu's AppArmor restriction of user
  namespaces an AppArmor profile that lets sandy use them. Setup never grants a right to a file
  that someone without admin rights can change: on Linux it prepares only a sandy whose file and
  directories up to `/` only root can change, or a root-owned copy of a portable sandy that
  `--install-copy` installs and that the portable sandy hands over to. `--elevate` asks for the
  rights (pkexec on Linux, UAC on Windows) and never runs a file with them that someone else
  can change. Setup ends with 0 when it is done or has nothing to do, 3 when it did nothing, and
  125 when it failed (see "Exit status").

## Non-goals

- Filtering where a program with `ip = "client"` or `ip = "all"` connects. Those values decide
  the direction of IP networking, not its destinations. The one place where sandy checks
  destinations is the egress broker of `ip = "private"` (see "Private network and egress").
- Protecting the program from the user, or protecting secrets the program itself holds.
- Resource limits (memory, CPU, process count). They can come later.
- Containers, images or a root file system of their own. The view of
  `filesystem.view = "policy"` shows the host's own paths, only fewer of them (see "The file
  system view").
- Filtering what the program writes to a terminal. A program whose standard output is the user's
  terminal can send escape sequences that some terminal emulators act on, for example to set the
  clipboard, and on Linux it can also change the terminal's modes. These are ordinary writes, so
  no system call filter can tell them apart. A program that is not trusted with the terminal gets
  a pipe or a file instead (README.md, "Using sandy from another program"). A later option could
  have sandy relay the terminal and filter what passes.

## Threat model

The sandboxed program and all its child processes are under attacker control. The attacker can run
arbitrary code with the program's user account and can make any system call. sandy itself, its
policy and the files it reads before the sandbox is applied are trusted. They must not be writable
by the sandboxed program, otherwise the next start runs attacker code outside the sandbox. The
writable-and-executable rule below enforces part of this; the integrator must store sandy and its
policy outside every writable path.

## Policy

```toml
version = 1

[filesystem]
system = "minimal"            # "minimal" | "none"
read = ["/opt/app/share"]     # read files, list directories
read_exec = ["/opt/app/bin"]  # read, list, execute
read_write = ["/var/lib/app"] # read, list, create, change, delete; never execute
view = "all"                  # "all" | "policy"; policy: paths outside the policy look missing

[network]
ip = "none"                   # "none" | "private" | "client" | "all"; IPv4 and IPv6 including
                              # loopback; private: only the sandbox's own loopback
unix_sockets = "none"         # "none" | "all"; "none" reaches no socket outside read_write
expose = [{ listen = "127.0.0.1:18080", port = 8080 }]  # relay into the program's port 8080
forward = [{ port = 18081, to = "127.0.0.1:8081" }]     # relay out to a local service
egress = { port = 1080, reach = "public" }  # with ip = "private": a SOCKS5 broker on the
                              # program's 127.0.0.1:1080; reach = "public" | "public-and-local"

[process]
signals = "any"               # "any" | "isolated"
children = "allowed"          # "allowed" | "none" | "contained"; see rule 9
end_with_parent = false       # end the program when sandy's parent ends; see rule 11

[environment]
pass = ["LANG"]               # copied from sandy's environment if present
set = { HOME = "/var/lib/app" }

[linux]
path_metadata = "deny"        # "deny" | "allow"; chmod, chown, utimensat, setxattr by path

[macos]
relays = "dual-stack"         # "dual-stack" | "ipv4"; ipv4: the program reaches its forwarded
                              # and egress ports over IPv4 only; needs ip = "private"

[windows]
appcontainer_name = "example.app"  # required on Windows
win32k = "allow"              # "allow" | "deny"; deny blocks win32k (GUI kernel) system calls
```

Command line options extend the policy file (`sandy --help`): path options add paths, and every
other option replaces the file's value, also with a weaker one. The caller is trusted, so sandy
obeys, but `sandy check` names every option that replaced a stricter value of the file in a
`warning:` line on standard error, together with the settings of the policy that give up part of
the isolation (`ResolvedPolicy::warnings`) and what the backend found on this host that makes the
program behave differently inside the sandbox or that its platform gives only in part
(`Backend::notes`). Warnings do not change what sandy enforces or its exit status; `sandy run`
prints none, because its standard error belongs to the program.

sandy's own executable and the policy file get the checks of rules 3 and 4: sandy refuses to
start when a writable path contains one of them, reaches one through a link or an alias, or
holds a second name of one, because the program could then change what the next start runs or
reads. The name sandy was started under counts next to the file it leads to, because that name
can be a link inside a writable path.

Rules:

1. Paths must be absolute and must exist. sandy resolves symbolic links before it builds the
   sandbox, so all backends see the same object. On Windows a path that resolves to a network
   share is refused: the program cannot open it in its AppContainer, and the grant would land
   on the folder behind the share (docs/windows.md, "Network and share paths").
2. A rule applies to the path and everything beneath it.
3. No path may be both writable and executable, also not through nesting. sandy rejects such a
   policy. The program could otherwise drop an executable that a process outside the sandbox
   later runs. The rule holds per file, not per name: a file that has a second name inside a
   writable path is writable, so an executable path, or the program file, that leads to the same
   file is refused as well (see "Links and file identity").
4. No policy path may lie inside a writable path, and none may be resolved through an entry
   inside one, such as a symbolic link in a writable directory that points elsewhere. sandy
   resolves symbolic links at every start, so the program could replace such an entry with a
   link and widen its access at the next start. For the same reason the integrator must keep the
   parent directories of policy paths out of the program's reach. Rules 3 and 4 compare files,
   not only paths, so one directory reachable under two paths counts as one (see "Links and file
   identity").
5. The program file itself gets read and execute access automatically.
6. `system = "minimal"` adds a backend-defined read-only set of system paths that programs need to
   start: shared libraries, loader configuration, time zone data, random devices. Each backend
   documents its set and the reason for every entry. The set never contains user data. No
   writable policy path may overlap the set: contain one of its entries (also one that does not
   exist yet, such as `/etc/ld.so.preload`) or lie inside one of its directories. The entries are
   code and configuration that the next start and programs outside the sandbox trust, so rules 3
   and 4 apply to them as to policy paths, including how they compare paths: another name of a
   directory of the set counts as that directory (see "Links and file identity"). The only
   exception is `/dev/null`, which the set makes writable. The backend checks this, because only
   it knows its set; with `system = "none"` it adds nothing, and every writable path is the
   policy's own choice. Rule 12 holds in that case too.
7. The environment of the program contains only `pass` and `set` variables, plus variables a
   backend must add for any process to start (documented per backend).
8. `unix_sockets = "all"` allows every Unix socket the user can reach, independent of the
   filesystem rules, on every platform and kernel version. Linux before 7.1 cannot restrict
   connections to pathname sockets by path, and the meaning of a policy must not depend on the
   kernel version.

   **WARNING:** `unix_sockets = "all"` gives up most of the isolation. The program can reach every
   local service that listens on a Unix socket. On Linux that includes the D-Bus session bus,
   through which the systemd user manager starts arbitrary commands outside the sandbox. On macOS
   it includes mDNSResponder, so even with `ip = "none"` the program can send data out in DNS
   queries. Use it only for programs you would also run without a sandbox.
9. Children of the program inherit the sandbox on every platform. `process.children` decides
   whether the program may start processes and whether they may outlive it:
   - `allowed` (the default): the program may start processes. On Linux and macOS they can
     outlive the program. On Windows the program's job ends them when the program ends.
   - `none`: the program cannot create processes at all (threads stay allowed, and so does
     replacing its own program image with `execve`), so nothing it starts can outlive it.
   - `contained`: the program may start processes, and sandy ends every one of them when the
     program ends, also when sandy itself is killed. On Linux and macOS, sandy then stays the
     program's parent instead of replacing itself with it (see "Process model"). On macOS the
     program cannot use `posix_spawn` then: its flags move the new process out of the group
     inside the kernel, where no profile rule sees them, so the profile denies the call as a
     whole. `fork`, `vfork` and `execve` keep working.

   `none` and `contained` cover the processes the program starts itself or through its
   children. Both need `unix_sockets = "none"`: through a Unix socket the program could ask a
   service of the user (for example the systemd user manager over D-Bus) to start a process,
   which is not its child. A service that starts processes on requests over TCP stays reachable
   with `ip = "client"`, `ip = "all"` or through a `forward` target, and its processes are not
   covered.
   `contained` also needs `signals = "isolated"`: otherwise the program could kill sandy and the
   process that ends the group. sandy rejects the policy when either condition is missing.
10. `linux.path_metadata = "deny"` (the default) requires that permissions, owner, timestamps and
   extended attributes of files outside the policy paths cannot change. Landlock does not control
   these calls, so the Linux backend denies the path-based variants (`chmod`, `chown`, `utimensat`
   with a path, `setxattr` and relatives) everywhere, also inside writable paths, and the owner and
   extended attribute calls on an open file (`fchown`, `fsetxattr`). The mode and time calls on an
   open file (`fchmod`, `futimens`) keep working, which is why `cp -p` needs nothing; they also
   reach a file the program may only read. `allow` removes the requirement for programs that change
   metadata by path (`install`, `cp -a` on a directory, `rsync -a`, `git`); they can then change
   the metadata of every file the user owns. macOS and Windows protect metadata outside the
   writable paths in every case.
11. `process.end_with_parent = true` ends the program when the process that started sandy
   ends, for example when the application that runs a helper in the sandbox crashes. The program
   gets a request to end (SIGTERM on Linux and macOS) and is killed if it has not ended 5 seconds
   later; Windows ends the program's job at once. With `children = "allowed"` on Linux and macOS,
   processes the program started can outlive it, as with any end of the program; use
   `children = "contained"` to end them too. The option needs `signals = "isolated"`, so that
   the program cannot kill the process that ends it. Without `--parent-start`, "parent" means
   sandy's direct parent: a wrapper between the application and sandy (`sh -c 'a; sandy ...'`,
   `timeout`, `systemd-run`) is the parent instead. sandy reads the parent's process ID as its
   first step; a parent that ends before that cannot be detected. The caller closes the first gap
   with `--parent-pid` and its own process ID: sandy then refuses when its parent is another
   process. `--parent-start` closes both: the caller adds when its own process started, which no
   other process can have and which nothing but a new start changes, so sandy checks the identity
   of the named process instead of asking whether it is its own parent. The form is
   platform-specific (field 22 of `/proc/PID/stat`, the recorded start time, the creation time).
   sandy also refuses when it sees that the process it would watch has already ended, and on
   macOS when that process is launchd, which has no end to wait for.
12. No writable policy path may reach a location of this user whose content other programs read
   or execute later: the home directory (which it may not contain), the startup files of the
   shells, the SSH, GnuPG, git and cargo configuration, and per platform autostart entries and
   user services, `~/Library/LaunchAgents`, the Startup folders, the PowerShell profile folders,
   `WindowsApps` and, on Windows, sandy's own state folder, which decides which policy may join a
   running AppContainer. Linux and macOS share one list for what every Unix has
   (`sandy_core::trust`), so one policy is refused on both for the same files. A file the program
   leaves in one of the others runs outside the sandbox with the user's rights at the next login,
   the next shell or the next run of the tool, which would make the whole policy pointless. The
   backend checks this, because only it knows the locations of its platform, and it compares
   paths as rules 3 and 4 do. A path below the home directory stays writable: only the locations
   themselves and the trees of those that hold code are protected.

   A directory on `PATH` is **warned about, not refused**. The escape is the same, a file the
   program leaves there runs when the user next types its name, but a writable path that holds
   one is often what the caller means (a package cache whose `bin` directory is on `PATH`, or
   `/usr/local`), so refusing it would turn away ordinary work. The directories are those on
   sandy's own `PATH` and, on Linux and macOS, the ones the usual shell setups put on the user's
   `PATH` (`sandy_core::trust::path_locations`), whether or not sandy's own holds them: a service
   or a desktop application starts sandy with a minimal `PATH`, while the escape works through
   the user's shell. The warning names the directory and the one answer that removes the risk:
   grant only the subdirectories the program needs, so that the directory stays outside every
   writable path. Starting sandy with another `PATH` would only silence the warning.

   The set is a heuristic. No list knows which files the programs of a user trust, and the set
   covers the usual shell and desktop setups only. It also does not depend on the policy:
   `system = "none"` changes nothing about it. The home directory comes from the password
   database or the known-folder API and from the environment, because a program that starts
   sandy with a minimal environment sets neither. When no source names one, sandy cannot check
   this rule, so it refuses a policy with a writable path, as it refuses when it cannot read the
   mount table, and the message says to set `HOME`. On Windows a known folder that cannot be
   found makes the filesystem requirement unavailable for every policy.

13. The standard streams stay the caller's choice, except for the sockets among them and, with
   `signals = "isolated"`, the master side of a pseudo-terminal. sandy passes descriptors 0, 1
   and 2 on as it received them and closes every other one, because a program reads its input
   and writes its output through them. Nothing inside the sandbox can
   take rights away from what is already open, so a socket on a standard stream keeps the access
   it was created with, whatever the policy says about networking. `run` therefore looks at the
   three streams before it applies the sandbox and accepts a socket only when the policy lets
   the program create one like it. Otherwise it refuses with status 125, naming the stream and
   the socket: an IP socket with `ip = "none"`, an unconnected, datagram or listening Unix
   socket with `unix_sockets = "none"`, a listening or datagram IP socket with
   `ip = "client"`, and under every policy a raw IP socket, an IP socket of a protocol outside
   the usual ones (`streams::IP_PROTOCOLS`: TCP, UDP, ICMP, MPTCP) and a socket of any other
   family, because no setting lets the program create one. A raw IP socket
   needs privileges: CAP_NET_RAW on Linux, which sandy refuses to start with, root on macOS and
   administrator rights on Windows; sandy refuses an inherited one also where the caller has
   them, so that a policy means the same everywhere. An ICMP datagram socket follows `ip`,
   because an unprivileged program can create one where the kernel allows it (on Linux within
   `net.ipv4.ping_group_range`). What `ip = "all"` and `ip = "client"` allow besides AF_INET and
   AF_INET6 comes from the backend (`Backend::ip_also_allows`): on Linux a route netlink socket,
   from the same list that the socket family filter is built from; on macOS and Windows
   nothing. The message for another family names it and says to pass a pipe, a file or a
   connected Unix stream socket instead; naming a setting would not help. A connected Unix
   stream or seqpacket socket is accepted, because it talks only to the peer it already has,
   which is how a parent passes a pipe (libuv, journald, `ssh` without a terminal); what that
   peer is stays the caller's choice, as with a file. A service that is handed its connection
   on standard input, inetd-style or with systemd `Accept=yes`, needs `ip = "client"`: a
   connected TCP socket talks only to its peer, like a connection the program makes. A datagram
   socket needs `ip = "all"`, also a connected one, because the program could disconnect it
   (connect to AF_UNSPEC) and then receive from every sender at the port its creator chose,
   which on Windows passes the firewall with the creator's rights. With
   `signals = "isolated"` `run` also refuses the master side of a pseudo-terminal on a standard
   stream, naming the stream and saying to pass the slave side or a pipe instead
   (`streams::terminal_master_refusal`). Writing the interrupt, quit or suspend character into
   a master makes the kernel send SIGINT, SIGQUIT or SIGTSTP to the foreground group of the
   other side, without the check that isolates signals (measured on Linux and macOS), and a
   write cannot be told from any other. The slave side, which a program gets when it runs in a
   terminal, is accepted. Linux knows a master by its device number, macOS by the major number
   of `/dev/ptmx` (see the platform docs); Windows has no such device. `check` cannot report
   any of this: the streams it is given are not the streams of the later `run`.

## Links and file identity

A path names a way to a file, not the file itself. Rules 3, 4, 6 and 12 therefore compare more
than the spelling of a path. The resolver compares the policy paths with each other; the
backends compare them with their system set and with the trusted locations of rule 12, through
the same functions (`PathIdentity`, `ProtectedPath`), so one policy is refused for the same
reason whichever check sees it first. A location of a backend counts twice: where it lies and
where its symbolic links lead, because whoever can write the one can repoint it and whoever can
write the other changes what programs read.

- **Two paths, one directory.** sandy compares the identity (device and inode; on Windows the
  volume serial number and the file ID) of a writable path with the path it checks and with
  each of that path's parent directories, so an alias of the writable path or of one of its
  parents counts as the same directory. On Linux it also compares where both paths lie inside
  their file system, which is the mount root from `/proc/self/mountinfo` plus the rest of the
  path. That sees a bind mount of a subdirectory of a writable path, which shares no parent
  directory with it. sandy refuses the policy when it cannot read the mount table, because it
  could not tell the two apart then; the Linux backend needs `/proc` anyway. On Windows a
  directory whose identity sandy cannot read counts as the same directory, so the check
  refuses; the warning for a directory on `PATH` (rule 12) follows the spellings then, so it
  names only an overlap sandy sees (see docs/windows.md).
- **Two names, one file.** A hard link gives one file a second name. The kernels check the name
  a call uses, so a file that is executable under one name and writable under another is both.
  At the start sandy looks for a second name inside the writable paths of every file that must
  not be writable: the files and trees of `read_exec` paths, the program file, its own
  executable and the policy file. It walks the writable trees first, because a file with more
  than one name is rare there, and the executable trees only when it found one. A directory
  the user may not list is skipped: the program runs as the same user and cannot list it
  either. On Windows a file lists its own names (`FindFirstFileNameW`), so sandy asks the
  files themselves and walks the writable trees only for a `read_exec` directory.
- **What stays open.** A hard link between a writable path and a file that no rule names, or
  that only a `read` rule names, is allowed: the program can change that file through the
  writable name. Refusing it would stop the package managers that fill a project from a shared
  cache with hard links, so the policy decides what a writable path may hold. The entries of the
  system set and the locations of rule 12 are compared as paths and directories, not for second
  names: a hard link of a shell startup file inside a writable path stays writable through that
  name. Two names that different file systems show for one file, as a passthrough FUSE mount
  does, have different identities and stay unseen. The check runs at the start, so a link that a
  process outside the sandbox makes while the program runs is not covered. The program cannot
  make one itself: it gets no link right out of its writable paths and no execute access inside
  them.

## Exposed ports

`network.expose` makes a loopback port of the program reachable from outside the sandbox.
sandy listens on `listen` (a loopback address) and relays every connection to `port` on the
loopback address of the same family, where the program listens. The relay copies bytes and never
interprets them.

Windows needs this: it blocks every inbound loopback connection into an AppContainer, with or
without the loopback exemption. A relay inside the same AppContainer can reach the program over
loopback, and a listening socket that sandy creates outside the container accepts connections from
outside. Linux and macOS relay the same way, so a policy means the same on every platform.

Rules:

1. `listen` must be a loopback address and must differ from the program's own address.
2. The program needs `ip = "all"` or `ip = "private"` to listen. `ip = "client"` denies
   listening, so sandy refuses `expose` with it and says to use `ip = "all"`.
3. The relay ends with the program. On Windows the job object ends it; on Linux and macOS the
   relay watches the program's process.
4. The relay is confined as tightly as the platform allows: on Windows it runs in the program's
   AppContainer and job; on Linux and macOS it runs outside the program's sandbox in its own
   sandbox with no file access.
5. Each exposed or forwarded port relays at most `sandy_relay::MAX_CONNECTIONS` connections at
   the same time, so clients of one port cannot take the connections of another.

## Forwarded ports

`network.forward` is the mirror of `expose`: it lets the program reach a loopback service outside
the sandbox. The program connects to `port` on the loopback address of the same family as `to`;
sandy relays each connection to `to`.

Windows needs this: an AppContainer cannot connect to loopback services outside it unless an
administrator installs a loopback exemption. A relay inside the AppContainer accepts the
program's connection over loopback (allowed inside one AppContainer) and passes it to sandy
outside through a Unix domain socket, which the loopback isolation does not filter; sandy then
connects to `to`. No administrator step is needed. Linux and macOS relay through the same kind of
confined relay process as `expose`, so a policy means the same on every platform.

Rules:

1. `to` must be a loopback address; the program's address (`port`) must differ from it.
2. The program needs `ip = "private"`, `ip = "client"` or `ip = "all"` to connect.
3. No address may be used by two relays (`expose` or `forward`), and `to` must not lead back into
   the sandbox (an exposed address).
4. The relay ends with the program and is confined like the `expose` relay.
5. Lifetime of both relays: when the program ends, the relay closes its listeners at once, gives
   connections it already accepted at most one second to deliver their remaining data, and then
   ends. A program that connects, writes and exits immediately therefore does not lose its data,
   and no relay outlives the program by more than one second, except when the program stopped it
   (below). Connections still open when that second ends close with a reset, so no peer takes a
   cut stream for a complete one. With `process.children = "contained"` on Linux and macOS, the
   relay watches the supervising sandy instead, which ends after the program's process group,
   and also a pipe that only the guard holds, so it ends with the group also while sandy is
   stopped.

   With `signals = "any"` the program can also send SIGSTOP, which no process can block, and a
   stopped relay sees nothing. On Linux the relay has a watchdog for that: the kernel kills it
   two seconds after its poll loop last ran, so the bound for a stopped relay is two seconds
   instead of one (docs/linux.md, "Exposed and forwarded ports"). Windows is not affected: sandy
   terminates the relay's job object from outside the sandbox. On macOS there is no such timer,
   so a stopped relay holds its ports until someone continues or kills it, and only
   `signals = "isolated"`, which keeps the program from signalling the relay at all, holds the
   bound there (docs/macos.md). With `signals = "isolated"` the Linux relay has no watchdog
   either: the program cannot stop it, and the timer would only kill a healthy relay that a busy
   host did not run for two seconds, which with `contained` ends the program too.

   A relay that is continued inside that bound can relay a connection that was made after the
   program ended. The poll loop looks for a stop and refuses the backlog it collected while
   stopped, but two races defeat that check, both measured: the kernel wakes a stopped process
   before it queues SIGCONT, so the first turn after a continue can find nothing pending, and
   the end of the program is not always in the same poll result as the readiness of a listener.
   On Linux the watchdog bounds how long that is possible; on macOS nothing does. The harm is a
   violation of the relay's lifetime, not an escape: an exposed port can answer once more after
   the operator believes the run ended, served by whatever now holds the inner address, and
   nothing gains access the relay did not already have. With `process.children = "contained"`
   the window does not exist, because `contained` requires `signals = "isolated"`.

   A dead relay ends a contained program. With `process.children = "contained"` on Linux and
   macOS, the guard of the program's group ends the group as soon as the relay is gone, whatever
   ended it and also while sandy is stopped, and sandy exits with status 125. A dead forward relay frees the program's
   forward port, and any local user can then bind it and receive what the program sends there
   for `to`: its requests, credentials and data. A relay that ends together with the program,
   or after it, is the normal end of a run. Without `contained` nothing watches the relay,
   because sandy has become the program, so a relay that something outside the sandbox kills
   leaves the program running with its forward port free for others to bind.
6. Who may connect: an exposed port is meant for other processes, including those of other
   users, and the program's own listener is reachable directly on Linux and macOS anyway, so
   the relay serves every connection there. A forwarded port is for the program alone, and the
   relay reaches `to` as sandy's user. On Linux it therefore refuses a connection whose other end
   the kernel names as another user's, and refuses the run when the kernel cannot answer such a
   lookup at all (docs/linux.md). With `ip = "private"` the forward listener is in the
   sandbox's own network namespace, which no other user reaches, so the relay asks nothing there.
   On macOS it cannot ask, so a forwarded port is reachable by every local user
   (docs/macos.md). On Windows only the program's AppContainer reaches it.

   There is one answer the kernel cannot give, and the residual that comes with it. The owner it
   reports comes from the socket's file, so a socket its process has closed has none, which the
   answer shows by carrying no inode. The relay serves such a connection. It has to: the kernel
   completes a handshake by itself, so a program that connects and exits is always ahead of the
   relay's accept, and refusing those answers dropped more than half of such a program's
   connections on every kernel measured, which is the opposite of what a forwarded port is for.
   Where the answer still carries a user other than sandy's and 0, which kernels from 6.17 do until
   a timewait record replaces the closed socket, the relay refuses it. What it leaves open is that
   another local user can deliver a blind write once its closed socket carries no user: on 6.8 from
   the close, usually on the first attempt, because a peer that connects, writes and closes at once
   is usually closed before the relay asks; on newer kernels only when the relay asks after the
   replacement. It cannot read the answer, because losing the file is what loses the owner and also
   gives up the reply, so the service cannot be used interactively or read from; and a peer that
   only half closes keeps its file and its owner, so that is not a way around the check either
   (docs/linux.md).
7. The relay passes the end of a stream on as it came: a normal end as a half close, and a reset,
   or data the relay cannot deliver, as a reset of the other side. After one direction of a
   connection has ended, the other ends when it stays idle for `sandy_relay::HALF_CLOSED_IDLE`
   (60 seconds), so a peer that never sends again cannot hold the connection and its slot.

## Private network and egress

`ip = "private"` gives the program IP networking among its own processes only, on a loopback
that belongs to the sandbox. It is the value for a program that serves or reaches the host only
through named ports, and the network only through a checked broker.

Rules:

1. The program may bind, listen and connect on its own loopback addresses. Nothing outside the
   sandbox reaches those sockets except through `expose`, and they reach nothing outside except
   through `forward` and `egress`: not the host's loopback services, not the host's other
   addresses, not the local network and not the internet, also not with datagrams, ICMP or name
   resolution. How each platform gives the program a loopback of its own, and where it gives
   less, is in the platform docs.
2. `expose` and `forward` work as with `ip = "all"`. A forwarded port, and the egress port,
   should be reachable by the program alone; a platform that cannot keep other local users away
   from them names that in the exceptions table. On macOS a forwarded or egress port also needs
   `signals = "isolated"`: there the program's profile reaches the port at every address of the
   host, and a program that killed its relay or broker would leave the port to whatever binds it
   next, so the backend refuses `signals = "any"` with such a port (docs/macos.md).
3. A socket on a standard stream belongs to the network it was created in, so `run` refuses
   every IP socket there (rule 13 of "Policy").
4. `network.egress` adds a broker that speaks SOCKS5 (RFC 1928) on `127.0.0.1:<port>` inside the
   sandbox. It needs `ip = "private"`: with any other value the program either has no network or
   reaches it without the broker. Its address must differ from every address of `expose` and
   `forward`.
5. The broker accepts one request per connection: `CONNECT` with an IPv4 or IPv6 address, no
   authentication. It refuses a domain name (reply 8), so it resolves nothing for the program,
   every other command (reply 7) and an unknown address type (reply 8, whatever the command,
   because its length is unknown). It checks the destination outside the sandbox, connects
   from there, and from then on copies bytes like the relay. Only TCP leaves this way.
6. Destinations (`sandy_core::destination`): `reach = "public"`, the default, allows only
   globally reachable unicast addresses, from the IANA special-purpose registries, outside the
   local network. `"public-and-local"` also allows the private, shared and unique local ranges
   and the local network: every network the host reaches without a router, which is the subnet
   of every interface address and the network of every other route without a gateway, except
   the default route and routes into a point-to-point or tunnel link. Never allowed, whatever
   `reach` says: an address of the host itself (what the kernel calls a local, broadcast or
   multicast route), loopback, `0.0.0.0`, link-local and multicast. An IPv4-mapped IPv6 address
   is judged as the IPv4 address it maps.
   After the connect the broker also closes a connection whose local address is loopback or
   equal to its peer, which is what a connection to the host itself looks like. A refused
   destination gets reply 2. The success reply names `0.0.0.0:0`, so a connection does not tell
   the program the host's address; which destinations are refused does, by trying them (the
   exceptions table, row "All").
7. The broker is a process of its own, apart from the relay, so the relay keeps its narrower
   rights. It is confined like the relay (no file access, no processes), parses nothing but the
   fixed handshake, and ends with the program as the relay does (rule 5 of "Forwarded ports").
   A flaw in its parser would give what `ip = "client"` gives a program today, minus datagrams
   (on Windows with datagrams, docs/windows.md).
8. `macos.relays = "ipv4"` (the default is `"dual-stack"`) lets the program reach its forwarded
   ports and the egress broker over IPv4 only. On macOS that closes a route of the exceptions
   table and costs the program its IPv6 sockets to those ports (docs/macos.md, "The private
   network"); elsewhere the private network has no such route. It needs `ip = "private"`, and it
   refuses a forward whose `to` is IPv6, because the program would reach that port at [::1].

## Egress broker

The detail behind rules 5 to 7 of "Private network and egress". `sandy_relay::broker` serves the
broker on every platform and `sandy_core::destination` decides, so a destination means the same
everywhere; a backend adds only its answer about its own addresses (`HostNetwork`).

1. The handshake (`sandy_relay::socks`) takes method 0 only and answers any other greeting with
   `X'FF'`. It has 10 seconds in total, every read has a size the protocol fixes, and a request is
   read whole before it is judged, so a refusal of a client that waits for its reply ends with
   the reply and a normal close, and data that a client sends behind its request reaches the
   destination. A client that sends data behind a refused request, or behind an address of an
   unknown type, leaves it unread, and the close then ends with a reset. Linux still delivers
   the reply before the reset; macOS often drops it and Windows always does (measured), so such
   a client sees only the reset.
2. The static check follows the IANA special-purpose registries, copied in
   `crates/sandy-core/data`. A test pins the tables to the copies, and a weekly workflow
   (`.github/workflows/iana.yml`) fails when IANA changes a registry. IPv4 is a denylist of the
   registry's blocks. IPv6 is an allowlist of `2000::/3` minus the registry's blocks inside it, so
   a block that IANA adds elsewhere is refused before the tables change. `192.0.0.0/24` and
   `2001::/23` are refused as a whole, with the anycast addresses in them that no program needs.
   The forms other than the mapped one that embed an IPv4 address (IPv4-compatible `::/96`,
   NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo `2001::/32`) are refused
   whatever `reach` says: whether a translator or a tunnel takes them to the embedded address
   depends on the network. Port 0 is refused.
3. The host's part: whether an address is the host's own (an interface address, a subnet
   broadcast address, or a local, broadcast, anycast or multicast route), and which networks the
   host reaches without a router, asked for every connection. Those are the subnet of every
   interface address, for a point-to-point link that of its peer, and the network of every
   unicast route whose next hop is no gateway, except the default route and routes into a
   point-to-point or tunnel link. A route counts also where no address of the host has its
   prefix: a DHCPv6 address is a /128 beside the on-link /64 of router advertisements, and a
   route can send a network into a link without any address. A route into a tunnel does not:
   what it sends goes to the other end, which takes it on as a router does. So a full tunnel
   that splits the default route into `0.0.0.0/1` and `128.0.0.0/1` leaves the internet public,
   while the subnet of the tunnel's own address stays the local network and the private ranges
   behind it stay refused by the static check. Linux takes a link with `IFF_POINTOPOINT` or
   `IFF_NOARP` for a tunnel, macOS one with `IFF_POINTOPOINT`, Windows an interface of a tunnel
   or PPP type or of a point-to-point access type. An address on such a network is the local
   network. `public` refuses it also when it is globally reachable, because on IPv6 a local
   network often has a global prefix.
   `public-and-local` allows it also in a block that is not globally reachable, but a subnet
   never opens what rule 6 never allows, such as loopback or link-local. When the host cannot
   tell, the broker refuses with reply 1. Linux asks the kernel's routing tables
   (`RTM_GETROUTE`, also as a dump of every table, `RTM_GETADDR` and `RTM_GETLINK`) over a
   `NETLINK_ROUTE` socket that it opens before the broker confines itself. macOS reads
   `getifaddrs` and the routing table for every connection, which its broker profile allows
   through the routing sysctl; it has no local route without an interface address. Windows asks
   `GetAdaptersAddresses`, `GetBestRoute2` and `GetIpForwardTable2`.
4. The broker connects to the address it checked, an IPv4-mapped one as IPv4, within 10
   seconds. A refused, unreachable or timed-out connect gets reply 5, 3 or 4, any other failure
   reply 1. It judges only the address: a router that maps a public address back to this host,
   or a firewall rule of this host that redirects outgoing connections to a local service, takes
   the connection where the check did not look, and the check after the connect sees the
   address the program named as the peer (the exceptions table, row "All").
5. It serves at most `sandy_relay::broker::MAX_CONNECTIONS` (1000) connections at the same time,
   more than a relayed port, because a program that talks to many peers needs them. Each takes
   two threads with small stacks and two descriptors; macOS allows a process 2048 threads.

## The file system view

`filesystem.view = "policy"` makes every path outside the policy paths and the system set look
missing to the program: a call that names one answers as for a path that does not exist. It
closes what a denial still tells: which files exist, their sizes, times and owners, and what
appears in a watched directory.

Rules:

1. The view hides; it grants nothing. Landlock, the profile or the AppContainer still decide what
   the program may do with what it sees.
2. Execute stays a right of its own. On Linux every path the policy does not make executable, a
   writable path or a `read` path, is mounted without execute, so a file there can be neither
   executed nor mapped as code; `read_exec` is how a policy grants both.
3. A platform that cannot hide paths reports the requirement as unavailable, and `run` refuses
   (Windows: docs/windows.md).
4. What the view changes for programs is in the platform docs: on Linux a rename or a link
   between two writable paths fails with `EXDEV`, and files of other users show the owner 65534.
   On macOS every profile hides those paths already, so the view changes nothing there.

## Requirements and the enforcement plan

`ResolvedPolicy::requirements` derives the guarantees a policy needs:

| Requirement | When |
|---|---|
| `FilesystemConfined` | always |
| `NoPrivilegeEscalation` | always |
| `ProcessMemoryIsolated` | always |
| `InheritedHandlesClosed` | always |
| `EnvironmentControlled` | always |
| `IpNetworkDenied` | `network.ip = "none"` |
| `IpNetworkPrivate` | `network.ip = "private"` |
| `EgressBrokered` | `network.egress` is set |
| `RelaysIpv4Only` | `macos.relays = "ipv4"` |
| `PathsHidden` | `filesystem.view = "policy"` |
| `InboundIpDenied` | `network.ip = "client"` |
| `UnixSocketsDenied` | `network.unix_sockets = "none"` |
| `SignalsIsolated` | `process.signals = "isolated"` |
| `MetadataConfined` | `linux.path_metadata = "deny"` (default) |
| `ExposedPortsRelayed` | `network.expose` is not empty |
| `ForwardedPortsRelayed` | `network.forward` is not empty |
| `ChildProcessesDenied` | `process.children = "none"` |
| `ChildProcessesContained` | `process.children = "contained"` |
| `EndsWithParent` | `process.end_with_parent = true` |
| `Win32kDenied` | `windows.win32k = "deny"` |

A requirement is a lower bound. A backend may deny more, but never less. For example,
`UnixSocketsDenied` guarantees that the program cannot connect to Unix sockets outside the paths
it may write; Linux and macOS deny connections to every Unix socket, while Windows checks access
to a socket through its file and therefore allows the sockets in the `read_write` paths and in
the program's private AppContainer folder (docs/windows.md).
(On Linux with `ip = "all"` or `ip = "client"` a socket pair can still take a free abstract name;
see `docs/linux.md`.)

`MetadataConfined`, `RelaysIpv4Only` and `Win32kDenied` come from a platform section of the
policy (`linux.path_metadata`, `macos.relays`, `windows.win32k`) but are requirements like any
other: every backend reports them. A platform without the mechanism the key names reports the
requirement as enforced with nothing to do, because it has no such route to begin with.
`Win32kDenied` (from `windows.win32k = "deny"`) is enforced on Linux and macOS, whose kernels
have no win32k, and on Windows by a process mitigation that disables the win32k system calls
(docs/windows.md, "Win32k"). `RelaysIpv4Only` (from `macos.relays = "ipv4"`) is enforced on
macOS by `tcp4` rules in the profile, and on Linux and Windows, whose private network has no
address that leads out, with nothing to do.
A platform key is never silently ignored off its platform; it maps to a requirement each backend
answers.

There is one exception to "never less". Some requirements mean less on one platform than their
description says, because the platform has no mechanism that closes a route, or because sandy
does not use one there yet. sandy does not refuse them: the plan reports the requirement as
enforced, the platform document describes the route, and `sandy check` prints a `warning:` line
for it (`Backend::notes`) that names the route and the section that explains it. The warning
appears only when the policy asks for what it concerns. A new exception needs the description,
the warning and a row in the table below. The requirement line keeps the word `enforced`,
because `run` starts the program with it, and the line a caller reads does not change. The
exceptions:

| Platform | When | What stays open |
|---|---|---|
| All | `egress` | the broker refuses an address of this host with reply 2 and answers others with the result of its connect, so the program can tell this host's addresses, and with `reach = "public"` its local network, by trying them (`sandy_relay` `every_forbidden_form_is_refused_with_reply_2` and `a_closed_port_gets_reply_5`); a NAT64 prefix of an operator other than the well-known ones cannot be recognised; a public address that a router maps back to this host (a port forward with hairpin NAT) reaches the services of this host that the forward exposes, because the broker sees only the public address; a firewall rule of this host that redirects outgoing connections (a REDIRECT or TPROXY rule on Linux, a pf `rdr` rule on macOS, a WFP connect redirect on Windows) takes the broker's connections to the local service it names, which the check after the connect cannot see, because the connection's peer address stays the destination the program named (measured on Linux with an nftables redirect in a network namespace of its own: the broker answered reply 0 for `1.1.1.1:443` and the service on `127.0.0.1:8443` took the connection; not verified on macOS and Windows) |
| Linux | `signals = "isolated"` without `children = "contained"` | a read from the terminal in the background stops the group sandy was started in, with the processes outside the sandbox in it |
| Linux | `ip = "client"` | a UDP socket that is not connected receives datagrams from every sender, at the port the kernel chose for it, and before Landlock ABI 10 at any port the program binds |
| Linux | `forward` with `ip = "client"` or `ip = "all"` | another local user can deliver a write to the forwarded service, through a connection it closed before the relay asked who owns it, and that no longer carries its user (from the close on Linux 6.8, after the timewait record on newer kernels) |
| Linux | `ip = "private"` | processes of the user that runs sandy can enter the sandbox's network namespace, which belongs to that user, and reach the program's ports and forwarded ports there without a relay, and the egress port |
| Linux | `path_metadata = "deny"` with a `read` or `read_exec` path, without `view = "policy"` | the mode, except the setuid and setgid bits, and the times of a file or directory the program may only read, through a descriptor it opened for reading (`fchmod`, `futimens`) |
| Linux | `view = "policy"` | `statfs` of a path in the view reports the host's file system there: its type, size, free space and number of files |
| Linux | `view = "policy"` | the directories above a granted path exist in the view, with their names |
| Linux | `view = "policy"` | the link count of a granted file counts its names outside the view |
| Linux | `view = "policy"` with a `/proc` path | the mount table names the host's device, file system and mount options of every mount of the view, and the mount table of a process outside the sandbox lists the host's mounts with their paths |
| macOS | `signals = "isolated"` | SIGIO (to a process of any user), and SIGURG with an `ip` other than `"none"`, through the owner ioctls of sockets and pipes; without `children = "contained"` also joining another job of the terminal session and stopping it |
| macOS | `ip = "client"` | a UDP socket that is not connected receives datagrams from every sender, at any port the program binds |
| macOS | `unix_sockets = "all"` | whether a path outside the policy exists, and its path through `getattrlist`, also by inode number through `/.vol` |
| macOS | `forward` | every local user reaches the forwarded service |
| macOS | `expose` or `forward` with `signals = "any"` | a stopped relay has no time limit |
| macOS | `ip = "private"` with `expose` | the program can listen on its exposed ports at every address of the Mac, where every local process and other hosts reach it without the relay |
| macOS | `ip = "private"` with `forward` or `egress` | a process of sandy's own user that listens on a forwarded or egress port at an address the Mac gains while sandy runs receives the program's connections there, and once the relay or the broker has ended, without `children = "contained"`, any process that binds the port does |
| macOS | `ip = "private"` with `forward` or `egress`, without `macos.relays = "ipv4"` | a host on another link of the Mac whose IPv6 link-local address equals one of the Mac's, such as `fe80::1`, receives the program's connections to those port numbers there |
| macOS | `egress` | every local user reaches the broker and connects out through it, as sandy's user, to the destinations of `reach` |
| macOS | `view = "policy"` | the names in the root directory, with their metadata through a bulk listing that asks for the type; the directories above each policy path; the volume and mount point that `statfs` names for a policy path |
| Windows | a directory in the policy | a file moved out of a granted directory keeps its grant |
| Windows | `ip = "none"` or `ip = "private"` | the program's own processes in its AppContainer reach each other over loopback (127.0.0.1 and ::1), because Windows isolates loopback between the AppContainer and the rest of the machine, not within one |

`children = "contained"` on macOS gets a warning as well, although it gives its full
guarantee: it denies `posix_spawn`, which many runtimes start processes with, and that cost is
easy to miss. So does `macos.relays = "ipv4"` with a forwarded or egress port: it denies IPv6
sockets there, which Java and .NET use for IPv4 addresses by default.

Within an exception sandy still closes every route it can. When a platform leaves one way to an
effect open, sandy denies the other ways it can deny, unless that breaks common programs: macOS
denies `fcntl(F_SETOWN)` under `signals = "isolated"` although the owner ioctls stay open, so a
later macOS that closes the ioctls needs no change in sandy to close the rest. Each open route
has a test that records it, so a platform release that closes one shows up as a failing test,
and sandy then removes the exception.

The backend reports each requirement as enforced (naming the mechanism) or unavailable (naming the
reason). `EnforcementPlan::new` treats a requirement without a report as unavailable, so a backend
cannot weaken the sandbox by omission. `sandy check` prints the plan. `sandy run` starts the
program only when every requirement is enforced, and the backend's `run` must fail rather than
continue if any mechanism fails while it is applied.

`plan` changes nothing on the host, so some reasons for `run` to refuse are invisible to it: a
port of a relay that another process holds, for example. `check` therefore also calls the
backend's `verify`, which may touch the host as long as it leaves it as it found it; its reports
join the plan, where an unavailable report wins. `run` does not call `verify`: it finds out while
it applies the sandbox, and it stays the authoritative answer, because a trial bind can be stale
a moment later.

## Process model

- Linux and macOS: sandy restricts itself, then calls `execve` on the program. The program keeps
  sandy's process ID, so the caller's process handle, signals and exit status refer to the program
  directly.
- Linux and macOS with `process.children = "contained"`: sandy forks the program and stays its
  parent. sandy forwards every signal it receives to the program, except `SIGCHLD`, `SIGCONT`,
  `SIGTTIN`, `SIGTTOU` and the fault signals, which it cannot wait for, `SIGPIPE`,
  which its own writes raise and which it ignores, and `SIGKILL` and `SIGSTOP`, which cannot be
  caught at all. It exits with the program's exit status, or 128 plus the signal number when a
  signal ended the program. With a terminal, sandy follows job
  control: the program's process group gets the terminal when the program uses it, and the rest
  of sandy's job gets it back when it uses it; any other stop of the program stops sandy, and
  `SIGCONT` to sandy continues the group.
- Linux with `--explain`: sandy forks the program and stays its parent, as with `contained`,
  because the watcher of the diagnostic mode must be allowed to read the memory of the program.
  It waits for the program and exits with its status, or 128 plus the signal number. Both
  processes are in the group the caller started, so a terminal signal reaches the program
  directly and job control works. sandy passes on to the program the signals sent to it, as
  with `contained`, except `SIGINT` and `SIGQUIT`, which it ignores as `system(3)` does, the job
  control signals, which stop and continue it with the program, and a signal the kernel sent
  for the terminal or the group (`SI_KERNEL`), which the program received itself. A signal sent
  with `kill` to the whole group reaches the program twice, because sandy cannot tell it from
  one sent to sandy alone. `SIGKILL` ends sandy alone and leaves the program without its
  watcher, still confined (see below). `process.end_with_parent` ends a program that outlasts
  `SIGTERM` with `SIGKILL`, so sandy refuses that combination unless `contained` supervises.
- Windows: there is no `execve`. sandy creates the program inside the AppContainer and a job
  object with kill-on-close, waits, and exits with the program's exit code. If sandy dies, the job
  closes and the program dies with it.

## Diagnostic mode

`run --explain` answers "which grant does this program need". It exists because a denial is
often invisible: a program that cannot read a path treats the file as missing and runs on with
less than it was built for, and neither its output nor its logs say so. Without the mode the
only way to find such a path is to widen the policy until the program behaves differently.

The mode is off by default, and it must not weaken the sandbox. Three rules follow from that.

**Observing is sound where deciding would not be.** On Linux the mode installs one more seccomp
filter in the program, which returns `SECCOMP_RET_USER_NOTIF` for the calls that take a path and
that Landlock can deny. A thread of sandy reads the path out of the calling process and answers
`SECCOMP_USER_NOTIF_FLAG_CONTINUE`. The kernel documents that this notification must not be used
to make a security decision, because the program can change the path between the watcher's read
and the call. That objection is about deciding, and nothing here decides: the watcher has one
answer, and it is "carry on", so the kernel performs the call with the program's own credentials
and its own Landlock domain. A path the program rewrites after the read makes the report wrong,
never the sandbox weaker. For the same reason the watcher never uses
`SECCOMP_IOCTL_NOTIF_ADDFD`, which would hand the program a descriptor the watcher opened and
would move the decision out of the kernel.

**The filter cannot change a decision either.** The observer returns only `USER_NOTIF` or
`ALLOW`. The kernel takes the most restrictive answer of all filters, and `USER_NOTIF` is less
restrictive than every action the other filters use, so a call they deny keeps their answer and
never reaches the watcher (measured on Linux 7.2). `ALLOW` is what they would have returned
anyway. A unit test checks this over every system call number for both filter configurations,
and the compiled program is in the committed snapshot.

**A report that is incomplete must say so.** The mode names the paths of the calls it watches
that no rule of the run grants, and it says in its own output that it does not see every denial.
What it cannot see is listed in [linux.md](linux.md), "Diagnostic mode": calls that seccomp
already denies never notify, the verdict comes from sandy's rules and not from the kernel's
answer, and the calls that take two paths are not watched. An integrator who reads silence as
"nothing was denied" would be wrong, so a backend that cannot report at all refuses the option
instead of printing nothing.

What the mode costs: two context switches per watched call, sandy as the program's parent, a
program that outlives sandy whose watched calls then fail with `ENOSYS`, and `EINTR` from a
watched call that a signal interrupts while it waits, in a program whose handler does not
restart calls. That is why it is opt in and documented as a tool for working out a policy. It
also runs a watcher in sandy's own process for as long as the program runs, which parses bytes
the program controls; it reads at most one path of bounded length per call and never acts on
what it reads. On Linux the watcher is a thread with a seccomp filter of its own, which ends
sandy at any call the watcher does not need. The thread shares its memory with sandy's
unconfined main thread, so the filter narrows what a flaw in the parsing reaches without walling
it off.

## Mechanisms (each backend section is owned by its backend)

### Linux

Details, the minimal system set and the known limitations are in [linux.md](linux.md).

- Order: mark descriptors above 2 close-on-exec, `PR_SET_NO_NEW_PRIVS`, check that the process
  has one thread, Landlock `restrict_self`, up to four seccomp filters (TSYNC), `execve`.
  Everything that can fail on bad input is prepared before the first step. Landlock restricts
  the calling thread, so the thread check is what makes the domain cover the whole process.
  With `ip = "private"` or `view = "policy"` the namespaces come first, after the relay, the
  egress broker and the watcher have started.
- `ip = "private"`: one `unshare(CLONE_NEWUSER | CLONE_NEWNET)` in the process that becomes the
  program (sandy in the exec model, so the program keeps its process ID; the forked child with
  `contained` and with `--explain`), then `setgroups` denied and single-ID maps of the user's own
  user and group ID, never root, and `lo` up. sandy binds the forward listeners inside and hands
  them to the relay over a socket pair, and the egress listener to the broker, drops every
  capability of the namespace, the bounding set included, and with exposed ports starts a socket
  factory there. The filters read their IDs after the maps, and the program's filter is the one
  of `ip = "all"`; it still denies namespaces and mounts. `plan` reads
  `user.max_user_namespaces`, `kernel.unprivileged_userns_clone`, and
  `kernel.apparmor_restrict_unprivileged_userns` with sandy's AppArmor label: under the Ubuntu
  restriction an unconfined sandy gets no rights in its user namespace, and the requirement needs
  setup (an AppArmor profile). `check` also tries the steps in a forked child.
- `sandy setup` under that restriction: as root it writes and loads
  `/etc/apparmor.d/sandy-setup.PATH`, an unconfined profile with only `userns,` for the path of
  the running sandy, marked as sandy's on its first line. It refuses a path that is not
  root-only from `/` down (owner root, no write for group or others, no symbolic link, no
  `nosuid` mount). `--install-copy` installs the running image as
  `/usr/local/libexec/sandy/VERSION/sandy` and prepares that path; a portable sandy whose copy
  has its bytes and a loaded profile execs the copy for `run` and `check` before it opens
  anything, and passes its own names in `SANDY_STARTED_AS`, which every sandy checks like its own
  and removes from its environment. `--elevate` uses pkexec: of sandy's own root-only file, or of
  a fixed shell script that copies `/proc/PID/exe` of its waiting parent, checks the bytes and
  the parent, and runs the copy's setup. Details in [linux.md](linux.md), "Setup on Ubuntu".
- `view = "policy"`: a mount namespace in the same `unshare`, with the user namespace (the network
  namespace only with `ip = "private"`). Right after the maps the process builds the view with
  descriptors only: `/` private; every path of a Landlock rule opened with `open_rule` after the
  `unshare`, because a descriptor of the host's namespace cannot be bound; each cloned with its
  submounts (`open_tree` with `OPEN_TREE_CLONE | AT_RECURSIVE`), given its flags on every mount
  (`mount_setattr` with `AT_RECURSIVE`) and moved onto its own path of a new tmpfs root
  (`move_mount`). A bind is read-only unless a writable path holds it, without execute unless a
  `read_exec` path, the program file, the loader or a library directory of the system set holds
  it, nosuid, and nodev outside `/dev`; `/proc` is read-only. The links on the way to the paths
  are recreated, `/dev` holds null, zero, full, random and urandom, and `tty` and a devpts
  instance of its own with a terminal, the tmpfs becomes read-only, and `pivot_root` makes it
  the root and detaches the old one. Landlock decides access as without the view. It requires
  the fix of Landlock erratum 3, read from the errata bitmask; `run` refuses a directory on a
  standard stream, through which the program would reach the hidden paths by name.
- Landlock (ABI 1 or newer, read from the kernel at run time) handles every file system right of
  the ABI. Writable paths never get execute, symbolic link, named pipe or device rights. Each
  rule path is opened without following links and must still be the file sandy planned with. ABI 6
  scopes signals (required for `signals = "isolated"`, unless `children = "contained"` runs the
  program in a PID namespace) and abstract Unix sockets; ABI 9 denies
  pathname Unix sockets when `unix_sockets = "none"`; ABI 4 denies TCP when `ip = "none"`. With
  `ip = "client"` a second ruleset, built with raw system calls because the `landlock` crate
  does not know the UDP right, lets sockets bind only port 0, a port the kernel chooses: TCP from
  ABI 4, UDP from ABI 10. It decides nothing about listening: `listen` on an unbound socket picks
  a port without that check.
- Seccomp allowlist: the reviewed system call table of Linux 7.2; every other number, x32 numbers,
  `clone3`, `openat2`, `fanotify_init` and `name_to_handle_at` fail with `ENOSYS`; other CPU
  architectures are killed.
  `openat2` stays out because its flags live in memory, so the rule against access mode 3 below
  cannot be applied to it. The cost is GNU tar, which does not fall back (docs/linux.md).
- Seccomp socket family filter: `socket` with a family outside the policy (an allowlist), or
  with `ip = "all"` or `ip = "client"` an IP protocol outside `streams::IP_PROTOCOLS`, whose
  module the kernel would load, fails with `EAFNOSUPPORT`, so that programs fall back as they
  would on a kernel without the family.
- Seccomp extended attribute filter: with `path_metadata = "deny"`, the reads that take a path,
  and `fsetxattr` and `fremovexattr` on a descriptor, fail with `ENOTSUP`, the error of a file
  system without extended attributes, so that programs skip them instead of failing.
- Seccomp denylist (`EPERM`): datagram socket pairs when Unix sockets are denied, with
  `ip = "client"` `listen`, `accept` and `accept4` for every socket, io_uring, ptrace
  and `process_vm_*`, `MADV_MERGEABLE` and `PR_SET_MEMORY_MERGE`, System V IPC, POSIX message
  queues, namespaces,
  `CLONE_PARENT`, mounts, `bpf`, `perf_event_open`, `userfaultfd`, keyrings, the security module
  calls, `PIDFD_GET_INFO`, `TIOCSTI`/`TIOCLINUX`/`TIOCSETD`/`TIOCEXCL`, the console ioctls that
  change a virtual console or its keyboard, the file system ioctls that change a file through a
  read-only descriptor (inode flags, fs-verity, fscrypt policies, btrfs subvolumes, deduplication),
  file leases and delegations (`F_SETLEASE`, `F_SETDELEG`), with `signals = "isolated"` also
  `TIOCSPGRP`, `TIOCSWINSZ`, `TIOCSIG` and `setpgid` into a process group that exists, calls that
  need capabilities and the arguments of allowed calls that need one (see docs/linux.md), `open`
  with access mode 3 (Landlock does not check it), the path-based
  metadata calls and `fchown` when `path_metadata = "deny"`, setuid and setgid mode bits, changes
  of the limits, priority and CPU affinity of other processes, and before Landlock ABI 3 `truncate`
  for every path and `O_TRUNC` on a read-only open.
- `process.children = "none"`: the seccomp denylist allows `clone` only with `CLONE_THREAD` and
  denies `fork` and `vfork`; `clone3` fails with `ENOSYS`, so threads use `clone`.
- `process.children = "contained"`: sandy becomes a child subreaper and forks a guard process,
  which leads a new process group, and then the program, which joins that group and confines
  itself as above. The seccomp denylist denies `setsid` and `setpgid`, and the Landlock signal
  scope keeps the program from signaling sandy or the guard, so no process the program starts can
  leave the group. The guard watches the program with a pidfd and sandy through a pipe, and kills
  the group when either ends, so the group ends with the program even while sandy is stopped. The
  program writes its own process ID into that pipe, after it has joined the group, so the guard
  learns it without sandy running again after the fork and never before a kill of the group would
  reach the program. sandy also kills the group when the program exits and waits until the group
  is gone. With exposed or forwarded ports the guard also watches the relay with a pidfd, and the
  egress broker with another; when one ends first, it tells sandy before the kill, and sandy
  exits with status 125 (rule 5 of "Forwarded ports").
  Where the host gives sandy a user namespace (for `contained` alone after a trial in a forked
  child), the child unshares a PID namespace and forks an init of sandy, PID 1, and the program,
  PID 2, which leads a group of its own; both become sandy's children. The init reaps the
  namespace's orphans and ends when the program or sandy ends (pidfds), and the guard kills it
  through a pidfd, which ends every process of the namespace. The guard, sandy and the init are
  outside the program's group and namespace, so below Landlock ABI 6 the namespace isolates
  signals: `kill`, `pidfd_open`, `F_SETOWN` and the priority calls reach no outside process by
  ID. A policy that grants a path of `/proc` keeps `contained` without the namespace, also with
  the file system view: the host's `/proc` names processes by their IDs outside it, and a
  `/proc` of the namespace would hide the host's files of the grant. `setsid` and `setpgid` stay
  denied, so a policy behaves the same with and without the namespace.
- `process.end_with_parent`: a watcher process, forked twice like the relay, polls pidfds for
  sandy's parent and for the program (with `contained`: the supervising sandy). When the parent
  ends, it sends SIGTERM and SIGCONT and, 5 seconds later, SIGKILL. Like the relay, it runs in a
  session of its own with every signal except the fault signals blocked, so no process group or
  terminal signal reaches it. It confines itself with no_new_privs, Landlock without file access
  or TCP, and a seccomp filter limited to polling, `pidfd_send_signal`, the readiness report,
  ending and the memory and clock calls of the Rust runtime; it has no Landlock signal scope,
  because it must signal the program. Its filter allows the signal only through the program's
  descriptor. It is also undumpable, so a program with a write grant on `/proc` cannot make the
  out-of-memory killer end it first; the supervising sandy and its guard do the same, sandy from
  before it forks the guard and the program, so that neither child starts dumpable. With
  `--parent-start` sandy checks field 22 of `/proc/PID/stat` of the named process after
  `pidfd_open` instead of asking whether it is its own parent; a caller can also let the kernel
  do the whole job with `clone3(CLONE_PIDFD_AUTOKILL | CLONE_AUTOREAP | CLONE_NNP)` on Linux 7
  (see docs/linux.md).
- Exposed and forwarded ports: one relay, forked twice from the single-threaded sandy before it
  confines itself, so it is not a child of the program. It watches the program with a pidfd and
  ends at most one second after it (rule 5 of "Forwarded ports"), or two seconds when the program
  stopped it, which a timer the relay re-arms takes care of. The timer exists only under
  `signals = "any"`; under `"isolated"` the program cannot stop the relay. It confines itself with
  no_new_privs, Landlock without file access (TCP connect only to the relay targets from ABI 4)
  and a seccomp filter limited to TCP, copying, threads and that timer. A forwarded port refuses
  a connection the kernel names as another user's (rule 6 of "Forwarded ports"). With
  `ip = "private"` the relay stays in the host's namespace: it receives the forward listeners
  from inside and checks no owner there, because no other user reaches that namespace, and it
  connects an exposed port with a socket that the factory inside creates. The factory is a helper
  without capabilities, file access or TCP rights whose filter allows creating TCP sockets and
  passing them on, and nothing else. The relay ends when the factory ends, so the guard of
  `contained`, which watches the relay, ends the program then.
- `network.egress`: a broker process, forked twice before the `unshare` like the relay, so it
  stays in the host's network namespace and is no child of the program. Its listener on
  `127.0.0.1:PORT` is bound inside the sandbox's namespace and handed to it as the forward
  listeners are handed to the relay. It answers the host's part of the destination check over a
  `NETLINK_ROUTE` socket that sandy opens and tries before it starts the broker (`RTM_GETROUTE`
  and `RTM_GETADDR`), and confines itself with no_new_privs, Landlock without file access and
  without TCP bind (from ABI 4) but with TCP connect left unhandled, the signal and abstract
  socket scopes (from ABI 6), and a seccomp filter limited to TCP sockets, the route lookups,
  copying, threads and its watchdog. It ends with the program as the relay does, with the same
  watchdog under `signals = "any"`, but it takes its backlog also after a stop: only the
  program's own processes and processes of sandy's user that entered the namespace reach it, and
  every connection is still checked (docs/linux.md, "Egress broker").
- Refused: no Landlock (the reason names the fix), no seccomp, root or any capability, a writable
  path that overlaps the minimal system set (rule 6), a program whose ELF loader no executable
  path covers (the kernel opens it during `execve`), `ip = "private"` and `view = "policy"` where
  user namespaces are disabled or a trial of them fails (under Ubuntu's AppArmor restriction they
  need setup), `egress` with them, or where the kernel does not answer the broker's route
  lookups, and `view = "policy"` on a kernel without the fix of Landlock erratum 3.

### macOS

- A Seatbelt profile (SBPL) generated from the policy: deny by default, then the policy paths, the
  minimal system set, a list of readable sysctls, and networking when the policy allows it. Every
  path is a profile parameter, so no character in a path can change the profile.
- sandy applies the profile to itself with `sandbox_init_with_parameters`, loaded at run time from
  `libsandbox` with `dlopen`, and checks with `sandbox_check` that it took effect. Then
  `posix_spawn` with `POSIX_SPAWN_SETEXEC` replaces sandy with the target, like `execve`.
  `POSIX_SPAWN_CLOEXEC_DEFAULT` makes the kernel close every descriptor except 0, 1 and 2.
- No Mach or XPC service. This closes LaunchServices, Apple events, launchd jobs and the
  pasteboard, through which another process could act for the target.
- Setuid and setgid files never execute. The root of a writable path cannot be deleted or
  replaced, so the target cannot redirect the next run with a symbolic link.
- Outside the policy every path answers `ENOENT`, as a path that does not exist, to every call,
  and every other process `ESRCH`; `getpriority`, `getpgid` and `getsid` are denied by number.
  Writes to a `read` path keep `EPERM`. With `unix_sockets = "all"`, `access`, `statfs`,
  `chdir` and the path from `getattrlist` answer for every path again, because a connect to a
  socket outside the policy needs that check. `kill(pid, 0)` still tells a live process ID from
  an unused one.
- Hard links are denied; clones (`std::fs::copy`) work only into writable paths and only from
  files the target may read. ptrace attach is denied (Seatbelt checks it as `system-debug`).
- dyld needs the root directory itself (only the names in `/`) to find the shared cache, so the
  minimal system set contains it; with `system = "none"` no program can start on macOS, so the
  backend refuses that unless a policy path covers "/".
- Name resolution is part of `ip = "all"` and `ip = "client"`: the profile allows exactly the
  Unix socket of mDNSResponder, so DNS does not need `unix_sockets = "all"`.
- `ip = "none"` also denies by number the calls of NECP, the kernel's network policy layer that
  Network.framework works through. With `ip = "client"` and `ip = "all"` they stay allowed,
  because URLSession and Network.framework fail without them.
- `ip = "private"` is relay only, because macOS has no loopback of a process's own: TCP out only
  to the forwarded and egress ports and in only on the exposed ports, no UDP, no name resolver
  (names come from `/etc/hosts` only), NECP denied. Seatbelt's `localhost` is every address of
  the Mac, so the relay and the broker bind their ports without listening at the wildcard
  addresses and at every current address of the Mac, and a connection to one at another address
  meets a socket of sandy's that never answers; a socket that already holds such an address
  makes `run` refuse. Forwarded and egress ports need `signals = "isolated"`. The program's own
  processes cannot use loopback among themselves. With `macos.relays = "ipv4"` the rules for the
  forwarded and egress ports are `tcp4`, for IPv4 sockets only.
- The egress broker is a helper process of its own, forked twice like the relay and watched like
  it, with its own profile: accept on its port, TCP out with every address of the Mac denied
  after that allow, the routing sysctl for `getifaddrs` and the routing table, no files, no Mach
  services. Its `HostNetwork` answer comes from both at every connection.
- `filesystem.view = "policy"` is the `ENOENT` rule that every profile has; it is unavailable
  with `unix_sockets = "all"`, which allows the existence check for every path.
- `ip = "client"`: `network-outbound` and `network-bind` for IP sockets, `network-inbound` for UDP
  only. Seatbelt checks `listen` and `accept` as `network-inbound`, so no TCP socket listens, and
  also every datagram that a socket which is not connected receives, which UDP clients need.
- Metadata (mode, owner, flags, times, extended attributes, ACLs) can change only on `read_write`
  paths, through paths and open descriptors alike. `linux.path_metadata = "allow"` only drops the
  requirement; the profile is the same.
- Exposed and forwarded ports: sandy binds the listeners, forks one relay twice so that launchd
  adopts it (it is not the program's child), and the relay watches the program's process ID with
  kqueue (`NOTE_EXIT`). The relay has its own profile: accept on its listeners, connect only to
  the targets (the program's ports for `expose`, `to` for `forward`), no files, no Mach services.
  Like the watcher below, it runs in a session of its own with every signal except the fault
  signals blocked. sandy execs only after the relay reports ready.
- `process.children = "none"`: the profile denies `process-fork`, which Seatbelt checks for
  `fork`, `vfork` and `posix_spawn`; threads and `execve` stay allowed.
- `process.children = "contained"`: sandy forks a guard process outside the program's group,
  which forks an anchor that leads a new process group, and then the program, which joins that
  group, writes its own process ID into the pipe to the guard, applies the profile and executes
  the target with `execve` after marking every descriptor above 2 close-on-exec. As on Linux, the
  program sends the ID itself, and only once it is in the group, so the guard learns it without
  sandy running again after the fork and never before a kill of the group would reach the
  program. The profile denies `setpgid`, `setsid` and `posix_spawn` with
  `syscall-unix` rules (the flags `POSIX_SPAWN_SETSID` and `POSIX_SPAWN_SETPGROUP` change the
  group inside `posix_spawn`, which no rule can inspect), and the signal rule keeps the program
  from signaling sandy, the guard or the anchor, which run outside the sandbox. The guard watches
  the program, a pipe from sandy and, with exposed or forwarded ports, the relay with kqueue and,
  when one ends, sends SIGKILL to the group until no live process is left: on macOS a process
  being forked can miss one signal for its group. sandy does the same after the program exits.
  When the relay ended first, the guard tells sandy before the kill, and sandy exits with status
  125 (rule 5 of "Forwarded ports"). The guard reaps the anchor, which keeps the group's ID
  reserved, only after sandy is done or gone.
- `process.end_with_parent`: a watcher process, forked twice like the relay, registers
  `NOTE_EXIT` for sandy's parent and for the program (with `contained`: the supervising sandy)
  and then applies its own profile (no files, no network, no Mach services, signals allowed).
  sandy checks after the watcher is ready that its parent is unchanged, so the registration names
  the real parent. When the parent ends, the watcher sends SIGTERM and SIGCONT and, 5 seconds
  later, SIGKILL. macOS has no pidfd: the watcher signals by process ID and checks for the
  program's end right before each signal. With `--parent-start` sandy checks the named
  process's recorded start time instead of `getppid`, before and after the registration. It
  refuses process 1: macOS has no child subreaper, so launchd is the parent of every orphan.
- `sandy check` compiles the profiles, so it reports operations or filters that this macOS does
  not know, and applies the program's profile in a helper process that ends right after, so it
  also reports a profile that compiles but is refused when applied.
- Refused: sandy running through Rosetta, and on Apple silicon a program without arm64 code, or
  a script whose interpreter has none; Rosetta cannot load its runtime inside the sandbox.
- `docs/macos.md` describes the profile, the system set with a reason per entry, and the known
  limitations.

### Windows

Details, limitations and sources: `docs/windows.md`.

- Requires Windows 10 1809 (build 17763) or later; `IpNetworkDenied`, `IpNetworkPrivate` and
  `InboundIpDenied` also require the fix for CVE-2021-41338. `sandy.exe` starts on older builds
  and the plan names the reason.

- AppContainer named by `windows.appcontainer_name`; sandy creates its profile on first use.
  While a program runs, a second run under the same name with a different policy is refused,
  because processes in one AppContainer can reach and control each other (see "Local servers in the
  sandbox" in `docs/windows.md`). One policy per AppContainer while runs overlap, coordinated
  through a lock file of the user and keyed on the AppContainer SID, because Windows derives the
  SID from the name without regard to case.
- File grants: one capability per policy path (named after the AppContainer, the level and the
  file ID), with one inheritable ACE on the path. The program starts with the capabilities of the
  current policy only, so grants of older policies grant nothing. A run never removes grants
  (`sandy setup --remove` does) and serializes its DACL changes with a lock file of the user, so
  concurrent runs do not conflict.
  Read and read-write never contain `FILE_EXECUTE`; read levels contain no right that changes
  metadata. sandy refuses to propagate a grant through junctions or symbolic links, and refuses
  a policy path on a network share. The system set is what Windows grants ALL APPLICATION
  PACKAGES; `system = "none"` is unavailable.
- Network capabilities `internetClientServer` and `privateNetworkClientServer` only with
  `ip = "all"`, `internetClient` alone with `ip = "client"`: Windows Firewall then drops what
  other hosts send that the program did not start, and the program reaches no host of a network
  that Windows counts as private or domain network, because no capability allows only
  connections out into one. Connections from the program to loopback listeners outside need the
  loopback exemption, which `sandy setup` installs for `ip = "client"` and `ip = "all"`
  (administrator rights); connections from outside to the program are always blocked. An exempt
  AppContainer reaches loopback without capabilities, so `ip = "none"` and `ip = "private"`
  refuse it, and `sandy setup` removes the exemption for them.
- `ip = "private"`: the AppContainer of `ip = "none"`, without capabilities and exemption. Its
  processes and the relays reach each other over loopback; loopback isolation and the missing
  capability cut off the rest of the machine and the network, a datagram out is dropped at the
  connect layer, and the DNS Client service resolves no name for it.
- `network.egress`: `sandy __broker` runs in an AppContainer of its own (the program's name plus
  a reserved suffix, so no program shares it) with the `internetClient` capability, and
  `privateNetworkClientServer` for `reach = "public-and-local"`. The program reaches it through a
  `sandy __forward` relay over an AF_UNIX socket that sandy binds and the broker inherits; the
  broker is in the relay job, so it ends with the program. `sandy_core::destination` limits
  where it connects, and the broker's own loopback isolation also keeps it off this machine; the
  plan refuses a broker AppContainer with the loopback exemption, which `sandy setup` removes.
- `filesystem.view = "policy"` is unavailable: Windows hides no path from an AppContainer
  without administrator rights, and the sandbox answers `ERROR_ACCESS_DENIED` for an existing
  path outside the policy.
- `UnixSocketsDenied` through the file ACL: AF_UNIX connect needs write access to the socket
  file, which the program has only in read-write paths and its profile folder.
- The AppContainer profile folder (`...\Packages\<name>\AC`, which holds `TEMP`) is private,
  writable scratch space that Windows always creates and sandy cannot remove. sandy reduces the
  AppContainer's allow entry on it to the rights of a `read_write` path, so the entry loses
  `FILE_EXECUTE`, `WRITE_DAC` and `WRITE_OWNER`: the program can neither execute what it writes
  there (the writable-never-executable rule) nor rewrite the permissions to grant execute back.
  A deny entry would not help: the AppContainer access check ignores a deny ACE for the package
  SID. The folder holds no user data and persists across runs.
- Writable paths (rules 3 and 6): the plan refuses a `read_write` path that overlaps the Windows
  or a program files directory, or where ALL APPLICATION PACKAGES, ALL RESTRICTED APPLICATION
  PACKAGES, the policy's AppContainer or one of its network capabilities may execute files, also
  only files created later. When sandy adds the grant it walks the tree and refuses a file below
  the path whose own permissions say the same.
- sandy sets `SystemRoot` and `LOCALAPPDATA`; without the latter Windows refuses to create an
  AppContainer process. Windows sets `LOCALAPPDATA`, `TEMP` and `TMP` to the profile folder.
- Job object with kill-on-close, no breakaway and all UI restrictions. The program is created
  suspended and assigned before it runs. Inside an outer job with UI restrictions Windows cannot
  nest this job, so the plan refuses; sandy never breaks away from an outer job.
- `network.expose`: sandy binds the listening socket outside the AppContainer and starts
  `sandy.exe __relay` in the program's AppContainer and a job of its own before the program. The
  relay has no network capability and only read and execute on `sandy.exe`; the program can
  control the relay, which gives it nothing beyond the exposed listener. The plan refuses when
  `sandy.exe` cannot be granted or lies in a read-write path; `sandy setup` with the policy adds
  the grant.
- `network.forward`: `sandy.exe __forward` in the program's AppContainer and the relay job
  creates the program's listener itself and passes each connection over an AF_UNIX socket that
  only the relays may open to sandy, which connects to the target. No loopback exemption is
  needed. The plan also refuses when AF_UNIX is missing or the socket paths exceed 107 bytes.
- `process.children = "none"`: the program's job has an active-process limit of 1, which the
  program cannot change; its console host is not counted. The relays always run without a
  console and with `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`, so the program cannot start
  processes through them.
- `process.children = "contained"` needs nothing beyond the job: every child joins the program's
  job (no breakaway), sandy ends the job when the program exits, and kill-on-close ends it when
  sandy dies. `allowed` behaves the same on Windows.
- `process.end_with_parent`: sandy finds its parent in a process snapshot, opens it and checks
  that it was created before sandy (Windows records only the parent's process ID, which another
  process can have once the parent has ended). With `--parent-start` it requires that exact
  creation time instead, which a clock change cannot alter and a reused process ID cannot have.
  sandy waits for the program and the parent, and ends the program's job when the parent ends.
- Relay lifetime (rule 5): when the program exits, sandy ends its job at once and closes the
  relays' standard input; the relays accept what already waits in the backlog, close their
  listeners, drain for at most one second and end; sandy ends the relay job one second after
  the program's end.
- Handle inheritance limited to the standard handles with `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.
  The program gets its own console and never a console handle of sandy; sandy relays its console
  through pipes and ends the job on Ctrl+C.

## Exit status

| Status | Meaning |
|---|---|
| program's status | `sandy run` started the program |
| 128 + signal number | Linux and macOS with `process.children = "contained"`, and Linux with `--explain`: a signal ended the program |
| 125 | sandy failed or refused (invalid policy, unenforceable policy, a socket on a standard stream the policy denies, a pseudo-terminal master on one with `signals = "isolated"`, setup failure); where sandy stays the parent also a failure while it supervises the program |
| 0 / 1 | `sandy check`: enforceable / not enforceable |
| 2 | `sandy check`: not enforceable on this host until `sandy setup`, run once with administrator rights, prepares it; nothing else is missing |
| 0 | `sandy setup` and `sandy setup --remove`: done, or nothing to do |
| 3 | `sandy setup` and `sandy setup --remove`: not done, and nothing changed: the rights were not given (run without administrator rights and without `--elevate`; with `--elevate`, a dismissed prompt, no authentication agent, not authorized), setup is not allowed for this binary, or on Linux user namespaces are disabled on the host, which setup cannot change |

The caller sees sandy's process ID where sandy stays the parent, and 125 means both "sandy
refused" and "the program exited with 125". These are additions, not changes: `--status-fd`
carries the program's process ID and how it ended on a descriptor of the caller's choosing,
which sandy makes close-on-exec and keeps out of what the program inherits. The lines are
`pid N`, then `exited N` or `signaled N`, or `failed` when sandy itself failed. See README.md,
"The status record". No exit status changes meaning, because callers parse the documented ones.

Status 2 of `check` lets a calling program tell "this host needs preparing" from "this host
cannot do it" without parsing text: it can ask the user for administrator rights, run
`sandy setup` with the same policy, and check again. A plan item that needs setup says so
(`Status::NeedsSetup`), and when several reports cover one requirement, one that setup cannot fix
wins, so status 2 never promises more than setup gives. `run` still refuses such a policy with
status 125.

Status 3 of `setup` lets the same program tell "setup did nothing" from "setup failed" (125,
where part of it may be done): after a 2 from `check` it runs `sandy setup --elevate`, adding
`--install-copy` on Linux for a sandy outside a root-only path, checks again on 0, and on 3 runs
its fallback policy, which does without what setup prepares. Every refusal of setup says what
to do instead.

## Testing

`sandy-probe` (in `sandy-cli`) performs one action per argument pair and reports `ok`, `denied`
or `error`. The escape tests in `crates/sandy-cli/tests/escape.rs` run it inside the sandbox. Each
denial is checked against a control run outside the sandbox, so a test cannot pass because the
action was impossible anyway. The same tests run on every platform; platform-specific escape
routes get additional tests. `check.rs` holds the agreement tests: for every case where `run`
refuses a policy, `sandy check` must refuse it too.

## Dependencies

sandy has seven direct dependencies: `landlock` and `seccompiler` on Linux, `windows-sys` on
Windows, `libc` on Unix, and `lexopt`, `serde` and `toml` everywhere. `deny.toml` turns that into
a rule the `audit` workflow enforces: only the crates listed there may be in the tree, at any
version, and only from crates.io. A crate that appears, an advisory, a yanked version or an
unexpected license fails the check. Advisories that report a crate as unmaintained or unsound
count as errors, not as notes.

### seccompiler

seccompiler's standalone repository is archived. Work continues in the rust-vmm monorepo, which
has published nothing newer on crates.io, so 0.5.0 of 2025-03-07 is the last release. sandy keeps
it, pinned by the lock file, for these reasons:

- It is a leaf crate, and its only dependency is `libc`.
- sandy uses a narrow part of it: `SeccompFilter`, `SeccompRule`, `SeccompCondition` with the
  `Dword` compares, the `Allow` and `Errno` actions, and `apply_filter_all_threads`. It assembles
  BPF and decides nothing.
- The system call numbers are sandy's own, taken from `libc::SYS_*`, so a stale table in
  seccompiler cannot reach the filters.
- `compiled_programs_match_the_snapshot` in `crates/sandy-linux/src/filter.rs` pins the compiled
  programs against `crates/sandy-linux/snapshots/x86_64.txt`, and the interpreter tests beside it
  check what those programs decide. A version of seccompiler that compiles the same rules
  differently is a diff to read, not a silent change.

No advisory against seccompiler exists today, so `deny.toml` has nothing to silence. If one
appears, the answer is a decision and not a quiet `ignore` entry: either replace the crate, or
write here why it stays and name the advisory in `deny.toml` with that reason. The other things
that would change the decision are a bug in its code generation and a filter sandy needs that it
cannot express. The replacement would not be another crate but a generator inside sandy, a few
hundred lines against the same `libc` constants, which the interpreter tests would then test
directly.

## Release integrity

The `release` workflow builds every target from a tag with `--locked`, keeps the path of the
checkout and of `CARGO_HOME` out of the binary, and packs the archives with sorted entries, a
fixed time and no owner. A second job builds one target in two directories and compares the
binaries, so a change that ties the output to the machine that built it is noticed.

Every archive gets a GitHub build provenance attestation, which names the workflow, the commit
and the run that produced it. The job verifies the attestations before it creates the draft, so a
release never carries an archive that cannot be checked. A user checks a download with `gh
attestation verify <archive> --repo <owner>/<repo>`.

`SHA256SUMS` says that the archives belong together, not who made them. A maintainer signature of
that file would say it, and there is none yet. The macOS binaries carry only the linker's ad-hoc
signature, and `sandy.exe` has no Authenticode signature; the workflow holds both steps, skipped
until the certificates exist.

## Code layout

| Crate | Role | May depend on |
|---|---|---|
| `sandy-core` | policy, validation, requirements, plan, backend trait | no other sandy crate; `libc` on Unix, `windows-sys` on Windows |
| `sandy-linux`, `sandy-macos`, `sandy-windows` | one backend each; empty on other platforms | `sandy-core`, `sandy-relay` |
| `sandy-relay` | byte relay behind `expose` and `forward`, and the egress broker | `sandy-core`; `libc` or `windows-sys` |
| `sandy-cli` | command line, backend selection, test probe | all of the above |
