# Linux backend

The Linux backend restricts sandy's own process and then replaces it with the program
(`execve`). The program keeps sandy's process ID, signals and exit status. With
`process.children = "contained"` a forked child does this instead, and sandy stays its parent
(see "Contained child processes"). Three kernel features do the work:

- **Landlock** confines the file system, isolates the process from ptrace, and (from ABI 6)
  scopes signals and abstract Unix sockets.
- **Up to four seccomp filters** deny system calls that Landlock does not cover: socket
  families, io_uring, namespaces, System V IPC, metadata changes by path, and more.
- **no_new_privs** stops setuid programs and file capabilities from adding privileges.

With `ip = "private"` the program also runs in a user and network namespace of its own (see
"Private network"), and with `filesystem.view = "policy"` in a user and mount namespace that shows
it only the paths of its policy (see "File system view").

The research behind the design is in [research/linux-mechanisms.md](research/linux-mechanisms.md).

## Launch sequence

`sandy run` first prepares everything that can fail on bad input:

1. Detect the host: the Landlock ABI, seccomp support, no_new_privs, user IDs and capabilities,
   and which paths of the minimal system set exist. Detection only reads state.
2. Plan: `plan_for` turns the policy and the host capabilities into the plan items and the
   exact configuration to apply. If any requirement is unavailable, sandy refuses. The plan also
   records the device and inode of every path a Landlock rule names.
3. Build the Landlock ruleset with all its rules (see "Rule paths" below), compile the seccomp
   filters, and build the `execve` arguments and environment as C strings. Change to the working
   directory if the policy sets one.

With `ip = "private"` or `filesystem.view = "policy"` the process then enters its namespaces,
after the relay, the egress broker and the watcher have started and before step 4 (see "Private
network" and "File system view").

Then sandy resets SIGPIPE to its default action, because the Rust runtime ignores it and an
ignored signal stays ignored across `execve`. Not earlier: until then sandy writes for itself,
the record of `--status-fd` for one, and a reader that has gone must not end it. Then it
restricts itself, in this order:

4. Mark every descriptor above 2 close-on-exec (`close_range` with `CLOSE_RANGE_CLOEXEC`; before
   Linux 5.11 through the list in `/proc/self/fd`). Closing them now would also close the
   Landlock ruleset, which is still needed.
5. Set no_new_privs.
6. Verify that the process has exactly one thread (one entry in `/proc/self/task`), then
   `landlock_restrict_self`. sandy checks that the ruleset is fully enforced.
7. Install the filters in this order, each with `SECCOMP_FILTER_FLAG_TSYNC`: the allowlist, the
   denylist, with `path_metadata = "deny"` the extended attribute filter, and the socket family
   filter last (see "Seccomp"). With `--explain`, the observer filter follows them, without
   TSYNC (this kernel rejects TSYNC together with a new listener, measured on Linux 7.2: EINVAL;
   the process has one thread here and every thread it starts later inherits the filter).
8. `execve`. Only this call remains after the filters are in place.

Landlock and seccomp restrict the calling thread. sandy starts no threads and verifies this before
step 6, the filters use TSYNC, and `execve` ends every other thread, so the program runs with
exactly these restrictions. Every child inherits them. sandy does not use Landlock's
`LANDLOCK_RESTRICT_SELF_TSYNC` (ABI 8): with a verified single thread it changes nothing, it exists
only on new kernels, and it would hide a thread that should not exist. If `/proc/self/task` cannot
be listed, the Landlock-based requirements are unavailable.

### Rule paths

The checks of the policy look at paths, and a Landlock rule binds the file that a descriptor
refers to. Between the two, a process that can write a parent of a policy path, for example one
that a previous run left behind with `children = "allowed"`, could replace the path with a
symbolic link or with another directory, and the rule would then grant access where no check
looked. sandy therefore opens every rule path one component at a time with
`O_PATH | O_NOFOLLOW` and refuses the run when a component is a symbolic link (the rule paths are
canonical, so any link appeared after the resolver read them) or when the file it reaches is not
the one recorded in step 2. The unit tests next to `open_rule` in `launch.rs` swap a path between
the plan and the launch, which a real race cannot hit reliably.

What stays open: a directory moved into place between the resolver's checks and step 2, a window
in which sandy does not wait for anything. A process can only move a directory from a place it
can write, so the rule then reaches nothing that this process could not reach already.

## Mechanism per requirement

| Requirement | Mechanism |
|---|---|
| FilesystemConfined | Landlock with every file system right of the ABI handled. The seccomp filter denies opening a file with access mode 3 and `openat2` (see "Access mode 3"). Before ABI 3 it also denies `truncate` for every path and `O_TRUNC` on a read-only open. |
| NoPrivilegeEscalation | no_new_privs. The filters deny namespaces, mounts, `bpf`, `perf_event_open`, io_uring, keyrings, `userfaultfd`, calls and arguments that need capabilities, setuid and setgid mode bits, unknown system calls and other CPU architectures. sandy refuses to run as root or with capabilities. |
| ProcessMemoryIsolated | Landlock: a domain cannot ptrace, open `/proc/<pid>/mem` or `environ`, or use `process_vm_readv` on processes outside it (all ABIs). The denylist also denies `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, `kcmp`, `process_madvise`, `MADV_MERGEABLE`, `PR_SET_MEMORY_MERGE`, System V IPC and POSIX message queues, and changes of the limits, priority and CPU affinity of other processes. |
| InheritedHandlesClosed | Close-on-exec on every descriptor above 2. |
| EnvironmentControlled | `execve` with exactly the policy environment. The backend adds no variables. |
| IpNetworkDenied | The socket family allowlist has no `AF_INET`, `AF_INET6` or `AF_NETLINK`; io_uring is denied. From ABI 4, Landlock also denies TCP bind and connect. |
| IpNetworkPrivate | A user and a network namespace with only `lo`, which the relays and the egress broker alone cross; the filters of `ip = "all"` and the denial of namespaces (see "Private network"). |
| EgressBrokered | A broker process in the host's network namespace that serves a listener handed to it from inside the sandbox's, checks every destination with the kernel's routing tables, and is confined by its own Landlock domain and seccomp filter (see "Egress broker"). |
| PathsHidden | A user and a mount namespace whose read-only root holds only the paths the Landlock rules name, bound at their own paths; Landlock with the fix of erratum 3 and the denial of mounts and namespaces (see "File system view"). |
| InboundIpDenied | The denylist denies `listen`, `accept` and `accept4` for every socket. A second Landlock ruleset lets sockets bind only port 0: TCP from ABI 4, UDP from ABI 10 (see "Client networking"). |
| UnixSocketsDenied | The allowlist has no `AF_UNIX`, and socket pairs are limited to stream and seqpacket. From ABI 6, Landlock scopes abstract sockets; from ABI 9 it denies connections to pathname sockets. |
| SignalsIsolated | Landlock signal scope (ABI 6) and the denylist, which denies `setpgid` into a process group that exists and the terminal ioctls `TIOCSPGRP`, `TIOCSWINSZ` and `TIOCSIG` (see "Signals and the terminal"). On older ABIs, with `children = "contained"`, the PID namespace of the program instead (see "A PID namespace"); unavailable otherwise. |
| MetadataConfined | The denylist denies the metadata calls that take a path, and `fchown`, `fsetxattr` and `fremovexattr` on a descriptor (see "Metadata"). |
| ChildProcessesDenied | The denylist denies `fork`, `vfork` and `clone` without `CLONE_THREAD`; `clone3` fails with `ENOSYS` (see "Child processes"). |
| ChildProcessesContained | sandy stays the parent and ends the program's process group; the denylist denies `setsid` and `setpgid`. Where the host gives sandy a user namespace, the program also runs in a PID namespace that ends with its init (see "Contained child processes"). |
| EndsWithParent | A watcher process outside the sandbox ends the program when sandy's parent ends (see "Ending with the parent"). |
| ExposedPortsRelayed, ForwardedPortsRelayed | One relay process outside the program's sandbox, confined by its own Landlock domain and seccomp filters (see "Exposed and forwarded ports"). |

## Client networking

`ip = "client"` gives the program the sockets and the system set of `ip = "all"`, so it connects,
sends, resolves names and receives the answers, but it cannot take connections:

- The denylist denies `listen`, `accept` and `accept4` with `EPERM`, so no socket of the program
  takes a TCP connection, and `run` refuses a listening socket on a standard stream (see
  "Refusals"). The filter sees the descriptor of the call, not the family of its socket, so a Unix
  socket cannot listen either, also with `unix_sockets = "all"`; a program that serves on a Unix
  socket needs `ip = "all"` on Linux, and `check` warns about that combination.
- Landlock cannot deny listening. `listen` on an unbound TCP socket gives it a port without the
  check of `LANDLOCK_ACCESS_NET_BIND_TCP`: a ruleset that handles the right without a rule refused
  every `bind`, but not that `listen` (measured on Linux 7.2, ABI 10).
- A second Landlock ruleset handles the bind rights and grants them for port 0 only, which the
  kernel turns into a free port of its choice: `LANDLOCK_ACCESS_NET_BIND_TCP` from ABI 4 and
  `LANDLOCK_ACCESS_NET_BIND_UDP` from ABI 10. A client that binds before it sends, as musl's
  resolver and Rust's `UdpSocket::bind("0.0.0.0:0")` do, keeps working, and so does the port a
  socket takes when it first connects or sends, which the UDP right covers too (measured); a bind
  to a chosen port fails with `EACCES`. sandy builds this ruleset with the system calls
  themselves, because the `landlock` crate does not know the UDP right, and applies it right
  after the first one. Older kernels let a socket bind any port. For TCP that gives nothing
  inbound, because the socket cannot listen.
- What stays open, an exception of DESIGN.md: a UDP socket that is not connected receives
  datagrams from every sender, not only from the addresses it sent to, at the port the kernel
  chose for it, and before ABI 10 also at any port the program binds it to. No rule tells a reply
  from any other datagram: seccomp cannot read the address of a call, and Landlock checks binds
  and sends, not what arrives. An ICMP datagram socket likewise receives every echo reply for its
  identifier. `sandy check` prints a warning with what this kernel leaves open, and
  `ip_client_datagrams_from_others` and `client_binds_follow_the_landlock_abi` record it.

Measured on Fedora 44 under `ip = "client"`: curl over HTTP, `getent hosts`, Python's `urllib`
and `dig` against systemd-resolved all work as with `ip = "all"`.

## Exposed and forwarded ports

Both are pairs of a loopback address that the relay listens on and a loopback address it connects
to. `network.expose` listens on `listen` outside and connects to the program's port.
`network.forward` listens on the program's loopback port and connects to `to`, a service outside.
One relay process serves all pairs. sandy starts it before it confines itself (with
`ip = "private"` the program's side is a network namespace of its own, which changes steps 1 and
4 and the owner check below; see "Private network"):

1. sandy binds every listen address (for `forward` the program's own loopback port, which is
   therefore taken before the program starts) and opens a pidfd for its own process ID. The
   program keeps this ID after `execve`, so the pidfd refers to the program. With
   `process.children = "contained"` it refers to the supervising sandy, which ends after the
   program's process group has ended (see "Contained child processes").
2. sandy verifies that it has one thread and forks twice. The intermediate process exits at once,
   so the relay is not a child of the program and the program's `wait` never reaps it. The relay
   is a fork of sandy, not a new program; a single-threaded parent makes this safe. It starts a
   session of its own and blocks every signal except the fault signals, so that no process group
   or terminal signal (for example Ctrl+C) ends it while the program runs (see "Ending with the
   parent" for why these signals matter).
3. The relay points 0, 1 and 2 at `/dev/null` and closes every descriptor except its listeners,
   the pidfd, those three and a readiness pipe. It then confines itself:
   - no_new_privs;
   - Landlock with every file system right of the ABI handled and no rule, so it cannot open,
     create or execute any file; from ABI 4 TCP bind is denied and TCP connect is allowed only to
     the target ports of the pairs (Landlock TCP rules match the port, not the address); from
     ABI 6 the signal and abstract socket scopes;
   - the shared allowlist filter and a relay filter that allows only TCP sockets, `accept`,
     `connect`, reading and writing, polling, memory calls, `clone` for threads only (with
     `CLONE_THREAD` and without namespace flags, because the relay never starts a process),
     `timer_settime` for the watchdog below, `rt_sigtimedwait` and `FIONBIO`. Every other call
     fails with `EPERM`; `clone3` fails with `ENOSYS`.
4. The relay starts and joins one test thread (so a filter that blocks threads fails here) and
   reports "ready" over the pipe. sandy reads the report and continues only on success. Any
   failure of the relay is reported back, and sandy refuses to run. The relay then polls the
   pidfd and its listeners and relays every accepted connection in its own threads, up to
   `sandy_relay::MAX_CONNECTIONS` per listener at the same time. Before it confines itself it
   raises its soft limit of open descriptors so that they fit.
5. When the pidfd becomes readable, that is when the program ends (also by SIGKILL), the relay
   accepts the connections reported in the same round, closes its listeners, waits while accepted
   connections deliver their data, at most one second, and exits (DESIGN.md rule 5 of "Forwarded
   ports"), resetting the connections that are still open. A program that connects, writes and
   exits at once therefore does not lose its data, and the relay never outlives the program by
   more than one second, unless the program stopped it (step 6). With `contained` the pidfd is
   sandy's; the relay also polls a pipe whose write end only the guard holds, which ends when
   the guard dies with the program's group, so the relay ends with the group also while sandy
   is stopped. If sandy fails after starting the relay, sandy's process ends and the relay with
   it.
6. No process can block SIGSTOP, so with the default `signals = "any"` the program can stop its
   relay. A stopped relay neither sees the program end nor accepts anything, while the kernel
   keeps completing handshakes for its listeners; once someone continues it, it would relay
   connections that were made after the program ended. The relay therefore arms a timer that
   asks the kernel for SIGKILL two seconds later, and re-arms it on every turn of its poll loop,
   which waits at most 250 ms. A stopped relay is killed within those two seconds and its ports
   are released. The timer is created before the relay confines itself, so only `timer_settime`
   has to pass the filter. A relay that the host does not schedule for two seconds is killed as
   well, and its connections then end with a normal close instead of the reset of rule 5. On a
   small machine that is not a remote risk: 16 busy loops on two CPUs, with no signal sent, were
   enough to kill a healthy relay within a minute.

   With `signals = "isolated"` the relay has no timer. The Landlock signal scope keeps the
   program from signalling it, and its own session keeps terminal and process group signals
   away, so the program cannot stop it, and a timer would only kill a relay that the host was
   slow to schedule. A relay that something outside the sandbox stops therefore keeps its ports
   until it is continued, and then serves on.

   The poll loop also looks for a stop: the helper blocks SIGCONT like every other signal, so
   the kernel continues the process and leaves SIGCONT pending, and the loop takes it from the
   pending set on every turn. When the turn that finds the program ended also finds that the
   relay was continued, it closes its listeners without accepting what the backlog collected
   while it was stopped. That narrows the window but does not close it, which was measured on
   this host. Two races defeat it, and either is enough. The kernel wakes a stopped process
   before it queues the signal, so the first turn after a continue can find nothing pending; and
   the end of the program is not always in the same poll result as the readiness of a listener,
   so the turn that sees the backlog can still believe the program is running. Both were seen.
   A relay continued inside the two seconds can therefore relay a connection that was made after
   the program ended.

   What that costs: the connection reaches whatever now holds the address the relay forwards to,
   which after the run may be another process, and an exposed port can answer once more after
   the operator believes the run is over. It is a violation of the relay's lifetime, not a way
   out of the sandbox: nothing gains access the relay did not already have, and anything the
   program started is still inside the sandbox and is ended with its group. With
   `process.children = "contained"` the window does not exist: `contained` requires
   `signals = "isolated"`, so the program cannot stop its relay.

7. With `contained` the guard of the program's group (see "Contained child processes") holds a
   pidfd for the relay and ends the group as soon as the relay is gone, whatever ended it, also
   while sandy is stopped. A dead forward relay frees the program's forward port, and any local
   user can then bind it and receive what the program sends there for `to`: its requests,
   credentials and data. The guard tells sandy over a pipe of its own before it kills the group,
   and the caller sees the end as exit 125 with the reason on standard error, and as a status
   record of `pid` followed by `failed` rather than `exited` or `signaled`. The guard reports
   the relay only when, in the same look, the program and sandy have not ended, so a relay that
   ended together with the program is the normal end of a run and not a failure. In a normal
   run the relay cannot end first: it ends when sandy ends or when the guard has ended the
   group, and both come after the guard has seen the program end. The relay has no watchdog
   there, so a host that is slow to run the relay does not end a contained program. Without
   `contained` nothing watches the relay: when something outside the sandbox kills it, the
   program keeps running and its forward port is free for others to bind.

The listeners and the pidfd are close-on-exec, and sandy closes its copies before it confines
itself, so the program never holds them. The relay has `/dev/null` as its standard descriptors,
as on macOS, so it holds nothing of the caller's: a caller that waits for the end of sandy's
output sees it end with the program, not with the relay. A relay that panics after it reported
readiness therefore leaves no message; a failure before that is reported over the readiness pipe.

The relay runs in its own Landlock domain, a sibling of the program's domain, so neither can
ptrace the other. With `signals = "any"` the program can kill or stop the relay; a kill ends the
relayed connections at once, and a stop ends the relay within two seconds (step 6 above). With
`signals = "isolated"` it can do neither. Any
local process can connect to the relay's listeners, like to any loopback port. Through an exposed
port it reaches the program, which is what an exposed port is for: the program's own listener is
reachable directly anyway, so the relay checks nobody there.

A forwarded port is different. It exists for the program alone, and the relay reaches `to` as
sandy's user, so a connection of another user would pass an owner rule of the packet filter or a
peer credential check in that service. The relay therefore asks the kernel who owns the other
end of every connection it accepts on a forwarded port, and closes the connection when the
answer names another user. It asks over a `NETLINK_SOCK_DIAG` socket that sandy opens before the
relay confines itself, with an exact lookup of the connection's four addresses
(`SOCK_DIAG_BY_FAMILY`), and it compares the answer with what it asked, so a lookup that matched
a listening socket instead is refused like any other failure. The kernel answers in the call
that sends the lookup, so the relay reads the answer without waiting, and a missing answer
refuses the connection instead of holding up the relay. A dual-stack IPv6 socket that
reached an IPv4 port, which is how Java connects by default, is answered in IPv6 form with
IPv4-mapped addresses; the comparison reads them as the IPv4 addresses they map, because they
name the same connection. Every failure closes the connection, and sandy checks the lookup on a
connection of its own before it starts the relay, so a kernel without `inet_diag` refuses the
run instead of refusing every connection later.

One answer names nobody, and this is the residual of the check. The owner the kernel reports comes
from the socket's file, so closing the socket takes it away: from the close onwards the answer
carries no inode, which is how the kernel says it has no owner to give. The user in such an answer
cannot be read instead, because kernels differ on it. Up to 6.8 the answer reports user 0 from the
close; 6.17 and later keep the user until the kernel replaces the socket with a timewait record,
which reports user 0: about a millisecond after the close, and about 40 milliseconds when the peer
wrote before it closed (measured on 6.8, 6.17 and 7.2). The relay therefore reads the inode, which
says the same thing on every kernel, and serves a connection that no owner can be found for. A user
that such an answer still carries counts, though: user 0 says nothing and sandy's own user is the
program's, but any other user is the closed socket of someone else, and the relay refuses it.

It has to. The kernel completes a handshake by itself, so a program that connects and exits is
always ahead of the relay's accept, and the relay cannot be made to win that race. Refusing
these answers refused much of what a forwarded port is there to carry, and how much depended on
the kernel rather than on anything the program did. One run of a program making 100 connections
through a forwarded port, counted at the service outside, reading the user:

| program | 6.8, two cpus | 6.17, two cpus | 7.2, 24 cpus |
| --- | --- | --- | --- |
| connect and exit | 10 and 6 of 100 | 34 and 43 of 100 | 30 to 32 idle, 8 to 23 loaded |
| connect, write and exit | 12 and 12 of 100 | 100 of 100 | 100 idle, 41 to 91 loaded |

Reading the inode gives 100 of 100 for both programs on all three kernels, and 4000 of 4000
connections on the host where the spread was widest. Writing before exiting buys nothing on
6.8, and the same test run twice on one host differs widely, so neither is a workaround a
program can rely on. Kernel 6.8 is Ubuntu 22.04 LTS's kernel, a common deployment target, and
there this is the difference between a forwarded port that mostly works and one that mostly
does not. Dropping the program's own connection is the one thing a forwarded port must not do,
and version 1.3.2 had no check at all, so refusing them was a reliability regression against it.

What this leaves open: another local user can deliver a blind write to the service when its closed
socket no longer carries its user. On 6.8 that is from the close, so the write usually arrives on
the first attempt: a peer that connects, writes and closes at once is usually closed before the
relay asks, as most connections of a program that connects and exits were in the measurement above.
On 6.17 and later the closed socket keeps its user until the timewait record replaces it, so the
write arrives only when the relay asks after that, which a busy host makes more likely. Measured on
7.2 with a sub-user ID of a user namespace as the other user, writing and closing 50 times: 41
writes reached the service before the relay refused such answers, none after, and all 50 of sandy's
own user both times; the tests are `a_peer_that_closed_its_socket_has_no_owner` and
`an_answer_is_judged_by_the_user_it_carries`. The Ubuntu VMs have no second user to measure with.
The peer cannot read what comes back. Losing the file is what loses the owner, and it also gives up
the answer, so the service cannot be used interactively, read from, or probed for a reply. A peer
that only shuts down its sending side keeps its socket and its file, so it keeps its owner and is
refused like any other: half closing is not a way around the check, and because a half closed peer
and a closed one are both in FIN_WAIT2, the check must read the inode and never the state. The only
way to close the residual rather than narrow it is a listener other local users cannot reach at
all, which on Linux means a network namespace, as the AppContainer gives on Windows. Forward only
to services that are safe against an unauthenticated local write, or that authenticate their
clients themselves. `sandy check` prints this as a warning for every policy with a forwarded port.

Two further limits are inherent: the owner is the user that created the socket, so a process of
sandy's own user that acts for someone else still passes, and a descriptor passed between
processes keeps the owner of its creator. macOS has no such check; on Windows only the program's
AppContainer reaches the forward listener.


## Private network

`ip = "private"` gives the program a network of its own: a user namespace and a network
namespace that holds only `lo`. Inside it the program may use IP freely: the socket family filter
allows what `ip = "all"` allows, and neither `listen` nor `bind` is restricted. No route leaves
the namespace. The relays of `expose` and `forward` are the only ways in and out, and the egress
broker of `egress` is the only way to the network.

### Launch order

The process that becomes the program enters the namespaces: sandy itself in the exec model, so
the program keeps sandy's process ID, and the forked child with `children = "contained"` and with
`--explain`, so the supervising sandy stays in the host's namespaces. It does so after the relay,
the egress broker and the watcher have started, which must stay in the host's namespaces, and
before step 4 of the launch sequence:

1. One `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, with one thread, which sandy checks. The forked
   child of `contained` first makes itself dumpable again: it inherits sandy's undumpable flag,
   and the map files of step 2 belong to root while a process is undumpable. The kernel makes the
   program dumpable at `execve` in any case; sandy and the guard stay undumpable.
2. `deny` into `/proc/self/setgroups`, then single-ID maps: the effective user ID to itself in
   `uid_map` and the effective group ID to itself in `gid_map`. Root is never mapped. A process
   that is root in its user namespace keeps its capabilities there across `execve`; a mapped
   user keeps none.
3. `lo` up (`SIOCSIFFLAGS`), which needs `CAP_NET_ADMIN` in the new user namespace. The process
   holds every capability there until step 5.
4. The forward listeners are bound inside and handed to the relay, and the egress listener to the
   broker (see "The relays" and "Egress broker" below).
5. Every capability is dropped: the bounding set (`PR_CAPBSET_DROP`), the ambient set, and the
   effective, permitted and inheritable sets. All five read zero in the program's
   `/proc/self/status`.
6. With exposed ports, the socket factory starts (see below).
7. The launch continues with step 4. The filters are built there: the rules of the set*id calls
   name the user and group IDs that `getresuid` and `getresgid` return, which between the
   `unshare` and the map writes is the overflow ID 65534.

The denylist still denies the program every namespace and mount call, so it cannot create a
namespace of its own, where it would hold capabilities, or join another one.

### The relays

A socket belongs to the network namespace it was created in, and the relay must stay in the
host's namespace, where it listens for exposed ports and connects to forward targets:

- **Forwarded ports.** The relay is forked before the `unshare`, as without the namespace. In
  step 4 sandy binds each forward listener inside the namespace and sends it to the relay over a
  socket pair (`SCM_RIGHTS`), before the program can run and take the port. The relay reports
  ready before the listeners arrive, because with `contained` sandy must know the relay before it
  forks the guard, and the child that binds the listeners comes after the guard. It then waits for
  them while it watches the end of the program and of the guard's pipe and, with
  `signals = "any"`, re-arms its watchdog. Its filter allows `recvmsg` for that. A forward port
  below 1024 works, because the capability that binds one is still there in step 4.
- **No owner check.** Only processes inside the namespace, or ones that enter it, reach a
  forward listener there, and the `NETLINK_SOCK_DIAG` socket of the check would see the host's
  namespace anyway, so the relay checks no owner. The `forward` exception of DESIGN.md does not
  apply under `ip = "private"`, and `sandy check` does not print its warning.
- **Exposed ports.** The outer listener is bound in the host's namespace before the `unshare`, as
  without the namespace, but the connection to the program's port must start inside. A socket
  factory makes the sockets for it: a helper process (forked twice, a session of its own,
  `/dev/null` as its standard descriptors), started in step 6, so it holds no capability. It
  confines itself with no_new_privs, Landlock without file access and without TCP bind and
  connect (from ABI 4) and with the signal and abstract socket scopes (from ABI 6), and a seccomp
  filter that allows reading a request, `sendmsg` for the answer, `socket` for an IPv4 or IPv6
  TCP socket with protocol 0, and ending. For each accepted connection the relay asks it for one
  socket over a seqpacket pair and connects that socket itself, so the relay's Landlock rules
  decide the port, as for its own sockets. The factory creates sockets and nothing else: it
  cannot connect, bind, listen, open a file or start a process.
- **Lifetime.** The factory ends when the relay ends: its side of the pair then reads nothing more.
  The relay polls its own side and ends when the factory has ended, because no exposed connection
  reaches the program without it. With `contained` the child starts the factory after sandy has
  forked the guard, so the guard cannot watch it; the relay's end makes the guard end the program
  as for a dead relay (step 7 of "Exposed and forwarded ports",
  `a_dead_socket_factory_ends_a_contained_program`). The supervising sandy closes its copies of
  both socket pairs right after the fork, so that the relay sees the end of the factory, and the
  end of a child that fails before it binds the forward listeners. With `signals = "any"` the
  program can stop or kill the factory, as it can the relay.

### Egress broker

`network.egress` adds a SOCKS5 broker on the program's `127.0.0.1:PORT`. DESIGN.md ("Private
network and egress", "Egress broker") describes the handshake and the destination check, which
every platform shares. On Linux the broker is a helper process of its own, apart from the relay:
the relay's Landlock rules allow TCP connect only to its targets, and the broker must reach every
port the check allows.

1. Before the `unshare`, sandy opens a `NETLINK_ROUTE` socket and checks that the kernel answers
   a route lookup and an address, a link and a route dump over it, so a kernel that cannot
   answer refuses the run instead of every connection later. It opens a pidfd for its own process ID
   (with `contained`: the supervising sandy's) and a socket pair for the listener.
2. It forks the broker twice, as it forks the relay: in a session of its own, with every signal
   except the fault signals blocked and `/dev/null` as its standard descriptors. The broker stays
   in the host's network namespace.
3. The broker raises its soft limit of open descriptors so that
   `sandy_relay::broker::MAX_CONNECTIONS` (1000) connections fit, creates its watchdog under
   `signals = "any"`, closes every descriptor except the netlink socket, the pidfd, the guard's
   pipe with `contained`, its side of the socket pair, the readiness pipe and the pipe of its
   stop request (see step 5), and confines itself:
   - no_new_privs;
   - Landlock with every file system right of the ABI handled and no rule, so it opens, creates
     and executes no file; from ABI 4 TCP bind handled with no rule, and TCP connect not handled,
     because the destination check decides where it connects; from ABI 6 the signal and abstract
     socket scopes;
   - the shared allowlist filter and a broker filter that allows only accepting, connecting,
     reading and writing sockets, the socket options it sets and reads, `getsockname` and
     `getpeername` for the check after the connect, `sendto` and `recvfrom` for the route
     lookups, `recvmsg` for the listener, polling, memory calls, `clone` for threads only,
     `timer_settime` for the watchdog and `FIONBIO`. `socket` is allowed for IPv4 and IPv6 TCP
     with protocol 0 alone; the netlink socket exists already. Every other call fails with
     `EPERM`, among them `bind`, `listen`, `sendmsg`, `read` and every call on a file; `clone3`
     fails with `ENOSYS`.
4. It starts and joins one test thread and reports ready. In step 4 of "Launch order" the process
   that enters the namespace binds `127.0.0.1:PORT` there and sends the listener over the socket
   pair; a port below 1024 works, because the capability that binds one is still there. The
   broker waits for it as the relay waits for its forward listeners: it watches the end of the
   program and of the guard's pipe meanwhile, and keeps its watchdog armed.
5. It serves the listener with `sandy_relay::broker::serve`, which asks the kernel for every
   connection whether the destination is this host (`RTM_GETROUTE` for the destination, and
   `RTM_GETADDR` for the addresses and subnets of every interface) and which networks the host
   reaches without a router (the subnets, and an `RTM_GETROUTE` dump of every table for the
   unicast routes without a gateway other than the default route, over links that an
   `RTM_GETLINK` dump shows neither point-to-point nor NOARP), and connects from the host's
   namespace. The route dump holds every table, also one that no rule uses for the broker's
   connections, such as a VRF's, so it can only add networks to the local network. A route that
   names only a nexthop object, which is all the kernel sends when
   `net.ipv4.nexthop_compat_mode` is 0, does not say whether it has a gateway and is left out,
   so the network of an on-link route of that form is not the local network. A thread polls
   the pidfd and the guard's pipe, keeps the watchdog armed, and asks the serve loop to stop
   when either ends. It asks through a pipe that the loop polls next to its listener, so the
   listener closes at once; the pipe is made before the filter, which allows no new one.

Its lifetime follows rule 5 of "Forwarded ports":

- When the program ends (with `contained`: when the guard's pipe or sandy ends), the broker takes
  the connections its backlog holds, closes its listener at once, gives the accepted connections
  at most one second, and resets the rest
  (`the_broker_closes_its_listener_as_soon_as_the_program_ends`).
- With `signals = "any"` the program can stop the broker. Its watchdog then kills it two seconds
  after the watching thread last ran, as the relay's does
  (`a_stopped_broker_ends_with_the_program`). With `signals = "isolated"` it has no watchdog, for
  the reason the relay has none.
- Unlike the relay, the broker takes its backlog also after it was stopped and continued. The
  relay refuses that backlog because a connection in it may have been made after the program
  ended and would reach whatever holds the relay's target by then. Only processes inside the
  sandbox's network namespace reach the broker's listener: the program's own, which are confined
  as the program is, and processes of sandy's user that entered it, which reach the network
  directly anyway. Every connection is still checked and gets at most the drain second, so a
  late one reaches nothing the program could not reach while it ran.
- With `contained` the guard watches the broker with a pidfd, as it watches the relay, and ends
  the program's group when the broker ends first: sandy exits with status 125 and says that the
  egress broker ended (`a_dead_broker_ends_a_contained_program`). Without `contained` nothing
  watches it, and a broker that something outside the sandbox kills leaves the program without
  its way out.

Who reaches it: the listener is in the sandbox's network namespace, so another user can neither
connect to it, because nothing listens at that port on the host's loopback, nor enter the
namespace (`another_user_cannot_reach_the_egress_port`). Processes of sandy's own user can enter
it, the exception that "What stays open" names.

What the program gets, measured on Fedora 44:

- `curl --socks5 127.0.0.1:1080 http://1.1.1.1/` works. curl's `--socks5-hostname` and
  `socks5h://` send the name, which gets reply 8, and no name server is reachable from inside,
  unless a forwarded port reaches one over TCP. A program therefore needs the address of each
  destination, or a resolver of its own behind a forwarded port.
- Only TCP leaves; ICMP and UDP stay inside.
- The broker reaches what the host's routes reach, as sandy's user, VPN tunnels and the bridges
  of containers and virtual machines included. Their subnets, and every network that a route
  without a gateway sends into a bridge or another link with neighbours of its own, are the
  local network, so `public` refuses their hosts and `public-and-local` allows them (measured:
  the SSH ports of the VMs of a libvirt network), while their bridge addresses, which are this
  host, stay refused. A tunnel (wg, tun, ppp, gre) is point-to-point or NOARP: what a route sends
  into it goes to the other end, which takes it on as a router does, so only the subnet of the
  tunnel's own address is the local network. A full tunnel therefore leaves the internet
  public, whether it takes all traffic through a default route without a gateway
  (`default dev wg0`) or through narrower routes such as `0.0.0.0/1`, `128.0.0.0/1` and
  `2000::/4`; the private ranges behind it stay refused by the static check
  (`on_link_routes_are_the_local_network_without_an_address`, in a network namespace of its
  own). A dummy link is NOARP too, until `ip link set ... arp on`.
- The start takes about 1.8 ms more than without the broker: 6.2 to 6.4 ms against 4.3 to 4.7 ms,
  as the median of 100 runs of `sandy run --ip private -- /usr/bin/true` with the release build
  (kernel 7.2, a busy 24 CPU host). Each connection costs a route lookup, an address dump, a
  link dump without statistics and a route dump over netlink (about 1, 4, 8 and 5 µs on that
  host with 8 links, and 76 ms for the dump of a million routes in a network namespace), two
  threads with 256 KiB stacks and two descriptors.

### Detection

`plan` reads, without trying anything:

1. `user.max_user_namespaces`: 0 disables user namespaces, and the requirement is unavailable.
2. `kernel.unprivileged_userns_clone`, which only Debian and Ubuntu kernels have: 0 disables them
   for unprivileged processes, and the requirement is unavailable.
3. `kernel.apparmor_restrict_unprivileged_userns` (Ubuntu 23.10 and newer) and sandy's own
   AppArmor label, `/proc/self/attr/apparmor/current`. With the restriction on (1) and the label
   `unconfined`, the user namespace sandy creates gives it no rights: the write to `setgroups`
   fails with `EACCES`, the maps and `lo` with `EPERM` (measured on Ubuntu 25.10). An AppArmor
   profile for sandy with the `userns,` rule lifts the restriction for sandy alone, and
   `sandy setup` installs one, so the requirement needs setup, and `check` exits with status 2
   when nothing else is missing. The plan says: "Ubuntu's AppArmor restriction of unprivileged
   user namespaces (kernel.apparmor_restrict_unprivileged_userns = 1) applies to sandy, which runs
   unconfined: the user namespace it creates gives it no rights, so it cannot set up the private
   network; an AppArmor profile that allows sandy user namespaces lifts the restriction for sandy
   alone". `sandy setup` installs that profile for a sandy that only root can change, or for a
   root-owned copy of one that is not (see "Setup on Ubuntu"). An administrator can also set the
   sysctl to 0, which lifts it for every program. Any other label is a profile, and whether that
   allows user namespaces only a trial shows.

When nothing of this rules the namespaces out, `plan` also tries them, in `check` and in `run`:
a forked child runs steps 1 to 3 and 5 and reports the first that fails, with its error number,
with `children = "contained"` together with the PID namespace that its run adds (see "A PID
namespace"). The namespaces end with the child. On Ubuntu the kernel log keeps the AppArmor
audit records of the `unshare`, which is all a trial leaves behind. The trial finds what the
host does not say, for example a sandbox around sandy whose seccomp filter denies `unshare`, as
sandy's own does (`check_tries_the_namespaces_inside_a_sandbox_that_denies_them`). One sandy
tries each set of namespaces once and plans every policy against that answer.

What a failed trial means depends on why it failed, because only a lasting shortfall of the host
may make sandy try a weaker fallback level:

- `EPERM`, `EACCES`, `ENOSYS`, `EINVAL` and `EUSERS`, and a probe that a sandbox around sandy
  ends with `SIGSYS`: the host refuses the namespaces for good, and the requirement is
  unavailable (`UNAVAILABLE`, `check` status 1).
- `ENOSPC` where `user.max_user_namespaces`, or the `user.max_*_namespaces` limit of another kind
  the trial creates, is 0: unavailable too.
- Everything else can pass, and others than an administrator can cause it: `EAGAIN` or `ENOMEM`
  when the user's processes or the memory run out (any process of the user, also one an earlier
  run left behind, counts against `RLIMIT_NPROC`), `ENOSPC` when the user's own namespaces fill
  a limit, `EMFILE`, a probe that cannot fork or report, or one that another signal ends. The
  requirement is then indeterminate (`UNDECIDED`): `check` and `run` fail with status 125 and
  never take the plan as unavailable (`a_process_limit_makes_the_namespaces_undecided`).

`run` stays the authoritative answer: a step that fails refuses the run with the step's error.

### Costs

- Start time, as the median of 100 runs of `sandy run -- /usr/bin/true` with the release build on
  Fedora 44 (kernel 7.2, a busy 24 CPU host): about 0.3 to 0.6 ms more than with `ip = "all"`
  (4.5 against 3.9 to 4.2 ms), and about 2.5 ms more with an exposed port, which the start of the
  socket factory takes. A forwarded port adds nothing measurable.
- Inside, files of other users and of root show the owner and group 65534, and so does every
  supplementary group except the user's own in `getgroups`. The kernel still checks access with
  the real groups. `setgroups` fails, also for the user's own groups.
- `ping` and other ICMP datagram sockets fail with `EACCES`: `net.ipv4.ping_group_range` of a new
  network namespace admits no group.
- No name server is reachable, unless a forwarded port reaches one over TCP. The system set
  keeps `/etc/hosts` and the resolver configuration readable, so `localhost` resolves.
- Each exposed connection asks the factory for its socket: one round trip over a socket pair.
- The trial forks a child that creates the namespaces once more, in every `run` and `check`. It
  adds about 1 ms to the start (0.7 to 1.2 ms in the medians of 150 runs of the release build
  on the same host).
- On Ubuntu every run and every `check` adds AppArmor audit records to the kernel log, for the
  trial and for the run.

### What stays open

- **Processes of the user that runs sandy.** The namespaces belong to that user, so its processes
  outside the sandbox hold every capability in them (the owner rule of `cap_capable`). A
  single-threaded one can enter them (`nsenter --target PID --user --net --preserve-credentials`)
  and reach the program's ports and the forward listeners without a relay, and the egress port,
  through which it reaches nothing it does not reach directly. With `ip = "all"` such a process
  reaches the program's ports directly. A process of another user can do neither:
  opening the program's `/proc/PID/ns` files fails with `EACCES`, and `setns` through a pidfd,
  as `nsenter` does it, with `EPERM` (measured with a sub-user ID on Fedora 44). This is an exception of
  `IpNetworkPrivate` (DESIGN.md, "Requirements and the enforcement plan"): `sandy check` warns
  about it, and `another_user_cannot_reach_a_forward_port` records it with sandy's own user as
  the control. By the same owner rule, Yama's `ptrace_scope` 1 no longer keeps the user's other
  processes from tracing the program (from the kernel source; not measured). Protecting the
  program from the user is a non-goal (DESIGN.md, "Non-goals").
- **Unix sockets.** A pathname Unix socket is not part of a network namespace, so with
  `unix_sockets = "all"` the program still reaches every Unix socket service of the host, and
  through some of them the network; the warning of that setting applies. Abstract names belong to
  the namespace, so no abstract socket of the host is reachable
  (`the_program_reaches_no_abstract_socket_of_the_host`), and the program cannot take one of the
  host's names either.
- **Standard streams.** A socket on a standard stream belongs to the network it was created in,
  so sandy refuses every IP socket there (see "Refusals").
- The namespace hides nothing of the file system: `/proc` and `/sys`, when granted, describe the
  host, apart from `/proc/net`, which shows the network namespace of the process that reads it.
  `filesystem.view = "policy"` hides what the policy does not grant (see "File system view").

## File system view

`filesystem.view = "policy"` runs the program in a mount namespace whose root holds only what the
Landlock rules name: the policy paths, the program file, the minimal system set and the program's
loader, each at its own path. Every other path looks missing: `stat`, `access`, `readlink`, `open`
and `inotify_add_watch` answer `ENOENT`, for `/etc/passwd` as for a file in the user's home
directory (`hidden_paths_look_missing`). The view hides and Landlock decides: the binds show the
same files the rules name, so every rule applies as without the view, and a path the view shows
is still denied when no rule grants it (`ls /` in the view gives `EACCES`).

The view needs the user namespace of "Private network", with the same detection, and adds a
mount namespace to the same `unshare`. It works with every other setting: `ip = "private"`,
`children = "contained"`, `--explain` and `end_with_parent`, where a forked child builds the view
and sandy stays outside, in the host's view (`the_view_works_with_the_process_modes`,
`the_view_works_with_a_private_network`). The diagnostic mode names the paths of the host as
without the view; inside, such a path is missing rather than denied.

### Building the view

The process that entered the namespaces builds the view right after the maps and `lo`, before it
binds the forward listeners and drops its capabilities, which the mount calls need. It uses
descriptors only, so no path is resolved twice:

1. It makes `/` private (`MS_REC | MS_PRIVATE`), so nothing it mounts reaches the host and
   nothing the host mounts later appears in the view.
2. It opens every path to bind with `open_rule` (see "Rule paths"): one component at a time,
   without following a link, and only if it is still the file of the plan. It opens them only
   now, because a descriptor opened in the host's mount namespace cannot be bound (`EINVAL`,
   measured on Linux 6.8 and 7.2). The Landlock ruleset keeps its own descriptors from step 3 of
   the launch sequence: Landlock binds the inode, which is the same in both namespaces.
3. A new tmpfs (`fsopen`, `fsmount`) becomes the root. It is attached at `/tmp` of the new
   namespace first, because Linux before 6.15 cannot mount onto a mount that is not attached
   (`EINVAL` on Ubuntu 22.04's 6.8, measured).
4. Each path is cloned with its submounts (`open_tree` with `OPEN_TREE_CLONE | AT_RECURSIVE`),
   gets its flags on every mount of the clone (`mount_setattr` with `AT_RECURSIVE`), and is moved
   onto its place (`move_mount`). The clone is recursive because a mount whose submounts came from
   the host's namespace is locked to them and cannot be bound alone (`EINVAL`), and because a
   read-only flag on the top mount alone would leave the submounts writable. The flags are only
   added: the kernel refuses to clear a flag the host set (`EPERM`), so a host's `noexec` stays.
   - A path inside another bound path is mounted inside that bind, on the host's own file there,
     which must still be the file of the plan; otherwise the run is refused.
   - A path anywhere else gets the directories above it on the tmpfs, with mode 0755 whatever
     the umask, owned by the user, and an empty file as the place of a file.
5. The symbolic links on the way to the paths are recreated with their text, `/dev` is built,
   the tmpfs mounts become read-only, and `pivot_root(".", ".")` with `umount2(".",
   MNT_DETACH)` makes the tmpfs the root and detaches the old one. The process then changes to
   the working directory it had, when the view holds it, as the path itself or a directory above
   a granted path, and to `/` otherwise.

The descriptors of `/proc/self/task` that the thread checks of the launch sequence use are opened
before the view, because the view hides `/proc` unless the policy grants it.

The program cannot change the view. It holds no capability, the filter denies every mount and
namespace call, and measured with a user and mount namespace of its own, which the filter would
deny, it still could not unmount a bind or make one writable (`EINVAL` and `EPERM`; research of
2026-10-25).

### Flags

| Bound path | Read-only | No execute | nosuid | nodev |
|---|---|---|---|---|
| `read` path | yes | yes | yes | yes |
| `read_exec` path, the program file, the loader, the library directories of the system set | yes | no | yes | yes |
| writable path | no | yes | yes | yes |
| other entries of the system set | yes | yes | yes | yes |
| a path below `/dev` | as above | as above | yes | no |
| a path below `/proc` | yes, also under a writable grant | yes | yes | yes |

A bind gets the rights of every policy path that holds it, as Landlock grants them: a `read` path
inside a `read_exec` path stays executable, and a path inside a writable path is writable.
Executing is a right of its own, so a file that no `read_exec` path holds can neither be
executed (`execve` gives `EACCES`) nor mapped as code (`mmap` with `PROT_EXEC` gives `EPERM`)
(`code_maps_only_from_executable_paths`). The library directories of the system set (`/usr/lib`,
`/usr/lib64`, `/lib`, `/lib64`) keep execute, because the loader maps the libraries as code after
a read open. Device nodes open only on a mount without `nodev`, so a device the policy grants
below `/dev` keeps working. `/proc` is read-only even under a writable grant, so the program
changes nothing of its own or of other processes there (`proc_is_bound_read_only`).

`fchmod` and `futimens` through a descriptor of a read-only bind fail with `EROFS`, so the
exception of "Metadata through open files" does not apply in the view
(`a_read_only_descriptor_changes_no_metadata_in_the_view`).

### Links, `/dev` and `/proc`

- **Links.** sandy recreates every symbolic link that the names of the policy paths, the program,
  the system set, the program's loader (`PT_INTERP`) and its `#!` interpreters pass, with the
  same text, where it lies outside every bind: `/lib64 -> usr/lib64` and `/bin -> usr/bin` on a
  merged `/usr`, `/etc/resolv.conf` into `/run/systemd/resolve`, `/usr/bin/python3` for a script
  that names it (`the_links_of_a_merged_usr_work`, `dynamic_programs_run_with_the_system_set`,
  `names_resolve_under_client`). A link inside a bind is part of the host's content there. The
  view has `/bin` only when a policy path is named through it.
- **`/dev`** is a tmpfs with `null`, `zero`, `full`, `random` and `urandom`, each the host's node,
  opened without following a link and checked by its device number, and bound read-only, which
  still takes writes to `/dev/null`. The system set grants all of them but `full`, which the view
  shows but Landlock denies. With a terminal on a standard stream, `/dev` also gets `tty` and a
  devpts instance of its own at `/dev/pts` (`newinstance,ptmxmode=0666,mode=620`), with
  `/dev/ptmx` a link to `pts/ptmx`, or the host's node there when the policy grants
  `/dev/ptmx`. Opening `/dev/tty` still needs a grant (`--read-write /dev/tty`), as without the
  view (`a_terminal_works_when_one_is_attached`). Without a terminal there is no `/dev/tty`
  (`dev_holds_the_minimal_devices`). Other devices are bound only when the policy grants them.
- **`/proc`** exists only when the policy grants a path of it, and holds what the policy grants,
  bound from the host's `/proc` (measured: binds of procfs and sysfs files and directories work in
  the user namespace on Linux 6.8 and 7.2). It lists the host's processes as without the view,
  also with `children = "contained"`, which then runs without a PID namespace (see "A PID
  namespace").

### Detection and refusals

- The requirement needs the user namespace as "Private network" does. `plan` reads the same
  sysctls and label, and under Ubuntu's AppArmor restriction the requirement needs setup, so
  `sandy check --view policy` exits with status 2 on Ubuntu 23.10 and newer
  (`check_needs_setup_under_the_apparmor_restriction` in `view_linux.rs`). The reason then says
  that sandy "cannot set up the file system view".
- It needs the fix of Landlock erratum 3: rights could widen through a directory that a bind
  mount disconnected, and the view creates such binds. sandy reads the errata bitmask with
  `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_ERRATA)`; erratum 3 is bit 2. A
  kernel without the fix, or one that answers no bitmask, makes the requirement unavailable.
  Measured: Ubuntu 22.04's 6.8 reports 0x5, Ubuntu 25.10's 6.17 0x7, Fedora 44's 7.2 0xf; all
  have the fix.
- `plan` tries the namespaces in a forked child as for the private network, and with the view
  also every kind of mount call of the run: it builds a view that holds only `/dev` and makes it
  the root (`the_probe_tries_the_mount_steps`). The error number of the step that fails decides
  as there.
- `run` refuses a directory on a standard stream (`a_directory_on_a_standard_stream_is_refused`).
  Such a descriptor was opened in the host's mount namespace, and through it the program would
  reach every path of the host by name with `openat` and `fstatat`, the hidden ones included. No
  common program is started with a directory as a stream. A file or a pipe is accepted.

### Costs

- `rename` and `link` between two writable paths fail with `EXDEV`, also on one file system,
  because each is a mount of its own. `mv` falls back to copying; a program that renames between
  them fails (`a_rename_between_writable_paths_fails_with_exdev`). Within one writable path they
  work.
- Files of other users and of root show the owner and group 65534, as in "Private network".
- A file of a `read` or a writable path cannot be mapped as code: a program that extracts a native
  library into a writable directory and loads it, as some Java programs do, or that loads a
  Python extension module from a `read` path, fails. Grant such a directory with `--read-exec`,
  which a writable path cannot be.
- `/proc` is read-only, and holds only the granted paths.
- A program started in a directory the view does not hold starts in `/`.
- The program cannot create a pseudo-terminal, also when the policy grants `/dev/ptmx` and
  `/dev/pts`: the host's `ptmx`, bound alone, finds no devpts next to it (`ENOENT`), and the
  devpts instance of the view lies outside every Landlock rule
  (`a_pty_grant_starts_in_the_view_and_makes_no_pty`). Terminal emulators, `script`, `expect`
  and programs that run others in a pseudo-terminal need `view = "all"`.
- `ttyname` of a terminal on a standard stream finds no name: the name the host gives it lies in
  the host's devpts, and the view's `/dev/pts` is another instance.
- `/dev/fd`, `/dev/stdin`, `/dev/stdout`, `/dev/stderr` and `/dev/shm` exist only when granted.
- Start time, as the median of 100 runs of `sandy run -- /usr/bin/true` with the release build:
  about 1.2 ms more than without the view on Fedora 44 (4.8 to 5.1 against 3.7 to 3.9 ms, a busy
  24 CPU host), and about 0.9 ms more on the Ubuntu 22.04 VM (5.3 against 4.4 ms). The binds of
  the system set take most of it.
- On Ubuntu every run adds the AppArmor audit records of the `unshare` to the kernel log.

### What stays visible

A policy that makes `/` readable gives the view the whole file system of the host, so it hides
nothing; `sandy check` warns about that instead of the items below, and sandy runs it as asked
(`a_view_of_the_whole_root_is_warned_about` in `plan.rs`).

These are exceptions of `PathsHidden` (DESIGN.md, "Requirements and the enforcement plan"):
`sandy check` warns about each, and a test records it.

- **The host's file systems.** `statfs` on a path of the view reports the host's file system
  there: its type, size, free space and number of files. `stat` reports the host's device and
  inode numbers.
- **The directories above a granted path.** They exist in the view with their names, for example
  `/home` and `/home/user` above a granted `/home/user/project`, owned by the user, with the time
  sandy built the view. The program cannot list them, because no Landlock rule covers them.
- **Link counts.** The link count of a granted file still counts its names outside the view, so
  the program learns that a file has another name, though not where.
  `the_view_leaves_the_file_systems_the_parents_and_link_counts_visible` records the three.
- **The mount tables, with `/proc` granted.** `/proc/self/mountinfo` lists every mount of the
  view with the host's device and file system and their mount options, for example the name of
  an encrypted volume and a btrfs subvolume. The mount table of a process outside the sandbox,
  `/proc/PID/mountinfo`, which every process may read, lists the mounts of the host with their
  paths, also the ones the view hides, such as a removable disk under `/run/media`
  (`the_mount_table_names_the_hosts_devices`).

Also visible, and not an exception because the policy grants it: the text of a recreated link,
which names its target, and the content of `/proc` when it is granted.

## Setup on Ubuntu

On Ubuntu 23.10 and newer, `kernel.apparmor_restrict_unprivileged_userns = 1` gives an unconfined
process no capabilities in a user namespace it creates, so `ip = "private"` cannot work there
(see "Detection" above). An AppArmor profile with the `userns,` rule lifts the restriction for
the file it attaches to. Only root can load a profile, and a profile attaches to a path: whatever
file is at that path gets the right. `sandy setup` therefore writes a profile only for a path that
only root can change.

### What setup does

`sandy setup`, run as root:

1. Where the host disables user namespaces altogether (`user.max_user_namespaces` or
   `kernel.unprivileged_userns_clone` 0), it installs nothing and ends with status 3: a profile
   lifts only the AppArmor restriction, and `check` reports such a host as plainly unavailable
   (status 1). The message says so and gives the fallback. `--elevate` then asks for no rights
   (`setup_cannot_enable_disabled_user_namespaces`).
2. Where the restriction does not apply, it does nothing and says so, with exit status 0: the
   sysctl is absent or 0, or AppArmor is not enabled (`/sys/module/apparmor/parameters/enabled`
   is not `Y`). That covers Ubuntu 22.04 and the distributions without the sysctl (measured on
   Ubuntu 22.04 and Fedora 44).
3. It checks that only root can change the file the kernel runs as sandy (`/proc/self/exe`; see
   "The root-only check" below). If not, it refuses with exit status 3 and names
   `--install-copy` and installing from a package.
4. It writes `/etc/apparmor.d/sandy-setup.PATH`, with the path's `/` as `.`. For
   `/usr/bin/sandy`:

   ```text
   # Written by sandy setup for /usr/bin/sandy. `sandy setup --remove` deletes it.
   abi <abi/4.0>,

   profile sandy-setup.usr.bin.sandy /usr/bin/sandy flags=(unconfined) {
     userns,
   }
   ```

   The first line is sandy's marker. sandy writes the file under a temporary name that starts
   with a dot, which the AppArmor parser skips when it loads the directory at boot, and renames it
   into place. An identical file stays as it is, a file with the same marker is replaced, and a
   file without it is left alone: setup then refuses with status 3.
5. It loads the profile with `apparmor_parser --replace` and checks that the kernel lists an
   unconfined profile of that name. The profile loads again at every boot, with the others.

The profile allows `userns` and nothing more: `flags=(unconfined)` leaves every other right as an
unconfined process has it, and the profile's name becomes the label that the restriction looks
at. An attachment is a pattern in AppArmor, so a path with characters that mean more there (`*`,
`?`, `[`, `{`, `@`, a space and others) gets no profile: only letters, digits, `.`, `_`, `+`,
`-` and `/` are allowed.

### The root-only check

A path passes when its file and every directory above it, up to `/`, belong to root, none is
writable by its group or by others, none is a symbolic link, and none lies on a file system
mounted `nosuid`. sandy reads each component with `lstat`, from `/` down, so a component that
passed can only be changed by root. The sticky bit does not count: `/tmp` (mode 1777) is refused.
`nosuid` is how a file system arrives that a user controls, such as a removable disk that udisks
mounts or a FUSE mount; the system does not trust its files with rights either.

ACLs: sandy reads the mode only. POSIX ACLs need no separate read: when a file or directory has
one, the group bits of its mode are the ACL's mask, and the mask bounds every entry of a named
user or group, so a mask without write leaves only the owner, root, able to write. Measured on
Ubuntu 25.10: an entry that gives a user write turns the mode into 775, and setup refuses; with
the mask set to `r-x` that user's write fails with "Permission denied", the mode reads 755, and
setup goes ahead. ACLs of other kinds, such as NFSv4 ACLs on a network file system, are not
read.

### A portable sandy: `--install-copy`

A sandy unpacked into a user's directory fails the check, as it should: anything that user runs
could replace it. `sandy setup --install-copy`, run as root, copies the running image of sandy,
read from `/proc/self/exe` and never from the path the caller named, to
`/usr/local/libexec/sandy/VERSION/sandy`, owned by root with mode 0755, through a temporary file
in that directory that it renames into place. An identical copy stays. The directories it
creates get owner root and mode 0755, whatever the umask, a default ACL or a set-group-ID bit
of the parent say. It checks the directory's existing part before it creates anything, and
refuses with status 3 when that fails, for example where `/usr/local` is writable by the group
`staff`. Then it prepares the copy's path as above. It copies nothing else, and the portable file
gets no profile.

### The hand-over

A portable sandy started for `run` or `check` replaces itself with the copy of its version
(`execve`, with the same arguments, environment and descriptors) when all of this holds, read in
this order:

1. it does not run as root, the restriction is on, and its label is `unconfined`;
2. its own file is not the copy;
3. the copy exists, and only root can change it;
4. a profile with the copy's name is loaded and unconfined: every user may read the names and
   modes of the loaded profiles in `/sys/kernel/security/apparmor/policy/profiles`, though not
   their attachments, which read `<unknown>` even for root;
5. the copy has the same bytes as the image this sandy runs.

It does so before it opens anything else: before the policy file, the status descriptor and the
standard streams. Otherwise it runs on as itself, and `check` reports that the host needs setup.
A condition that sandy cannot read before it knows that the copy is installed (condition 3)
counts as not holding. From there, a condition it cannot read, for example because its
descriptor table is full, and a failed `execve` end `check` and `run` with status 125 and the
reason, after the status descriptor is open: the copy may be the one that should run, and the
portable sandy would report a need for setup that is not there
(`a_failed_check_of_the_installed_copy_is_an_error`).
The copy runs under its profile, so its label is not `unconfined` and it never hands over again;
condition 2 stops a loop even where the label would allow one.

**The portable file is still checked.** sandy refuses a policy with a writable path over its own
file or over a name it was started under (DESIGN.md, rules 3 and 4), because the next start runs
that file. After the hand-over the copy's own names are the copy's, so the portable sandy passes
its names in the variable `SANDY_STARTED_AS`: its file (`/proc/self/exe`), the name `execve` was
given (`AT_EXECFN`), and the names it received there itself, separated by `:`. Every sandy reads
the variable at its start, removes it from its environment, and checks each name in it that
exists like its own. The variable can only add checks: a caller that sets it makes sandy check
more files. A name that holds a `:` cannot pass intact, and then sandy fails with status 125. The
program never sees the variable, also when the policy passes it on
(`started_as_never_reaches_the_program`).

**The parent of `end_with_parent`.** sandy reads its parent's process ID as its first step, and
the copy reads its own again after the hand-over, a few milliseconds later. A parent that ends in
between would make the copy's parent another process. So the portable sandy also passes the ID it
read in `SANDY_PARENT_AT_START`; the copy removes that variable too, and with
`end_with_parent` it refuses when its own parent is not that process. The variable decides
nothing else, so it can only add that refusal.

**Costs.** On a host with the restriction, every `run` and `check` of a portable sandy reads two
small files. With a copy installed it also checks the copy's path, lists the loaded profiles and
compares the copy with its own image, which is as large as sandy. Measured on Ubuntu 25.10 (two
virtual CPUs, the 1.4 MB release build, means of 100 runs of `run -- /usr/bin/true`): a start of
the portable sandy that hands over takes 0.3 to 0.7 ms more than a start of the copy itself.
Where the restriction does not apply, the first read ends it.

**The program's label.** The profile is unconfined, and a program that sandy starts keeps
sandy's label when no other profile attaches to it (the kernel's `domain.c`, "unconfined exec no
attachment"). So the program and every process it starts run under the profile's label, which
allows user namespaces, and sandy's seccomp filter is what keeps the program from creating
them: it denies every namespace call. Measured on Ubuntu 25.10: a program that the copy runs
reads `sandy-setup.usr.local.libexec.sandy.2.1.0.sandy (unconfined)` as its label, and
`unshare -U` and `unshare -n` fail there with "Operation not permitted". The requirement holds
through the filter, so this is no exception of `IpNetworkPrivate`.

### Removing

`sandy setup --remove`, run as root, takes back only what setup wrote: the profile of the file
that runs, and only a file that starts with sandy's marker for that path, after it unloaded the
profile with `apparmor_parser --remove` and checked that the kernel no longer has it. It goes by
the path, so it also finds the profile after a package replaced the file. With `--install-copy`
it also removes the copy's profile, the copy, temporary files that setup left in the copy's
directory, that directory, and `/usr/local/libexec/sandy` when it is empty then. It is
idempotent: with nothing to remove it says so and exits 0, also without root.

A profile whose file someone deleted by hand stays loaded until the next boot, or until an
administrator unloads it: `apparmor_parser -R` with a file that defines it, or its name written
to `/sys/kernel/security/apparmor/.remove`. `--remove` leaves it alone, because nothing marks it
as sandy's any more.

### Asking for root's rights: `--elevate`

`sandy setup --elevate`, run by a user, asks for root's rights with `pkexec`, whose authentication
agent asks for an administrator's password once. Root never runs a file that someone other than
root can change:

- Where the restriction does not apply, or with `--remove` where nothing is to remove, it asks
  for nothing and exits 0. As root it runs setup directly.
- When only root can change sandy's own file, `pkexec` runs that file with the same arguments,
  less `--elevate`. pkexec starts the program in root's home directory, so with `--elevate` a
  `--policy` path must be absolute.
- A portable sandy with `--install-copy`: root must not run the portable file. `pkexec` runs
  `/bin/sh -c SCRIPT sandy-setup PID VERSION`. SCRIPT is fixed text in sandy that names every
  tool by its absolute path (`/usr/bin/mktemp`, `chmod`, `mv`, `cat`, `cmp`, `rm` and `rmdir`),
  and the process ID and the version arrive as positional parameters, never as script text. The
  script:
  1. refuses a process ID that is not its parent, and a version with other characters than
     letters, digits, `.`, `+` and `-` or with a leading `.`, before it writes anything. pkexec
     runs the shell in its own process, so its parent is the sandy that asked, which waits for
     it;
  2. creates each missing directory of the copy's path as a directory that `mktemp` makes with
     mode 0700, gives it mode 0755 and renames it into place, then copies `/proc/PID/exe`, the
     image of that sandy and never the file at its path, to a temporary file that `mktemp`
     creates there with mode 0600, and renames it into place; an identical copy stays. A default
     ACL of a directory above passes its entries on to what is created below it, limited by the
     mode of the call that creates it and not by the umask, so these modes are what keeps
     everyone but root from writing there before root runs the copy. `mkdir -m 0755` would not
     do: under such an ACL the `mkdir` of Ubuntu 25.10 (uutils coreutils 0.2.2) gives the new
     directory group write, and so its ACL's users (measured;
     `elevate_installs_a_copy_that_only_root_can_change`);
  3. checks with `cmp` that the copy has the same bytes as that image, and that the sandy that
     asked is still its parent, so that the process ID named that sandy during both reads;
     otherwise it deletes a copy it wrote and fails;
  4. only then runs the copy's `setup --install-copy`, which checks the copy's path, finds the
     copy identical to its own image, and writes and loads the profile.

  With `--remove`, pkexec runs the installed copy's `setup --remove --install-copy`, once sandy
  has checked that only root can change the copy.
- Otherwise it refuses with status 3, before pkexec runs.

pkexec exits with 126 when the user dismissed the dialog and with 127 when it gave no rights
(not authorized, or no authentication agent, as in an SSH session); both end with status 3, and
the message shows the `sudo` command to run instead. So does a missing `pkexec`. The elevated
sandy writes its own messages, and its statuses 0, 3 and 125 pass through; the script's own
failures exit with 125.

Measured on Ubuntu 25.10 (pkexec 126): over SSH pkexec finds no agent and exits with 127
(`elevate_without_an_authentication_agent_is_not_done`). With a temporary polkit rule that let the
test user run pkexec without a password, each of the three routes took one pkexec call and
installed and loaded the profile, and the removals left nothing behind. A process ID that was
not the shell's parent and the version `../../etc` were refused before anything was written.

Why one shell script: polkit's `org.freedesktop.policykit.exec` action asks for the password at
every call, so two calls (copy, then setup) would ask twice, and pkexec of the portable file
would have root run a file its user can change. The script runs only system tools, takes the
image from the waiting process instead of a path, and binds the process ID to its parent, so a
sandy that ends and a process that takes its ID over cannot hand root another image. pkexec
writes the whole command, script included, to the system log (measured in `/var/log/auth.log`).

### Exit status

| Status | `sandy setup` and `sandy setup --remove` |
|---|---|
| 0 | done, or nothing to do |
| 3 | not done, and nothing changed: not root and no `--elevate`, the rights were not given, user namespaces are disabled on this host, or setup is not allowed for this binary |
| 125 | failed, for example when the AppArmor parser rejected the profile |

A program that starts sandy can decide by status alone. When `check` exits with 2, it runs
`sandy setup --elevate`, with `--install-copy` for a sandy it ships in a user's directory. On 0
it checks again; on 3 it runs its fallback policy, without `ip = "private"`.

### Packaging

A package installs sandy at a path that only root can change, so its maintainer scripts can run
setup for it. They do not fail the installation when setup fails: `ip = "private"` then needs
setup later, and `sandy check` says so.

A Debian package, `debian/postinst` and `debian/prerm`:

```sh
#!/bin/sh
set -e
if [ "$1" = configure ]; then
    /usr/bin/sandy setup || echo "sandy setup failed; ip = \"private\" needs it on this host" >&2
fi
#DEBHELPER#
exit 0
```

```sh
#!/bin/sh
set -e
case "$1" in
remove | deconfigure)
    /usr/bin/sandy setup --remove || true
    ;;
esac
#DEBHELPER#
exit 0
```

An upgrade keeps the path, so `prerm upgrade` leaves the profile, and the new `postinst` runs
setup again.

An RPM package, in the spec file (`$1` is 0 when the package is erased, 1 when it is
upgraded):

```spec
%post
/usr/bin/sandy setup || :

%preun
if [ "$1" -eq 0 ]; then
    /usr/bin/sandy setup --remove || :
fi
```

On a host without the restriction both scripts do nothing.

## Contained child processes

With `process.children = "contained"` the program may start processes, and sandy ends all of them
when the program ends. sandy does not replace itself with the program:

1. After it has started the relay, if any, sandy makes itself a child subreaper
   (`PR_SET_CHILD_SUBREAPER`): a process whose parent ends is re-parented to sandy instead of
   init. sandy sets `SIGCHLD` to its default action, so that it can wait for children even if
   its caller ignored the signal, and blocks every signal except the fault signals.
2. sandy forks the guard. The guard creates a process group of its own and closes every
   descriptor except the read end of a pipe. sandy holds the write end; the forked program in
   step 3 has a copy until `execve` closes it, so the pipe ends only once sandy is gone and the
   program has started or ended. With exposed or forwarded ports, or an egress broker, the guard
   also keeps a pidfd for the relay and one for the broker, the write end of their pipe, and the
   write end of a pipe back to sandy (step 7 of "Exposed and forwarded ports").
3. sandy forks the program, and then closes every descriptor it inherited from its caller and
   does not need: each one above 2 without close-on-exec. sandy opens its own descriptors
   close-on-exec and makes the one of `--status-fd` so, which it keeps; the program gets none of
   them either way. Without this, a socket the caller leaked into sandy would stay open, and its
   port busy, for as long as the program runs
   (`sandy_closes_what_it_inherited_while_the_program_runs`). Once the program has reported its
   process ID (step 4), the guard opens a pidfd for it and polls that and the pipe, and the
   pidfds of the relay and the broker.
   When the program ends, when the pipe ends because sandy died (also by `SIGKILL`), or when the
   relay or the broker ends, the guard checks that it leads its group and kills the group with
   `SIGKILL`. The group therefore ends with the program even while sandy is stopped.
4. The forked program joins the guard's group and then writes its own process ID into the guard's
   pipe, in that order. The guard therefore learns the ID even if sandy never runs again after
   the fork, for example because it was stopped or killed in that moment, and it never learns it
   while a kill of the group would still miss the program. A failed write means the guard is
   gone, and the program refuses to start. The program then restores `SIGCHLD` and the signal
   mask that sandy's caller set, and runs steps 4 to 8 of the launch sequence. The denylist
   filter names the child's process ID. If a step fails, the child writes the error into a
   close-on-exec pipe and exits; sandy reads the pipe until `execve` closes it, and refuses with
   that error.
5. sandy waits for signals with `sigwaitinfo`. It forwards every signal it can wait for to the
   program except `SIGCHLD`, `SIGCONT`, `SIGTTIN` and `SIGTTOU`. `SIGKILL` and `SIGSTOP` cannot
   be blocked or caught, so a `SIGKILL` to sandy leaves the guard to end the group and a
   `SIGSTOP` stops only sandy. The fault signals (`SIGSEGV`, `SIGBUS`, `SIGILL`, `SIGFPE`,
   `SIGSYS`, `SIGABRT`, `SIGTRAP`) stay unblocked, so `kill -SEGV` to sandy ends sandy and the
   guard then kills the group instead of the program receiving the signal. `SIGPIPE` stays
   unblocked and ignored, because sandy's own writes raise it when their reader has gone (the
   status record of `--status-fd`, for one), and it must not reach the program. sandy also reaps
   processes that were re-parented to it, and refuses to continue if the guard ends before the
   program. With a terminal (one of sandy's standard descriptors is its controlling terminal),
   sandy follows job control:
   - The program's group starts in the background. When the program stops because it read or
     wrote the terminal (`SIGTTIN`, `SIGTTOU`) and sandy's group is the foreground group, sandy
     gives the terminal to the program's group and continues it. Then Ctrl+C and Ctrl+Z reach the
     program and every process it started.
   - When another process of sandy's job (for example `less` in `sandy run ... | less`) uses the
     terminal while the program's group has it, the kernel stops it and sends `SIGTTIN` or
     `SIGTTOU` to sandy's group. sandy takes the terminal back and continues its job.
   - Any other stop of the program stops sandy too, after it has taken the terminal back, so that
     the shell sees the job stop. `SIGCONT` to sandy gives the terminal to the program's group
     again if it had it, and continues that group.
6. When the program has exited, sandy gives the terminal back to its own group, kills the group
   with `SIGKILL`, kills the guard and the program by process ID as well, and waits for the
   members of the group (`waitpid` with the negative group ID) until none is left. Other children
   of sandy, for example processes its caller started before it executed sandy, are not waited
   for. sandy exits with the program's exit status, or 128 plus the signal number if a signal
   ended the program.

Two rules keep every process the program starts inside the group. The denylist denies `setsid`
and `setpgid`, the only system calls that move a process to another group. The policy must have
`signals = "isolated"`, so the Landlock signal scope keeps the program from signaling sandy and the
guard, which are outside its domain, or below ABI 6 the PID namespace of "A PID namespace", which
they are outside of. The guard, not sandy, ends the group when the program ends,
so the program cannot keep its processes alive by stopping sandy (with a terminal it can make
sandy stop, see step 5). sandy reaps neither the guard nor the program before it has killed the
group, so the group ID (the guard's process ID) cannot belong to another process while sandy can
still signal it. Killing a process group with `SIGKILL` reaches every member in one operation; the
kernel lets no member fork a new process past it. A member whose parent ends is re-parented to
sandy before that parent can be reaped, so waiting for the group's members ends only when none is
left.

Costs and differences from the exec model:

- The program has another process ID than sandy. The caller's process handle refers to sandy,
  which forwards signals and reports the exit status.
- A signal death becomes the exit status 128 plus the signal number, which a caller cannot tell
  from a program that exits with that status.
- `--status-fd` reports both on a descriptor of the caller's choosing, without changing any exit
  status. sandy writes `pid N` once the program runs, then `exited N` or `signaled N`, or
  `failed` when sandy itself failed or refused, which tells its exit status 125 from a program
  that exits with 125. The descriptor is made close-on-exec, so the program never has it. In the
  exec model the record ends after `pid`, because sandy becomes the program and the caller's own
  wait status is the program's.
- Programs that call `setsid` or `setpgid` get `EPERM`: programs that turn themselves into
  daemons, and shells with job control, which then run without it.
- Without a terminal, sandy does not stop when the program stops. There is no job control to
  follow, and a stopped sandy cannot forward signals.
- With a terminal, the program can stop sandy: it stops itself, and one of its processes continues
  it. sandy then stays stopped until it receives `SIGCONT` (a shell's `fg`). The guard still ends
  the group when the program ends.
- Only one process group can own a terminal. While the program's group has it, the rest of
  sandy's job gets it back only when it uses the terminal (see step 5). Two processes that read
  the terminal at the same time pass it back and forth.
- sandy and the guard hold no descriptor of the program except standard input, output and error,
  which sandy keeps until it exits, that is after the group has ended.
- Without a PID namespace, if both sandy and the guard are killed with `SIGKILL`, nothing ends the
  group. Both run sandy's command line, so `pkill -9 -f sandy` does this. Killing sandy alone is
  safe. With one, the init ends the namespace then (see below).

### A PID namespace

Where the host gives sandy a user namespace, `contained` also runs the program in a PID namespace
of its own, whose end ends every process in it. The detection is the one of "Private network".
With `ip = "private"` or `filesystem.view = "policy"` the run needs the user namespace anyway and
stays the authoritative answer; it asks for the PID namespace in the same `unshare`, so `check`
tries both together and refuses where `run` would, on a host that gives sandy user namespaces but
no PID namespace (`user.max_pid_namespaces` 0;
`check_tries_the_pid_namespace_where_the_run_needs_one`). With `contained` alone the namespace
only adds to the process group, so `plan` also tries one in a forked child, once per sandy, and
a host that allows user namespaces but refuses them to sandy, such as a container whose seccomp
profile denies `unshare`, keeps `contained` as described above. A trial that fails for a reason
that can pass (see "Detection" of "Private network") does not: the requirement is indeterminate
and sandy fails with status 125, instead of running the program with the process group alone
(`an_undecided_pid_namespace_swaps_no_mechanism`). Under Ubuntu's AppArmor restriction
`contained` keeps the process group too, without needing setup; below Landlock ABI 6, where only
the PID namespace isolates signals, `signals = "isolated"` then needs setup, and `check` exits
with status 2.

1. The forked child of step 3 does not join the guard's group. It adds `CLONE_NEWPID` to the
   `unshare` of its namespaces (with `contained` alone, `CLONE_NEWUSER | CLONE_NEWPID`) and forks
   twice: first the init, which becomes PID 1 of the namespace, then the program, which becomes
   PID 2 and leads a process group of its own, out of sandy's. It writes both process IDs to the
   guard and to sandy and ends. sandy is the child subreaper, so both become its children: it
   waits for the program, forwards signals to it and follows its stops for job control as in
   steps 5 and 6. The kernel re-parents them only at the end of the child's exit, after it has
   closed the child's descriptors, so sandy reaps the child before it watches them, and kills
   and reaps it before it ends them after a failure. Until then `waitid` reports nothing of the
   two: a program that has already exited would look as if it still ran, and the guard, which
   ends with it, as if it had ended first
   (`a_program_that_exits_before_it_is_sandys_child_is_reported`); and after a failed start a
   wait for the init would last for ever, because the init ends only once sandy has reaped the
   program (`a_failed_start_in_the_namespace_leaves_no_process_behind`). The program, not PID 1,
   gets those signals: a PID 1 ignores every signal it has no handler for, so a `SIGTERM` to it
   would be lost.
2. The init closes every descriptor but a pidfd of sandy and the pipe from the forked child, sets
   every signal to its default action and `SIGCHLD` to ignored, drops its capabilities and makes
   itself undumpable. Once the pipe has ended it opens a pidfd for PID 2 and ends when the program
   or sandy ends. The kernel re-parents the namespace's orphans to it, and with `SIGCHLD` ignored
   the kernel reaps them as they end (`orphans_are_reaped`). From inside its namespace a PID 1
   receives a signal only through a handler, and from outside only `SIGKILL` and `SIGSTOP`; it has
   no handler, so the program cannot end or stop it
   (`the_program_runs_as_pid_2_below_an_init_of_sandy`).
3. When the init ends, the kernel ends every process of the namespace. The guard watches the
   program and sandy as in step 3 and then kills the init through a pidfd; sandy kills the
   program's group and the init when the program ends. A guard that ends while the program runs
   ends the run as in step 5, and sandy's error names the guard of the PID namespace
   (`a_guard_that_ends_while_the_program_runs_ends_the_run`). The init watches sandy itself as
   well, so the namespace also ends when sandy and the guard are both killed with `SIGKILL`
   (`the_namespace_ends_when_sandy_and_the_guard_are_killed`).
4. Processes outside the namespace have no process ID in it, so `kill`, `pidfd_open`,
   `F_SETOWN`, `setpriority`, `ioprio_set` and `sched_setaffinity` reach none of them (`ESRCH`,
   measured on Ubuntu 22.04 and Fedora 44; `processes_outside_are_unreachable_by_id`).
   `kill(0, ...)` reaches the program's own group and `kill(-1, ...)` the namespace. The guard,
   sandy and the init lead groups of their own, so the program reaches none of them through its
   group either (`a_signal_to_the_programs_group_reaches_only_the_program`): without the
   namespace the guard leads the program's group, and only the Landlock scope keeps a
   `kill(0, ...)` from it. This is what isolates signals on kernels before Landlock ABI 6:
   `signals = "isolated"` with `contained` is enforced there through the namespace and the rules
   of "Signals and the terminal", and `check` names that mechanism
   (`check_names_the_pid_namespace_for_isolated_signals_below_abi_6`). Inside the namespace the
   program can still signal its own processes, the init, which ignores it, and with exposed ports
   the socket factory, which ends the program when it ends (step 7 of "Exposed and forwarded
   ports"); from ABI 6 the factory's own signal scope keeps it out of reach as well.
5. The init is undumpable, so its `/proc` files belong to root: no process of the user reads its
   environment, which is sandy's (`the_init_is_undumpable`). Its command line, which is sandy's,
   stays readable as every process's is. The program itself never sees the init in a `/proc`: it
   has none in the namespace, by the rule below.

A policy that grants a path of `/proc`, or of a directory above it such as `/`, keeps `contained`
without the namespace, with or without the file system view. The host's `/proc` names processes
by their IDs outside the namespace, so a program that reads `/proc/<its pid>` would read another
process, and a `/proc` of the namespace (`subset=pid`), which lists only its processes, would
hide the host's files the policy grants, such as `meminfo` or `sys`. A grant of a process
directory alone does not help: the resolver makes `/proc/self` the directory of sandy's process
ID when it plans, which names no process of the namespace. So with a `/proc` grant `/proc/meminfo`
stays readable and `/proc` lists the host's processes, as without `contained`
(`a_proc_grant_keeps_its_host_files_with_contained`). Below Landlock ABI 6 such a policy with
`signals = "isolated"` is refused, and the reason says that `contained` gets no PID namespace
while the policy grants a path of `/proc`.

The denylist still denies `setsid` and `setpgid`, although the namespace, not the group, now ends
the processes. That keeps one behaviour for one policy on hosts with and without the namespace:
a program that detaches into a session of its own fails on both, instead of working where user
namespaces do and failing on Ubuntu 23.10. It also keeps every process of the program in the
group that the terminal's job control signals reach.

Costs and differences:

- Inside, the program is process 2, and its parent has no ID there (`getppid` returns 0), nor do
  its process group and session (`getpgrp` and `getsid` return 0). The record of `--status-fd`
  names the program by its ID outside, which a caller can signal
  (`the_status_record_names_the_program_outside_its_namespace`).
- The PID namespace belongs to a user namespace of sandy's own, also with `contained` alone, so
  inside, files of root and of other users show the owner and group 65534, and so does every
  supplementary group except the user's own in `getgroups`, as in "Private network"
  (`files_of_root_show_the_owner_65534_in_the_pid_namespace`). Without the namespace, as in
  sandy 2.0, they show their owners. Processes of the user that runs sandy hold every capability
  in that namespace, so Yama's `ptrace_scope` 1 no longer keeps them from tracing the program
  (from the kernel source; not measured), as in "What stays open".
- Start time: with `contained` alone, the trial of `plan` adds a fork and an `unshare` to every
  start, and the namespace and the init add another. As the median of 100 runs of
  `sandy run --children contained --signals isolated -- /usr/bin/true` with the release build,
  about 1.1 to 1.4 ms more than without the namespace on Fedora 44 (5.3 to 5.5 against 4.1 to
  4.3 ms, a busy 24 CPU host).
- On Ubuntu every run adds AppArmor audit records to the kernel log, as in "Private network".

## Ending with the parent

With `process.end_with_parent = true` a watcher process ends the program when the process that
started sandy ends:

1. sandy reads its parent's process ID (`getppid`) as the first step of `main`. With
   `--parent-pid`, the caller names its own process ID, and sandy refuses when its parent is
   another process, for example because the caller has already ended and sandy was re-parented.
   Without `--parent-pid`, a parent that ends before this first step cannot be detected: sandy
   then already has another parent, the process it was re-parented to. Without `--parent-start`,
   "parent" is always the direct parent; a wrapper such as `sh -c`, `timeout` or `systemd-run`
   between the application and sandy is the parent instead.
2. Before it starts the watcher, sandy opens a pidfd for that process ID and checks that
   `getppid` still returns it. If it does not, the parent ended in between, and sandy refuses to
   start the program. A process ID that another process got in between fails this check too.
   With `--parent-start` sandy checks that start time instead of `getppid` (see "Naming the
   caller" below).
3. sandy opens a pidfd for its own process ID. The program keeps this ID after `execve`; with
   `children = "contained"` it stays the supervising sandy's.
4. sandy starts the watcher like the relay: it forks twice, so the watcher is not a child of the
   program, and continues only after the watcher has reported that it is confined. The watcher
   starts a session of its own (`setsid`) and blocks every signal except the fault signals. It
   keeps only the two pidfds, the readiness pipe and `/dev/null` as its standard descriptors,
   and confines itself with no_new_privs, Landlock without file access and without TCP (from
   ABI 6 also the abstract socket scope), and a seccomp filter that allows only polling,
   `pidfd_send_signal`, the readiness report, ending, and the memory and clock calls of the
   Rust runtime. It has no Landlock signal scope: it must signal the program, which runs in
   another Landlock domain. The filter allows `pidfd_send_signal` only through the program's
   descriptor and only with SIGTERM, SIGCONT and SIGKILL, so the watcher cannot reach the
   process that started sandy, whose pidfd it also holds.
5. The watcher polls both pidfds. When the program ends first, the watcher ends. When the parent
   ends, the watcher sends SIGTERM and SIGCONT through the program's pidfd (SIGCONT, so that a
   stopped program gets the request), waits at most 5 seconds for the program to end, and then
   sends SIGKILL. A pidfd always names the same process, so a reused process ID cannot redirect
   the signals. If polling fails, the watcher ends the program the same way, because it can no
   longer see the parent.

With `contained`, the supervising sandy forwards SIGTERM to the program and ends the group when the
program ends; SIGKILL to the supervising sandy makes the guard end the group.

### Naming the caller

`--parent-pid` alone is a process ID, which another process can have once the caller has ended,
so sandy accepts it only when it is sandy's own parent. `--parent-start` adds when that process
started: field 22 of `/proc/PID/stat`, in clock ticks since the boot of the host, so no change
of the system clock can alter it. The caller reads its own value from `/proc/self/stat` and
passes it with its process ID:

```sh
start=$(awk '{ match($0, /.*\)/); rest = substr($0, RLENGTH + 2); split(rest, f, " ")
               print f[20] }' /proc/$$/stat)
sandy run --signals isolated --end-with-parent --parent-pid $$ --parent-start "$start" ...
```

The name is in field 2 and can hold spaces and parentheses, so the fields are counted from the
last closing parenthesis; field 3 is the first after it, which makes the start time the
twentieth. The file is read by process ID and not through `/proc/self`, which would name the
`awk` process.

sandy opens a pidfd for the process ID, reads the start time, and then checks that the pidfd has
not become readable, which it does as soon as its process ends. A process that is still running
after the read held its ID throughout, so the start time belongs to it. sandy refuses when the
ID is gone, when its process has ended, or when the start time differs. With the token the named
process need not be sandy's parent, so a wrapper between the caller and sandy is allowed, and a
caller that ended before sandy's first step is caught instead of going unnoticed.

Without the token, a caller that ends before sandy's first step cannot be detected at all. The
kernel gives the orphan to the nearest child subreaper, usually the user's service manager,
which sandy cannot tell from a caller that is still there (`tests/parent.rs`,
`a_parent_that_ended_before_sandy_ran_is_refused`, records this).

### Letting the kernel do it

A caller on Linux 7.0 or newer can start sandy with
`clone3(CLONE_PIDFD | CLONE_PIDFD_AUTOKILL | CLONE_AUTOREAP | CLONE_NNP)` instead. The kernel
then kills sandy, and the program after the `execve`, as soon as the caller's pidfd closes,
which the end of the caller does (measured on kernel 7.2.11). Nothing has to be identified and
no watcher runs, and a caller that dies between `clone3` and sandy's first instruction is
covered as well. The limits: it is a SIGKILL with no grace period; it reaches only the process
the caller started, so it needs `children = "contained"` for the guard to end the rest of the
group; and the caller must not let the pidfd reach processes that outlive it. The exit status
stays readable through `PIDFD_GET_INFO` with `PIDFD_INFO_EXIT`.

Two rules keep the program from stopping the watcher. The policy requires `signals = "isolated"`,
so the program cannot signal the watcher, which is outside its Landlock domain. And the watcher is
in a session and process group of its own with its signals blocked: the kernel sends some signals
to a whole process group or to a terminal's foreground group (Ctrl+C, a hangup, SIGTTIN,
SIGWINCH, SIGHUP and SIGCONT to an orphaned group with a stopped member) without the permission
check that Landlock hooks, and the program can cause some of them (see "Signals and the
terminal"). The relay starts the same way for the same reason.

The watcher, the supervising sandy of `children = "contained"` and of the diagnostic mode, and
the guard are undumpable (`PR_SET_DUMPABLE` 0), which gives their `/proc/<pid>` files to root.
Without that, a program with a write grant on `/proc` could set their `oom_score_adj` to 1000
and let the out-of-memory killer end them first, which would take away the guarantee they stand
for (measured: the write succeeded before this). sandy makes itself undumpable before it forks
the guard and the program, so both start with the flag. Setting it after the fork left the
program a moment to write first: with a filter that held each `prctl(PR_SET_DUMPABLE, 0)` for
half a second, the program raised the priority of sandy and of the guard (measured on Linux
7.2; `a_program_cannot_raise_the_oom_priority_of_sandys_helpers` runs under such a filter). The
kernel clears the flag when the program executes the target (measured: `PR_GET_DUMPABLE` returns
1 in the program), so the program itself is unaffected. In the diagnostic mode the forked
program makes itself dumpable again before it executes the target, because the watcher reads the
path of that `execve` out of its memory, which the kernel allows only for a dumpable process
(measured: without it the path was unreadable in every run); that changes only the program, not
sandy or the guard. The watcher is undumpable before it reports that it is ready, so before the
program starts. The relay stays dumpable on purpose: it is the process that holds the relayed ports,
and only a dumpable process can be attributed to a listening socket (`ss -ltnp`). A relay that
the killer ends only closes those ports, which is the safe direction.

Residual risk: if the watcher itself is killed from outside the sandbox, for example by the
out-of-memory killer or by `pkill -f sandy`, which matches it, nothing ends the program with its
parent. The watcher uses about 2 MB, so the killer chooses it only after larger processes. An
unprivileged process can lower its own `oom_score_adj` only down to the value it inherited, so
the watcher cannot take itself out of reach of the killer.

## Landlock

### ABI

sandy reads the ABI from the kernel each time (`landlock_create_ruleset` with the VERSION flag).
It never infers the ABI from the kernel version, because distributions backport Landlock. It uses
the lower of the kernel ABI and ABI 9, the newest ABI that the `landlock` crate (0.4.7) knows. The
crate runs with `CompatLevel::HardRequirement`, so a right that the kernel does not support is an
error, not a silent omission. ABI 10 adds UDP rights. sandy uses the bind right for
`ip = "client"`, in a second ruleset built with raw system calls, because the crate's `AccessNet`
knows only the two TCP rights (see "Client networking"). `ip = "none"` needs no UDP right: the
seccomp filter denies IP sockets, so a program inside cannot create one, and a UDP socket created
before the sandbox is refused on a standard stream and closed on every other descriptor.

| ABI | Linux | What changes in sandy |
|---|---|---|
| none | | Refused. The reason names the fix: RHEL 9 needs 9.6 or newer; SLES 15 and openSUSE Leap 15 need `landlock` in the `lsm=` boot parameter; RHEL 8 has no Landlock. |
| 1 | 5.13 | Renaming or linking a file into another directory fails with `EXDEV`, also inside writable paths. |
| 1, 2 | | Landlock cannot restrict truncation. The denylist denies `truncate` for every path, also inside a writable one, because the call carries no access mode the filter could look at, and `open`/`openat` with `O_TRUNC` on a read-only open. A program that empties a file in a writable path needs `O_TRUNC` with write access, or `ftruncate`; both stay allowed. |
| 3 | 6.2 | Truncation is a Landlock right. |
| 4 | 6.7 | TCP bind and connect are denied when IP is denied (a second layer). With `ip = "client"` a TCP socket binds only port 0. |
| 1 to 4 | | Device ioctls are not checked by Landlock; the program can only open the devices of the policy and the system set. |
| 5 | 6.10 | `LANDLOCK_ACCESS_FS_IOCTL_DEV` is handled. |
| 1 to 5 | | `signals = "isolated"` is refused. |
| 6 | 6.12 | Signal and abstract socket scopes. |
| 9 | 7.1 | `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` is handled when `unix_sockets = "none"`. |
| 10 | 7.2 | With `ip = "client"` a UDP socket binds only port 0. |

### Rights per access level

| Policy access | Landlock rights |
|---|---|
| `read` | read file, read directory |
| `read_exec` | read file, read directory, execute |
| `read_write` | read file, read directory, write file, truncate, remove file, remove directory, make directory, make regular file, refer (move between writable directories), device ioctl; make socket only with `unix_sockets = "all"` |

A writable path never gets these rights:

- **Execute.** The policy rule against writable and executable paths.
- **Make symbolic link.** A process outside the sandbox that later writes a file in the writable
  directory (for example a configuration file that it writes before every start) would follow a
  planted link to any file of the user.
- **Make named pipe.** A planted FIFO blocks a process outside the sandbox that opens the path.
- **Make character or block device.** Never needed; it also needs `CAP_MKNOD`.
- **Make socket** when Unix sockets are denied. Binding a pathname socket needs an `AF_UNIX`
  socket, which the filter denies anyway.
- **Resolve Unix socket.** With `unix_sockets = "none"`, no path grants it. With `"all"`, the
  right is not handled at all, so `"all"` means every socket the user can reach on every kernel.

### Device ioctls and the terminal

From ABI 5 sandy handles `LANDLOCK_ACCESS_FS_IOCTL_DEV` and grants it only in writable paths.
Landlock decides the ioctl right when a file is opened. Standard input, output and error were
opened before the sandbox, so a terminal on them keeps working (`TIOCGWINSZ`, `tcsetattr`). The
filter still denies `TIOCSTI`, `TIOCLINUX` and `TIOCSETD` on every descriptor; the tests
`terminal_input_injection_is_denied` and `the_terminal_line_discipline_cannot_change` check
them. Cost: tools that attach a line discipline, such as `ldattach`, fail with `EPERM`; they
need privileges anyway.

`TIOCEXCL` is denied as well. It puts a terminal in exclusive mode, after which every open of
it fails with `EBUSY` for processes without `CAP_SYS_ADMIN`, also after the program that set it
has ended (measured on Linux 7.2: a shell redirection to the terminal failed). A program that
inherited the user's terminal could otherwise keep a pager in a pipeline or a password prompt,
which open `/dev/tty`, from working until someone clears the mode. Clearing it (`TIOCNXCL`) and
asking for it (`TIOCGEXCL`) stay allowed. The test is `the_terminal_cannot_be_made_exclusive`.
Cost: a serial terminal program that asks for exclusive access to its line gets `EPERM`;
`minicom` does not ask (measured), pyserial locks with `flock` instead, and the bash, Python,
git, curl, nano, less, tmux, `stty` and `reset` runs of the measurement did not use it.

The filter also denies the console ioctls that change a Linux virtual console: its keyboard map,
the strings of its function keys, its keyboard mode, its fonts and colors, and which console the
screen shows (`KDSKBENT`, `KDSKBSENT`, `KDSKBMODE`, `PIO_FONT`, `VT_ACTIVATE` and the others in
`CONSOLE_IOCTLS` in `filter.rs`). When the user starts sandy from a text console, that console is
the program's controlling terminal, and the kernel's console code lets a process make most of these
changes on its controlling terminal without privileges. The key map and the function key strings
belong to every console of the host, so a program could map a key the user presses later to a
command of its choice, which the shell outside the sandbox then reads as typed input, as with
`TIOCSTI`. The calls that only read stay allowed (`KDGKBTYPE`, `VT_GETSTATE`; nano asks the second
whether it runs on a console). The test `console_ioctls_are_denied` checks the filter on the
kernel; no test host gives an unprivileged process a virtual console, so the effect on a real
console is taken from the kernel's console code and was not measured. Cost: `loadkeys`, `setfont`,
`chvt`, `kbd_mode -s` and `setleds` fail with `EPERM` on a text console; the bash, Python, git,
curl, nano, less, `stty` and `reset` runs of the measurement used none of these calls.

### Access mode 3

Linux accepts the access mode 3 (`O_RDWR | O_WRONLY`) in `open`. It means "check read and write
permission, then return a descriptor that can neither read nor write, only use ioctl". Landlock
derives the rights it checks at open time from the read and write modes of the descriptor, so it
checks no right for such an open. This is a limitation of Landlock, and sandy closes it with
seccomp.

Measured on Fedora 44 (Linux 7.2, Landlock ABI 10), in a domain that handles every right of ABI 9
as sandy builds it, on a file that the policy grants nothing on and that the user may read and
write:

| On the descriptor of `open(path, 3)` | Result |
|---|---|
| the open itself | succeeds on every path the user may read and write; `EACCES` where the file permissions deny one of the two |
| `fchmod`, `fchown`, `fsetxattr`, `futimens` | change the file |
| `fstat`, `statx`, `fgetxattr`, `flistxattr` | read its metadata and its extended attributes |
| `ioctl` on a regular file (`FIONREAD`, `FS_IOC_GETFLAGS`) | works |
| `FIDEDUPERANGE` on btrfs, with the descriptor as the destination and a file of the program as the source | compares a 4 KiB block of the file with the program's guess: status 0 and the block deduplicated when the guess is right, status 1 when it is wrong; the contents stay the same |
| `FIDEDUPERANGE` with the descriptor as the source | `EINVAL` |
| `ioctl` on a device | `EACCES` from ABI 5; reaches the driver on ABI 1 to 4 |
| `read`, `write`, `flock` | `EBADF` |
| `ftruncate` | `EINVAL` |
| `mmap`, `execveat` and `linkat` with `AT_EMPTY_PATH`, reopening through `/proc/self/fd` | `EACCES` |

The descriptor cannot read the file, but it still reaches its contents. On a file system that
deduplicates (btrfs here), the program writes a guess of one 4 KiB block to a file of its own on
the same file system and asks the kernel to deduplicate it with that block of the file. The
status says whether the guess was right. That confirms a guessed block, and it finds a block
with few unknown bytes by trying every value. The descriptor also carries the metadata calls
past Landlock in both directions, which is also a way around `path_metadata = "deny"`.
`LANDLOCK_ACCESS_FS_IOCTL_DEV` (ABI 5) covers only the device ioctls. Landlock has no hook for
the metadata calls on a descriptor at any ABI, ABI 10 included, so no ABI makes access mode 3
harmless.

The denylist therefore denies `open` and `openat` with access mode 3. `openat2` performs the same
opens, and its flags live in an `open_how` structure in memory, which seccomp cannot read, so the
rule cannot be applied to it and the call is left out of the allowlist (`ENOSYS`). Allowing it
from some ABI upwards would reopen the hole on every kernel, so sandy does not. The cost is GNU
tar (see "Structure" below). `landlock_alone_allows_access_mode_3` in `escape_linux.rs` holds the
measurement, so a kernel that closes the hole is noticed. `FIDEDUPERANGE` is denied as well, on
every descriptor (see "Metadata"), so the oracle is closed twice.

## Seccomp

### Structure

sandy installs up to four filters, built with `seccompiler` from `libc::SYS_*` numbers, and a
fifth only with `--explain` (see "Diagnostic mode"):

1. **Allowlist.** Every number of the reviewed table is allowed: the Linux 7.2 table, on x86_64
   0 to 336 and 424 to 471, on arm64 0 to 243, 260 to 294 and 424 to 471. Every other number
   fails with `ENOSYS`: system calls of newer kernels until sandy reviews them, x32 numbers,
   `clone3`, `openat2`, `fanotify_init` and `name_to_handle_at`. A system call of another
   architecture (for example `int 0x80` on x86_64) kills the process.
2. **Denylist.** Rules with argument checks return `EPERM`.
3. **Extended attribute reads.** With `path_metadata = "deny"`, the reads that take a path
   return `ENOTSUP`.
4. **Socket families.** `socket` with a family the policy denies returns `EAFNOSUPPORT`. `run`
   accepts an inherited socket on a standard stream only when this filter would let the program
   create one like it (see "Refusals").

The kernel applies the stricter result of all of them, and among equal results the one of the
filter installed last, which is why the family filter comes after the denylist. Programs mostly
treat `ENOSYS` like an older kernel: glibc falls back from `clone3` to `clone`, callers of
`openat2` fall back to `openat`, and a program that cannot create an fanotify group uses
inotify. They treat `EAFNOSUPPORT` like a kernel without the family, so a program that probes
for IPv6 or for AF_UNIX falls back instead of ending, and `ENOTSUP` like a file system without
extended attributes, which every caller of `getxattr` handles; `EPERM` reads like a temporary
failure. `socketpair` keeps `EPERM`, because its denials are about the socket type, not the
family. Arguments of type int (socket family, ioctl command, clone flags, open flags) are
compared on their low 32 bits only, because the kernel ignores the high bits.

Not every caller falls back. GNU tar 1.35 on glibc 2.43 opens each directory of an archive with
`openat2` (`O_PATH` with `RESOLVE_BENEATH`) and gives up when that fails, so it creates the top
directory of an archive and extracts nothing below it. Another error code does not help: with a
filter that failed `openat2` with `EPERM`, `EINVAL`, `EOPNOTSUPP`, `EACCES` or `ENOENT` instead,
tar gave up the same way. Creating and listing an archive work, and so does extracting one that
holds no directory, and `bsdtar` extracts the same archive in the sandbox. Measured on Fedora 44,
under both settings of `path_metadata`. Why `openat2` is not allowed instead is in "Access
mode 3".

### Denylist

The rules return `EPERM`, except where the table says otherwise.

| System calls | Rule | Reason |
|---|---|---|
| `socket` (`EAFNOSUPPORT`) | family not in the allowlist; with `ip = "all"` or `ip = "client"` an IP protocol other than 0, ICMP, TCP, UDP, ICMPv6 and MPTCP | `AF_UNIX` only with `unix_sockets = "all"`. `AF_INET`, `AF_INET6` and `AF_NETLINK` with protocol `NETLINK_ROUTE` only with `ip = "all"` or `ip = "client"`. A denylist would miss families that reach TCP, for example `AF_SMC`. Within `AF_INET` and `AF_INET6` the kernel loads the module of a protocol when a program asks for a socket of it, for any user: SCTP, L2TP over IP, and since Linux 6.14 SMC through `IPPROTO_SMC`, which reaches the same code as `AF_SMC`. On Fedora 44 the modules `sctp`, `l2tp_ip`, `l2tp_ip6` and `smc` are installed and not blocked (checked with `modinfo` and `modprobe -c`). That is kernel code no common program needs: the measured programs used 0, TCP (Python, curl, Java, Node, Go), MPTCP (Go), ICMP and ICMPv6 (ping), and ran the same with the rule. `ip_sockets_of_unusual_protocols_are_denied` checks it with protocol 253, which has no module. Route netlink lets the C library list interfaces (`getifaddrs`, `getaddrinfo`); other netlink protocols expose, for example, every socket of the host (`sock_diag`). `AF_VSOCK`, `AF_ALG`, `AF_PACKET` and the rest are always denied. |
| `listen`, `accept`, `accept4` | with `ip = "client"`: always | No socket of the program takes a connection. The filter cannot tell an IP socket from a Unix one by its descriptor, so this holds for Unix sockets too (see "Client networking"). |
| `socketpair` | other family than `AF_UNIX`; datagram or raw type when `unix_sockets = "none"` | A datagram socket can send to any address, also from a pair. `AF_UNIX` treats `SOCK_RAW` as `SOCK_DGRAM`. Stream and seqpacket pairs stay allowed. |
| `ioctl` | `TIOCSTI`, `TIOCLINUX`, `TIOCSETD`, `TIOCEXCL`, the console ioctls that change a virtual console, and the file system ioctls that change a file; with `signals = "isolated"` also `TIOCSPGRP`, `TIOCSWINSZ` and `TIOCSIG` | `TIOCSTI` and `TIOCLINUX` can inject input into the terminal of the user. `TIOCSETD` changes its line discipline, and the kernel loads the module of a discipline on demand when `dev.tty.ldisc_autoload` is 1, which is kernel attack surface. `TIOCEXCL` keeps every process outside from opening the terminal again. The console ioctls change the key map and the fonts of every console of the host (see "Device ioctls and the terminal"). For the file system ioctls see "Metadata", for the three others "Signals and the terminal". |
| `fcntl` | `F_SETLEASE` with anything but `F_UNLCK`, `F_SETDELEG` | A lease or a delegation needs only a read descriptor of a file or directory the user owns, and Landlock does not cover `fcntl`. While the program holds one, a process outside that opens the file for writing, or creates, renames or removes an entry in the directory, waits until `/proc/sys/fs/lease-break-time` passes (45 seconds by default; measured: 48 seconds). Giving one up stays allowed. |
| `clone` | any `CLONE_NEW*` flag, and `CLONE_PARENT` | Namespaces expose kernel interfaces that are otherwise reserved for root. `CLONE_PARENT` makes the new process a child of the program's parent, a process outside the sandbox, which then receives a `SIGCHLD` it did not ask for and has to reap a process it never started (measured: the process that started sandy reaped it). None of the measured programs used it; container runtimes do, and they fail in the sandbox anyway. |
| `unshare` | any `CLONE_NEW*` flag, including `CLONE_NEWTIME` | Same. `unshare(CLONE_FILES)` stays allowed. |
| `setns` | always | Same. |
| `personality` | other values than 0, 0x8, 0x20000, 0x20008, 0x40000, 0x40008, 0x60000, 0x60008, 0xffffffff | The values Docker allows, and `ADDR_NO_RANDOMIZE` (0x40000) alone and with those flags, which `setarch -R`, `rr` and the thread sanitizer need; it weakens address space randomization only inside the sandbox. The rest are old exploit helpers, for example `READ_IMPLIES_EXEC`. |
| `open`, `openat` | access mode 3; before ABI 3 also `O_TRUNC` with read-only access | See "Access mode 3" and the ABI table. |
| `truncate` | before ABI 3, for every path | Landlock cannot check it, and the call shows the filter no access mode. `ftruncate` and `O_TRUNC` with write access stay allowed, so a writable path still works. |
| io_uring (3 calls) | always | io_uring operations bypass seccomp, including socket creation. |
| `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, `kcmp`, `process_madvise` | always | Second layer to Landlock. Debuggers do not work inside the sandbox. |
| `madvise`, `prctl` | `MADV_MERGEABLE`; `PR_SET_MEMORY_MERGE` with anything but 0 | Where an administrator enabled KSM, the kernel shares the program's mergeable pages with identical pages of other processes, and the time a write to such a page takes tells whether another process holds the same content. `PR_SET_MEMORY_MERGE` makes every page of the process mergeable at once and needs no capability (measured on Linux 7.2: it succeeded in the sandbox before this rule). KSM is off on the Fedora test host (`/sys/kernel/mm/ksm/run` is 0), so the effect was not measured. No measured program used either; `MADV_UNMERGEABLE`, `PR_SET_MEMORY_MERGE` with 0, `PR_GET_MEMORY_MERGE` and the other advice stay allowed. |
| System V IPC (12 calls), POSIX message queues (6 calls) | always | These objects belong to all processes of the user and Landlock does not cover them. `shmat` would give access to the memory of processes outside the sandbox. |
| `mount`, `umount2`, `pivot_root`, `chroot`, new mount API, `open_tree_attr`, `mount_setattr` | always | Second layer; Landlock denies mounts already. |
| `statmount`, `listmount`, `listns` | always | They show the mount and namespace topology of the host, which leaving out `/proc` otherwise hides (`/proc/self/mountinfo`, `/proc/*/ns`). |
| `ioctl` with `PIDFD_GET_INFO` (every size of its structure) | always | `pidfd_open` takes any process of the host, and this call then tells its parent, its user and group IDs, its cgroup and how it ended, which leaving out `/proc` otherwise hides (measured: for process 1, also with `signals = "isolated"`). Only libsystemd uses it, for the peers of a bus, and does without: `busctl` lists no peer process IDs in the sandbox before and after. |
| `lsm_get_self_attr`, `lsm_set_self_attr`, `lsm_list_modules` | always | They show which security modules the host runs and the program's own security attributes, which leaving out `/proc` and `/sys/kernel/security` otherwise hides, and `lsm_set_self_attr` changes them. |
| `bpf`, `perf_event_open`, `userfaultfd` | always | Kernel attack surface. |
| `keyctl`, `add_key`, `request_key` | always | The keyrings of the user are shared by all its processes. |
| `kexec_*`, module calls, `reboot`, `swapon`, `swapoff`, `acct`, `quotactl`, `quotactl_fd`, `syslog`, `open_by_handle_at`, `settimeofday`, `clock_settime`, `vhangup`, `sethostname`, `setdomainname`, `setgroups`; on x86_64 `iopl`, `ioperm`, `modify_ldt`, `uselib` | always | They need capabilities, which sandy never passes on. A second layer. |
| `prctl`, `ioprio_set`, the calls that set user and group IDs, `socket`, `setsockopt`, `getsockopt`, `ioctl`, `mbind`, `move_pages` | arguments that need a capability | A second layer. See "Arguments that need a capability". |
| metadata calls by path, `fchown` | with `linux.path_metadata = "deny"` | See "Metadata". |
| `getxattr`, `lgetxattr`, `listxattr`, `llistxattr`, `getxattrat`, `listxattrat`, `file_getattr`, `fsetxattr`, `fremovexattr` (`ENOTSUP`) | with `linux.path_metadata = "deny"` | The reads see extended attributes of every file the user can reach, outside the policy as well; the two calls on a descriptor change those of a file the program may only read. See "Metadata". |
| `fanotify_init` (`ENOSYS`, from the allowlist) | always | An unprivileged fanotify group reports which files change on every path the user can reach, outside the policy as well. Landlock has no hook for it. |
| `name_to_handle_at` (`ENOSYS`, from the allowlist) | always | It gives the file handle (inode, parent and generation on btrfs) and the mount of every path the user can reach, outside the policy as well (measured: `~/.bashrc` under a policy without it), and only `open_by_handle_at`, which needs a capability, takes the handle. No measured program used it; without it a program works with paths, as on a kernel built without file handles. |
| `clone`; on x86_64 also `fork`, `vfork` | with `process.children = "none"`: `clone` without `CLONE_THREAD`, `fork` and `vfork` always | See "Child processes". |
| `setsid`, `setpgid` | with `process.children = "contained"`: always | See "Contained child processes". |
| `setpgid` | with `signals = "isolated"`: a process group other than 0 | See "Signals and the terminal". |
| `fchown`, `fchownat`; on x86_64 also `chown`, `lchown` | with `path_metadata = "allow"`: a user ID that is neither -1 nor one the process holds | A second layer. See "Arguments that need a capability". |
| `fchmod`; with `path_metadata = "allow"` also `chmod`, `fchmodat`, `fchmodat2` | mode with `S_ISUID` or `S_ISGID` | A file with these bits runs with the rights of this user when another local user runs it. See "Setuid and setgid bits". |
| `prlimit64`, `sched_setaffinity`, `sched_setscheduler`, `sched_setparam`, `sched_setattr` | process ID other than 0 and the target's own | See "Other processes". |
| `setpriority`, `ioprio_set` | a process group or user, or a process ID other than 0 and the target's own | Same. |

### Arguments that need a capability

Some allowed calls do something only with a capability when they get certain arguments. sandy
passes on no capability, so the kernel refuses those arguments to the program anyway. The
denylist refuses them too, with `EPERM`, the error the kernel returns for most of them, so that
the denial does not rest on the kernel's capability check alone, as for the calls in the table
that need a capability:

- `prctl` with `PR_CAPBSET_DROP` (`CAP_SETPCAP`), `PR_SET_MM` and `PR_SET_IO_FLUSHER`
  (`CAP_SYS_RESOURCE`), and `PR_CAP_AMBIENT` with `PR_CAP_AMBIENT_RAISE`, which needs the
  capability in the permitted and inheritable sets. The option is an int, the subcommand of
  `PR_CAP_AMBIENT` an unsigned long that the kernel compares on all 64 bits. Two forms of
  `PR_SET_MM`, `PR_SET_MM_MAP` and `PR_SET_MM_MAP_SIZE`, need no capability, but the executable
  that `PR_SET_MM_MAP` can set needs `CAP_CHECKPOINT_RESTORE` and lies in memory, where the
  filter cannot read it, so all of `PR_SET_MM` is denied. Only tools that restore checkpointed
  processes use these forms, and they need ptrace.
- `ioprio_set` with the real-time class (`CAP_SYS_ADMIN` or `CAP_SYS_NICE`). The class is in
  bits 13 to 15 of an int, and the rule looks at those bits only.
- `setuid`, `setreuid`, `setresuid` and `setfsuid`, and their group forms, with an ID that is
  not the real, effective or saved ID of the process (`CAP_SETUID`, `CAP_SETGID`). sandy reads
  these IDs when it builds the filter, in the process that then executes the program, and
  no_new_privs keeps `execve` from changing them. -1, which leaves an ID as it is, stays allowed,
  and so do the program's own IDs, which programs pass to drop privileges they do not hold.
  `setfsuid` and `setfsgid`, which the kernel ignores for another ID, fail with `EPERM` then.
- With `path_metadata = "allow"`, `fchown`, `fchownat`, and on x86_64 `chown` and `lchown`, with
  a user ID that is neither -1 nor one the process holds (`CAP_CHOWN`): without the capability a
  process can only keep the owner of its own file, which is its file system user ID. The group
  stays with the kernel's check, because a process may give its file any of its supplementary
  groups, which the filter does not know. Under `"deny"` these calls are denied anyway. Measured
  on Fedora 44 with sources owned by root and by the user: `cp -a` (which tries user 0, and then
  -1 to keep the group), `tar -x`, `tar --same-owner -x`, `rsync -a` and `install`, also with
  `-o`, gave the same exit status and wrote files with the same owner, group and mode with and
  without the rule.
- `socket` for a raw IPv4 or IPv6 socket (`CAP_NET_RAW`). `ping` uses ICMP datagram sockets,
  which need none.
- `setsockopt` with `SO_SNDBUFFORCE` and `SO_RCVBUFFORCE` (`CAP_NET_ADMIN`), which go past the
  buffer limits of the host, `SO_MARK` (`CAP_NET_RAW` or `CAP_NET_ADMIN`), which selects routing
  tables and firewall rules, `IP_IPSEC_POLICY`, `IP_XFRM_POLICY` and their IPv6 forms
  (`CAP_NET_ADMIN`), and `TCP_REPAIR` (`CAP_NET_ADMIN`) with the options that work only in
  repair mode. Reading these options needs no capability and stays allowed.
- `setsockopt` and `getsockopt` with the options of the legacy firewall interfaces: iptables,
  ip6tables, arptables, ebtables, IPVS and ipset. Each needs `CAP_NET_ADMIN` before the kernel
  module behind it parses the request. No other IP option has these numbers; the ones between
  them, among them `IPV6_TCLASS` and `SO_ORIGINAL_DST`, which transparent proxies read without a
  capability, stay allowed.
- `ioctl` with `TIOCVHANGUP`, which hangs up a terminal like `vhangup`, `TIOCCONS`, which sends
  the console messages of the host to a terminal, and `TIOCSLCKTRMIOS`, which locks the settings
  of a terminal, and with `FIFREEZE`, `FITHAW`, `FITRIM`, `FS_IOC_SHUTDOWN` and
  `FS_IOC_SETFSLABEL`, which freeze, thaw, trim, shut down or rename the whole file system of a
  descriptor (all `CAP_SYS_ADMIN`). `TIOCSCTTY` stays allowed: it needs a capability only to
  take a terminal from another session, and `setsid -c` passes the same argument for a free one.
- `mbind` and `move_pages` with `MPOL_MF_MOVE_ALL` (`CAP_SYS_NICE`), which moves the pages
  that other processes map as well.

Left to the kernel's check:

- `prctl` with `PR_SET_SECUREBITS`. Since Linux 6.14 a process may set
  `SECBIT_EXEC_RESTRICT_FILE` and `SECBIT_EXEC_DENY_INTERACTIVE` without a capability, so
  whether a call needs one depends on the bits the process holds already. The other bits change
  only how the kernel treats root and capabilities, and the program has neither.
- `mknod` and `mknodat` of a device node (`CAP_MKNOD`). Landlock never grants the right to
  make one, which every ABI handles, so this denial has a second layer already, and Landlock
  decides first (`EACCES`). A seccomp rule would be a third layer.
- Real-time scheduling and a lower nice value. Besides a capability, `RLIMIT_RTPRIO` and
  `RLIMIT_NICE` allow them, which the caller sets.
- The management ioctls of single file systems, such as resizing, adding devices and quotas on
  btrfs, or growing XFS. Each file system has its own set.
- Socket options for which the value decides: `SO_PRIORITY` above 6, `SO_DEBUG`,
  `IP_TRANSPARENT`, `IPV6_TRANSPARENT` and the busy polling options.
- Arguments in memory, which seccomp cannot read: the sets of `capset`, the modes of `adjtimex`
  and `clock_adjtime`, the policy of `sched_setattr` (`SCHED_DEADLINE`), raised hard limits in
  `prlimit64` and `setrlimit`, the real-time priority of an asynchronous I/O request
  (`io_submit`), and a mark or a priority in a control message of `sendmsg`.

Measured on Fedora 44 with a recorder built on seccomp user notifications, outside the sandbox:
bash, sh, coreutils, Python 3.14 (threads, multiprocessing, asyncio, sqlite3, urllib), git,
curl, sqlite3, Perl, a Rust program and rustc, a Go program, Java 21, Node.js 22, ping, ionice,
nice, chrt, taskset, setpriv, getent, ip, id and flock passed none of these arguments. They pass
their own IDs to `setuid`, `setgid`, `setreuid`, `setregid` and `setresuid` (ping, Python, Perl),
ask `PR_CAP_AMBIENT_IS_SET` (setpriv) and set the best-effort and idle I/O classes (ionice). Run
in the sandbox before and after the rules, they gave the same output under both settings of
`path_metadata`.

The tests are `prctl_options_that_need_a_capability_are_denied`,
`realtime_io_priority_is_denied`, `ids_the_process_does_not_hold_cannot_be_set`,
`raw_ip_sockets_are_denied`, `socket_options_that_need_a_capability_are_denied`,
`ioctls_that_need_a_capability_are_denied`, `pages_that_other_processes_map_cannot_be_moved`
and `files_cannot_be_given_to_another_user`.

### Metadata

Landlock does not restrict `chmod`, `chown`, `utimensat` or extended attributes. With the default
`linux.path_metadata = "deny"`, the denylist denies:

- `fchmodat`, `fchmodat2`, `fchownat`, `setxattr`, `lsetxattr`, `removexattr`, `lremovexattr`,
  `setxattrat`, `removexattrat`, `file_setattr`, and `utimensat` with a path;
- on x86_64 also `chmod`, `chown`, `lchown`, `utime`, `utimes` and `futimesat`;
- through a descriptor, `fchown`, and `fsetxattr` and `fremovexattr` with `ENOTSUP`.

`fchmodat`, `fchmodat2` and `fchownat` are denied completely, because they accept an `O_PATH`
descriptor with `AT_EMPTY_PATH`, and `O_PATH` opens need no Landlock right. The calls on a
descriptor reject `O_PATH` descriptors, and access mode 3 is denied, so they only reach files that
Landlock let the program open, but that includes a file of a `read` path opened read-only and a
file the caller passed on a standard stream: seccomp sees only the descriptor number, not how the
file was opened. So the owner and the extended attributes, among them ACLs and the SELinux label,
are denied through a descriptor too. The programs that set them on the files they write carry on
without them (measured on Fedora 44: `sed -i`, `gzip`, `xz`, `zstd`, `patch`, `cp -p`, `mv` to
another file system, Java's `Files.copy` with `COPY_ATTRIBUTES`, and Node's `copyFileSync` behaved
the same before and after). `fchown` fails with `EPERM`, as for any user who may not give a file
away. The attribute calls fail with `ENOTSUP`, as on a file system without extended attributes,
because with `EPERM` `sed -i` and `patch` printed a warning for every file. `fchmod` and
`utimensat` without a path stay allowed: `cp`, `touch` and Rust's `fs::copy` need them on the files
they write, and `sandy check` warns that they also reach files the program may only read (see
"Known limitations"). Programs that change metadata by path need
`path_metadata = "allow"`; then the program can change the metadata of every file the user owns.
Measured on Fedora 44: `install`, `rsync -a`, `unzip`, `cpio -idm` and `git` fail under `"deny"`
and work under `"allow"`, while `cp -p` works under both, because it sets the metadata through the
descriptor it wrote. `cp -a` is in between: it copies a single file under `"deny"` too, with its
mode and times and, since the descriptor calls for attributes fail, without its extended
attributes, but it fails on a directory, whose times it sets by path ("preserving times ...:
Operation not permitted"), and works there under `"allow"`. A tree that holds a symbolic link
fails under both settings, because a writable path never gets the right to make one. The test is
`cp_a_copies_a_file_under_deny_and_a_directory_only_under_allow`.

The same setting decides the reads. `getxattr`, `lgetxattr`, `listxattr` and `llistxattr` with a
path, and `getxattrat`, `listxattrat` and `file_getattr`, fail with `ENOTSUP`, the error of a file
system without extended attributes. Landlock has no hook for them, so they otherwise read the
attributes of every file the user can reach, outside the policy as well: the names and values of
user attributes, ACLs and, on a host with SELinux, the security label. `fgetxattr` and `flistxattr`
stay allowed: they only reach files that Landlock let the program open, and reading what the
program may read changes nothing. `getxattrat`, `listxattrat` and `file_getattr` are denied
completely, because they read the descriptor itself with `AT_EMPTY_PATH`.

Cost: `cp -a` and `cp --preserve=xattr` copy no extended attributes; `rsync -X`,
`tar --xattrs`, `getfacl` and `ls -Z` read by path and see none. `path_metadata = "allow"`
brings both the reads and the writes back. The tests `extended_attributes_by_path_are_unreadable`
and `a_read_only_descriptor_changes_only_the_mode_and_the_times` check both settings.

Under every policy the denylist also denies the file system ioctls that change a file or a
directory. Landlock checks ioctls only on device files, so they reach every descriptor the
program holds, also one of a file in a `read` path (measured on Linux 7.2):

- `FS_IOC_SETFLAGS`, its 32-bit form and `FS_IOC_FSSETXATTR` change inode flags and attributes,
  which is metadata like `chmod`. Only `chattr` and tools that set `NOCOW` use them, and they
  have no counterpart that the metadata calls on a descriptor need.
- `FS_IOC_SETVERSION`, its 32-bit form and `EXT4_IOC_SETVERSION`, which ext4 treats the same
  way, change the version a file carries, which is metadata that the policy denies when the
  call takes a path.
- `FS_IOC_ENABLE_VERITY` makes the content of a file permanently read-only (measured on btrfs
  with a descriptor opened read-only).
- `FS_IOC_SET_ENCRYPTION_POLICY` encrypts what the user later writes into an empty directory,
  with a key the program chose. `FS_IOC_REMOVE_ENCRYPTION_KEY` and its all-users form lock
  encrypted directories the user has unlocked, which reaches files outside the policy.
- The btrfs ioctls that create, snapshot and delete subvolumes, or make them read-only, change
  directories without the Landlock checks for creating and removing entries.
  `BTRFS_IOC_SET_RECEIVED_SUBVOL` and its 32-bit form, which a 64-bit kernel also takes, change
  the identity by which `btrfs receive` finds the parent of an incremental stream (measured on
  Linux 7.2 with a descriptor opened read-only).
- `FIDEDUPERANGE` makes a file share blocks with another file of the same content. The kernel
  takes a destination the user owns also when it was opened read-only, so the program could
  change how a file of a `read` path is stored (measured on btrfs: the file's extent became
  shared with a file of the program), and the answer tells whether a guessed block equals a
  block of the destination, the oracle of "Access mode 3". `FICLONE`, which `cp` uses, needs a
  destination opened for writing and stays allowed.

The reading forms (`FS_IOC_GETFLAGS`, `FS_IOC_FSGETXATTR`, `FS_IOC_MEASURE_VERITY`) stay
allowed. The test `file_system_ioctls_cannot_change_readable_files` checks the denials.

### Setuid and setgid bits

Under every policy, `fchmod` fails with `EPERM` when the mode has `S_ISUID` or `S_ISGID`. With
`path_metadata = "allow"`, `chmod`, `fchmodat` and `fchmodat2` get the same check; with the
default `"deny"` they are denied anyway. Otherwise the program could mark a file in a writable
path setuid to the user, and another local user who can reach the file would run it with this
user's rights.

Creating a file with these bits (`open` with `O_CREAT` and mode 4755, `mknod`) stays allowed.
Tested on Linux 7.2: `write` and `ftruncate` (which `mmap` writes need first) clear both bits, so
such a file stays empty or loses the bits. Programs that set the setgid bit on directories, for
example `git init --shared`, fail.

### Child processes

With `process.children = "none"` the denylist allows `clone` only when its flags contain
`CLONE_THREAD`, and on x86_64 it denies `fork` and `vfork`. The flags are the first argument of
`clone` on x86_64 and arm64, and the filter compares their low 32 bits, which the kernel uses.
`clone3` fails with `ENOSYS` in every policy, so the C library creates threads with `clone` and
`CLONE_THREAD`, and `posix_spawn` falls back to `clone` with `CLONE_VM | CLONE_VFORK`, which is
denied. Threads therefore keep working, and so does `execve`, which replaces the program's own
image. Programs that start helpers, shells or other programs fail with `EPERM`. The relay of
exposed and forwarded ports is forked before the program's filter exists, so it is not affected.

### Signals and the terminal

The Landlock signal scope checks the system calls that send a signal. The kernel also signals
whole process groups for terminal job control, and those signals skip that check: `SIGTTIN` and
`SIGTTOU` for a background group that reads the terminal or changes it, and `SIGWINCH` for the
foreground group when the window size changes. Without further rules a program with
`signals = "isolated"` could stop other jobs of the user's terminal session, for example an
editor the user suspended in the same shell (measured on Linux 7.2):

- It joins the job's process group with `setpgid(0, group)` and then reads the terminal. The
  kernel stops every process of the group, including the job.
- It takes the terminal with `TIOCSPGRP`. The job that had the foreground stops as soon as it
  reads the terminal again.
- It changes the window size with `TIOCSWINSZ`, which sends `SIGWINCH` to the foreground group.
- On the master side of a pseudo-terminal, `TIOCSIG` sends `SIGINT`, `SIGQUIT` or `SIGTSTP` to
  the foreground group of the other side (measured: an outside process on the other side
  received `SIGINT`). A program holds a master when the policy grants `/dev/ptmx`, or when its
  caller passes one on a standard stream, which `sandy run` refuses (see below).

With `signals = "isolated"` the denylist therefore allows `setpgid` only with process group 0,
which makes the caller a group leader, and denies `TIOCSPGRP`, `TIOCSWINSZ` and `TIOCSIG`.
seccomp cannot compare two arguments, so `setpgid(pid, pid)` is denied as well; a program that
wants its own group uses `setpgid(0, 0)` or `setsid`, which stay allowed. The four routes are
checked by `other_jobs_of_the_terminal_cannot_be_stopped`,
`the_terminal_cannot_be_taken_from_the_foreground_job`, `terminal_resize_cannot_signal_outside`
and `a_pseudo_terminal_master_cannot_signal_outside`.

Cost: a shell inside the sandbox has no job control, because it cannot put a pipeline in a group
of its own and cannot hand the terminal to it. Programs that resize their terminal (`stty rows`,
`resize`) fail with `EPERM`; tmux inside the sandbox still works (measured), because it ends
its panes with `kill`. What stays open: the program's own reads from the terminal still
stop its own process group. In the exec model that is the group sandy was started in, so the
processes outside the sandbox that share it stop as well: the shell that ran sandy without job
control, for example in a script, and the other commands of its pipeline. They are the job the
user started, which stops as it would without a sandbox; no other job is reached.
`a_terminal_read_stops_the_group_sandy_was_started_in` records this. `sandy check` prints it as
a warning for every policy with `signals = "isolated"` and without `children = "contained"`,
which gives the program a process group of its own.

The interrupt, quit and suspend characters reach the same group: a program that holds a master
writes Ctrl+C, Ctrl+\ or Ctrl+Z into it, and the kernel sends the same signals as `TIOCSIG`
(measured on Linux 7.2, also with `children = "contained"`). A write cannot be told from any
other, so with `signals = "isolated"` `sandy run` refuses a master on a standard stream with
status 125, naming the stream and saying to pass the slave side or a pipe instead. sandy knows a
master by its device number, which the kernel fixes: every Unix98 master is open on a ptmx
device, 5:2, whether `/dev/ptmx` or the `ptmx` of another devpts instance, as in a container, and
the legacy BSD masters (`CONFIG_LEGACY_PTYS`, which Fedora leaves out) have major 2. The slave
side, which a program gets when it runs in a terminal, is accepted. A master the program opens
itself through a grant on `/dev/ptmx` belongs to a new pseudo-terminal, whose other side has no
process until one outside opens it as its terminal. The filter denies `TIOCSIG` on it as well;
the characters stay open there. The tests are
`a_pseudo_terminal_master_on_a_standard_stream_needs_signals_any` and
`a_master_of_another_devpts_instance_is_refused`.

### Other processes

`prlimit64`, `setpriority`, `ioprio_set`, `sched_setaffinity`, `sched_setscheduler`,
`sched_setparam` and `sched_setattr` can change other processes of the user: lower their resource
limits, priority or I/O priority, or pin them to one CPU. The denylist allows them only with
process ID 0 (the caller), and with `children = "none"` or `"contained"` also with the target's
own process ID, which it keeps from sandy after `execve`. With `children = "allowed"` a process
the program started can outlive it, and once another process of the user has that ID, the
exemption would cover it; there only 0 works. For `setpriority` and `ioprio_set` it also denies
the process group and user forms, because sandy's process group can contain processes outside the
sandbox.

These are system calls. The out-of-memory priority of a process is not set by a call but by a
write to `/proc/<pid>/oom_score_adj`, which the denylist cannot see. A policy with a write grant
on `/proc` therefore lets the program raise the out-of-memory priority of every process of the
user, and lower its own down to the value sandy inherited. sandy's own processes are out of
reach, because they are undumpable (see "Ending with the parent"); other processes of the user
are not. Grant `/proc` writable only to programs you would also run without a sandbox.

Costs: children of the program cannot use these calls on each other, and a thread ID other than
the one of the main thread counts as another process. For example,
`pthread_setaffinity_np` and `pthread_setschedparam` fail for threads other than the main
thread, and `nice` works only for the calling thread through ID 0.

## Diagnostic mode

`sandy run --explain` names the paths of a run that the policy does not grant. It is off by
default. Its reason, and why observing this way does not weaken the sandbox, are in
[DESIGN.md](DESIGN.md), "Diagnostic mode".

How it works:

1. sandy forks the program and stays its parent, as with `children = "contained"`. Only a
   parent may read the memory of its child where Yama restricts ptrace
   (`/proc/sys/kernel/yama/ptrace_scope` 1, the default on Debian and Ubuntu). As with
   `contained`, sandy then closes the descriptors it inherited from its caller
   (`sandy_closes_what_it_inherited_while_the_program_runs` in `tests/explain_linux.rs`).
2. The forked program installs the observer filter as its last step before `execve`. It returns
   `SECCOMP_RET_USER_NOTIF` for the watched calls and allows everything else. The kernel hands
   the installer a descriptor for the filter, which the program sends to sandy over a socket
   pair with `SCM_RIGHTS`.
3. A thread of sandy reads one notification per watched call, reads the path out of the calling
   process with `process_vm_readv`, resolves it against that process's current directory or the
   call's directory descriptor, and answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
4. When no rule of this run grants what the call needs, sandy writes one line to standard error
   with the path, the rule that comes closest and the policy grant that would allow it. Each
   path is named once, and a closing line counts what the watcher saw.

The watched calls are the ones that take a path and that Landlock can deny: `open`, `openat`,
`creat`, `execve`, `execveat`, `truncate`, `mkdir`, `mkdirat`, `unlink`, `unlinkat`, `rmdir`,
`mknod`, `mknodat`, `symlink` and `symlinkat` (x86_64; arm64 has only the `*at` forms). The
`stat` family, `statx`, `access`, `faccessat`, `readlink` and `chdir` pass a path to the kernel
but are not denied by any Landlock right (measured on Linux 7.2 in a domain that handles every
right and grants nothing), so watching them would only cost two context switches per call.

The verdict follows the order in which the kernel checks a call. A call that the kernel answers
before it asks Landlock is not named, because no grant changes that answer: a file to use or a
name to remove that does not exist (`ENOENT`), a name to add that exists already (`EEXIST`), an
empty path (`ENOENT`, except for `execveat` with `AT_EMPTY_PATH`, which executes its descriptor),
and an `O_PATH` open, which Landlock does not check at all. Neither does it check a file that
has no path of its own, such as the pipe that `/dev/stdin` leads to when standard input is a
pipe, so that is not named either. A right that adds or removes a name (create, remove,
symbolic link, device, named pipe, socket) is checked on the directory that holds the name, as
Landlock checks it, and a symbolic link at the end of such a path is not followed: removing a
link removes the link, not what it points to.

### What it cannot see

The mode reports less than the kernel denies, and a report that is read as complete is worse
than none. It does not see:

- **Calls another seccomp filter already denies.** The kernel takes the most restrictive answer
  of all filters, and an `errno` beats a notification, so the watcher is never told about them
  (measured). With `path_metadata = "deny"` that covers `chmod`, `chown` and `setxattr` by path;
  with `ip = "none"` or `unix_sockets = "none"` it covers `socket`; it also covers every call
  outside the reviewed table, which fails with `ENOSYS`.
- **Denials that are not about a path argument**: a signal the Landlock scope stops, a TCP bind
  or connect Landlock denies, and a connection to a pathname Unix socket (ABI 9), whose address
  is a `sockaddr` and not a path argument.
- **`rename`, `link` and their `*at` forms**, which take two paths. They are not watched at all.
- **What the kernel answered.** The verdict comes from sandy's own rules, not from the call's
  result, which the watcher never sees. It is the same rule set Landlock gets, compared against
  the path after symbolic links are resolved, so the two agree in the cases that matter; they
  can differ where a path reaches a granted directory by another route, for example through a
  bind mount, which the mode then names although the kernel allowed it. sandy also resolves
  symbolic links in its own process, so a link into `/proc/self`, such as `/dev/stdin` or
  `/dev/fd/3`, leads to sandy's descriptor with that number and not the program's. For the
  standard streams the program inherited they are the same file; for any other they can differ.
- **A path the watcher could not read**, because the process ended first or the host forbids
  reading another process's memory (`ptrace_scope` 2 or 3). The closing line counts these.
- **A process that outlives sandy.** The watcher ends with sandy, and the watched calls of such
  a process then fail with `ENOSYS`; it stays confined. That is also what a `SIGKILL` to sandy
  leaves behind. Do not use `--explain` for a program that daemonizes.
- **More than 1000 paths.** The program decides how many paths it uses, and the watcher keeps
  every path it named so that it names it only once. After 1000 it names no more, and the
  closing line says so.

The program can also change the path between the watcher's read and the call, or create and
remove files in between, which makes the report name a path the kernel never saw or leave out
one it denied. That is a wrong report, not a weaker sandbox: see DESIGN.md.

### Cost and other effects

- Two context switches per watched call. Measured on Fedora 44: a run with about 4900 watched
  calls took 0.11 to 0.24 seconds instead of 0.03, roughly 25 microseconds per call.
- A watched call waits for the watcher in a state that a signal interrupts. When the program
  handles that signal without `SA_RESTART`, the call fails with `EINTR` where it would otherwise
  have completed, also an `open` of a local file, which programs rarely retry. Measured on Linux
  7.2: 420 to 550 of 20000 opens with a 200 microsecond interval timer, none without the mode.
  `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (Linux 5.19) would only narrow this, to 93 of 20000,
  because a signal that comes before the watcher has taken the call still interrupts it, and it
  would let nothing but SIGKILL reach a program whose call the watcher holds; sandy does not use
  it. Programs that retry on `EINTR`, as the Go runtime does, are not affected.
- sandy stays the program's parent, so the caller's process ID is sandy's and not the program's
  (as with `contained`; `--status-fd` reports the program's). sandy blocks the signals it can
  wait for, waits with `sigwaitinfo` and passes each one on to the program, so a caller that
  signals sandy's process ID reaches the program, with these exceptions:
  - `SIGINT` and `SIGQUIT` are ignored while the program runs, as `system(3)` does. The terminal
    sends Ctrl+C and Ctrl+\ to the program as well, and a sandy that ended first would leave a
    program that cleans up after them with `ENOSYS` for every watched call. Sent to sandy alone,
    they do not reach the program.
  - `SIGTSTP`, `SIGTTIN`, `SIGTTOU` and `SIGCONT` keep their default actions, so the terminal
    stops and continues sandy together with the program and a shell sees the job stop.
  - A signal the kernel sent for the terminal or the process group (`si_code` `SI_KERNEL`, such
    as `SIGHUP` on a hangup or `SIGWINCH`) reached the program as well and is not passed on a
    second time (measured: a window resize arrives at sandy with `SI_KERNEL`, a `kill` with
    `SI_USER`).
  - A signal sent with `kill` to the whole process group reaches both processes and cannot be
    told from one sent to sandy alone, so the program receives it twice.

  `SIGKILL` and `SIGSTOP` cannot be caught. `SIGKILL` ends sandy alone: the program keeps
  running, confined as before, and its watched calls fail with `ENOSYS`. That is why
  `--explain` with `process.end_with_parent`, whose watcher ends a program that outlasts
  `SIGTERM` with `SIGKILL`, is refused unless `children = "contained"` supervises the run.
- The watcher is a thread of sandy, outside the sandbox, which parses bytes the program
  controls. It reads at most one path of `PATH_MAX` bytes per call and acts on none of them.
  Once it holds the notification descriptor, it confines itself with a seccomp filter on that
  thread alone (`filter::explain_watcher`): polling, the three notification ioctls on that
  descriptor only, `process_vm_readv`, the `stat`, `access` and `readlink` family, writes to
  standard error only, memory calls without `PROT_EXEC`, futexes and ending. Any other call ends
  sandy with `SIGSYS`, because a watcher that went on after a denied call would report what it
  did not see; the program keeps its sandbox, and its watched calls fail with `ENOSYS` from then
  on. The filter keeps the thread from opening files, starting processes, signalling, using the
  network and making code of its own. It shares its memory with sandy's main thread, which has
  no filter, so a flaw in the parsing that gives control of the thread could still reach that
  thread's code: the filter narrows the watcher, it does not wall it off. The test is
  `the_watcher_thread_confines_itself`; measured: bash, Python, git, curl, Java, Node, Go and
  coreutils ran under `--explain` with the filter in the glibc and musl builds.
- The report goes to sandy's standard error, which is usually the program's as well. A reader
  that goes away does not end the run: sandy ignores `SIGPIPE` (the program gets the default
  action back before it confines itself), and a line that cannot be written is dropped.
  Without that, sandy would die and the program would lose its watcher.
- A run with `--explain` is otherwise the same run: the Landlock ruleset and the other filters
  are built exactly as without it.

### What `check --explain-path` answers

`sandy check --explain-path PATH` needs no run and no kernel feature. It prints, for each path,
the deepest rule of the policy that covers it and what that rule allows, or that no rule covers
it. The rules are the ones the run would give Landlock, including the minimal system set and
the program's loader, so the answer is about this host and this policy.

### Landlock's own audit records

Linux 6.15 and newer let Landlock report its denials to the audit subsystem, which is the one
source that knows what the kernel really answered. Measured on Fedora 44 with kernel 7.2 and
`auditd` running: a denial produces `LANDLOCK_ACCESS domain=... blockers=fs.read_file
path="/etc/hostname" dev="dm-0" ino=218832`, next to a `LANDLOCK_DOMAIN` record that ties the
domain to the process that created it. sandy does not use these records, because reading them
needs rights sandy must not require: `CAP_AUDIT_READ` for the audit multicast group, root for
`/var/log/audit/audit.log` and `ausearch`, or membership in a group the journal is readable for
(`adm`, `wheel` or `systemd-journal` on Fedora; `journalctl -t audit` showed the records for a
user in `wheel`, and `dmesg` refused with `dmesg_restrict=1`). Where those rights exist, the
audit log is the better source and it costs the run nothing.

## Minimal system set

`system = "minimal"` adds these paths when they exist. sandy resolves symbolic links first, so
`/lib` on a merged-`/usr` system becomes `/usr/lib`. Nothing in the set holds user data. Only
`/dev/null` is writable.

| Path | Access | When | Reason |
|---|---|---|---|
| `/usr/lib`, `/usr/lib64`, `/lib`, `/lib64` | read | always | Shared libraries, gconv modules and the locale archive. A library is mapped with `PROT_EXEC` after a normal read open, which Landlock does not check as execute. |
| `/lib64/ld-linux-x86-64.so.2`, `/lib/ld-musl-x86_64.so.1` (arm64: `/lib/ld-linux-aarch64.so.1`, `/lib/ld-musl-aarch64.so.1`) | read, execute | always | The kernel opens the dynamic loader of a program for execution during `execve`. Only the loader file is executable, not the library directories. |
| `/etc/ld.so.cache` | read | always | The library search cache of the glibc loader. |
| `/etc/ld.so.preload` | read | always | The system-wide preload list. Without it the program would start differently than outside the sandbox. |
| `/etc/ld-musl-x86_64.path` (arm64: `-aarch64`) | read | always | The library path of the musl loader. |
| `/etc/localtime`, `/usr/share/zoneinfo` | read | always | Time zone data. |
| `/etc/ssl/openssl.cnf`, `/etc/pki/tls/openssl.cnf`, `/etc/pki/tls/openssl.d`, `/etc/crypto-policies/back-ends`, `/usr/share/crypto-policies`, `/etc/ssl/openssl.conf.d`, `/var/lib/crypto-config/profiles/current/openssl.conf.d` | read | always | OpenSSL configuration and the system crypto policy it includes on Fedora and RHEL (the back-ends are symbolic links into `/usr/share/crypto-policies`, and Landlock checks the target), and the two directories the configuration of Ubuntu 25.10 includes, when they exist. OpenSSL drops an include it cannot read without an error and then runs with weaker built-in defaults; Node.js does not start when the configuration exists but cannot be read. |
| `/dev/null` | read, write | always | Programs redirect output to it. Writes are discarded. No ioctl right. |
| `/dev/zero`, `/dev/random`, `/dev/urandom` | read | always | Zero and random sources for programs that do not use `getrandom`. |
| `/sys/devices/system/cpu/online`, `/sys/devices/system/cpu/possible` | read | always | The number of CPUs for glibc, Go and Java. |
| `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf`, `/etc/host.conf`, `/etc/gai.conf`, `/etc/services`, `/etc/protocols` | read | `ip` other than `"none"` | Name resolution. When `/etc/resolv.conf` leads into `/run/systemd/resolve`, sandy grants that directory instead of the file (see "Replaced resolver files"). |
| `/etc/ssl/certs`, `/usr/share/ca-certificates`, `/etc/pki/tls/certs`, `/etc/pki/ca-trust/extracted`, `/etc/ca-certificates/extracted`, `/var/lib/ca-certificates` | read | `ip` other than `"none"` | CA certificates for TLS on Debian, Ubuntu, Fedora, RHEL, Arch and openSUSE. |
| the loader of the program itself | read, execute | always | The file the program names in its ELF `PT_INTERP` header, with symbolic links resolved, when no other rule covers it. The entries above name the loaders of the FHS layout; this covers a host with another libc, another name, or a layout outside the FHS (NixOS, Guix). |

The loader of the program is read from the program file, which is untrusted input, so sandy
grants it only under `/usr`, `/lib`, `/lib64`, `/nix/store` and `/gnu/store`: the locations that
belong to root and hold the loaders of the FHS layout and of the two package stores that do not
follow it. It is never granted inside a writable path, where the program could replace what it
executes; that comparison is the one of "Links and the mount table", so a writable path that
names an alias of the loader's directory counts too. Every other loader is refused instead (see
"Refusals"), so a program that names its own loader cannot gain execute on a file no policy
rule covers.

Left out on purpose:

- `/proc` (see below), `/tmp`, `/dev/shm`, `/run` (apart from systemd-resolved's directory),
  `/var`, `/home`.
- `/dev/tty` and `/dev/pts`: a program whose standard streams are redirected could otherwise open
  the terminal of the user.
- `/etc/passwd` and `/etc/group`: not needed to start, and they list the accounts of the host.
  `ls -l` shows numeric owners, and `getpwuid` finds nothing (see below).
- `/usr/bin` and other program directories: the program file is executable by rule 5 of
  [DESIGN.md](DESIGN.md).
  A program that starts other programs needs `--read-exec` for them.
- `/usr/local/lib`: add it to the policy if a program needs libraries from there.

Distributions outside the FHS layout (for example NixOS) need the store paths of the program's
libraries in the policy; only its loader is covered.

### Replaced resolver files

A Landlock rule binds the file that existed when sandy started. When the system later writes a
new file and renames it over the old one, a running program cannot read the new file. For the
resolver configuration this ends name resolution: glibc and musl treat an unreadable
`/etc/resolv.conf` like a missing one and ask the default name server, 127.0.0.1, where nothing
answers on a host whose resolver listens elsewhere. Measured on Ubuntu 22.04 with
systemd-resolved, replacing `stub-resolv.conf` by rename in a private mount namespace while a
program resolved names: musl failed with `EAI_AGAIN` after its 5 second timeout, glibc (Python
3.10) failed at once, and neither recovered after the file was replaced once more.

systemd-resolved, which `/etc/resolv.conf` leads to on Fedora, Ubuntu and other current
distributions, writes `stub-resolv.conf` and `resolv.conf` in `/run/systemd/resolve` this way. On
the Fedora 44 test host, `resolv.conf` had been replaced after a change of the network, while
`stub-resolv.conf`, whose content had not changed, was still the file from boot. The stub file
lists the search domains, so it is replaced when they change, for example when a VPN or another
network brings its own. When `/etc/resolv.conf` leads into this directory, sandy therefore grants
the directory, read-only, instead of the file. The test is
`a_resolver_file_replaced_by_rename_stays_readable`. Besides the two resolver files the directory
holds:

- The resolver's Unix sockets, `io.systemd.Resolve` and `io.systemd.Resolve.Monitor`. A read
  right does not connect to a socket. With `unix_sockets = "none"` the filter denies `AF_UNIX`
  sockets, and from ABI 9 Landlock also denies connecting to a socket file; with `"all"` every
  socket of the user is reachable anyway, these two included.
- `netif`, the settings of each network link, which only the resolver's own user and root may
  open (mode 0700). sandy refuses to run as root.

Every other layout keeps the rule on the file, so there a program that runs across such a
replacement loses name resolution until it restarts:

- A plain file `/etc/resolv.conf`. Its directory is `/etc`.
- `/run/NetworkManager/resolv.conf`. The directory also holds NetworkManager's state for each
  device, readable by every user, with DHCP client identifiers derived from hardware addresses.
- `/run/resolvconf/resolv.conf` (resolvconf) and `/run/netconfig/resolv.conf` (SUSE netconfig).
  No test host has them, so what else these directories hold has not been checked.
- `/etc/hosts`, `/etc/nsswitch.conf` and the other files of the row. They lie in `/etc`, or in
  `/etc/authselect` on Fedora, which also holds the PAM configuration, and they change when an
  administrator edits them rather than with the network.

### What the set does not cover

Three things work outside the sandbox and behave differently inside it without the program
noticing. sandy reports the first two in `sandy check`, as `warning:` lines on standard error
that change neither what it enforces nor the exit status.

- **OpenSSL includes.** The set covers the configuration and the crypto policy files of Fedora and
  RHEL, and the directories that Ubuntu 25.10 includes. An administrator can include files from
  anywhere, and OpenSSL drops an include it cannot read without an error, so the program then runs
  with weaker built-in defaults: measured on Fedora with only `openssl.cnf` readable,
  `openssl ciphers -s -tls1_2` silently gained two CBC suites and lost the CCM suites. sandy
  reads the `.include` lines of the configuration files of the set, follows them, and names every
  target the policy does not cover, in every policy and not only with `ip = "all"`, because the
  configuration is read for local cryptography as well. It grants nothing on its own: the
  targets are chosen by the host, not by sandy. The test is
  `unreadable_openssl_includes_are_reported`.
- **cgroup limits.** `/proc` and `/sys/fs/cgroup` are not in the set, so a program cannot find
  the memory and CPU limits of its cgroup and sizes its heap and its thread pool from the whole
  host instead: measured in a 512 MB scope, a JVM reports "No metrics available for this
  platform" and a 16 GB maximum heap, against 512 MB outside, which ends in an out-of-memory
  kill. Resource limits are a non-goal (see [DESIGN.md](DESIGN.md)), so sandy sets none and
  removes none. When sandy itself runs under a limit, `sandy check` names it and suggests
  `--set-env GOMAXPROCS=N` or `--set-env JAVA_TOOL_OPTIONS=...`; it never sets them itself,
  because the policy decides the environment of the program. Granting `--read /proc` is not
  enough; a program needs the files under `/sys/fs/cgroup` too. The test is
  `a_cgroup_limit_is_invisible_and_reported`.
- **Accounts.** `getpwuid` and `getgrgid` find nothing without `/etc/passwd` and `/etc/group`,
  so a program that asks for the name, home directory or shell of its user gets an error
  (measured: Python's `pwd.getpwuid` raises `KeyError`, and glibc reports `EACCES`). Add
  `--read /etc/passwd`, and `--read /etc/group` for groups, when a program needs them;
  `/etc/nsswitch.conf` is not needed, because glibc falls back to the files back end. The set
  never gets them: they are user data, and on a multi-user host they list every account. The
  test is `the_user_account_needs_a_grant_for_etc_passwd`.

### /proc

`/proc` is not in the set. Landlock rules bind to inodes, and `/proc/self` resolves to the
directory of one process ID, so a rule cannot give each process only its own entry: a child of
the program gets `EACCES`. A policy can add `--read /proc`. The program can then read
`/proc/<pid>/cmdline`, `status` and `stat` of every process of the host, which can contain
secrets passed on command lines, and `/proc/net` of the network namespace. `/proc/<pid>/mem` and
`environ` of processes outside the sandbox stay denied by the Landlock ptrace check (tested).

With `filesystem.view = "policy"`, `/proc` holds only the granted paths, bound read-only (see "File
system view").

Without `/proc`, the program cannot read `/proc/self/maps`, `status`, `fd`, `cgroup` and
`mountinfo`, which costs it `pthread_getattr_np` on the main thread, loops that close every open
descriptor, and the cgroup limits (see "What the set does not cover").
`readlink("/proc/self/exe")` still works, because `readlink` is not a Landlock right, so
`std::env::current_exe` and everything built on it keeps working (measured; the test is
`the_programs_own_path_is_readable_without_proc`). Common runtimes (glibc, Rust, Python, Go,
Java, Node.js) still start.

## Trusted user locations

Rule 12 of [DESIGN.md](DESIGN.md): a writable policy path may not reach a location of this user
that other programs read or execute later. Landlock rules are allow-only and apply to a whole
tree, so a writable home directory cannot leave out the shell startup file in it; refusing the
policy is the only way to keep what it promises. The locations every Unix has are in
`sandy_core::trust`, the same list as on macOS; those of Linux alone are in `trust::locations`:

| Location | Protected | Why |
|---|---|---|
| the home directory | itself | holds the files below; a writable path below it stays allowed |
| `.bashrc`, `.bash_profile`, `.bash_login`, `.bash_logout`, `.profile`, `.zshenv`, `.zprofile`, `.zshrc`, `.zlogin`, `.zlogout` | the file | every shell of this user reads them at its start |
| `.bash_aliases` | the file | Debian's `.bashrc` sources it |
| `.bashrc.d` | the tree | Fedora's `.bashrc` sources every file in it |
| `<config>/fish` | the tree | the startup files of the fish shell |
| `.gitconfig`, `<config>/git` | the file, the tree | `core.fsmonitor`, `core.sshCommand`, `core.pager` and `!` aliases run commands at the next git command |
| `.cargo/config.toml`, `.cargo/config`, and both in `CARGO_HOME` | the file | `build.rustc`, `build.rustc-wrapper` and target runners name programs that the next cargo command runs |
| `.ssh` | the tree | `ProxyCommand` and `LocalCommand` in the configuration run programs, and `authorized_keys` admits logins |
| `.gnupg` | the tree | `pinentry-program` and `photo-viewer` name programs that gpg runs |
| `.pam_environment`, `.xprofile`, `.xinitrc`, `.xsession`, `.xsessionrc` | the file | read when a session starts (Linux) |
| `<config>/autostart` | the tree | desktop entries that run at the next login (Linux) |
| `<config>/systemd`, `<data>/systemd` | the tree | systemd user units, which the program can enable with a link of its own (Linux) |
| `<config>/environment.d` | the tree | variables for every program of the session (Linux) |
| `<config>/plasma-workspace/env`, `<config>/plasma-workspace/shutdown` | the tree | KDE Plasma sources the scripts in `env` at login and runs those in `shutdown` at logout (Linux) |
| `<config>/autostart-scripts` | the tree | KDE Plasma runs the scripts in it at login (Linux) |
| `<data>/applications` | the tree | desktop entries that say which program opens a file (Linux) |

`<config>` is `XDG_CONFIG_HOME` and `~/.config`, `<data>` is `XDG_DATA_HOME` and
`~/.local/share`; both spellings count, because the variables are not set for every program that
starts sandy, and the same holds for `CARGO_HOME` and `~/.cargo`. So `--read-write ~/.cargo` is
refused; a program that downloads crates needs `~/.cargo/registry` and `~/.cargo/git`. A
location that does not exist counts, because the program could create it, and each counts where
it lies and where its symbolic links lead.

The home directory comes from the password database (`getpwuid_r`) and from `HOME`, for the
same reason. When neither names one, or the password database cannot be read, sandy cannot tell
whether a writable path reaches these locations, so a policy with a writable path is undecided
and `check` and `run` fail with status 125, as when sandy cannot read the mount table; a policy
without one is not affected. This happens with the static release build, which
reads only `/etc/passwd`, for a user that only SSSD, LDAP or systemd-homed knows, started
without `HOME`. The message says to start sandy with `HOME` set to the home directory.

Every absolute directory on sandy's `PATH` is such a location too, and so are the directories
the usual shell setups put on the user's `PATH`, whether or not sandy's own `PATH` holds them:
`~/.local/bin`, `~/bin`, `bin` in `CARGO_HOME` and in `~/.cargo`, `/usr/local/bin` and
`/usr/local/sbin` (`trust::path_locations`). A service or a desktop application that
starts sandy passes a shorter `PATH` than the user's shell has, and the escape works through the
shell's. Rule 12 warns about these directories instead of refusing them, because a writable path
that holds one is ordinary work: `--read-write ~/tools` with `~/tools/bin` on `PATH`, or
`--read-write /usr/local`. `sandy check` exits 0 and prints a `warning:` line on standard error
that names the writable path and the directory (`plan::notes`). What removes the risk is a
policy that keeps the directory out of every writable path, by granting only the subdirectories
the program needs; starting sandy with another `PATH` silences the warning for a directory that
is not one of the usual ones, and leaves the risk. A directory below one of them is on no `PATH`
and says nothing, and a writable path that reaches a refused location as well stays refused.

The list is a heuristic and can never be complete: no list knows which files the programs of
this user trust. It also does not see a hard link that already gives one of these files a second
name inside a writable path.

sandy does not check the loader variables of its own environment (`LD_PRELOAD`, `LD_AUDIT`,
`LD_LIBRARY_PATH`). A dynamically linked sandy loads what they name before it confines itself,
so a caller that points them into a writable path runs that code as sandy, with no sandbox. The
release binaries are statically linked against musl and ignore the variables; a build from
source is dynamic by default.

## Links and the mount table

Landlock binds a rule to the inode behind a path when sandy starts, and it checks the path a
call uses. One file under two names, or one directory under two paths, would otherwise get the
rights of both, so the resolver compares files before it builds the rules.

- **Bind mounts.** sandy reads `/proc/self/mountinfo` and works out where each path lies inside
  its file system: the root of the mount that holds it plus the rest of the path, together with
  the device. A bind mount of a subdirectory of a writable path, given as `read_exec`, is
  refused this way. Comparing the identity of the path and of its parent directories does not
  see that case, because such an alias has no parent directory in common with the writable path.
  sandy refuses the policy when it cannot read the table. Nothing is lost by that: sandy needs
  `/proc` before Landlock anyway, to check that it is single-threaded. Each btrfs subvolume has
  its own device number, so two subvolumes are compared as two file systems, as the kernel
  reports them. sandy picks the mount by the longest mount point that is a prefix of the path
  and lies on the same file system; a mount that a later mount over one of its parents hides is
  the one case where that can pick the wrong one.
- **Hard links.** `read_exec` files, the program file, sandy's own executable and the policy
  file must have no second name inside a writable path. sandy checks `st_nlink` first and then
  walks the writable trees, which costs one `lstat` per file there; it walks the `read_exec`
  trees only when the writable trees hold a file with more than one name, which is rare. A
  directory the user may not list is skipped: the program runs as the same user and cannot list
  it either.
- A file outside the policy that has a second name inside a writable path stays writable through
  that name, and two names that a passthrough FUSE mount shows for one file have different
  identities and stay unseen. See "Links and file identity" in [DESIGN.md](DESIGN.md).

## Refusals

`sandy check` shows the reason for each requirement it cannot enforce, in one of three kinds:

- `UNAVAILABLE`: a lasting shortfall of the host. `check` exits with status 1, or 2 when only
  `sandy setup` is missing.
- `CONFLICT`: the policy contradicts the layout of this host, for example with a writable path
  over the minimal system set.
- `UNDECIDED`: a probe failed for a reason that can pass, such as a full process or descriptor
  table, so sandy cannot tell now.

The last two end `check` and `run` with status 125, because every fallback level of a policy has
the same paths and program, and a passing failure says nothing about the host: neither may make
sandy try a weaker level. A policy that breaks one of the path rules is refused before that, with
exit code 125 and the paths it compared.

- No Landlock: FilesystemConfined, ProcessMemoryIsolated and SignalsIsolated are unavailable.
- No seccomp filter support, or a CPU architecture other than x86_64 and arm64: every requirement
  that uses the filter is unavailable.
- Running as root (real, effective or saved user ID 0), or with any effective, permitted or
  ambient capability: NoPrivilegeEscalation is unavailable. no_new_privs removes nothing that is
  already held, and Landlock does not restrict `chmod`, so root could, for example, set the
  setuid bit on a shell.
- A writable policy path that overlaps the minimal system set, with `system = "minimal"`:
  FilesystemConfined is a conflict. The path contains an entry of the set, or lies inside one of
  its directories. Entries that do not exist on this host count too (their location with the
  symbolic links of the existing part resolved), because the program could create them, for
  example `/etc/ld.so.preload`. A symbolic link counts where it is and where it points, also when
  its target is missing, as `/etc/resolv.conf` can be before the resolver starts. Only
  `/dev/null` is exempt. Otherwise the program could change the
  dynamic loader, shared libraries, the loader configuration or files such as `/etc/hosts`, which
  the next start and programs outside the sandbox use. File permissions usually forbid this
  anyway, because these files belong to root and sandy refuses to run as root; the check keeps
  the guarantee independent of them. Paths are compared as in "Links and the mount table", so a
  bind alias of a directory of the set is refused like the directory itself. When sandy cannot
  read the mount table, FilesystemConfined is undecided, and unavailable only where there is no
  `/proc` at all; the same holds for the thread list `/proc/self/task`.
- A writable policy path that overlaps a trusted user location, whatever the system access:
  FilesystemConfined is a conflict. The locations are in "Trusted user locations" above; a
  directory on `PATH` warns there instead.
- A writable policy path while neither `HOME` nor the password database names the home
  directory, or the database cannot be read: FilesystemConfined is undecided, because sandy
  cannot check the locations below it. Setting `HOME` fixes it.
- `children = "contained"` while sandy itself runs in a sandbox that denies `setpgid`:
  ChildProcessesContained is unavailable. The program runs in a process group of its own, and
  sandy's own filter denies `setpgid` inside `contained`, so one contained sandbox cannot hold
  another. sandy probes this by joining the process group it is already in, which changes
  nothing. A session leader cannot change its own group whatever a filter allows, so sandy skips
  the probe then; the group is led by the guard, which is no session leader.
- A program whose loader no `read_exec` path and no entry of the minimal system set covers:
  FilesystemConfined is a conflict. The kernel opens the loader of the program's ELF
  `PT_INTERP` header for execution during `execve`, so it needs an execute right of its own.
  Without the check, `execve` would fail with "Permission denied" after the sandbox is in place.
  It happens with `system = "none"` and no `read_exec` path for the loader, and on a host whose
  loader lies outside the locations above. The fix is in the message: `--read-exec` for the
  loader. A statically linked program and a script have no loader; a script's interpreter is
  checked by the rule below.
- A program that is a script whose interpreter no `read_exec` path covers: FilesystemConfined is
  a conflict. The kernel reads the `#!` line and executes the interpreter, which needs execute
  access of its own, so `sandy check` reads that line too and follows up to four levels of it.
  Without the check, `execve` would fail with "Permission denied" after the sandbox is in place.
  The minimal system set grants execute on the dynamic loader, so a chain that ends there is
  covered.
- `ip = "private"` where user namespaces are disabled (`user.max_user_namespaces` or
  `kernel.unprivileged_userns_clone` 0), or where the kernel refuses a trial of the namespaces
  for good, for example inside another sandbox: IpNetworkPrivate is unavailable. A trial that
  fails for a reason that can pass leaves it undecided (see "Detection" of "Private network").
  Under Ubuntu's AppArmor restriction of unprivileged user namespaces it needs setup, and
  `sandy check` exits with status 2 (see "Private network" and "Setup on Ubuntu").
  EgressBrokered follows it, because the broker serves a listener in that namespace. When the
  kernel does not answer a route lookup and an address dump over a `NETLINK_ROUTE` socket, which
  `check` tries and `run` asks before it starts the broker, `check` fails with status 125.
- `filesystem.view = "policy"` in the same cases, and on a kernel that does not report the fix of
  Landlock erratum 3: PathsHidden is unavailable, or needs setup under the AppArmor restriction.
  With the view, `sandy run` also refuses a directory on a standard stream, with exit code 125
  (see "File system view").
- A listening address of a relay that another process holds: `sandy check` binds the same
  addresses for a moment and releases them again, and fails with status 125 when one is taken,
  as `run` does. Any local user can hold a port, so a busy one says nothing about the host. The
  answer can be stale one moment later; `run` binds for real and stays the authoritative answer.
- A standard stream that carries a socket the policy denies: `sandy run` refuses with exit code 125
  and names the stream and the socket. Such a socket was created before the sandbox, so neither
  Landlock nor the filter takes its access away: an unconnected UDP socket on standard input
  delivered a datagram to a listener outside under `ip = "none"`, a listening TCP socket on
  standard input took a connection from outside with `unix_sockets = "all"`, which leaves `accept`
  allowed, and a `NETLINK_SOCK_DIAG` socket on standard input listed the TCP sockets of the host
  under `ip = "all"`, although the program's own `socket` for one fails with `EAFNOSUPPORT` (all
  measured on Linux 7.2). sandy accepts a socket only when the program could create one like it:
  the socket family filter allows its family and protocol, and creating it needs no capability,
  because sandy never starts the program with one. sandy reads the family, the type and the
  protocol with `SO_DOMAIN`, `SO_TYPE` and `SO_PROTOCOL`. Refused are an IP socket or a route
  netlink socket with `ip = "none"` and with `ip = "private"`, where such a socket belongs to the
  host's network and not the sandbox's (`an_inherited_ip_socket_is_refused`), a listening or
  datagram IP socket with `ip = "client"` (a connected TCP socket is accepted), an unconnected, datagram or listening Unix socket with
  `unix_sockets = "none"`, and under every policy a raw IP socket (`SOCK_RAW`, which needs
  `CAP_NET_RAW`), an IP socket of a protocol the filter denies (see "Denylist"), and a socket of
  every other family, a netlink socket of another protocol included. The kernel turns an `AF_INET`
  socket of the obsolete type `SOCK_PACKET` into an `AF_PACKET` socket, which is refused as another
  family. An ICMP datagram socket follows `ip` like any IP datagram socket, because the kernel lets
  an unprivileged program create one within `net.ipv4.ping_group_range`. A connected Unix stream or
  seqpacket socket is accepted, because it reaches only the peer it already has. `sandy check`
  cannot report this: the streams it is given are not the streams of the later `run`. The tests are
  `a_socket_on_standard_input_gives_no_network_access`,
  `a_socket_of_another_family_on_standard_input_is_refused` (sock_diag netlink, AF_VSOCK and
  AF_ALG), `route_netlink_on_standard_input_follows_ip` and
  `a_raw_ip_socket_on_standard_input_is_refused`, which creates the raw socket in a user and
  network namespace of its own, where it holds `CAP_NET_RAW`, and executes sandy from there.
- With `signals = "isolated"`, a standard stream that carries the master side of a
  pseudo-terminal: `sandy run` refuses with exit code 125 and names the stream. The program could
  write the interrupt character into it and so signal the processes on the other side (see
  "Signals and the terminal").

## Known limitations

- **Paths outside the policy are visible** with the default `filesystem.view = "all"`. `stat`,
  `access`, `readlink` and `inotify` watches work on every path the user can reach. The program
  can learn which files exist, their sizes and times, and when other programs touch them. It
  cannot open them: `open_by_handle_at` needs a capability. Landlock has no right for these calls,
  and seccomp cannot read the path a call names, so only a mount namespace hides them:
  `filesystem.view = "policy"` does (see "File system view"), where user namespaces work. Two
  details are easy to miss:
  - An `inotify` watch on a directory the program cannot list reports the **names** of the
    entries that appear in it, not only that something changed (tested:
    `inotify_reports_names_in_unlistable_directories` reads the name of a file that another
    process creates in a directory outside the policy). A program that watches a directory of
    the user therefore learns its new file names.
  - A directory that the caller passes as standard input, output or error stays listable
    (`a_directory_on_standard_input_stays_listable`). Landlock checks the directory right when a
    path is opened, and such a descriptor was opened before the sandbox. The entries in it
    cannot be opened; only their names are readable. Pass a directory on a standard stream only
    when its listing may be seen.
  The reads of extended attributes by path, `fanotify_init` and `name_to_handle_at` are denied
  (see "Metadata" and "Denylist").
- **Abstract socket names with `ip = "all"` or `ip = "client"`.** The program can bind one end
  of a socket pair to a free abstract name, because the filter cannot tell a socket's family
  from its descriptor and the Landlock scope checks connect and send, not bind. A service outside
  that binds the same name later then fails to start. With `unix_sockets = "none"` that is all it
  can do: the pair is a stream or seqpacket pair, which is connected already and cannot listen,
  so a client that reaches the name gets a refused connection. With `unix_sockets = "all"` the
  program can take the name of a service and serve it: a datagram pair end that binds the name
  and then disconnects with `connect(AF_UNSPEC)` receives what clients send to it (measured on
  Linux 7.2), and an ordinary AF_UNIX socket can listen, except under `ip = "client"`. With
  `ip = "none"` and `unix_sockets = "none"` the filter denies `bind`, `listen`, `connect` and
  `accept`, which no socket pair needs. With `ip = "private"` the abstract names are the
  sandbox's own, because they belong to its network namespace, so the program can take none of
  the host's.
- **System information.** `uname`, `sysinfo` and `statfs` stay allowed. They show the kernel
  version, load and memory, and file system statistics. The mount and namespace listing calls,
  the security module calls (`lsm_list_modules`, `lsm_get_self_attr`, `lsm_set_self_attr`) and
  `PIDFD_GET_INFO` are denied, like the `/proc` and `/sys` files that hold the same facts. What
  stays: a pidfd of any process says when it ends, which Python's asyncio and Go need for their
  own children, and `stat` on `/proc/PID` shows the owner of a process.
- **Metadata through open files.** `fchmod` and `futimens` work on every file the program may
  open, also on a descriptor of a file or a directory in a `read` path, except for setuid and
  setgid bits; with `path_metadata = "allow"` so do `fchown`, `fsetxattr` and `fremovexattr`.
  The program can, for example, make a file or a directory of a `read` path that this user owns
  writable for other local users, or unreadable. seccomp sees only the descriptor number, not
  how the file was opened, Landlock has no metadata right, and `cp -p`, `touch`, Rust's
  `fs::copy`, Java's `Files.copy` and Node.js's `copyFileSync` call them on the files they write
  (measured on Fedora 44), so the only remaining fix is a helper outside the sandbox that
  performs these calls after checking the descriptor.
  The file system ioctls of the same kind are denied (see "Metadata"). This is an exception of
  `MetadataConfined` (DESIGN.md, "Requirements and the enforcement plan"): `sandy check` warns
  about it when the policy has a `read` or `read_exec` path, keeps `path_metadata = "deny"` and
  keeps the default view. The test `a_read_only_descriptor_changes_only_the_mode_and_the_times`
  records it. With `filesystem.view = "policy"` these paths are read-only mounts, where both calls
  fail with `EROFS`, so the exception does not apply there (see "File system view").
- **Files the program writes can be executed outside the sandbox.** The program gets no execute
  right in a writable path, but a file it writes keeps the mode it gives it: the filter strips
  only the setuid and setgid bits, and Landlock has no right over the execute bit. A process
  outside the sandbox can run such a file. The trusted-location check keeps the writable paths
  out of the places where other programs run or read files on their own (see "Trusted user
  locations"); whether a user runs a file from a writable path stays the user's decision.
- **Locks on readable files.** `flock` and POSIX and open file description locks need only a
  read descriptor, and seccomp cannot tell a descriptor's access mode. Through a descriptor of a
  file it may only read, the program can hold an exclusive `flock` or a shared POSIX lock, and a
  process outside that locks the same file then waits or fails: a writer, and with `flock` a
  reader as well (measured on Linux 7.2: with the program's lock held, `flock` and the POSIX and
  open file description write locks of a process outside failed with `EAGAIN`). That is all a
  lock does. The locks are advisory, so the program cannot read or change anything through one,
  and a process that takes no lock reads and writes the file as before (measured too); a POSIX
  write lock needs a descriptor opened for writing (`EBADF`). The locks stay allowed because
  SQLite takes them on every database it reads, and Java takes them through `FileChannel.lock`.
  Leases and delegations, which stall outside writers for a fixed time without any cooperation,
  are denied (see "Denylist"). The test `a_lock_on_a_readable_file_holds_off_other_processes`
  records this.
- **Signals.** With `signals = "any"` the program can kill other processes of the user. With
  `"isolated"` its own reads from the terminal still stop its own process group, which is the
  behaviour of any background job. Below Landlock ABI 6, `"isolated"` needs `children =
  "contained"` and a PID namespace (see "A PID namespace").
- **Processes that outlive the program.** With `process.children = "allowed"` (the default) a
  process the program starts can outlive it. `none` and `contained` prevent this for processes the
  program starts itself or through its children. Both need `unix_sockets = "none"`, because
  through a Unix socket the program could ask a service of the user, for example the systemd user
  manager over D-Bus, to start a process outside the sandbox. A service that starts processes on
  requests over TCP is still reachable with `ip = "client"`, `ip = "all"` or through a `forward`
  target; such processes are not the program's and are not covered.
- **Standard streams.** sandy passes descriptors 0, 1 and 2 on as it got them, so whatever they
  carry keeps working inside the sandbox: a file outside the policy can be read and written, a
  directory stays listable, and its mode and times can change (see "Metadata through open
  files"). A socket the policy denies is refused at the start instead, and so is a
  pseudo-terminal master with `signals = "isolated"` (see "Refusals"). A
  connected Unix stream or seqpacket socket is accepted, and the program then reaches whatever
  its peer is, so pass one only from a process that is the peer itself.
- **The terminal.** If standard input or output is the user's terminal, the program can read
  input, write escape sequences and change terminal modes. `TIOCSTI`, `TIOCLINUX`, `TIOCSETD`,
  `TIOCEXCL` and the console ioctls that change a virtual console are always denied, and with
  `signals = "isolated"` also `TIOCSPGRP`, `TIOCSWINSZ` and `TIOCSIG`. Some terminal emulators
  act on escape sequences, for example by setting the clipboard (OSC 52), and the filter cannot
  tell them from other writes. Give a program that is not trusted with the terminal a pipe or a
  file instead (DESIGN.md, "Non-goals").
- **`unix_sockets = "all"`** gives every Unix socket the user can reach, including the D-Bus
  session bus. Through the systemd user manager on that bus, the program can start commands
  outside the sandbox. Use it only for programs that are trusted with this.
- **Replaced files.** Landlock rules bind to the inode that existed when sandy started. A file
  that is later replaced by rename becomes unreadable for a running program. For the resolver
  files of systemd-resolved sandy grants their directory instead; a plain `/etc/resolv.conf`,
  the other layouts and `/etc/hosts` stay single files, so a long-running program needs a
  restart after the system replaces one (see "Replaced resolver files").
- **Hard links made outside.** The link check runs at the start. A process outside the sandbox
  can link a file into a writable path while the program runs, and the program can then change
  that file. The program cannot do it itself: it gets no `refer` right out of its writable paths
  and no execute right inside them.
- **What fails inside the sandbox:** 32-bit programs (killed), user namespace sandboxes of browsers
  (they fall back or fail), io_uring, debuggers, System V IPC, datagram socket pairs, `mkfifo` and
  symbolic links in writable paths, metadata changes and extended attribute reads by path with the
  default setting, `fanotify`, `chattr` and the other file system ioctls that change a file, block
  deduplication (`duperemove`), file leases, `ldattach`, the console tools that change a text
  console (`loadkeys`, `setfont`, `chvt`), exclusive mode on a terminal, job control in a shell and
  terminal resizing with `signals = "isolated"`, GNU tar extracting an archive that holds a
  directory (it uses `openat2`), and system calls newer than the reviewed table (`ENOSYS`).
- **Landlock errata.** Without the file system view sandy does not check the errata bitmask. A
  kernel without the fix for erratum 3 lets rights widen through renames of directories that a
  bind mount disconnected. The program cannot mount, and `refer` is granted only inside writable
  paths, so the practical risk is low. Whether a supported stable kernel lacks the fix is not
  verified. The view creates bind mounts itself, so it requires the fix (see "File system
  view").
- Kernel bugs in allowed system calls are out of scope. The filters reduce the reachable kernel
  code, but they are not a full allowlist per program.

## Testing

`crates/sandy-cli/tests/escape_linux.rs` holds the Linux escape tests; the shared ones are in
`escape.rs`, and `check.rs` holds the tests that `sandy check` reports what `sandy run` refuses.
Every denial has a control run outside the sandbox. Checks that need a host feature
(a session bus, a pseudo-terminal, ptrace or `/proc/<pid>/mem` under Yama `ptrace_scope` 1 or
higher, a socket family) call `common::skip`, which records the skip; the README section
"Testing" describes the accounting around it. Checks that depend on the Landlock ABI read it
from the kernel: below ABI 6, the signal test expects sandy to refuse `signals = "isolated"`.
The unit tests in `crates/sandy-linux` cover the planning function with invented host
capabilities, and the filter decisions with a small BPF interpreter that applies every
installed filter with the kernel's precedence. A unit test whose forked child allocates or starts
threads runs again in a process of its own (`alone.rs`): libtest runs the tests on many threads,
and a child that `fork` makes from one of them inherits the locks the others hold at that moment,
which hung the relay's test in about 1 of 40 runs of the binary. `setup_linux.rs` covers
`sandy setup`; its tests that change the host take root with `sudo -n`, skip where sudo asks for a
password (`passwordless-sudo`) or the restriction does not apply, run one at a time, and remove
what they installed without sandy's help, so a failed test leaves nothing behind either.

### A lower ABI on this kernel

A host reports one ABI, so one kernel runs one of sandy's ABI branches. `sandy-abi-cap ABI
PROGRAM [ARGUMENT]...` lowers the version that everything it starts reads: a seccomp filter
notifies it for `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` and answers
with the cap, while every other call passes through. `sandy-abi-cap 2 cargo test` therefore runs
a whole suite against the ABI 1 and 2 code paths, because the tests read the ABI with the same
call.

It changes what sandy handles, not what the kernel can do, which is enough for the rights of an
ABI: under cap 1 a rename between directories fails with `EXDEV`, and under caps 1 and 2
`truncate` fails with `EPERM` from the seccomp rules instead of `EACCES` from Landlock
(`truncation_is_denied_everywhere_before_abi_3` checks that). It does not bring back a kernel
without an errata fix or with an older system call table, so one real old kernel is still the
only way to see those. It also sets `PR_SET_NO_NEW_PRIVS` for the whole run, so a check that
needs a setuid program outside the sandbox cannot run under the cap.

Static test binaries for another host, for example a test VM:

```sh
cargo build --release --target x86_64-unknown-linux-musl -p sandy-cli --bins
cargo test --no-run --target x86_64-unknown-linux-musl -p sandy-cli \
    --test escape --test escape_linux
```

The second command prints the paths of the test executables
(`target/x86_64-unknown-linux-musl/debug/deps/escape-<hash>` and `escape_linux-<hash>`). Copy
them and `target/x86_64-unknown-linux-musl/release/sandy`, `sandy-probe` and `sandy-abi-cap` to
the host, put the three binaries in one directory, and run each test executable with
`SANDY_TEST_BIN_DIR` set to that directory. Without `sandy-abi-cap` the checks that need the ABI
cap record a skip.
