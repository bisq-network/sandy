# sandy 1.2.0 Highlights

## One Behaviour on Every Platform

What a policy allows now matches across Linux, macOS and Windows in more places. macOS refuses symbolic links, named pipes and directory clones in writable paths, as Linux does, and Windows protects the git and GnuPG configuration and refuses an executable path that the program may write, as Linux and macOS do.

## Symbolic Links When a Tool Needs Them

`filesystem.symlinks = "allow"` (`--symlinks allow`) lets a program make symbolic links in its writable paths, for tools such as npm, pnpm and `python3 -m venv`. The default stays `deny`.

## The Egress Broker Explains Its Refusals

With `--explain`, the egress broker names each connection it refuses or cannot make, on Linux, macOS and Windows, with the reply it gave and a hint when another `reach` would allow it.

## VPN Adapters on Windows

A WireGuard or other TUN adapter that splits the default route no longer makes every public address look local to the egress broker, so `reach = "public"` works with such a VPN up.

## Faster Starts

sandy no longer walks the trees below policy paths at each start, except to look for a second name of its own executable or the policy file, and the egress broker keeps its view of the network until the system reports a change.

## Before Upgrading

Some policies that 1.1.0 accepted are now refused, most of them on macOS and Windows. Read [notable changes](notable-changes.md) before upgrading; the [full release notes](full-release-notes.md) have the details.
