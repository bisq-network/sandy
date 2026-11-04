# sandy 1.0.0 Highlights

## First Public Release

sandy runs a program inside the sandbox of the operating system, as a small policy allows. The same policy works on Linux, macOS and Windows.

## Fails Closed

If the host cannot enforce every restriction of the policy, sandy does not start the program and says why. Fallback levels let one policy run on hosts with different hardening without ever choosing a weaker level for a passing failure.

## Built for Callers

`sandy check --json`, the status record and stable exit statuses let another program start sandy and act on the result. Bisq's Tor library uses sandy to run Tor.

## Verifiable Releases

The release archives are signed through `SHA256SUMS`, carry build provenance attestations, and can be built again byte for byte from the tag.

## Before Using It

Install sandy outside every writable path of its policies. On Linux, run it as an unprivileged user. To check the release with the script of v1.0.0, pass the release key with `--key` and set `XWIN_ACCEPT_LICENSE=true`.

See [notable changes](notable-changes.md) and [full release notes](full-release-notes.md) for details.
