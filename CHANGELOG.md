# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each release opens with a sentence on
why the version moved the way it did.

## [Unreleased]

### Added

- Protocol v4: UDP and echo flows, datagrams outside credit, raw DNS queries, and the relay's
  capabilities in its `Hello`. Each flow queues at most 32 datagrams (64 KiB) each way and drops
  what doesn't fit rather than stall the pipe, and each end's writer serves the flows round-robin,
  taking turns with stream data.

### Changed

- A published package refuses to build with relays from a commit other than its own.

## [0.1.0] - 2026-10-21

The first release, at 0.1.0 rather than 1.0.0 because the command line and the wire protocol can
still change while UDP and ICMP routing is built.

### Added

- `sshunnel`, `sshunnel-mux` and `sshunnel-relay` on crates.io, with `sshunnel` carrying both
  relays inside, so `cargo install sshunnel` builds on stable with nothing else to fetch. Those
  relays are built at publish time, so their hashes can differ from the GitHub release's.
- `cargo binstall sshunnel` support: the GitHub release's client for x86_64 Linux and aarch64
  macOS, a source build elsewhere.
- `sshunnel forward -L [bind:]port:host:hostport <destination>`: TCP forwards through a relay
  that sshunnel pushes over the system `ssh`, caches on the remote by sha256, and execs. Like
  `ssh -L`, it listens on both loopbacks by default and outlives running out of descriptors.
- The bootstrap: a one-line POSIX `sh` script that reuses a cached relay only from a directory the
  user owns and only after its sha256 checks out, receives one otherwise (falling through full and
  noexec dirs), runs from a memfd when every mount is noexec, and evicts relays installed over 30
  days ago.
- `sshunnel-relay`: the static musl relay for x86_64 and aarch64 Linux (about 600 KB each).
- `sshunnel-mux`: the wire protocol, with per-stream credit flow control that bounds memory at
  window × streams; each side announces its receive window in its `Hello`.
- `sshunnel relays`: the arch, sha256 and size of each relay the client would execute.
- `cargo xtask relay`, `dist`, `package` and `bench`: build the relays and `SHA256SUMS`, build a
  client with them embedded, package the crates with the relays inside (and build that client on
  stable from the packages alone), and compare throughput against `ssh -L`.
- `cargo xtask bench --route`: `sshunnel route` against `sshunnel forward -L`, one stream each way,
  with the client side in network namespaces (a privileged Docker container where Ubuntu restricts
  user namespaces), over 15 interleaved rounds by default. It fails when either direction's median
  is under 90% of forward mode's, and prints the best beside it.
- `sshunnel route <destination> <target>...` (Linux): routes TCP to CIDRs and to names matching
  domain patterns (`*.corp.example`) through the relay, over a TUN device, `sshunnel0`. Names
  resolve on the remote and get stable fake addresses from `198.18.0.0/15`, kept in
  `~/.local/state/sshunnel/names` (under `$XDG_STATE_HOME` when set), and `-x` carves CIDRs and
  names out. Domain patterns need systemd-resolved, which hands sshunnel only the queries under
  them. UDP and ICMP to a routed address get ICMP administratively prohibited. Every refusal (`/0`,
  a bare `*`, a pattern no hostname can match, a target inside a connected subnet or the fake range,
  a connected subnet overlapping the fake range, more than 4096 routes, a route the main table
  already has, patterns without systemd-resolved) is reported before ssh runs. A root helper started
  through sudo (the hidden `sshunnel helper`, which the README's `NOPASSWD` sudoers line names) sets
  the device up, keeps ssh's peers and the DNS servers on their routes, and leaves nothing behind on
  exit: it deletes the device itself rather than leaving it to go with the last fd, which a client
  setting the device's persist flag could keep open past the helper.
- Protocol v3: `Resolve` / `Resolved` / `ResolveErr` frames, so the relay can resolve a name with
  its own resolver (`getaddrinfo`), and a kind on `OpenErr` (refused, unreachable, timed out,
  other), so a failed dial says why. The cache is keyed by hash, so the new relay is pushed beside a
  cached v2 one under its own hash, and the v2 one is cleared out by the first install in its
  directory once it is over 30 days old.
- Initial scaffold.
- `route`'s e2e tests run as root over throwaway network namespaces: through `unshare`, or where
  Ubuntu restricts user namespaces, in a privileged Docker container built on first use
  (`sshunnel-netns:*`). `SSHUNNEL_NETNS=docker` forces the container. In CI, `tests/route_sudo.rs`
  also runs `route` as a user does, through the real sudo on a pseudo-terminal, and ends it with a
  Ctrl-C typed there.

### Changed

- Relays carry no build-machine paths: `cargo xtask relay` trims them, and refuses a relay that
  still names a builder's directory.
