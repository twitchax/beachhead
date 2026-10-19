# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each release opens with a sentence on
why the version moved the way it did.

## [Unreleased]

### Added

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
- `cargo xtask relay`, `dist` and `bench`: build the relays and `SHA256SUMS`, build a client with
  them embedded, and compare throughput against `ssh -L`.
- Protocol v3: `Resolve` / `Resolved` / `ResolveErr` frames, so the relay can resolve a name with
  its own resolver (`getaddrinfo`), and a kind on `OpenErr` (refused, unreachable, timed out,
  other), so a failed dial says why. A cached v2 relay is simply replaced, since the cache is keyed
  by hash.
- Initial scaffold.
