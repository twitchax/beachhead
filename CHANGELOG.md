# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each release opens with a sentence on
why the version moved the way it did.

## [Unreleased]

### Added

- `sshunnel forward -L [bind:]port:host:hostport <destination>`: TCP forwards through a relay
  that sshunnel pushes over the system `ssh`, caches on the remote by sha256, and execs.
- The bootstrap: a one-line POSIX `sh` script that reuses a verified cached relay, receives one
  otherwise, falls through noexec mounts, and runs from a memfd when every mount is noexec.
- `sshunnel-relay`: the static musl relay for x86_64 and aarch64 Linux (about 600 KB each).
- `sshunnel-mux`: the wire protocol, with per-stream credit flow control.
- `sshunnel relays`: the arch, sha256 and size of each relay the client would execute.
- `cargo xtask relay`, `dist` and `bench`: build the relays and `SHA256SUMS`, build a client with
  them embedded, and compare throughput against `ssh -L`.
- Initial scaffold.
