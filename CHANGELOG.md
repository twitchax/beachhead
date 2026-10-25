# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each release opens with a sentence on
why the version moved the way it did.

## [Unreleased]

### Fixed

- `route` no longer stalls new connections behind dials that hang: past 256 dials in flight (a
  firewall that drops SYNs makes each take about two minutes), the oldest gives way to the new
  connection instead of the new one being dropped.
- The relay stops dialing when the client gives up on an open, such as a `route` dial evicted past
  the held-dial cap, instead of trying to connect for up to two minutes.
- `route` runs on a kernel booted with `ipv6.disable=1`, where reading the IPv6 routing tables
  failed every run; IPv6 targets are refused there.
- Ctrl-C at `route`'s sudo password prompt exits cleanly instead of failing with `sudo exited before
  the root helper started`.

## [0.2.0] - 2026-10-23

UDP through `forward` and `route`, and ping and every DNS record type through `route`. A minor
version rather than a patch because the libraries' public API changes (listed under Changed), which
below 1.0 moves the minor version.

### Added

- Protocol v4: UDP and echo flows, datagrams outside credit, raw DNS queries, and the relay's
  capabilities in its `Hello`. Each flow queues at most 32 datagrams (64 KiB) each way and drops
  what doesn't fit rather than stall the pipe, and each end's writer serves the flows round-robin,
  taking turns with stream data.
- The relay serves UDP flows: a connected socket per flow, datagrams both ways, and socket errors
  (port unreachable and the like) reported as flow errors. Any other socket error (a path MTU
  lowered by ICMP, an egress firewall's `EPERM`) loses only its datagram: the flow and its source
  port live on, unless 64 come in a row with nothing getting through.
- The relay answers raw DNS queries from its own `/etc/resolv.conf`, and reports in its `Hello`
  whether it may ping over IPv4 and IPv6.
- UDP forwards: `sshunnel forward -L [bind:]port:host:hostport/udp`. Each local sender gets a flow
  of its own, opened by its first datagram and answered from the port it sent to; flows idle out
  after 30 s (120 s once they've carried more than one reply), and a session holds at most 4096,
  closing the least recently used to open another.
- UDP through `sshunnel route`, to CIDR targets and to names under a pattern: each app socket and
  destination is a flow through the relay, with UDP forwards' timeouts and cap. A closed port or an
  unreachable host on the remote comes back as the ICMP unreachable a real network sends, so a
  connected socket sees `ECONNREFUSED` for a closed port. UDP to an address nothing routes, and
  ICMP other than ping, still get administratively prohibited.
- Ping through `sshunnel route`, over IPv4 and IPv6, to CIDR targets and to names under a pattern:
  each `ping`'s echoes to an address are a flow to an unprivileged ping socket on the remote, and
  each reply comes back in the app's own family under its identifier. Where the remote doesn't
  allow unprivileged ping (`net.ipv4.ping_group_range`), `route` warns once its routes are up, and
  ping through it gets administratively prohibited.
- Fake IPv6 addresses for names under a pattern: where the machine has IPv6, AAAA answers the
  name's v4 fake in the low 32 bits of `2001:2::/96`, which `route` sends to its device, so TCP, UDP
  and ping reach the name over IPv6 too. The root helper decides, by trying the device's IPv6
  address. `2001:2::/96` is reserved like `198.18.0.0/15`: a target inside it is refused, one
  containing it is routed around it with a warning, and with a domain pattern a connected subnet
  overlapping it is refused.
- Every DNS record type for names under a pattern: SRV, MX, TXT and the rest come from the remote's
  resolver through the relay, with every A, AAAA, HTTPS and SVCB record removed from the answer so
  none hands out a real address. A remote NXDOMAIN for a name the relay finds (one only in the
  remote's `/etc/hosts`) becomes NODATA, and HTTPS and SVCB queries are NODATA, since their address
  hints would bypass the fakes.
- Reverse lookups of fake addresses, v4 and v6, answer the name each was handed out for (NXDOMAIN
  for one no name holds). The root helper routes the fake ranges' reverse zones to the device's
  resolver link, next to the patterns' domains.
- DNS over TCP on `route`'s DNS server (`198.18.0.2:53`, RFC 7766): a query that comes over TCP
  goes on over TCP, to the remote's resolver for a name under a pattern and to the normal DNS
  servers for any other, so a truncated answer's retry over TCP now succeeds. A connection closes
  after 10 s without a query, and is reset when its asker leaves an answer unread for 10 s; the
  server serves at most 64 at once, resetting the rest.

### Changed

- AAAA for a name under a pattern is no longer always empty (NODATA): it stays empty only where the
  machine has no IPv6.
- Record types other than A and AAAA for a name under a pattern are no longer always empty
  (NODATA): they come from the remote's resolver.
- `route::stack::Dns::answer` takes the transport the query came over.
- The relay resolves every open through its bounded lookup path, and raises its open-file limit to
  the hard limit.
- A published package refuses to build with relays from a commit other than its own.
- `Forward` gains `proto` (a public field, `Proto::Tcp` unless the spec ends in `/udp`) and
  `bind_udp`; `bind` refuses a UDP forward, and `bind_udp` a TCP one.
- For library users: `route::dns::Server::new` takes a `fake_v6` argument,
  `route::helper::Reply::Ready` carries a `fake_v6` field, and the relay's `serve` takes the
  capabilities it reports in `Hello`. `Tunnel` gains flows and queries. In `sshunnel-mux`,
  `hello::send_hello` takes capabilities, `recv_hello` returns a `PeerHello` that `start` takes,
  `Frame::Hello` has a `capabilities` field, and `Frame` and `Request` gain variants (neither is
  `#[non_exhaustive]`).

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
