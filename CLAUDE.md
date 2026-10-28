# sshunnel: project instructions

A userspace VPN over plain SSH: push-exec a static musl relay, cache it by hash, route through it.

The global conventions in `~/CLAUDE.md` and the `bootstrap-rust-project` skill's `conventions.md`
apply in full. This file records only what is specific to sshunnel; **where it is silent,
defer to `~/CLAUDE.md`.**

## Architecture

A workspace of three product crates plus `xtask`. The design and its reasons live in
`.prds/PRD-0002.md` (Technical Approach).

- `.` (`sshunnel`): the client library and a thin binary (`src/bin.rs`) behind the default `cli`
  feature. The binary parses arguments and calls the library; everything testable lives in the
  library. `src/help/` holds the commands' long help text, which the binary includes. `tests` is the
  shared fixture factory. `build.rs` embeds the relays in `SSHUNNEL_EMBED_RELAY_DIR`, else a
  package's own `relays/` (no `.git` beside the manifest), never a checkout's, and fails when its
  directory's `SHA256SUMS` and relays disagree either way, or when a package's `relays/COMMIT` isn't
  the commit cargo packaged. A package (`Cargo.toml.orig` beside the manifest) with neither fails to
  build, so cargo won't publish it.
- `src/forward.rs`: `sshunnel forward`, on every platform (no Linux-only API). TCP pumps a stream
  per connection; `UdpForwards` keeps one flow table across the session's UDP listeners, a flow per
  local sender. Its listeners never wait (a full queue drops); an entry that goes aborts its open,
  which keeps the opens in flight within the cap, and each entry's generation keeps an open that
  finished first from taking a newer flow's place.
- `src/flows.rs`: the flow table `forward`'s UDP and `route`'s UDP and echo share (conntrack's
  timeouts, a 4096 cap, LRU eviction), and the hold and tasks (the open, then the replies) their
  entries both keep, aborted when an entry goes. Plain data: no locks, no awaits.
- `src/route/`: `sshunnel route` (Linux), designed in `.prds/PRD-0004.md`. `targets` (parsing,
  matching, refusals), `names` (the fake-address map), `reverse` (the fake ranges' reverse names
  and zones), `router` (the per-connection decision, sharing the map), `stack` (the smoltcp
  netstack) with `dns` and `datagrams` (routed UDP's and echo's flows) on it, `device` (the TUN fd
  as the stack's packets), `peers` and `system` (what the machine depends on, and the commands and
  syscalls behind it), `helper` (the root side, run as the hidden `sshunnel helper` through
  sudo), `thread` (the netstack's own thread: `device`, `stack` and `dns` on a runtime of their
  own), `lifecycle`, which runs them in the spec's order and, on every exit path, joins the
  netstack's thread and then stops the helper, `check` (the dry run, `route --check`: the
  lifecycle's preflight, the device, a `sudo -n -k` probe of the helper, ssh and ping, changing
  nothing), and `sudoers` (`sshunnel sudoers`: the `NOPASSWD` setup as a script for a person to
  run, its line for the user's uid and naming only a binary that it and every directory above it
  leave to root alone). When
  sudo prompts for this binary, both also probe the root-only copy in `/usr/local/bin`
  (`sudoers::ask`), so neither sends someone back to a setup that's already done for that copy.
- `crates/sshunnel-mux`: the wire protocol and multiplexer both ends share. Its `base` holds the
  error aliases every crate re-exports.
- `crates/sshunnel-relay`: the remote binary, pushed over SSH as a static musl build. Every
  dependency crosses the wire on a cache miss, so it stays off clap, tracing-subscriber and anything
  with C code (`rust-lld` links it). Build it with `cargo xtask relay` (`--profile relay`).

The mux invariant to protect: **the frame reader never blocks**. It hands frames to per-stream
channels bounded by credit, so the ssh pipe always drains. Datagrams don't take credit: the reader
drops one whose flow's queue is full, and the writer alternates datagrams, round-robin over the
flows, with stream data after control. `route::stack` (the TUN netstack) keeps the same shape:
**its packet loop never waits on one connection**. Each smoltcp socket bridges to its relay stream
through a bounded pipe, so a slow stream closes only that socket's window, and routed UDP and echo
become flows through the flow table: datagrams go out with `try_send`, and replies come back
through one bounded channel the loop reads only while the device keeps up, so a flood drops at its
own flow's queue. A connection to the DNS server is bridged the same way, to a task of its own
(`dns::serve_tcp`), so a slow answer holds up only that connection. The packet loop, its
connections' and flows' tasks, the device's reader and writer and the DNS server share one
current-thread runtime on a thread of their own (`route::thread`, named `sshunnel-stack`), so the
netstack's own hops stay on one thread. The mux and everything else stay on the main runtime, and
each segment still crosses to the mux there and back, through tokio's channels. **Nothing on that
thread may block**: a blocking call there stalls every connection.

`route::helper` is the privilege boundary, not the client. `sshunnel route` starts it through sudo,
and with a `NOPASSWD` sudoers line anything running as the user can too, so it trusts nothing the
client sends: it connects only to a socket that user owns (checked through an `O_PATH` fd, never by
name), re-parses the targets and re-runs every refusal as root against its own route snapshot,
honors only pins inside a route and works out their gateways itself, decides whether fake v6 is on
(it tries the device's v6 address) and reports it in `Ready`, runs iproute2 and
resolvectl from a fixed `PATH`, and at teardown deletes the device itself while its fd still holds
it (any fd's holder can make the device persistent, so the last fd closing proves nothing). It and
`route::system` (the system calls behind it) are Linux only. In product code, the two TUN ioctls
(`route::system`: creating the device, clearing its persist flag), registering the device's fd with
tokio (`route::device`; tokio offers no safe way) and the relay's `getaddrinfo` and `setrlimit` are
the only `unsafe`, each block with a `// SAFETY:` comment.

## Commands

```bash
cargo make ci        # fmt-check + clippy (-D warnings) + nextest: the gate, run verbatim in CI
cargo make test      # nextest
cargo make uat       # ci + the #[ignore]d slow suites: what PRD UATs point at
cargo make codecov   # coverage.lcov
cargo xtask relay    # static musl relays + SHA256SUMS into target/relay; paths trimmed, refuses a relay naming the builder's dirs
cargo xtask dist     # release client with target/relay embedded, hashes checked
cargo xtask package  # trimmed relays into relays/, package the workspace, build the packaged client on stable
cargo xtask bench    # sshunnel -L vs ssh -L through a throwaway sshd (not part of ci)
cargo xtask bench --route  # sshunnel route vs sshunnel -L from namespaces; 15 rounds, fails if a median is under 90%
```

## Releasing

`/ship-it` follows this section where its generic steps differ. All three crates publish to
crates.io, `sshunnel`'s binary included (it's what `cargo install sshunnel` builds): `sshunnel-mux`,
`sshunnel-relay` and `sshunnel`, from this machine, never from CI, with Aaron confirming each
publish at the time. In order (`.prds/PRD-0005.md`'s Shipping section has the reasons):

1. `cargo make ci` passes on the commit you tag, and so do the UATs of the PRD that ships.
2. Tag `vX.Y.Z`, then push `main` and the tag. `release.yml` creates the GitHub release (clients,
   relays, `SHA256SUMS`), in place of a `gh release create` by hand.
3. `cargo xtask package` from the tagged tree: it rebuilds `relays/` and writes `relays/COMMIT`,
   packages the crates, and proves the stable build embeds both relays.
4. `git status --porcelain` prints nothing.
5. `cargo publish -p sshunnel-mux`, then `-p sshunnel-relay`, then `-p sshunnel --allow-dirty`.
   Only `sshunnel` takes the flag: cargo refuses the gitignored `relays/` without it, and the flag
   also drops cargo's own dirty-tree check, which step 4 replaces.

## Conventions

- **Toolchain:** pinned in `rust-toolchain.toml` (a dated nightly). Nothing else
  may pin a toolchain; `repo_sync` tests enforce it.
- **Lints:** the `[workspace.lints]` table in `Cargo.toml` (`all` + `pedantic` + `unused` +
  `unwrap_used` / `expect_used` denied). No new `allow`s beyond a narrow, commented one, and never
  for `too_many_*` or `needless_pass_by_value`: refactor instead.
- **Errors:** `anyhow` through the `Res` / `Void` aliases, with `.context()` on every `?` that
  crosses an I/O or parse boundary.
- **Tests:** unit tests in-module, integration and e2e in `tests/` (one subsystem per file, `e2e_*`
  names for tests that spawn the binary), fixtures from the `tests` factory module, behind the
  `testing` feature, which the crate's self dev-dependency turns on for its own tests. Every
  behavioral change ships a test. A test that needs a TUN device or routes opens with
  `if !netns("<its name>").unwrap() { return; }`: `tests::netns` runs it again as root over
  throwaway namespaces, in a privileged Docker container where Ubuntu restricts user namespaces
  (`SSHUNNEL_NETNS=docker` forces that), and `RemoteNs` is the remote's network.
- **Help and README:** usage docs live in the binary: the clap definitions in `src/bin.rs` and the
  long help in `src/help/*.txt` (ASCII, hand-wrapped at 100 columns; no `wrap_help`, so a pipe and
  a terminal print the same). The README embeds that output, `tests/cli.rs` fails when they differ,
  and `UPDATE_README=1 cargo nextest run -E 'test(e2e_readme_help)'` rewrites the README's blocks.
  `.editorconfig` keeps the README's trailing whitespace, which clap prints inside a long help.
- **PRDs** live in `.prds/`; reference task IDs in commits, and never mark a UAT verified without a
  real, passing test.
- **No AI attribution** anywhere: no `Co-Authored-By` trailers, session links or "generated with"
  footers in commits, PRs, changelogs or docs.
