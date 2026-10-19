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
  library. `tests` is the shared fixture factory.
- `crates/sshunnel-mux`: the wire protocol and multiplexer both ends share. Its `base` holds the
  error aliases every crate re-exports.
- `crates/sshunnel-relay`: the remote binary, pushed over SSH as a static musl build. Every
  dependency crosses the wire on a cache miss, so it stays off clap, tracing-subscriber and anything
  with C code (`rust-lld` links it). Build it with `cargo xtask relay` (`--profile relay`).

The mux invariant to protect: **the frame reader never blocks**. It hands frames to per-stream
channels bounded by credit, so the ssh pipe always drains. `route::stack` (the TUN netstack) keeps
the same shape: **its packet loop never waits on one connection**. Each smoltcp socket bridges to
its relay stream through a bounded pipe, so a slow stream closes only that socket's window.

`route::helper` is the privilege boundary, not the client. `sshunnel route` starts it through sudo,
and with a `NOPASSWD` sudoers line anything running as the user can too, so it trusts nothing the
client sends: it re-parses the targets and re-runs every refusal as root against its own route
snapshot, honors only pins inside a route and works out their gateways itself, and runs iproute2
and resolvectl from a fixed `PATH`. It and `route::system` (the system calls behind it) are Linux
only. In product code, the TUN ioctl (`route::system`) and the relay's `getaddrinfo` are the only
`unsafe`, each block with a `// SAFETY:` comment.

## Commands

```bash
cargo make ci        # fmt-check + clippy (-D warnings) + nextest: the gate, run verbatim in CI
cargo make test      # nextest
cargo make uat       # ci + the #[ignore]d slow suites: what PRD UATs point at
cargo make codecov   # coverage.lcov
cargo xtask relay    # static musl relays + SHA256SUMS into target/relay
cargo xtask dist     # release client with target/relay embedded, hashes checked
cargo xtask bench    # sshunnel -L vs ssh -L through a throwaway sshd (not part of ci)
```

## Conventions

- **Toolchain:** pinned in `rust-toolchain.toml` (a dated nightly). Nothing else
  may pin a toolchain; `repo_sync` tests enforce it.
- **Lints:** the `[workspace.lints]` table in `Cargo.toml` (`all` + `pedantic` + `unused` +
  `unwrap_used` / `expect_used` denied). No new `allow`s beyond a narrow, commented one, and never
  for `too_many_*` or `needless_pass_by_value`: refactor instead.
- **Errors:** `anyhow` through the `Res` / `Void` aliases, with `.context()` on every `?` that crosses an I/O or parse boundary.
- **Tests:** unit tests in-module, integration and e2e in `tests/` (one subsystem per file, `e2e_*`
  names for tests that spawn the binary), fixtures from the `tests` factory module. Every
  behavioral change ships a test.
- **PRDs** live in `.prds/`; reference task IDs in commits, and never mark a UAT verified without a
  real, passing test.
- **No AI attribution** anywhere: no `Co-Authored-By` trailers, session links or "generated with"
  footers in commits, PRs, changelogs or docs.
