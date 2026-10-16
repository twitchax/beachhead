# beachhead: project instructions

A userspace VPN over plain SSH: push-exec a static musl relay, cache it by hash, route through it.

The global conventions in `~/CLAUDE.md` and the `bootstrap-rust-project` skill's `conventions.md`
apply in full. This file records only what is specific to beachhead; **where it is silent,
defer to `~/CLAUDE.md`.**

## Architecture

One package: a library (`beachhead`) and a thin binary (`beachhead`, `src/bin.rs`) behind the
default `cli` feature. The binary parses arguments and calls the library; everything testable
lives in the library. `base` holds the error aliases; `tests` is the shared fixture factory.

## Commands

```bash
cargo make ci        # fmt-check + clippy (-D warnings) + nextest: the gate, run verbatim in CI
cargo make test      # nextest
cargo make uat       # ci + the #[ignore]d slow suites: what PRD UATs point at
cargo make codecov   # coverage.lcov
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
