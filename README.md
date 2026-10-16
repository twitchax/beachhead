# beachhead

[![Build and Test](https://github.com/twitchax/beachhead/actions/workflows/build.yml/badge.svg)](https://github.com/twitchax/beachhead/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/twitchax/beachhead/branch/main/graph/badge.svg)](https://codecov.io/gh/twitchax/beachhead)
[![Version](https://img.shields.io/crates/v/beachhead.svg)](https://crates.io/crates/beachhead)
[![Docs](https://docs.rs/beachhead/badge.svg)](https://docs.rs/beachhead)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A userspace VPN over plain SSH: push-exec a static musl relay, cache it by hash, route through it.

## Usage

```text
$ beachhead --help
TODO: paste the real `--help` output once the CLI settles.
```

## Install

Prebuilt binaries are attached to each [GitHub Release](https://github.com/twitchax/beachhead/releases/latest):

```bash
# Linux
curl -LO https://github.com/twitchax/beachhead/releases/latest/download/beachhead_x86_64-unknown-linux-gnu.zip
# macOS (Apple silicon)
curl -LO https://github.com/twitchax/beachhead/releases/latest/download/beachhead_aarch64-apple-darwin.zip
```

```bash
cargo install beachhead
```

## Development

```bash
cargo make ci        # fmt-check + clippy (-D warnings) + nextest: the gate CI runs
cargo make uat       # ci + the #[ignore]d slow suites
cargo make codecov   # coverage.lcov
```

## License

MIT
