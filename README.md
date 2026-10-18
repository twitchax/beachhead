# sshunnel

[![Build and Test](https://github.com/twitchax/sshunnel/actions/workflows/build.yml/badge.svg)](https://github.com/twitchax/sshunnel/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/twitchax/sshunnel/branch/main/graph/badge.svg)](https://codecov.io/gh/twitchax/sshunnel)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A userspace VPN over plain SSH: push-exec a static musl relay, cache it by hash, route through it.

> **Status: milestone 1.** sshunnel forwards TCP ports (the way `ssh -L` does) through a relay it
> installs on the remote by itself. Routing a whole subnet over a TUN device comes next, then DNS
> interception.

## Why

I want hosts on a remote LAN to work from anywhere the way they do at home, by name and by address,
over the SSH login I already have. [sshuttle](https://github.com/sshuttle/sshuttle) has that
shape, but it pipes Python to the remote, which leaves it beholden to whatever interpreter (if any)
the server happens to have. `ssh -D` plus [tun2proxy](https://github.com/tun2proxy/tun2proxy)
also exists, so sshunnel is worth building only if it beats that combination on UDP, ICMP, DNS
interception and subnet routing. Milestone 1 builds the push-exec-cache loop and the multiplexed
transport those features need, and measures their overhead against `ssh -L`.

## How it works

sshunnel runs your system `ssh` (so the aliases, `ProxyCommand`, `Match` blocks and keepalives in
`~/.ssh/config` keep working) with a one-line POSIX `sh` script as the remote command. The script:

1. Picks the relay for `uname -m`. There is one for x86_64 and one for aarch64, each a static musl
   binary of roughly 600 KB, so the remote's glibc version never enters into it.
2. Looks for `relay-<sha256>` in `~/.cache/sshunnel`, then `$XDG_RUNTIME_DIR`, `/dev/shm` and
   `$TMPDIR`, and runs it if its sha256 matches and a `--probe` proves the mount still allows
   exec. A cached copy counts only when the user owns both it and its directory (a symlink never
   does), since `/dev/shm` and `/tmp` are shared with every other account on the box.
3. Otherwise asks for it. The client streams the relay down the same session, and the script
   checks it, installs the relay atomically (`mv`), and runs it. A noexec mount hands the
   relay to the next candidate (a full one asks for another copy there); when *every* candidate
   is noexec, it runs from a `memfd` via `python3`, uncached. Relays an old build left behind are
   cleared out 30 days after they were installed.

Nothing is installed system-wide and the remote needs no root. Only the first run pays for the
transfer, and a new build carries a new hash, which doubles as the upgrade path.

Once the relay is up, the session's stdio carries a small multiplexed protocol (9-byte frame
headers, one stream per TCP connection). Every stream has its own 1 MiB credit window, and the
frame reader *never* blocks, so a stalled connection parks its own sender without holding up the
pipe or its neighbors. Memory stays bounded at window × streams.

Release builds embed the relays and will ship their `SHA256SUMS` beside the binaries, and
`sshunnel relays` prints the arch, sha256 and size of **exactly what the client will execute on a
remote**:

```text
$ sshunnel relays
relays (embedded):
  x86_64   sha256 a0e309b80a71f62836712f6c441c887be46f4c357032ea58fcb29b766cfb3e0d  606672 bytes
  aarch64  sha256 9f1087bf49fa09eb7333f1e48395573ea435b05646e72992c8f470c1fc3db05f  547352 bytes
```

## Usage

```text
$ sshunnel forward -L 8080:server.lan:80 server
sshunnel: relay x86_64 a0e309b80a71 pushed to /home/me/.cache/sshunnel
sshunnel: forwarding 127.0.0.1:8080 -> server.lan:80
sshunnel: forwarding [::1]:8080 -> server.lan:80
```

The relay resolves and dials `server.lan` on the remote, so names that only exist inside that
network work. `-L` repeats, and every connection rides the one SSH session.

```text
$ sshunnel forward --help
Forward local TCP ports through a relay on DESTINATION, like `ssh -L`

Usage: sshunnel forward [OPTIONS] --local <SPEC> <DESTINATION>

Arguments:
  <DESTINATION>  Where to run the relay, exactly as you'd pass it to ssh (config aliases work)

Options:
  -L, --local <SPEC>       `[bind_address:]port:host:hostport`. The relay resolves and dials host; the bind address defaults to localhost (IPv4 and IPv6), and port 0 picks a free local port
      --ssh-cmd <COMMAND>  The ssh program and its leading arguments, split like a shell would [env: SSHUNNEL_SSH=] [default: ssh]
      --relay-dir <DIR>    Read relays from DIR instead of the ones built in (`cargo xtask relay` writes target/relay) [env: SSHUNNEL_RELAY_DIR=]
  -h, --help               Print help
```

## Performance

`cargo xtask bench` runs both through the same throwaway sshd on loopback (512 MiB per transfer,
best of three, x86_64 Linux, OpenSSH 10.2):

| | upload | download | download, 8 streams |
|---|---|---|---|
| `ssh -L` | 497 MiB/s | 533 MiB/s | 556 MiB/s |
| `sshunnel forward -L` | 484 MiB/s | 449 MiB/s | 490 MiB/s |

Bootstrap to ready takes 146 ms when the relay has to be pushed and 111 ms from cache, and ssh's own
connection setup is most of either figure. These are loopback numbers, so they measure overhead
rather than any real link. A single stream's throughput tracks window ÷ round trip: a 256 KiB
window held one stream to roughly half of `ssh -L`, which is why the default is 1 MiB (the sweep is
in the [bench log](.prds/PRD-0002.log.md)).

## Caveats

- Remotes must be Linux on x86_64 or aarch64, with a POSIX `sh`, `uname`, `ls`, `head -c` and
  `mkdir` (GNU coreutils, busybox and toybox all qualify).
- A cache hit needs a sha256 hasher on the remote (`sha256sum`, `shasum` or `openssl`). Without
  one, the relay is sent on every run.
- The relay resolves names with musl's resolver, which reads `/etc/hosts` and `/etc/resolv.conf`
  and ignores `nsswitch.conf`. The systemd-resolved stub works; mDNS (`.local`), LDAP and NIS names
  don't.
- The memfd fallback is defeated by `vm.memfd_noexec=2` (Linux 6.3+).
- There are no reverse (`-R`) forwards yet, and a dropped session isn't re-established.

## Install

There is no release yet. To build a client with both relays embedded:

```bash
cargo xtask relay   # static musl relays and SHA256SUMS into target/relay
cargo xtask dist    # target/dist/sshunnel, with those relays inside
```

The relays link with the toolchain's own `rust-lld`, so the musl targets that `rust-toolchain.toml`
already lists are all the setup required. A plain `cargo build` produces a client without embedded
relays, which then needs `--relay-dir target/relay`.

## Development

```bash
cargo make ci        # fmt-check + clippy (-D warnings) + nextest: the gate CI runs
cargo make uat       # ci + the #[ignore]d slow suites
cargo make codecov   # coverage.lcov
cargo xtask bench    # sshunnel -L against ssh -L through a throwaway sshd
```

The e2e tests play the remote with a fake `ssh` that runs the bootstrap locally through `sh`, dash,
bash, busybox, zsh, fish or tcsh. The push, cache and noexec paths all run without an sshd.

## License

MIT
