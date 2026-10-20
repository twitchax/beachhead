# sshunnel

[![Build and Test](https://github.com/twitchax/sshunnel/actions/workflows/build.yml/badge.svg)](https://github.com/twitchax/sshunnel/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/twitchax/sshunnel/branch/main/graph/badge.svg)](https://codecov.io/gh/twitchax/sshunnel)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A userspace VPN over plain SSH: push-exec a static musl relay, cache it by hash, route through it.

> **Status: milestone 2 done.** sshunnel forwards TCP ports (the way `ssh -L` does) and, on
> Linux, routes subnets and domain names over a TUN device (`sshunnel route`), through a relay it
> installs on the remote by itself. UDP and ICMP come later.

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
  x86_64   sha256 604223ed029fe70992b2d61cbe9346c823c45b1aa8914d9dc369d034146ef886  618032 bytes
  aarch64  sha256 8e945bdc13c0a21ad98c41d6fd3e9da84b6ae086780fb1d01f94853029d5ed0b  557744 bytes
```

## Usage

```text
$ sshunnel forward -L 8080:server.lan:80 server
sshunnel: relay x86_64 604223ed029f pushed to /home/me/.cache/sshunnel
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

### Routing subnets and names (Linux)

```text
$ sshunnel route jump.corp.example 10.99.0.0/16 '*.corp.example' -x 10.99.7.0/24
sshunnel: relay x86_64 604223ed029f cached in /home/me/.cache/sshunnel
[sudo] password for me:
sshunnel: routing 10.99.0.0/16, *.corp.example (except 10.99.7.0/24) through jump.corp.example on sshunnel0
```

TCP to every address in a CIDR target, and to every name a domain pattern matches, now goes through
the relay, which dials it on the remote; everything else keeps the machine's normal routes and DNS.
`*.corp.example` matches `corp.example` and every name under it, and `wiki.corp.example` matches
that name only. The most specific target wins, and an exclude (`-x`) wins a tie. CIDR excludes
carve CIDR targets and name excludes carve patterns; they never cross, so a pattern routes a name
whatever address it has on the remote.

Names resolve on the remote. The relay looks each one up with the remote's own resolver, and a name
that exists there gets a stable fake address from `198.18.0.0/15`, remembered in
`$XDG_STATE_HOME/sshunnel/names` (by default `~/.local/state/sshunnel/names`); one that doesn't is
NXDOMAIN here too. Connections refused or unreachable on the remote look the same to the app.

Before ssh even starts, `route` refuses `0.0.0.0/0` and `::/0`, a bare `*`, a pattern no hostname
can match (labels are ASCII letters, digits, `-` and `_`; an IDN goes in its `xn--` form), a target
equal to or inside a directly connected subnet (a broader one is allowed, and the connected part
stays local, with a warning), a target equal to or inside `198.18.0.0/15`, a connected subnet
overlapping `198.18.0.0/15` (whatever the targets), targets that come to more than 4096 routes (an
exclude carves its target into pieces, each a route), and a route the main table already has at the
metric sshunnel's own would get (0 for IPv4, 1 for IPv6, so either wins a tie with a route at the
kernel's default; the kernel won't hold two at the same metric), reporting every problem at once.
Each target gets a route of its own, never merged with its neighbors, so each competes with the
machine's routes on its own prefix.

```text
$ sshunnel route --help
Route CIDRs and domain patterns through a relay on DESTINATION, over a TUN device (Linux)

Usage: sshunnel route [OPTIONS] <DESTINATION> <TARGET>...

Arguments:
  <DESTINATION>  Where to run the relay, exactly as you'd pass it to ssh (config aliases work)
  <TARGET>...    What to route: CIDRs (`10.99.0.0/16`, `fd99::/64`) and domain patterns (`*.corp.example`, `host.corp.example`)

Options:
  -x, --exclude <TARGET>   Carve a CIDR or a name out of the targets (repeatable)
      --ssh-cmd <COMMAND>  The ssh program and its leading arguments, split like a shell would [env: SSHUNNEL_SSH=] [default: ssh]
      --relay-dir <DIR>    Read relays from DIR instead of the ones built in (`cargo xtask relay` writes target/relay) [env: SSHUNNEL_RELAY_DIR=]
  -h, --help               Print help
```

**Privileges.** ssh runs as you. Once the session is up, `route` starts a small root helper through
`sudo` (or directly, when already root) that creates `sshunnel0`, adds its addresses and routes, and
configures systemd-resolved for it, then hands the device back and waits for `route` to exit. The
helper trusts nothing it is sent: it re-checks every target as root and does a fixed set of things
to its own device. To skip the password prompt, install sshunnel where only root can write, check
that, and allow the helper alone:

```bash
sudo install -o root -g root -m 0755 target/dist/sshunnel /usr/local/bin/sshunnel
namei -l /usr/local/bin/sshunnel          # every line root-owned and writable by root alone
sudo visudo -f /etc/sudoers.d/sshunnel    # add the line below, with your user name
```

```text
me ALL=(root) NOPASSWD: /usr/local/bin/sshunnel helper --socket *
```

sudo runs the helper by the binary's real path (symlinks resolved), so that is the path the line
names. **Never point a `NOPASSWD` line at a binary you can write:** whoever can write it is root,
since sudo runs whatever they put there. The line lets anything running as you start the helper, so
it grants exactly what `route` allows: route any range except the default route (`0.0.0.0/0`,
`::/0`) through `sshunnel0`, keep addresses inside those ranges on their current route, and send the
matching domains' queries to sshunnel while the device exists. That grant is machine-wide: the
routes and the `~domain` resolver routing apply to every user's traffic and lookups on the host, and
that traffic goes to a process running as you. `0.0.0.0/1` plus `128.0.0.0/1` is a deliberate full
tunnel; the `/0` refusal guards against accidents and is not a security boundary.

**systemd-resolved.** Domain patterns need systemd-resolved, and the system has to actually ask it:
`/etc/resolv.conf` points at its stub (`127.0.0.53`), or `nss-resolve` is on the `hosts:` line of
`/etc/nsswitch.conf`. Otherwise a run with any pattern fails, CIDR targets included, rather than
half-working. sshunnel sets only its own link's DNS: a `~domain` routing domain per pattern and no
default route, so resolved hands it the queries under those domains and nothing else.

**What it leaves behind: nothing.** Ctrl-C, SIGTERM, a closed terminal (unless started under
`nohup`), the session ending and the helper dying all end the run. Before `route` returns, the
helper deletes its pinned routes (the host routes that keep ssh's peer and your DNS servers off the
device when a target covers them; an address with a host route of its own already stays off it)
and then the device itself, which takes its addresses, routes and resolver config with it. Only the
helper dying without its teardown (a SIGKILL, say) can leave a pinned route, and the device still
goes when `route` closes its own fd on it. The next start sweeps the pin, or
`sudo ip route flush proto 222` and `sudo ip -6 route flush proto 222` remove it by hand.

## Performance

`cargo xtask bench` runs both through the same throwaway sshd on loopback (512 MiB per transfer,
best of three, x86_64 Linux, OpenSSH 10.2):

| | upload | download | download, 8 streams |
|---|---|---|---|
| `ssh -L` | 497 MiB/s | 533 MiB/s | 556 MiB/s |
| `sshunnel forward -L` | 484 MiB/s | 449 MiB/s | 490 MiB/s |

Bootstrap to ready takes about 140 ms when the relay has to be pushed and 120 ms from cache, and
ssh's own connection setup is most of either figure. These are loopback numbers, so they measure overhead
rather than any real link. A single stream's throughput tracks window ÷ round trip: a 256 KiB
window held one stream to roughly half of `ssh -L`, which is why the default is 1 MiB (the sweep is
in the [bench log](.prds/PRD-0002.log.md)).

`cargo xtask bench --route` puts `route` against `forward -L`, one stream each way, both from a
network namespace of their own and through the same sshd, to this host's own address. It runs 15
interleaved rounds and fails when either direction's median is under 90% of forward mode's. The
medians of two runs (512 MiB per transfer) on a 64-core x86_64 Linux machine:

| | upload | download |
|---|---|---|
| `sshunnel forward -L` | 485 and 457 MiB/s | 435 and 412 MiB/s |
| `sshunnel route` | 486 and 482 MiB/s | 429 and 377 MiB/s |
| route / forward | 1.00 and 1.06 | 0.99 and 0.91 |

Upload keeps pace. Download is about 93% of forward mode's across all 30 rounds, and its rounds
vary more than forward mode's. The runs, the profile and how the bar came to be on the median are
in the [PRD log](.prds/PRD-0004.log.md).

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
- `route` carries TCP only; UDP and ICMP to a routed address get ICMP administratively prohibited.
  One `route` runs at a time.
- Apps that resolve names themselves bypass domain patterns: a browser using DNS over HTTPS never
  asks the system resolver. CIDR targets still catch their traffic.
- Fake addresses only mean something while `route` runs. Answers carry a 5-second TTL, so a cached
  one fades soon after an exit.
- Names under a pattern's domain that `route` doesn't send through the relay (an excluded name, or
  `a.host.corp.example` under the exact `host.corp.example`) go to your normal DNS servers over UDP
  only. An answer too large for UDP comes back truncated, and the lookup fails rather than retrying
  over TCP.
- `route` adds its routes to the main table and no `ip rule` of its own. A more specific route, or
  another tool's policy routing (Tailscale's subnet routes, say), can still win a target; `route`
  warns, naming the device that won, and leaves it be.
- A target containing `198.18.0.0/15` (such as `128.0.0.0/1`) leaves that range to sshunnel's fake
  addresses, with a warning.

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
cargo xtask bench --route   # sshunnel route against sshunnel -L, from network namespaces
```

The e2e tests play the remote with a fake `ssh` that runs the bootstrap locally through `sh`, dash,
bash, busybox, zsh, fish or tcsh. The push, cache and noexec paths all run without an sshd.

`route`'s e2e tests (`tests/route.rs`) need a real TUN device and real routes, so each one runs
again as root over throwaway user, mount, PID and network namespaces (`unshare`), with the remote's
network in a second namespace across a veth pair. Nothing on the machine changes, and nothing needs
sudo. Ubuntu 23.10 and later block unprivileged user namespaces through AppArmor; there, each test
runs in a privileged Docker container instead (Docker without sudo, about half a second a test),
built from your own Ubuntu release (for a derivative, the one it is built on) plus iproute2 and an
ssh client as `sshunnel-netns:<codename>-<hash>` (the hash is the Dockerfile's) on first use, with
the checkout and the cargo target dir mounted read-only. `cargo xtask bench --route` runs its
client side in the same container. With neither, the tests skip with a warning (under `CI`, they
fail). `SSHUNNEL_NETNS=docker` forces the container. A change to the image's definition builds a
new tag and leaves the old one behind: `docker image ls sshunnel-netns` lists them, and
`docker image rm sshunnel-netns:<tag>` frees one. The alternative to Docker is lifting the
restriction, as CI does on its throwaway runners:

```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0   # until reboot
```

That trades back what the restriction protects: any program you run can create user namespaces
again, and with them reach kernel code that otherwise needs root, a common path for privilege
escalation exploits.

The name tests (`tests/route_root.rs`) go through the host's own systemd-resolved, which no test
namespace has, so they run as root on the host and only in CI (`#[ignore]`d, through
`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E'`). Locally they skip. So does
`tests/route_sudo.rs`, which runs `route` the way you do: not root, through the real sudo, on a
pseudo-terminal, ended by a Ctrl-C typed there. CI runs it as the runner's own user, which has
passwordless sudo.

## License

MIT
