//! What the root helper does to the machine, and what the client reads from it first: iproute2 and
//! resolvectl, `/proc`, and the TUN ioctl. Every command's output goes through a pure parser, so
//! the logic is tested without privileges.
//!
//! Commands run with a cleared environment, a fixed `PATH` and their own process group. sudo keeps
//! the caller's `PATH` unless the system sets `secure_path`, and the helper must never run an `ip`
//! the caller chose; and a terminal's Ctrl-C, which the helper handles, must not kill a command
//! halfway through teardown.

use std::{
    collections::HashSet,
    ffi::OsStr,
    fs::OpenOptions,
    io::ErrorKind,
    net::IpAddr,
    os::{
        fd::OwnedFd,
        raw::{c_char, c_int, c_short},
        unix::{fs::MetadataExt as _, process::CommandExt as _},
    },
    process::{Command, Output, Stdio},
};

use anyhow::{Context as _, anyhow, bail, ensure};
use ipnet::IpNet;
use rustix::{
    io::Errno,
    ioctl::{IntegerSetter, Opcode, Updater, ioctl, opcode},
};
use serde::{Deserialize, de::IgnoredAny};

use crate::{
    base::{Res, Void},
    route::{DEVICE, DNS_ADDR, PIN_PROTO, targets::Snapshot},
};

/// Wherever distributions keep iproute2 and resolvectl, and nothing a user might own: `/usr/local`
/// is often user-writable (`npm -g`), and neither tool lives there.
const SYSTEM_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin:/run/current-system/sw/bin";
/// systemd-resolved's stub listener.
const RESOLVED_STUB: &str = "127.0.0.53";
/// `_IOW('T', 202, int)` from `<linux/if_tun.h>`: the size says `int`, but the driver reads and
/// writes back a whole `ifreq`.
const TUNSETIFF: Opcode = opcode::write::<c_int>(b'T', 202);
/// `_IOW('T', 203, int)`, whose int travels by value.
const TUNSETPERSIST: Opcode = opcode::write::<c_int>(b'T', 203);

const _: () = assert!(DEVICE.len() < libc::IFNAMSIZ, "the device name must fit an ifreq with its NUL");

/// The directly connected subnets, v4 and v6, from every routing table a rule consults.
///
/// # Errors
///
/// Fails when `ip` can't run or prints something unexpected.
pub fn snapshot() -> Res<Snapshot> {
    let mut connected = Vec::new();
    for family in ["-4", "-6"] {
        let rules = output("ip", &["-j", family, "rule", "show"])?;
        let routes = output("ip", &["-j", family, "route", "show", "table", "all"])?;
        connected.extend(parse_snapshot(&rules, &routes)?.connected);
    }
    Ok(Snapshot { connected })
}

/// Where the machine sends traffic for one address right now: the route a pin copies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Via {
    pub dev: String,
    /// `None` when the address is on-link.
    pub gateway: Option<IpAddr>,
    /// `false` when the kernel delivers the address some other way (it's one of this machine's):
    /// the local table outranks main, so no route sshunnel adds can capture it.
    pub unicast: bool,
}

/// The route the kernel picks for `addr`, rules included.
///
/// # Errors
///
/// Fails when nothing routes `addr`, or its gateway is of the other address family.
pub fn route_get(addr: IpAddr) -> Res<Via> {
    parse_route_get(&output("ip", &["-j", "route", "get", &addr.to_string()])?).with_context(|| format!("finding the route to {addr}"))
}

/// Whether systemd-resolved can route names: it answers `resolvectl status`, and the system
/// actually asks it (otherwise the link config would apply and do nothing).
///
/// # Errors
///
/// Fails when `resolvectl` exists but can't be run, or a config file exists but can't be read.
pub fn resolved_usable() -> Res<bool> {
    let answered = match tool("resolvectl", &["status"]).stdout(Stdio::null()).stderr(Stdio::null()).status() {
        Ok(status) => status.success(),
        Err(e) if e.kind() == ErrorKind::NotFound => false,
        Err(e) => return Err(e).context("running resolvectl status"),
    };
    Ok(answered && resolver_wired(&read_optional("/etc/resolv.conf")?, &read_optional("/etc/nsswitch.conf")?))
}

/// The DNS servers the machine used before sshunnel: resolved's upstreams, else `/etc/resolv.conf`'s.
///
/// # Errors
///
/// Fails when neither file can be read.
pub fn upstream_dns() -> Res<Vec<IpAddr>> {
    let resolved = read_optional("/run/systemd/resolve/resolv.conf")?;
    if !resolved.is_empty() {
        return Ok(upstreams(&resolved));
    }
    let conf = std::fs::read_to_string("/etc/resolv.conf").context("reading /etc/resolv.conf")?;
    Ok(upstreams(&conf))
}

/// Creates [`DEVICE`]: a non-persistent TUN device without packet info, which vanishes, with its
/// addresses, routes and resolver config, when the last fd on it closes. It must be new: an
/// existing one, leftover or made persistent, is never attached to and configured.
///
/// # Errors
///
/// "Another sshunnel route is running" when the device exists; otherwise whatever the driver says
/// (without root, `EPERM`).
pub fn create_tun() -> Res<OwnedFd> {
    let device = OpenOptions::new().read(true).write(true).open("/dev/net/tun").context("opening /dev/net/tun")?;

    let mut name: [c_char; libc::IFNAMSIZ] = [0; libc::IFNAMSIZ];
    for (slot, byte) in name.iter_mut().zip(DEVICE.bytes()) {
        *slot = c_char::from_ne_bytes([byte]);
    }
    let mut request = libc::ifreq {
        ifr_name: name,
        ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: tun_flags()? },
    };

    // SAFETY: TUNSETIFF takes a pointer to a `struct ifreq`, which `libc::ifreq` mirrors, and may
    // write the device's name back into it; `request` is a live, exclusively borrowed `ifreq` for
    // the whole call, and its name is NUL-terminated (the assertion above).
    let attached = unsafe { ioctl(&device, Updater::<TUNSETIFF, libc::ifreq>::new(&mut request)) };
    match attached {
        Ok(()) => Ok(device.into()),
        Err(Errno::BUSY) => bail!("another sshunnel route is running, or a leftover {DEVICE} is in use (`ip link del {DEVICE}` removes one)"),
        Err(e) => Err(e).with_context(|| format!("creating the TUN device {DEVICE}")),
    }
}

/// Clears the device's persist flag, then closes this fd on it. A client holding the other fd can
/// set the flag without any capability; cleared here, the device still goes when that fd closes.
///
/// # Errors
///
/// Fails when the driver refuses, after closing the fd all the same.
pub fn release_tun(tun: OwnedFd) -> Void {
    // SAFETY: TUNSETPERSIST takes its argument by value, an int where 0 clears the flag, and `tun`
    // is an open fd on the device for the whole call.
    let cleared = unsafe { ioctl(&tun, IntegerSetter::<TUNSETPERSIST>::new_usize(0)) };
    drop(tun);
    cleared.with_context(|| format!("clearing {DEVICE}'s persist flag"))
}

/// `IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL`, the last so an existing device is EBUSY. 0x9001 overflows a
/// signed short, so the bits go through `u16`.
fn tun_flags() -> Res<c_short> {
    let bits = u16::try_from(libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_TUN_EXCL).context("TUN flags overflow 16 bits")?;
    Ok(c_short::from_ne_bytes(bits.to_ne_bytes()))
}

/// Whether this process shares the network namespace of pid 1, whose links systemd-resolved
/// configures. Only root can read pid 1's; unreadable counts as no.
#[must_use]
pub fn same_netns_as_init() -> bool {
    let id = |path: &str| std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()));
    matches!((id("/proc/self/ns/net"), id("/proc/1/ns/net")), (Some(own), Some(init)) if own == init)
}

/// Runs `program` with `args` and fails, naming the command and quoting its stderr, unless it
/// succeeds.
pub(crate) fn run<S: AsRef<OsStr>>(program: &str, args: &[S]) -> Void {
    checked(program, args).map(drop)
}

/// `program` with `args` and nothing else from this process: no environment but [`SYSTEM_PATH`], no
/// stdin, and a process group of its own, out of reach of the terminal's Ctrl-C.
fn tool<S: AsRef<OsStr>>(program: &str, args: &[S]) -> Command {
    let mut command = Command::new(program);
    command.args(args).env_clear().env("PATH", SYSTEM_PATH).stdin(Stdio::null()).process_group(0);
    command
}

fn checked<S: AsRef<OsStr>>(program: &str, args: &[S]) -> Res<Output> {
    let line = || {
        std::iter::once(OsStr::new(program))
            .chain(args.iter().map(AsRef::as_ref))
            .map(OsStr::to_string_lossy)
            .collect::<Vec<_>>()
            .join(" ")
    };
    let output = tool(program, args).output().with_context(|| format!("running `{}`", line()))?;
    if !output.status.success() {
        bail!("`{}` failed ({}): {}", line(), output.status, String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(output)
}

fn output(program: &str, args: &[&str]) -> Res<String> {
    String::from_utf8(checked(program, args)?.stdout).with_context(|| format!("`{program}` printed something other than UTF-8"))
}

/// A file's contents, or nothing when it doesn't exist.
fn read_optional(path: &str) -> Res<String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(contents),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).with_context(|| format!("reading {path}")),
    }
}

#[derive(Deserialize)]
struct Rule {
    /// Absent for rules that don't look a table up (`unreachable`, `goto`).
    table: Option<String>,
}

#[derive(Deserialize)]
struct Route {
    /// Absent for unicast.
    #[serde(rename = "type")]
    kind: Option<String>,
    dst: String,
    /// Absent for the main table.
    table: Option<String>,
    dev: Option<String>,
    protocol: Option<String>,
    gateway: Option<IgnoredAny>,
    /// A gateway of the other family (`via inet6 ...`).
    via: Option<IgnoredAny>,
    nexthops: Option<IgnoredAny>,
}

impl Route {
    fn is_unicast(&self) -> bool {
        self.kind.as_deref().is_none_or(|kind| kind == "unicast")
    }
}

/// The on-link unicast routes (no next hop: v4 marks them scope link, v6 marks them no scope at
/// all) of the tables `rules` consult, from `ip -j rule show` and `ip -j route show table all` for
/// one family. sshunnel's own device and its pinned routes are not connected subnets.
fn parse_snapshot(rules: &str, routes: &str) -> Res<Snapshot> {
    let rules: Vec<Rule> = serde_json::from_str(rules).context("parsing `ip -j rule show`")?;
    let routes: Vec<Route> = serde_json::from_str(routes).context("parsing `ip -j route show`")?;
    let tables: HashSet<String> = rules.into_iter().filter_map(|rule| rule.table).collect();
    let pin_proto = PIN_PROTO.to_string();

    let mut connected = Vec::new();
    for route in routes {
        let on_link = route.is_unicast() && route.gateway.is_none() && route.via.is_none() && route.nexthops.is_none();
        let consulted = tables.contains(route.table.as_deref().unwrap_or("main"));
        let ours = route.dev.as_deref() == Some(DEVICE) || route.protocol.as_deref() == Some(&pin_proto);
        if !on_link || !consulted || ours || route.dst == "default" {
            continue;
        }
        let net = route.dst.parse::<IpNet>().or_else(|_| route.dst.parse::<IpAddr>().map(IpNet::from));
        connected.push(net.with_context(|| format!("unexpected route destination '{}'", route.dst))?);
    }

    connected.sort_unstable();
    connected.dedup();
    Ok(Snapshot { connected })
}

#[derive(Deserialize)]
struct Got {
    #[serde(rename = "type")]
    kind: Option<String>,
    dev: String,
    gateway: Option<IpAddr>,
    via: Option<IgnoredAny>,
}

/// The route in `ip -j route get` output.
fn parse_route_get(json: &str) -> Res<Via> {
    let got: Vec<Got> = serde_json::from_str(json).context("parsing `ip -j route get`")?;
    let [got] = <[Got; 1]>::try_from(got).map_err(|routes| anyhow!("expected one route, got {}", routes.len()))?;

    let unicast = got.kind.as_deref().is_none_or(|kind| kind == "unicast");
    ensure!(!unicast || got.via.is_none(), "the route's gateway is of the other address family, which can't be pinned");
    Ok(Via {
        dev: got.dev,
        gateway: got.gateway,
        unicast,
    })
}

/// The `nameserver` addresses in a resolv.conf.
fn nameservers(resolv_conf: &str) -> impl Iterator<Item = &str> {
    resolv_conf.lines().filter_map(|line| {
        let mut words = line.split_whitespace();
        (words.next() == Some("nameserver")).then(|| words.next()).flatten()
    })
}

/// The upstream servers in a resolv.conf, minus sshunnel's own; scoped (`%eth0`) ones can't be
/// dialed by address alone and are skipped.
fn upstreams(resolv_conf: &str) -> Vec<IpAddr> {
    nameservers(resolv_conf)
        .filter_map(|server| server.parse().ok())
        .filter(|server| *server != IpAddr::V4(DNS_ADDR))
        .collect()
}

/// Whether the system resolver goes through resolved: resolv.conf points at its stub, or
/// `nss-resolve` is on the `hosts:` line.
fn resolver_wired(resolv_conf: &str, nsswitch: &str) -> bool {
    let stub = nameservers(resolv_conf).any(|server| server == RESOLVED_STUB);
    let nss = nsswitch
        .lines()
        .filter_map(|line| line.split('#').next()?.trim_start().strip_prefix("hosts:"))
        .any(|services| services.split_whitespace().any(|service| service == "resolve"));
    stub || nss
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;

    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Tailscale-style policy routing: its table 52 is consulted ahead of main.
    const RULES: &str = r#"[
        {"priority":0,"src":"all","table":"local"},
        {"priority":5210,"src":"all","fwmark":"0x80000/0xff0000","table":"main"},
        {"priority":5250,"src":"all","fwmark":"0x80000/0xff0000","action":"unreachable"},
        {"priority":5270,"src":"all","table":"52"},
        {"priority":32766,"src":"all","table":"main"},
        {"priority":32767,"src":"all","table":"default"}
    ]"#;

    const ROUTES: &str = r#"[
        {"dst":"default","gateway":"192.0.2.1","dev":"eth0","protocol":"dhcp","prefsrc":"192.0.2.10","metric":100,"flags":[]},
        {"dst":"192.0.2.0/24","dev":"eth0","protocol":"kernel","scope":"link","prefsrc":"192.0.2.10","metric":100,"flags":[]},
        {"dst":"10.99.0.0/16","gateway":"192.0.2.1","dev":"eth0","flags":[]},
        {"dst":"10.88.0.5","dev":"eth0","scope":"link","flags":[]},
        {"dst":"100.64.0.0/10","dev":"tailscale0","table":"52","scope":"link","flags":[]},
        {"dst":"10.77.0.0/16","dev":"eth1","table":"99","scope":"link","flags":[]},
        {"type":"local","dst":"192.0.2.10","dev":"eth0","table":"local","protocol":"kernel","scope":"host","prefsrc":"192.0.2.10","flags":[]},
        {"type":"broadcast","dst":"192.0.2.255","dev":"eth0","table":"local","protocol":"kernel","scope":"link","prefsrc":"192.0.2.10","flags":[]},
        {"type":"unreachable","dst":"10.66.0.0/16","scope":"link","flags":[]},
        {"dst":"198.51.100.7","dev":"eth0","protocol":"222","scope":"link","flags":[]},
        {"dst":"198.18.0.0/15","dev":"sshunnel0","protocol":"kernel","scope":"link","prefsrc":"198.18.0.1","flags":[]},
        {"dst":"192.0.2.0/24","dev":"eth0","table":"52","scope":"link","flags":[]}
    ]"#;

    /// v6 routes carry no scope: on-link is "no next hop".
    const RULES6: &str = r#"[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]"#;

    const ROUTES6: &str = r#"[
        {"dst":"2001:db8:1::/64","dev":"eth0","protocol":"ra","metric":100,"flags":[],"pref":"medium"},
        {"dst":"fd99::/64","gateway":"fe80::1","dev":"eth0","protocol":"ra","metric":100,"flags":[],"pref":"medium"},
        {"dst":"fe80::/64","dev":"eth0","protocol":"kernel","metric":256,"flags":[],"pref":"medium"},
        {"dst":"fe80::/64","dev":"docker0","protocol":"kernel","metric":256,"flags":[],"pref":"medium"},
        {"dst":"default","gateway":"fe80::1","dev":"eth0","protocol":"ra","metric":100,"flags":[],"pref":"high"},
        {"type":"local","dst":"2001:db8:1::10","dev":"eth0","table":"local","protocol":"kernel","metric":0,"flags":[],"pref":"medium"},
        {"type":"multicast","dst":"ff00::/8","dev":"eth0","table":"local","protocol":"kernel","metric":256,"flags":[],"pref":"medium"}
    ]"#;

    #[test]
    fn snapshot_parses_ip_json() {
        let v4 = parse_snapshot(RULES, ROUTES).unwrap();
        assert_eq!(v4.connected, vec![net("10.88.0.5/32"), net("100.64.0.0/10"), net("192.0.2.0/24")]);

        let v6 = parse_snapshot(RULES6, ROUTES6).unwrap();
        assert_eq!(v6.connected, vec![net("2001:db8:1::/64"), net("fe80::/64")]);

        // A connected route that can't be read fails the check rather than slipping past it.
        assert!(parse_snapshot(RULES6, r#"[{"dst":"not-an-address","dev":"eth0","scope":"link"}]"#).is_err());
        assert!(parse_snapshot("not json", "[]").is_err());
    }

    #[test]
    fn snapshot_reads_this_machine() {
        snapshot().unwrap();
    }

    #[test]
    fn route_get_parses_ip_json() {
        let via = |dev: &str, gateway: Option<&str>, unicast: bool| Via {
            dev: dev.to_owned(),
            gateway: gateway.map(addr),
            unicast,
        };

        let routed = parse_route_get(r#"[{"dst":"192.0.2.77","gateway":"192.0.2.1","dev":"eth0","prefsrc":"192.0.2.10","flags":[],"uid":1000,"cache":[]}]"#).unwrap();
        assert_eq!(routed, via("eth0", Some("192.0.2.1"), true));

        let on_link = parse_route_get(r#"[{"dst":"192.0.2.5","dev":"eth0","prefsrc":"192.0.2.10","flags":[],"uid":1000,"cache":[]}]"#).unwrap();
        assert_eq!(on_link, via("eth0", None, true));

        let v6 = parse_route_get(r#"[{"dst":"2001:db8::1","from":"::","gateway":"fe80::1","dev":"eth0","protocol":"ra","metric":100,"flags":[],"pref":"high"}]"#).unwrap();
        assert_eq!(v6, via("eth0", Some("fe80::1"), true));

        // The machine's own address: the local table delivers it, so there is nothing to pin.
        let local = parse_route_get(r#"[{"type":"local","dst":"127.0.0.1","dev":"lo","prefsrc":"127.0.0.1","flags":[],"uid":1000,"cache":["local"]}]"#).unwrap();
        assert_eq!(local, via("lo", None, false));
        let other_family = parse_route_get(r#"[{"dst":"192.0.2.9","via":{"family":"inet6","host":"fe80::1"},"dev":"eth0","flags":[]}]"#);
        assert!(other_family.is_err());
        assert!(parse_route_get("[]").is_err());
    }

    #[test]
    fn resolv_conf_upstreams_skip_the_dns_address() {
        let conf = "# written by a tool\n\
                    nameserver 192.0.2.53\n\
                    nameserver 198.18.0.2\n\
                    nameserver 2001:db8::53\n\
                    nameserver fe80::1%eth0\n\
                    ; nameserver 192.0.2.99\n\
                    search corp.example\n\
                    options edns0\n";

        assert_eq!(upstreams(conf), vec![addr("192.0.2.53"), addr("2001:db8::53")]);
    }

    #[test]
    fn resolved_counts_only_when_the_system_asks_it() {
        let stub = "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n";
        let direct = "nameserver 192.0.2.53\n";

        assert!(resolver_wired(stub, "hosts: files dns\n"));
        assert!(resolver_wired(direct, "passwd: files\nhosts:          files mymachines resolve [!UNAVAIL=return] dns myhostname\n"));
        assert!(!resolver_wired(direct, "hosts: files dns\n"));
        assert!(!resolver_wired(direct, "# hosts: files resolve\nhosts: files dns # resolve later\nnetworks: resolve\n"));
        assert!(!resolver_wired("# nameserver 127.0.0.53\nnameserver 192.0.2.53\n", ""));
    }

    #[test]
    fn the_tun_ioctl_reaches_the_driver() {
        if rustix::process::geteuid().is_root() {
            eprintln!("skipping: as root this would create {DEVICE}");
            return;
        }
        // The driver checks the request and the name before the capability, so EPERM (not ENOTTY
        // or EINVAL) means the opcode and the `ifreq` were understood; with a session running, the
        // exclusive flag answers EBUSY first.
        let error = format!("{:#}", create_tun().unwrap_err());
        assert!(error.contains(DEVICE) && (error.contains("Operation not permitted") || error.contains("in use")), "{error}");
    }

    #[test]
    fn the_device_is_created_exclusively() {
        // IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL: an existing sshunnel0, leftover or made persistent by
        // a client, is EBUSY rather than attached to and configured.
        assert_eq!(tun_flags().unwrap().to_ne_bytes(), 0x9001_u16.to_ne_bytes());
    }

    #[test]
    fn system_commands_run_in_their_own_process_group() {
        // A terminal's Ctrl-C goes to its foreground process group; a command leading its own group
        // (pgid == pid) never sees it, so a second Ctrl-C can't cut teardown's `ip route del` short.
        run("sh", &["-c", "read -r pid comm state ppid pgrp rest < /proc/$$/stat && [ \"$pid\" = \"$pgrp\" ]"]).unwrap();
    }

    #[test]
    fn the_system_path_leaves_out_usr_local() {
        // /usr/local is often user-writable (`npm -g`), and an `ip` planted there would run as root.
        assert!(SYSTEM_PATH.split(':').all(|dir| !dir.starts_with("/usr/local")), "{SYSTEM_PATH}");
    }
}
