//! `sshunnel route` as root on the host, through the machine's own systemd-resolved: what a test
//! namespace can't show, since resolved serves the host's namespace alone. The remote is this
//! machine with an `/etc/hosts` of its own (`FakeRemote::with_hosts`), and for SRV a `/etc/resolv.conf`
//! naming a stub nameserver the test runs (`FakeRemote::with_resolv_conf`). `#[ignore]`d: CI runs them
//! under `sudo -E` (the workflow's route-root step), and without root they skip.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::Command as StdCommand,
    time::Duration,
};

use pretty_assertions::assert_eq;
use rustix::process::{Pid, Signal, geteuid, kill_process};
use simple_dns::{
    CLASS, Name, Packet, PacketFlag, QTYPE, RCODE, ResourceRecord, TYPE,
    rdata::{RData, SRV},
};
use sshunnel::{
    route::{FAKE_RANGE, FAKE_RANGE6, names::fake_v6},
    tests::{FakeRemote, Pinged, Watched, echo_server, pattern, ping, relay_dir, resolved_leftovers, round_trip, route_command, udp_echo_server},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, UdpSocket},
    time::timeout,
};

/// How long `route` may take to bring its routes up, or to exit.
const WITHIN: Duration = Duration::from_secs(30);

/// Root, or a skip; CI runs these as root, so there a skip is a failure.
fn root() -> bool {
    if geteuid().is_root() {
        return true;
    }
    assert!(
        std::env::var_os("CI").is_none(),
        "these tests need root on CI: run them with CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E'"
    );
    eprintln!("skipped: not root");
    false
}

/// `route` routing `*.corp.example` through `remote`, once its routes are up.
async fn route_through(dir: &TempDir, remote: &FakeRemote) -> Watched {
    let relays = relay_dir(dir.path()).unwrap();
    let command = route_command(env!("CARGO_BIN_EXE_sshunnel"), dir.path(), remote.ssh_path(), &relays, &["*.corp.example"]);
    let mut route = Watched::spawn(command).unwrap();
    route.line("sshunnel: routing ", WITHIN).await.unwrap();
    route
}

/// `route` routing `*.corp.example` through a remote whose `/etc/hosts` has `wiki.corp.example`,
/// once its routes are up.
async fn route_names(dir: &TempDir) -> Watched {
    let remote = FakeRemote::new(dir.path(), "sh", &[]).unwrap().with_hosts("127.0.0.1 wiki.corp.example\n").unwrap();
    route_through(dir, &remote).await
}

/// The stub nameserver's address: a loopback address of its own, since 127.0.0.53 and .54 are
/// systemd-resolved's. Binding port 53 is why these tests need root.
const STUB: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 153)), 53);

/// What the stub nameserver answers: SRV for `_ldap._tcp.corp.example` pointing at
/// `ldap.corp.example`, and NXDOMAIN for anything else. `None` for what isn't a DNS query.
fn stub_answer(query: &[u8]) -> Option<Vec<u8>> {
    let query = Packet::parse(query).ok()?;
    let question = query.questions.first()?;
    let mut reply = Packet::new_reply(query.id());
    reply.set_flags(PacketFlag::RECURSION_AVAILABLE);
    reply.questions.clone_from(&query.questions);
    if question.qtype == QTYPE::TYPE(TYPE::SRV) && question.qname.to_string().eq_ignore_ascii_case("_ldap._tcp.corp.example") {
        let target = Name::new_unchecked("ldap.corp.example");
        reply.answers.push(ResourceRecord::new(
            question.qname.clone(),
            CLASS::IN,
            60,
            RData::SRV(SRV {
                priority: 0,
                weight: 0,
                port: 389,
                target,
            }),
        ));
    } else {
        *reply.rcode_mut() = RCODE::NameError;
    }
    reply.build_bytes_vec().ok()
}

/// The stub nameserver, over UDP and TCP, until the test ends (the runtime drops its tasks).
async fn stub_nameserver() {
    let udp = UdpSocket::bind(STUB).await.expect("binding the stub nameserver's UDP port needs root");
    let tcp = TcpListener::bind(STUB).await.expect("binding the stub nameserver's TCP port needs root");
    tokio::spawn(async move {
        let mut buf = [0; 1500];
        while let Ok((n, from)) = udp.recv_from(&mut buf).await {
            if let Some(answer) = stub_answer(&buf[..n]) {
                let _ = udp.send_to(&answer, from).await;
            }
        }
    });
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = tcp.accept().await {
            tokio::spawn(async move {
                // RFC 7766 framing: a two-byte length before each message.
                while let Ok(len) = conn.read_u16().await {
                    let mut query = vec![0; usize::from(len)];
                    if conn.read_exact(&mut query).await.is_err() {
                        return;
                    }
                    let Some(answer) = stub_answer(&query) else { return };
                    let framed = [&u16::try_from(answer.len()).unwrap().to_be_bytes()[..], &answer].concat();
                    if conn.write_all(&framed).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
}

/// SIGTERM, then a clean exit.
async fn stop(route: Watched) {
    kill_process(Pid::from_raw(i32::try_from(route.pid().unwrap()).unwrap()).unwrap(), Signal::TERM).unwrap();
    let (status, stderr) = route.exit(WITHIN).await.unwrap();
    assert!(status.success(), "{status}; stderr:\n{stderr}");
}

/// The addresses `getent <database> <name>` finds through the system resolver, each once; `None`
/// when the name doesn't resolve.
fn getent(database: &str, name: &str) -> Option<Vec<IpAddr>> {
    let out = StdCommand::new("getent").args([database, name]).output().unwrap();
    out.status.success().then(|| {
        let mut addrs: Vec<IpAddr> = String::from_utf8(out.stdout).unwrap().lines().filter_map(|line| line.split_whitespace().next()?.parse().ok()).collect();
        // One line per socket type.
        addrs.dedup();
        addrs
    })
}

fn is_fake(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => FAKE_RANGE.contains(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some_and(|v4| FAKE_RANGE.contains(&v4)),
    }
}

/// A native v6 fake, which a v4-mapped one is not.
fn is_fake_v6(addr: &IpAddr) -> bool {
    matches!(addr, IpAddr::V6(v6) if FAKE_RANGE6.contains(v6))
}

/// Whether the machine has IPv6, which the helper needs to turn fake v6 on: `all` disables it on
/// every device, and a new device, as `sshunnel0` is, starts with `default`'s setting.
fn ipv6_on() -> bool {
    ["all", "default"]
        .into_iter()
        .all(|conf| std::fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{conf}/disable_ipv6")).is_ok_and(|disabled| disabled.trim() == "0"))
}

/// `name`'s v6 fake, the one address an IPv6 lookup finds once AAAA answers.
fn v6_fake(name: &str) -> IpAddr {
    let v6 = getent("ahostsv6", name).unwrap_or_else(|| panic!("{name} resolves over IPv6"));
    assert!(v6.len() == 1 && is_fake_v6(&v6[0]), "{v6:?}");
    v6[0]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root and the host's systemd-resolved; CI runs it under sudo"]
async fn e2e_route_name_connects_by_name() {
    if !root() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let echo = echo_server().await.unwrap();
    let route = route_names(&dir).await;

    let fake = getent("ahostsv4", "wiki.corp.example").expect("wiki.corp.example resolves");
    assert!(fake.len() == 1 && is_fake(&fake[0]), "{fake:?}");
    // The relay dials the name, which the remote's /etc/hosts sends to the echo server.
    let data = pattern(5, 1 << 20);
    assert!(round_trip(SocketAddr::new(fake[0], echo.port()), &data).await.unwrap() == data);

    // A name the remote doesn't know doesn't resolve here either.
    assert_eq!(getent("ahostsv4", "nonexistent.corp.example"), None);
    if ipv6_on() {
        // AAAA is the v6 fake, paired with the v4 one.
        eprintln!("IPv6 is on: AAAA answers the name's v6 fake");
        let IpAddr::V4(v4) = fake[0] else { panic!("{fake:?}") };
        assert_eq!(v6_fake("wiki.corp.example"), IpAddr::V6(fake_v6(v4)));
    } else {
        // AAAA is NODATA: an IPv6 lookup (glibc's ahostsv6 asks with AI_V4MAPPED) finds the A record
        // alone, v4-mapped. A failed lookup would mean NXDOMAIN or SERVFAIL instead.
        eprintln!("IPv6 is off: AAAA is NODATA, so an IPv6 lookup finds the v4 fake, v4-mapped");
        let v6 = getent("ahostsv6", "wiki.corp.example").expect("an IPv6 lookup finds the A record, v4-mapped");
        assert!(!v6.is_empty() && v6.iter().all(|addr| matches!(addr, IpAddr::V6(_)) && is_fake(addr)), "{v6:?}");
    }
    stop(route).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root and the host's systemd-resolved; CI runs it under sudo"]
async fn e2e_route_name_udp_reaches_the_remote_by_name() {
    if !root() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let echo = udp_echo_server().await.unwrap();
    let route = route_names(&dir).await;

    let fake = getent("ahostsv4", "wiki.corp.example").expect("wiki.corp.example resolves");
    assert!(fake.len() == 1 && is_fake(&fake[0]), "{fake:?}");
    // The relay opens the flow by name, which the remote's /etc/hosts sends to the echo server.
    let app = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    app.connect(SocketAddr::new(fake[0], echo.port())).await.unwrap();
    app.send(b"by name").await.unwrap();
    let mut back = [0; 64];
    let n = timeout(WITHIN, app.recv(&mut back)).await.expect("the echo comes back").unwrap();
    assert_eq!(&back[..n], b"by name");
    stop(route).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root and the host's systemd-resolved; CI runs it under sudo"]
async fn e2e_route_name_udp_reaches_the_remote_over_its_v6_fake() {
    if !root() {
        return;
    }
    if !ipv6_on() {
        eprintln!("skipped: IPv6 is disabled here (net.ipv6.conf.all or .default.disable_ipv6), so route leaves fake v6 off");
        return;
    }
    let dir = TempDir::new().unwrap();
    let echo = udp_echo_server().await.unwrap();
    let route = route_names(&dir).await;

    let fake = v6_fake("wiki.corp.example");
    // The app sends over IPv6; the relay opens the flow by name, which the remote's /etc/hosts sends
    // to the echo server on 127.0.0.1.
    let app = UdpSocket::bind("[::]:0").await.unwrap();
    app.connect(SocketAddr::new(fake, echo.port())).await.unwrap();
    app.send(b"by name over v6").await.unwrap();
    let mut back = [0; 64];
    let n = timeout(WITHIN, app.recv(&mut back)).await.expect("the echo comes back").unwrap();
    assert_eq!(&back[..n], b"by name over v6");
    stop(route).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root and the host's systemd-resolved; CI runs it under sudo"]
async fn e2e_route_name_ping_reaches_the_remote_over_its_v6_fake() {
    if !root() {
        return;
    }
    if !ipv6_on() {
        eprintln!("skipped: IPv6 is disabled here (net.ipv6.conf.all or .default.disable_ipv6), so route leaves fake v6 off");
        return;
    }
    let dir = TempDir::new().unwrap();
    let route = route_names(&dir).await;

    let fake = v6_fake("wiki.corp.example");
    // The app pings over IPv6, and the relay over IPv4: the remote's /etc/hosts has the name at
    // 127.0.0.1 alone. The reply still comes back as ICMPv6, under the app's identifier.
    assert_eq!(ping(fake, WITHIN).await.unwrap(), Pinged::Reply, "{fake}");
    stop(route).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root and the host's systemd-resolved; CI runs it under sudo"]
async fn e2e_route_name_ping_gets_echo_replies() {
    if !root() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let route = route_names(&dir).await;

    let fake = getent("ahostsv4", "wiki.corp.example").expect("wiki.corp.example resolves");
    assert!(fake.len() == 1 && is_fake(&fake[0]), "{fake:?}");
    // The relay opens the echo flow by name, which the remote's /etc/hosts sends to 127.0.0.1: the
    // remote, this machine, pings itself.
    assert_eq!(ping(fake[0], WITHIN).await.unwrap(), Pinged::Reply, "{}", fake[0]);
    stop(route).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root and the host's systemd-resolved; CI runs it under sudo"]
async fn e2e_resolved_routes_only_the_patterns() {
    if !root() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let localhost = getent("ahosts", "localhost");
    let unrelated = getent("ahostsv4", "example.com");
    let route = route_names(&dir).await;

    let fake = getent("ahostsv4", "wiki.corp.example").expect("wiki.corp.example resolves");
    assert!(fake.iter().all(is_fake), "{fake:?}");
    // The link routes the fake ranges' reverse zones too, so a PTR for a fake reaches the client.
    let link = resolved_leftovers().unwrap().join("\n");
    let mut zones = vec!["~18.198.in-addr.arpa", "~19.198.in-addr.arpa"];
    if ipv6_on() {
        zones.push("~0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.1.0.0.2.ip6.arpa");
    }
    for zone in zones {
        assert!(link.contains(zone), "{zone} missing from the link: {link}");
    }
    // Every other name goes where it went before.
    assert_eq!(getent("ahosts", "localhost"), localhost);
    let now = getent("ahostsv4", "example.com");
    assert_eq!(now.is_some(), unrelated.is_some(), "example.com: {now:?} now, {unrelated:?} before");
    assert!(now.unwrap_or_default().iter().all(|addr| !is_fake(addr)));
    stop(route).await;

    // The link's resolver config went with the device, reverse zones included.
    assert_eq!(resolved_leftovers().unwrap(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root and the host's systemd-resolved; CI runs it under sudo"]
async fn e2e_resolved_answers_srv_from_the_remote() {
    if !root() {
        return;
    }
    let dir = TempDir::new().unwrap();
    stub_nameserver().await;
    // The relay asks the nameservers in its own resolv.conf, which is the stub.
    let remote = FakeRemote::new(dir.path(), "sh", &[])
        .unwrap()
        .with_hosts("127.0.0.1 wiki.corp.example\n")
        .unwrap()
        .with_resolv_conf(&format!("nameserver {}\n", STUB.ip()))
        .unwrap();
    let route = route_through(&dir, &remote).await;

    let out = StdCommand::new("resolvectl").args(["query", "--legend=no", "-t", "SRV", "_ldap._tcp.corp.example"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}; stdout:\n{stdout}\nstderr:\n{}", out.status, String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("ldap.corp.example"), "{stdout}");
    stop(route).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root and the host's systemd-resolved; CI runs it under sudo"]
async fn e2e_resolved_answers_ptr_for_a_fake() {
    if !root() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let route = route_names(&dir).await;

    let fake = getent("ahostsv4", "wiki.corp.example").expect("wiki.corp.example resolves");
    assert!(fake.len() == 1 && is_fake(&fake[0]), "{fake:?}");
    // The reverse zone is routed to the link, and the client answers from the name it handed out.
    let out = StdCommand::new("getent").args(["hosts", &fake[0].to_string()]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}; stdout:\n{stdout}", out.status);
    assert!(stdout.split_whitespace().any(|word| word == "wiki.corp.example"), "{stdout}");
    stop(route).await;
}
