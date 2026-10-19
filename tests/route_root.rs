//! `sshunnel route` as root on the host, through the machine's own systemd-resolved: what a test
//! namespace can't show, since resolved serves the host's namespace alone. The remote is this
//! machine with an `/etc/hosts` of its own (`FakeRemote::with_hosts`). `#[ignore]`d: CI runs them
//! under `sudo -E` (the workflow's route-root step), and without root they skip.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    net::{IpAddr, SocketAddr},
    process::Command as StdCommand,
    time::Duration,
};

use pretty_assertions::assert_eq;
use rustix::process::{Pid, Signal, geteuid, kill_process};
use sshunnel::{
    route::FAKE_RANGE,
    tests::{FakeRemote, Watched, echo_server, pattern, relay_dir, round_trip, route_command},
};
use tempfile::TempDir;

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

/// `route` routing `*.corp.example` through a remote whose `/etc/hosts` has `wiki.corp.example`,
/// once its routes are up.
async fn route_names(dir: &TempDir) -> Watched {
    let remote = FakeRemote::new(dir.path(), "sh", &[]).unwrap().with_hosts("127.0.0.1 wiki.corp.example\n").unwrap();
    let relays = relay_dir(dir.path()).unwrap();
    let command = route_command(env!("CARGO_BIN_EXE_sshunnel"), dir.path(), remote.ssh_path(), &relays, &["*.corp.example"]);
    let mut route = Watched::spawn(command).unwrap();
    route.line("sshunnel: routing ", WITHIN).await.unwrap();
    route
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
    // AAAA is NODATA: an IPv6 lookup finds the A record alone, v4-mapped.
    let v6 = getent("ahostsv6", "wiki.corp.example").unwrap_or_default();
    assert!(v6.iter().all(|addr| matches!(addr, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())), "{v6:?}");
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
    // Every other name goes where it went before.
    assert_eq!(getent("ahosts", "localhost"), localhost);
    let now = getent("ahostsv4", "example.com");
    assert_eq!(now.is_some(), unrelated.is_some(), "example.com: {now:?} now, {unrelated:?} before");
    assert!(now.unwrap_or_default().iter().all(|addr| !is_fake(addr)));
    stop(route).await;

    // The link's resolver config went with the device.
    let link = StdCommand::new("resolvectl").args(["status", "sshunnel0"]).output().unwrap();
    assert!(!link.status.success(), "{}", String::from_utf8_lossy(&link.stdout));
}
