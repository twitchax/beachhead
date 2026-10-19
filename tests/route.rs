//! `sshunnel route` against a real TUN device and real routes. Each test runs again in throwaway
//! namespaces (see `tests::netns`): the client, root over a network namespace of its own, and the
//! remote's network in a second one across a veth pair (`RemoteNs`), where the relay runs. Named
//! `e2e_*` because they spawn the binary.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    net::{Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::Command as StdCommand,
    time::{Duration, Instant},
};

use pretty_assertions::assert_eq;
use rustix::process::{Pid, Signal, kill_process, kill_process_group};
use sshunnel::{
    route::{peers::process_tree, system::same_netns_as_init},
    tests::{FakeRemote, RemoteNs, Watched, echo_on, netns, pattern, relay_dir, round_trip, route_command, shim_dir},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream, UdpSocket},
    process::Command,
    time::timeout,
};

/// How long `route` may take to bring its routes up, or to exit.
const WITHIN: Duration = Duration::from_secs(30);
/// The pin `RemoteNs`'s topology calls for: ssh's peer, kept on the route it had before the device.
const PIN: &str = "10.98.0.2 via 172.31.0.2 dev cl0 proto 222";

/// One test's world: a scratch dir, the remote's network, and a fake ssh into it.
struct World {
    dir: TempDir,
    ns: RemoteNs,
    remote: FakeRemote,
    relays: PathBuf,
}

impl World {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let ns = RemoteNs::new().unwrap();
        let remote = FakeRemote::new(dir.path(), "sh", &[]).unwrap().in_netns(&ns).unwrap();
        let relays = relay_dir(dir.path()).unwrap();
        Self { dir, ns, remote, relays }
    }

    fn route(&self, ssh: &Path, targets: &[&str]) -> Command {
        route_command(env!("CARGO_BIN_EXE_sshunnel"), self.dir.path(), ssh, &self.relays, targets)
    }

    /// Starts `route` through the fake remote and waits for its routes to be up.
    async fn start(&self, targets: &[&str]) -> Watched {
        started(self.route(self.remote.ssh_path(), targets)).await
    }

    /// A listener on the remote, at `addr`.
    fn listen(&self, addr: SocketAddr) -> TcpListener {
        let listener = self.ns.listen(addr).unwrap();
        listener.set_nonblocking(true).unwrap();
        TcpListener::from_std(listener).unwrap()
    }

    /// An echo server on the remote, at `addr`; returns its address.
    fn echo(&self, addr: SocketAddr) -> SocketAddr {
        echo_on(self.listen(addr)).unwrap()
    }

    /// An ssh that, as the real one does, holds its own TCP connection to `peer` for the session
    /// (a child echoes whatever arrives on it) and runs the fake remote's session as another child.
    fn ssh_holding(&self, peer: SocketAddr) -> PathBuf {
        self.ssh_connecting(peer, "")
    }

    /// An ssh whose connection to `peer` only a child holds, as `ProxyCommand nc %h %p` would: ssh
    /// itself holds nothing but pipes.
    fn ssh_through_a_proxy(&self, peer: SocketAddr) -> PathBuf {
        self.ssh_connecting(peer, "exec 3>&-\n")
    }

    /// An ssh that connects to `peer`, leaves a child (`cat`) echoing on the connection, runs the
    /// `sh` lines in `then`, and runs the fake remote's session as another child. `-O check` opens
    /// no connection.
    fn ssh_connecting(&self, peer: SocketAddr, then: &str) -> PathBuf {
        let path = self.dir.path().join("ssh-connecting");
        let fake = self.remote.ssh_path().display();
        let script = format!(
            "#!/bin/bash\n\
             [ \"$1\" = -O ] && exec '{fake}' \"$@\"\n\
             exec 3<>/dev/tcp/{ip}/{port}\n\
             cat <&3 >&3 2>/dev/null &\n\
             {then}\
             '{fake}' \"$@\" 3>&-\n",
            ip = peer.ip(),
            port = peer.port(),
        );
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }
}

/// Spawns `command` and waits for its status line.
async fn started(command: Command) -> Watched {
    let mut route = Watched::spawn(command).unwrap();
    route.line("sshunnel: routing ", WITHIN).await.unwrap();
    route
}

/// SIGTERM, then a clean exit that leaves nothing behind.
async fn stop(route: Watched) {
    signal(route.pid().unwrap(), Signal::TERM);
    let (status, stderr) = route.exit(WITHIN).await.unwrap();
    assert!(status.success(), "{status}; stderr:\n{stderr}");
    assert_eq!(leftovers(), Vec::<String>::new(), "stderr:\n{stderr}");
}

fn signal(pid: u32, signal: Signal) {
    kill_process(Pid::from_raw(i32::try_from(pid).unwrap()).unwrap(), signal).unwrap();
}

/// The root helper `route` started: directly, since the client is root here.
fn helper_of(route: &Watched) -> u32 {
    let is_helper = |pid: &u32| std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|argv| argv.split(|&b| b == 0).nth(1) == Some(b"helper"));
    process_tree(route.pid().unwrap()).unwrap().into_iter().find(is_helper).expect("route has no helper")
}

/// `ip`'s output, trimmed line by line.
fn ip(args: &[&str]) -> Vec<String> {
    let out = StdCommand::new("ip").args(args).output().unwrap();
    assert!(out.status.success(), "ip {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap().lines().map(|line| line.trim().to_owned()).collect()
}

/// Every route in every table, v4 then v6.
fn routes() -> impl Iterator<Item = String> {
    ["-4", "-6"].into_iter().flat_map(|family| ip(&[family, "route", "show", "table", "all"]))
}

/// The pinned routes. (`ip route show proto 222` would leave the protocol out of each line.)
fn pins() -> Vec<String> {
    routes().filter(|route| route.contains("proto 222")).collect()
}

/// What `route` has in this namespace: its device, any route on the device, any pinned route.
fn leftovers() -> Vec<String> {
    let device = ip(&["-o", "link", "show"]).into_iter().filter(|link| link.contains("sshunnel0"));
    device.chain(routes().filter(|route| route.contains("sshunnel0") || route.contains("proto 222"))).collect()
}

/// [`leftovers`] once `settled` holds for them (or [`WITHIN`] has passed), for what goes with a
/// process that is still exiting.
async fn leftovers_once(settled: impl Fn(&[String]) -> bool) -> Vec<String> {
    let deadline = Instant::now() + WITHIN;
    loop {
        let left = leftovers();
        if settled(&left) || Instant::now() > deadline {
            return left;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Bytes sent on `conn` come back: whatever echoes at the other end is still reachable.
async fn still_echoes(conn: &mut TcpStream) {
    const PING: &[u8] = b"still here\n";
    conn.write_all(PING).await.unwrap();
    let mut back = vec![0; PING.len()];
    timeout(WITHIN, conn.read_exact(&mut back)).await.expect("the echo comes back").unwrap();
    assert_eq!(back, PING);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_route_carries_tcp_to_a_cidr_target() {
    if !netns("e2e_route_carries_tcp_to_a_cidr_target").unwrap() {
        return;
    }
    let world = World::new();
    let v4 = world.echo(SocketAddr::new(RemoteNs::HOST.into(), 0));
    let v6 = world.echo(SocketAddr::new(RemoteNs::HOST6.into(), 0));
    let route = world.start(&["10.99.0.0/16", "fd99::/64"]).await;

    // Nothing here reaches either host but the device.
    for (seed, echo) in [(1, v4), (2, v6)] {
        let data = pattern(seed, 1 << 20);
        let back = round_trip(echo, &data).await.unwrap();
        assert!(back == data, "{echo}: {} of {} bytes came back, or they differ", back.len(), data.len());
    }
    stop(route).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_teardown_after_a_clean_exit() {
    if !netns("e2e_route_teardown_after_a_clean_exit").unwrap() {
        return;
    }
    let world = World::new();
    let peer = world.listen(SocketAddr::new(RemoteNs::PEER.into(), 2222));
    let ssh = world.ssh_holding(peer.local_addr().unwrap());
    let route = started(world.route(&ssh, &["10.99.0.0/16", "fd99::/64", "10.98.0.0/16"])).await;

    // Adjacent targets stay routes of their own, so the 10.98 one beats the metric-100 route here.
    let during = leftovers();
    for expected in ["10.99.0.0/16 dev sshunnel0", "10.98.0.0/16 dev sshunnel0", "fd99::/64 dev sshunnel0", PIN] {
        assert!(during.iter().any(|line| line.starts_with(expected)), "no `{expected}` in {during:#?}");
    }
    assert!(!route.stderr().contains("goes through"), "{}", route.stderr());
    stop(route).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_teardown_after_sigkill() {
    if !netns("e2e_route_teardown_after_sigkill").unwrap() {
        return;
    }
    let world = World::new();
    let peer = world.listen(SocketAddr::new(RemoteNs::PEER.into(), 2222));
    let ssh = world.ssh_holding(peer.local_addr().unwrap());
    let targets = ["10.98.0.0/16"];

    // The client alone: the helper sees its socket close, deletes the pin and lets the device go.
    let route = started(world.route(&ssh, &targets)).await;
    signal(route.pid().unwrap(), Signal::KILL);
    let (_, stderr) = route.exit(WITHIN).await.unwrap();
    assert_eq!(leftovers_once(<[String]>::is_empty).await, Vec::<String>::new(), "stderr:\n{stderr}");

    // Both: nothing deletes the pin, and the device still goes with the last fd.
    let route = started(world.route(&ssh, &targets)).await;
    signal(helper_of(&route), Signal::KILL);
    signal(route.pid().unwrap(), Signal::KILL);
    let (_, stderr) = route.exit(WITHIN).await.unwrap();
    let left = leftovers_once(|left| left.iter().all(|line| !line.contains("sshunnel0"))).await;
    assert_eq!(left, [PIN], "stderr:\n{stderr}");

    // The next start sweeps it, though this session has no peer to pin.
    let route = world.start(&targets).await;
    assert_eq!(pins(), Vec::<String>::new());
    stop(route).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_teardown_after_the_session_drops() {
    if !netns("e2e_route_teardown_after_the_session_drops").unwrap() {
        return;
    }
    let world = World::new();
    let route = world.start(&["10.99.0.0/16"]).await;

    // The remote side dies, as when a Wi-Fi change kills ssh: everything under the client but the
    // helper is ssh's.
    let client = route.pid().unwrap();
    let helper = process_tree(helper_of(&route)).unwrap();
    for pid in process_tree(client).unwrap().into_iter().filter(|pid| *pid != client && !helper.contains(pid)) {
        signal(pid, Signal::KILL);
    }

    let (status, stderr) = route.exit(WITHIN).await.unwrap();
    assert!(!status.success(), "{stderr}");
    assert!(stderr.contains("the ssh session ended"), "{stderr}");
    assert_eq!(leftovers(), Vec::<String>::new(), "stderr:\n{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_teardown_when_the_helper_gets_sigint() {
    if !netns("e2e_route_teardown_when_the_helper_gets_sigint").unwrap() {
        return;
    }
    let world = World::new();
    let peer = world.listen(SocketAddr::new(RemoteNs::PEER.into(), 2222));
    let ssh = world.ssh_holding(peer.local_addr().unwrap());
    let route = started(world.route(&ssh, &["10.98.0.0/16"])).await;
    assert_eq!(pins(), [PIN]);

    // A Ctrl-C that reaches the helper alone (through sudo, say): it deletes its pins and exits,
    // and the client follows.
    signal(helper_of(&route), Signal::INT);

    let (status, stderr) = route.exit(WITHIN).await.unwrap();
    assert!(!status.success(), "{stderr}");
    assert!(stderr.contains("the root helper exited"), "{stderr}");
    assert_eq!(leftovers(), Vec::<String>::new(), "stderr:\n{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_teardown_when_the_helper_dies() {
    if !netns("e2e_route_teardown_when_the_helper_dies").unwrap() {
        return;
    }
    let world = World::new();
    let route = world.start(&["10.99.0.0/16"]).await;

    signal(helper_of(&route), Signal::KILL);

    let (status, stderr) = route.exit(WITHIN).await.unwrap();
    assert!(!status.success(), "{stderr}");
    assert!(stderr.contains("the root helper exited"), "{stderr}");
    assert_eq!(leftovers(), Vec::<String>::new(), "stderr:\n{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_teardown_when_ctrl_c_reaches_every_process() {
    if !netns("e2e_route_teardown_when_ctrl_c_reaches_every_process").unwrap() {
        return;
    }
    let world = World::new();
    let peer = world.listen(SocketAddr::new(RemoteNs::PEER.into(), 2222));
    let ssh = world.ssh_holding(peer.local_addr().unwrap());
    // A terminal's foreground group, led by the client: the helper and ssh are in it too.
    let mut command = world.route(&ssh, &["10.98.0.0/16", "fd99::/64"]);
    command.process_group(0);
    let route = started(command).await;

    kill_process_group(Pid::from_raw(i32::try_from(route.pid().unwrap()).unwrap()).unwrap(), Signal::INT).unwrap();

    let (status, stderr) = route.exit(WITHIN).await.unwrap();
    assert!(status.success(), "{status}; stderr:\n{stderr}");
    assert_eq!(leftovers(), Vec::<String>::new(), "stderr:\n{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_teardown_after_a_signal_during_connect() {
    if !netns("e2e_route_teardown_after_a_signal_during_connect").unwrap() {
        return;
    }
    let world = World::new();
    let connecting = world.dir.path().join("connecting");
    let ssh = shim_dir(world.dir.path(), &[("ssh", &format!(": > '{}'\nexec sleep 60", connecting.display()))]).unwrap().join("ssh");
    let route = Watched::spawn(world.route(&ssh, &["10.99.0.0/16"])).unwrap();
    let waiting = async {
        while !connecting.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    timeout(WITHIN, waiting).await.expect("the client starts ssh");

    signal(route.pid().unwrap(), Signal::TERM);

    let (status, stderr) = route.exit(WITHIN).await.unwrap();
    assert!(status.success(), "{status}; stderr:\n{stderr}");
    assert_eq!(leftovers(), Vec::<String>::new(), "stderr:\n{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_teardown_when_the_device_is_deleted() {
    if !netns("e2e_route_teardown_when_the_device_is_deleted").unwrap() {
        return;
    }
    let world = World::new();
    let peer = world.listen(SocketAddr::new(RemoteNs::PEER.into(), 2222));
    let ssh = world.ssh_holding(peer.local_addr().unwrap());
    let route = started(world.route(&ssh, &["10.98.0.0/16"])).await;

    ip(&["link", "del", "sshunnel0"]);

    let (status, stderr) = route.exit(WITHIN).await.unwrap();
    assert!(!status.success(), "{stderr}");
    assert!(stderr.contains("sshunnel0"), "{stderr}");
    // The helper still deletes its pins, and has nothing else to undo.
    assert!(!stderr.contains("the root helper exited with"), "{stderr}");
    assert_eq!(leftovers(), Vec::<String>::new(), "stderr:\n{stderr}");
}

/// `route` over the ssh `make_ssh` writes, which connects to the peer: the target captures the
/// peer, and the pin keeps ssh's connection on its old route.
async fn assert_peer_pinned(make_ssh: impl FnOnce(&World, SocketAddr) -> PathBuf) {
    let world = World::new();
    let peer = world.listen(SocketAddr::new(RemoteNs::PEER.into(), 2222));
    let ssh = make_ssh(&world, peer.local_addr().unwrap());
    let route = started(world.route(&ssh, &["10.98.0.0/16"])).await;
    let (mut conn, _) = timeout(WITHIN, peer.accept()).await.expect("ssh connected to its peer").unwrap();

    assert_eq!(pins(), [PIN]);
    still_echoes(&mut conn).await;
    stop(route).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_pins_the_ssh_peer() {
    if !netns("e2e_route_pins_the_ssh_peer").unwrap() {
        return;
    }
    assert_peer_pinned(World::ssh_holding).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_pins_a_proxy_commands_peer() {
    if !netns("e2e_route_pins_a_proxy_commands_peer").unwrap() {
        return;
    }
    assert_peer_pinned(World::ssh_through_a_proxy).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_pins_a_shared_connection_master() {
    if !netns("e2e_route_pins_a_shared_connection_master").unwrap() {
        return;
    }
    let world = World::new();
    let peer = world.listen(SocketAddr::new(RemoteNs::PEER.into(), 2222));
    // A `ControlPersist` master: it holds the connection from outside the tree of the ssh that
    // `route` runs, which holds none.
    let master = Command::new("bash")
        .args(["-c", "exec 3<>/dev/tcp/10.98.0.2/2222 && exec cat <&3 >&3"])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let (mut conn, _) = timeout(WITHIN, peer.accept()).await.expect("the master connected").unwrap();
    let remote = FakeRemote::new(&world.dir.path().join("mastered"), "sh", &[])
        .unwrap()
        .in_netns(&world.ns)
        .unwrap()
        .with_master(master.id().unwrap())
        .unwrap();
    let route = started(world.route(remote.ssh_path(), &["10.98.0.0/16"])).await;

    assert_eq!(pins(), [PIN]);
    still_echoes(&mut conn).await;
    stop(route).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_pins_nothing_for_a_peer_with_a_host_route() {
    if !netns("e2e_route_pins_nothing_for_a_peer_with_a_host_route").unwrap() {
        return;
    }
    let world = World::new();
    // A host route of the peer's own, as OpenVPN adds for its server, outranks any target's route.
    ip(&["route", "add", "10.98.0.2/32", "via", "172.31.0.2"]);
    let peer = world.listen(SocketAddr::new(RemoteNs::PEER.into(), 2222));
    let ssh = world.ssh_holding(peer.local_addr().unwrap());
    let route = started(world.route(&ssh, &["10.98.0.0/16"])).await;
    let (mut conn, _) = timeout(WITHIN, peer.accept()).await.expect("ssh connected to its peer").unwrap();

    assert_eq!(pins(), Vec::<String>::new());
    still_echoes(&mut conn).await;
    stop(route).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_pins_an_upstream_dns_server() {
    if !netns("e2e_route_pins_an_upstream_dns_server").unwrap() {
        return;
    }
    let world = World::new();
    // The machine's DNS server is on the remote's network, inside the target.
    let server = world.ns.udp(SocketAddr::new(RemoteNs::PEER.into(), 53)).unwrap();
    server.set_nonblocking(true).unwrap();
    let server = UdpSocket::from_std(server).unwrap();
    tokio::spawn(async move {
        let mut query = [0; 512];
        while let Ok((n, from)) = server.recv_from(&mut query).await {
            let _ = server.send_to(&query[..n], from).await;
        }
    });
    use_dns_server(world.dir.path(), RemoteNs::PEER);
    let route = world.start(&["10.98.0.0/16"]).await;

    assert_eq!(pins(), [PIN]);
    // A query still reaches the server, where the device would answer administratively prohibited.
    let client = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    client.connect((RemoteNs::PEER, 53)).await.unwrap();
    client.send(b"a query").await.unwrap();
    let mut answer = [0; 16];
    let n = timeout(WITHIN, client.recv(&mut answer)).await.expect("the DNS server answers").unwrap();
    assert_eq!(&answer[..n], b"a query");
    stop(route).await;
}

/// Points both files `route` reads its DNS servers from at `server`, by bind mounts in the test's
/// own mount namespace (see `tests::netns`).
fn use_dns_server(dir: &Path, server: Ipv4Addr) {
    let conf = dir.join("resolv.conf");
    std::fs::write(&conf, format!("nameserver {server}\n")).unwrap();
    for file in ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"] {
        if Path::new(file).exists() {
            let mounted = StdCommand::new("mount").arg("--bind").arg(&conf).arg(file).status().unwrap();
            assert!(mounted.success(), "bind-mounting over {file}: {mounted}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_refuses_a_connected_subnet() {
    if !netns("e2e_route_refuses_a_connected_subnet").unwrap() {
        return;
    }
    let world = World::new();

    let route = Watched::spawn(world.route(world.remote.ssh_path(), &["172.31.0.0/30"])).unwrap();
    let (status, stderr) = route.exit(WITHIN).await.unwrap();

    assert!(!status.success(), "{stderr}");
    assert!(stderr.contains("'172.31.0.0/30' is inside the connected subnet 172.31.0.0/30"), "{stderr}");
    assert!(world.remote.last_ssh_args().is_err(), "ssh ran before the targets were checked");
    assert_eq!(leftovers(), Vec::<String>::new(), "stderr:\n{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_refuses_a_destination_with_a_route_of_its_own() {
    if !netns("e2e_route_refuses_a_destination_with_a_route_of_its_own").unwrap() {
        return;
    }
    let world = World::new();
    // Each at the metric sshunnel's own route would get (0 for v4, 1024 for v6), so `ip route add`
    // would fail on it.
    ip(&["route", "add", "10.97.0.0/16", "via", "172.31.0.2"]);
    ip(&["-6", "route", "add", "unreachable", "fd97::/64"]);

    let route = Watched::spawn(world.route(world.remote.ssh_path(), &["10.97.0.0/16", "fd97::/64"])).unwrap();
    let (status, stderr) = route.exit(WITHIN).await.unwrap();

    // Both at once, before ssh runs.
    assert!(!status.success(), "{stderr}");
    assert!(stderr.contains("'10.97.0.0/16' already has a route of its own (via 172.31.0.2 dev cl0, metric 0)"), "{stderr}");
    assert!(stderr.contains("'fd97::/64' already has a route of its own (unreachable"), "{stderr}");
    assert!(world.remote.last_ssh_args().is_err(), "ssh ran before the targets were checked");
    assert_eq!(leftovers(), Vec::<String>::new(), "stderr:\n{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_one_session_at_a_time() {
    if !netns("e2e_route_one_session_at_a_time").unwrap() {
        return;
    }
    let world = World::new();
    let echo = world.echo(SocketAddr::new(RemoteNs::HOST.into(), 0));
    let first = world.start(&["10.99.0.0/16"]).await;

    let second = Watched::spawn(world.route(world.remote.ssh_path(), &["10.98.0.0/16"])).unwrap();
    let (status, stderr) = second.exit(WITHIN).await.unwrap();
    assert!(!status.success(), "{stderr}");
    assert!(stderr.contains("another sshunnel route is running"), "{stderr}");

    // The first one carries on.
    let data = pattern(3, 64 * 1024);
    assert!(round_trip(echo, &data).await.unwrap() == data);
    stop(first).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_patterns_need_the_init_netns() {
    if !netns("e2e_route_patterns_need_the_init_netns").unwrap() {
        return;
    }
    // The helper's check holds only while pid 1 lives outside the test's namespace, as the
    // machine's init does (see `tests::netns`).
    assert!(!same_netns_as_init(), "the test's network namespace passes for init's");
    let world = World::new();

    // resolved serves only the host's namespace: the client's check refuses (resolved doesn't
    // answer here) or the helper's does (this isn't pid 1's namespace).
    let route = Watched::spawn(world.route(world.remote.ssh_path(), &["10.99.0.0/16", "*.corp.example"])).unwrap();
    let (status, stderr) = route.exit(WITHIN).await.unwrap();

    assert!(!status.success(), "{stderr}");
    assert!(stderr.contains("domain patterns need"), "{stderr}");
    assert_eq!(leftovers(), Vec::<String>::new(), "stderr:\n{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_warns_when_another_rule_wins() {
    if !netns("e2e_route_warns_when_another_rule_wins").unwrap() {
        return;
    }
    let world = World::new();
    // Another tool's policy routing, Tailscale-style: a rule ahead of main sends the range to its
    // own table.
    ip(&["route", "add", "10.99.0.0/16", "via", "172.31.0.2", "table", "52"]);
    ip(&["rule", "add", "to", "10.99.0.0/16", "lookup", "52", "priority", "100"]);

    let route = world.start(&["10.99.0.0/16"]).await;

    let stderr = route.stderr();
    assert!(stderr.contains(&format!("10.99.0.0/16 goes through {}, not sshunnel0", RemoteNs::LINK)), "{stderr}");
    stop(route).await;
}
