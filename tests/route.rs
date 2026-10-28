//! `sshunnel route` against a real TUN device and real routes. Each test runs again in throwaway
//! namespaces (see `tests::netns`): the client, root over a network namespace of its own, and the
//! remote's network in a second one across a veth pair (`RemoteNs`), where the relay runs. Named
//! `e2e_*` because they spawn the binary.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::{
        fd::{AsRawFd as _, OwnedFd},
        unix::fs::PermissionsExt as _,
    },
    path::{Path, PathBuf},
    process::Command as StdCommand,
    time::{Duration, Instant},
};

use pretty_assertions::assert_eq;
use rustix::process::{Pid, Signal, kill_process, kill_process_group};
use sshunnel::{
    route::{PING_WARNING, helper::Setup, peers::process_tree, system::same_netns_as_init},
    tests::{self, FakeRemote, Pinged, RemoteNs, Watched, allow_ping, echo_on, netns, pattern, ping, relay_dir, round_trip, route_command, shim_dir, start_helper, udp_echo_on},
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
        Self::on(RemoteNs::new().unwrap())
    }

    /// A world whose remote may not ping.
    fn without_ping() -> Self {
        Self::on(RemoteNs::without_ping().unwrap())
    }

    fn on(ns: RemoteNs) -> Self {
        let dir = TempDir::new().unwrap();
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

    /// A UDP echo server on the remote, at `addr`; returns its address.
    fn udp_echo(&self, addr: SocketAddr) -> SocketAddr {
        let socket = self.ns.udp(addr).unwrap();
        socket.set_nonblocking(true).unwrap();
        udp_echo_on(UdpSocket::from_std(socket).unwrap()).unwrap()
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

/// SIGTERM, then a clean exit that leaves nothing behind; returns all of stderr.
async fn stop(route: Watched) -> String {
    signal(route.pid().unwrap(), Signal::TERM);
    let (status, stderr) = route.exit(WITHIN).await.unwrap();
    assert!(status.success(), "{status}; stderr:\n{stderr}");
    assert_eq!(leftovers(), Vec::<String>::new(), "stderr:\n{stderr}");
    stderr
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
    tests::ip(args).unwrap()
}

/// The pinned routes. (`ip route show proto 222` would leave the protocol out of each line.)
fn pins() -> Vec<String> {
    tests::routes().unwrap().into_iter().filter(|route| route.contains("proto 222")).collect()
}

/// What `route` has in this namespace: its device, any route on the device, any pinned route.
fn leftovers() -> Vec<String> {
    tests::leftovers().unwrap()
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
async fn e2e_route_prints_a_ready_line() {
    if !netns("e2e_route_prints_a_ready_line").unwrap() {
        return;
    }
    let world = World::new();
    let mut route = world.start(&["10.99.0.0/16"]).await;

    route.line("sshunnel: check it with ", WITHIN).await.unwrap();
    route.line("sshunnel: ready (pid ", WITHIN).await.unwrap();
    stop(route).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_a_closed_port_is_refused() {
    if !netns("e2e_route_a_closed_port_is_refused").unwrap() {
        return;
    }
    let world = World::new();
    let route = world.start(&["10.99.0.0/16"]).await;

    // Nothing listens there on the remote: the relay's dial is refused, and so is the app's connect.
    let connect = timeout(WITHIN, TcpStream::connect((RemoteNs::HOST, 9))).await.expect("the connect ends");
    let refused = connect.expect_err("connected to a closed port");
    assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused, "{refused}");
    stop(route).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_udp_cidr_round_trips_v4_and_v6() {
    if !netns("e2e_route_udp_cidr_round_trips_v4_and_v6").unwrap() {
        return;
    }
    let world = World::new();
    let v4 = world.udp_echo(SocketAddr::new(RemoteNs::HOST.into(), 0));
    let v6 = world.udp_echo(SocketAddr::new(RemoteNs::HOST6.into(), 0));
    let route = world.start(&["10.99.0.0/16", "fd99::/64"]).await;

    for (seed, echo) in [(1, v4), (2, v6)] {
        let any: IpAddr = if echo.is_ipv4() { Ipv4Addr::UNSPECIFIED.into() } else { Ipv6Addr::UNSPECIFIED.into() };
        let app = UdpSocket::bind((any, 0)).await.unwrap();
        app.connect(echo).await.unwrap();
        let mut back = vec![0; 2048];
        // 1 to 1 400 bytes, one at a time: each waits for its echo, so none is lost to a full queue.
        for i in 0..20 {
            let data = pattern(seed * 100 + i, usize::try_from(1 + i * 1399 / 19).unwrap());
            app.send(&data).await.unwrap();
            let n = timeout(WITHIN, app.recv(&mut back)).await.expect("the echo comes back").unwrap();
            assert!(back[..n] == data[..], "{echo}: datagram {i} came back as {n} bytes, or differs");
        }
    }
    stop(route).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_udp_cidr_closed_port_is_refused() {
    if !netns("e2e_route_udp_cidr_closed_port_is_refused").unwrap() {
        return;
    }
    let world = World::new();
    let route = world.start(&["10.99.0.0/16"]).await;

    // Nothing listens there on the remote: its port unreachable reaches the relay's socket, and the
    // app's socket hears it as it would from a real network.
    let app = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    app.connect((RemoteNs::HOST, 9)).await.unwrap();
    app.send(b"anyone there?").await.unwrap();
    let recv = timeout(WITHIN, app.recv(&mut [0; 64])).await.expect("the recv ends");
    let refused = recv.expect_err("a closed port answered");
    assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused, "{refused}");
    stop(route).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_ping_gets_echo_replies_v4_and_v6() {
    if !netns("e2e_route_ping_gets_echo_replies_v4_and_v6").unwrap() {
        return;
    }
    let world = World::new();
    allow_ping().unwrap();
    let route = world.start(&["10.99.0.0/16", "fd99::/64"]).await;

    // Nothing here reaches either host but the device, so the replies come from the relay's ping
    // sockets on the remote's network.
    for host in [IpAddr::V4(RemoteNs::HOST), IpAddr::V6(RemoteNs::HOST6)] {
        assert_eq!(ping(host, WITHIN).await.unwrap(), Pinged::Reply, "{host}");
    }
    stop(route).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_ping_refused_remote_is_admin_prohibited_and_warns_once() {
    if !netns("e2e_route_ping_refused_remote_is_admin_prohibited_and_warns_once").unwrap() {
        return;
    }
    let world = World::without_ping();
    allow_ping().unwrap();
    let route = world.start(&["10.99.0.0/16", "fd99::/64"]).await;

    // Administratively prohibited reaches the app's ping socket as its family's error: ICMP's as
    // EHOSTUNREACH, ICMPv6's as EACCES.
    for (host, error) in [
        (IpAddr::V4(RemoteNs::HOST), io::ErrorKind::HostUnreachable),
        (IpAddr::V6(RemoteNs::HOST6), io::ErrorKind::PermissionDenied),
    ] {
        assert_eq!(ping(host, WITHIN).await.unwrap(), Pinged::Refused(error), "{host}");
    }
    let stderr = stop(route).await;
    assert_eq!(stderr.matches(PING_WARNING).count(), 1, "{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_an_unreachable_host_is_unreachable() {
    if !netns("e2e_route_an_unreachable_host_is_unreachable").unwrap() {
        return;
    }
    let world = World::new();
    let route = world.start(&["10.99.0.0/16"]).await;

    // Inside the target, but nothing on the remote's network routes it: the relay's dial fails
    // there, and the app's connect here fails as the spec promises.
    let connect = timeout(WITHIN, TcpStream::connect((Ipv4Addr::new(10, 99, 0, 77), 80))).await.expect("the connect ends");
    let unreachable = connect.expect_err("connected to an unreachable host");
    assert_eq!(unreachable.kind(), io::ErrorKind::HostUnreachable, "{unreachable}");
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
    // The v6 one is at metric 1 (the space rules out 1024).
    let during = leftovers();
    for expected in ["10.99.0.0/16 dev sshunnel0", "10.98.0.0/16 dev sshunnel0", "fd99::/64 dev sshunnel0 metric 1 ", PIN] {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_teardown_deletes_a_device_the_client_made_persistent() {
    if !netns("e2e_route_teardown_deletes_a_device_the_client_made_persistent").unwrap() {
        return;
    }
    let world = World::new();
    // The test plays `route`'s side of the helper, so it holds the device's fd itself.
    let setup = Setup {
        include: vec!["10.98.0.0/16".to_owned()],
        exclude: Vec::new(),
        pins: vec![RemoteNs::PEER.into()],
    };
    let mut helper = start_helper(Path::new(env!("CARGO_BIN_EXE_sshunnel")), world.dir.path(), &setup).await.unwrap();
    let tun = helper.take_tun().unwrap();
    assert_eq!(pins(), [PIN]);

    // The helper sees its socket close, tears down and exits, while this fd outlives it.
    helper.stop().await.unwrap();
    // Then the client asks the driver to keep the device past its last close. Once the helper has
    // deleted the device, this fd is detached and the driver refuses.
    let _ = persist(&tun);
    drop(tun);

    assert_eq!(leftovers(), Vec::<String>::new());
}

/// Sets the persist flag on a TUN device through `tun`, so the device outlives its last fd. Any
/// holder of an fd on the device can, without a capability.
fn persist(tun: &OwnedFd) -> io::Result<()> {
    // SAFETY: TUNSETPERSIST takes an int by value (non-zero sets the flag), and `tun` is an open fd
    // for the whole call.
    let set = unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNSETPERSIST, 1) };
    if set == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
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
    // The machine's DNS server is on the remote's network, inside the target. It answers with the
    // address each query came from.
    let server = world.ns.udp(SocketAddr::new(RemoteNs::PEER.into(), 53)).unwrap();
    server.set_nonblocking(true).unwrap();
    let server = UdpSocket::from_std(server).unwrap();
    tokio::spawn(async move {
        let mut query = [0; 512];
        while let Ok((_, from)) = server.recv_from(&mut query).await {
            let _ = server.send_to(from.ip().to_string().as_bytes(), from).await;
        }
    });
    use_dns_server(world.dir.path(), RemoteNs::PEER);
    let route = world.start(&["10.98.0.0/16"]).await;

    assert_eq!(pins(), [PIN]);
    // A query goes around the device, over the veth: through the device and the relay, it would
    // reach the server from the remote's own side.
    let client = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    client.connect((RemoteNs::PEER, 53)).await.unwrap();
    client.send(b"a query").await.unwrap();
    let mut answer = [0; 64];
    let n = timeout(WITHIN, client.recv(&mut answer)).await.expect("the DNS server answers").unwrap();
    assert_eq!(&answer[..n], RemoteNs::LINK_ADDR.to_string().as_bytes());
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
    // Its kernel prefix route is in main too, which makes it no second refusal.
    assert_eq!(stderr.matches("'172.31.0.0/30'").count(), 1, "{stderr}");
    assert!(world.remote.last_ssh_args().is_err(), "ssh ran before the targets were checked");
    assert_eq!(leftovers(), Vec::<String>::new(), "stderr:\n{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_route_refuses_a_destination_with_a_route_of_its_own() {
    if !netns("e2e_route_refuses_a_destination_with_a_route_of_its_own").unwrap() {
        return;
    }
    let world = World::new();
    // Each at the metric sshunnel's own route would get (0 for v4, 1 for v6), so `ip route add`
    // would fail on it. One at the kernel's v6 default, 1024, is no collision: sshunnel's wins.
    ip(&["route", "add", "10.97.0.0/16", "via", "172.31.0.2"]);
    ip(&["-6", "route", "add", "unreachable", "fd97::/64", "metric", "1"]);
    ip(&["-6", "route", "add", "unreachable", "fd96::/64"]);

    let route = Watched::spawn(world.route(world.remote.ssh_path(), &["10.97.0.0/16", "fd97::/64", "fd96::/64"])).unwrap();
    let (status, stderr) = route.exit(WITHIN).await.unwrap();

    // Both at once, before ssh runs.
    assert!(!status.success(), "{stderr}");
    assert!(stderr.contains("'10.97.0.0/16' already has a route of its own (via 172.31.0.2 dev cl0, metric 0)"), "{stderr}");
    let fd97 = stderr.lines().find(|line| line.contains("'fd97::/64' already has a route of its own (unreachable"));
    assert!(fd97.is_some_and(|line| line.contains(", metric 1)")), "{stderr}");
    assert!(!stderr.contains("'fd96::/64'"), "{stderr}");
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

#[test]
fn e2e_helper_failed_exits_with_its_own_status() {
    let dir = TempDir::new().unwrap();

    let status = StdCommand::new(env!("CARGO_BIN_EXE_sshunnel"))
        .args(["helper", "--socket"])
        .arg(dir.path().join("missing.sock"))
        .env_remove("SUDO_UID")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();

    assert_eq!(status.code(), Some(i32::from(sshunnel::route::helper::FAILED)));
}
