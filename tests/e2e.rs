//! End to end: spawn the real binary as a user would, inside a scratch directory, with the remote
//! played by a fake `ssh` (see `FakeRemote`). Tests here are named `e2e_*`, which nextest
//! serializes and retries (see `.config/nextest.toml`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    net::SocketAddr,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use sshunnel::{
    arch::Arch,
    forward::Forward,
    relays::Relays,
    session::ready_line,
    tests::{FakeRemote, echo_server, host_arch, pattern, relay_dir, resetting_server, udp_echo_server, udp_peer_server},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::{TcpStream, UdpSocket},
    process::{Child, Command},
    sync::watch,
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};

/// The binary with the env vars it reads cleared, so the host environment can't leak in.
fn sshunnel(dir: &TempDir) -> Command {
    isolated(Command::new(env!("CARGO_BIN_EXE_sshunnel")), dir)
}

/// The binary under `ulimit -n fds`, so it runs out of file descriptors on demand.
fn sshunnel_with_fd_limit(dir: &TempDir, fds: u32) -> Command {
    let mut cmd = Command::new("sh");
    cmd.args(["-c", &format!("ulimit -n {fds} && exec \"$0\" \"$@\""), env!("CARGO_BIN_EXE_sshunnel")]);
    isolated(cmd, dir)
}

fn isolated(mut cmd: Command, dir: &TempDir) -> Command {
    cmd.current_dir(dir.path())
        .env_remove("SSHUNNEL_RELAY_DIR")
        .env_remove("SSHUNNEL_SSH")
        .env_remove("RUST_LOG")
        .kill_on_drop(true);
    cmd
}

/// Runs `cmd forward` with one `-L` per spec and waits for each spec's first `forwarding <addr> ->
/// ...` line; returns the child, those addresses in spec order, and every stderr line so far, which
/// keeps filling in the background. A line belongs to the spec whose target it names, so the specs'
/// targets must differ.
async fn start_forwards(mut cmd: Command, dir: &TempDir, specs: &[&str]) -> (Child, Vec<String>, watch::Receiver<Vec<String>>) {
    let remote = FakeRemote::new(dir.path(), "sh", &[]).unwrap();
    let relays = relay_dir(dir.path()).unwrap();
    cmd.arg("forward");
    for spec in specs {
        cmd.args(["-L", spec]);
    }
    let mut child = cmd
        .arg("--ssh-cmd")
        .arg(remote.ssh_path())
        .arg("--relay-dir")
        .arg(&relays)
        .arg("fake-host")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A forwarding line ends in its spec's target as `Forward` displays it.
    let targets: Vec<String> = specs.iter().map(|spec| spec.parse::<Forward>().unwrap().to_string().split_once(" -> ").unwrap().1.to_owned()).collect();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let (seen, stderr) = watch::channel(Vec::new());
    let mut addrs: Vec<Option<String>> = vec![None; specs.len()];
    timeout(Duration::from_secs(30), async {
        while addrs.iter().any(Option::is_none) {
            let line = lines.next_line().await.unwrap().unwrap_or_else(|| panic!("sshunnel exited; stderr:\n{}", seen.borrow().join("\n")));
            if let Some((addr, target)) = line.strip_prefix("sshunnel: forwarding ").and_then(|rest| rest.split_once(" -> ")) {
                let spec = targets.iter().zip(&mut addrs).find(|(t, a)| a.is_none() && *t == target);
                if let Some((_, slot)) = spec {
                    *slot = Some(addr.to_owned());
                }
            }
            seen.send_modify(|seen| seen.push(line));
        }
    })
    .await
    .expect("sshunnel starts forwarding");
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            seen.send_modify(|seen| seen.push(line));
        }
    });
    (child, addrs.into_iter().map(Option::unwrap).collect(), stderr)
}

/// [`start_forwards`] with the one spec `0:{target}`; returns its first address.
async fn start_forward(cmd: Command, dir: &TempDir, target: &str) -> (Child, String, watch::Receiver<Vec<String>>) {
    let (child, mut addrs, stderr) = start_forwards(cmd, dir, &[&format!("0:{target}")]).await;
    (child, addrs.remove(0), stderr)
}

/// Waits for a forwarding line naming `target` on an address that starts with `prefix`; returns
/// that address.
async fn listening_on(stderr: &mut watch::Receiver<Vec<String>>, prefix: &str, target: &str) -> String {
    let find = |lines: &[String]| {
        lines.iter().find_map(|line| {
            let (addr, to) = line.strip_prefix("sshunnel: forwarding ")?.split_once(" -> ")?;
            (addr.starts_with(prefix) && to == target).then(|| addr.to_owned())
        })
    };
    let lines = timeout(Duration::from_secs(10), stderr.wait_for(|lines| find(lines).is_some()))
        .await
        .expect("sshunnel listens there")
        .unwrap();
    find(&lines).unwrap()
}

async fn echo_through(addr: &str, data: &[u8]) -> Vec<u8> {
    let socket = TcpStream::connect(addr).await.unwrap();
    let (mut r, mut w) = socket.into_split();
    let sent = data.to_vec();
    let writer = tokio::spawn(async move {
        w.write_all(&sent).await.unwrap();
        w.shutdown().await.unwrap();
    });
    let mut reply = Vec::new();
    timeout(Duration::from_secs(30), r.read_to_end(&mut reply)).await.expect("the echo finishes").unwrap();
    writer.await.unwrap();
    reply
}

#[tokio::test]
async fn e2e_forward_prints_a_ready_line() {
    let dir = TempDir::new().unwrap();
    let echo = echo_server().await.unwrap();
    let (child, _, mut stderr) = start_forward(sshunnel(&dir), &dir, &format!("127.0.0.1:{}", echo.port())).await;

    let ready = ready_line(child.id().unwrap());
    timeout(Duration::from_secs(10), stderr.wait_for(|lines| lines.contains(&ready)))
        .await
        .expect("the ready line arrives")
        .unwrap();
    let lines = stderr.borrow();
    let last_forwarding = lines.iter().rposition(|line| line.starts_with("sshunnel: forwarding ")).unwrap();
    let at = lines.iter().position(|line| *line == ready).unwrap();
    assert!(at > last_forwarding, "the ready line follows the forwarding lines: {lines:?}");
}

#[tokio::test]
async fn e2e_forward_stopped_by_a_signal_exits_0() {
    for signal in [rustix::process::Signal::TERM, rustix::process::Signal::INT] {
        let dir = TempDir::new().unwrap();
        let echo = echo_server().await.unwrap();
        let (mut child, _, mut stderr) = start_forward(sshunnel(&dir), &dir, &format!("127.0.0.1:{}", echo.port())).await;
        let pid = child.id().unwrap();
        let ready = ready_line(pid);
        timeout(Duration::from_secs(10), stderr.wait_for(|lines| lines.contains(&ready)))
            .await
            .expect("the ready line arrives")
            .unwrap();

        rustix::process::kill_process(rustix::process::Pid::from_raw(i32::try_from(pid).unwrap()).unwrap(), signal).unwrap();

        let status = timeout(Duration::from_secs(10), child.wait()).await.expect("sshunnel stops").unwrap();
        assert_eq!(status.code(), Some(0), "{signal:?}: {status}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_forward_carries_tcp() {
    let dir = TempDir::new().unwrap();
    let echo = echo_server().await.unwrap();
    let (_child, addr, stderr) = start_forward(sshunnel(&dir), &dir, &format!("127.0.0.1:{}", echo.port())).await;
    let stderr = stderr.borrow();
    assert!(stderr.iter().any(|line| line.contains("pushed to")), "the first run pushes the relay: {stderr:?}");

    let data = pattern(7, 1 << 20);
    assert!(echo_through(&addr, &data).await == data);

    // Many connections at once share the one ssh session.
    let mut clients = tokio::task::JoinSet::new();
    for seed in 0..20 {
        let addr = addr.clone();
        clients.spawn(async move {
            let data = pattern(seed, 64 * 1024);
            assert!(echo_through(&addr, &data).await == data, "connection {seed}");
        });
    }
    while let Some(done) = clients.join_next().await {
        done.unwrap();
    }
}

#[tokio::test]
async fn e2e_forward_listens_on_the_ipv6_loopback_too() {
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        return assert!(std::env::var_os("CI").is_none(), "CI runners have an IPv6 loopback");
    }
    let dir = TempDir::new().unwrap();
    let echo = echo_server().await.unwrap();
    let (_child, _, mut stderr) = start_forward(sshunnel(&dir), &dir, &format!("127.0.0.1:{}", echo.port())).await;
    // `-L port:host:hostport` binds like `ssh -L`: each family's loopback, so a client that tries
    // ::1 first (Node 17+, say) reaches it too.
    let listening = stderr.wait_for(|lines| lines.iter().any(|line| line.starts_with("sshunnel: forwarding [::1]:")));
    let lines = timeout(Duration::from_secs(10), listening).await.expect("sshunnel listens on ::1").unwrap().clone();
    let v6 = lines
        .iter()
        .find_map(|line| line.strip_prefix("sshunnel: forwarding ")?.split_whitespace().next().filter(|a| a.starts_with("[::1]")))
        .unwrap();

    let data = pattern(11, 64 * 1024);
    assert!(echo_through(v6, &data).await == data);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_forward_survives_running_out_of_file_descriptors() {
    let dir = TempDir::new().unwrap();
    let echo = echo_server().await.unwrap();
    let (mut child, addr, mut stderr) = start_forward(sshunnel_with_fd_limit(&dir, 32), &dir, &format!("127.0.0.1:{}", echo.port())).await;

    // More connections than the forwarder has descriptors for, so an accept fails with EMFILE.
    let mut held = Vec::new();
    for _ in 0..64 {
        held.extend(TcpStream::connect(&addr).await.ok());
    }
    let failed = stderr.wait_for(|lines| lines.iter().any(|line| line.contains("accepting a local connection")));
    timeout(Duration::from_secs(10), failed).await.expect("an accept fails").unwrap();

    drop(held);
    let data = pattern(9, 64 * 1024);
    let served = TcpStream::connect(&addr).await.is_ok() && echo_through(&addr, &data).await == data;
    assert!(served, "the forwarder serves again once descriptors free up; stderr:\n{}", stderr.borrow().join("\n"));
    assert!(child.try_wait().unwrap().is_none(), "the forwarder is still running");
}

#[tokio::test]
async fn e2e_forward_remote_reset_reaches_the_app() {
    let dir = TempDir::new().unwrap();
    let target = resetting_server(b"partial").await.unwrap();
    let (_child, addr, _) = start_forward(sshunnel(&dir), &dir, &target.to_string()).await;
    let mut socket = TcpStream::connect(&addr).await.unwrap();
    let mut partial = [0u8; 7];
    timeout(Duration::from_secs(10), socket.read_exact(&mut partial)).await.expect("the payload arrives").unwrap();
    assert_eq!(&partial, b"partial");
    socket.write_all(b"!").await.unwrap();
    let next = timeout(Duration::from_secs(10), socket.read(&mut partial)).await.expect("the app's read ends");
    assert_eq!(next.unwrap_err().kind(), std::io::ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn e2e_forward_to_a_closed_port_closes_the_local_connection() {
    let dir = TempDir::new().unwrap();
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let (_child, addr, _) = start_forward(sshunnel(&dir), &dir, &closed.to_string()).await;
    let mut socket = TcpStream::connect(&addr).await.unwrap();
    let mut buf = Vec::new();
    let read = timeout(Duration::from_secs(10), socket.read_to_end(&mut buf)).await.expect("the local connection closes");
    assert!(read.is_err() || buf.is_empty());
}

/// Sends `data` on `socket` and waits up to `within` for a datagram back; returns it.
async fn udp_exchange(socket: &UdpSocket, data: &[u8], within: Duration) -> Vec<u8> {
    socket.send(data).await.unwrap();
    let mut buf = vec![0; 65_536];
    let n = timeout(within, socket.recv(&mut buf)).await.expect("a datagram comes back").unwrap();
    buf.truncate(n);
    buf
}

/// A UDP socket on `bind`, connected to `to`.
async fn udp_to(bind: &str, to: &str) -> UdpSocket {
    let socket = UdpSocket::bind(bind).await.unwrap();
    socket.connect(to).await.unwrap();
    socket
}

#[tokio::test]
async fn e2e_forward_udp_round_trips_datagrams() {
    let dir = TempDir::new().unwrap();
    let echo = udp_echo_server().await.unwrap();
    let (_child, addrs, _) = start_forwards(sshunnel(&dir), &dir, &[&format!("0:127.0.0.1:{}/udp", echo.port())]).await;
    let socket = udp_to("127.0.0.1:0", &addrs[0]).await;

    // Up to the largest datagram IPv4 carries.
    for (seed, len) in (0u64..).zip([1, 100, 1_200, 1_472, 9_000, 65_507]) {
        let data = pattern(seed, len);
        assert!(udp_exchange(&socket, &data, Duration::from_secs(10)).await == data, "a datagram of {len} bytes");
    }
}

#[tokio::test]
async fn e2e_forward_udp_listens_on_the_ipv6_loopback_too() {
    if std::net::UdpSocket::bind("[::1]:0").is_err() {
        return assert!(std::env::var_os("CI").is_none(), "CI runners have an IPv6 loopback");
    }
    let dir = TempDir::new().unwrap();
    let echo = udp_echo_server().await.unwrap();
    let target = format!("127.0.0.1:{}/udp", echo.port());
    let (_child, _, mut stderr) = start_forwards(sshunnel(&dir), &dir, &[&format!("0:{target}")]).await;
    let v6 = listening_on(&mut stderr, "[::1]:", &target).await;
    let socket = udp_to("[::1]:0", &v6).await;

    let data = pattern(13, 1_200);
    assert!(udp_exchange(&socket, &data, Duration::from_secs(10)).await == data);
}

#[tokio::test]
async fn e2e_forward_udp_one_flow_per_sender() {
    let dir = TempDir::new().unwrap();
    let echo = udp_echo_server().await.unwrap();
    let (_child, addrs, _) = start_forwards(sshunnel(&dir), &dir, &[&format!("0:127.0.0.1:{}/udp", echo.port())]).await;
    let senders = [(b'a', udp_to("127.0.0.1:0", &addrs[0]).await), (b'b', udp_to("127.0.0.1:0", &addrs[0]).await)];

    // Interleaved, so one flow per listener would cross the replies.
    for round in 0..10u8 {
        for (tag, socket) in &senders {
            socket.send(&[*tag, round]).await.unwrap();
        }
    }
    let mut buf = [0; 16];
    for (tag, socket) in &senders {
        let mut got = Vec::new();
        for _ in 0..10 {
            let n = timeout(Duration::from_secs(10), socket.recv(&mut buf)).await.expect("an echo comes back").unwrap();
            got.push(buf[..n].to_vec());
        }
        assert_eq!(got, (0..10u8).map(|round| vec![*tag, round]).collect::<Vec<_>>());
    }
    for (_, socket) in &senders {
        assert!(timeout(Duration::from_millis(200), socket.recv(&mut buf)).await.is_err(), "no stray datagram");
    }
}

/// Review Focus 4: a reply leaves through the listener its sender used.
#[tokio::test]
async fn e2e_forward_udp_replies_leave_through_the_senders_listener() {
    if std::net::UdpSocket::bind("[::1]:0").is_err() {
        return assert!(std::env::var_os("CI").is_none(), "CI runners have an IPv6 loopback");
    }
    let dir = TempDir::new().unwrap();
    let echo = udp_echo_server().await.unwrap();
    let target = format!("127.0.0.1:{}/udp", echo.port());
    let (_child, addrs, mut stderr) = start_forwards(sshunnel(&dir), &dir, &[&format!("0:{target}")]).await;
    let v6 = listening_on(&mut stderr, "[::1]:", &target).await;

    for (bind, listener) in [("127.0.0.1:0", &addrs[0]), ("[::1]:0", &v6)] {
        // Unconnected, so a reply from anywhere else arrives to be seen.
        let socket = UdpSocket::bind(bind).await.unwrap();
        socket.send_to(b"which", listener).await.unwrap();
        let mut buf = [0; 16];
        let (n, from) = timeout(Duration::from_secs(10), socket.recv_from(&mut buf)).await.expect("the echo comes back").unwrap();
        assert_eq!(&buf[..n], b"which");
        assert_eq!(from, listener.parse::<SocketAddr>().unwrap(), "the reply to a sender on {bind}");
    }
}

/// A datagram the relay's socket refuses is dropped and the flow lives on: the remote sees the
/// sender's next datagram come from the same relay port.
#[tokio::test]
async fn e2e_forward_udp_drops_a_datagram_the_relay_cannot_send_and_keeps_the_flow() {
    if std::net::UdpSocket::bind("[::1]:0").is_err() {
        return assert!(std::env::var_os("CI").is_none(), "CI runners have an IPv6 loopback");
    }
    let dir = TempDir::new().unwrap();
    let server = udp_peer_server().await.unwrap();
    let target = format!("127.0.0.1:{}/udp", server.port());
    let (_child, _, mut stderr) = start_forwards(sshunnel(&dir), &dir, &[&format!("0:{target}")]).await;
    let socket = udp_to("[::1]:0", &listening_on(&mut stderr, "[::1]:", &target).await).await;
    let before = udp_exchange(&socket, b"before", Duration::from_secs(10)).await;

    // IPv6 carries this datagram to the listener, but it's over IPv4's 65 507-byte limit, so the
    // relay's send to the server fails (EMSGSIZE), as a send past a path's lowered MTU does.
    socket.send(&pattern(5, 65_520)).await.unwrap();
    let after = udp_exchange(&socket, b"after", Duration::from_secs(10)).await;
    assert_eq!(String::from_utf8_lossy(&after), String::from_utf8_lossy(&before), "the relay's source port moved");
}

/// Floods `to` with 1 200-byte datagrams in a tight loop until dropped, reading and discarding the
/// replies; also returns how many replies came back.
async fn blast(to: &str) -> (JoinSet<()>, Arc<AtomicU64>) {
    let socket = Arc::new(udp_to("127.0.0.1:0", to).await);
    let replies = Arc::new(AtomicU64::new(0));
    let mut blaster = JoinSet::new();
    let sender = Arc::clone(&socket);
    blaster.spawn(async move {
        let datagram = pattern(99, 1_200);
        loop {
            let _ = sender.send(&datagram).await;
        }
    });
    let counted = Arc::clone(&replies);
    blaster.spawn(async move {
        let mut buf = [0; 2_048];
        loop {
            if socket.recv(&mut buf).await.is_ok() {
                counted.fetch_add(1, Ordering::Relaxed);
            }
        }
    });
    // The flood is on once its flow has opened and echoes flow back.
    let flowing = async {
        while replies.load(Ordering::Relaxed) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    timeout(Duration::from_secs(10), flowing).await.expect("the flood's echoes come back");
    (blaster, replies)
}

/// Runs up to `n` request and reply exchanges on `socket`, each given 1 s, stopping once more than
/// `losses` have failed; returns how many got their reply.
async fn exchanges(socket: &UdpSocket, n: u32, losses: u32) -> u32 {
    let mut answered = 0;
    let mut buf = [0; 16];
    for i in 0..n {
        let request = i.to_be_bytes();
        socket.send(&request).await.unwrap();
        // A late reply to an earlier exchange may come first: skip it.
        let reply = async { while socket.recv(&mut buf).await.ok() != Some(request.len()) || buf[..request.len()] != request {} };
        if timeout_at(Instant::now() + Duration::from_secs(1), reply).await.is_ok() {
            answered += 1;
        }
        if i + 1 - answered > losses {
            break;
        }
    }
    answered
}

/// uat-005: a UDP flood on the session leaves a TCP transfer's time within a bound set from its
/// unloaded time. The bound's floor is tuned from measured runs (`.prds/PRD-0006.log.md`, T-004).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_udp_flood_does_not_stall_tcp() {
    let dir = TempDir::new().unwrap();
    let (tcp, udp) = (echo_server().await.unwrap(), udp_echo_server().await.unwrap());
    let specs = [format!("0:127.0.0.1:{}", tcp.port()), format!("0:127.0.0.1:{}/udp", udp.port())];
    let (_child, addrs, _) = start_forwards(sshunnel(&dir), &dir, &specs.iter().map(String::as_str).collect::<Vec<_>>()).await;
    let data = pattern(3, 8 << 20);

    let started = Instant::now();
    assert!(echo_through(&addrs[0], &data).await == data);
    let unloaded = started.elapsed();

    let (blaster, replies) = blast(&addrs[1]).await;
    let before = replies.load(Ordering::Relaxed);
    let started = Instant::now();
    assert!(echo_through(&addrs[0], &data).await == data);
    let loaded = started.elapsed();
    let flood = replies.load(Ordering::Relaxed) - before;
    drop(blaster);

    let bound = (unloaded * 4).max(unloaded + Duration::from_secs(2));
    eprintln!("8 MiB round trip: {unloaded:?} unloaded, {loaded:?} under a flood that echoed {flood} datagrams meanwhile; bound {bound:?}");
    assert!(flood > 0, "the flood kept flowing through the transfer");
    assert!(loaded <= bound, "{loaded:?} under the flood, over the {bound:?} bound ({unloaded:?} unloaded)");
}

/// uat-005: a UDP flood on the session leaves another flow's request and reply exchanges (a
/// ping-pong, as DNS does) succeeding, within a loss bound tuned from measured runs
/// (`.prds/PRD-0006.log.md`, T-004). Each flow has a forward and an echo server of its own, so
/// what they share is sshunnel's: the session, the mux, the ssh pipe and the relay. A listener's
/// socket buffer is the kernel's, shared by every sender on its port: a flood that outruns the
/// forward fills it, and whatever else arrives then is dropped before sshunnel sees it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_udp_flood_does_not_starve_another_flow() {
    let dir = TempDir::new().unwrap();
    let (flooded, exchanged) = (udp_echo_server().await.unwrap(), udp_echo_server().await.unwrap());
    let specs = [format!("0:127.0.0.1:{}/udp", flooded.port()), format!("0:127.0.0.1:{}/udp", exchanged.port())];
    let (_child, addrs, _) = start_forwards(sshunnel(&dir), &dir, &specs.iter().map(String::as_str).collect::<Vec<_>>()).await;
    let socket = udp_to("127.0.0.1:0", &addrs[1]).await;

    let unloaded = exchanges(&socket, 200, 0).await;
    assert_eq!(unloaded, 200, "every exchange succeeds without the flood");

    let (blaster, replies) = blast(&addrs[0]).await;
    let before = replies.load(Ordering::Relaxed);
    let started = Instant::now();
    let loaded = exchanges(&socket, 200, 10).await;
    let took = started.elapsed();
    let flood = replies.load(Ordering::Relaxed) - before;
    drop(blaster);

    eprintln!("{loaded} of 200 exchanges answered in {took:?}, under a flood that echoed {flood} datagrams meanwhile");
    assert!(flood > 0, "the flood kept flowing through the exchanges");
    assert!(loaded >= 190, "{loaded} of 200 exchanges answered under the flood");
}

#[tokio::test]
async fn e2e_relays_lists_each_arch_with_its_sha256() {
    let dir = TempDir::new().unwrap();
    let relays_dir = relay_dir(dir.path()).unwrap();
    let out = sshunnel(&dir).arg("relays").arg("--relay-dir").arg(&relays_dir).output().await.unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();

    let relays = Relays::from_dir(&relays_dir).unwrap();
    let host = relays.get(host_arch().unwrap()).unwrap();
    assert!(stdout.contains(&format!("sha256 {}  {} bytes", host.sha256(), host.len())), "{stdout}");
    let other = Arch::ALL.into_iter().find(|a| *a != host_arch().unwrap()).unwrap();
    assert!(stdout.contains(&format!("{:<8} (none)", other.name())), "{stdout}");
}

#[tokio::test]
async fn e2e_relays_without_any_says_how_to_get_them() {
    let dir = TempDir::new().unwrap();
    let out = sshunnel(&dir).arg("relays").output().await.unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--relay-dir"));
}

#[tokio::test]
async fn e2e_forward_rejects_a_malformed_spec() {
    let dir = TempDir::new().unwrap();
    let out = sshunnel(&dir).args(["forward", "-L", "8080", "somewhere"]).output().await.unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("[bind_address:]port:host:hostport"));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn e2e_route_refuses_before_running_ssh() {
    let dir = TempDir::new().unwrap();
    let remote = FakeRemote::new(dir.path(), "sh", &[]).unwrap();
    let relays = relay_dir(dir.path()).unwrap();

    let out = sshunnel(&dir)
        .arg("route")
        .arg("--ssh-cmd")
        .arg(remote.ssh_path())
        .arg("--relay-dir")
        .arg(&relays)
        .args(["fake-host", "0.0.0.0/0", "*", "*.caf\u{e9}.example"])
        .output()
        .await
        .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "stderr: {stderr}");
    // Every problem at once, so one run shows everything to fix. A pattern no hostname can match
    // would otherwise get resolved's routing domain and answer NXDOMAIN for every name.
    assert!(stderr.contains("'0.0.0.0/0'") && stderr.contains("'*'"), "{stderr}");
    assert!(stderr.contains("'*.caf\u{e9}.example'"), "{stderr}");
    assert!(remote.last_ssh_args().is_err(), "ssh ran before the targets were checked");
}

/// The test plays `sshunnel route`'s end of the helper's socket, as the same user.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn e2e_helper_leaves_a_refusal_it_sent_to_the_client() {
    let dir = TempDir::new().unwrap();
    let socket = dir.path().join("helper.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let helper = sshunnel(&dir).env_remove("SUDO_UID").arg("helper").arg("--socket").arg(&socket).stderr(Stdio::piped()).spawn().unwrap();

    let (conn, _) = timeout(Duration::from_secs(10), listener.accept()).await.expect("the helper connects").unwrap();
    let (reader, mut writer) = conn.into_split();
    writer.write_all(b"{\"include\":[\"0.0.0.0/0\"],\"exclude\":[],\"pins\":[]}\n").await.unwrap();
    let mut reply = String::new();
    BufReader::new(reader).read_line(&mut reply).await.unwrap();
    let out = timeout(Duration::from_secs(10), helper.wait_with_output()).await.expect("the helper exits").unwrap();

    assert!(reply.contains("Failed") && reply.contains("'0.0.0.0/0'"), "{reply}");
    assert!(!out.status.success());
    // The client prints the refusal; the helper shares its terminal (through sudo) and stays quiet.
    assert_eq!(String::from_utf8_lossy(&out.stderr), "");
}

/// `nohup sshunnel route ...` must outlive its terminal: a SIGHUP ignored at startup stays ignored.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn e2e_route_leaves_an_ignored_sighup_ignored() {
    use rustix::process::{Pid, Signal, kill_process};
    use sshunnel::tests::shim_dir;

    let dir = TempDir::new().unwrap();
    let started = dir.path().join("ssh-started");
    // An ssh that never connects holds the client in its session stage, signals already handled.
    let shims = shim_dir(dir.path(), &[("ssh", &format!(": > '{}'\nexec sleep 60", started.display()))]).unwrap();
    let relays = relay_dir(dir.path()).unwrap();
    let mut nohup = Command::new("sh");
    nohup.args(["-c", "trap '' HUP && exec \"$0\" \"$@\"", env!("CARGO_BIN_EXE_sshunnel")]);
    let mut client = isolated(nohup, &dir)
        .env("XDG_STATE_HOME", dir.path())
        .arg("route")
        .arg("--ssh-cmd")
        .arg(shims.join("ssh"))
        .arg("--relay-dir")
        .arg(&relays)
        .args(["fake-host", "192.0.2.0/24"])
        .spawn()
        .unwrap();
    let pid = client.id().unwrap();
    let waiting = async {
        while !started.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    timeout(Duration::from_secs(10), waiting).await.expect("the client starts ssh");

    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let ignored = status
        .lines()
        .find_map(|line| line.strip_prefix("SigIgn:"))
        .map(|mask| u64::from_str_radix(mask.trim(), 16).unwrap())
        .unwrap();
    assert_ne!(ignored & 1, 0, "SIGHUP (bit 0) is no longer ignored: SigIgn {ignored:016x}");

    // SIGTERM still ends the run cleanly.
    kill_process(Pid::from_raw(i32::try_from(pid).unwrap()).unwrap(), Signal::TERM).unwrap();
    let exited = timeout(Duration::from_secs(10), client.wait()).await.expect("SIGTERM ends the run").unwrap();
    assert!(exited.success(), "{exited}");
}
