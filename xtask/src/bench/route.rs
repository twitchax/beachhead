//! `cargo xtask bench --route` (Linux): `sshunnel route` against `sshunnel forward -L`, one stream
//! each way, through the same kind of sshd as the plain bench. The client side runs as root over
//! fresh namespaces, wherever the route tests would run theirs (`tests::Namespaces`: here, or their
//! container where user namespaces are restricted), so `route` gets a TUN device of its own. It
//! reaches sshd through a unix socket, since a path crosses network namespaces and a loopback port
//! doesn't: ssh's `ProxyCommand` is `cargo xtask bridge`, and the bench process carries the socket
//! to sshd's port. The target is this host's own address as a `/32`, which the relay, on the host,
//! dials locally. Forward mode dials that same address from the same namespace through the same
//! bridge, so both pay the same overhead.

use std::{
    ffi::OsString,
    fs::File,
    io::{self, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream},
    os::{
        fd::AsFd as _,
        unix::net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration,
};

use anyhow::{Context as _, Result, bail, ensure};
use sshunnel::tests::Namespaces;

use super::{DESTINATION, Forwarder, Guard, MIB, Options, Sshd, download, local, serve, sink_conn, source_conn, started, upload};
use crate::StatusOk as _;

/// Route mode's bar: the share of forward mode's single-stream throughput it keeps, each way.
const BAR: f64 = 0.90;
/// How long the route bench's client side may run in its container: a backstop, since a killed
/// `docker run` leaves its container running.
const CLIENT_LIMIT: Duration = Duration::from_secs(3600);

/// The route bench's host side: sshd, a sink and a source on every address, and the unix socket
/// that carries ssh to sshd; then [`client`] over fresh namespaces, which measures.
pub fn run(client: &Path, dir: &Path, target: &Path, options: &Options) -> Result<()> {
    let namespaces = Namespaces::pick().context("the route bench's client side runs over fresh namespaces")?;
    let sshd = Sshd::start(dir)?;
    let addr = host_address()?;
    let ports = [serve(sink_conn, Ipv4Addr::UNSPECIFIED)?, serve(source_conn, Ipv4Addr::UNSPECIFIED)?];
    let socket = dir.join("sshd.sock");
    carry_to_sshd(&socket, sshd.port)?;

    let xtask = std::env::current_exe().context("locating xtask")?;
    let proxy = format!("ProxyCommand={} bridge {}", xtask.display(), socket.display());
    let side = ClientSide {
        client: client.to_owned(),
        ssh_cmd: sshd.ssh_command(&["-o", &proxy])?,
        addr,
        ports,
        mib: options.mib,
        runs: options.runs,
    };
    let mut program = vec![xtask.into_os_string(), "bench-client".into()];
    program.extend(side.args());
    println!("route bench: the client side runs in {namespaces}");
    let status = namespaces.command(&program, &[target.to_owned()], CLIENT_LIMIT)?.status().context("running the client side")?;
    ensure!(status.success(), "the route bench's client side failed ({status})");
    Ok(())
}

/// What the route bench's client side needs from the host side, carried as `bench-client`'s
/// arguments.
#[derive(Debug, PartialEq, Eq)]
struct ClientSide {
    /// The `sshunnel` to run.
    client: PathBuf,
    /// `--ssh-cmd`, through the bridge.
    ssh_cmd: String,
    /// This host's own address: route mode's `/32` and forward mode's target.
    addr: Ipv4Addr,
    /// The sink's and the source's ports on `addr`.
    ports: [u16; 2],
    mib: usize,
    runs: usize,
}

impl ClientSide {
    fn args(&self) -> Vec<OsString> {
        let [sink, source] = self.ports;
        let mut args = vec![self.client.clone().into_os_string(), OsString::from(&self.ssh_cmd)];
        args.extend([self.addr.to_string(), sink.to_string(), source.to_string(), self.mib.to_string(), self.runs.to_string()].map(OsString::from));
        args
    }

    fn parse(args: &[String]) -> Result<Self> {
        let [client, ssh_cmd, addr, sink, source, mib, runs] = args else {
            bail!("bench-client takes 7 arguments, not {}: {args:?}", args.len());
        };
        Ok(Self {
            client: client.into(),
            ssh_cmd: ssh_cmd.clone(),
            addr: addr.parse().with_context(|| format!("bench-client: `{addr}` is not an IPv4 address"))?,
            ports: [number(sink)?, number(source)?],
            mib: number(mib)?,
            runs: number(runs)?,
        })
    }

    /// Brings up `sshunnel route` to the host's address and `sshunnel forward -L` to the same sink
    /// and source, then measures both, in rounds that alternate which goes first.
    fn measure(&self, state: &Path) -> Result<()> {
        let targets = self.ports.map(|port| SocketAddr::from((self.addr, port)));
        let routed = route_up(&self.client, &self.ssh_cmd, self.addr, state)?;
        let (forwarded, _) = Forwarder::sshunnel(&self.client, &self.ssh_cmd, &targets.map(|target| target.to_string()))?;
        // Route mode dials the target itself; forward mode, its local ports.
        let modes = [targets, forwarded.ports.map(local)];
        let bytes = self.mib * MIB;

        println!();
        // Each mode's rates by direction, one per round.
        let mut rounds: [[Vec<f64>; 2]; 2] = Default::default();
        for round in 0..self.runs {
            let mut rates = [[0f64; 2]; 2];
            // Swapping the order each round keeps drift over the run from favoring either mode.
            let order = if round % 2 == 0 { [0, 1] } else { [1, 0] };
            for mode in order {
                let [sink, source] = modes[mode];
                rates[mode] = [upload(sink, bytes)?, download(source, bytes)?];
            }
            let [[route_up, route_down], [forward_up, forward_down]] = rates;
            println!(
                "round {}: route {route_up:.0} up, {route_down:.0} down; forward -L {forward_up:.0} up, {forward_down:.0} down (MiB/s)",
                round + 1
            );
            for (series, &rate) in rounds.iter_mut().flatten().zip(rates.iter().flatten()) {
                series.push(rate);
            }
        }
        drop(forwarded);
        drop(routed);

        let [route, forward] = rounds.each_ref().map(|mode| mode.each_ref().map(|rates| rates.iter().copied().fold(0.0, f64::max)));
        let [route_median, forward_median] = rounds.each_ref().map(|mode| mode.each_ref().map(|rates| median(rates)));
        println!("\n{} MiB per transfer, one stream, {} interleaved rounds; the bar is on the best:\n", self.mib, self.runs);
        println!("{:<20} {:>15} {:>15} {:>15} {:>15}", "", "best up", "best down", "median up", "median down");
        let row = |[best_up, best_down]: [f64; 2], [median_up, median_down]: [f64; 2]| format!("{best_up:>9.0} MiB/s {best_down:>9.0} MiB/s {median_up:>9.0} MiB/s {median_down:>9.0} MiB/s");
        println!("{:<20} {}", "sshunnel forward -L", row(forward, forward_median));
        println!("{:<20} {}", "sshunnel route", row(route, route_median));
        println!(
            "{:<20} {:>15} {:>15} {:>15.3} {:>15.3}",
            "route / forward",
            ratio(route[0], forward[0]),
            ratio(route[1], forward[1]),
            route_median[0] / forward_median[0],
            route_median[1] / forward_median[1]
        );
        Ok(())
    }
}

fn number<T: std::str::FromStr>(arg: &str) -> Result<T> {
    arg.parse().ok().with_context(|| format!("bench-client: `{arg}` is not a number"))
}

/// `route / forward`, marked when it falls below [`BAR`].
fn ratio(route: f64, forward: f64) -> String {
    let ratio = route / forward;
    if ratio < BAR { format!("{ratio:.3} < {BAR:.2}") } else { format!("{ratio:.3}") }
}

/// The middle of `rates`, or the mean of the middle two when there are an even number.
fn median(rates: &[f64]) -> f64 {
    let mut sorted = rates.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mid = sorted.len() / 2;
    match sorted.len() {
        0 => f64::NAN,
        len if len % 2 == 0 => f64::midpoint(sorted[mid - 1], sorted[mid]),
        _ => sorted[mid],
    }
}

/// `cargo xtask bench-client`: the route bench's client side, as root over its namespaces.
pub fn client(args: &[String]) -> Result<()> {
    let side = ClientSide::parse(args)?;
    // A fresh network namespace's loopback starts down, and forward mode listens on it.
    Command::new("ip").args(["link", "set", "lo", "up"]).status_ok()?;
    // Not in the scratch dir, which the container mounts read-only.
    let state = std::env::temp_dir().join(format!("sshunnel-bench-{}", std::process::id()));
    std::fs::create_dir_all(&state).with_context(|| format!("creating {}", state.display()))?;
    let result = side.measure(&state);
    let _ = std::fs::remove_dir_all(&state);
    result
}

/// Starts `sshunnel route` to `addr/32` and returns once its routes are up. As root here, it starts
/// its helper without sudo; its state file and the helper's socket go in `state`.
fn route_up(client: &Path, ssh_cmd: &str, addr: Ipv4Addr, state: &Path) -> Result<Guard> {
    let mut cmd = Command::new(client);
    cmd.env("XDG_STATE_HOME", state)
        .env("XDG_RUNTIME_DIR", state)
        .arg("route")
        .arg("--ssh-cmd")
        .arg(ssh_cmd)
        .arg(DESTINATION)
        .arg(format!("{addr}/32"));
    let (child, _) = started(&mut cmd, "sshunnel route", |line| line.starts_with("sshunnel: routing "))?;
    Ok(child)
}

/// This host's first non-loopback IPv4 address: the route bench's target.
fn host_address() -> Result<Ipv4Addr> {
    let out = Command::new("ip").args(["-4", "-o", "addr", "show", "scope", "global"]).output().context("running `ip addr`")?;
    ensure!(out.status.success(), "`ip addr` failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    first_address(&String::from_utf8_lossy(&out.stdout)).context("this host has no non-loopback IPv4 address for route mode to target")
}

/// The first address in `ip -o addr`'s listing.
fn first_address(listing: &str) -> Option<Ipv4Addr> {
    listing.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        words.find(|word| *word == "inet")?;
        words.next()?.split('/').next()?.parse().ok()
    })
}

/// Listens on `socket` and carries each connection to sshd's loopback port, for ssh in a network
/// namespace that can't reach this one's loopback. Failures are printed: ssh would report only a
/// closed connection.
fn carry_to_sshd(socket: &Path, port: u16) -> Result<()> {
    let listener = UnixListener::bind(socket).with_context(|| format!("binding {}", socket.display()))?;
    thread::spawn(move || {
        for conn in listener.incoming() {
            match conn {
                Ok(conn) => {
                    thread::spawn(move || {
                        if let Err(e) = carry(&conn, port) {
                            eprintln!("route bench: {e:#}");
                        }
                    });
                }
                Err(e) => eprintln!("route bench: accepting ssh on the bridge's socket: {e}"),
            }
        }
    });
    Ok(())
}

/// Carries one bridged connection to sshd's loopback port and back, until both directions end.
fn carry(conn: &UnixStream, port: u16) -> Result<()> {
    let sshd = TcpStream::connect(("127.0.0.1", port)).with_context(|| format!("connecting to sshd on port {port}"))?;
    copy_both_ways((conn, &sshd, || sshd.shutdown(Shutdown::Write)), (&sshd, conn, || conn.shutdown(Shutdown::Write))).context("carrying ssh to sshd")
}

/// `cargo xtask bridge <socket>`: [`bridge`] on this process's stdin and stdout, unbuffered: a
/// line-buffered stdout would hold back ssh's packets.
pub fn bridge_stdio(socket: &Path) -> Result<()> {
    let stdin = File::from(io::stdin().as_fd().try_clone_to_owned().context("duplicating stdin")?);
    let stdout = File::from(io::stdout().as_fd().try_clone_to_owned().context("duplicating stdout")?);
    bridge(socket, stdin, stdout)
}

/// ssh's `ProxyCommand` on the route bench's client side: carries `input` (ssh's stdin) to the
/// bench's unix socket and what comes back to `output`. It returns once the bench's side ends,
/// without waiting for `input` to, as `nc -q0` does: ssh holds `input` open until it sees `output`
/// close, which [`bridge_stdio`] does by exiting.
pub fn bridge(socket: &Path, input: impl Read + Send + 'static, output: impl Write) -> Result<()> {
    let conn = UnixStream::connect(socket).with_context(|| format!("connecting to {}", socket.display()))?;
    let sending = conn.try_clone().context("cloning the bridge's socket")?;
    // Detached, so it ends with `input` or with the process, whichever comes first.
    thread::spawn(move || flow((input, &sending, || sending.shutdown(Shutdown::Write))));
    flow((&conn, output, || Ok(()))).context("bridging ssh to the bench")
}

/// Copies `there` and `back` at once. Each is `(from, to, end)`: bytes go from `from` to `to`
/// until `from` ends, then `end` tells whoever reads `to` that no more are coming.
fn copy_both_ways(there: (impl Read + Send, impl Write + Send, impl FnOnce() -> io::Result<()> + Send), back: (impl Read, impl Write, impl FnOnce() -> io::Result<()>)) -> io::Result<()> {
    thread::scope(|scope| {
        let sending = scope.spawn(move || flow(there));
        let received = flow(back);
        sending.join().map_err(|_| io::Error::other("a copying thread panicked"))??;
        received
    })
}

fn flow((mut from, mut to, end): (impl Read, impl Write, impl FnOnce() -> io::Result<()>)) -> io::Result<()> {
    // Not `io::copy`: on Linux it splices between a socket and a pipe, and a splice waiting on the
    // socket holds the pipe, so ssh can't read the reply already in it. Large reads, since ssh's
    // whole stream crosses here twice in both modes.
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => to.write_all(&buf[..n])?,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    to.flush()?;
    end()
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        thread,
    };

    use super::*;

    /// A scratch dir, removed on drop, so a failing test leaves nothing behind.
    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A unix socket in a scratch dir whose first connection `serve` handles; returns the dir's
    /// guard and the socket's path.
    fn socket_serving(serve: impl FnOnce(UnixStream) -> io::Result<()> + Send + 'static) -> (Scratch, PathBuf) {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!("xtask-bridge-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("server.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        thread::spawn(move || serve(listener.accept()?.0));
        (Scratch(dir), socket)
    }

    /// A unix socket that echoes one connection and half-closes once its peer has.
    fn echo_socket() -> (Scratch, PathBuf) {
        socket_serving(|conn| {
            io::copy(&mut &conn, &mut &conn)?;
            conn.shutdown(Shutdown::Write)
        })
    }

    #[test]
    fn bridge_copies_both_ways() {
        let (_dir, socket) = echo_socket();
        // More than the socket's buffers hold, so the bridge has to send and receive at once.
        let sent: Vec<u8> = (0..=250u8).cycle().take(4 * MIB).collect();
        let mut got = Vec::new();

        bridge(&socket, io::Cursor::new(sent.clone()), &mut got).unwrap();

        assert!(got == sent, "{} of {} bytes came back, or they differ", got.len(), sent.len());
    }

    #[test]
    fn a_reply_can_be_read_while_the_bridge_waits_for_the_next() {
        // ssh reads each reply from a pipe before it sends the next message. A bridge that holds
        // the pipe while it waits on the socket (a splice does) leaves the reply unreadable.
        let (_dir, socket) = echo_socket();
        let (input, mut to_bridge) = io::pipe().unwrap();
        let (mut from_bridge, output) = io::pipe().unwrap();
        thread::spawn(move || bridge(&socket, input, output));

        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            for message in 0..=255u8 {
                to_bridge.write_all(&[message]).unwrap();
                let mut reply = [0u8];
                from_bridge.read_exact(&mut reply).unwrap();
                assert_eq!(reply, [message]);
            }
            done_tx.send(()).unwrap();
        });

        done_rx.recv_timeout(Duration::from_secs(10)).expect("a reply sat in the pipe while the bridge waited for the next");
    }

    #[test]
    fn the_bridge_ends_when_the_server_does() {
        // sshd closing first has to reach ssh, which learns of it only as EOF on the bridge's
        // output, while ssh itself still holds the bridge's input open.
        let (_dir, socket) = socket_serving(|mut conn| conn.write_all(b"bye"));
        let (input, _held_open) = io::pipe().unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            let mut got = Vec::new();
            let bridged = bridge(&socket, input, &mut got);
            done_tx.send((bridged.is_ok(), got)).unwrap();
        });

        let (bridged, got) = done_rx.recv_timeout(Duration::from_secs(10)).expect("the bridge outlived the server's close");
        assert!(bridged);
        assert_eq!(got, b"bye");
    }

    #[test]
    fn a_failed_carry_says_why() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let (conn, _peer) = UnixStream::pair().unwrap();

        let carried = carry(&conn, closed);

        let why = format!("{:#}", carried.unwrap_err());
        assert!(why.contains(&format!("connecting to sshd on port {closed}")), "{why}");
    }

    #[test]
    fn the_route_target_is_the_hosts_first_global_address() {
        let listing = "2: eth0    inet 192.0.2.10/24 brd 192.0.2.255 scope global dynamic eth0\\       valid_lft 600sec preferred_lft 600sec\n\
                       3: br0    inet 10.99.0.1/16 brd 10.99.255.255 scope global br0\\       valid_lft forever preferred_lft forever\n";

        assert_eq!(first_address(listing), Some(Ipv4Addr::new(192, 0, 2, 10)));
        assert_eq!(first_address(""), None, "no global address");
        assert_eq!(first_address("2: eth0    inet nonsense scope global eth0\n"), None);
    }

    #[test]
    fn the_client_side_gets_everything_through_its_arguments() {
        let side = ClientSide {
            client: PathBuf::from("/repo/target/dist/sshunnel"),
            ssh_cmd: "'ssh' '-o' 'ProxyCommand=/repo/target/debug/xtask bridge /repo/target/bench-1/sshd.sock'".to_owned(),
            addr: Ipv4Addr::new(192, 0, 2, 10),
            ports: [40001, 40002],
            mib: 512,
            runs: 3,
        };
        let args: Vec<String> = side.args().into_iter().map(|arg| arg.into_string().unwrap()).collect();

        assert_eq!(ClientSide::parse(&args).unwrap(), side);
        assert!(ClientSide::parse(&args[1..]).is_err(), "an argument short");
        let mut bad = args.clone();
        bad[2] = "192.0.2.300".to_owned();
        assert!(ClientSide::parse(&bad).is_err(), "not an address");
    }

    #[test]
    fn median_of_rounds() {
        assert_eq!(median(&[470.0, 354.0, 389.0]), 389.0, "odd: the middle one");
        assert_eq!(median(&[470.0, 354.0, 389.0, 428.0]), 408.5, "even: the mean of the middle two");
        assert_eq!(median(&[437.0]), 437.0);
    }

    #[test]
    fn a_ratio_under_the_bar_is_marked() {
        assert_eq!(ratio(450.0, 500.0), "0.900");
        assert_eq!(ratio(510.0, 500.0), "1.020");
        assert_eq!(ratio(449.0, 500.0), "0.898 < 0.90");
    }
}
