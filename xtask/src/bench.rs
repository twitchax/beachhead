//! `cargo xtask bench`: throughput of `sshunnel forward -L` against `ssh -L` through the same
//! throwaway sshd. It runs as this user on a free loopback port with temp host and client keys and
//! `-F /dev/null`, so nothing reads or writes `~/.ssh`, and the relay cache lands in the scratch dir
//! (`AcceptEnv XDG_CACHE_HOME`).
//!
//! `cargo xtask bench --route`: `sshunnel route` against `sshunnel forward -L`, one stream each way,
//! through the same kind of sshd. The client side runs as root over fresh namespaces, wherever the
//! route tests would run theirs (`tests::Namespaces`: here, or their container where user namespaces
//! are restricted), so `route` gets a TUN device of its own. It reaches sshd through a unix socket,
//! since a path crosses network namespaces and a loopback port doesn't: ssh's `ProxyCommand` is
//! `cargo xtask bridge`, and this process carries the socket to sshd's port. The target is this
//! host's own address as a `/32`, which the relay, here, dials locally. Forward mode dials that same
//! address from the same namespace through the same bridge, so both pay the same overhead.

use std::{
    ffi::OsString,
    fs::File,
    io::{self, BufRead as _, BufReader, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    os::{
        fd::AsFd as _,
        unix::net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail, ensure};
use sshunnel::tests::Namespaces;

use crate::StatusOk as _;

const MIB: usize = 1024 * 1024;
const PARALLEL: usize = 8;
/// Route mode's bar: the share of forward mode's single-stream throughput it keeps, each way.
const BAR: f64 = 0.90;
/// How long the route bench's client side may run in its container: a backstop, since a killed
/// `docker run` leaves its container running.
const CLIENT_LIMIT: Duration = Duration::from_secs(3600);
/// What ssh is told it connects to. Through the bridge it names only the host key.
const DESTINATION: &str = "127.0.0.1";

pub struct Options {
    pub mib: usize,
    pub runs: usize,
    /// `sshunnel route` against `sshunnel forward -L`, rather than `-L` against `ssh -L`.
    pub route: bool,
}

/// Runs the bench `options` picks, with its scratch dir under `target` rather than `/tmp`: snap's
/// Docker mounts only paths under `$HOME`, and the route bench's container mounts `target`.
pub fn run(client: &Path, target: &Path, options: &Options) -> Result<()> {
    let dir = target.join(format!("bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let result = if options.route { route(client, &dir, target, options) } else { bench(client, &dir, options) };
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn bench(client: &Path, dir: &Path, options: &Options) -> Result<()> {
    let sshd = Sshd::start(dir)?;
    let sink = serve(sink_conn, Ipv4Addr::LOCALHOST)?;
    let source = serve(source_conn, Ipv4Addr::LOCALHOST)?;
    let targets = [format!("127.0.0.1:{sink}"), format!("127.0.0.1:{source}")];
    let bytes = options.mib * MIB;

    let mut table = Vec::new();
    let ssh_forward = Forwarder::ssh(&sshd, &targets)?;
    table.push(("ssh -L", measure(ssh_forward.ports, bytes, options.runs)?));
    drop(ssh_forward);

    let ssh_cmd = sshd.ssh_command(&[])?;
    let (pushed, push_time) = Forwarder::sshunnel(client, &ssh_cmd, &targets)?;
    drop(pushed);
    let (cached, cache_time) = Forwarder::sshunnel(client, &ssh_cmd, &targets)?;
    table.push(("sshunnel -L", measure(cached.ports, bytes, options.runs)?));
    drop(cached);

    println!("\n{} MiB per transfer, best of {} runs, through sshd on loopback:\n", options.mib, options.runs);
    println!("{:<14} {:>14} {:>14} {:>22}", "", "upload", "download", format!("download x{PARALLEL}"));
    for (name, rates) in &table {
        println!("{name:<14} {:>9.0} MiB/s {:>9.0} MiB/s {:>17.0} MiB/s", rates[0], rates[1], rates[2]);
    }
    println!(
        "\nsshunnel bootstrap to ready: {} ms pushing the relay, {} ms from cache",
        push_time.as_millis(),
        cache_time.as_millis()
    );
    Ok(())
}

/// The route bench's host side: sshd, a sink and a source on every address, and the unix socket
/// that carries ssh to sshd; then [`client`] over fresh namespaces, which measures.
fn route(client: &Path, dir: &Path, target: &Path, options: &Options) -> Result<()> {
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
        let mut best = [[0f64; 2]; 2];
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
            for (best, rate) in best.iter_mut().flatten().zip(rates.iter().flatten()) {
                *best = best.max(*rate);
            }
        }
        drop(forwarded);
        drop(routed);

        let [route, forward] = best;
        println!("\n{} MiB per transfer, one stream, best of {} interleaved rounds:\n", self.mib, self.runs);
        println!("{:<20} {:>14} {:>14}", "", "upload", "download");
        println!("{:<20} {:>9.0} MiB/s {:>9.0} MiB/s", "sshunnel forward -L", forward[0], forward[1]);
        println!("{:<20} {:>9.0} MiB/s {:>9.0} MiB/s", "sshunnel route", route[0], route[1]);
        println!("{:<20} {:>14} {:>14}", "route / forward", ratio(route[0], forward[0]), ratio(route[1], forward[1]));
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
/// namespace that can't reach this one's loopback.
fn carry_to_sshd(socket: &Path, port: u16) -> Result<()> {
    let listener = UnixListener::bind(socket).with_context(|| format!("binding {}", socket.display()))?;
    thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            thread::spawn(move || -> io::Result<()> {
                let sshd = TcpStream::connect(("127.0.0.1", port))?;
                splice((&conn, &sshd, || sshd.shutdown(Shutdown::Write)), (&sshd, &conn, || conn.shutdown(Shutdown::Write)))
            });
        }
    });
    Ok(())
}

/// `cargo xtask bridge <socket>`: [`bridge`] on this process's stdin and stdout, unbuffered: a
/// line-buffered stdout would hold back ssh's packets.
pub fn bridge_stdio(socket: &Path) -> Result<()> {
    let stdin = File::from(io::stdin().as_fd().try_clone_to_owned().context("duplicating stdin")?);
    let stdout = File::from(io::stdout().as_fd().try_clone_to_owned().context("duplicating stdout")?);
    bridge(socket, stdin, stdout)
}

/// ssh's `ProxyCommand` on the route bench's client side: carries `input` (ssh's stdin) to the
/// bench's unix socket and what comes back to `output`, until both directions end.
pub fn bridge(socket: &Path, input: impl Read + Send, output: impl Write + Send) -> Result<()> {
    let conn = UnixStream::connect(socket).with_context(|| format!("connecting to {}", socket.display()))?;
    // `output` is a pipe, closed as the process exits.
    splice((input, &conn, || conn.shutdown(Shutdown::Write)), (&conn, output, || Ok(()))).context("bridging ssh to the bench")
}

/// Copies `there` and `back` at once. Each is `(from, to, end)`: bytes go from `from` to `to`
/// until `from` ends, then `end` tells whoever reads `to` that no more are coming.
fn splice(there: (impl Read + Send, impl Write + Send, impl FnOnce() -> io::Result<()> + Send), back: (impl Read, impl Write, impl FnOnce() -> io::Result<()>)) -> io::Result<()> {
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

/// Best MiB/s over `runs` for upload, download, and parallel download.
fn measure(ports: [u16; 2], bytes: usize, runs: usize) -> Result<[f64; 3]> {
    let mut best = [0f64; 3];
    for _ in 0..runs {
        let rates = [upload(local(ports[0]), bytes)?, download(local(ports[1]), bytes)?, parallel_download(local(ports[1]), bytes)?];
        for (best, rate) in best.iter_mut().zip(rates) {
            *best = best.max(rate);
        }
    }
    Ok(best)
}

fn local(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

#[allow(clippy::cast_precision_loss, reason = "a throughput figure, not an exact count")]
fn rate(bytes: usize, elapsed: Duration) -> f64 {
    bytes as f64 / MIB as f64 / elapsed.as_secs_f64()
}

fn upload(addr: SocketAddr, bytes: usize) -> Result<f64> {
    let block = vec![0xA5u8; MIB];
    let start = Instant::now();
    let mut conn = TcpStream::connect(addr).context("connecting for upload")?;
    for _ in 0..bytes / MIB {
        conn.write_all(&block).context("uploading")?;
    }
    conn.shutdown(Shutdown::Write).context("half-closing the upload")?;
    let mut count = [0u8; 8];
    conn.read_exact(&mut count).context("reading the sink's count")?;
    let elapsed = start.elapsed();
    if u64::from_be_bytes(count) != bytes as u64 {
        bail!("the sink counted {} bytes, sent {bytes}", u64::from_be_bytes(count));
    }
    Ok(rate(bytes, elapsed))
}

fn download(addr: SocketAddr, bytes: usize) -> Result<f64> {
    let start = Instant::now();
    let got = fetch(addr, bytes)?;
    let elapsed = start.elapsed();
    if got != bytes {
        bail!("downloaded {got} of {bytes} bytes");
    }
    Ok(rate(bytes, elapsed))
}

fn parallel_download(addr: SocketAddr, bytes: usize) -> Result<f64> {
    let each = bytes / PARALLEL;
    let start = Instant::now();
    let workers: Vec<_> = (0..PARALLEL).map(|_| thread::spawn(move || fetch(addr, each))).collect();
    let mut total = 0;
    for worker in workers {
        total += worker.join().map_err(|_| anyhow::anyhow!("a download thread panicked"))??;
    }
    let elapsed = start.elapsed();
    if total != each * PARALLEL {
        bail!("downloaded {total} of {} bytes", each * PARALLEL);
    }
    Ok(rate(total, elapsed))
}

fn fetch(addr: SocketAddr, bytes: usize) -> Result<usize> {
    let mut conn = TcpStream::connect(addr).context("connecting for download")?;
    conn.write_all(&(bytes as u64).to_be_bytes()).context("asking the source for bytes")?;
    let mut buf = vec![0u8; 256 * 1024];
    let mut got = 0;
    loop {
        match conn.read(&mut buf).context("downloading")? {
            0 => return Ok(got),
            n => got += n,
        }
    }
}

/// Reads to EOF, then answers with the byte count.
fn sink_conn(mut conn: TcpStream) -> std::io::Result<()> {
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        match conn.read(&mut buf)? {
            0 => break,
            n => total += n as u64,
        }
    }
    conn.write_all(&total.to_be_bytes())
}

/// Reads a byte count, sends that many bytes, closes.
fn source_conn(mut conn: TcpStream) -> std::io::Result<()> {
    let mut want = [0u8; 8];
    conn.read_exact(&mut want)?;
    let block = vec![0x5Au8; MIB];
    let mut left = usize::try_from(u64::from_be_bytes(want)).unwrap_or(usize::MAX);
    while left > 0 {
        let n = left.min(block.len());
        conn.write_all(&block[..n])?;
        left -= n;
    }
    Ok(())
}

/// Serves `handler` on a free port of `ip` in background threads; returns the port.
fn serve(handler: fn(TcpStream) -> std::io::Result<()>, ip: Ipv4Addr) -> Result<u16> {
    let listener = TcpListener::bind((ip, 0)).context("binding a bench target")?;
    let port = listener.local_addr().context("reading a bench target's port")?.port();
    thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            thread::spawn(move || handler(conn));
        }
    });
    Ok(port)
}

fn free_port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0").context("finding a free port")?.local_addr()?.port())
}

/// A child process killed on drop, so an early return can't leak sshd.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Sshd {
    port: u16,
    dir: PathBuf,
    /// The only user a non-root sshd lets in: this one. The route bench's client side runs as root.
    user: String,
    _child: Guard,
}

impl Sshd {
    fn start(dir: &Path) -> Result<Self> {
        for key in ["host_key", "client_key"] {
            let status = Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", ""])
                .arg("-f")
                .arg(dir.join(key))
                .status()
                .context("running ssh-keygen")?;
            if !status.success() {
                bail!("ssh-keygen failed: {status}");
            }
        }
        std::fs::copy(dir.join("client_key.pub"), dir.join("authorized_keys")).context("authorizing the client key")?;
        let id = Command::new("id").arg("-un").output().context("running `id -un`")?;
        ensure!(id.status.success(), "`id -un` failed: {}", String::from_utf8_lossy(&id.stderr).trim());
        let user = String::from_utf8(id.stdout).context("`id -un` printed non-UTF-8")?.trim().to_owned();
        let port = free_port()?;
        let d = dir.display();
        let config = format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {d}/host_key\nAuthorizedKeysFile {d}/authorized_keys\nPidFile {d}/sshd.pid\n\
             UsePAM no\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\n\
             AllowTcpForwarding yes\nAcceptEnv XDG_CACHE_HOME\n"
        );
        std::fs::write(dir.join("sshd_config"), config).context("writing sshd_config")?;
        let sshd = ["/usr/sbin/sshd", "/usr/local/sbin/sshd"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .context("no sshd found in /usr/sbin or /usr/local/sbin")?;
        let child = Command::new(sshd)
            .arg("-D")
            .arg("-e")
            .arg("-f")
            .arg(dir.join("sshd_config"))
            .stderr(Stdio::null())
            .spawn()
            .context("starting sshd")?;
        let guard = Guard(child);
        wait_for_port(port)?;
        Ok(Self {
            port,
            dir: dir.to_owned(),
            user,
            _child: guard,
        })
    }

    /// ssh options that reach this sshd and nothing else. The host key is new each run, so there is
    /// nothing to remember (and the route bench's container mounts the scratch dir read-only).
    fn ssh_args(&self) -> Vec<String> {
        let d = self.dir.display();
        [
            "-F",
            "/dev/null",
            "-p",
            &self.port.to_string(),
            "-l",
            &self.user,
            "-i",
            &format!("{d}/client_key"),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            &format!("SetEnv=XDG_CACHE_HOME={d}/cache"),
        ]
        .map(str::to_owned)
        .to_vec()
    }

    /// `--ssh-cmd` for sshunnel: `ssh`, [`Self::ssh_args`], then `extra`.
    fn ssh_command(&self, extra: &[&str]) -> Result<String> {
        let args = self.ssh_args();
        let words: Vec<&str> = std::iter::once("ssh").chain(args.iter().map(String::as_str)).chain(extra.iter().copied()).collect();
        shell_line(&words)
    }
}

/// `words` single-quoted and joined, so shell splitting gives them back.
fn shell_line(words: &[&str]) -> Result<String> {
    let quoted = words
        .iter()
        .map(|word| {
            ensure!(!word.contains('\''), "`{word}` has a single quote, which this quoting can't carry");
            Ok(format!("'{word}'"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(quoted.join(" "))
}

struct Forwarder {
    ports: [u16; 2],
    _child: Guard,
}

impl Forwarder {
    fn ssh(sshd: &Sshd, targets: &[String; 2]) -> Result<Self> {
        let ports = [free_port()?, free_port()?];
        let mut cmd = Command::new("ssh");
        cmd.args(sshd.ssh_args()).args(["-N", "-o", "ExitOnForwardFailure=yes"]);
        for (port, target) in ports.iter().zip(targets) {
            cmd.arg("-L").arg(format!("{port}:{target}"));
        }
        let child = Guard(cmd.arg(DESTINATION).spawn().context("starting ssh -L")?);
        for port in ports {
            wait_for_port(port)?;
        }
        Ok(Self { ports, _child: child })
    }

    /// Starts `sshunnel forward` through `ssh_cmd` and returns once it reports both forwards, with
    /// how long that took.
    fn sshunnel(client: &Path, ssh_cmd: &str, targets: &[String; 2]) -> Result<(Self, Duration)> {
        let ports = [free_port()?, free_port()?];
        let mut cmd = Command::new(client);
        cmd.arg("forward").arg("--ssh-cmd").arg(ssh_cmd);
        for (port, target) in ports.iter().zip(targets) {
            cmd.arg("-L").arg(format!("{port}:{target}"));
        }
        cmd.arg(DESTINATION);
        let mut readiness = Readiness::new(targets);
        let (child, elapsed) = started(&mut cmd, "sshunnel forward", move |line| readiness.saw(line))?;
        Ok((Self { ports, _child: child }, elapsed))
    }
}

/// Spawns `cmd` with its stderr echoed, indented, and returns once a line is `ready`, with how long
/// that took.
fn started(cmd: &mut Command, name: &str, mut ready: impl FnMut(&str) -> bool + Send + 'static) -> Result<(Guard, Duration)> {
    let start = Instant::now();
    let mut child = cmd.stderr(Stdio::piped()).spawn().with_context(|| format!("starting {name}"))?;
    let stderr = child.stderr.take().with_context(|| format!("{name} has no stderr pipe"))?;
    let child = Guard(child);

    let (ready_tx, ready_rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            eprintln!("  {line}");
            if ready(&line) {
                let _ = ready_tx.send(());
            }
        }
    });
    ready_rx.recv_timeout(Duration::from_secs(60)).with_context(|| format!("{name} wasn't ready within 60s"))?;
    Ok((child, start.elapsed()))
}

/// Follows `sshunnel forward`'s stderr until every target has a `forwarding <addr> -> <target>`
/// line. A forward prints one per local address it listens on (`127.0.0.1` and `::1`), so lines are
/// matched to targets, not counted.
struct Readiness {
    waiting: Vec<String>,
}

impl Readiness {
    fn new(targets: &[String]) -> Self {
        Self { waiting: targets.to_vec() }
    }

    /// Notes one stderr line; true for the line that leaves no target waiting.
    fn saw(&mut self, line: &str) -> bool {
        let Some(forward) = line.strip_prefix("sshunnel: forwarding ") else { return false };
        let before = self.waiting.len();
        self.waiting.retain(|target| !forward.ends_with(&format!("-> {target}")));
        before > 0 && self.waiting.is_empty()
    }
}

fn wait_for_port(port: u16) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    bail!("nothing listened on port {port} within 30s")
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::{io, os::unix::net::UnixListener};

    use super::*;

    #[test]
    fn bridge_copies_both_ways() {
        let dir = std::env::temp_dir().join(format!("xtask-bridge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("echo.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        thread::spawn(move || -> io::Result<()> {
            let (conn, _) = listener.accept()?;
            io::copy(&mut &conn, &mut &conn)?;
            conn.shutdown(Shutdown::Write)
        });
        // More than the socket's buffers hold, so the bridge has to send and receive at once.
        let sent: Vec<u8> = (0..=250u8).cycle().take(4 * MIB).collect();
        let mut got = Vec::new();

        bridge(&socket, sent.as_slice(), &mut got).unwrap();

        std::fs::remove_dir_all(&dir).unwrap();
        assert!(got == sent, "{} of {} bytes came back, or they differ", got.len(), sent.len());
    }

    #[test]
    fn a_reply_can_be_read_while_the_bridge_waits_for_the_next() {
        // ssh reads each reply from a pipe before it sends the next message. A bridge that holds
        // the pipe while it waits on the socket (a splice does) leaves the reply unreadable.
        let dir = std::env::temp_dir().join(format!("xtask-bridge-pipes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("echo.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        thread::spawn(move || -> io::Result<()> {
            let (conn, _) = listener.accept()?;
            io::copy(&mut &conn, &mut &conn)?;
            conn.shutdown(Shutdown::Write)
        });
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

        let finished = done_rx.recv_timeout(Duration::from_secs(10));
        std::fs::remove_dir_all(&dir).unwrap();
        finished.expect("a reply sat in the pipe while the bridge waited for the next");
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
    fn a_ratio_under_the_bar_is_marked() {
        assert_eq!(ratio(450.0, 500.0), "0.900");
        assert_eq!(ratio(510.0, 500.0), "1.020");
        assert_eq!(ratio(449.0, 500.0), "0.898 < 0.90");
    }

    #[test]
    fn ssh_cmd_words_survive_shell_splitting() {
        assert_eq!(shell_line(&["ssh", "-o", "ProxyCommand=/x bridge /y"]).unwrap(), "'ssh' '-o' 'ProxyCommand=/x bridge /y'");
        assert!(shell_line(&["it's"]).is_err());
    }

    #[test]
    fn ready_once_every_target_has_reported() {
        let targets = ["127.0.0.1:1".to_owned(), "127.0.0.1:2".to_owned()];
        let mut readiness = Readiness::new(&targets);
        assert!(!readiness.saw("sshunnel: relay x86_64 0123456789ab pushed to /tmp/cache"));
        assert!(!readiness.saw("sshunnel: forwarding 127.0.0.1:9 -> 127.0.0.1:1"));
        assert!(!readiness.saw("sshunnel: forwarding [::1]:9 -> 127.0.0.1:1"), "a forward's second address is not the other forward");
        assert!(readiness.saw("sshunnel: forwarding 127.0.0.1:8 -> 127.0.0.1:2"));
        assert!(!readiness.saw("sshunnel: forwarding [::1]:8 -> 127.0.0.1:2"), "ready is reported once");
    }
}
