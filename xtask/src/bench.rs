//! `cargo xtask bench`: throughput of `sshunnel forward -L` against `ssh -L` through the same
//! throwaway sshd. It runs as this user on a free loopback port with temp host and client keys and
//! `-F /dev/null`, so nothing reads or writes `~/.ssh`, and the relay cache lands in the temp dir
//! (`AcceptEnv XDG_CACHE_HOME`).

use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{Shutdown, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};

const MIB: usize = 1024 * 1024;
const PARALLEL: usize = 8;

pub struct Options {
    pub mib: usize,
    pub runs: usize,
}

pub fn run(client: &Path, options: &Options) -> Result<()> {
    let dir = std::env::temp_dir().join(format!("sshunnel-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let result = bench(client, &dir, options);
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn bench(client: &Path, dir: &Path, options: &Options) -> Result<()> {
    let sshd = Sshd::start(dir)?;
    let sink = serve(sink_conn)?;
    let source = serve(source_conn)?;
    let targets = [format!("127.0.0.1:{sink}"), format!("127.0.0.1:{source}")];
    let bytes = options.mib * MIB;

    let mut table = Vec::new();
    let ssh_forward = Forwarder::ssh(&sshd, &targets)?;
    table.push(("ssh -L", measure(ssh_forward.ports, bytes, options.runs)?));
    drop(ssh_forward);

    let (pushed, push_time) = Forwarder::sshunnel(client, &sshd, &targets)?;
    drop(pushed);
    let (cached, cache_time) = Forwarder::sshunnel(client, &sshd, &targets)?;
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

/// Best MiB/s over `runs` for upload, download, and parallel download.
fn measure(ports: [u16; 2], bytes: usize, runs: usize) -> Result<[f64; 3]> {
    let mut best = [0f64; 3];
    for _ in 0..runs {
        let rates = [upload(ports[0], bytes)?, download(ports[1], bytes)?, parallel_download(ports[1], bytes)?];
        for (best, rate) in best.iter_mut().zip(rates) {
            *best = best.max(rate);
        }
    }
    Ok(best)
}

#[allow(clippy::cast_precision_loss, reason = "a throughput figure, not an exact count")]
fn rate(bytes: usize, elapsed: Duration) -> f64 {
    bytes as f64 / MIB as f64 / elapsed.as_secs_f64()
}

fn upload(port: u16, bytes: usize) -> Result<f64> {
    let block = vec![0xA5u8; MIB];
    let start = Instant::now();
    let mut conn = TcpStream::connect(("127.0.0.1", port)).context("connecting for upload")?;
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

fn download(port: u16, bytes: usize) -> Result<f64> {
    let start = Instant::now();
    let got = fetch(port, bytes)?;
    let elapsed = start.elapsed();
    if got != bytes {
        bail!("downloaded {got} of {bytes} bytes");
    }
    Ok(rate(bytes, elapsed))
}

fn parallel_download(port: u16, bytes: usize) -> Result<f64> {
    let each = bytes / PARALLEL;
    let start = Instant::now();
    let workers: Vec<_> = (0..PARALLEL).map(|_| thread::spawn(move || fetch(port, each))).collect();
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

fn fetch(port: u16, bytes: usize) -> Result<usize> {
    let mut conn = TcpStream::connect(("127.0.0.1", port)).context("connecting for download")?;
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

/// Serves `handler` on a loopback port in background threads; returns the port.
fn serve(handler: fn(TcpStream) -> std::io::Result<()>) -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("binding a bench target")?;
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
        Ok(Self { port, dir: dir.to_owned(), _child: guard })
    }

    /// ssh options that reach this sshd and nothing else.
    fn ssh_args(&self) -> Vec<String> {
        let d = self.dir.display();
        [
            "-F",
            "/dev/null",
            "-p",
            &self.port.to_string(),
            "-i",
            &format!("{d}/client_key"),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            &format!("UserKnownHostsFile={d}/known_hosts"),
            "-o",
            &format!("SetEnv=XDG_CACHE_HOME={d}/cache"),
        ]
        .map(str::to_owned)
        .to_vec()
    }
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
        let child = Guard(cmd.arg("127.0.0.1").spawn().context("starting ssh -L")?);
        for port in ports {
            wait_for_port(port)?;
        }
        Ok(Self { ports, _child: child })
    }

    /// Starts `sshunnel forward` and returns once it reports both forwards, with how long that took.
    fn sshunnel(client: &Path, sshd: &Sshd, targets: &[String; 2]) -> Result<(Self, Duration)> {
        let ports = [free_port()?, free_port()?];
        let ssh_cmd = std::iter::once("ssh".to_owned()).chain(sshd.ssh_args()).collect::<Vec<_>>().join(" ");
        let mut cmd = Command::new(client);
        cmd.arg("forward").arg("--ssh-cmd").arg(ssh_cmd);
        for (port, target) in ports.iter().zip(targets) {
            cmd.arg("-L").arg(format!("{port}:{target}"));
        }
        let start = Instant::now();
        let mut child = cmd.arg("127.0.0.1").stderr(Stdio::piped()).spawn().context("starting sshunnel forward")?;
        let stderr = child.stderr.take().context("sshunnel has no stderr pipe")?;
        let child = Guard(child);

        let (ready_tx, ready_rx) = mpsc::channel();
        let mut readiness = Readiness::new(targets);
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                eprintln!("  {line}");
                if readiness.saw(&line) {
                    let _ = ready_tx.send(());
                }
            }
        });
        ready_rx.recv_timeout(Duration::from_secs(60)).context("sshunnel didn't report its forwards within 60s")?;
        Ok((Self { ports, _child: child }, start.elapsed()))
    }
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
    use super::*;

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
