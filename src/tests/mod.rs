//! Fixtures shared by unit tests, integration tests and benches. Behind the `testing` feature
//! (which the crate's self dev-dependency turns on for its own tests) rather than `#[cfg(test)]`,
//! so `tests/` and `benches/` can use it too. The library build never sees dev-dependencies, so
//! keep it free of them.

use std::{
    ffi::OsStr,
    fmt::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::Duration,
};

use anyhow::{Context as _, bail};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, Command},
    sync::watch,
    task::JoinHandle,
    time::timeout,
};

use crate::{
    arch::Arch,
    base::{Res, Void},
    session::SshCommand,
};
#[cfg(target_os = "linux")]
use {
    crate::route::{
        DEVICE, PIN_PROTO,
        helper::{self, Helper, Setup},
    },
    anyhow::ensure,
    rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair},
    std::os::fd::OwnedFd,
    tokio::net::UnixDatagram,
};

mod app;
#[cfg(target_os = "linux")]
mod netns;
mod tunnel;

pub use app::{AppConn, AppStack, Connect, Icmp, Sent};
#[cfg(target_os = "linux")]
pub use netns::{Namespaces, RemoteNs, netns};
pub use tunnel::{FakeConn, FakeFlow, FakeTunnel, Gate, NoFlow};

/// A stand-in for a remote machine: a fake `ssh` that ignores its options and destination and runs
/// the remote command here, through a chosen login shell, with `HOME` and every cache candidate
/// except `/dev/shm` inside `root`. That covers push, exec and cache with no sshd. The builders give
/// the remote side namespaces of its own: a network ([`Self::in_netns`]) or an `/etc/hosts`
/// ([`Self::with_hosts`]). Not `Clone`: each builder rewrites the one fake `ssh` in `root`.
#[derive(Debug)]
pub struct FakeRemote {
    root: PathBuf,
    ssh: PathBuf,
    login_shell: String,
    exports: String,
    /// What runs the login shell, word by word: the namespaces to enter first.
    wrapper: Vec<String>,
    /// The pid `ssh -O check` reports for a shared-connection master.
    master: Option<u32>,
}

impl FakeRemote {
    /// Writes the fake `ssh` into `root`. `login_shell` is the command that runs the remote
    /// command (`sh`, `bash`, `busybox sh`, ...), and `env` is exported for it.
    ///
    /// # Errors
    ///
    /// Fails when `root` can't be written or a path would break the script's quoting.
    pub fn new(root: &Path, login_shell: &str, env: &[(&str, &str)]) -> Res<Self> {
        std::fs::create_dir_all(root.join("home")).context("creating the fake home")?;
        std::fs::create_dir_all(root.join("tmp")).context("creating the fake TMPDIR")?;
        let mut exports = String::new();
        for (key, value) in env {
            // Writing to a String can't fail.
            let _ = writeln!(exports, "export {key}={}", quote(value)?);
        }
        let remote = Self {
            root: root.to_owned(),
            ssh: root.join("fake-ssh"),
            login_shell: login_shell.to_owned(),
            exports,
            wrapper: Vec::new(),
            master: None,
        };
        remote.write()?;
        Ok(remote)
    }

    /// Runs the remote side in `ns`, the remote's network.
    ///
    /// # Errors
    ///
    /// Fails when the fake `ssh` can't be rewritten.
    #[cfg(target_os = "linux")]
    pub fn in_netns(mut self, ns: &RemoteNs) -> Res<Self> {
        self.wrapper.push(ns.nsenter());
        self.write()?;
        Ok(self)
    }

    /// Runs the remote side with `hosts` as its `/etc/hosts`, bind-mounted in user and mount
    /// namespaces of its own (`unshare -rm`, so any user can, where user namespaces are allowed).
    /// Its `/etc/nsswitch.conf` names that file alone: the remote is this machine, whose resolver
    /// `route` may be sending back to the relay.
    ///
    /// # Errors
    ///
    /// Fails when the files can't be written or a path would break the script's quoting.
    pub fn with_hosts(mut self, hosts: &str) -> Res<Self> {
        let hosts_file = self.root.join("hosts");
        let nsswitch = self.root.join("nsswitch.conf");
        std::fs::write(&hosts_file, hosts).context("writing the remote's hosts file")?;
        std::fs::write(&nsswitch, "hosts: files\n").context("writing the remote's nsswitch.conf")?;
        self.wrapper.push(format!(
            "unshare -rm sh -c {} sh {} {}",
            quote(r#"mount --bind "$1" /etc/hosts && mount --bind "$2" /etc/nsswitch.conf && shift 2 && exec "$@""#)?,
            quote(&hosts_file.to_string_lossy())?,
            quote(&nsswitch.to_string_lossy())?,
        ));
        self.write()?;
        Ok(self)
    }

    /// Answers `ssh -O check` as a shared-connection master with pid `pid` does, rather than
    /// running a remote command.
    ///
    /// # Errors
    ///
    /// Fails when the fake `ssh` can't be rewritten.
    pub fn with_master(mut self, pid: u32) -> Res<Self> {
        self.master = Some(pid);
        self.write()?;
        Ok(self)
    }

    fn write(&self) -> Void {
        let check = self.master.map_or_else(String::new, |pid| {
            format!("if [ \"$1\" = -O ] && [ \"$2\" = check ]; then echo 'Master running (pid={pid})' >&2; exit 0; fi\n")
        });
        let shell = self.wrapper.iter().chain([&self.login_shell]).map(String::as_str).collect::<Vec<_>>().join(" ");
        let script = format!(
            "#!/bin/sh\n\
             # A fake ssh: drop the options and the destination, run the remote command here.\n\
             {check}\
             for a do last=$a; done\n\
             printf '%s\\n' \"$@\" > {args}\n\
             unset XDG_CACHE_HOME XDG_RUNTIME_DIR BASH_ENV ENV\n\
             export HOME={home} TMPDIR={tmp}\n\
             {exports}\
             exec {shell} -c \"$last\"\n",
            args = quote(&self.root.join("ssh-args").to_string_lossy())?,
            home = quote(&self.home().to_string_lossy())?,
            tmp = quote(&self.root.join("tmp").to_string_lossy())?,
            exports = self.exports,
        );
        write_executable(&self.ssh, &script)
    }

    /// The `--ssh-cmd` that reaches this remote.
    ///
    /// # Errors
    ///
    /// Fails when the path won't survive shell splitting.
    pub fn ssh_command(&self) -> Res<SshCommand> {
        SshCommand::parse(&quote(&self.ssh.to_string_lossy())?)
    }

    /// The path of the fake `ssh`.
    #[must_use]
    pub fn ssh_path(&self) -> &Path {
        &self.ssh
    }

    /// The remote's `HOME`.
    #[must_use]
    pub fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    /// The arguments the client passed to the last ssh run, one per line.
    ///
    /// # Errors
    ///
    /// Fails before the first run.
    pub fn last_ssh_args(&self) -> Res<Vec<String>> {
        let args = std::fs::read_to_string(self.root.join("ssh-args")).context("reading the recorded ssh args")?;
        Ok(args.lines().map(str::to_owned).collect())
    }
}

/// This machine's arch: the fake remote is this machine.
///
/// # Errors
///
/// Fails on an arch sshunnel has no relay for.
pub fn host_arch() -> Res<Arch> {
    Arch::from_name(std::env::consts::ARCH).with_context(|| format!("no relay arch for this host ({})", std::env::consts::ARCH))
}

/// The relay binary cargo built for this workspace. `CARGO_BIN_EXE_*` only reaches the relay's own
/// package, so this walks up from the running test executable to the profile dir holding it: that
/// is `target/<profile>/deps/<test>` in the classic layout and deeper under `build/` in the newer
/// build-dir layout.
///
/// # Errors
///
/// Fails when the relay wasn't built, which happens when the tests run without `--workspace`.
pub fn relay_binary() -> Res<PathBuf> {
    let name = format!("sshunnel-relay{}", std::env::consts::EXE_SUFFIX);
    let exe = std::env::current_exe().context("locating the test executable")?;
    exe.ancestors().skip(1).map(|dir| dir.join(&name)).find(|candidate| candidate.is_file()).with_context(|| {
        format!(
            "no {name} above {}: run the tests with `cargo make test` (nextest --workspace) so cargo builds the relay",
            exe.display()
        )
    })
}

/// A relay dir in `root` holding the workspace's relay under this host's arch.
///
/// # Errors
///
/// Fails when the relay is missing or the link can't be made.
pub fn relay_dir(root: &Path) -> Res<PathBuf> {
    let dir = root.join("relays");
    std::fs::create_dir_all(&dir).context("creating the relay dir")?;
    std::os::unix::fs::symlink(relay_binary()?, dir.join(host_arch()?.file_name())).context("linking the relay")?;
    Ok(dir)
}

/// A relay dir in `root` whose relay is a script that refuses to run from any path matching the
/// `case` pattern `noexec`, then execs the real relay. Running it from a matching dir fails the
/// bootstrap's probe exactly as a noexec mount would.
///
/// # Errors
///
/// Fails when the relay is missing or the script can't be written.
pub fn noexec_relay_dir(root: &Path, noexec: &str) -> Res<PathBuf> {
    wrapped_relay_dir(
        root,
        &format!("# Simulates a noexec mount: refuse to run from a matching path.\ncase \"$0\" in {noexec}) exit 126;; esac"),
    )
}

/// A relay dir in `root` whose relay is a script that runs the `sh` lines in `prelude`, then execs
/// the real relay: a relay that misbehaves in one chosen way.
///
/// # Errors
///
/// Fails when the relay is missing or the script can't be written.
pub fn wrapped_relay_dir(root: &Path, prelude: &str) -> Res<PathBuf> {
    let dir = root.join("wrapped-relays");
    std::fs::create_dir_all(&dir).context("creating the relay dir")?;
    let script = format!("#!/bin/sh\n{prelude}\nexec {} \"$@\"\n", quote(&relay_binary()?.to_string_lossy())?);
    write_executable(&dir.join(host_arch()?.file_name()), &script)?;
    Ok(dir)
}

/// A dir in `root` of shims for `tools` that act as if every path matching the `case` pattern
/// `full` sat on a full disk: stdout bound for one goes to `/dev/full` (so writes fail with ENOSPC),
/// and a run whose last argument is one (`cp src dst`) fails outright. Goes first on a remote's
/// `PATH`. Linux only: the shim reads its stdout's target from `/proc`.
///
/// # Errors
///
/// Fails when a tool isn't on `PATH` or a shim can't be written.
pub fn full_disk_dir(root: &Path, full: &str, tools: &[&str]) -> Res<PathBuf> {
    let dir = root.join("full-disk");
    std::fs::create_dir_all(&dir).context("creating the shim dir")?;
    for tool in tools {
        let real = quote(&on_path(tool)?.to_string_lossy())?;
        let script = format!(
            "#!/bin/sh\n\
             # Simulates a full disk under matching paths.\n\
             case $(readlink /proc/$$/fd/1) in {full}) exec {real} \"$@\" > /dev/full;; esac\n\
             last=; for last do :; done\n\
             case $last in {full}) echo \"{tool}: $last: No space left on device\" >&2; exit 1;; esac\n\
             exec {real} \"$@\"\n"
        );
        write_executable(&dir.join(tool), &script)?;
    }
    Ok(dir)
}

/// A dir in `root` of `sh` scripts standing in for tools, given as (name, body) pairs. Ahead of the
/// real `PATH`, each shadows the tool it names.
///
/// # Errors
///
/// Fails when a shim can't be written.
pub fn shim_dir(root: &Path, shims: &[(&str, &str)]) -> Res<PathBuf> {
    let dir = root.join("shims");
    std::fs::create_dir_all(&dir).context("creating the shim dir")?;
    for (tool, body) in shims {
        write_executable(&dir.join(tool), &format!("#!/bin/sh\n{body}\n"))?;
    }
    Ok(dir)
}

/// Where `tool` lives on this machine's `PATH`.
fn on_path(tool: &str) -> Res<PathBuf> {
    let path = std::env::var_os("PATH").context("PATH is not set")?;
    std::env::split_paths(&path)
        .map(|d| d.join(tool))
        .find(|p| p.is_file())
        .with_context(|| format!("{tool} is not on PATH"))
}

/// A dir in `root` holding only `tools`, each linked to the copy on this machine's `PATH`. As a
/// remote's `PATH`, it stands in for a box that lacks everything else (no `sha256sum`, say).
///
/// # Errors
///
/// Fails when a tool isn't on `PATH` or a link can't be made.
pub fn path_with(root: &Path, tools: &[&str]) -> Res<PathBuf> {
    let dir = root.join("bin");
    std::fs::create_dir_all(&dir).context("creating the tool dir")?;
    for tool in tools {
        std::os::unix::fs::symlink(on_path(tool)?, dir.join(tool)).with_context(|| format!("linking {tool}"))?;
    }
    Ok(dir)
}

/// A loopback TCP echo server that half-closes after echoing; returns its address.
///
/// # Errors
///
/// Fails when no loopback port can be bound.
pub async fn echo_server() -> Res<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await.context("binding the echo server")?;
    echo_on(listener)
}

/// Echoes every connection `listener` accepts, half-closing after each, on the current runtime;
/// returns its address.
///
/// # Errors
///
/// Fails when the listener has no address.
pub fn echo_on(listener: TcpListener) -> Res<SocketAddr> {
    let addr = listener.local_addr().context("reading the echo server's address")?;
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = socket.into_split();
                if tokio::io::copy(&mut r, &mut w).await.is_ok() {
                    let _ = w.shutdown().await;
                }
            });
        }
    });
    Ok(addr)
}

/// A loopback UDP echo server; returns its address.
///
/// # Errors
///
/// Fails when no loopback port can be bound.
pub async fn udp_echo_server() -> Res<SocketAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.context("binding the UDP echo server")?;
    udp_echo_on(socket)
}

/// Sends every datagram `socket` receives back to its sender, on the current runtime; returns its
/// address.
///
/// # Errors
///
/// Fails when the socket has no address.
pub fn udp_echo_on(socket: UdpSocket) -> Res<SocketAddr> {
    let addr = socket.local_addr().context("reading the UDP echo server's address")?;
    tokio::spawn(async move {
        let mut buf = vec![0; 65_535];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    Ok(addr)
}

/// A stand-in for the TUN device's fd that keeps packet boundaries, and the far end of it, as the
/// kernel, on the current runtime.
///
/// # Errors
///
/// Fails when the pair can't be made or the far end can't join the runtime.
#[cfg(target_os = "linux")]
pub fn device_pair() -> Res<(OwnedFd, UnixDatagram)> {
    let (tun, kernel) = socketpair(AddressFamily::UNIX, SocketType::SEQPACKET, SocketFlags::CLOEXEC, None).context("making the device's socket pair")?;
    let kernel = std::os::unix::net::UnixDatagram::from(kernel);
    kernel.set_nonblocking(true).context("making the device's far end non-blocking")?;
    Ok((tun, UnixDatagram::from_std(kernel).context("registering the device's far end")?))
}

/// Sends `data` to the echo server at `addr` and reads until it closes; returns what came back.
///
/// # Errors
///
/// Fails when the connection fails or the echo takes over 30 s.
pub async fn round_trip(addr: SocketAddr, data: &[u8]) -> Res<Vec<u8>> {
    let socket = TcpStream::connect(addr).await.with_context(|| format!("connecting to {addr}"))?;
    let (mut r, mut w) = socket.into_split();
    let sent = data.to_vec();
    let writer = tokio::spawn(async move {
        w.write_all(&sent).await?;
        w.shutdown().await
    });
    let mut reply = Vec::new();
    timeout(Duration::from_secs(30), r.read_to_end(&mut reply))
        .await
        .with_context(|| format!("the echo from {addr} didn't finish"))?
        .with_context(|| format!("reading the echo from {addr}"))?;
    writer.await.context("the writer panicked")?.with_context(|| format!("writing to {addr}"))?;
    Ok(reply)
}

/// `sshunnel route` (the binary at `exe`) routing `targets` through the fake `ssh`, as a user
/// would run it but kept to `dir`: its state and socket dirs there, and none of the variables it
/// reads from the environment.
#[must_use]
pub fn route_command(exe: impl AsRef<OsStr>, dir: &Path, ssh: &Path, relays: &Path, targets: &[&str]) -> Command {
    let mut command = Command::new(exe);
    command
        .current_dir(dir)
        .env_remove("SSHUNNEL_RELAY_DIR")
        .env_remove("SSHUNNEL_SSH")
        .env_remove("RUST_LOG")
        .env("XDG_STATE_HOME", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .arg("route")
        .arg("--ssh-cmd")
        .arg(ssh)
        .arg("--relay-dir")
        .arg(relays)
        .arg("fake-host")
        .args(targets);
    command
}

/// `sshunnel route`'s side of the root helper: starts `exe helper` (through sudo unless already root)
/// with its socket in `dir`, sends it `setup` and returns once the device is up. The client code
/// is `route`'s own; only the executable is the caller's, since a test's own isn't sshunnel.
///
/// # Errors
///
/// Fails as [`Helper::start`] does.
#[cfg(target_os = "linux")]
pub async fn start_helper(exe: &Path, dir: &Path, setup: &Setup) -> Res<Helper> {
    let euid = rustix::process::geteuid().as_raw();
    Helper::start_with(setup, dir, |socket| helper::command(exe, socket, euid)).await
}

/// What `sshunnel route` has in this network namespace, one line of `ip` each: its device, any route
/// on the device and any pinned route. Empty once a run is over.
///
/// # Errors
///
/// Fails when `ip` does.
#[cfg(target_os = "linux")]
pub fn leftovers() -> Res<Vec<String>> {
    let pinned = format!("proto {PIN_PROTO}");
    let device = ip(&["-o", "link", "show"])?.into_iter().filter(|link| link.contains(DEVICE));
    let routes = routes()?.into_iter().filter(|route| route.contains(DEVICE) || route.contains(&pinned));
    Ok(device.chain(routes).collect())
}

/// What systemd-resolved still has for `sshunnel route`'s device: its link's line in `resolvectl
/// domain`. Empty once a run is over, since a link's resolver config goes with its device. (Asking
/// `resolvectl status sshunnel0` can't tell: since systemd 259 it ignores a missing link and
/// succeeds.)
///
/// # Errors
///
/// Fails when `resolvectl` does.
#[cfg(target_os = "linux")]
pub fn resolved_leftovers() -> Res<Vec<String>> {
    let out = std::process::Command::new("resolvectl").arg("domain").output().context("running resolvectl")?;
    ensure!(out.status.success(), "resolvectl domain: {}", String::from_utf8_lossy(&out.stderr));
    Ok(device_links(&String::from_utf8(out.stdout).context("resolvectl printed something other than UTF-8")?))
}

/// The lines of a `resolvectl` listing that name [`DEVICE`]'s link.
#[cfg(target_os = "linux")]
fn device_links(listing: &str) -> Vec<String> {
    let link = format!("({DEVICE})");
    listing.lines().filter(|line| line.contains(&link)).map(|line| line.trim().to_owned()).collect()
}

/// Every route in every table, v4 then v6, one line of `ip` each.
///
/// # Errors
///
/// Fails when `ip` does.
#[cfg(target_os = "linux")]
pub fn routes() -> Res<Vec<String>> {
    let mut routes = ip(&["-4", "route", "show", "table", "all"])?;
    routes.extend(ip(&["-6", "route", "show", "table", "all"])?);
    Ok(routes)
}

/// `ip`'s output, trimmed line by line.
///
/// # Errors
///
/// Fails, quoting its stderr, when `ip` does.
#[cfg(target_os = "linux")]
pub fn ip(args: &[&str]) -> Res<Vec<String>> {
    let out = std::process::Command::new("ip").args(args).output().context("running ip")?;
    ensure!(out.status.success(), "ip {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).context("ip printed something other than UTF-8")?;
    Ok(stdout.lines().map(|line| line.trim().to_owned()).collect())
}

/// A process whose stderr is collected line by line as it arrives, so a test can wait for a line and
/// still show everything printed when something goes wrong. It is killed on drop.
pub struct Watched {
    child: Child,
    lines: watch::Receiver<Vec<String>>,
    reader: JoinHandle<()>,
}

impl Watched {
    /// Spawns `command` with its stderr piped here.
    ///
    /// # Errors
    ///
    /// Fails when it can't be spawned.
    pub fn spawn(mut command: Command) -> Res<Self> {
        let mut child = command.stderr(Stdio::piped()).kill_on_drop(true).spawn().context("spawning the process")?;
        let mut stderr = BufReader::new(child.stderr.take().context("the process has no stderr pipe")?).lines();
        let (seen, lines) = watch::channel(Vec::new());
        let reader = tokio::spawn(async move {
            while let Ok(Some(line)) = stderr.next_line().await {
                seen.send_modify(|lines| lines.push(line));
            }
        });
        Ok(Self { child, lines, reader })
    }

    /// The process's pid.
    ///
    /// # Errors
    ///
    /// Fails once it has been waited for.
    pub fn pid(&self) -> Res<u32> {
        self.child.id().context("the process has exited")
    }

    /// Waits up to `within` for a stderr line starting with `prefix`, and returns it.
    ///
    /// # Errors
    ///
    /// Fails, quoting stderr, when stderr closes or time runs out first.
    pub async fn line(&mut self, prefix: &str, within: Duration) -> Res<String> {
        let line = match timeout(within, self.lines.wait_for(|lines| lines.iter().any(|line| line.starts_with(prefix)))).await {
            Ok(Ok(lines)) => lines.iter().find(|line| line.starts_with(prefix)).cloned(),
            Ok(Err(_)) | Err(_) => None,
        };
        line.with_context(|| format!("no line starting `{prefix}`; stderr:\n{}", self.stderr()))
    }

    /// Everything on stderr so far.
    #[must_use]
    pub fn stderr(&self) -> String {
        self.lines.borrow().join("\n")
    }

    /// Waits up to `within` for the process to exit, then for its stderr to close (briefly: a
    /// process it started may still hold it); returns the exit status and all of stderr.
    ///
    /// # Errors
    ///
    /// Fails, quoting stderr, when the process is still running after `within`.
    pub async fn exit(mut self, within: Duration) -> Res<(ExitStatus, String)> {
        let status = match timeout(within, self.child.wait()).await {
            Ok(status) => status.context("waiting for the process")?,
            Err(_) => bail!("still running after {within:?}; stderr:\n{}", self.stderr()),
        };
        let _ = timeout(Duration::from_secs(5), &mut self.reader).await;
        Ok((status, self.stderr()))
    }
}

/// Deterministic bytes that differ per `seed`, so a misrouted chunk can't compare equal.
#[must_use]
pub fn pattern(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

/// Single-quotes `s` for `sh`.
fn quote(s: &str) -> Res<String> {
    if s.contains('\'') {
        bail!("`{s}` contains a single quote");
    }
    Ok(format!("'{s}'"))
}

fn write_executable(path: &Path, contents: &str) -> Res<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).with_context(|| format!("marking {} executable", path.display()))
}

// `unit`, not `tests`: this module is already `tests`.
#[cfg(all(test, target_os = "linux"))]
mod unit {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn resolved_leftovers_are_the_devices_link() {
        let listing = "Global:\nLink 2 (eth0): ~.\nLink 15 (sshunnel0): ~corp.example\nLink 16 (sshunnel0x):\n";
        assert_eq!(device_links(listing), ["Link 15 (sshunnel0): ~corp.example"]);
        assert_eq!(device_links("Global:\nLink 2 (eth0): ~.\n"), Vec::<String>::new());
    }
}
