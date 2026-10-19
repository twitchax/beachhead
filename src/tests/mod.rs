//! Fixtures shared by unit tests, integration tests and benches. Always compiled (not
//! `#[cfg(test)]`), so `tests/` and `benches/` can use it too; keep it free of test-only
//! dependencies.

use std::{
    fmt::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use tokio::{io::AsyncWriteExt as _, net::TcpListener};

use crate::{arch::Arch, base::Res, session::SshCommand};

mod app;
mod tunnel;

pub use app::{AppConn, AppStack, Connect, Icmp, Sent};
pub use tunnel::{FakeConn, FakeTunnel, Gate};

/// A stand-in for a remote machine: a fake `ssh` that ignores its options and destination and runs
/// the remote command here, through a chosen login shell, with `HOME` and every cache candidate
/// except `/dev/shm` inside `root`. That covers push, exec and cache with no sshd.
#[derive(Clone, Debug)]
pub struct FakeRemote {
    root: PathBuf,
    ssh: PathBuf,
}

impl FakeRemote {
    /// Writes the fake `ssh` into `root`. `login_shell` is the command that runs the remote
    /// command (`sh`, `bash`, `busybox sh`, ...), and `env` is exported for it.
    ///
    /// # Errors
    ///
    /// Fails when `root` can't be written or a path would break the script's quoting.
    pub fn new(root: &Path, login_shell: &str, env: &[(&str, &str)]) -> Res<Self> {
        let home = root.join("home");
        std::fs::create_dir_all(&home).context("creating the fake home")?;
        std::fs::create_dir_all(root.join("tmp")).context("creating the fake TMPDIR")?;
        let mut exports = String::new();
        for (key, value) in env {
            // Writing to a String can't fail.
            let _ = writeln!(exports, "export {key}={}", quote(value)?);
        }
        let script = format!(
            "#!/bin/sh\n\
             # A fake ssh: drop the options and the destination, run the remote command here.\n\
             for a do last=$a; done\n\
             printf '%s\\n' \"$@\" > {args}\n\
             unset XDG_CACHE_HOME XDG_RUNTIME_DIR BASH_ENV ENV\n\
             export HOME={home} TMPDIR={tmp}\n\
             {exports}\
             exec {login_shell} -c \"$last\"\n",
            args = quote(&root.join("ssh-args").to_string_lossy())?,
            home = quote(&home.to_string_lossy())?,
            tmp = quote(&root.join("tmp").to_string_lossy())?,
        );
        let ssh = root.join("fake-ssh");
        write_executable(&ssh, &script)?;
        Ok(Self { root: root.to_owned(), ssh })
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
