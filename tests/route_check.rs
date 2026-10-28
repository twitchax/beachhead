//! `sshunnel route --check` and `sshunnel sudoers` as a user runs them, touching nothing outside a
//! scratch dir: a shim sudo that would ask for a password (`sudo -n` exits 1) first on `PATH`,
//! `FakeRemote` as ssh, and CIDR targets in `192.0.2.0/24`, so neither a resolver nor sudoers is
//! involved. Named `e2e_*` because they spawn the binary.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use pretty_assertions::assert_eq;
use rustix::process::{Pid, Signal, geteuid, kill_process};
use sshunnel::{
    route::{
        DEVICE,
        sudoers::{INSTALL_DIR, root_only},
    },
    tests::{FakeRemote, relay_dir, route_command, shim_dir},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt as _, BufReader},
    process::Command,
    time::timeout,
};

/// How long a check may take, or a stopped one to exit.
const WITHIN: Duration = Duration::from_secs(30);

/// One test's world: a scratch dir, a fake ssh into this machine, and the shim sudo's `PATH`.
struct World {
    dir: TempDir,
    remote: FakeRemote,
    relays: PathBuf,
    path: OsString,
}

impl World {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let remote = FakeRemote::new(dir.path(), "sh", &[]).unwrap();
        let relays = relay_dir(dir.path()).unwrap();
        let shims = shim_dir(dir.path(), &[("sudo", "exit 1")]).unwrap();
        let path = std::env::var_os("PATH").unwrap_or_default();
        let path = std::env::join_paths(std::iter::once(shims).chain(std::env::split_paths(&path))).unwrap();
        Self { dir, remote, relays, path }
    }

    /// `route --check` through `ssh`, with the shim sudo first on `PATH`.
    fn check(&self, ssh: &Path, targets: &[&str]) -> Command {
        let mut command = route_command(env!("CARGO_BIN_EXE_sshunnel"), self.dir.path(), ssh, &self.relays, targets);
        command.arg("--check").env("PATH", &self.path).stdin(Stdio::null()).kill_on_drop(true);
        command
    }

    /// Runs `route --check` to the end; returns its exit code, stdout and stderr.
    async fn run(&self, ssh: &Path, targets: &[&str]) -> (Option<i32>, String, String) {
        let out = timeout(WITHIN, self.check(ssh, targets).output()).await.expect("route --check hung").unwrap();
        (out.status.code(), String::from_utf8(out.stdout).unwrap(), String::from_utf8(out.stderr).unwrap())
    }

    /// Runs `sshunnel sudoers` to the end, with the shim sudo first on `PATH` and its probe's
    /// socket dir here; returns its exit code, stdout and stderr.
    async fn sudoers(&self) -> (Option<i32>, String, String) {
        let mut sudoers = Command::new(env!("CARGO_BIN_EXE_sshunnel"));
        sudoers
            .arg("sudoers")
            .env("PATH", &self.path)
            .env("XDG_RUNTIME_DIR", self.dir.path())
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .kill_on_drop(true);
        let out = timeout(WITHIN, sudoers.output()).await.expect("sshunnel sudoers hung").unwrap();
        (out.status.code(), String::from_utf8(out.stdout).unwrap(), String::from_utf8(out.stderr).unwrap())
    }

    /// The probe's socket dirs left in the scratch dir.
    fn socket_dirs(&self) -> usize {
        std::fs::read_dir(self.dir.path())
            .unwrap()
            .filter(|entry| entry.as_ref().unwrap().file_name().to_string_lossy().starts_with("sshunnel-"))
            .count()
    }
}

/// The check and status of each finding line (`targets  ok: ...`), skipping a detail's
/// continuation lines.
fn findings(stdout: &str) -> Vec<(String, String)> {
    stdout
        .lines()
        .filter(|line| !line.starts_with(char::is_whitespace) && !line.starts_with("sshunnel:"))
        .map(|line| {
            let mut words = line.split_whitespace();
            let check = words.next().unwrap_or_default().to_owned();
            let status = words.next().unwrap_or_default().trim_end_matches(':').to_owned();
            (check, status)
        })
        .collect()
}

fn pairs(expected: &[(&str, &str)]) -> Vec<(String, String)> {
    expected.iter().map(|(check, status)| ((*check).to_owned(), (*status).to_owned())).collect()
}

/// What the sudo check says with the shim on `PATH`: root never asks sudo.
fn sudo_status() -> &'static str {
    if geteuid().is_root() { "ok" } else { "warn" }
}

/// Whether a real route, up when the test starts, holds the device: the check then fails it.
fn device_taken() -> bool {
    Path::new("/sys/class/net").join(DEVICE).exists()
}

fn device_status(taken: bool) -> &'static str {
    if taken { "fail" } else { "ok" }
}

#[tokio::test]
async fn e2e_route_check_reports_every_check_and_exits_0() {
    let world = World::new();
    let taken = device_taken();

    let (code, stdout, stderr) = world.run(world.remote.ssh_path(), &["192.0.2.0/24"]).await;

    assert_eq!(code, Some(i32::from(taken)), "stdout:\n{stdout}\nstderr:\n{stderr}");
    let mut found = findings(&stdout);
    let (ping, status) = found.pop().unwrap();
    assert_eq!(found, pairs(&[("targets", "ok"), ("device", device_status(taken)), ("sudo", sudo_status()), ("ssh", "ok")]), "{stdout}");
    // The remote's ping range decides.
    assert!(ping == "ping" && (status == "ok" || status == "warn"), "{stdout}");
    if taken {
        assert_eq!(stdout.lines().count(), 5, "{stdout}");
        assert_eq!(stderr.lines().last(), Some("error: route would not start: 1 problem"), "{stderr}");
    } else {
        assert_eq!(stdout.lines().count(), 6, "{stdout}");
        assert_eq!(stdout.lines().last(), Some("sshunnel: route can start"));
    }

    // Changes nothing here: no fake-address map, and the probe's socket dir is gone.
    assert!(!world.dir.path().join("sshunnel/names").exists());
    assert_eq!(world.socket_dirs(), 0);
}

#[tokio::test]
async fn e2e_route_check_reports_every_problem_and_exits_1() {
    let world = World::new();
    let taken = device_taken();

    let (code, stdout, stderr) = world.run(Path::new("false"), &["0.0.0.0/0"]).await;

    assert_eq!(code, Some(1), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(
        findings(&stdout),
        pairs(&[("targets", "fail"), ("device", device_status(taken)), ("sudo", sudo_status()), ("ssh", "fail")]),
        "{stdout}"
    );
    let problems = if taken { 3 } else { 2 };
    assert_eq!(stderr.lines().last(), Some(format!("error: route would not start: {problems} problems").as_str()), "{stderr}");
}

#[tokio::test]
async fn e2e_route_check_prints_the_local_checks_before_ssh() {
    let world = World::new();
    // An ssh to a host that never answers.
    let ssh = shim_dir(&world.dir.path().join("hanging"), &[("ssh", "exec sleep 30")]).unwrap().join("ssh");
    let mut check = world.check(&ssh, &["192.0.2.0/24"]).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut lines = BufReader::new(check.stdout.take().unwrap()).lines();

    let mut seen = Vec::new();
    let local = timeout(Duration::from_secs(5), async {
        while seen.len() < 3 {
            match lines.next_line().await.unwrap() {
                Some(line) => seen.push(line),
                None => break,
            }
        }
    })
    .await;

    let pid = Pid::from_raw(check.id().unwrap().try_into().unwrap()).unwrap();
    kill_process(pid, Signal::TERM).unwrap();
    timeout(WITHIN, check.wait()).await.expect("route --check ignored SIGTERM").unwrap();
    assert!(local.is_ok(), "the local checks waited for ssh; stdout so far: {seen:#?}");
    let checks: Vec<String> = findings(&seen.join("\n")).into_iter().map(|(check, _)| check).collect();
    assert_eq!(checks, ["targets", "device", "sudo"], "{seen:#?}");
}

#[tokio::test]
async fn e2e_sudoers_prints_the_setup() {
    let world = World::new();

    let (code, stdout, stderr) = world.sudoers().await;

    let output = format!("stdout:\n{stdout}\nstderr:\n{stderr}");
    if geteuid().is_root() {
        assert_eq!(code, Some(1), "{output}");
        assert_eq!(stderr.lines().last(), Some("error: run `sshunnel sudoers` as the user who will run route, not as root"), "{output}");
    } else if root_only(Path::new(INSTALL_DIR)).unwrap() {
        assert_eq!(code, Some(0), "{output}");
        // The test binary is cargo's, which this user can write: the script installs it.
        let exe = Path::new(env!("CARGO_BIN_EXE_sshunnel")).canonicalize().unwrap();
        let install = format!("install -o root -g root -m 0755 {} /usr/local/bin/sshunnel", exe.display());
        assert!(stdout.contains(&install), "{output}");
        let user = std::process::Command::new("id").arg("-un").output().unwrap();
        let user = String::from_utf8(user.stdout).unwrap();
        let uid = std::process::Command::new("id").arg("-u").output().unwrap();
        let uid = String::from_utf8(uid.stdout).unwrap();
        let allowed = format!("'# {}' '#{} ALL=(root) NOPASSWD: /usr/local/bin/sshunnel helper --socket *'", user.trim(), uid.trim());
        assert!(stdout.lines().any(|line| line.contains(&allowed)), "{output}");
        assert_eq!(stdout.lines().last(), Some("# Right now, sudo asks for a password to start the helper."), "{output}");
        assert_eq!(world.socket_dirs(), 0, "the probe's socket dir is left behind");
    } else {
        // Here the binary can only be installed somewhere others can write, so no line can name it.
        assert_eq!(code, Some(1), "{output}");
        let last = stderr.lines().last().unwrap_or_default();
        let refused = format!("error: {INSTALL_DIR} can be written by users other than root, so a sudoers line can't safely name a binary in it; ");
        assert!(last.starts_with(&refused), "{output}");
        // The way forward is a root-owned copy under /opt, unless what's there is open to others too.
        let opt = Path::new("/opt/sshunnel/bin").ancestors().find(|dir| dir.exists()).unwrap().canonicalize().unwrap();
        if root_only(&opt).unwrap() {
            let exe = Path::new(env!("CARGO_BIN_EXE_sshunnel")).canonicalize().unwrap();
            let install = format!("`sudo install -D -o root -g root -m 0755 {} /opt/sshunnel/bin/sshunnel`", exe.display());
            assert!(last.contains(&install), "{output}");
            assert!(last.ends_with("then run both sudoers and route as that copy: `/opt/sshunnel/bin/sshunnel sudoers`"), "{output}");
        } else {
            assert!(
                last.ends_with(" can be too, so install sshunnel in another directory only root can write, and run both sudoers and route as that copy"),
                "{output}"
            );
        }
        assert!(stdout.is_empty(), "{output}");
    }
}
