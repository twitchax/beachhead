//! `sshunnel route --check` as a user runs it, touching nothing outside a scratch dir: a shim sudo
//! that would ask for a password (`sudo -n` exits 1) first on `PATH`, `FakeRemote` as ssh, and CIDR
//! targets in `192.0.2.0/24`, so neither a resolver nor sudoers is involved. Named `e2e_*` because
//! they spawn the binary.

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
use sshunnel::tests::{FakeRemote, relay_dir, route_command, shim_dir};
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

#[tokio::test]
async fn e2e_route_check_reports_every_check_and_exits_0() {
    let world = World::new();

    let (code, stdout, stderr) = world.run(world.remote.ssh_path(), &["192.0.2.0/24"]).await;

    assert_eq!(code, Some(0), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(stdout.lines().count(), 6, "{stdout}");
    let mut found = findings(&stdout);
    let (ping, status) = found.pop().unwrap();
    assert_eq!(found, pairs(&[("targets", "ok"), ("device", "ok"), ("sudo", sudo_status()), ("ssh", "ok")]), "{stdout}");
    // The remote's ping range decides.
    assert!(ping == "ping" && (status == "ok" || status == "warn"), "{stdout}");
    assert_eq!(stdout.lines().last(), Some("sshunnel: route can start"));

    // Changes nothing here: no fake-address map, and the probe's socket dir is gone.
    assert!(!world.dir.path().join("sshunnel/names").exists());
    let socket_dirs = std::fs::read_dir(world.dir.path())
        .unwrap()
        .filter(|entry| entry.as_ref().unwrap().file_name().to_string_lossy().starts_with("sshunnel-"));
    assert_eq!(socket_dirs.count(), 0);
}

#[tokio::test]
async fn e2e_route_check_reports_every_problem_and_exits_1() {
    let world = World::new();

    let (code, stdout, stderr) = world.run(Path::new("false"), &["0.0.0.0/0"]).await;

    assert_eq!(code, Some(1), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(findings(&stdout), pairs(&[("targets", "fail"), ("device", "ok"), ("sudo", sudo_status()), ("ssh", "fail")]), "{stdout}");
    assert_eq!(stderr.lines().last(), Some("error: route would not start: 2 problems"), "{stderr}");
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
