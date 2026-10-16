//! End to end: spawn the real binary as a user would, inside a scratch directory, with the remote
//! played by a fake `ssh` (see `FakeRemote`). Tests here are named `e2e_*`, which nextest
//! serializes and retries (see `.config/nextest.toml`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{process::Stdio, time::Duration};

use beachhead::{
    arch::Arch,
    relays::Relays,
    tests::{FakeRemote, echo_server, host_arch, pattern, relay_dir},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::TcpStream,
    process::{Child, Command},
    time::timeout,
};

/// The binary with the env vars it reads cleared, so the host environment can't leak in.
fn beachhead(dir: &TempDir) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_beachhead"));
    cmd.current_dir(dir.path())
        .env_remove("BEACHHEAD_RELAY_DIR")
        .env_remove("BEACHHEAD_SSH")
        .env_remove("RUST_LOG")
        .kill_on_drop(true);
    cmd
}

/// Starts `beachhead forward` and waits for its `forwarding <addr> -> ...` line; returns the
/// child and the local address. The child's remaining stderr keeps draining in the background.
async fn start_forward(dir: &TempDir, target: &str) -> (Child, String, Vec<String>) {
    let remote = FakeRemote::new(dir.path(), "sh", &[]).unwrap();
    let relays = relay_dir(dir.path()).unwrap();
    let mut child = beachhead(dir)
        .args(["forward", "-L", &format!("0:{target}"), "--ssh-cmd"])
        .arg(remote.ssh_path())
        .arg("--relay-dir")
        .arg(&relays)
        .arg("fake-host")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let mut seen = Vec::new();
    let addr = timeout(Duration::from_secs(30), async {
        loop {
            let line = lines.next_line().await.unwrap().unwrap_or_else(|| panic!("beachhead exited; stderr:\n{}", seen.join("\n")));
            if let Some(rest) = line.strip_prefix("beachhead: forwarding ") {
                let addr = rest.split_whitespace().next().unwrap().to_owned();
                seen.push(line);
                return addr;
            }
            seen.push(line);
        }
    })
    .await
    .expect("beachhead starts forwarding");
    tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
    (child, addr, seen)
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_forward_carries_tcp() {
    let dir = TempDir::new().unwrap();
    let echo = echo_server().await.unwrap();
    let (_child, addr, stderr) = start_forward(&dir, &format!("127.0.0.1:{}", echo.port())).await;
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
async fn e2e_forward_to_a_closed_port_closes_the_local_connection() {
    let dir = TempDir::new().unwrap();
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let (_child, addr, _) = start_forward(&dir, &closed.to_string()).await;
    let mut socket = TcpStream::connect(&addr).await.unwrap();
    let mut buf = Vec::new();
    let read = timeout(Duration::from_secs(10), socket.read_to_end(&mut buf)).await.expect("the local connection closes");
    assert!(read.is_err() || buf.is_empty());
}

#[tokio::test]
async fn e2e_relays_lists_each_arch_with_its_sha256() {
    let dir = TempDir::new().unwrap();
    let relays_dir = relay_dir(dir.path()).unwrap();
    let out = beachhead(&dir).arg("relays").arg("--relay-dir").arg(&relays_dir).output().await.unwrap();
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
    let out = beachhead(&dir).arg("relays").output().await.unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--relay-dir"));
}

#[tokio::test]
async fn e2e_forward_rejects_a_malformed_spec() {
    let dir = TempDir::new().unwrap();
    let out = beachhead(&dir).args(["forward", "-L", "8080", "somewhere"]).output().await.unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("[bind_address:]port:host:hostport"));
}
