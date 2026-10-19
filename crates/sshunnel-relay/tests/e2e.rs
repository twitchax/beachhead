//! The relay binary end to end: spawn it as the bootstrap would, play the client over its stdio,
//! and dial real loopback TCP through it. Tests are named `e2e_*` (serialized and retried by
//! nextest; see `.config/nextest.toml`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{process::Stdio, time::Duration};

use bytes::BytesMut;
use pretty_assertions::assert_eq;
use sshunnel_mux::{
    Config, Mux, Role,
    frame::ResolveErrKind,
    hello::{recv_hello, send_hello},
    pump, start,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, duplex, split},
    net::TcpListener,
    process::{Child, Command},
    time::timeout,
};

fn relay() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sshunnel-relay"));
    cmd.kill_on_drop(true);
    cmd
}

/// Spawns `relay --stdio`, shakes hands, and returns the client's mux.
async fn connect() -> (Mux, Child) {
    let mut child = relay().arg("--stdio").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut buf = BytesMut::new();
    let relay_window = recv_hello(&mut stdout, &mut buf).await.unwrap();
    send_hello(&mut stdin, Config::default().window()).await.unwrap();
    let (mux, _incoming, driver) = start(stdout, buf, stdin, Role::Client, Config::default(), relay_window);
    tokio::spawn(driver);
    (mux, child)
}

/// A loopback TCP echo server; returns its port.
async fn echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = sock.into_split();
                tokio::io::copy(&mut r, &mut w).await.unwrap();
                w.shutdown().await.unwrap();
            });
        }
    });
    port
}

#[tokio::test]
async fn e2e_probe_prints_the_version_and_exits_zero() {
    let out = relay().arg("--probe").output().await.unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.starts_with(concat!("sshunnel-relay ", env!("CARGO_PKG_VERSION"))), "{stdout}");
}

#[tokio::test]
async fn e2e_unknown_arguments_exit_with_usage() {
    let out = relay().arg("--bogus").output().await.unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_stdio_dials_tcp_and_carries_bytes_both_ways() {
    let port = echo_server().await;
    let (mux, _child) = connect().await;

    let stream = mux.open("127.0.0.1", port).await.unwrap();
    let (near, far) = duplex(64 * 1024);
    let pumped = tokio::spawn(pump(stream, near));
    let data: Vec<u8> = (0..2_000_000u32).map(|i| (i % 251) as u8).collect();
    let (mut r, mut w) = split(far);
    let sent = data.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&sent).await.unwrap();
        w.shutdown().await.unwrap();
    });
    let mut reply = Vec::new();
    timeout(Duration::from_secs(30), r.read_to_end(&mut reply)).await.unwrap().unwrap();
    writer.await.unwrap();
    assert!(reply == data, "echo differs: {} of {} bytes back", reply.len(), data.len());
    assert_eq!(pumped.await.unwrap().unwrap().received, data.len() as u64);
}

#[tokio::test]
async fn e2e_stdio_reports_a_refused_dial() {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let (mux, _child) = connect().await;
    let err = mux.open("127.0.0.1", port).await.unwrap_err();
    assert!(format!("{err:#}").to_lowercase().contains("refused"), "{err:#}");
}

#[tokio::test]
async fn e2e_stdio_reports_a_refused_dial_with_its_kind() {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let (mux, _child) = connect().await;
    let err = mux.open("127.0.0.1", port).await.unwrap_err();
    assert_eq!(err.kind, sshunnel_mux::frame::OpenErrKind::Refused);
}

#[tokio::test]
async fn relay_answers_a_resolve() {
    let (mux, _child) = connect().await;
    timeout(Duration::from_secs(30), mux.resolve("localhost")).await.unwrap().unwrap();
    let err = timeout(Duration::from_secs(30), mux.resolve("nonexistent.invalid")).await.unwrap().unwrap_err();
    assert_eq!(err.kind, ResolveErrKind::NoSuchName, "{err}");
}

#[tokio::test]
async fn e2e_stdio_exits_cleanly_when_stdin_closes() {
    let mut child = relay().arg("--stdio").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    recv_hello(&mut stdout, &mut BytesMut::new()).await.unwrap();
    send_hello(&mut stdin, Config::default().window()).await.unwrap();
    drop(stdin);
    let status = timeout(Duration::from_secs(10), child.wait()).await.expect("the relay exits").unwrap();
    assert!(status.success(), "{status}");
}
