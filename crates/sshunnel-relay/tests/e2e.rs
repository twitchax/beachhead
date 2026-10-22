//! The relay binary end to end: spawn it as the bootstrap would, play the client over its stdio,
//! and dial real loopback TCP through it. Tests are named `e2e_*` (serialized and retried by
//! nextest; see `.config/nextest.toml`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{process::Stdio, time::Duration};

use bytes::{Bytes, BytesMut};
use pretty_assertions::assert_eq;
use sshunnel_mux::{
    Config, Flow, FlowEvent, Mux, Role,
    frame::{Capabilities, FlowErrKind, OpenErrKind},
    frame::{ResolveErrKind, Transport},
    hello::{recv_hello, send_hello},
    pump, start,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, duplex, split},
    net::{TcpListener, UdpSocket},
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
    let relay = recv_hello(&mut stdout, &mut buf).await.unwrap();
    send_hello(&mut stdin, Config::default().window(), Capabilities::default()).await.unwrap();
    let (mux, _incoming, driver) = start(stdout, buf, stdin, Role::Client, Config::default(), relay);
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
async fn e2e_stdio_answers_a_resolve() {
    let (mux, _child) = connect().await;
    timeout(Duration::from_secs(30), mux.resolve("localhost")).await.unwrap().unwrap();
    let err = timeout(Duration::from_secs(30), mux.resolve("nonexistent.invalid")).await.unwrap().unwrap_err();
    assert_eq!(err.kind, ResolveErrKind::NoSuchName, "{err}");
}

#[tokio::test]
async fn e2e_stdio_refuses_flows_and_queries_it_does_not_serve_yet() {
    let (mux, _child) = connect().await;
    let err = timeout(Duration::from_secs(30), mux.open_echo("127.0.0.1")).await.unwrap().unwrap_err();
    assert_eq!(err.kind, OpenErrKind::Other, "{err}");
    let err = timeout(Duration::from_secs(30), mux.query(Bytes::from_static(b"q"), Transport::Udp)).await.unwrap().unwrap_err();
    assert_eq!(err.reason, "not answered");
}

/// A loopback UDP echo; returns its port.
async fn udp_echo() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            let (n, from) = socket.recv_from(&mut buf).await.unwrap();
            socket.send_to(&buf[..n], from).await.unwrap();
        }
    });
    port
}

async fn next_event(flow: &mut Flow) -> FlowEvent {
    timeout(Duration::from_secs(30), flow.recv()).await.expect("an event in time").expect("the flow is open")
}

#[tokio::test]
async fn e2e_stdio_carries_udp_both_ways() {
    let port = udp_echo().await;
    let (mux, _child) = connect().await;
    let mut flow = timeout(Duration::from_secs(30), mux.open_udp("127.0.0.1", port)).await.unwrap().unwrap();
    let sender = flow.sender();
    for i in 0..5u8 {
        let datagram = Bytes::from(vec![i; 100 + usize::from(i)]);
        assert!(sender.try_send(datagram.clone()));
        assert_eq!(next_event(&mut flow).await, FlowEvent::Datagram(datagram));
    }
}

#[tokio::test]
async fn e2e_stdio_reports_a_closed_udp_port_as_a_flow_error() {
    let port = {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.local_addr().unwrap().port()
    };
    let (mux, _child) = connect().await;
    let mut flow = timeout(Duration::from_secs(30), mux.open_udp("127.0.0.1", port)).await.unwrap().unwrap();
    let sender = flow.sender();
    // The flow outlives its errors: the second send is answered the same way.
    for _ in 0..2 {
        assert!(sender.try_send(Bytes::from_static(b"anyone?")));
        assert_eq!(next_event(&mut flow).await, FlowEvent::Error(FlowErrKind::PortUnreachable));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_stdio_opens_tcp_by_name_through_the_lookup_path() {
    let port = echo_server().await;
    let (mux, _child) = connect().await;
    let stream = timeout(Duration::from_secs(30), mux.open("localhost", port)).await.unwrap().unwrap();
    let (near, far) = duplex(1024);
    tokio::spawn(pump(stream, near));
    let (mut r, mut w) = split(far);
    w.write_all(b"by name").await.unwrap();
    let mut reply = [0u8; 7];
    timeout(Duration::from_secs(30), r.read_exact(&mut reply)).await.unwrap().unwrap();
    assert_eq!(&reply, b"by name");
}

#[tokio::test]
async fn e2e_stdio_a_udp_open_out_of_descriptors_is_an_open_err() {
    let port = udp_echo().await;
    // `ulimit -n` lowers the soft and hard limits together, so the relay's raise cannot undo it.
    let mut child = Command::new("sh")
        .args(["-c", "ulimit -n 32 && exec \"$0\" --stdio", env!("CARGO_BIN_EXE_sshunnel-relay")])
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut buf = BytesMut::new();
    let hello = recv_hello(&mut stdout, &mut buf).await.unwrap();
    send_hello(&mut stdin, Config::default().window(), Capabilities::default()).await.unwrap();
    let (mux, _incoming, driver) = start(stdout, buf, stdin, Role::Client, Config::default(), hello);
    tokio::spawn(driver);

    let mut open = Vec::new();
    let mut refused = 0;
    for _ in 0..64 {
        match timeout(Duration::from_secs(30), mux.open_udp("127.0.0.1", port)).await.unwrap() {
            Ok(flow) => open.push(flow),
            Err(e) => {
                assert_eq!(e.kind, OpenErrKind::Other, "{e}");
                refused += 1;
            }
        }
    }
    assert!(!open.is_empty() && refused > 0, "{} open, {refused} refused", open.len());
    drop(open);
    // The relay closes a flow's socket once it sees the client's end; retry while it does.
    let mut reopened = None;
    for _ in 0..50 {
        match timeout(Duration::from_secs(30), mux.open_udp("127.0.0.1", port)).await.unwrap() {
            Ok(flow) => {
                reopened = Some(flow);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    assert!(reopened.is_some(), "descriptors never came back");
}

#[tokio::test]
async fn e2e_stdio_exits_cleanly_when_stdin_closes() {
    let mut child = relay().arg("--stdio").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    recv_hello(&mut stdout, &mut BytesMut::new()).await.unwrap();
    send_hello(&mut stdin, Config::default().window(), Capabilities::default()).await.unwrap();
    drop(stdin);
    let status = timeout(Duration::from_secs(10), child.wait()).await.expect("the relay exits").unwrap();
    assert!(status.success(), "{status}");
}
