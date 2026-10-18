//! The multiplexer end to end, in process: a client mux and a relay mux joined by a
//! `tokio::io::duplex` "ssh pipe", with duplex pairs standing in for TCP sockets. Small windows and
//! buffer capacities force flow control to do real work. Paused-clock tests use `sleep` only as a
//! quiescence probe: with the clock paused, time advances only once every task is blocked.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::BytesMut;
use pretty_assertions::assert_eq;
use sshunnel_mux::{
    Config, Incoming, Mux, Role,
    frame::{Frame, StreamId},
    pump, start,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, duplex, split},
    task::JoinHandle,
    time::{sleep, timeout},
};

const WINDOW: u32 = 16 * 1024;
const CHUNK: usize = 4 * 1024;
const PIPE_CAP: usize = 8 * 1024;
const SOCK_CAP: usize = 4 * 1024;

fn small() -> Config {
    Config::new(WINDOW, CHUNK).unwrap()
}

/// Deterministic, stream-specific bytes (xorshift64), so a misrouted chunk can't compare equal.
fn pattern(seed: u64, len: usize) -> Vec<u8> {
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

/// Starts a client and a relay mux over one in-memory pipe and serves the relay side.
fn connect(config: Config) -> Mux {
    let (a, b) = duplex(PIPE_CAP);
    let (ar, aw) = split(a);
    let (br, bw) = split(b);
    let (client, _client_incoming, client_driver) = start(ar, BytesMut::new(), aw, Role::Client, config);
    let (_relay, relay_incoming, relay_driver) = start(br, BytesMut::new(), bw, Role::Relay, config);
    tokio::spawn(client_driver);
    tokio::spawn(relay_driver);
    tokio::spawn(serve(relay_incoming));
    client
}

/// The relay's stand-in targets, picked by the `Open` host.
async fn serve(mut incoming: Incoming) {
    while let Some(request) = incoming.next().await {
        match request.host() {
            "echo" => {
                let (near, far) = duplex(SOCK_CAP);
                tokio::spawn(pump(request.accept(), near));
                tokio::spawn(async move {
                    let (mut r, mut w) = split(far);
                    tokio::io::copy(&mut r, &mut w).await.unwrap();
                    w.shutdown().await.unwrap();
                });
            }
            // A target that accepts and then never reads: the stalled consumer.
            "sink" => {
                let (near, far) = duplex(SOCK_CAP);
                tokio::spawn(pump(request.accept(), near));
                tokio::spawn(async move {
                    let _held = far;
                    std::future::pending::<()>().await;
                });
            }
            // Reads to EOF, then answers with the byte count: data must flow back after a Fin.
            "count" => {
                let (near, far) = duplex(SOCK_CAP);
                tokio::spawn(pump(request.accept(), near));
                tokio::spawn(async move {
                    let (mut r, mut w) = split(far);
                    let mut all = Vec::new();
                    r.read_to_end(&mut all).await.unwrap();
                    w.write_all(all.len().to_string().as_bytes()).await.unwrap();
                    w.shutdown().await.unwrap();
                });
            }
            // Reads a little, then vanishes: the relay's pump fails and resets the stream.
            "vanish" => {
                let (near, far) = duplex(SOCK_CAP);
                tokio::spawn(pump(request.accept(), near));
                tokio::spawn(async move {
                    let mut far = far;
                    let mut first = [0; 16];
                    far.read_exact(&mut first).await.unwrap();
                    drop(far);
                });
            }
            // Opens, then hangs up at once: an open that only needs to succeed.
            "accept" => drop(request.accept()),
            "refuse" => request.reject("connection refused"),
            other => panic!("unexpected host {other}"),
        }
    }
}

/// Opens `host` through `mux` and returns the test's end of the client-side socket.
async fn open(mux: &Mux, host: &str) -> (DuplexStream, JoinHandle<anyhow::Result<sshunnel_mux::Traffic>>) {
    let stream = mux.open(host, 7).await.unwrap();
    let (near, far) = duplex(SOCK_CAP);
    (far, tokio::spawn(pump(stream, near)))
}

/// Writes `data` then half-closes, while reading the reply to EOF.
async fn round_trip(sock: DuplexStream, data: Vec<u8>) -> Vec<u8> {
    let (mut r, mut w) = split(sock);
    let writer = tokio::spawn(async move {
        w.write_all(&data).await.unwrap();
        w.shutdown().await.unwrap();
    });
    let mut reply = Vec::new();
    r.read_to_end(&mut reply).await.unwrap();
    writer.await.unwrap();
    reply
}

/// Writes 1 KiB at a time forever, counting what the socket accepts.
fn produce(sock: DuplexStream) -> (Arc<AtomicUsize>, JoinHandle<()>) {
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    let task = tokio::spawn(async move {
        let mut sock = sock;
        let block = [0x5A; 1024];
        loop {
            let n = sock.write(&block).await.unwrap();
            counter.fetch_add(n, Ordering::SeqCst);
        }
    });
    (accepted, task)
}

/// With the clock paused, this returns only once every task is blocked.
async fn quiesce() {
    sleep(Duration::from_secs(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fifty_concurrent_streams_echo_intact() {
    let mux = connect(small());
    let mut tasks = tokio::task::JoinSet::new();
    for seed in 0..50 {
        let mux = mux.clone();
        tasks.spawn(async move {
            let data = pattern(seed, 256 * 1024);
            let (sock, pumped) = open(&mux, "echo").await;
            let reply = round_trip(sock, data.clone()).await;
            assert!(reply == data, "stream {seed}: echo differs ({} of {} bytes back)", reply.len(), data.len());
            let traffic = pumped.await.unwrap().unwrap();
            assert_eq!((traffic.sent, traffic.received), (data.len() as u64, data.len() as u64));
        });
    }
    let all = timeout(Duration::from_secs(60), async {
        while let Some(done) = tasks.join_next().await {
            done.unwrap();
        }
    });
    all.await.expect("50 streams finish");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_opens_reach_the_peer_in_id_order() {
    // The relay resets any id at or below the last it saw, so an Open that loses a race to the
    // wire fails. Enough opens across 8 threads make that race all but certain to show.
    const OPENS: usize = 10_000;
    let mux = connect(small());
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..OPENS {
        let mux = mux.clone();
        tasks.spawn(async move { mux.open("accept", 7).await.map(drop) });
    }
    let mut failures = Vec::new();
    let all = timeout(Duration::from_secs(60), async {
        while let Some(done) = tasks.join_next().await {
            if let Err(e) = done.unwrap() {
                failures.push(format!("{e:#}"));
            }
        }
    });
    all.await.expect("every open finishes");
    assert!(failures.is_empty(), "{} of {OPENS} opens failed, e.g. {}", failures.len(), failures[0]);
}

#[tokio::test(start_paused = true)]
async fn stalled_stream_does_not_block_others() {
    let mux = connect(small());
    let (stalled_sock, _stalled_pump) = open(&mux, "sink").await;
    let (_accepted, stalled) = produce(stalled_sock);
    quiesce().await;
    assert!(!stalled.is_finished(), "the sink never reads, so its producer must be parked");

    let data = pattern(1, 512 * 1024);
    let (sock, _pump) = open(&mux, "echo").await;
    let reply = timeout(Duration::from_secs(30), round_trip(sock, data.clone())).await.expect("echo completes beside a stalled stream");
    assert!(reply == data);
    assert!(!stalled.is_finished());
}

#[tokio::test(start_paused = true)]
async fn stalled_consumer_caps_producer_at_one_window() {
    let mux = connect(small());
    let (sock, _pump) = open(&mux, "sink").await;
    let (accepted, _producer) = produce(sock);
    quiesce().await;

    // In flight once everything parks: one window of credit, plus the chunk the client's pump
    // holds while it waits for credit, plus what the client socket buffers, plus what the sink's
    // socket buffers before its writer blocks. The relay consumed less than half a window, so it
    // never granted credit back.
    let accepted = accepted.load(Ordering::SeqCst);
    let window = WINDOW as usize;
    let ceiling = window + CHUNK + SOCK_CAP + SOCK_CAP;
    assert!((window..=ceiling).contains(&accepted), "accepted {accepted} bytes, expected {window}..={ceiling}");
}

#[tokio::test]
async fn data_flows_back_after_a_half_close() {
    let mux = connect(small());
    let (sock, _pump) = open(&mux, "count").await;
    let reply = round_trip(sock, pattern(2, 100_000)).await;
    assert_eq!(String::from_utf8(reply).unwrap(), "100000");
}

#[tokio::test]
async fn a_refused_open_reports_the_reason() {
    let mux = connect(small());
    let err = mux.open("refuse", 7).await.unwrap_err();
    assert!(err.to_string().contains("connection refused"), "{err:#}");
}

#[tokio::test]
async fn a_vanished_target_resets_the_client_stream() {
    let mux = connect(small());
    let (sock, pumped) = open(&mux, "vanish").await;
    let (mut r, mut w) = split(sock);
    w.write_all(&pattern(3, 64 * 1024)).await.ok();
    let mut rest = Vec::new();
    timeout(Duration::from_secs(10), r.read_to_end(&mut rest)).await.expect("the client socket closes").ok();
    let err = pumped.await.unwrap().unwrap_err();
    assert!(format!("{err:#}").contains("reset"), "{err:#}");
}

#[tokio::test]
async fn a_dead_connection_fails_opens_and_live_streams() {
    let (a, b) = duplex(PIPE_CAP);
    let (ar, aw) = split(a);
    let (client, _incoming, driver) = start(ar, BytesMut::new(), aw, Role::Client, small());
    let driver = tokio::spawn(driver);

    let (mut br, mut bw) = split(b);
    let opener = {
        let client = client.clone();
        tokio::spawn(async move { client.open("echo", 7).await })
    };
    // Play the relay by hand: accept the open, then hang up.
    let mut buf = BytesMut::new();
    let open = loop {
        if let Some(frame) = Frame::decode(&mut buf).unwrap() {
            break frame;
        }
        assert!(br.read_buf(&mut buf).await.unwrap() > 0);
    };
    let Frame::Open { stream, .. } = open else { panic!("expected Open, got {open:?}") };
    let mut ok = BytesMut::new();
    Frame::OpenOk { stream }.encode(&mut ok).unwrap();
    bw.write_all(&ok).await.unwrap();
    let live = opener.await.unwrap().unwrap();
    let (near, _far) = duplex(SOCK_CAP);
    let pumped = tokio::spawn(pump(live, near));

    drop((br, bw));
    timeout(Duration::from_secs(10), driver).await.expect("the driver notices the hangup").unwrap().ok();
    assert!(client.open("echo", 7).await.is_err(), "opens fail once the connection is gone");
    assert!(pumped.await.unwrap().is_err(), "live streams fail once the connection is gone");
}

/// Reads frames from a hand-driven peer until one matches.
async fn next_frame(r: &mut (impl tokio::io::AsyncRead + Unpin), buf: &mut BytesMut) -> Frame {
    loop {
        if let Some(frame) = Frame::decode(buf).unwrap() {
            return frame;
        }
        assert!(r.read_buf(buf).await.unwrap() > 0, "peer hung up");
    }
}

#[tokio::test]
async fn a_peer_exceeding_its_credit_is_reset() {
    let (a, b) = duplex(PIPE_CAP);
    let (ar, aw) = split(a);
    let (client, _incoming, driver) = start(ar, BytesMut::new(), aw, Role::Client, small());
    tokio::spawn(driver);
    let (mut br, mut bw) = split(b);

    let opener = tokio::spawn(async move { client.open("x", 7).await });
    let mut buf = BytesMut::new();
    let Frame::Open { stream, .. } = next_frame(&mut br, &mut buf).await else {
        panic!("expected Open")
    };
    let mut out = BytesMut::new();
    Frame::OpenOk { stream }.encode(&mut out).unwrap();
    bw.write_all(&out).await.unwrap();
    // Hold the stream unpumped, so nothing is consumed and no credit comes back.
    let _held = opener.await.unwrap().unwrap();

    // One byte more than the window the client granted.
    let mut out = BytesMut::new();
    let mut left = WINDOW as usize + 1;
    while left > 0 {
        let n = left.min(CHUNK);
        Frame::Data { stream, data: vec![0; n].into() }.encode(&mut out).unwrap();
        left -= n;
    }
    let sender = tokio::spawn(async move {
        bw.write_all(&out).await.unwrap();
        bw
    });
    let reset = loop {
        match next_frame(&mut br, &mut buf).await {
            Frame::Rst { stream: s, reason } if s == stream => break reason,
            _ => {}
        }
    };
    assert!(reset.contains("credit"), "{reset}");
    sender.await.unwrap();
}

#[tokio::test]
async fn an_open_with_the_wrong_parity_is_reset() {
    let (a, b) = duplex(PIPE_CAP);
    let (ar, aw) = split(a);
    // The client opens odd ids, so an odd id arriving from the relay is the client's own space.
    let (_client, _incoming, driver) = start(ar, BytesMut::new(), aw, Role::Client, small());
    tokio::spawn(driver);
    let (mut br, mut bw) = split(b);

    let mut out = BytesMut::new();
    Frame::Open {
        stream: StreamId(1),
        host: "x".into(),
        port: 1,
    }
    .encode(&mut out)
    .unwrap();
    bw.write_all(&out).await.unwrap();
    let mut buf = BytesMut::new();
    let frame = next_frame(&mut br, &mut buf).await;
    assert!(matches!(frame, Frame::Rst { stream: StreamId(1), .. }), "{frame:?}");
}

#[test]
fn config_rejects_a_chunk_larger_than_half_the_window() {
    assert!(Config::new(16 * 1024, 8 * 1024).is_ok());
    assert!(Config::new(16 * 1024, 8 * 1024 + 1).is_err());
    assert!(Config::new(1 << 20, 128 * 1024).is_err(), "a chunk must fit one frame");
    assert!(Config::new(16 * 1024, 0).is_err());
}
