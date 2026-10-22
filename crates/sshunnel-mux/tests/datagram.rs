//! Datagram flows and queries through the mux, in process, over `common`'s client/relay pair and
//! hand peer. Datagrams skip credit, a full queue drops them at either end, and the writer shares
//! itself fairly: round-robin across flows, taking turns with stream data. The writer tests park
//! the writer part way through one big datagram on a pipe the peer isn't reading, so its queues
//! fill before it picks what goes next.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::{CHUNK, HandPeer, SOCK_CAP, WINDOW, client_with_hand_peer, client_with_hand_peer_over, open_by_hand, pair, small};
use pretty_assertions::assert_eq;
use sshunnel_mux::{
    FLOW_QUEUE, Flow, FlowEvent, FlowKind, Incoming, Mux, QueryError, Request,
    frame::{FlowErrKind, Frame, OpenErrKind, StreamId, Transport},
    pump,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, duplex},
    time::timeout,
};

/// A pipe one big datagram overfills many times, so the writer parks until the peer reads.
const TINY_PIPE: usize = 1024;
/// The datagram that parks the writer.
const BIG: usize = 16 * 1024;
/// As many data frames as the mux's data channel holds (its `DATA_QUEUE`).
const DATA_FRAMES: usize = 16;
const WAIT: Duration = Duration::from_secs(10);

/// A datagram that says which flow and which turn it is.
fn datagram(flow: u8, seq: usize) -> Bytes {
    Bytes::from(format!("flow {flow} datagram {seq}"))
}

/// A datagram of `len` bytes that says which turn it is.
fn sized(seq: usize, len: usize) -> Bytes {
    let mut bytes = format!("datagram {seq} ").into_bytes();
    bytes.resize(len, b'.');
    Bytes::from(bytes)
}

/// Opens a UDP flow from `client` that the relay side accepts; returns the client's end, then the
/// relay's.
async fn open_flow(client: &Mux, relay: &mut Incoming) -> (Flow, Flow) {
    let opener = {
        let client = client.clone();
        tokio::spawn(async move { client.open_udp("h", 53).await })
    };
    let Some(Request::OpenFlow(request)) = relay.next().await else {
        panic!("expected a flow request")
    };
    let far = request.accept();
    (opener.await.unwrap().unwrap(), far)
}

/// Opens a UDP flow that the hand peer accepts.
async fn open_flow_by_hand(client: &Mux, peer: &mut HandPeer) -> (Flow, StreamId) {
    let opener = {
        let client = client.clone();
        tokio::spawn(async move { client.open_udp("h", 53).await })
    };
    let Frame::OpenUdp { stream, .. } = peer.next().await else { panic!("expected OpenUdp") };
    peer.send(Frame::OpenOk { stream }).await;
    (opener.await.unwrap().unwrap(), stream)
}

/// Parks the client's writer part way through one big datagram on `flow`. Whatever is queued from
/// here on waits for the writer's next pick, which comes once the peer reads.
async fn park_writer(flow: &Flow, peer: &mut HandPeer) {
    assert!(flow.sender().try_send(Bytes::from(vec![0; BIG])));
    peer.read_some().await;
}

/// The big datagram [`park_writer`] sent, read off the pipe.
async fn unpark(peer: &mut HandPeer) {
    let frame = peer.next().await;
    assert!(matches!(&frame, Frame::Datagram { data, .. } if data.len() == BIG), "{frame:?}");
}

/// Proves the client has dispatched every frame the peer sent before it: a `Resolve` behind them
/// reaches the client's requests.
async fn sync(peer: &mut HandPeer, incoming: &mut Incoming, id: u32) {
    peer.send(Frame::Resolve {
        stream: StreamId(id),
        host: "sync.corp.example".into(),
    })
    .await;
    let request = timeout(WAIT, incoming.next()).await.expect("the client reads on");
    assert!(matches!(request, Some(Request::Resolve(_))));
}

#[tokio::test]
async fn datagram_flows_round_trip_both_ways() {
    let (client, mut relay) = pair(small(), small());
    let opener = {
        let client = client.clone();
        tokio::spawn(async move { client.open_udp("h", 53).await })
    };
    let Some(Request::OpenFlow(request)) = relay.next().await else {
        panic!("expected a flow request")
    };
    assert_eq!((request.kind(), request.host(), request.port()), (FlowKind::Udp, "h", 53));
    let mut far = request.accept();
    let mut near = opener.await.unwrap().unwrap();

    for seq in 0..10 {
        assert!(near.sender().try_send(datagram(1, seq)));
        assert!(far.sender().try_send(datagram(2, seq)));
    }
    for seq in 0..10 {
        assert_eq!(timeout(WAIT, far.recv()).await.unwrap(), Some(FlowEvent::Datagram(datagram(1, seq))));
        assert_eq!(timeout(WAIT, near.recv()).await.unwrap(), Some(FlowEvent::Datagram(datagram(2, seq))));
    }
}

#[tokio::test]
async fn datagram_frames_skip_credit() {
    let (client, mut relay) = pair(small(), small());
    let (near, mut far) = open_flow(&client, &mut relay).await;
    let len = 1024;
    assert!(FLOW_QUEUE * len > WINDOW as usize, "the datagrams must outrun one window");

    let sender = near.sender();
    for seq in 0..FLOW_QUEUE {
        assert!(sender.try_send(sized(seq, len)), "datagram {seq} fits the queue");
    }
    for seq in 0..FLOW_QUEUE {
        assert_eq!(timeout(WAIT, far.recv()).await.unwrap(), Some(FlowEvent::Datagram(sized(seq, len))));
    }
}

#[tokio::test(start_paused = true)]
async fn a_datagram_for_a_full_queue_is_dropped_without_blocking_the_reader() {
    let (_client, mut incoming, mut peer) = client_with_hand_peer();
    let id = StreamId(2);
    peer.send(Frame::OpenUdp { stream: id, host: "h".into(), port: 53 }).await;
    let Some(Request::OpenFlow(request)) = incoming.next().await else {
        panic!("expected a flow request")
    };
    // Accepted, then not read until the flood is over.
    let mut flow = request.accept();
    assert_eq!(peer.next().await, Frame::OpenOk { stream: id });

    let flood = (0..1000).map(|seq| Frame::Datagram { stream: id, data: datagram(0, seq) });
    let behind = Frame::Resolve {
        stream: StreamId(4),
        host: "after.corp.example".into(),
    };
    timeout(Duration::from_secs(1), peer.send_all(flood.chain([behind]))).await.expect("the reader drains the flood");
    let request = timeout(Duration::from_secs(1), incoming.next()).await.expect("the Resolve arrives behind the flood");
    assert!(matches!(request, Some(Request::Resolve(_))));

    for seq in 0..FLOW_QUEUE {
        assert_eq!(timeout(WAIT, flow.recv()).await.unwrap(), Some(FlowEvent::Datagram(datagram(0, seq))));
    }
    assert!(timeout(Duration::from_secs(1), flow.recv()).await.is_err(), "the queue kept only FLOW_QUEUE datagrams");
}

#[tokio::test(start_paused = true)]
async fn a_datagram_for_an_unknown_flow_is_dropped() {
    let (client, _incoming, mut peer) = client_with_hand_peer();
    peer.send(Frame::Datagram {
        stream: StreamId(99),
        data: Bytes::from_static(b"nobody's"),
    })
    .await;
    let (stream, id) = open_by_hand(&client, &mut peer).await;
    // A TCP stream's id names no flow either: this must not become stream bytes.
    peer.send(Frame::Datagram {
        stream: id,
        data: Bytes::from_static(b"not stream bytes"),
    })
    .await;

    // The connection is still up: the peer plays an echo server for a stream opened after both.
    let (near, mut app) = duplex(SOCK_CAP);
    tokio::spawn(pump(stream, near));
    app.write_all(b"ping").await.unwrap();
    let Frame::Data { stream, data } = peer.next().await else { panic!("expected Data") };
    assert_eq!((stream, &data[..]), (id, &b"ping"[..]));
    peer.send(Frame::Data { stream: id, data }).await;
    let mut echoed = [0; 4];
    timeout(WAIT, app.read_exact(&mut echoed)).await.expect("the echo comes back").unwrap();
    assert_eq!(&echoed, b"ping");
}

#[tokio::test(start_paused = true)]
async fn a_full_send_queue_drops_at_the_sender() {
    let (client, _incoming, mut peer) = client_with_hand_peer_over(TINY_PIPE, WINDOW);
    let (flow, id) = open_flow_by_hand(&client, &mut peer).await;
    park_writer(&flow, &mut peer).await;

    let sender = flow.sender();
    for seq in 0..FLOW_QUEUE {
        assert!(sender.try_send(datagram(1, seq)), "datagram {seq} fits the queue");
    }
    assert!(!sender.try_send(datagram(1, FLOW_QUEUE)), "a full queue drops at the sender");

    // Every datagram the sender took arrives, in order, and nothing else.
    unpark(&mut peer).await;
    for seq in 0..FLOW_QUEUE {
        assert_eq!(peer.next().await, Frame::Datagram { stream: id, data: datagram(1, seq) });
    }
    assert_eq!(peer.next_within(Duration::from_secs(1)).await, None);
}

#[tokio::test(start_paused = true)]
async fn the_writer_serves_datagram_flows_round_robin() {
    let (client, _incoming, mut peer) = client_with_hand_peer_over(TINY_PIPE, WINDOW);
    let (parker, _) = open_flow_by_hand(&client, &mut peer).await;
    let (a, _) = open_flow_by_hand(&client, &mut peer).await;
    let (b, b_id) = open_flow_by_hand(&client, &mut peer).await;
    park_writer(&parker, &mut peer).await;

    for seq in 0..FLOW_QUEUE {
        assert!(a.sender().try_send(datagram(1, seq)));
    }
    assert!(b.sender().try_send(datagram(2, 0)));

    unpark(&mut peer).await;
    let mut first_two = Vec::new();
    for _ in 0..2 {
        let frame = peer.next().await;
        let Frame::Datagram { stream, .. } = frame else { panic!("expected a Datagram, got {frame:?}") };
        first_two.push(stream);
    }
    assert!(first_two.contains(&b_id), "B waited behind A's whole queue: {first_two:?}");
}

#[tokio::test(start_paused = true)]
async fn datagrams_and_stream_data_alternate_in_the_writer() {
    // The peer's window pays for exactly DATA_FRAMES chunks: the stream queues that many, then
    // waits on credit.
    let window = u32::try_from(DATA_FRAMES * CHUNK).unwrap();
    let (client, _incoming, mut peer) = client_with_hand_peer_over(TINY_PIPE, window);
    let (parker, _) = open_flow_by_hand(&client, &mut peer).await;
    let (flow, flow_id) = open_flow_by_hand(&client, &mut peer).await;
    let (stream, stream_id) = open_by_hand(&client, &mut peer).await;
    park_writer(&parker, &mut peer).await;

    // The app's socket holds one chunk, so this write returns only once the pump has read the
    // chunk after its credit ran out: by then every data frame it may send is queued.
    let (near, mut app) = duplex(CHUNK);
    tokio::spawn(pump(stream, near));
    timeout(WAIT, app.write_all(&vec![0x5A; (DATA_FRAMES + 2) * CHUNK]))
        .await
        .expect("the pump queues a window of data")
        .unwrap();
    for seq in 0..FLOW_QUEUE {
        assert!(flow.sender().try_send(datagram(1, seq)));
    }

    unpark(&mut peer).await;
    let mut kinds = String::new();
    while kinds.len() < DATA_FRAMES + FLOW_QUEUE {
        match peer.next().await {
            Frame::Data { stream, .. } if stream == stream_id => kinds.push('D'),
            Frame::Datagram { stream, .. } if stream == flow_id => kinds.push('G'),
            other => panic!("unexpected {other:?}"),
        }
    }
    // While both kinds wait they take turns; the datagrams left over go last.
    let (both, rest) = kinds.split_at(2 * DATA_FRAMES);
    assert!(both.as_bytes().windows(2).all(|pair| pair[0] != pair[1]), "{kinds}");
    assert!(rest.chars().all(|kind| kind == 'G'), "{kinds}");
}

#[tokio::test]
async fn a_flow_error_reaches_the_opener_and_the_flow_lives_on() {
    let (client, mut relay) = pair(small(), small());
    let (mut near, mut far) = open_flow(&client, &mut relay).await;

    far.sender().report(FlowErrKind::PortUnreachable);
    assert_eq!(timeout(WAIT, near.recv()).await.unwrap(), Some(FlowEvent::Error(FlowErrKind::PortUnreachable)));

    assert!(far.sender().try_send(datagram(2, 0)));
    assert_eq!(timeout(WAIT, near.recv()).await.unwrap(), Some(FlowEvent::Datagram(datagram(2, 0))));
    assert!(near.sender().try_send(datagram(1, 0)));
    assert_eq!(timeout(WAIT, far.recv()).await.unwrap(), Some(FlowEvent::Datagram(datagram(1, 0))));
}

#[tokio::test(start_paused = true)]
async fn a_flow_error_is_not_lost_behind_a_full_queue() {
    let (client, mut incoming, mut peer) = client_with_hand_peer();
    let (mut flow, id) = open_flow_by_hand(&client, &mut peer).await;

    let flood = (0..2 * FLOW_QUEUE).map(|seq| Frame::Datagram { stream: id, data: datagram(2, seq) });
    let error = Frame::FlowErr {
        stream: id,
        kind: FlowErrKind::HostUnreachable,
    };
    peer.send_all(flood.chain([error])).await;
    sync(&mut peer, &mut incoming, 2).await;

    // The error waits in a slot of its own, ahead of the datagrams that filled the queue.
    assert_eq!(timeout(WAIT, flow.recv()).await.unwrap(), Some(FlowEvent::Error(FlowErrKind::HostUnreachable)));
    for seq in 0..FLOW_QUEUE {
        assert_eq!(timeout(WAIT, flow.recv()).await.unwrap(), Some(FlowEvent::Datagram(datagram(2, seq))));
    }
}

#[tokio::test(start_paused = true)]
async fn dropping_a_flow_resets_it() {
    let (client, _incoming, mut peer) = client_with_hand_peer();
    let (flow, id) = open_flow_by_hand(&client, &mut peer).await;
    drop(flow);
    let frame = peer.next().await;
    assert!(matches!(&frame, Frame::Rst { stream, .. } if *stream == id), "{frame:?}");
}

#[tokio::test(start_paused = true)]
async fn a_reset_ends_a_flow() {
    let (client, _incoming, mut peer) = client_with_hand_peer();
    let (mut flow, id) = open_flow_by_hand(&client, &mut peer).await;
    let sender = flow.sender();
    peer.send(Frame::Rst { stream: id, reason: "gone".into() }).await;

    assert_eq!(timeout(WAIT, flow.recv()).await.expect("the reset ends the flow"), None);
    assert!(!sender.try_send(datagram(1, 0)), "a reset flow takes no datagrams");
    // The peer ended it, so dropping it tells the peer nothing.
    drop(flow);
    assert_eq!(peer.next_within(Duration::from_secs(1)).await, None);
}

#[tokio::test(start_paused = true)]
async fn a_dead_connection_fails_flows_and_queries() {
    let (client, _incoming, mut peer) = client_with_hand_peer();
    let (mut flow, _) = open_flow_by_hand(&client, &mut peer).await;
    let sender = flow.sender();
    let query = {
        let client = client.clone();
        tokio::spawn(async move { client.query(Bytes::from_static(b"q"), Transport::Udp).await })
    };
    assert!(matches!(peer.next().await, Frame::Query { .. }));
    drop(peer);

    assert_eq!(timeout(WAIT, flow.recv()).await.expect("the flow ends"), None);
    assert!(!sender.try_send(datagram(1, 0)));
    let err = timeout(WAIT, query).await.expect("the query fails rather than waiting").unwrap().unwrap_err();
    assert!(err.reason.contains("connection closed"), "{err}");
    assert!(client.open_udp("h", 53).await.is_err(), "flows can't open once the connection is gone");
    assert!(client.query(Bytes::from_static(b"q"), Transport::Tcp).await.is_err());
}

#[tokio::test]
async fn query_round_trips_a_message_and_its_transport() {
    let (client, mut relay) = pair(small(), small());
    tokio::spawn(async move {
        while let Some(request) = relay.next().await {
            let Request::Query(query) = request else { panic!("expected a query") };
            let answer = match &query.message()[..] {
                b"fail" => Err(QueryError { reason: "no nameserver answered".into() }),
                message => Ok(Bytes::from(format!("{:?} answer to {}", query.transport(), String::from_utf8_lossy(message)))),
            };
            query.answer(answer);
        }
    });

    let udp = client.query(Bytes::from_static(b"q1"), Transport::Udp).await.unwrap();
    assert_eq!(udp, Bytes::from_static(b"Udp answer to q1"));
    let tcp = client.query(Bytes::from_static(b"q2"), Transport::Tcp).await.unwrap();
    assert_eq!(tcp, Bytes::from_static(b"Tcp answer to q2"));
    let err = client.query(Bytes::from_static(b"fail"), Transport::Udp).await.unwrap_err();
    assert_eq!(err.reason, "no nameserver answered");
}

#[tokio::test]
async fn a_dropped_query_request_answers_an_error() {
    let (client, mut relay) = pair(small(), small());
    tokio::spawn(async move {
        while let Some(request) = relay.next().await {
            drop(request);
        }
    });
    let err = client.query(Bytes::from_static(b"q"), Transport::Udp).await.unwrap_err();
    assert_eq!(err, QueryError { reason: "not answered".into() });
}

#[tokio::test]
async fn a_refused_flow_open_reports_its_kind() {
    let (client, mut relay) = pair(small(), small());
    tokio::spawn(async move {
        while let Some(request) = relay.next().await {
            let Request::OpenFlow(request) = request else { panic!("expected a flow request") };
            let expected = match request.kind() {
                FlowKind::Udp => ("closed.corp.example", 53),
                FlowKind::Echo => ("far.corp.example", 0),
            };
            assert_eq!((request.host(), request.port()), expected);
            match request.kind() {
                FlowKind::Udp => request.reject(OpenErrKind::Refused, "port closed"),
                FlowKind::Echo => request.reject(OpenErrKind::Unreachable, "no route"),
            }
        }
    });

    let err = client.open_udp("closed.corp.example", 53).await.unwrap_err();
    assert_eq!((err.kind, err.reason.as_str()), (OpenErrKind::Refused, "port closed"));
    let err = client.open_echo("far.corp.example").await.unwrap_err();
    assert_eq!((err.kind, err.reason.as_str()), (OpenErrKind::Unreachable, "no route"));
}

#[tokio::test]
async fn a_dropped_flow_request_rejects_the_open() {
    let (client, mut relay) = pair(small(), small());
    tokio::spawn(async move {
        while let Some(request) = relay.next().await {
            drop(request);
        }
    });
    let err = client.open_udp("h", 53).await.unwrap_err();
    assert_eq!(err.kind, OpenErrKind::Other);
}
