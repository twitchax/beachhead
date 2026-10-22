//! Helpers the mux's test files share: a client and a relay mux joined by a `tokio::io::duplex`
//! "ssh pipe", and a client whose peer the test plays by hand.

#![allow(dead_code, reason = "each test binary compiles this module and uses its own part of it")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use bytes::BytesMut;
use sshunnel_mux::{
    Config, Incoming, Mux, Request, Role, Stream,
    frame::{Capabilities, Frame, OpenErrKind, StreamId},
    hello::PeerHello,
    pump, start,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, ReadHalf, WriteHalf, duplex, split},
    time::timeout,
};

pub const WINDOW: u32 = 16 * 1024;
pub const CHUNK: usize = 4 * 1024;
pub const PIPE_CAP: usize = 8 * 1024;
pub const SOCK_CAP: usize = 4 * 1024;

pub fn hello(window: u32) -> PeerHello {
    PeerHello {
        window,
        capabilities: Capabilities::default(),
    }
}

pub fn small() -> Config {
    Config::new(WINDOW, CHUNK).unwrap()
}

/// Starts a client and a relay mux over one in-memory pipe and serves the relay side.
pub fn connect(config: Config) -> Mux {
    connect_pair(config, config)
}

/// [`connect`], with each end's own config.
pub fn connect_pair(client_config: Config, relay_config: Config) -> Mux {
    let (client, relay_incoming) = pair(client_config, relay_config);
    tokio::spawn(serve(relay_incoming));
    client
}

/// A client and a relay mux over one in-memory pipe, with the relay's requests left to the test.
pub fn pair(client_config: Config, relay_config: Config) -> (Mux, Incoming) {
    let (a, b) = duplex(PIPE_CAP);
    let (ar, aw) = split(a);
    let (br, bw) = split(b);
    // Each end learns the other's window from its Hello; here the test hands it over directly.
    let (client, _client_incoming, client_driver) = start(ar, BytesMut::new(), aw, Role::Client, client_config, hello(relay_config.window()));
    let (_relay, relay_incoming, relay_driver) = start(br, BytesMut::new(), bw, Role::Relay, relay_config, hello(client_config.window()));
    tokio::spawn(client_driver);
    tokio::spawn(relay_driver);
    (client, relay_incoming)
}

/// The relay's stand-in targets, picked by the `Open` host.
pub async fn serve(mut incoming: Incoming) {
    while let Some(request) = incoming.next().await {
        let Request::Open(request) = request else { panic!("unexpected request") };
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
            "refuse" => request.reject(OpenErrKind::Refused, "connection refused"),
            other => panic!("unexpected host {other}"),
        }
    }
}

/// Reads frames from a hand-driven peer until one is complete.
pub async fn next_frame(r: &mut (impl tokio::io::AsyncRead + Unpin), buf: &mut BytesMut) -> Frame {
    loop {
        if let Some(frame) = Frame::decode(buf).unwrap() {
            return frame;
        }
        assert!(r.read_buf(buf).await.unwrap() > 0, "peer hung up");
    }
}

/// The far end of a client mux, played by hand: the test reads its frames and writes the replies.
pub struct HandPeer {
    r: ReadHalf<DuplexStream>,
    w: WriteHalf<DuplexStream>,
    buf: BytesMut,
}

impl HandPeer {
    /// The client's next frame. Under a paused clock, one that never comes fails at once.
    pub async fn next(&mut self) -> Frame {
        self.next_within(Duration::from_secs(10)).await.expect("the client sends a frame")
    }

    /// The client's next frame, or `None` if none comes within `limit`.
    pub async fn next_within(&mut self, limit: Duration) -> Option<Frame> {
        timeout(limit, next_frame(&mut self.r, &mut self.buf)).await.ok()
    }

    /// Waits until the client's writer has put its first bytes on the pipe, and keeps them for
    /// [`Self::next`]. Once this returns, the writer holds the batch those bytes came from.
    pub async fn read_some(&mut self) {
        let read = timeout(Duration::from_secs(10), self.r.read_buf(&mut self.buf)).await.expect("the client writes");
        assert!(read.unwrap() > 0, "peer hung up");
    }

    pub async fn send(&mut self, frame: Frame) {
        self.send_all([frame]).await;
    }

    /// Writes `frames` in one go.
    pub async fn send_all(&mut self, frames: impl IntoIterator<Item = Frame>) {
        let mut out = BytesMut::new();
        for frame in frames {
            frame.encode(&mut out).unwrap();
        }
        self.w.write_all(&out).await.unwrap();
    }
}

/// A client mux whose peer the test plays by hand.
pub fn client_with_hand_peer() -> (Mux, Incoming, HandPeer) {
    client_with_hand_peer_over(PIPE_CAP, WINDOW)
}

/// [`client_with_hand_peer`] over a pipe that holds `pipe` bytes each way, with the peer announcing
/// `window`.
pub fn client_with_hand_peer_over(pipe: usize, window: u32) -> (Mux, Incoming, HandPeer) {
    let (a, b) = duplex(pipe);
    let (ar, aw) = split(a);
    let (client, incoming, driver) = start(ar, BytesMut::new(), aw, Role::Client, small(), hello(window));
    tokio::spawn(driver);
    let (r, w) = split(b);
    (client, incoming, HandPeer { r, w, buf: BytesMut::new() })
}

/// Opens a stream that the hand peer accepts.
pub async fn open_by_hand(client: &Mux, peer: &mut HandPeer) -> (Stream, StreamId) {
    let opener = {
        let client = client.clone();
        tokio::spawn(async move { client.open("x", 7).await })
    };
    let Frame::Open { stream, .. } = peer.next().await else { panic!("expected Open") };
    peer.send(Frame::OpenOk { stream }).await;
    (opener.await.unwrap().unwrap(), stream)
}
