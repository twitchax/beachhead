//! The handshake: one `Hello` each way before the mux starts, each announcing its sender's receive
//! window. The relay speaks first; the client answers only after reading the relay's `Hello`,
//! because until then the bootstrap's `head -c` may still be reading the pipe and would swallow
//! anything extra.

use anyhow::{Context as _, bail};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::{
    base::{Res, Void},
    frame::{Capabilities, Frame, HEADER_LEN, VERSION},
};

/// What the peer's `Hello` announced: its receive window, and what it can do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerHello {
    pub window: u32,
    pub capabilities: Capabilities,
}

/// Writes and flushes this side's `Hello`, announcing `window`, the most this side lets the peer
/// have in flight on one stream (its [`crate::Config::window`]), and its `capabilities`.
///
/// # Errors
///
/// Fails when the pipe is closed.
pub async fn send_hello<W: AsyncWrite + Unpin>(writer: &mut W, window: u32, capabilities: Capabilities) -> Void {
    let mut buf = BytesMut::new();
    Frame::Hello { version: VERSION, window, capabilities }.encode(&mut buf)?;
    writer.write_all(&buf).await.context("sending Hello")?;
    writer.flush().await.context("flushing Hello")
}

/// Reads the peer's `Hello` and returns what it announced, for [`crate::start`]. Bytes read
/// past it stay in `buf` for the mux to decode.
///
/// # Errors
///
/// Fails when the first frame is not a `Hello` for this protocol version, it announces a zero
/// window (no stream could ever send), or the peer hangs up.
pub async fn recv_hello<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut BytesMut) -> Res<PeerHello> {
    loop {
        if let Some(frame) = Frame::decode(buf).context("decoding the peer's Hello")? {
            return match frame {
                Frame::Hello { version: VERSION, window: 0, .. } => bail!("the peer announced a zero window, so no stream could send"),
                Frame::Hello { version: VERSION, window, capabilities } => Ok(PeerHello { window, capabilities }),
                Frame::Hello { version, .. } => bail!("the peer speaks protocol version {version}; this side speaks {VERSION}"),
                other => bail!("expected Hello, got {}", other.name()),
            };
        }
        buf.reserve(HEADER_LEN + 64);
        if reader.read_buf(buf).await.context("reading the peer's Hello")? == 0 {
            bail!("the peer hung up before its Hello");
        }
    }
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;
    use tokio::io::duplex;

    use super::*;
    use crate::frame::StreamId;

    #[tokio::test]
    async fn hello_round_trips_its_window_and_keeps_what_follows() {
        let (mut a, mut b) = duplex(1024);
        send_hello(&mut a, 48 * 1024, Capabilities::default()).await.unwrap();
        let mut next = BytesMut::new();
        Frame::Fin { stream: StreamId(1) }.encode(&mut next).unwrap();
        a.write_all(&next).await.unwrap();
        drop(a);

        let mut buf = BytesMut::new();
        assert_eq!(recv_hello(&mut b, &mut buf).await.unwrap().window, 48 * 1024);
        b.read_buf(&mut buf).await.unwrap();
        assert_eq!(Frame::decode(&mut buf).unwrap(), Some(Frame::Fin { stream: StreamId(1) }));
    }

    #[tokio::test]
    async fn hello_round_trips_its_capabilities() {
        let (mut a, mut b) = duplex(1024);
        let capabilities = Capabilities { ping4: true, ping6: false };
        send_hello(&mut a, 1024, capabilities).await.unwrap();
        let peer = recv_hello(&mut b, &mut BytesMut::new()).await.unwrap();
        assert_eq!(peer, PeerHello { window: 1024, capabilities });
    }

    #[tokio::test]
    async fn a_v3_hello_is_refused_by_version() {
        // Version 3's Hello: magic, version and window, ten bytes and no capabilities.
        let wire = [0, 0, 0, 0, 0, 0, 0, 0, 10, b'S', b'S', b'H', b'N', 0, 3, 0, 0x10, 0, 0];
        let err = recv_hello(&mut &wire[..], &mut BytesMut::new()).await.unwrap_err();
        assert!(err.to_string().contains("version 3"), "{err:#}");
    }

    #[tokio::test]
    async fn another_version_is_refused() {
        let mut wire = BytesMut::new();
        Frame::Hello {
            version: VERSION + 1,
            window: 1024,
            capabilities: Capabilities::default(),
        }
        .encode(&mut wire)
        .unwrap();
        let err = recv_hello(&mut &wire[..], &mut BytesMut::new()).await.unwrap_err();
        assert!(err.to_string().contains("version"), "{err:#}");
    }

    #[tokio::test]
    async fn an_older_hello_reports_its_version_not_its_layout() {
        // Version 1's Hello: magic and version, no window.
        let wire = [0, 0, 0, 0, 0, 0, 0, 0, 6, b'S', b'S', b'H', b'N', 0, 1];
        let err = recv_hello(&mut &wire[..], &mut BytesMut::new()).await.unwrap_err();
        assert!(err.to_string().contains("version 1"), "{err:#}");
    }

    #[tokio::test]
    async fn a_zero_window_is_refused() {
        let mut wire = BytesMut::new();
        Frame::Hello {
            version: VERSION,
            window: 0,
            capabilities: Capabilities::default(),
        }
        .encode(&mut wire)
        .unwrap();
        let err = recv_hello(&mut &wire[..], &mut BytesMut::new()).await.unwrap_err();
        assert!(err.to_string().contains("zero window"), "{err:#}");
    }

    #[tokio::test]
    async fn a_first_frame_other_than_hello_is_refused() {
        let mut wire = BytesMut::new();
        Frame::Fin { stream: StreamId(1) }.encode(&mut wire).unwrap();
        let err = recv_hello(&mut &wire[..], &mut BytesMut::new()).await.unwrap_err();
        assert!(err.to_string().contains("expected Hello"), "{err:#}");
    }

    #[tokio::test]
    async fn a_hangup_before_hello_is_an_error() {
        let err = recv_hello(&mut &b"BH"[..], &mut BytesMut::new()).await.unwrap_err();
        assert!(err.to_string().contains("hung up"), "{err:#}");
    }
}
