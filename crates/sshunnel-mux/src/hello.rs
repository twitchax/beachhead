//! The handshake: one `Hello` each way before the mux starts, each announcing its sender's receive
//! window. The relay speaks first; the client answers only after reading the relay's `Hello`,
//! because until then the bootstrap's `head -c` may still be reading the pipe and would swallow
//! anything extra.

use anyhow::{Context as _, bail};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::{
    base::{Res, Void},
    frame::{Frame, HEADER_LEN, VERSION},
};

/// Writes and flushes this side's `Hello`, announcing `window`, the most this side lets the peer
/// have in flight on one stream (its [`crate::Config::window`]).
///
/// # Errors
///
/// Fails when the pipe is closed.
pub async fn send_hello<W: AsyncWrite + Unpin>(writer: &mut W, window: u32) -> Void {
    let mut buf = BytesMut::new();
    Frame::Hello { version: VERSION, window }.encode(&mut buf)?;
    writer.write_all(&buf).await.context("sending Hello")?;
    writer.flush().await.context("flushing Hello")
}

/// Reads the peer's `Hello` and returns the window it announced, for [`crate::start`]. Bytes read
/// past it stay in `buf` for the mux to decode.
///
/// # Errors
///
/// Fails when the first frame is not a `Hello` for this protocol version, it announces a zero
/// window (no stream could ever send), or the peer hangs up.
pub async fn recv_hello<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut BytesMut) -> Res<u32> {
    loop {
        if let Some(frame) = Frame::decode(buf).context("decoding the peer's Hello")? {
            return match frame {
                Frame::Hello { version: VERSION, window: 0 } => bail!("the peer announced a zero window, so no stream could send"),
                Frame::Hello { version: VERSION, window } => Ok(window),
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
        send_hello(&mut a, 48 * 1024).await.unwrap();
        let mut next = BytesMut::new();
        Frame::Fin { stream: StreamId(1) }.encode(&mut next).unwrap();
        a.write_all(&next).await.unwrap();
        drop(a);

        let mut buf = BytesMut::new();
        assert_eq!(recv_hello(&mut b, &mut buf).await.unwrap(), 48 * 1024);
        b.read_buf(&mut buf).await.unwrap();
        assert_eq!(Frame::decode(&mut buf).unwrap(), Some(Frame::Fin { stream: StreamId(1) }));
    }

    #[tokio::test]
    async fn another_version_is_refused() {
        let mut wire = BytesMut::new();
        Frame::Hello { version: VERSION + 1, window: 1024 }.encode(&mut wire).unwrap();
        let err = recv_hello(&mut &wire[..], &mut BytesMut::new()).await.unwrap_err();
        assert!(err.to_string().contains("version"), "{err:#}");
    }

    #[tokio::test]
    async fn a_zero_window_is_refused() {
        let mut wire = BytesMut::new();
        Frame::Hello { version: VERSION, window: 0 }.encode(&mut wire).unwrap();
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
