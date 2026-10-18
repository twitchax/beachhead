//! One stream's handle, and [`pump`], which joins it to any byte stream: a TCP socket today, a
//! smoltcp socket once the TUN milestone lands.

use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

use anyhow::{Context as _, anyhow, bail};
use bytes::{BufMut as _, Bytes, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    sync::{Notify, Semaphore, mpsc},
};

use crate::{
    base::Res,
    frame::{Frame, StreamId},
    mux::Shared,
};

/// What the reader delivers to a stream.
pub(crate) enum Inbound {
    Data(Bytes),
    Fin,
    Reset(String),
}

/// Where a stream is in its life, which decides what dropping it tells the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    /// The peer asked to open it and this side hasn't answered: dropping rejects it.
    Pending,
    /// Live: dropping resets it.
    Open,
    /// Closed cleanly or already reset: dropping says nothing.
    Finished,
}

/// One open stream. Hand it to [`pump`]; dropping it unfinished resets it.
pub struct Stream {
    id: StreamId,
    inbound: mpsc::UnboundedReceiver<Inbound>,
    credit: Arc<Semaphore>,
    outstanding: Arc<AtomicU32>,
    reset: Arc<Notify>,
    pub(crate) shared: Arc<Shared>,
    pub(crate) state: State,
}

impl Stream {
    pub(crate) fn new(id: StreamId, inbound: mpsc::UnboundedReceiver<Inbound>, credit: Arc<Semaphore>, outstanding: Arc<AtomicU32>, reset: Arc<Notify>, shared: Arc<Shared>, state: State) -> Self {
        Self {
            id,
            inbound,
            credit,
            outstanding,
            reset,
            shared,
            state,
        }
    }

    /// This stream's id on the wire.
    #[must_use]
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Resets the stream unless the peer already did.
    fn reset(&mut self, reason: &str) {
        let was_pending = self.state == State::Pending;
        self.state = State::Finished;
        if self.shared.forget(self.id) {
            let reason = reason.to_owned();
            let frame = if was_pending {
                Frame::OpenErr { stream: self.id, reason }
            } else {
                Frame::Rst { stream: self.id, reason }
            };
            self.shared.control(frame);
        }
    }
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream").field("id", &self.id).field("state", &self.state).finish_non_exhaustive()
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        match self.state {
            State::Finished => {
                self.shared.forget(self.id);
            }
            State::Pending => self.reset("not accepted"),
            State::Open => self.reset("stream dropped"),
        }
    }
}

/// Bytes moved by one [`pump`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Traffic {
    /// From the local side to the peer.
    pub sent: u64,
    /// From the peer to the local side.
    pub received: u64,
}

/// Copies both directions between `stream` and `io` until both have half-closed (`Fin`), then
/// returns the byte counts.
///
/// # Errors
///
/// Fails when either side resets, the local I/O fails, or the connection drops. A local failure
/// resets the stream for the peer.
pub async fn pump<IO>(mut stream: Stream, io: IO) -> Res<Traffic>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, writer) = tokio::io::split(io);
    let id = stream.id;
    let shared = Arc::clone(&stream.shared);
    let result = {
        let Stream { inbound, credit, outstanding, reset, .. } = &mut stream;
        let up = upload(&shared, id, credit, reader);
        let down = download(&shared, id, inbound, outstanding, writer);
        tokio::pin!(up, down);
        tokio::select! {
            sent = &mut up => match sent {
                // The download still hears a reset itself, through the inbound channel.
                Ok(sent) => down.await.map(|received| (sent, received)),
                Err(e) => Err(e),
            },
            received = &mut down => match received {
                // The peer has sent Fin, so nothing more reaches the inbound channel, and an idle
                // local side would never wake the upload: from here on, a reset (or teardown) must.
                // Watching only now keeps the per-read path free of it.
                Ok(received) => tokio::select! {
                    sent = &mut up => sent.map(|sent| (sent, received)),
                    () = reset.notified() => Err(anyhow!("stream reset by peer or connection closed")),
                },
                Err(e) => Err(e),
            },
        }
    };
    match result {
        Ok((sent, received)) => {
            stream.state = State::Finished;
            Ok(Traffic { sent, received })
        }
        Err(e) => {
            stream.reset(&format!("{e:#}"));
            Err(e)
        }
    }
}

/// Local socket to peer: read a chunk, pay for it in credit, queue it.
async fn upload<R: AsyncRead + Unpin>(shared: &Shared, id: StreamId, credit: &Semaphore, mut reader: R) -> Res<u64> {
    let chunk = shared.send_chunk;
    let mut buf = BytesMut::new();
    let mut sent = 0;
    loop {
        // Once the writer has encoded the previous chunk, `reserve` reclaims its space.
        buf.reserve(chunk);
        let n = reader.read_buf(&mut (&mut buf).limit(chunk)).await.context("reading from the local socket")?;
        if n == 0 {
            shared.send_data(Frame::Fin { stream: id }).await?;
            return Ok(sent);
        }
        let permits = u32::try_from(n).context("a chunk always fits u32")?;
        credit.acquire_many(permits).await.map_err(|_| anyhow!("stream reset by peer"))?.forget();
        shared.send_data(Frame::Data { stream: id, data: buf.split().freeze() }).await?;
        sent += n as u64;
    }
}

/// Peer to local socket: write each chunk, then return its credit in half-window steps. Credit
/// returns only after the local write, so a stalled local reader stalls the peer's sender.
async fn download<W: AsyncWrite + Unpin>(shared: &Shared, id: StreamId, inbound: &mut mpsc::UnboundedReceiver<Inbound>, outstanding: &AtomicU32, mut writer: W) -> Res<u64> {
    let threshold = shared.config.window() / 2;
    let mut unreported: u32 = 0;
    let mut received = 0;
    loop {
        match inbound.recv().await {
            Some(Inbound::Data(data)) => {
                writer.write_all(&data).await.context("writing to the local socket")?;
                received += data.len() as u64;
                #[allow(clippy::cast_possible_truncation, reason = "the decoder caps payloads at MAX_PAYLOAD")]
                let len = data.len() as u32;
                unreported += len;
                if unreported >= threshold {
                    // Release before granting: the peer may answer the grant before this side
                    // would otherwise get around to it, and that must not read as a violation.
                    outstanding.fetch_sub(unreported, Ordering::AcqRel);
                    shared.control(Frame::Window { stream: id, credit: unreported });
                    unreported = 0;
                }
                if inbound.is_empty() {
                    writer.flush().await.context("flushing the local socket")?;
                }
            }
            Some(Inbound::Fin) => {
                writer.shutdown().await.context("half-closing the local socket")?;
                return Ok(received);
            }
            Some(Inbound::Reset(reason)) => bail!("stream reset by peer: {reason}"),
            None => bail!("connection closed"),
        }
    }
}
