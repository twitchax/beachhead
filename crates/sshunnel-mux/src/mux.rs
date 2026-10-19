//! The connection: many streams over one byte pipe, the ssh session's stdio.
//!
//! The invariant everything rests on: **the reader never blocks.** It hands each frame to a
//! per-stream unbounded channel whose depth is bounded by credit, so the pipe always drains and one
//! stalled stream can't hold up the rest. A single writer owns the outbound pipe and drains two
//! channels: control frames first (so credit returns promptly), then data. `Fin` rides the data
//! channel, because it must never overtake that stream's queued data.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, PoisonError, atomic::AtomicU32},
};

use anyhow::{Context as _, anyhow, bail};
use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    sync::{Notify, Semaphore, mpsc, oneshot},
};
use tracing::debug;

use crate::{
    base::{Res, Void},
    frame::{Frame, HEADER_LEN, MAX_HOST, MAX_PAYLOAD, OpenErrKind, ResolveErrKind, StreamId},
    stream::{Inbound, State, Stream},
};

/// Data frames the writer may have queued: enough to keep the pipe busy, few enough that a queued
/// control frame never waits long.
const DATA_QUEUE: usize = 16;
/// How much the reader asks for per read.
const READ_RESERVE: usize = 64 * 1024;
/// How many encoded bytes the writer batches into one write.
const WRITE_BATCH: usize = 256 * 1024;

/// This side's flow-control sizes. The window goes to the peer in this side's `Hello` and is
/// enforced against it; the peer's own window, from its `Hello`, caps what this side sends. The
/// ends may differ.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    window: u32,
    chunk: usize,
}

impl Config {
    /// `window` is the per-stream credit in bytes; `chunk` is the largest `Data` frame.
    ///
    /// # Errors
    ///
    /// Fails unless `0 < chunk <= window / 2` and the chunk fits a frame. Credit returns in
    /// half-window steps, so a sender cuts its chunk to half the peer's window; between two ends
    /// sharing this config, a larger chunk would never go out whole.
    pub fn new(window: u32, chunk: usize) -> Res<Self> {
        if chunk == 0 || chunk > MAX_PAYLOAD {
            bail!("chunk {chunk} must be between 1 and {MAX_PAYLOAD} bytes");
        }
        if chunk > window as usize / 2 {
            bail!("chunk {chunk} exceeds half the {window}-byte window, so credit could stall");
        }
        Ok(Self { window, chunk })
    }

    /// The per-stream window in bytes.
    #[must_use]
    pub fn window(&self) -> u32 {
        self.window
    }

    /// The largest `Data` payload this side sends, before the cap at half the peer's window.
    #[must_use]
    pub fn chunk(&self) -> usize {
        self.chunk
    }
}

impl Default for Config {
    /// 1 MiB windows and 32 KiB chunks. A stream's throughput tops out near window ÷ round trip,
    /// and the round trip crosses ssh, sshd and both ends' schedulers: on loopback, 256 KiB held a
    /// single stream to about half of `ssh -L` and 1 MiB came within 5% (`cargo xtask bench`). It
    /// also covers a ~100 ms mobile link at 80 Mbit/s, and sits under OpenSSH's own 2 MiB channel
    /// window. Memory stays bounded at window × streams; a chunk is small enough to interleave
    /// streams fairly.
    fn default() -> Self {
        Self { window: 1024 * 1024, chunk: 32 * 1024 }
    }
}

/// Which end of the connection this is. It decides the stream-id space: the client opens odd ids,
/// the relay even ones, so both could open streams without colliding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Relay,
}

impl Role {
    fn first_id(self) -> u32 {
        match self {
            Self::Client => 1,
            Self::Relay => 2,
        }
    }

    fn owns(self, id: StreamId) -> bool {
        (id.0 % 2 == 1) == (self == Self::Client)
    }
}

/// Why [`Mux::open`] failed: the peer's typed refusal, or a local failure (kind
/// [`OpenErrKind::Other`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenError {
    pub kind: OpenErrKind,
    pub reason: String,
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for OpenError {}

impl OpenError {
    fn other(reason: impl Into<String>) -> Self {
        Self {
            kind: OpenErrKind::Other,
            reason: reason.into(),
        }
    }
}

/// How an open in flight failed. A peer's refusal already names its target (the relay's reasons
/// say `dialing host:port`); a local failure doesn't, so [`Mux::open`] adds the target to those.
enum Refusal {
    Peer(OpenError),
    Local(String),
}

/// Why [`Mux::resolve`] failed: the peer's typed answer, or a local failure (kind
/// [`ResolveErrKind::Failed`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolveError {
    pub kind: ResolveErrKind,
    pub reason: String,
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for ResolveError {}

impl ResolveError {
    fn failed(reason: impl Into<String>) -> Self {
        Self {
            kind: ResolveErrKind::Failed,
            reason: reason.into(),
        }
    }
}

/// The handle for opening streams. Clones share one connection.
#[derive(Clone)]
pub struct Mux {
    shared: Arc<Shared>,
}

impl Mux {
    /// Asks the peer to dial `host:port` and returns the stream once it has.
    ///
    /// # Errors
    ///
    /// Fails when the peer refuses (with its kind) or the connection is gone.
    pub async fn open(&self, host: &str, port: u16) -> Result<Stream, OpenError> {
        if host.len() > MAX_HOST {
            return Err(OpenError::other(format!("host `{host}` is longer than {MAX_HOST} bytes")));
        }
        let (opened_tx, opened_rx) = oneshot::channel();
        let mut stream = {
            let mut table = self.shared.table();
            if let Some(reason) = &table.dead {
                return Err(OpenError::other(format!("connection closed: {reason}")));
            }
            let id = table.allocate_id().map_err(|e| OpenError::other(format!("{e:#}")))?;
            let stream = self.shared.insert(&mut table, id, State::Open, Some(opened_tx));
            // Queued under the lock that allocated the id: the peer requires ids in increasing
            // order, so a concurrent open must not get its Open onto the wire first. The send
            // never blocks.
            self.shared.control(Frame::Open { stream: id, host: host.to_owned(), port });
            stream
        };

        match opened_rx.await {
            Ok(Ok(())) => Ok(stream),
            Ok(Err(refusal)) => {
                stream.state = State::Finished;
                Err(match refusal {
                    Refusal::Peer(e) => e,
                    Refusal::Local(reason) => OpenError::other(format!("{host}:{port}: {reason}")),
                })
            }
            Err(_) => {
                stream.state = State::Finished;
                Err(OpenError::other(format!("connection closed while opening {host}:{port}")))
            }
        }
    }

    /// Asks the peer to resolve `host` with its own resolver, so the answer is what the peer's
    /// network would say.
    ///
    /// # Errors
    ///
    /// Fails with the peer's typed answer, or [`ResolveErrKind::Failed`] when the connection is
    /// gone.
    pub async fn resolve(&self, host: &str) -> Result<(), ResolveError> {
        if host.len() > MAX_HOST {
            return Err(ResolveError::failed(format!("host `{host}` is longer than {MAX_HOST} bytes")));
        }
        let (answer_tx, answer_rx) = oneshot::channel();
        {
            let mut table = self.shared.table();
            if let Some(reason) = &table.dead {
                return Err(ResolveError::failed(format!("connection closed: {reason}")));
            }
            let id = table.allocate_id().map_err(|e| ResolveError::failed(format!("{e:#}")))?;
            table.resolves.insert(id, answer_tx);
            // Same lock, same order rule as `open`.
            self.shared.control(Frame::Resolve { stream: id, host: host.to_owned() });
        }
        answer_rx.await.unwrap_or_else(|_| Err(ResolveError::failed(format!("connection closed while resolving {host}"))))
    }
}

/// Something the peer asked this side to do.
pub enum Request {
    /// Dial a host.
    Open(OpenRequest),
    /// Resolve a name.
    Resolve(ResolveRequest),
}

/// Requests the peer made of this side.
pub struct Incoming {
    rx: mpsc::UnboundedReceiver<Request>,
}

impl Incoming {
    /// The next request, or `None` once the connection is gone.
    pub async fn next(&mut self) -> Option<Request> {
        self.rx.recv().await
    }
}

/// A peer's request to open a stream to `host:port`. Dropping it unanswered rejects it.
pub struct OpenRequest {
    host: String,
    port: u16,
    stream: Stream,
}

impl OpenRequest {
    /// The host the peer asked for.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port the peer asked for.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Tells the peer the stream is open and returns it.
    #[must_use]
    pub fn accept(mut self) -> Stream {
        self.stream.state = State::Open;
        self.stream.shared.control(Frame::OpenOk { stream: self.stream.id() });
        self.stream
    }

    /// Tells the peer the open failed.
    pub fn reject(mut self, kind: OpenErrKind, reason: &str) {
        self.stream.state = State::Finished;
        self.stream.shared.control(Frame::OpenErr {
            stream: self.stream.id(),
            kind,
            reason: reason.to_owned(),
        });
    }
}

/// A peer's request to resolve `host`. Dropping it unanswered answers [`ResolveErrKind::Failed`].
pub struct ResolveRequest {
    host: String,
    stream: StreamId,
    shared: Arc<Shared>,
    answered: bool,
}

impl ResolveRequest {
    /// The name the peer asked about.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Tells the peer how the lookup went.
    pub fn answer(mut self, result: Result<(), ResolveError>) {
        self.answered = true;
        self.shared.control(match result {
            Ok(()) => Frame::Resolved { stream: self.stream },
            Err(ResolveError { kind, reason }) => Frame::ResolveErr { stream: self.stream, kind, reason },
        });
    }
}

impl Drop for ResolveRequest {
    fn drop(&mut self) {
        if !self.answered {
            self.shared.control(Frame::ResolveErr {
                stream: self.stream,
                kind: ResolveErrKind::Failed,
                reason: "not answered".to_owned(),
            });
        }
    }
}

/// Starts a connection over a pipe whose `Hello`s were already exchanged (see [`crate::hello`]).
/// `buffered` holds bytes already read past the peer's `Hello`, and `peer_window` is the window it
/// announced: every stream's starting credit, and the most the peer may ever return.
///
/// Returns the opener, the peer's open requests, and the driver: the future that runs the reader
/// and the writer. The caller spawns it; it resolves when the connection ends, after failing every
/// open and live stream.
pub fn start<R, W>(reader: R, buffered: BytesMut, writer: W, role: Role, config: Config, peer_window: u32) -> (Mux, Incoming, impl Future<Output = Void> + Send + 'static)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
    let (data_tx, data_rx) = mpsc::channel(DATA_QUEUE);
    let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
    let table = Table {
        streams: HashMap::new(),
        resolves: HashMap::new(),
        next_id: role.first_id(),
        last_peer_id: 0,
        dead: None,
    };
    let shared = Arc::new(Shared {
        table: Mutex::new(table),
        ctrl: ctrl_tx,
        data: data_tx,
        config,
        peer_window,
        // Credit returns in half-window steps, so a chunk over half the peer's window could stall.
        send_chunk: config.chunk.min(peer_window as usize / 2).max(1),
        role,
    });

    let driver = {
        let shared = Arc::clone(&shared);
        async move {
            let result = tokio::select! {
                read = read_loop(reader, buffered, &shared, incoming_tx) => read.context("reading from the peer"),
                write = write_loop(writer, ctrl_rx, data_rx) => write.context("writing to the peer"),
            };
            let reason = match &result {
                Ok(()) => "the peer hung up".to_owned(),
                Err(e) => format!("{e:#}"),
            };
            debug!(%reason, "connection closed");
            shared.teardown(&reason);
            result
        }
    };
    (Mux { shared: Arc::clone(&shared) }, Incoming { rx: incoming_rx }, driver)
}

/// State both the driver and every stream handle reach.
pub(crate) struct Shared {
    table: Mutex<Table>,
    ctrl: mpsc::UnboundedSender<Frame>,
    data: mpsc::Sender<Frame>,
    pub(crate) config: Config,
    /// The window the peer announced: each stream's starting send credit.
    peer_window: u32,
    /// The largest `Data` payload this side sends to this peer.
    pub(crate) send_chunk: usize,
    role: Role,
}

struct Table {
    streams: HashMap<StreamId, Entry>,
    /// Resolves awaiting an answer. They share `next_id` with streams but carry no data, so they
    /// need no credit or channel.
    resolves: HashMap<StreamId, oneshot::Sender<Result<(), ResolveError>>>,
    next_id: u32,
    last_peer_id: u32,
    /// Set once, when the connection ends; checked under the same lock as inserts, so no stream
    /// can register after teardown and wait forever.
    dead: Option<String>,
}

impl Table {
    /// The next id this side may open with; opens and resolves draw from one sequence.
    fn allocate_id(&mut self) -> Res<StreamId> {
        let id = StreamId(self.next_id);
        self.next_id = self.next_id.checked_add(2).context("stream ids exhausted")?;
        Ok(id)
    }
}

/// The reader's view of one stream.
struct Entry {
    inbound: mpsc::UnboundedSender<Inbound>,
    credit: Arc<Semaphore>,
    outstanding: Arc<AtomicU32>,
    /// Wakes a pump whose download is done but whose upload is parked on a local read that the
    /// reset will never end.
    reset: Arc<Notify>,
    opened: Option<oneshot::Sender<Result<(), Refusal>>>,
}

impl Entry {
    fn abort(mut self, reason: &str) {
        self.credit.close();
        self.reset.notify_one();
        if let Some(opened) = self.opened.take() {
            let _ = opened.send(Err(Refusal::Local(reason.to_owned())));
        }
        let _ = self.inbound.send(Inbound::Reset(reason.to_owned()));
    }
}

impl Shared {
    fn table(&self) -> MutexGuard<'_, Table> {
        // A panic while holding the lock can't leave the table half-updated in a way that matters
        // more than the panic itself, so recover the guard rather than propagating poison.
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn insert(self: &Arc<Self>, table: &mut Table, id: StreamId, state: State, opened: Option<oneshot::Sender<Result<(), Refusal>>>) -> Stream {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let credit = Arc::new(Semaphore::new(self.peer_window as usize));
        let outstanding = Arc::new(AtomicU32::new(0));
        let reset = Arc::new(Notify::new());
        let entry = Entry {
            inbound: inbound_tx,
            credit: Arc::clone(&credit),
            outstanding: Arc::clone(&outstanding),
            reset: Arc::clone(&reset),
            opened,
        };
        table.streams.insert(id, entry);
        Stream::new(id, inbound_rx, credit, outstanding, reset, Arc::clone(self), state)
    }

    /// Queues a control frame. A closed writer means the connection is already tearing down, which
    /// fails every stream on its own.
    pub(crate) fn control(&self, frame: Frame) {
        let _ = self.ctrl.send(frame);
    }

    /// Queues a data-channel frame (`Data` or `Fin`), waiting while the writer is backed up.
    pub(crate) async fn send_data(&self, frame: Frame) -> Void {
        self.data.send(frame).await.map_err(|_| anyhow!("connection closed"))
    }

    /// Drops `id` from the table, returning whether the peer still thinks it is live.
    pub(crate) fn forget(&self, id: StreamId) -> bool {
        self.table().streams.remove(&id).is_some()
    }

    fn dispatch(self: &Arc<Self>, frame: Frame, incoming: &mpsc::UnboundedSender<Request>) -> Void {
        match frame {
            Frame::Hello { .. } => bail!("unexpected Hello mid-connection"),
            Frame::Open { stream, host, port } => self.on_open(stream, host, port, incoming),
            Frame::OpenOk { stream } => {
                if let Some(opened) = self.table().streams.get_mut(&stream).and_then(|e| e.opened.take()) {
                    let _ = opened.send(Ok(()));
                }
            }
            Frame::OpenErr { stream, kind, reason } => {
                let entry = self.table().streams.remove(&stream);
                if let Some(mut entry) = entry {
                    if let Some(opened) = entry.opened.take() {
                        let _ = opened.send(Err(Refusal::Peer(OpenError { kind, reason: reason.clone() })));
                    }
                    entry.abort(&reason);
                }
            }
            Frame::Resolve { stream, host } => self.on_resolve(stream, host, incoming),
            Frame::Resolved { stream } => self.answer_resolve(stream, Ok(())),
            Frame::ResolveErr { stream, kind, reason } => self.answer_resolve(stream, Err(ResolveError { kind, reason })),
            Frame::Data { stream, data } => self.on_data(stream, data),
            Frame::Window { stream, credit } => self.on_window(stream, credit),
            Frame::Fin { stream } => {
                if let Some(entry) = self.table().streams.get(&stream) {
                    let _ = entry.inbound.send(Inbound::Fin);
                }
            }
            Frame::Rst { stream, reason } => {
                let entry = self.table().streams.remove(&stream);
                if let Some(entry) = entry {
                    debug!(%stream, %reason, "peer reset stream");
                    entry.abort(&reason);
                } else {
                    // A resolve the peer refused outright (a bad id) is reset, not answered.
                    self.answer_resolve(stream, Err(ResolveError::failed(reason)));
                }
            }
        }
        Ok(())
    }

    /// Checks that `stream` is the peer's to open and newer than any it opened before, and records
    /// it. On failure, resets it and returns `false`.
    fn admit_peer_id(&self, table: &mut Table, stream: StreamId) -> bool {
        if self.role.owns(stream) || stream.0 <= table.last_peer_id {
            self.control(Frame::Rst {
                stream,
                reason: format!("stream id {stream} is not the peer's to open"),
            });
            return false;
        }
        table.last_peer_id = stream.0;
        true
    }

    fn on_open(self: &Arc<Self>, stream: StreamId, host: String, port: u16, incoming: &mpsc::UnboundedSender<Request>) {
        let request = {
            let mut table = self.table();
            if !self.admit_peer_id(&mut table, stream) {
                return;
            }
            OpenRequest {
                host,
                port,
                stream: self.insert(&mut table, stream, State::Pending, None),
            }
        };
        debug!(%stream, host = request.host, port, "peer opened stream");
        // With no one accepting, the returned request drops here, which rejects it.
        let _ = incoming.send(Request::Open(request));
    }

    fn on_resolve(self: &Arc<Self>, stream: StreamId, host: String, incoming: &mpsc::UnboundedSender<Request>) {
        if !self.admit_peer_id(&mut self.table(), stream) {
            return;
        }
        debug!(%stream, %host, "peer asked to resolve");
        // With no one serving, the returned request drops here, which answers `Failed`.
        let _ = incoming.send(Request::Resolve(ResolveRequest {
            host,
            stream,
            shared: Arc::clone(self),
            answered: false,
        }));
    }

    fn answer_resolve(&self, stream: StreamId, result: Result<(), ResolveError>) {
        let waiting = self.table().resolves.remove(&stream);
        if let Some(waiting) = waiting {
            let _ = waiting.send(result);
        }
    }

    fn on_data(&self, stream: StreamId, data: Bytes) {
        let mut table = self.table();
        let Some(entry) = table.streams.get(&stream) else {
            // A late frame for a stream this side already finished.
            return;
        };
        #[allow(clippy::cast_possible_truncation, reason = "the decoder caps payloads at MAX_PAYLOAD")]
        let len = data.len() as u32;
        let outstanding = entry.outstanding.fetch_add(len, std::sync::atomic::Ordering::AcqRel) + len;
        if outstanding > self.config.window {
            let entry = table.streams.remove(&stream);
            drop(table);
            self.violation(stream, entry, "the peer exceeded its credit");
            return;
        }
        let _ = entry.inbound.send(Inbound::Data(data));
    }

    fn on_window(&self, stream: StreamId, credit: u32) {
        let mut table = self.table();
        let Some(entry) = table.streams.get(&stream) else { return };
        // An honest peer returns at most what this side sent, so credit never tops the window.
        if entry.credit.available_permits() + credit as usize > self.peer_window as usize {
            let entry = table.streams.remove(&stream);
            drop(table);
            self.violation(stream, entry, "the peer returned more credit than it was sent");
            return;
        }
        entry.credit.add_permits(credit as usize);
    }

    fn violation(&self, stream: StreamId, entry: Option<Entry>, what: &str) {
        let reason = format!("protocol error on stream {stream}: {what}");
        debug!(%reason, "resetting stream");
        self.control(Frame::Rst { stream, reason: reason.clone() });
        if let Some(entry) = entry {
            entry.abort(&reason);
        }
    }

    fn teardown(&self, reason: &str) {
        let (streams, resolves) = {
            let mut table = self.table();
            table.dead = Some(reason.to_owned());
            (std::mem::take(&mut table.streams), std::mem::take(&mut table.resolves))
        };
        let reason = format!("connection closed: {reason}");
        for waiting in resolves.into_values() {
            let _ = waiting.send(Err(ResolveError::failed(reason.clone())));
        }
        for entry in streams.into_values() {
            entry.abort(&reason);
        }
    }
}

async fn read_loop<R: AsyncRead + Unpin>(mut reader: R, mut buf: BytesMut, shared: &Arc<Shared>, incoming: mpsc::UnboundedSender<Request>) -> Void {
    loop {
        while let Some(frame) = Frame::decode(&mut buf)? {
            shared.dispatch(frame, &incoming)?;
        }
        buf.reserve(READ_RESERVE);
        if reader.read_buf(&mut buf).await.context("reading frames")? == 0 {
            if buf.is_empty() {
                return Ok(());
            }
            bail!("the peer hung up mid-frame");
        }
    }
}

async fn write_loop<W: AsyncWrite + Unpin>(mut writer: W, mut ctrl: mpsc::UnboundedReceiver<Frame>, mut data: mpsc::Receiver<Frame>) -> Void {
    let mut buf = BytesMut::with_capacity(WRITE_BATCH + HEADER_LEN + MAX_PAYLOAD);
    loop {
        let first = tokio::select! {
            biased;
            Some(frame) = ctrl.recv() => frame,
            Some(frame) = data.recv() => frame,
            else => return Ok(()),
        };
        first.encode(&mut buf)?;
        // Batch whatever else is ready, control first, so credit goes back promptly. That is a
        // priority, not an order: a control frame queued just after its channel was checked can
        // still go out behind data queued later (an `OpenOk` behind its stream's first `Data`).
        // That is harmless only because an opener registers its stream before its `Open` leaves.
        while buf.len() < WRITE_BATCH {
            let Some(next) = ctrl.try_recv().ok().or_else(|| data.try_recv().ok()) else { break };
            next.encode(&mut buf)?;
        }
        writer.write_all(&buf).await.context("writing frames")?;
        buf.clear();
        if ctrl.is_empty() && data.is_empty() {
            writer.flush().await.context("flushing frames")?;
        }
    }
}
