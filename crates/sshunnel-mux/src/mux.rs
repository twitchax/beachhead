//! The connection: many streams and datagram flows over one byte pipe, the ssh session's stdio.
//!
//! The invariant everything rests on: **the reader never blocks.** It hands each frame to a
//! per-stream unbounded channel whose depth is bounded by credit, so the pipe always drains and one
//! stalled stream can't hold up the rest. Datagrams take no credit: the reader pushes each into its
//! flow's bounded queue and drops it when the queue is full. A single writer owns the outbound pipe:
//! control frames first (so credit returns promptly), then datagrams and data taking turns, the
//! datagrams round-robin over the flows. `Fin` rides the data channel, because it must never
//! overtake that stream's queued data.

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
    flow::{Flow, FlowKind, Inbox, Outbox},
    frame::{Capabilities, FlowErrKind, Frame, HEADER_LEN, MAX_HOST, MAX_PAYLOAD, MAX_QUERY, OpenErrKind, ResolveErrKind, StreamId, Transport},
    hello::PeerHello,
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

/// Why [`Mux::query`] failed: the peer got no answer, or the query never reached it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryError {
    pub reason: String,
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for QueryError {}

impl QueryError {
    fn new(reason: impl Into<String>) -> Self {
        Self { reason: reason.into() }
    }
}

/// The handle for opening streams. Clones share one connection.
#[derive(Clone)]
pub struct Mux {
    shared: Arc<Shared>,
}

impl Mux {
    /// What the peer announced it can do in its `Hello`.
    #[must_use]
    pub fn capabilities(&self) -> Capabilities {
        self.shared.peer_capabilities
    }

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

    /// Asks the peer to open a UDP flow to `host:port` and returns the flow once it has.
    ///
    /// # Errors
    ///
    /// Fails when the peer refuses (with its kind) or the connection is gone.
    pub async fn open_udp(&self, host: &str, port: u16) -> Result<Flow, OpenError> {
        self.open_flow(FlowKind::Udp, host, port).await
    }

    /// Asks the peer to open an ICMP echo flow to `host` and returns the flow once it has.
    ///
    /// # Errors
    ///
    /// Fails when the peer refuses (with its kind) or the connection is gone.
    pub async fn open_echo(&self, host: &str) -> Result<Flow, OpenError> {
        self.open_flow(FlowKind::Echo, host, 0).await
    }

    async fn open_flow(&self, kind: FlowKind, host: &str, port: u16) -> Result<Flow, OpenError> {
        let target = || match kind {
            FlowKind::Udp => format!("UDP {host}:{port}"),
            FlowKind::Echo => format!("echo {host}"),
        };
        if host.len() > MAX_HOST {
            return Err(OpenError::other(format!("host `{host}` is longer than {MAX_HOST} bytes")));
        }
        let (opened_tx, opened_rx) = oneshot::channel();
        // Built before the wait, so a caller that gives up drops it and resets the flow.
        let flow = {
            let mut table = self.shared.table();
            if let Some(reason) = &table.dead {
                return Err(OpenError::other(format!("connection closed: {reason}")));
            }
            let id = table.allocate_id().map_err(|e| OpenError::other(format!("{e:#}")))?;
            let inbox = self.shared.register_flow(&mut table, id, Some(opened_tx));
            // Same lock, same order rule as `open`.
            self.shared.control(match kind {
                FlowKind::Udp => Frame::OpenUdp { stream: id, host: host.to_owned(), port },
                FlowKind::Echo => Frame::OpenEcho { stream: id, host: host.to_owned() },
            });
            Flow::new(id, inbox, Arc::clone(&self.shared))
        };

        // A refused or failed flow is already forgotten, so dropping it tells the peer nothing.
        match opened_rx.await {
            Ok(Ok(())) => Ok(flow),
            Ok(Err(Refusal::Peer(e))) => Err(e),
            Ok(Err(Refusal::Local(reason))) => Err(OpenError::other(format!("{}: {reason}", target()))),
            Err(_) => Err(OpenError::other(format!("connection closed while opening {}", target()))),
        }
    }

    /// Asks the peer's resolvers a raw DNS `message`, over the `transport` its asker used, and
    /// returns their answer. Nothing here times it out: a caller gives up by dropping the future,
    /// which forgets the query, and a late answer is ignored.
    ///
    /// # Errors
    ///
    /// Fails when the peer got no answer, the message is too long for a frame, or the connection is
    /// gone.
    pub async fn query(&self, message: Bytes, transport: Transport) -> Result<Bytes, QueryError> {
        if message.len() > MAX_QUERY {
            return Err(QueryError::new(format!("the query is {} bytes, over the {MAX_QUERY}-byte limit", message.len())));
        }
        let (answer_tx, answer_rx) = oneshot::channel();
        let id = {
            let mut table = self.shared.table();
            if let Some(reason) = &table.dead {
                return Err(QueryError::new(format!("connection closed: {reason}")));
            }
            let id = table.allocate_id().map_err(|e| QueryError::new(format!("{e:#}")))?;
            table.queries.insert(id, answer_tx);
            // Same lock, same order rule as `open`.
            self.shared.control(Frame::Query { stream: id, transport, message });
            id
        };
        let _waiting = WaitingQuery { shared: &self.shared, id };
        answer_rx.await.unwrap_or_else(|_| Err(QueryError::new("connection closed while querying")))
    }
}

/// Forgets a query once its caller stops waiting, so one given up leaves nothing behind.
struct WaitingQuery<'a> {
    shared: &'a Shared,
    id: StreamId,
}

impl Drop for WaitingQuery<'_> {
    fn drop(&mut self) {
        self.shared.table().queries.remove(&self.id);
    }
}

/// Something the peer asked this side to do.
pub enum Request {
    /// Dial a host.
    Open(OpenRequest),
    /// Resolve a name.
    Resolve(ResolveRequest),
    /// Open a datagram flow.
    OpenFlow(FlowRequest),
    /// Ask this side's resolvers a raw DNS message.
    Query(QueryRequest),
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

/// A peer's request to open a datagram flow. Dropping it unanswered rejects it.
pub struct FlowRequest {
    kind: FlowKind,
    host: String,
    port: u16,
    stream: StreamId,
    inbox: Arc<Inbox>,
    shared: Arc<Shared>,
    answered: bool,
}

impl FlowRequest {
    /// What the flow carries.
    #[must_use]
    pub fn kind(&self) -> FlowKind {
        self.kind
    }

    /// The host the peer asked for.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port the peer asked for; 0 for an echo flow.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Tells the peer the flow is open and returns it.
    #[must_use]
    pub fn accept(mut self) -> Flow {
        self.answered = true;
        self.shared.control(Frame::OpenOk { stream: self.stream });
        Flow::new(self.stream, Arc::clone(&self.inbox), Arc::clone(&self.shared))
    }

    /// Tells the peer the open failed.
    pub fn reject(mut self, kind: OpenErrKind, reason: &str) {
        self.answered = true;
        self.refuse(kind, reason);
    }

    /// Forgets the flow and refuses it, unless the peer already reset it.
    fn refuse(&self, kind: OpenErrKind, reason: &str) {
        if self.shared.forget_flow(self.stream) {
            self.shared.control(Frame::OpenErr {
                stream: self.stream,
                kind,
                reason: reason.to_owned(),
            });
        }
    }
}

impl Drop for FlowRequest {
    fn drop(&mut self) {
        if !self.answered {
            self.refuse(OpenErrKind::Other, "not accepted");
        }
    }
}

/// A peer's raw DNS query for this side's resolvers. Dropping it unanswered answers a query error.
pub struct QueryRequest {
    message: Bytes,
    transport: Transport,
    stream: StreamId,
    shared: Arc<Shared>,
    answered: bool,
}

impl QueryRequest {
    /// The raw DNS message the peer asked.
    #[must_use]
    pub fn message(&self) -> &Bytes {
        &self.message
    }

    /// The transport the peer's asker used, and the one to ask over.
    #[must_use]
    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// Sends the peer the answer, or why there is none. An answer too long for a frame goes as a
    /// query error.
    pub fn answer(mut self, result: Result<Bytes, QueryError>) {
        self.answered = true;
        let stream = self.stream;
        self.shared.control(match result {
            Ok(message) if message.len() <= MAX_PAYLOAD => Frame::Answer { stream, message },
            Ok(message) => Frame::QueryErr {
                stream,
                reason: format!("the answer is {} bytes, over the {MAX_PAYLOAD}-byte limit", message.len()),
            },
            Err(QueryError { reason }) => Frame::QueryErr { stream, reason },
        });
    }
}

impl Drop for QueryRequest {
    fn drop(&mut self) {
        if !self.answered {
            self.shared.control(Frame::QueryErr {
                stream: self.stream,
                reason: "not answered".to_owned(),
            });
        }
    }
}

/// Starts a connection over a pipe whose `Hello`s were already exchanged (see [`crate::hello`]).
/// `buffered` holds bytes already read past the peer's `Hello`, and `peer` is what it announced: its
/// window is every stream's starting credit and the most the peer may ever return.
///
/// Returns the opener, the peer's open requests, and the driver: the future that runs the reader
/// and the writer. The caller spawns it; it resolves when the connection ends, after failing every
/// open and live stream.
pub fn start<R, W>(reader: R, buffered: BytesMut, writer: W, role: Role, config: Config, peer: PeerHello) -> (Mux, Incoming, impl Future<Output = Void> + Send + 'static)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let peer_window = peer.window;
    let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
    let (data_tx, data_rx) = mpsc::channel(DATA_QUEUE);
    let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
    let table = Table {
        streams: HashMap::new(),
        resolves: HashMap::new(),
        flows: HashMap::new(),
        queries: HashMap::new(),
        next_id: role.first_id(),
        last_peer_id: 0,
        dead: None,
    };
    let shared = Arc::new(Shared {
        table: Mutex::new(table),
        ctrl: ctrl_tx,
        data: data_tx,
        outbox: Outbox::default(),
        config,
        peer_window,
        peer_capabilities: peer.capabilities,
        // Credit returns in half-window steps, so a chunk over half the peer's window could stall.
        send_chunk: config.chunk.min(peer_window as usize / 2).max(1),
        role,
    });

    let driver = {
        let shared = Arc::clone(&shared);
        async move {
            let result = tokio::select! {
                read = read_loop(reader, buffered, &shared, incoming_tx) => read.context("reading from the peer"),
                write = write_loop(writer, Outgoing::new(ctrl_rx, data_rx, &shared.outbox)) => write.context("writing to the peer"),
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
    /// Every flow's send queue; the writer takes turns between it and `data`.
    pub(crate) outbox: Outbox,
    pub(crate) config: Config,
    /// The window the peer announced: each stream's starting send credit.
    peer_window: u32,
    peer_capabilities: Capabilities,
    /// The largest `Data` payload this side sends to this peer.
    pub(crate) send_chunk: usize,
    role: Role,
}

struct Table {
    streams: HashMap<StreamId, Entry>,
    /// Resolves awaiting an answer. They share `next_id` with streams but carry no data, so they
    /// need no credit or channel.
    resolves: HashMap<StreamId, oneshot::Sender<Result<(), ResolveError>>>,
    /// Datagram flows, opened by either side. They share the id sequence too, and take no credit.
    flows: HashMap<StreamId, FlowEntry>,
    /// Queries awaiting an answer, like `resolves`.
    queries: HashMap<StreamId, oneshot::Sender<Result<Bytes, QueryError>>>,
    next_id: u32,
    last_peer_id: u32,
    /// Set once, when the connection ends; checked under the same lock as inserts, so no stream
    /// can register after teardown and wait forever.
    dead: Option<String>,
}

impl Table {
    /// The next id this side may open with; opens, flows, resolves and queries draw from one
    /// sequence.
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

/// The reader's view of one flow.
struct FlowEntry {
    inbox: Arc<Inbox>,
    opened: Option<oneshot::Sender<Result<(), Refusal>>>,
}

impl FlowEntry {
    fn abort(mut self, reason: &str) {
        self.inbox.close();
        if let Some(opened) = self.opened.take() {
            let _ = opened.send(Err(Refusal::Local(reason.to_owned())));
        }
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

    /// Registers flow `id` and gives it a send queue, under the lock that allocated or admitted
    /// the id, so the flow exists before its open frame can leave or its first datagram arrive.
    fn register_flow(&self, table: &mut Table, id: StreamId, opened: Option<oneshot::Sender<Result<(), Refusal>>>) -> Arc<Inbox> {
        let inbox = Arc::new(Inbox::default());
        table.flows.insert(id, FlowEntry { inbox: Arc::clone(&inbox), opened });
        self.outbox.open(id);
        inbox
    }

    /// Drops flow `id` and its send queue, returning whether the peer still thinks it is live.
    pub(crate) fn forget_flow(&self, id: StreamId) -> bool {
        let mut table = self.table();
        self.outbox.close(id);
        table.flows.remove(&id).is_some()
    }

    fn dispatch(self: &Arc<Self>, frame: Frame, incoming: &mpsc::UnboundedSender<Request>) -> Void {
        match frame {
            Frame::Hello { .. } => bail!("unexpected Hello mid-connection"),
            Frame::Open { stream, host, port } => self.on_open(stream, host, port, incoming),
            Frame::OpenUdp { stream, host, port } => self.on_open_flow(stream, FlowKind::Udp, host, port, incoming),
            Frame::OpenEcho { stream, host } => self.on_open_flow(stream, FlowKind::Echo, host, 0, incoming),
            Frame::OpenOk { stream } => self.on_open_ok(stream),
            Frame::OpenErr { stream, kind, reason } => self.on_open_err(stream, OpenError { kind, reason }),
            Frame::Resolve { stream, host } => self.on_resolve(stream, host, incoming),
            Frame::Resolved { stream } => self.answer_resolve(stream, Ok(())),
            Frame::ResolveErr { stream, kind, reason } => self.answer_resolve(stream, Err(ResolveError { kind, reason })),
            Frame::Query { stream, transport, message } => self.on_query(stream, transport, message, incoming),
            Frame::Answer { stream, message } => self.answer_query(stream, Ok(message)),
            Frame::QueryErr { stream, reason } => self.answer_query(stream, Err(QueryError { reason })),
            Frame::Data { stream, data } => self.on_data(stream, data),
            Frame::Window { stream, credit } => self.on_window(stream, credit),
            Frame::Fin { stream } => {
                if let Some(entry) = self.table().streams.get(&stream) {
                    let _ = entry.inbound.send(Inbound::Fin);
                }
            }
            Frame::Datagram { stream, data } => self.on_datagram(stream, data),
            Frame::FlowErr { stream, kind } => self.on_flow_err(stream, kind),
            Frame::Rst { stream, reason } => self.on_rst(stream, reason),
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

    fn on_open_flow(self: &Arc<Self>, stream: StreamId, kind: FlowKind, host: String, port: u16, incoming: &mpsc::UnboundedSender<Request>) {
        let request = {
            let mut table = self.table();
            if !self.admit_peer_id(&mut table, stream) {
                return;
            }
            FlowRequest {
                kind,
                host,
                port,
                stream,
                inbox: self.register_flow(&mut table, stream, None),
                shared: Arc::clone(self),
                answered: false,
            }
        };
        debug!(%stream, ?kind, host = request.host, port, "peer opened flow");
        // With no one accepting, the returned request drops here, which rejects it.
        let _ = incoming.send(Request::OpenFlow(request));
    }

    fn on_open_ok(&self, stream: StreamId) {
        let opened = {
            let mut table = self.table();
            match table.streams.get_mut(&stream) {
                Some(entry) => entry.opened.take(),
                None => table.flows.get_mut(&stream).and_then(|entry| entry.opened.take()),
            }
        };
        if let Some(opened) = opened {
            let _ = opened.send(Ok(()));
        }
    }

    fn on_open_err(&self, stream: StreamId, refusal: OpenError) {
        let mut table = self.table();
        if let Some(mut entry) = table.streams.remove(&stream) {
            drop(table);
            if let Some(opened) = entry.opened.take() {
                let _ = opened.send(Err(Refusal::Peer(refusal.clone())));
            }
            entry.abort(&refusal.reason);
        } else if let Some(mut entry) = table.flows.remove(&stream) {
            self.outbox.close(stream);
            drop(table);
            if let Some(opened) = entry.opened.take() {
                let _ = opened.send(Err(Refusal::Peer(refusal)));
            }
            entry.inbox.close();
        }
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

    fn on_query(self: &Arc<Self>, stream: StreamId, transport: Transport, message: Bytes, incoming: &mpsc::UnboundedSender<Request>) {
        if !self.admit_peer_id(&mut self.table(), stream) {
            return;
        }
        debug!(%stream, ?transport, len = message.len(), "peer sent a query");
        // With no one serving, the returned request drops here, which answers a query error.
        let _ = incoming.send(Request::Query(QueryRequest {
            message,
            transport,
            stream,
            shared: Arc::clone(self),
            answered: false,
        }));
    }

    /// Hands over an answer, unless its asker gave up (or never asked).
    fn answer_query(&self, stream: StreamId, result: Result<Bytes, QueryError>) {
        let waiting = self.table().queries.remove(&stream);
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

    /// Hands a datagram to its flow without waiting: no credit, and a full queue drops it.
    fn on_datagram(&self, stream: StreamId, data: Bytes) {
        let pushed = self.table().flows.get(&stream).map(|entry| entry.inbox.push(data));
        match pushed {
            Some(true) => {}
            Some(false) => debug!(%stream, "dropping a datagram: its flow's queue is full"),
            // A flow this side already ended, or an id that names no flow (a stream's included).
            None => debug!(%stream, "dropping a datagram for no flow"),
        }
    }

    fn on_flow_err(&self, stream: StreamId, kind: FlowErrKind) {
        if let Some(entry) = self.table().flows.get(&stream) {
            entry.inbox.report(kind);
        } else {
            debug!(%stream, ?kind, "ignoring a flow error for no flow");
        }
    }

    fn on_rst(&self, stream: StreamId, reason: String) {
        let mut table = self.table();
        if let Some(entry) = table.streams.remove(&stream) {
            drop(table);
            debug!(%stream, %reason, "peer reset stream");
            entry.abort(&reason);
        } else if let Some(entry) = table.flows.remove(&stream) {
            // The send queue goes first, so a flow whose `recv` has ended takes no more datagrams.
            self.outbox.close(stream);
            drop(table);
            debug!(%stream, %reason, "peer reset flow");
            entry.abort(&reason);
        } else if let Some(waiting) = table.queries.remove(&stream) {
            drop(table);
            let _ = waiting.send(Err(QueryError { reason }));
        } else if let Some(waiting) = table.resolves.remove(&stream) {
            drop(table);
            // A resolve the peer refused outright (a bad id) is reset, not answered.
            let _ = waiting.send(Err(ResolveError::failed(reason)));
        }
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
        let (streams, resolves, flows, queries) = {
            let mut table = self.table();
            table.dead = Some(reason.to_owned());
            // Under the table lock, which every flow registers under after checking `dead`, so no
            // flow gets a send queue from here on.
            self.outbox.clear();
            (
                std::mem::take(&mut table.streams),
                std::mem::take(&mut table.resolves),
                std::mem::take(&mut table.flows),
                std::mem::take(&mut table.queries),
            )
        };
        let reason = format!("connection closed: {reason}");
        for waiting in resolves.into_values() {
            let _ = waiting.send(Err(ResolveError::failed(reason.clone())));
        }
        for waiting in queries.into_values() {
            let _ = waiting.send(Err(QueryError::new(reason.clone())));
        }
        for entry in streams.into_values() {
            entry.abort(&reason);
        }
        for entry in flows.into_values() {
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

/// What the writer sends, in its order: control first, then datagrams and data-channel frames
/// taking turns while both wait, so neither can starve the other. The outbox takes its flows
/// round-robin, so a flood on one flow gets only its own turns.
struct Outgoing<'a> {
    ctrl: mpsc::UnboundedReceiver<Frame>,
    data: mpsc::Receiver<Frame>,
    outbox: &'a Outbox,
    /// Whether a datagram goes ahead of data when both wait.
    datagram_turn: bool,
}

impl<'a> Outgoing<'a> {
    fn new(ctrl: mpsc::UnboundedReceiver<Frame>, data: mpsc::Receiver<Frame>, outbox: &'a Outbox) -> Self {
        Self { ctrl, data, outbox, datagram_turn: false }
    }

    /// The next frame ready to go, without waiting.
    fn ready(&mut self) -> Option<Frame> {
        if let Ok(frame) = self.ctrl.try_recv() {
            return Some(frame);
        }
        let frame = if self.datagram_turn {
            self.outbox.pop().or_else(|| self.data.try_recv().ok())
        } else {
            self.data.try_recv().ok().or_else(|| self.outbox.pop())
        }?;
        self.datagram_turn = !matches!(frame, Frame::Datagram { .. });
        Some(frame)
    }

    /// The next frame, waiting for one. The channels' senders live in `Shared`, which the driver
    /// holds, so neither closes while the writer runs.
    async fn next(&mut self) -> Frame {
        loop {
            if let Some(frame) = self.ready() {
                return frame;
            }
            tokio::select! {
                biased;
                Some(frame) = self.ctrl.recv() => return frame,
                Some(frame) = self.data.recv() => {
                    self.datagram_turn = true;
                    return frame;
                }
                () = self.outbox.ready() => {}
            }
        }
    }

    /// Whether nothing waits, so the batch just written is the last for now.
    fn is_idle(&self) -> bool {
        self.ctrl.is_empty() && self.data.is_empty() && self.outbox.is_empty()
    }
}

async fn write_loop<W: AsyncWrite + Unpin>(mut writer: W, mut outgoing: Outgoing<'_>) -> Void {
    let mut buf = BytesMut::with_capacity(WRITE_BATCH + HEADER_LEN + MAX_PAYLOAD);
    loop {
        outgoing.next().await.encode(&mut buf)?;
        // Batch whatever else is ready, in the same order, so credit goes back promptly. Control
        // first is a priority, not an order: a control frame queued just after its channel was
        // checked can still go out behind data queued later (an `OpenOk` behind its stream's first
        // `Data`, or its flow's first `Datagram`). That is harmless only because an opener
        // registers its stream or flow before its open leaves.
        while buf.len() < WRITE_BATCH {
            let Some(next) = outgoing.ready() else { break };
            next.encode(&mut buf)?;
        }
        writer.write_all(&buf).await.context("writing frames")?;
        buf.clear();
        if outgoing.is_idle() {
            writer.flush().await.context("flushing frames")?;
        }
    }
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::time::Duration;

    use tokio::{
        io::{AsyncRead, duplex, split},
        time::timeout,
    };

    use super::*;
    use crate::frame::Transport;

    /// The next frame from the client's side of the pipe.
    async fn next_frame(r: &mut (impl AsyncRead + Unpin), buf: &mut BytesMut) -> Frame {
        loop {
            if let Some(frame) = Frame::decode(buf).unwrap() {
                return frame;
            }
            assert!(r.read_buf(buf).await.unwrap() > 0, "the client hung up");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_query_given_up_is_forgotten() {
        let (a, b) = duplex(64 * 1024);
        let (ar, aw) = split(a);
        let peer = PeerHello {
            window: 64 * 1024,
            capabilities: Capabilities::default(),
        };
        let (mux, _incoming, driver) = start(ar, BytesMut::new(), aw, Role::Client, Config::default(), peer);
        tokio::spawn(driver);
        let (mut r, mut w) = split(b);
        let mut buf = BytesMut::new();

        let given_up = timeout(Duration::from_secs(1), mux.query(Bytes::from_static(b"q1"), Transport::Udp)).await;
        assert!(given_up.is_err(), "nothing answers, so the caller gives up");
        assert!(mux.shared.table().queries.is_empty(), "a query given up leaves nothing behind");

        // The answer arrives late, then a second query asks.
        let Frame::Query { stream: late, .. } = next_frame(&mut r, &mut buf).await else {
            panic!("expected the first Query")
        };
        let asking = tokio::spawn({
            let mux = mux.clone();
            async move { mux.query(Bytes::from_static(b"q2"), Transport::Udp).await }
        });
        let Frame::Query { stream: second, .. } = next_frame(&mut r, &mut buf).await else {
            panic!("expected the second Query")
        };
        let mut wire = BytesMut::new();
        Frame::Answer {
            stream: late,
            message: Bytes::from_static(b"late"),
        }
        .encode(&mut wire)
        .unwrap();
        Frame::Answer {
            stream: second,
            message: Bytes::from_static(b"a2"),
        }
        .encode(&mut wire)
        .unwrap();
        w.write_all(&wire).await.unwrap();

        // The late answer changed nothing: the second query gets its own.
        assert_eq!(asking.await.unwrap().unwrap(), Bytes::from_static(b"a2"));
        assert!(mux.shared.table().queries.is_empty());
    }
}
