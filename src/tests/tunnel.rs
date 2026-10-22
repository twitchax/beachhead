//! [`FakeTunnel`]: a [`Tunnel`] scripted per target, standing in for the relay in the route and
//! forward tests; and [`NoFlow`], the flow of test tunnels that open none.

use std::{
    collections::HashMap,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError, Weak,
        atomic::{AtomicUsize, Ordering},
    },
};

use anyhow::{Context as _, bail};
use bytes::Bytes;
use sshunnel_mux::{
    FlowEvent, FlowKind, OpenError, QueryError, ResolveError, Traffic,
    base::Res,
    frame::{Capabilities, FlowErrKind, OpenErrKind, ResolveErrKind, Transport},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, copy, copy_bidirectional, sink, split},
    net::{TcpStream, UdpSocket},
    sync::{Notify, watch},
};

use crate::tunnel::{Conn, Flow, FlowSender, Tunnel};

/// What an open of one `(host, port)` does.
#[derive(Clone)]
enum Dial {
    /// Dials this local address.
    To(SocketAddr),
    /// Fails with this kind.
    Reject(OpenErrKind),
    /// Waits for the gate, then echoes in memory.
    Gated(watch::Receiver<bool>),
    /// Succeeds with a connection that never reads or writes.
    Stall,
    /// Succeeds with a connection whose remote end closes at once.
    Hangup,
    /// Like `Hangup`, then fails once the app has closed too and the gate opens.
    FailLate(watch::Receiver<bool>),
}

/// What a UDP flow open of one `(host, port)` does.
#[derive(Clone)]
enum UdpDial {
    /// Connects a local UDP socket to this address.
    To(SocketAddr),
    /// Fails with this kind.
    Reject(OpenErrKind),
    /// Waits for the gate, then connects to this address.
    Gated(watch::Receiver<bool>, SocketAddr),
    /// Succeeds with a flow the relay ends at once.
    Hangup,
}

#[derive(Default)]
struct Script {
    dials: HashMap<(String, u16), Dial>,
    udp: HashMap<(String, u16), UdpDial>,
    names: HashMap<String, Result<(), ResolveErrKind>>,
    opens: Vec<(String, u16)>,
    flows: Vec<(FlowKind, String, u16)>,
    resolves: Vec<String>,
}

/// A tunnel whose opens and lookups follow a script, recording every target it is asked for. An
/// unscripted open (of a connection or a flow) fails with [`OpenErrKind::Other`]; an unscripted
/// name doesn't exist.
#[derive(Clone, Default)]
pub struct FakeTunnel {
    script: Arc<Mutex<Script>>,
    asked: Arc<Notify>,
    live: Arc<AtomicUsize>,
    opened: Arc<AtomicUsize>,
}

/// Holds the opens of one gated target until [`Gate::open`].
pub struct Gate(watch::Sender<bool>);

impl Gate {
    /// Lets every waiting and future open through.
    pub fn open(&self) {
        self.0.send_replace(true);
    }
}

impl FakeTunnel {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens of `host:port` reach the local address `to`.
    pub fn dial(&self, host: &str, port: u16, to: SocketAddr) {
        self.script().dials.insert((host.to_owned(), port), Dial::To(to));
    }

    /// Opens of `host:port` fail with `kind`.
    pub fn reject(&self, host: &str, port: u16, kind: OpenErrKind) {
        self.script().dials.insert((host.to_owned(), port), Dial::Reject(kind));
    }

    /// Opens of `host:port` wait until the returned gate opens, then succeed with a connection
    /// that echoes in memory. No real I/O, so paused-time tests stay deterministic: tokio advances
    /// a paused clock whenever the runtime idles, even while a socket is still connecting.
    #[must_use]
    pub fn gate(&self, host: &str, port: u16) -> Gate {
        let (gate, waiting) = watch::channel(false);
        self.script().dials.insert((host.to_owned(), port), Dial::Gated(waiting));
        Gate(gate)
    }

    /// Opens of `host:port` succeed with a connection that never moves a byte: a relay stream
    /// whose remote end has stopped reading.
    pub fn stall(&self, host: &str, port: u16) {
        self.script().dials.insert((host.to_owned(), port), Dial::Stall);
    }

    /// Opens of `host:port` succeed with a connection whose remote end closes at once, so the
    /// stack's side of it closes first.
    pub fn hangup(&self, host: &str, port: u16) {
        self.script().dials.insert((host.to_owned(), port), Dial::Hangup);
    }

    /// Opens of `host:port` succeed with a connection whose remote end closes at once and which
    /// fails only after the app has closed its end too and the returned gate opens: a relay
    /// stream that resets after the app is done with it.
    #[must_use]
    pub fn fail_late(&self, host: &str, port: u16) -> Gate {
        let (gate, waiting) = watch::channel(false);
        self.script().dials.insert((host.to_owned(), port), Dial::FailLate(waiting));
        Gate(gate)
    }

    /// UDP flows to `host:port` reach the local address `to`, through a socket connected to it.
    pub fn udp(&self, host: &str, port: u16, to: SocketAddr) {
        self.script().udp.insert((host.to_owned(), port), UdpDial::To(to));
    }

    /// UDP flow opens of `host:port` fail with `kind`.
    pub fn udp_reject(&self, host: &str, port: u16, kind: OpenErrKind) {
        self.script().udp.insert((host.to_owned(), port), UdpDial::Reject(kind));
    }

    /// UDP flow opens of `host:port` wait until the returned gate opens, then reach `to` as
    /// [`Self::udp`]'s do. Scripting the target again leaves opens already waiting on this gate.
    #[must_use]
    pub fn udp_gate(&self, host: &str, port: u16, to: SocketAddr) -> Gate {
        let (gate, waiting) = watch::channel(false);
        self.script().udp.insert((host.to_owned(), port), UdpDial::Gated(waiting, to));
        Gate(gate)
    }

    /// UDP flow opens of `host:port` succeed with a flow the relay ends at once, as it ends one on
    /// a socket error it doesn't report.
    pub fn udp_hangup(&self, host: &str, port: u16) {
        self.script().udp.insert((host.to_owned(), port), UdpDial::Hangup);
    }

    /// Lookups of `name` answer `answer`.
    pub fn name(&self, name: &str, answer: Result<(), ResolveErrKind>) {
        self.script().names.insert(name.to_owned(), answer);
    }

    /// Every open asked for so far, in order.
    #[must_use]
    pub fn opens(&self) -> Vec<(String, u16)> {
        self.script().opens.clone()
    }

    /// Every flow open asked for so far, in order: its kind, host and port (0 for echo).
    #[must_use]
    pub fn flows(&self) -> Vec<(FlowKind, String, u16)> {
        self.script().flows.clone()
    }

    /// How many flows this tunnel opened that haven't been dropped.
    #[must_use]
    pub fn live_flows(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    /// How many flow opens finished with a flow, dropped since or not; an open cancelled while
    /// it waited isn't one.
    #[must_use]
    pub fn flows_opened(&self) -> usize {
        self.opened.load(Ordering::SeqCst)
    }

    /// Every lookup asked for so far, in order.
    #[must_use]
    pub fn resolves(&self) -> Vec<String> {
        self.script().resolves.clone()
    }

    /// Returns once at least `n` opens have been asked for.
    pub async fn wait_for_opens(&self, n: usize) {
        loop {
            let asked = self.asked.notified();
            if self.script().opens.len() >= n {
                return;
            }
            asked.await;
        }
    }

    fn script(&self) -> MutexGuard<'_, Script> {
        self.script.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A [`FakeTunnel`] connection.
pub enum FakeConn {
    /// A plain TCP stream to the scripted address.
    Tcp(TcpStream),
    /// Echoes what it's sent, in memory.
    Echo,
    /// Never moves a byte.
    Stall,
    /// Closes at once.
    Hangup,
    /// Closes its sending side at once, then fails once the app has closed and the gate opens.
    FailLate(watch::Receiver<bool>),
}

impl Tunnel for FakeTunnel {
    type Conn = FakeConn;
    type Flow = FakeFlow;

    async fn open(&self, host: &str, port: u16) -> Result<FakeConn, OpenError> {
        let dial = {
            let mut script = self.script();
            script.opens.push((host.to_owned(), port));
            script.dials.get(&(host.to_owned(), port)).cloned()
        };
        self.asked.notify_waiters();
        let fail = |kind, reason: String| OpenError { kind, reason };
        match dial {
            None => Err(fail(OpenErrKind::Other, format!("nothing scripted for {host}:{port}"))),
            Some(Dial::Reject(kind)) => Err(fail(kind, format!("dialing {host}:{port}: scripted {kind:?}"))),
            Some(Dial::To(to)) => TcpStream::connect(to).await.map(FakeConn::Tcp).map_err(|e| fail(OpenErrKind::Other, format!("dialing {to}: {e}"))),
            Some(Dial::Gated(mut gate)) => {
                gate.wait_for(|open| *open).await.map_err(|_| fail(OpenErrKind::Other, "the gate was dropped".to_owned()))?;
                Ok(FakeConn::Echo)
            }
            Some(Dial::Stall) => Ok(FakeConn::Stall),
            Some(Dial::Hangup) => Ok(FakeConn::Hangup),
            Some(Dial::FailLate(gate)) => Ok(FakeConn::FailLate(gate)),
        }
    }

    fn resolve(&self, host: &str) -> impl Future<Output = Result<(), ResolveError>> + Send {
        let answer = {
            let mut script = self.script();
            script.resolves.push(host.to_owned());
            script.names.get(host).copied().unwrap_or(Err(ResolveErrKind::NoSuchName))
        };
        std::future::ready(answer.map_err(|kind| ResolveError {
            kind,
            reason: format!("resolving {host}: scripted {kind:?}"),
        }))
    }

    async fn open_udp(&self, host: &str, port: u16) -> Result<FakeFlow, OpenError> {
        let dial = {
            let mut script = self.script();
            script.flows.push((FlowKind::Udp, host.to_owned(), port));
            script.udp.get(&(host.to_owned(), port)).cloned()
        };
        let fail = |kind, reason: String| OpenError { kind, reason };
        let connect = |to| FakeFlow::udp(to, &self.live).map_err(|e| fail(OpenErrKind::Other, format!("connecting to {to}: {e}")));
        let flow = match dial {
            None => return Err(fail(OpenErrKind::Other, format!("nothing scripted for UDP {host}:{port}"))),
            Some(UdpDial::Reject(kind)) => return Err(fail(kind, format!("opening UDP {host}:{port}: scripted {kind:?}"))),
            Some(UdpDial::To(to)) => connect(to)?,
            Some(UdpDial::Hangup) => FakeFlow::Ended(FakeEnded { _live: Live::new(&self.live) }),
            Some(UdpDial::Gated(mut gate, to)) => {
                gate.wait_for(|open| *open).await.map_err(|_| fail(OpenErrKind::Other, "the gate was dropped".to_owned()))?;
                connect(to)?
            }
        };
        self.opened.fetch_add(1, Ordering::SeqCst);
        Ok(flow)
    }

    fn open_echo(&self, host: &str) -> impl Future<Output = Result<FakeFlow, OpenError>> + Send {
        self.script().flows.push((FlowKind::Echo, host.to_owned(), 0));
        std::future::ready(Err(OpenError {
            kind: OpenErrKind::Other,
            reason: format!("nothing scripted for echo {host}"),
        }))
    }

    fn query(&self, _message: Bytes, _transport: Transport) -> impl Future<Output = Result<Bytes, QueryError>> + Send {
        NoFlow::unanswered()
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }
}

/// A [`FakeTunnel`] flow.
pub enum FakeFlow {
    /// A local UDP socket connected to the scripted address.
    Udp(FakeUdp),
    /// A flow the relay ended at once: it delivers nothing and takes nothing.
    Ended(FakeEnded),
}

/// A [`FakeFlow::Ended`].
pub struct FakeEnded {
    _live: Live,
}

/// A [`FakeFlow::Udp`]: socket errors become flow errors as the relay maps them
/// ([`FlowErrKind::from_io`]); any other error ends the flow, as it ends the relay's.
pub struct FakeUdp {
    link: Arc<UdpLink>,
    buf: Box<[u8]>,
    ended: bool,
    _live: Live,
}

/// A [`FakeUdp`]'s socket, shared with its senders. A send's error waits here for `recv`, since
/// the relay reports a failed send on the flow too.
struct UdpLink {
    socket: UdpSocket,
    /// The same socket, for sending: tokio's `try_send` refuses until the runtime has seen the
    /// socket writable, which would drop the datagrams flushed the moment a flow opens.
    sending: std::net::UdpSocket,
    failed: Mutex<Option<std::io::Error>>,
    wake: Notify,
}

impl UdpLink {
    fn failed(&self) -> MutexGuard<'_, Option<std::io::Error>> {
        self.failed.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Counts a flow in [`FakeTunnel::live_flows`] until it drops.
struct Live(Arc<AtomicUsize>);

impl Live {
    fn new(count: &Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(count))
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl FakeFlow {
    fn udp(to: SocketAddr, live: &Arc<AtomicUsize>) -> std::io::Result<Self> {
        let any = if to.is_ipv6() { IpAddr::V6(Ipv6Addr::UNSPECIFIED) } else { IpAddr::V4(Ipv4Addr::UNSPECIFIED) };
        let sending = std::net::UdpSocket::bind((any, 0))?;
        sending.connect(to)?;
        sending.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(sending.try_clone()?)?;
        Ok(Self::Udp(FakeUdp {
            link: Arc::new(UdpLink {
                socket,
                sending,
                failed: Mutex::new(None),
                wake: Notify::new(),
            }),
            buf: vec![0; 65_535].into_boxed_slice(),
            ended: false,
            _live: Live::new(live),
        }))
    }
}

impl Flow for FakeFlow {
    type Sender = FakeSender;

    fn sender(&self) -> FakeSender {
        match self {
            Self::Udp(udp) => FakeSender(Arc::downgrade(&udp.link)),
            Self::Ended(_) => FakeSender(Weak::new()),
        }
    }

    async fn recv(&mut self) -> Option<FlowEvent> {
        let Self::Udp(udp) = self else { return None };
        loop {
            if udp.ended {
                return None;
            }
            let failed = udp.link.failed().take();
            let read = if let Some(e) = failed {
                Err(e)
            } else {
                tokio::select! {
                    read = udp.link.socket.recv(&mut udp.buf) => read,
                    () = udp.link.wake.notified() => continue,
                }
            };
            match read {
                Ok(n) => return Some(FlowEvent::Datagram(Bytes::copy_from_slice(&udp.buf[..n]))),
                Err(e) => match FlowErrKind::from_io(&e) {
                    Some(kind) => return Some(FlowEvent::Error(kind)),
                    None => udp.ended = true,
                },
            }
        }
    }
}

/// A [`FakeFlow`]'s sending half; it sends nothing once its flow has dropped.
#[derive(Clone)]
pub struct FakeSender(Weak<UdpLink>);

impl FlowSender for FakeSender {
    fn try_send(&self, datagram: Bytes) -> bool {
        let Some(link) = self.0.upgrade() else { return false };
        match link.sending.send(&datagram) {
            Ok(_) => true,
            Err(e) => {
                if e.kind() != ErrorKind::WouldBlock {
                    *link.failed() = Some(e);
                    link.wake.notify_one();
                }
                false
            }
        }
    }
}

impl Conn for FakeConn {
    async fn pump<IO>(self, mut io: IO) -> Res<Traffic>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send,
    {
        match self {
            Self::Tcp(mut stream) => {
                let (sent, received) = copy_bidirectional(&mut io, &mut stream).await.context("copying")?;
                Ok(Traffic { sent, received })
            }
            Self::Echo => {
                let (mut r, mut w) = split(io);
                let echoed = copy(&mut r, &mut w).await.context("echoing")?;
                w.shutdown().await.context("closing the echo")?;
                Ok(Traffic { sent: echoed, received: echoed })
            }
            Self::Stall => std::future::pending().await,
            Self::Hangup => {
                drop(io);
                Ok(Traffic::default())
            }
            Self::FailLate(mut gate) => {
                let (mut r, mut w) = split(io);
                w.shutdown().await.context("closing")?;
                let sent = copy(&mut r, &mut sink()).await.context("draining")?;
                let _ = gate.wait_for(|open| *open).await;
                bail!("the remote reset after {sent} bytes")
            }
        }
    }
}

/// The flow of a test tunnel that opens none: no value of it exists, so its methods never run.
#[derive(Clone)]
pub enum NoFlow {}

impl NoFlow {
    /// An open of `target` that fails, since nothing is scripted for it.
    pub fn refuse(target: &str) -> std::future::Ready<Result<Self, OpenError>> {
        std::future::ready(Err(OpenError {
            kind: OpenErrKind::Other,
            reason: format!("nothing scripted for {target}"),
        }))
    }

    /// A query that fails, since nothing is scripted to answer it.
    pub fn unanswered() -> std::future::Ready<Result<Bytes, QueryError>> {
        std::future::ready(Err(QueryError {
            reason: "nothing scripted to answer the query".to_owned(),
        }))
    }
}

impl Flow for NoFlow {
    type Sender = Self;

    fn sender(&self) -> Self {
        match *self {}
    }

    async fn recv(&mut self) -> Option<FlowEvent> {
        match *self {}
    }
}

impl FlowSender for NoFlow {
    fn try_send(&self, _datagram: Bytes) -> bool {
        match *self {}
    }
}
