//! The userspace netstack: smoltcp terminates the app's TCP on the device's packets, and each
//! connection is bridged to a stream the relay dialed.
//!
//! Every packet is classified before smoltcp sees it. A SYN that opens a connection is held while
//! the relay dials, so the app sees the remote's answer rather than ours: a dial that succeeds
//! replays the SYN into a fresh listening socket, a refused one becomes an RST, an unreachable host
//! ICMP host unreachable, and a timed-out one silence (the app's own timeout fires). UDP to the DNS
//! address goes to [`Dns`]; other UDP and ICMP get ICMP administratively prohibited. smoltcp only
//! ever sees TCP.
//!
//! One task runs it all from one `poll_fn`: the device's packets, the dials and DNS answers in
//! flight, smoltcp's timer, and every connection's end of the duplex pipe its relay stream pumps,
//! so a pump's write wakes it. Back-pressure is per connection, as in the mux: a slow relay stream
//! fills its pipe and then its socket's receive window, never the packet path.

use std::{
    collections::{HashMap, VecDeque},
    future::{Future, poll_fn},
    hash::{BuildHasher as _, RandomState},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Context as _, anyhow, bail};
use bytes::Bytes;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{self, State},
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IPV6_HEADER_LEN, IpAddress, IpCidr, IpListenEndpoint, IpProtocol, IpRepr, Ipv4Packet, Ipv6Packet, TcpPacket, UDP_HEADER_LEN, UdpPacket, UdpRepr, checksum},
};
use sshunnel_mux::{OpenError, Traffic, frame::OpenErrKind};
use tokio::{
    io::{AsyncRead as _, AsyncWrite as _, DuplexStream, ReadBuf, duplex},
    sync::mpsc::{self, OwnedPermit, error::SendError, error::TrySendError},
    task::{self, AbortHandle, JoinSet},
    time::{Instant, Sleep},
};
use tracing::debug;

use crate::{
    base::{Res, Void},
    route::{DNS_ADDR, FAKE_RANGE, MTU, TUN_ADDR, TUN_ADDR6, router::Router},
    tunnel::{Conn as _, Tunnel},
};

/// SYNs held while their dials run. Past this a new connection's SYN is dropped, and the app
/// retransmits it, so a SYN storm costs bounded memory and relay dials.
pub const MAX_HELD: usize = 256;
/// DNS queries answered at once; past this a query is dropped, and the client retries it.
pub const MAX_QUERIES: usize = 256;
/// Each socket's receive and send buffer: four full-size segments at the default MTU, which lets
/// window scaling keep a fast app busy without much memory per connection.
const SOCKET_BUFFER: usize = 256 * 1024;
/// Each direction of a connection's pipe to its relay stream.
pub(crate) const PIPE: usize = 256 * 1024;
/// Packets smoltcp may queue for the device before it holds off and the stack stops reading.
const BACKLOG: usize = 64;
/// Packets read from the device per pass, so dials, answers and pipes get their turn.
const BATCH: usize = 64;
/// Passes per wake before the stack yields to other tasks.
const PASSES: usize = 4;
/// The DNS server's port on [`DNS_ADDR`], and the upstreams' it forwards to.
pub(crate) const DNS_PORT: u16 = 53;
/// The most an ICMP error may total, quoting as much of its packet as fits (RFC 1812).
const ICMP4_MAX: usize = 576;
/// The same for IPv6 (RFC 4443): the minimum IPv6 MTU.
const ICMP6_MAX: usize = 1280;
/// The hop limit of the packets the stack writes itself.
const HOP_LIMIT: u8 = 64;

/// The device's IP packets: what it read, for the stack, and what it should write.
pub struct Packets {
    pub rx: mpsc::Receiver<Bytes>,
    pub tx: mpsc::Sender<Bytes>,
}

/// The DNS server behind [`DNS_ADDR`]: a query's UDP payload in, at most one answer out.
pub trait Dns: Send + Sync + 'static {
    fn answer(&self, query: Bytes) -> impl Future<Output = Option<Bytes>> + Send;
}

/// Runs the stack until the device's packets end.
///
/// # Errors
///
/// Fails when the device stops taking packets while it still sends them, or a connection's task
/// panics.
pub async fn run<T: Tunnel, D: Dns>(packets: Packets, tunnel: T, router: Arc<Router>, dns: Arc<D>) -> Void {
    // Owning the DNS address and answering for every other one (any-IP), the stack sends
    // everything back out through the device.
    let engine = Engine::new(&[IpCidr::new(DNS_ADDR.into(), FAKE_RANGE.prefix_len())], &[TUN_ADDR.into(), TUN_ADDR6.addr().into()], packets.tx)?;
    let mut stack = Stack {
        engine,
        rx: packets.rx,
        tunnel,
        router,
        dns,
        held: HashMap::new(),
        flows: HashMap::new(),
        handles: HashMap::new(),
        dials: JoinSet::new(),
        queries: JoinSet::new(),
        pumps: JoinSet::new(),
    };
    poll_fn(|cx| stack.poll(cx)).await
}

/// One TCP connection, as the app sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Flow {
    app: SocketAddr,
    remote: SocketAddr,
}

impl std::fmt::Display for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.app, self.remote)
    }
}

type Dialed<C> = (Flow, Result<C, OpenError>);

struct Stack<T: Tunnel, D: Dns> {
    engine: Engine,
    rx: mpsc::Receiver<Bytes>,
    tunnel: T,
    router: Arc<Router>,
    dns: Arc<D>,
    /// The SYN of each connection whose dial is in flight.
    held: HashMap<Flow, Bytes>,
    /// Each connection with a socket, both ways.
    flows: HashMap<Flow, SocketHandle>,
    handles: HashMap<SocketHandle, Flow>,
    dials: JoinSet<Dialed<T::Conn>>,
    /// Answers to send: the asker and the answer.
    queries: JoinSet<Option<(SocketAddr, Bytes)>>,
    pumps: JoinSet<(Flow, Res<Traffic>)>,
}

impl<T: Tunnel, D: Dns> Stack<T, D> {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Void> {
        for _ in 0..PASSES {
            // Whether `rx` holds this task's waker: `recv` registers none when it hands over a
            // packet, so a pass that stops reading early must read again before it sleeps.
            let mut listening = false;
            for _ in 0..BATCH {
                if self.engine.backlogged() {
                    break;
                }
                match self.rx.poll_recv(cx) {
                    Poll::Ready(Some(packet)) => self.classify(packet),
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Pending => {
                        listening = true;
                        break;
                    }
                }
            }
            if let Err(e) = self.finish(cx) {
                return Poll::Ready(Err(e));
            }
            self.engine.poll();
            let Self { engine, flows, handles, .. } = self;
            engine.run_bridges(cx, |handle| {
                if let Some(flow) = handles.remove(&handle) {
                    flows.remove(&flow);
                }
            });
            self.engine.poll();
            if let Err(e) = self.engine.flush(cx) {
                return Poll::Ready(Err(e));
            }
            // Still backlogged after a flush means the device is full, and its permit wakes us.
            // `|`, not `||`: the timer is armed either way.
            let again = (!listening && !self.engine.backlogged()) | self.engine.wait(cx);
            if !again {
                return Poll::Pending;
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// Sends a packet where it belongs: smoltcp, a held SYN, the DNS server, or an ICMP refusal.
    fn classify(&mut self, packet: Bytes) {
        let Some(ip) = Ip::parse(&packet) else { return };
        // Router solicitations, MLD reports and broadcasts (the device subnet's included) aren't
        // for any one host to answer.
        if !unicast(ip.src) || !unicast(ip.dst) {
            return;
        }
        match ip.proto {
            IpProtocol::Tcp => self.tcp(packet, &ip),
            IpProtocol::Udp if ip.dst == IpAddr::V4(DNS_ADDR) && UdpPacket::new_checked(ip.payload(&packet)).is_ok_and(|udp| udp.dst_port() == DNS_PORT) => self.query(&packet, &ip),
            // Never an ICMP error about an ICMP error (RFC 1122).
            IpProtocol::Icmp | IpProtocol::Icmpv6 if ip.payload(&packet).first().is_some_and(|kind| is_icmp_error(ip.proto, *kind)) => {}
            _ => self.engine.send_opt(icmp_error(&packet, &ip, Refusal::Prohibited)),
        }
    }

    fn tcp(&mut self, packet: Bytes, ip: &Ip) {
        let Ok(tcp) = TcpPacket::new_checked(ip.payload(&packet)) else { return };
        let flow = Flow {
            app: SocketAddr::new(ip.src, tcp.src_port()),
            remote: SocketAddr::new(ip.dst, tcp.dst_port()),
        };
        let opening = tcp.syn() && !tcp.ack() && !tcp.rst();
        if opening
            && let Some(&handle) = self.flows.get(&flow)
            && self.engine.state(handle) == State::TimeWait
        {
            // The app reused the port of a connection this end closed first. That one is over,
            // and smoltcp would only challenge-ACK the SYN, so make way, as Linux does.
            self.engine.remove(handle);
            self.flows.remove(&flow);
            self.handles.remove(&handle);
        }
        if !opening || self.flows.contains_key(&flow) {
            // Its socket's, or a stray segment smoltcp answers with an RST.
            return self.engine.inject(packet);
        }
        if self.held.contains_key(&flow) {
            // A retransmit while the dial runs.
            return;
        }
        let Some(host) = self.router.destination(flow.remote.ip()) else {
            debug!(%flow, "not routed; resetting");
            // No socket for it: smoltcp answers with an RST.
            return self.engine.inject(packet);
        };
        if self.held.len() >= MAX_HELD {
            debug!(%flow, "{MAX_HELD} connections already opening; dropping a SYN");
            return;
        }
        self.held.insert(flow, packet);
        let tunnel = self.tunnel.clone();
        self.dials.spawn(async move {
            let opened = tunnel.open(&host, flow.remote.port()).await;
            (flow, opened)
        });
    }

    fn query(&mut self, packet: &Bytes, ip: &Ip) {
        if self.queries.len() >= MAX_QUERIES {
            debug!("{MAX_QUERIES} DNS queries in flight; dropping one");
            return;
        }
        let Ok(udp) = UdpPacket::new_checked(ip.payload(packet)) else { return };
        let asker = SocketAddr::new(ip.src, udp.src_port());
        let start = ip.start + UDP_HEADER_LEN;
        let query = packet.slice(start..start + udp.payload().len());
        let dns = Arc::clone(&self.dns);
        self.queries.spawn(async move { dns.answer(query).await.map(|answer| (asker, answer)) });
    }

    /// Acts on the dials, DNS answers and pumps that finished.
    fn finish(&mut self, cx: &mut Context<'_>) -> Void {
        while let Poll::Ready(Some(dialed)) = self.dials.poll_join_next(cx) {
            let (flow, opened) = dialed.context("a dial task failed")?;
            self.dialed(flow, opened);
        }
        while let Poll::Ready(Some(answered)) = self.queries.poll_join_next(cx) {
            if let Some((asker, answer)) = answered.context("a DNS task failed")? {
                self.engine.send_opt(udp_packet(SocketAddr::new(DNS_ADDR.into(), DNS_PORT), asker, &answer));
            }
        }
        while let Poll::Ready(Some(pumped)) = self.pumps.poll_join_next_with_id(cx) {
            let (pump, (flow, traffic)) = match pumped {
                Ok(pumped) => pumped,
                // The stack aborted it when the app reset the connection.
                Err(e) if e.is_cancelled() => continue,
                Err(e) => return Err(e).context("a connection task failed"),
            };
            match traffic {
                Ok(traffic) => debug!(%flow, sent = traffic.sent, received = traffic.received, "connection closed"),
                Err(e) => {
                    debug!(%flow, "connection failed: {e:#}");
                    // The remote end reset or the session dropped: reset the app too, unless the
                    // app has since reused the 4-tuple for a connection of its own.
                    if let Some(&handle) = self.flows.get(&flow)
                        && self.engine.pumped_by(handle, pump)
                    {
                        self.engine.abort(handle);
                    }
                }
            }
        }
        Ok(())
    }

    fn dialed(&mut self, flow: Flow, opened: Result<T::Conn, OpenError>) {
        let Some(syn) = self.held.remove(&flow) else { return };
        let conn = match opened {
            Ok(conn) => conn,
            Err(e) => {
                debug!(%flow, "dial failed: {e}");
                return match e.kind {
                    OpenErrKind::Refused | OpenErrKind::Other => self.engine.replay(syn),
                    OpenErrKind::Unreachable => self.engine.send_opt(Ip::parse(&syn).and_then(|ip| icmp_error(&syn, &ip, Refusal::Unreachable))),
                    OpenErrKind::TimedOut => {}
                };
            }
        };
        let Some(handle) = self.engine.accept(flow.remote, flow.app, syn) else {
            // Dropping the stream resets it on the relay; the app retransmits its SYN.
            debug!(%flow, "the replayed SYN wasn't taken");
            return;
        };
        let (near, far) = duplex(PIPE);
        let pump = self.pumps.spawn(async move { (flow, conn.pump(far).await) });
        self.engine.bridge(handle, near, Some(pump));
        self.flows.insert(flow, handle);
        self.handles.insert(handle, flow);
    }
}

/// How the stack turns a packet away with ICMP.
#[derive(Clone, Copy)]
enum Refusal {
    Unreachable,
    Prohibited,
}

impl Refusal {
    /// The ICMP type and code for a packet of `family`. Linux reports each as `EHOSTUNREACH`.
    fn icmp(self, v4: bool) -> (u8, u8) {
        match (self, v4) {
            (Self::Unreachable, true) => (3, 1),
            (Self::Unreachable, false) => (1, 3),
            (Self::Prohibited, true) => (3, 13),
            (Self::Prohibited, false) => (1, 1),
        }
    }
}

/// Whether an ICMP message type (`proto` is `Icmp` or `Icmpv6`) is an error rather than a query.
pub(crate) fn is_icmp_error(proto: IpProtocol, kind: u8) -> bool {
    match proto {
        // Destination unreachable, source quench, redirect, time exceeded, parameter problem.
        IpProtocol::Icmp => matches!(kind, 3 | 4 | 5 | 11 | 12),
        IpProtocol::Icmpv6 => kind < 128,
        _ => false,
    }
}

fn unicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => !(v4.is_multicast() || v4.is_broadcast() || v4 == FAKE_RANGE.broadcast() || v4.is_unspecified()),
        IpAddr::V6(v6) => !(v6.is_multicast() || v6.is_unspecified()),
    }
}

/// The IP header fields the stack classifies by, and where the payload sits.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ip {
    pub(crate) src: IpAddr,
    pub(crate) dst: IpAddr,
    pub(crate) proto: IpProtocol,
    start: usize,
    end: usize,
}

impl Ip {
    /// Parses a whole IPv4 or IPv6 packet. A v4 fragment doesn't parse: the stack doesn't
    /// reassemble, and with the device's MTU the kernel has no reason to fragment toward it.
    pub(crate) fn parse(packet: &[u8]) -> Option<Self> {
        match packet.first()? >> 4 {
            4 => {
                let ip = Ipv4Packet::new_checked(packet).ok()?;
                if ip.more_frags() || ip.frag_offset() != 0 {
                    return None;
                }
                Some(Self {
                    src: ip.src_addr().into(),
                    dst: ip.dst_addr().into(),
                    proto: ip.next_header(),
                    start: usize::from(ip.header_len()),
                    end: usize::from(ip.total_len()),
                })
            }
            6 => {
                let ip = Ipv6Packet::new_checked(packet).ok()?;
                Some(Self {
                    src: ip.src_addr().into(),
                    dst: ip.dst_addr().into(),
                    proto: ip.next_header(),
                    start: IPV6_HEADER_LEN,
                    end: IPV6_HEADER_LEN + usize::from(ip.payload_len()),
                })
            }
            _ => None,
        }
    }

    pub(crate) fn payload<'a>(&self, packet: &'a [u8]) -> &'a [u8] {
        packet.get(self.start..self.end).unwrap_or_default()
    }
}

/// An ICMP error from `packet`'s destination back to its source, quoting as much of it as fits.
fn icmp_error(packet: &[u8], ip: &Ip, refusal: Refusal) -> Option<Bytes> {
    let v4 = ip.src.is_ipv4();
    let (proto, max) = if v4 { (IpProtocol::Icmp, ICMP4_MAX) } else { (IpProtocol::Icmpv6, ICMP6_MAX) };
    let (from, to) = (IpAddress::from(ip.dst), IpAddress::from(ip.src));
    if from.version() != to.version() {
        return None;
    }
    let header_len = IpRepr::new(from, to, proto, 0, HOP_LIMIT).header_len();
    let quoted = packet.get(..ip.end.min(max - header_len - 8))?;
    let reply = IpRepr::new(from, to, proto, 8 + quoted.len(), HOP_LIMIT);
    let mut buf = vec![0; reply.buffer_len()];
    reply.emit(&mut buf[..], &ChecksumCapabilities::default());
    let icmp = buf.get_mut(header_len..)?;
    (icmp[0], icmp[1]) = refusal.icmp(v4);
    icmp[8..].copy_from_slice(quoted);
    let sum = if v4 {
        checksum::data(icmp)
    } else {
        let len = u32::try_from(icmp.len()).ok()?;
        checksum::combine(&[checksum::pseudo_header(&from, &to, proto, len), checksum::data(icmp)])
    };
    icmp[2..4].copy_from_slice(&(!sum).to_be_bytes());
    Some(buf.into())
}

/// A UDP datagram from `from` to `to`; `None` when the families differ or it won't fit the MTU.
pub(crate) fn udp_packet(from: SocketAddr, to: SocketAddr, payload: &[u8]) -> Option<Bytes> {
    if from.is_ipv4() != to.is_ipv4() || payload.len() > usize::from(MTU) {
        return None;
    }
    let udp = UdpRepr {
        src_port: from.port(),
        dst_port: to.port(),
    };
    let ip = IpRepr::new(from.ip().into(), to.ip().into(), IpProtocol::Udp, UDP_HEADER_LEN + payload.len(), HOP_LIMIT);
    if ip.buffer_len() > usize::from(MTU) {
        return None;
    }
    let caps = ChecksumCapabilities::default();
    let mut buf = vec![0; ip.buffer_len()];
    ip.emit(&mut buf[..], &caps);
    let mut datagram = UdpPacket::new_unchecked(&mut buf[ip.header_len()..]);
    udp.emit(&mut datagram, &ip.src_addr(), &ip.dst_addr(), payload.len(), |space| space.copy_from_slice(payload), &caps);
    Some(buf.into())
}

/// Room reserved in the device's channel.
type Reserve = Pin<Box<dyn Future<Output = Result<OwnedPermit<Bytes>, SendError<()>>> + Send>>;

/// A smoltcp interface on an in-memory device, its TCP sockets, and the pipes bridged to them:
/// the machinery the stack and the tests' app side share.
pub(crate) struct Engine {
    iface: Interface,
    wire: Wire,
    sockets: SocketSet<'static>,
    bridges: HashMap<SocketHandle, Bridge>,
    /// smoltcp's clock starts here, on tokio's clock, so paused time pauses it too.
    epoch: Instant,
    timer: Pin<Box<Sleep>>,
    outlet: mpsc::Sender<Bytes>,
    /// Waits for room in a full `outlet`.
    permit: Option<Reserve>,
}

impl Engine {
    /// An any-IP interface owning `addrs`, with a default route through each of `gateways`,
    /// writing its packets to `outlet`.
    pub(crate) fn new(addrs: &[IpCidr], gateways: &[IpAddr], outlet: mpsc::Sender<Bytes>) -> Res<Self> {
        let mut wire = Wire::default();
        let mut config = Config::new(HardwareAddress::Ip);
        // Seeds smoltcp's initial sequence numbers; `RandomState` draws its keys from the OS.
        config.random_seed = RandomState::new().hash_one(0_u8);
        let mut iface = Interface::new(config, &mut wire, SmolInstant::ZERO);
        iface.set_any_ip(true);
        let mut full = false;
        iface.update_ip_addrs(|ips| full = addrs.iter().any(|addr| ips.push(*addr).is_err()));
        if full {
            bail!("too many interface addresses");
        }
        for gateway in gateways {
            let added = match gateway {
                IpAddr::V4(v4) => iface.routes_mut().add_default_ipv4_route(*v4),
                IpAddr::V6(v6) => iface.routes_mut().add_default_ipv6_route(*v6),
            };
            added.map_err(|_| anyhow!("the route table is full"))?;
        }
        let epoch = Instant::now();
        Ok(Self {
            iface,
            wire,
            sockets: SocketSet::new(Vec::new()),
            bridges: HashMap::new(),
            epoch,
            timer: Box::pin(tokio::time::sleep_until(epoch)),
            outlet,
            permit: None,
        })
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(i64::try_from(self.epoch.elapsed().as_micros()).unwrap_or(i64::MAX))
    }

    fn socket() -> tcp::Socket<'static> {
        let mut socket = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]), tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]));
        // The bytes come off a pipe already batched; Nagle would only add latency.
        socket.set_nagle_enabled(false);
        socket
    }

    /// Queues a packet for smoltcp.
    pub(crate) fn inject(&mut self, packet: Bytes) {
        self.wire.inbound.push_back(packet);
    }

    /// Queues a packet straight for the device.
    fn send_opt(&mut self, packet: Option<Bytes>) {
        if let Some(packet) = packet {
            self.wire.outbound.push_back(packet);
        }
    }

    /// Hands smoltcp one packet now, ahead of any queued ones.
    fn replay(&mut self, packet: Bytes) {
        self.wire.inbound.push_front(packet);
        self.iface.poll_ingress_single(self.now(), &mut self.wire, &mut self.sockets);
    }

    /// Replays `syn` into a socket listening on `local`, and keeps the socket if it took the SYN
    /// from `peer`. Listening only for the replay means no other SYN can land on the socket.
    fn accept(&mut self, local: SocketAddr, peer: SocketAddr, syn: Bytes) -> Option<SocketHandle> {
        let mut socket = Self::socket();
        let endpoint = IpListenEndpoint {
            addr: Some(local.ip().into()),
            port: local.port(),
        };
        if socket.listen(endpoint).is_err() {
            // Nothing can listen on port 0: refuse it.
            self.replay(syn);
            return None;
        }
        let handle = self.sockets.add(socket);
        self.replay(syn);
        let socket = self.sockets.get::<tcp::Socket>(handle);
        if socket.state() == State::SynReceived && socket.remote_endpoint() == Some(peer.into()) {
            Some(handle)
        } else {
            self.sockets.remove(handle);
            None
        }
    }

    /// Opens a connection from `port` to `to`. Only the test factory's app side dials in.
    #[cfg(feature = "testing")]
    pub(crate) fn connect(&mut self, to: SocketAddr, port: u16) -> Option<SocketHandle> {
        let mut socket = Self::socket();
        socket.connect(self.iface.context(), to, port).ok()?;
        Some(self.sockets.add(socket))
    }

    pub(crate) fn state(&self, handle: SocketHandle) -> State {
        self.sockets.get::<tcp::Socket>(handle).state()
    }

    pub(crate) fn remove(&mut self, handle: SocketHandle) {
        self.bridges.remove(&handle);
        self.sockets.remove(handle);
    }

    /// Whether `pump` is the task on the far end of `handle`'s pipe.
    fn pumped_by(&self, handle: SocketHandle, pump: task::Id) -> bool {
        self.bridges.get(&handle).and_then(|bridge| bridge.pump.as_ref()).is_some_and(|abort| abort.id() == pump)
    }

    /// Resets a connection; the bridge sweep removes it once the RST is out.
    fn abort(&mut self, handle: SocketHandle) {
        self.sockets.get_mut::<tcp::Socket>(handle).abort();
    }

    /// Joins a socket to its end of a pipe. `pump` is the task on the far end, aborted if the
    /// connection resets so the reset reaches the far side too.
    pub(crate) fn bridge(&mut self, handle: SocketHandle, io: DuplexStream, pump: Option<AbortHandle>) {
        self.bridges.insert(handle, Bridge { io, pump, shut: false, ended: false });
    }

    /// Lets smoltcp take in what's queued and send what it can.
    pub(crate) fn poll(&mut self) {
        self.iface.poll(self.now(), &mut self.wire, &mut self.sockets);
    }

    /// Moves bytes between every bridged socket and its pipe, and removes the connections that
    /// are gone, calling `closed` with each.
    pub(crate) fn run_bridges(&mut self, cx: &mut Context<'_>, mut closed: impl FnMut(SocketHandle)) {
        let Self { sockets, bridges, .. } = self;
        bridges.retain(|&handle, bridge| {
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            // An RST in SYN-RECEIVED puts a socket back to listening; never leave it so.
            let gone = match socket.state() {
                State::Listen => true,
                // Once any RST of ours is out.
                State::Closed => socket.remote_endpoint().is_none(),
                _ => false,
            };
            if gone {
                if !(bridge.shut && bridge.ended)
                    && let Some(pump) = &bridge.pump
                {
                    pump.abort();
                }
                sockets.remove(handle);
                closed(handle);
                return false;
            }
            bridge.step(socket, cx);
            true
        });
    }

    /// Hands queued packets to the device, as far as it has room.
    ///
    /// # Errors
    ///
    /// Fails when the device is gone.
    pub(crate) fn flush(&mut self, cx: &mut Context<'_>) -> Void {
        loop {
            if let Some(waiting) = self.permit.as_mut() {
                let Poll::Ready(permit) = waiting.as_mut().poll(cx) else { return Ok(()) };
                self.permit = None;
                let permit = permit.map_err(|_| anyhow!("the device stopped taking packets"))?;
                let Some(packet) = self.wire.outbound.pop_front() else { return Ok(()) };
                permit.send(packet);
            }
            let Some(packet) = self.wire.outbound.pop_front() else { return Ok(()) };
            match self.outlet.try_send(packet) {
                Ok(()) => {}
                Err(TrySendError::Full(packet)) => {
                    self.wire.outbound.push_front(packet);
                    self.permit = Some(Box::pin(self.outlet.clone().reserve_owned()));
                }
                Err(TrySendError::Closed(_)) => bail!("the device stopped taking packets"),
            }
        }
    }

    /// Whether the device's queue is full, so reading more would only grow it.
    fn backlogged(&self) -> bool {
        self.wire.outbound.len() >= BACKLOG
    }

    /// Arms the timer for smoltcp's next deadline; true when that's already due and the device
    /// has room to act on it.
    pub(crate) fn wait(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(at) = self.iface.poll_at(self.now(), &self.sockets) else { return false };
        let deadline = self.epoch + Duration::from_micros(u64::try_from(at.total_micros()).unwrap_or(0));
        if self.timer.deadline() != deadline {
            self.timer.as_mut().reset(deadline);
        }
        self.timer.as_mut().poll(cx).is_ready() && !self.backlogged()
    }
}

/// A connection's socket joined to its end of a pipe.
struct Bridge {
    io: DuplexStream,
    pump: Option<AbortHandle>,
    /// The peer's FIN has reached the pipe.
    shut: bool,
    /// The pipe ended and the socket is closing.
    ended: bool,
}

impl Bridge {
    fn step(&mut self, socket: &mut tcp::Socket<'_>, cx: &mut Context<'_>) {
        // From the peer to the pipe, until the pipe is full.
        while socket.can_recv() {
            let wrote = socket.recv(|buf| match Pin::new(&mut self.io).poll_write(cx, buf) {
                Poll::Ready(Ok(n)) => (n, Ok(n)),
                Poll::Ready(Err(e)) => (0, Err(e)),
                Poll::Pending => (0, Ok(0)),
            });
            match wrote {
                Ok(Ok(0)) => break,
                Ok(Ok(_)) => {}
                // The far end is gone: reset the peer.
                Ok(Err(_)) | Err(_) => {
                    socket.abort();
                    return;
                }
            }
        }
        let peer_finished = matches!(socket.state(), State::CloseWait | State::LastAck | State::Closing | State::TimeWait) && !socket.can_recv();
        if peer_finished && !self.shut && Pin::new(&mut self.io).poll_shutdown(cx).is_ready() {
            self.shut = true;
        }
        // From the pipe to the peer, until the socket's buffer is full.
        while !self.ended && socket.can_send() {
            let read = socket.send(|buf| {
                let mut buf = ReadBuf::new(buf);
                match Pin::new(&mut self.io).poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(())) => {
                        let n = buf.filled().len();
                        (n, Some(Ok(n)))
                    }
                    Poll::Ready(Err(e)) => (0, Some(Err(e))),
                    Poll::Pending => (0, None),
                }
            });
            match read {
                Ok(None) => break,
                Ok(Some(Ok(0))) => {
                    self.ended = true;
                    socket.close();
                }
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(_))) | Err(_) => {
                    socket.abort();
                    return;
                }
            }
        }
    }
}

/// The in-memory device under smoltcp: packets in from the outside, packets out to it.
#[derive(Default)]
struct Wire {
    inbound: VecDeque<Bytes>,
    outbound: VecDeque<Bytes>,
}

impl Device for Wire {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _now: SmolInstant) -> Option<(Rx, Tx<'_>)> {
        let packet = self.inbound.pop_front()?;
        Some((Rx(packet), Tx(&mut self.outbound)))
    }

    fn transmit(&mut self, _now: SmolInstant) -> Option<Tx<'_>> {
        (self.outbound.len() < BACKLOG).then_some(Tx(&mut self.outbound))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = usize::from(MTU);
        caps
    }
}

struct Rx(Bytes);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct Tx<'a>(&'a mut VecDeque<Bytes>);

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push_back(packet.into());
        result
    }
}
