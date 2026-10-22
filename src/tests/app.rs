//! [`AppStack`]: the app side of the netstack tests. A second smoltcp interface at the device's
//! addresses, on the other end of an in-memory packet pipe, so a test connects, sends UDP and
//! ICMP and pings the way an app on the machine would, and sees every packet the stack sent back.

use std::{
    future::poll_fn,
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicU16, Ordering},
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use smoltcp::{
    iface::SocketHandle,
    phy::ChecksumCapabilities,
    socket::tcp::State,
    wire::{IPV4_HEADER_LEN, IPV6_HEADER_LEN, Icmpv4Packet, Icmpv4Repr, Icmpv6Packet, Icmpv6Repr, IpCidr, IpProtocol, IpRepr, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket},
};
use tokio::{
    io::{DuplexStream, duplex},
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
    time::timeout,
};

use crate::{
    base::Res,
    route::{
        DNS_ADDR, FAKE_RANGE, TUN_ADDR, TUN_ADDR6,
        stack::{Engine, Ip, PIPE, Packets, is_icmp_error, udp_packet},
    },
};

/// How long [`AppStack::connect`] waits for an answer, as an app's own connect timeout would.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the UDP and ICMP probes wait for an answer.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Packets in flight each way between the app and the stack.
const PIPE_PACKETS: usize = 256;
/// The first local port (and ping identifier) handed out.
const FIRST_PORT: u16 = 40_000;
/// Passes per wake before the app's task yields.
const PASSES: usize = 4;

/// How a connect failed, as the app's socket would report it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Connect {
    /// An RST came back (`ECONNREFUSED`).
    Refused,
    /// An ICMP error came back (`EHOSTUNREACH`).
    Unreachable,
    /// Nothing came back within the app's connect timeout; also what a stopped app stack gives.
    TimedOut,
}

/// An established connection from the app: its end of the byte stream.
pub type AppConn = DuplexStream;

/// A packet the stack sent the app, decoded as far as the tests look.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sent {
    /// A TCP segment; `window` is the raw (unscaled) window field.
    Tcp {
        from: SocketAddr,
        to: SocketAddr,
        syn: bool,
        ack: bool,
        rst: bool,
        window: u16,
    },
    Udp {
        from: SocketAddr,
        to: SocketAddr,
        payload: Bytes,
    },
    /// An ICMP error, for either family.
    Icmp(Icmp),
    /// An echo reply (type 0, or 129 between v6 addresses) whose checksum holds.
    Echo {
        from: IpAddr,
        to: IpAddr,
        id: u16,
        seq: u16,
        payload: Bytes,
    },
    /// Anything else: another ICMP message, or a packet that doesn't parse.
    Other,
}

impl Sent {
    /// The ICMP error, if this is one.
    #[must_use]
    pub fn icmp(&self) -> Option<&Icmp> {
        match self {
            Self::Icmp(icmp) => Some(icmp),
            _ => None,
        }
    }

    fn parse(packet: &[u8]) -> Self {
        let Some(ip) = Ip::parse(packet) else { return Self::Other };
        let payload = ip.payload(packet);
        match ip.proto {
            IpProtocol::Tcp => TcpPacket::new_checked(payload).map_or(Self::Other, |tcp| Self::Tcp {
                from: SocketAddr::new(ip.src, tcp.src_port()),
                to: SocketAddr::new(ip.dst, tcp.dst_port()),
                syn: tcp.syn(),
                ack: tcp.ack(),
                rst: tcp.rst(),
                window: tcp.window_len(),
            }),
            IpProtocol::Udp => UdpPacket::new_checked(payload).map_or(Self::Other, |udp| Self::Udp {
                from: SocketAddr::new(ip.src, udp.src_port()),
                to: SocketAddr::new(ip.dst, udp.dst_port()),
                payload: Bytes::copy_from_slice(udp.payload()),
            }),
            IpProtocol::Icmp | IpProtocol::Icmpv6 => match payload {
                [kind, code, _, _, _, _, _, _, quoted @ ..] if is_icmp_error(ip.proto, *kind) => Self::Icmp(Icmp {
                    kind: *kind,
                    code: *code,
                    about: about(quoted),
                }),
                _ => Self::echo_reply(&ip, payload).unwrap_or(Self::Other),
            },
            _ => Self::Other,
        }
    }

    /// The echo reply `icmp` is, parsed as a kernel would: in the IP packet's own family, and only
    /// with a checksum that holds (over the pseudo-header for v6).
    fn echo_reply(ip: &Ip, icmp: &[u8]) -> Option<Self> {
        let caps = ChecksumCapabilities::default();
        let (id, seq, payload) = match (ip.proto, ip.src, ip.dst) {
            (IpProtocol::Icmp, IpAddr::V4(_), IpAddr::V4(_)) => match Icmpv4Repr::parse(&Icmpv4Packet::new_checked(icmp).ok()?, &caps).ok()? {
                Icmpv4Repr::EchoReply { ident, seq_no, data } => (ident, seq_no, data),
                _ => return None,
            },
            (IpProtocol::Icmpv6, IpAddr::V6(src), IpAddr::V6(dst)) => match Icmpv6Repr::parse(&src, &dst, &Icmpv6Packet::new_checked(icmp).ok()?, &caps).ok()? {
                Icmpv6Repr::EchoReply { ident, seq_no, data } => (ident, seq_no, data),
                _ => return None,
            },
            _ => return None,
        };
        Some(Self::Echo {
            from: ip.src,
            to: ip.dst,
            id,
            seq,
            payload: Bytes::copy_from_slice(payload),
        })
    }
}

/// An ICMP error message, for either family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmp {
    pub kind: u8,
    pub code: u8,
    /// The packet it reports on: source, destination (port 0 for a protocol without ports) and
    /// protocol.
    pub about: Option<(SocketAddr, SocketAddr, IpProtocol)>,
}

/// The addressing of a packet an ICMP error quotes. A quote may stop 8 bytes past the IP header
/// (RFC 792), short of the length that header claims, so only the headers are read, as a kernel
/// reads them.
fn about(quoted: &[u8]) -> Option<(SocketAddr, SocketAddr, IpProtocol)> {
    let (src, dst, proto, rest): (IpAddr, IpAddr, IpProtocol, &[u8]) = match quoted.first()? >> 4 {
        4 if quoted.len() >= IPV4_HEADER_LEN => {
            let ip = Ipv4Packet::new_unchecked(quoted);
            (ip.src_addr().into(), ip.dst_addr().into(), ip.next_header(), quoted.get(usize::from(ip.header_len())..)?)
        }
        6 if quoted.len() >= IPV6_HEADER_LEN => {
            let ip = Ipv6Packet::new_unchecked(quoted);
            (ip.src_addr().into(), ip.dst_addr().into(), ip.next_header(), quoted.get(IPV6_HEADER_LEN..)?)
        }
        _ => return None,
    };
    let ports = match (proto, rest) {
        (IpProtocol::Tcp | IpProtocol::Udp, [a, b, c, d, ..]) => (u16::from_be_bytes([*a, *b]), u16::from_be_bytes([*c, *d])),
        _ => (0, 0),
    };
    Some((SocketAddr::new(src, ports.0), SocketAddr::new(dst, ports.1), proto))
}

/// The app's side of a stack under test. Dropping it stops its task, which closes the pipe and
/// so ends the stack.
pub struct AppStack {
    commands: mpsc::UnboundedSender<Command>,
    to_stack: mpsc::Sender<Bytes>,
    tap: watch::Receiver<Vec<Sent>>,
    next_port: AtomicU16,
    task: JoinHandle<()>,
}

impl AppStack {
    /// An app stack and the packets for the stack under test to run on.
    ///
    /// # Errors
    ///
    /// Fails when the interface can't be configured.
    pub fn new() -> Res<(Self, Packets)> {
        let (to_stack, stack_rx) = mpsc::channel(PIPE_PACKETS);
        let (stack_tx, from_stack) = mpsc::channel(PIPE_PACKETS);
        let addrs = [IpCidr::new(TUN_ADDR.into(), FAKE_RANGE.prefix_len()), IpCidr::new(TUN_ADDR6.addr().into(), TUN_ADDR6.prefix_len())];
        // An IP-medium device has no next hop to resolve: the routes only tell smoltcp that every
        // destination is reachable through the pipe.
        let engine = Engine::new(&addrs, &[DNS_ADDR.into(), TUN_ADDR6.addr().into()], to_stack.clone())?;
        let (tap_tx, tap) = watch::channel(Vec::new());
        let (commands, command_rx) = mpsc::unbounded_channel();
        let mut app = App {
            engine,
            from_stack,
            commands: command_rx,
            tap: tap_tx,
            opening: Vec::new(),
        };
        let task = tokio::spawn(async move { poll_fn(|cx| app.poll(cx)).await });
        let stack = Packets { rx: stack_rx, tx: stack_tx };
        Ok((
            Self {
                commands,
                to_stack,
                tap,
                next_port: AtomicU16::new(FIRST_PORT),
                task,
            },
            stack,
        ))
    }

    /// Connects to `to`, returning once the handshake completes or fails.
    ///
    /// # Errors
    ///
    /// How the connect failed.
    pub async fn connect(&self, to: SocketAddr) -> Result<AppConn, Connect> {
        self.connect_from(self.port(), to).await
    }

    /// Connects to `to` from local port `from_port`, as an app reusing a port would.
    ///
    /// # Errors
    ///
    /// How the connect failed.
    pub async fn connect_from(&self, from_port: u16, to: SocketAddr) -> Result<AppConn, Connect> {
        let (reply, answer) = oneshot::channel();
        if self.commands.send(Command { to, from_port, reply }).is_err() {
            return Err(Connect::TimedOut);
        }
        match timeout(CONNECT_TIMEOUT, answer).await {
            Ok(Ok(connected)) => connected,
            Ok(Err(_)) | Err(_) => Err(Connect::TimedOut),
        }
    }

    /// Sends one UDP datagram to `to` and returns the ICMP error the stack answers it with.
    pub async fn udp(&self, to: SocketAddr, payload: &[u8]) -> Option<Icmp> {
        let from = SocketAddr::new(local(to.ip()), self.port());
        self.send(udp_packet(from, to, payload)?).await?;
        self.find(|sent| match sent {
            Sent::Icmp(icmp) if icmp.about == Some((from, to, IpProtocol::Udp)) => Some(icmp.clone()),
            _ => None,
        })
        .await
    }

    /// Sends one echo request to `to` and returns the ICMP error the stack answers it with.
    pub async fn ping(&self, to: IpAddr) -> Option<Icmp> {
        self.send(echo_request(local(to), to, self.port(), 1, b"ping")?).await?;
        self.icmp_error_about(to).await
    }

    /// Sends one echo request to `to` with identifier `id`, sequence number `seq` and `payload`,
    /// and returns the first echo reply from `to` after it (a [`Sent::Echo`]), or `None` when none
    /// comes within five seconds.
    pub async fn echo(&self, to: IpAddr, id: u16, seq: u16, payload: &[u8]) -> Option<Sent> {
        let before = self.tap.borrow().len();
        self.send(echo_request(local(to), to, id, seq, payload)?).await?;
        self.find_after(before, |sent| matches!(sent, Sent::Echo { from, .. } if *from == to).then(|| sent.clone())).await
    }

    /// Sends one ICMP query of type `kind` (code 0, with an identifier, a sequence number and 12
    /// bytes, a timestamp request's shape) to `to`, and returns the ICMP error the stack answers it
    /// with.
    pub async fn icmp_query(&self, to: IpAddr, kind: u8) -> Option<Icmp> {
        self.send(icmp_query(local(to), to, kind)?).await?;
        self.icmp_error_about(to).await
    }

    /// The ICMP error about an ICMP message from the app to `to`.
    async fn icmp_error_about(&self, to: IpAddr) -> Option<Icmp> {
        let proto = if to.is_ipv4() { IpProtocol::Icmp } else { IpProtocol::Icmpv6 };
        let about = Some((SocketAddr::new(local(to), 0), SocketAddr::new(to, 0), proto));
        self.find(|sent| match sent {
            Sent::Icmp(icmp) if icmp.about == about => Some(icmp.clone()),
            _ => None,
        })
        .await
    }

    /// Sends one UDP datagram to `to` and returns the payload of the datagram that answers it.
    pub async fn exchange(&self, to: SocketAddr, payload: &[u8]) -> Option<Bytes> {
        self.exchange_from(self.port(), to, payload).await
    }

    /// Sends one UDP datagram to `to` from local port `from_port`, as an app reusing its socket
    /// would, and returns the payload of the first datagram from `to` to that port after it.
    pub async fn exchange_from(&self, from_port: u16, to: SocketAddr, payload: &[u8]) -> Option<Bytes> {
        let from = SocketAddr::new(local(to.ip()), from_port);
        let before = self.tap.borrow().len();
        self.send(udp_packet(from, to, payload)?).await?;
        self.find_after(before, |sent| match sent {
            Sent::Udp { from: answerer, to: asker, payload } if *answerer == to && *asker == from => Some(payload.clone()),
            _ => None,
        })
        .await
    }

    /// Every packet the stack has sent the app so far, in order.
    #[must_use]
    pub fn tap(&self) -> Vec<Sent> {
        self.tap.borrow().clone()
    }

    fn port(&self) -> u16 {
        self.next_port.fetch_add(1, Ordering::Relaxed)
    }

    /// Hands the stack a raw packet, as though the app's kernel sent it; `None` once the stack
    /// is gone.
    pub async fn send(&self, packet: Bytes) -> Option<()> {
        self.to_stack.send(packet).await.ok()
    }

    /// The first thing `pick` finds on the tap, waiting up to five seconds for it.
    pub async fn find<T>(&self, pick: impl Fn(&Sent) -> Option<T>) -> Option<T> {
        self.find_after(0, pick).await
    }

    /// [`Self::find`], past the first `skip` packets on the tap.
    async fn find_after<T>(&self, skip: usize, pick: impl Fn(&Sent) -> Option<T>) -> Option<T> {
        let mut tap = self.tap.clone();
        let seen = timeout(PROBE_TIMEOUT, tap.wait_for(|seen| seen.iter().skip(skip).any(|sent| pick(sent).is_some()))).await.ok()?.ok()?;
        seen.iter().skip(skip).find_map(&pick)
    }
}

impl Drop for AppStack {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The app's address in `to`'s family.
fn local(to: IpAddr) -> IpAddr {
    if to.is_ipv4() { TUN_ADDR.into() } else { TUN_ADDR6.addr().into() }
}

fn echo_request(from: IpAddr, to: IpAddr, ident: u16, seq_no: u16, data: &[u8]) -> Option<Bytes> {
    let caps = ChecksumCapabilities::default();
    match (from, to) {
        (IpAddr::V4(from), IpAddr::V4(to)) => {
            let icmp = Icmpv4Repr::EchoRequest { ident, seq_no, data };
            let ip = IpRepr::new(from.into(), to.into(), IpProtocol::Icmp, icmp.buffer_len(), 64);
            let mut buf = vec![0; ip.buffer_len()];
            ip.emit(&mut buf[..], &caps);
            icmp.emit(&mut Icmpv4Packet::new_unchecked(&mut buf[ip.header_len()..]), &caps);
            Some(buf.into())
        }
        (IpAddr::V6(from), IpAddr::V6(to)) => {
            let icmp = Icmpv6Repr::EchoRequest { ident, seq_no, data };
            let ip = IpRepr::new(from.into(), to.into(), IpProtocol::Icmpv6, icmp.buffer_len(), 64);
            let mut buf = vec![0; ip.buffer_len()];
            ip.emit(&mut buf[..], &caps);
            icmp.emit(&from, &to, &mut Icmpv6Packet::new_unchecked(&mut buf[ip.header_len()..]), &caps);
            Some(buf.into())
        }
        _ => None,
    }
}

/// An ICMP query of type `kind` from `from` to `to`, in their family's ICMP: code 0, then an
/// identifier, a sequence number and 12 bytes of zeros.
fn icmp_query(from: IpAddr, to: IpAddr, kind: u8) -> Option<Bytes> {
    const LEN: usize = 8 + 12;
    let proto = match (from, to) {
        (IpAddr::V4(_), IpAddr::V4(_)) => IpProtocol::Icmp,
        (IpAddr::V6(_), IpAddr::V6(_)) => IpProtocol::Icmpv6,
        _ => return None,
    };
    let ip = IpRepr::new(from.into(), to.into(), proto, LEN, 64);
    let mut buf = vec![0; ip.buffer_len()];
    ip.emit(&mut buf[..], &ChecksumCapabilities::default());
    let icmp = &mut buf[ip.header_len()..];
    icmp[0] = kind;
    icmp[4..8].copy_from_slice(&[0, 1, 0, 1]);
    match (from, to) {
        (IpAddr::V6(from), IpAddr::V6(to)) => Icmpv6Packet::new_unchecked(icmp).fill_checksum(&from, &to),
        _ => Icmpv4Packet::new_unchecked(icmp).fill_checksum(),
    }
    Some(buf.into())
}

struct Command {
    to: SocketAddr,
    from_port: u16,
    reply: oneshot::Sender<Result<AppConn, Connect>>,
}

/// A connect waiting on its handshake.
struct Opening {
    handle: SocketHandle,
    from_port: u16,
    to: SocketAddr,
    reply: oneshot::Sender<Result<AppConn, Connect>>,
}

/// The app stack's task.
struct App {
    engine: Engine,
    from_stack: mpsc::Receiver<Bytes>,
    commands: mpsc::UnboundedReceiver<Command>,
    tap: watch::Sender<Vec<Sent>>,
    opening: Vec<Opening>,
}

impl App {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        for _ in 0..PASSES {
            loop {
                match self.commands.poll_recv(cx) {
                    Poll::Ready(Some(command)) => self.open(command),
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => break,
                }
            }
            loop {
                match self.from_stack.poll_recv(cx) {
                    Poll::Ready(Some(packet)) => self.receive(packet),
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => break,
                }
            }
            self.engine.poll();
            self.settle();
            self.engine.run_bridges(cx, |_| {});
            self.engine.poll();
            if self.engine.flush(cx).is_err() {
                return Poll::Ready(());
            }
            if !self.engine.wait(cx) {
                return Poll::Pending;
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn open(&mut self, Command { to, from_port, reply }: Command) {
        // A connect that can't start drops `reply`, which the caller reads as a timeout.
        if let Some(handle) = self.engine.connect(to, from_port) {
            self.opening.push(Opening { handle, from_port, to, reply });
        }
    }

    fn receive(&mut self, packet: Bytes) {
        let sent = Sent::parse(&packet);
        match &sent {
            Sent::Tcp { .. } => self.engine.inject(packet),
            // smoltcp's TCP ignores ICMP, so the app reads it here, as the kernel would.
            Sent::Icmp(Icmp {
                about: Some((from, to, IpProtocol::Tcp)), ..
            }) => {
                if let Some(i) = self.opening.iter().position(|o| o.from_port == from.port() && o.to == *to) {
                    let opening = self.opening.swap_remove(i);
                    self.engine.remove(opening.handle);
                    let _ = opening.reply.send(Err(Connect::Unreachable));
                }
            }
            _ => {}
        }
        self.tap.send_modify(|tap| tap.push(sent));
    }

    /// Answers the connects whose handshakes finished (or whose callers gave up).
    fn settle(&mut self) {
        let mut i = 0;
        while i < self.opening.len() {
            let state = self.engine.state(self.opening[i].handle);
            let waiting = matches!(state, State::SynSent | State::SynReceived) && !self.opening[i].reply.is_closed();
            if waiting {
                i += 1;
                continue;
            }
            let opening = self.opening.swap_remove(i);
            match state {
                State::SynSent | State::SynReceived => self.engine.remove(opening.handle),
                State::Closed | State::Listen => {
                    self.engine.remove(opening.handle);
                    let _ = opening.reply.send(Err(Connect::Refused));
                }
                _ => {
                    let (near, far) = duplex(PIPE);
                    self.engine.bridge(opening.handle, near, None);
                    let _ = opening.reply.send(Ok(far));
                }
            }
        }
    }
}
