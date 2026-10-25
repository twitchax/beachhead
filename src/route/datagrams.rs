//! Routed UDP and ICMP echo as flows through the relay. The first datagram between an app's address
//! and port and a remote's, or the first echo request between their addresses under an identifier,
//! opens a flow, and it and those after it wait while the relay opens it; after that, each goes
//! straight to the flow. Replies come back as UDP packets from the remote's address, or as echo
//! replies in the app's own family under its identifier, and a flow error as the ICMP unreachable a
//! real network would send, quoting the app's last datagram. The flow table idles flows out and caps
//! them, and a flow that goes resets.
//!
//! An echo flow carries each request's sequence number and payload alone (protocol v4's
//! family-neutral echo): the relay's ping socket may be of either family, and its kernel picks the
//! identifier, so the reply's family and identifier are restored here.
//!
//! Nothing here waits, since it runs on the netstack's thread: a datagram goes to its flow with
//! `try_send`, dropped when the flow's queue is full, and a task per open flow carries the flow's
//! replies into one bounded channel ([`REPLIES`]) that the stack reads only while the device keeps
//! up. Tokio's bounded `send` serves its waiters in turn, so every flow gets its turn there.

use std::{
    future::Future as _,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::Context as _;
use bytes::Bytes;
use smoltcp::wire::{IpProtocol, UdpPacket};
use sshunnel_mux::{
    FlowEvent, OpenError,
    frame::{FlowErrKind, OpenErrKind},
};
use tokio::{
    sync::mpsc,
    task::JoinSet,
    time::{Instant, Sleep},
};
use tracing::debug;

use crate::{
    base::Void,
    flows::{FlowTable, FlowTask, Held},
    route::{
        router::Router,
        stack::{Ip, Refusal, icmp_error, icmp_packet, udp_packet},
    },
    tunnel::{Flow, FlowSender as _, SenderOf, Tunnel},
};

/// What a routed flow is between.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum DatagramKey {
    /// UDP between an app's address and port and a remote's.
    Udp { app: SocketAddr, remote: SocketAddr },
    /// ICMP echo between an app's address and a remote's, under the identifier the app's requests
    /// carry (one per `ping`).
    Echo { app: IpAddr, remote: IpAddr, id: u16 },
}

impl DatagramKey {
    /// What of the app's `packet` the flow carries: a UDP datagram's payload, or an echo request's
    /// sequence number and payload. Shares the packet's buffer.
    fn datagram(self, packet: &Bytes, ip: &Ip) -> Option<Bytes> {
        match self {
            Self::Udp { .. } => ip.udp_payload(packet),
            Self::Echo { .. } => {
                let seq = ip.start + ECHO_SEQ;
                (ip.end >= ip.start + ECHO_HEADER && ip.end <= packet.len()).then(|| packet.slice(seq..ip.end))
            }
        }
    }

    /// The packet the flow's `datagram` becomes for the app.
    fn reply(self, datagram: &[u8]) -> Option<Bytes> {
        match self {
            Self::Udp { app, remote } => udp_packet(remote, app, datagram),
            Self::Echo { app, remote, id } => echo_reply(remote, app, id, datagram),
        }
    }

    /// How the app hears that its flow's open failed `kind` (R5), as it would from the remote's
    /// network; `None` for silence, so the app's own timeout fires.
    fn refusal(self, kind: OpenErrKind) -> Option<Refusal> {
        match (self, kind) {
            (_, OpenErrKind::TimedOut) => None,
            (_, OpenErrKind::Unreachable) => Some(Refusal::Unreachable),
            (Self::Udp { .. }, OpenErrKind::Refused | OpenErrKind::Other) => Some(Refusal::PortUnreachable),
            // The relay can't ping that host's family, or can't open a ping socket at all.
            (Self::Echo { .. }, OpenErrKind::Refused | OpenErrKind::Other) => Some(Refusal::Prohibited),
        }
    }
}

/// The replies on their way from the flows' tasks to the stack.
pub(crate) const REPLIES: usize = 64;

/// What an ICMP error must quote of a datagram past its IP header (RFC 792): all of a UDP header, or
/// of an echo's.
const QUOTED: usize = 8;
/// The most of a datagram an ICMP error about it quotes: an IPv4 header with every option, then
/// [`QUOTED`].
const QUOTE: usize = 60 + QUOTED;

// ICMP's echo request and reply types, then ICMPv6's.
const ECHO_REQUEST: u8 = 8;
const ECHO_REPLY: u8 = 0;
const ECHO_REQUEST6: u8 = 128;
const ECHO_REPLY6: u8 = 129;
/// An echo's header: type, code, checksum, identifier and sequence number.
const ECHO_HEADER: usize = 8;
/// Where an echo's sequence number sits, and the part an echo flow carries starts.
const ECHO_SEQ: usize = 6;

/// A finished open: its flow's key, its entry's generation and the relay's answer.
type Opened<F> = (DatagramKey, u64, Result<F, OpenError>);
/// A flow's event for the stack, under its key and generation; `None` once the flow is over.
type Reply = (DatagramKey, u64, Option<FlowEvent>);

struct Entry<S> {
    /// Tells this entry from earlier ones under its key, so an open or a reply of a flow that went
    /// can't land on a newer one.
    generation: u64,
    /// The app's last datagram, as an ICMP error about the flow quotes it.
    quote: Quote,
    state: State<S>,
}

enum State<S> {
    /// The relay hasn't answered yet. The app's packets wait here whole, so a failed open can
    /// answer each, and the hold's bound counts their headers too.
    Opening { held: Held, _open: FlowTask },
    /// Datagrams go straight to the flow, and a task carries its replies to the stack.
    Open { sender: S, _replies: FlowTask },
}

/// The start of an app's datagram, copied so its buffer can go: the IP header and the 8 bytes after
/// it, which is what an ICMP error must quote (RFC 792, RFC 4443) and all the app's kernel reads to
/// find the socket it is about.
#[derive(Clone, Copy)]
struct Quote {
    bytes: [u8; QUOTE],
    ip: Ip,
}

impl Quote {
    fn new(packet: &[u8], ip: &Ip) -> Option<Self> {
        let ip = Ip { end: ip.start + QUOTED, ..*ip };
        let mut bytes = [0; QUOTE];
        bytes.get_mut(..ip.end)?.copy_from_slice(packet.get(..ip.end)?);
        Some(Self { bytes, ip })
    }

    /// The ICMP error `refusal` about the datagram, from its destination.
    fn icmp(&self, refusal: Refusal) -> Option<Bytes> {
        icmp_error(self.bytes.get(..self.ip.end)?, &self.ip, refusal)
    }
}

/// The routed flows: their table, the opens in flight, and the replies on their way back.
pub(crate) struct Datagrams<T: Tunnel> {
    tunnel: T,
    router: Arc<Router>,
    table: FlowTable<DatagramKey, Entry<SenderOf<T>>>,
    generations: u64,
    opens: JoinSet<Opened<T::Flow>>,
    replies: mpsc::Receiver<Reply>,
    /// What each flow's task sends its replies with.
    reply_to: mpsc::Sender<Reply>,
    /// Fires at the table's earliest deadline.
    timer: Pin<Box<Sleep>>,
}

impl<T: Tunnel> Datagrams<T> {
    pub(crate) fn new(tunnel: T, router: Arc<Router>) -> Self {
        let (reply_to, replies) = mpsc::channel(REPLIES);
        Self {
            tunnel,
            router,
            table: FlowTable::new(),
            generations: 0,
            opens: JoinSet::new(),
            replies,
            reply_to,
            timer: Box::pin(tokio::time::sleep_until(Instant::now())),
        }
    }

    /// Sends an app's UDP `packet` on, as [`Self::send`] does.
    pub(crate) fn udp(&mut self, packet: Bytes, ip: &Ip) -> Option<Bytes> {
        let udp = UdpPacket::new_checked(ip.payload(&packet)).ok()?;
        let key = DatagramKey::Udp {
            app: SocketAddr::new(ip.src, udp.src_port()),
            remote: SocketAddr::new(ip.dst, udp.dst_port()),
        };
        self.send(key, packet, ip)
    }

    /// Sends an app's echo request on, as [`Self::send`] does, unless the relay can ping over neither
    /// family: then it is refused without asking the relay.
    pub(crate) fn echo(&mut self, packet: Bytes, ip: &Ip) -> Option<Bytes> {
        let key = DatagramKey::Echo {
            app: ip.src,
            remote: ip.dst,
            id: echo_id(&packet, ip)?,
        };
        let can = self.tunnel.capabilities();
        if !(can.ping4 || can.ping6) {
            debug!(?key, "the remote can't ping; refusing");
            return icmp_error(&packet, ip, Refusal::Prohibited);
        }
        self.send(key, packet, ip)
    }

    /// Sends an app's `packet` on: to its flow, into the hold of a flow still opening, or opening a
    /// flow for it. Never waits: a full queue or hold drops it. Returns the ICMP error to answer it
    /// with when nothing routes its destination.
    fn send(&mut self, key: DatagramKey, packet: Bytes, ip: &Ip) -> Option<Bytes> {
        let quote = Quote::new(&packet, ip)?;
        let now = Instant::now();
        if let Some(entry) = self.table.get_mut(&key) {
            entry.quote = quote;
            match &mut entry.state {
                State::Opening { held, .. } => held.push(packet),
                State::Open { sender, .. } => {
                    if let Some(datagram) = key.datagram(&packet, ip) {
                        sender.try_send(datagram);
                    }
                }
            }
            // Opening or open, the sender is still sending: a slow open mustn't idle out under it.
            self.table.sent(&key, now);
            return None;
        }
        let Some(host) = self.router.destination(ip.dst) else {
            debug!(?key, "not routed; refusing");
            return icmp_error(&packet, ip, Refusal::Prohibited);
        };
        let generation = self.generations;
        self.generations += 1;
        let tunnel = self.tunnel.clone();
        let open = self.opens.spawn(async move {
            let opened = match key {
                DatagramKey::Udp { remote, .. } => tunnel.open_udp(&host, remote.port()).await,
                DatagramKey::Echo { .. } => tunnel.open_echo(&host).await,
            };
            (key, generation, opened)
        });
        let mut held = Held::default();
        held.push(packet);
        let state = State::Opening { held, _open: FlowTask(open) };
        // The least recently used flow, at the cap: it resets as it drops, and so does its open.
        drop(self.table.insert(key, Entry { generation, quote, state }, now));
        None
    }

    /// Acts on the opens that finished, handing `send` each packet to write.
    ///
    /// # Errors
    ///
    /// Fails when an open's task panicked.
    pub(crate) fn opened(&mut self, cx: &mut Context<'_>, mut send: impl FnMut(Option<Bytes>)) -> Void {
        while let Poll::Ready(Some(opened)) = self.opens.poll_join_next(cx) {
            let (key, generation, opened) = match opened {
                Ok(opened) => opened,
                // Its entry went first, which aborted it.
                Err(e) if e.is_cancelled() => continue,
                Err(e) => return Err(e).context("a flow's open failed"),
            };
            self.open(key, generation, opened, &mut send);
        }
        Ok(())
    }

    /// Sends what a flow's entry holds once it opens and starts carrying its replies, or answers
    /// each held packet the way the open failed (R5), as a connection's dial is answered.
    fn open(&mut self, key: DatagramKey, generation: u64, opened: Result<T::Flow, OpenError>, send: &mut impl FnMut(Option<Bytes>)) {
        // An open whose entry went is aborted with it, but one whose result was already in gets
        // here: its entry evicted in the same pass by a new flow, and the app may have opened
        // another under its key since. The flow drops either way, which resets it.
        let Some(entry) = self.table.get_mut(&key).filter(|entry| entry.generation == generation) else {
            return;
        };
        let State::Opening { held, .. } = &mut entry.state else { return };
        let held = held.take();
        match opened {
            Ok(flow) => {
                let sender = flow.sender();
                for packet in &held {
                    if let Some(datagram) = Ip::parse(packet).and_then(|ip| key.datagram(packet, &ip)) {
                        sender.try_send(datagram);
                    }
                }
                let replies = tokio::spawn(carry(flow, key, generation, self.reply_to.clone()));
                entry.state = State::Open {
                    sender,
                    _replies: FlowTask(replies.abort_handle()),
                };
                self.table.sent(&key, Instant::now());
            }
            Err(e) => {
                debug!(?key, "opening the flow failed: {e}");
                self.table.remove(&key);
                let Some(refusal) = key.refusal(e.kind) else { return };
                for packet in held {
                    send(Ip::parse(&packet).and_then(|ip| icmp_error(&packet, &ip, refusal)));
                }
            }
        }
    }

    /// The packet a waiting reply becomes, if any; `Pending` when none is waiting.
    pub(crate) fn poll_reply(&mut self, cx: &mut Context<'_>) -> Poll<Option<Bytes>> {
        // `self` holds a sender, so the channel never ends.
        let Poll::Ready(Some((key, generation, event))) = self.replies.poll_recv(cx) else {
            return Poll::Pending;
        };
        Poll::Ready(self.reply(key, generation, event))
    }

    fn reply(&mut self, key: DatagramKey, generation: u64, event: Option<FlowEvent>) -> Option<Bytes> {
        // The reply of a flow that has since gone has no one to go to.
        let entry = self.table.get_mut(&key).filter(|entry| entry.generation == generation)?;
        match event {
            Some(FlowEvent::Datagram(datagram)) => {
                self.table.replied(&key, Instant::now());
                key.reply(&datagram)
            }
            Some(FlowEvent::Error(kind)) => entry.quote.icmp(refusal(kind)),
            None => {
                // The relay ended the flow, or the session dropped: the app's next datagram opens a
                // fresh one.
                debug!(?key, "the flow ended");
                self.table.remove(&key);
                None
            }
        }
    }

    /// Drops the flows idle past their deadlines, which resets them, and sets the timer for the
    /// next.
    pub(crate) fn expire(&mut self, cx: &mut Context<'_>) {
        while let Some(deadline) = self.table.deadline() {
            if self.timer.deadline() != deadline {
                self.timer.as_mut().reset(deadline);
            }
            if self.timer.as_mut().poll(cx).is_pending() {
                return;
            }
            // At least up to the deadline that fired, so each turn of this loop on the netstack's
            // thread drops a flow whatever the clock reads.
            let idle = self.table.expire(Instant::now().max(deadline));
            debug!(flows = idle.len(), "idled out");
        }
    }
}

/// Carries `flow`'s events to the stack until the flow is over, then says so.
async fn carry<F: Flow>(mut flow: F, key: DatagramKey, generation: u64, replies: mpsc::Sender<Reply>) {
    loop {
        let event = flow.recv().await;
        let over = event.is_none();
        // Past a failed send, the stack is gone.
        if replies.send((key, generation, event)).await.is_err() || over {
            return;
        }
    }
}

/// The identifier of `packet`'s ICMP echo request (v4 type 8, or v6 type 128; code 0), if it is
/// one.
pub(crate) fn echo_id(packet: &[u8], ip: &Ip) -> Option<u16> {
    let request = match (ip.proto, ip.src) {
        (IpProtocol::Icmp, IpAddr::V4(_)) => ECHO_REQUEST,
        (IpProtocol::Icmpv6, IpAddr::V6(_)) => ECHO_REQUEST6,
        _ => return None,
    };
    match ip.payload(packet) {
        [kind, 0, _, _, a, b, _, _, ..] if *kind == request => Some(u16::from_be_bytes([*a, *b])),
        _ => None,
    }
}

/// An echo reply from `from` to `to` (type 0, or 129 between v6 addresses) under identifier `id`,
/// around an echo flow's `datagram`: a sequence number, then a payload. `None` without the sequence
/// number.
fn echo_reply(from: IpAddr, to: IpAddr, id: u16, datagram: &[u8]) -> Option<Bytes> {
    if datagram.len() < ECHO_HEADER - ECHO_SEQ {
        return None;
    }
    let kind = if to.is_ipv4() { ECHO_REPLY } else { ECHO_REPLY6 };
    icmp_packet(from, to, ECHO_SEQ + datagram.len(), |icmp| {
        icmp[0] = kind;
        icmp[4..ECHO_SEQ].copy_from_slice(&id.to_be_bytes());
        icmp[ECHO_SEQ..].copy_from_slice(datagram);
    })
}

/// The ICMP unreachable a flow error stands for: the one the remote's socket heard.
fn refusal(kind: FlowErrKind) -> Refusal {
    match kind {
        FlowErrKind::PortUnreachable => Refusal::PortUnreachable,
        FlowErrKind::HostUnreachable => Refusal::Unreachable,
        FlowErrKind::NetUnreachable => Refusal::NetUnreachable,
    }
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;

    use super::*;
    use crate::route::{TUN_ADDR, TUN_ADDR6};

    /// The type and code of the ICMP error `kind` becomes for a datagram from `app` to `remote`,
    /// and how many bytes of the datagram it quotes.
    fn icmp_for(app: SocketAddr, remote: SocketAddr, kind: FlowErrKind) -> (u8, u8, usize) {
        let packet = udp_packet(app, remote, &[7; 100]).unwrap();
        let ip = Ip::parse(&packet).unwrap();
        let icmp = Quote::new(&packet, &ip).unwrap().icmp(refusal(kind)).unwrap();
        let reply = Ip::parse(&icmp).unwrap();
        assert_eq!((reply.src, reply.dst), (remote.ip(), app.ip()));
        let body = reply.payload(&icmp);
        (body[0], body[1], body.len() - 8)
    }

    #[test]
    fn flow_errors_become_the_unreachables_a_network_sends() {
        let v4 = |kind| icmp_for(SocketAddr::new(TUN_ADDR.into(), 40_000), "10.99.0.5:53".parse().unwrap(), kind);
        let v6 = |kind| icmp_for(SocketAddr::new(TUN_ADDR6.addr().into(), 40_000), "[fd99::5]:53".parse().unwrap(), kind);

        // Each quotes the IP and UDP headers, not the payload.
        assert_eq!(v4(FlowErrKind::PortUnreachable), (3, 3, 28));
        assert_eq!(v4(FlowErrKind::HostUnreachable), (3, 1, 28));
        assert_eq!(v4(FlowErrKind::NetUnreachable), (3, 0, 28));
        assert_eq!(v6(FlowErrKind::PortUnreachable), (1, 4, 48));
        assert_eq!(v6(FlowErrKind::HostUnreachable), (1, 3, 48));
        assert_eq!(v6(FlowErrKind::NetUnreachable), (1, 0, 48));
    }

    #[test]
    fn only_an_echo_request_has_an_echo_id() {
        let id = |from: &str, to: &str, kind: u8, code: u8| {
            let message = icmp_packet(from.parse().unwrap(), to.parse().unwrap(), ECHO_HEADER + 4, |icmp| {
                (icmp[0], icmp[1]) = (kind, code);
                icmp[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
            })
            .unwrap();
            echo_id(&message, &Ip::parse(&message).unwrap())
        };

        assert_eq!(id("198.18.0.1", "10.99.0.5", ECHO_REQUEST, 0), Some(0x1234));
        assert_eq!(id("fd73:7368::1", "fd99::5", ECHO_REQUEST6, 0), Some(0x1234));
        // Another code, a timestamp request, and an echo request's type in the other family.
        assert_eq!(id("198.18.0.1", "10.99.0.5", ECHO_REQUEST, 1), None);
        assert_eq!(id("198.18.0.1", "10.99.0.5", 13, 0), None);
        assert_eq!(id("fd73:7368::1", "fd99::5", ECHO_REQUEST, 0), None);
    }

    #[test]
    fn an_echo_reply_needs_the_sequence_number() {
        let (remote, app) = ("10.99.0.5".parse().unwrap(), IpAddr::V4(TUN_ADDR));

        assert_eq!(echo_reply(remote, app, 7, &[0]), None);
        let reply = echo_reply(remote, app, 7, &[0, 1]).unwrap();
        let ip = Ip::parse(&reply).unwrap();
        assert_eq!(ip.payload(&reply)[..2], [ECHO_REPLY, 0]);
        assert_eq!(ip.payload(&reply)[4..], [0, 7, 0, 1]);
    }
}
