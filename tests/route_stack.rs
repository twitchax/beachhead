//! The netstack against a second smoltcp interface standing in for the app (`AppStack`), over an
//! in-memory packet pipe, with a scripted tunnel (`FakeTunnel`). Every test is a top-level function,
//! so the PRD's `test(/^held_syn/)` filter sees the bare names.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use pretty_assertions::assert_eq;
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{Icmpv4DstUnreachable, Icmpv4Packet, Icmpv4Repr, IpProtocol, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr},
};
use sshunnel::{
    flows::MAX_FLOWS,
    route::{
        DNS_ADDR, TUN_ADDR,
        names::{FakeMap, today},
        router::Router,
        stack::{self, Dns, MAX_HELD, MAX_QUERIES, Packets},
        targets::Targets,
    },
    tests::{AppStack, Connect, FakeTunnel, Icmp, Sent, echo_server, pattern, udp_echo_server, udp_stale_server, until},
};
use sshunnel_mux::{FlowKind, frame::OpenErrKind};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    sync::{mpsc, watch},
    time::timeout,
};

/// Answers nothing, for the tests that don't look at DNS.
struct NoDns;

impl Dns for NoDns {
    fn answer(&self, _query: Bytes) -> impl Future<Output = Option<Bytes>> + Send {
        std::future::ready(None)
    }
}

/// Answers every query with the same bytes and records the queries.
struct FixedDns {
    answer: Bytes,
    asked: Arc<Mutex<Vec<Bytes>>>,
}

impl Dns for FixedDns {
    fn answer(&self, query: Bytes) -> impl Future<Output = Option<Bytes>> + Send {
        self.asked.lock().unwrap().push(query);
        std::future::ready(Some(self.answer.clone()))
    }
}

/// Holds every query until released, counting them, then echoes each back as its answer.
struct GatedDns {
    asked: watch::Sender<usize>,
    release: watch::Receiver<bool>,
}

impl Dns for GatedDns {
    async fn answer(&self, query: Bytes) -> Option<Bytes> {
        self.asked.send_modify(|asked| *asked += 1);
        self.release.clone().wait_for(|open| *open).await.ok()?;
        Some(query)
    }
}

/// An app, the stack between it and a fake tunnel, and the router the stack consults.
struct Rig {
    app: AppStack,
    tunnel: FakeTunnel,
    router: Arc<Router>,
    _state: TempDir,
}

fn rig(targets: &[&str]) -> Rig {
    rig_with(targets, NoDns)
}

/// A router for `targets`, with its fake-address map in the returned dir.
fn router(targets: &[&str]) -> (Arc<Router>, TempDir) {
    let state = TempDir::new().unwrap();
    let names = FakeMap::load(state.path().join("names"), today()).unwrap();
    let targets: Vec<String> = targets.iter().map(|t| (*t).to_owned()).collect();
    (Arc::new(Router::new(Targets::parse(&targets, &[]).unwrap(), names)), state)
}

fn rig_with(targets: &[&str], dns: impl Dns) -> Rig {
    let (router, state) = router(targets);
    let tunnel = FakeTunnel::new();
    let (app, packets) = AppStack::new().unwrap();
    tokio::spawn(stack::run(packets, tunnel.clone(), Arc::clone(&router), Arc::new(dns)));
    Rig { app, tunnel, router, _state: state }
}

fn at(ip: &str, port: u16) -> SocketAddr {
    SocketAddr::new(ip.parse().unwrap(), port)
}

/// Waits for the stack to send the app an RST from `from`.
async fn reset_from(app: &AppStack, from: SocketAddr) -> bool {
    app.find(|sent| matches!(sent, Sent::Tcp { from: f, rst: true, .. } if *f == from).then_some(())).await.is_some()
}

/// Waits for the stack to advertise a zero window from `from`: it has stopped taking bytes on
/// that connection.
async fn window_closed_from(app: &AppStack, from: SocketAddr) -> bool {
    app.find(|sent| matches!(sent, Sent::Tcp { from: f, ack: true, rst: false, window: 0, .. } if *f == from).then_some(()))
        .await
        .is_some()
}

/// An ICMP port unreachable from the app to `10.99.0.5`, about a datagram from it.
fn port_unreachable() -> Bytes {
    let caps = ChecksumCapabilities::default();
    let remote = Ipv4Addr::new(10, 99, 0, 5);
    let quoted = Ipv4Repr {
        src_addr: remote,
        dst_addr: TUN_ADDR,
        next_header: IpProtocol::Udp,
        payload_len: 8,
        hop_limit: 64,
    };
    let icmp = Icmpv4Repr::DstUnreachable {
        reason: Icmpv4DstUnreachable::PortUnreachable,
        header: quoted,
        data: &[0; 8],
    };
    let ip = Ipv4Repr {
        src_addr: TUN_ADDR,
        dst_addr: remote,
        next_header: IpProtocol::Icmp,
        payload_len: icmp.buffer_len(),
        hop_limit: 64,
    };
    let mut buf = vec![0; ip.buffer_len() + icmp.buffer_len()];
    ip.emit(&mut Ipv4Packet::new_unchecked(&mut buf[..]), &caps);
    icmp.emit(&mut Icmpv4Packet::new_unchecked(&mut buf[ip.buffer_len()..]), &caps);
    buf.into()
}

/// A UDP datagram from the device's address and `port` to `10.99.0.5:9999`.
fn datagram(port: u16) -> Bytes {
    datagram_to(port, 9999)
}

/// A UDP datagram from the device's address and `port` to `10.99.0.5:to_port`.
fn datagram_to(port: u16, to_port: u16) -> Bytes {
    let caps = ChecksumCapabilities::default();
    let (from, to) = (TUN_ADDR, Ipv4Addr::new(10, 99, 0, 5));
    let payload = b"hello";
    let udp = UdpRepr { src_port: port, dst_port: to_port };
    let ip = Ipv4Repr {
        src_addr: from,
        dst_addr: to,
        next_header: IpProtocol::Udp,
        payload_len: 8 + payload.len(),
        hop_limit: 64,
    };
    let mut buf = vec![0; ip.buffer_len() + ip.payload_len];
    ip.emit(&mut Ipv4Packet::new_unchecked(&mut buf[..]), &caps);
    let datagram = &mut UdpPacket::new_unchecked(&mut buf[ip.buffer_len()..]);
    udp.emit(datagram, &from.into(), &to.into(), payload.len(), |space| space.copy_from_slice(payload), &caps);
    buf.into()
}

fn saw_syn_ack(app: &AppStack) -> bool {
    app.tap().iter().any(|p| matches!(p, Sent::Tcp { syn: true, ack: true, .. }))
}

/// Connects to `to` and echoes `len` bytes of a pattern through it, both directions at once.
async fn assert_echoes(app: &AppStack, to: SocketAddr, len: usize) {
    let conn = app.connect(to).await.unwrap();
    let (mut r, mut w) = tokio::io::split(conn);
    let data = pattern(len as u64, len);
    let sent = data.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&sent).await.unwrap();
        w.shutdown().await.unwrap();
    });
    let mut back = Vec::with_capacity(len);
    timeout(Duration::from_secs(60), r.read_to_end(&mut back)).await.expect("the echo finishes").unwrap();
    writer.await.unwrap();
    assert!(back == data, "echo differs: {} of {} bytes back", back.len(), data.len());
}

#[tokio::test(start_paused = true)]
async fn held_syn_completes_only_after_the_relay_dials() {
    let rig = rig(&["10.99.0.0/16"]);
    let gate = rig.tunnel.gate("10.99.0.5", 80);

    let app = Arc::new(rig.app);
    let connecting = tokio::spawn({
        let app = Arc::clone(&app);
        async move { app.connect(at("10.99.0.5", 80)).await.map(drop) }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(rig.tunnel.opens(), [("10.99.0.5".to_owned(), 80)]);
    assert!(!saw_syn_ack(&app), "the stack answered before the relay dialed");
    assert!(!connecting.is_finished());

    // Past the app's first SYN retransmit (1 s): dropped while the dial runs, not dialed again.
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert_eq!(rig.tunnel.opens(), [("10.99.0.5".to_owned(), 80)]);
    assert!(!saw_syn_ack(&app));

    gate.open();
    assert_eq!(connecting.await.unwrap(), Ok(()));
    assert!(saw_syn_ack(&app));
}

#[tokio::test]
async fn held_syn_refused_dial_is_a_reset() {
    let rig = rig(&["10.99.0.0/16"]);
    rig.tunnel.reject("10.99.0.5", 80, OpenErrKind::Refused);

    assert_eq!(rig.app.connect(at("10.99.0.5", 80)).await.err(), Some(Connect::Refused));
    assert!(rig.app.tap().iter().any(|p| matches!(p, Sent::Tcp { rst: true, .. })));
}

#[tokio::test]
async fn held_syn_unreachable_dial_is_icmp_host_unreachable() {
    let rig = rig(&["10.99.0.0/16", "fd99::/64"]);
    rig.tunnel.reject("10.99.0.5", 80, OpenErrKind::Unreachable);
    rig.tunnel.reject("fd99::5", 80, OpenErrKind::Unreachable);

    assert_eq!(rig.app.connect(at("10.99.0.5", 80)).await.err(), Some(Connect::Unreachable));
    assert_eq!(rig.app.connect(at("fd99::5", 80)).await.err(), Some(Connect::Unreachable));

    let icmp: Vec<(u8, u8)> = rig.app.tap().iter().filter_map(Sent::icmp).map(|i| (i.kind, i.code)).collect();
    // IPv4 host unreachable, then ICMPv6 address unreachable (Linux's EHOSTUNREACH for both).
    assert_eq!(icmp, [(3, 1), (1, 3)]);
}

#[tokio::test(start_paused = true)]
async fn held_syn_timed_out_dial_is_silent() {
    let rig = rig(&["10.99.0.0/16"]);
    rig.tunnel.reject("10.99.0.5", 80, OpenErrKind::TimedOut);

    assert_eq!(rig.app.connect(at("10.99.0.5", 80)).await.err(), Some(Connect::TimedOut));
    assert_eq!(rig.tunnel.opens().first(), Some(&("10.99.0.5".to_owned(), 80)));
    let answered = rig.app.tap().into_iter().filter(|p| matches!(p, Sent::Tcp { rst: true, .. } | Sent::Icmp(_))).collect::<Vec<_>>();
    assert_eq!(answered, []);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cidr_connection_carries_bytes_both_ways() {
    let rig = rig(&["10.99.0.0/16", "fd99::/64"]);
    let echo = echo_server().await.unwrap();
    rig.tunnel.dial("10.99.0.5", 80, echo);
    rig.tunnel.dial("fd99::5", 80, echo);

    assert_echoes(&rig.app, at("10.99.0.5", 80), 1024 * 1024).await;
    assert_echoes(&rig.app, at("fd99::5", 80), 1024 * 1024).await;
    assert_eq!(rig.tunnel.opens(), [("10.99.0.5".to_owned(), 80), ("fd99::5".to_owned(), 80)]);
}

#[tokio::test]
async fn a_fake_address_opens_by_name() {
    let rig = rig(&["*.corp.example"]);
    let echo = echo_server().await.unwrap();
    rig.tunnel.dial("wiki.corp.example", 443, echo);
    let fake = rig.router.names().address("wiki.corp.example", today());

    assert_echoes(&rig.app, SocketAddr::new(fake.into(), 443), 4096).await;
    assert_eq!(rig.tunnel.opens(), [("wiki.corp.example".to_owned(), 443)]);
}

#[tokio::test]
async fn tcp_that_is_not_routed_is_reset() {
    let rig = rig(&["10.99.0.0/16", "*.corp.example"]);
    let unmatched = rig.router.names().address("wiki.other.example", today());
    let unassigned = Ipv4Addr::new(198, 18, 200, 7);
    assert_eq!(rig.router.names().name(unassigned), None);

    for to in [
        SocketAddr::new(DNS_ADDR.into(), 80),
        SocketAddr::new(TUN_ADDR.into(), 22),
        SocketAddr::new(unassigned.into(), 80),
        SocketAddr::new(unmatched.into(), 80),
    ] {
        let refused = timeout(Duration::from_secs(5), rig.app.connect(to)).await.expect("an immediate answer");
        assert_eq!(refused.err(), Some(Connect::Refused), "{to}");
    }
    assert_eq!(rig.tunnel.opens(), []);
}

fn udp_flow(host: &str, port: u16) -> (FlowKind, String, u16) {
    (FlowKind::Udp, host.to_owned(), port)
}

/// The payloads of the datagrams the stack has sent the app's `port`, in order.
fn udp_to(app: &AppStack, port: u16) -> Vec<Bytes> {
    let to_port = |sent: Sent| match sent {
        Sent::Udp { to, payload, .. } if to.port() == port => Some(payload),
        _ => None,
    };
    app.tap().into_iter().filter_map(to_port).collect()
}

/// The ICMP error (type and code) the stack answers one datagram to `to` with.
async fn udp_refusal(app: &AppStack, to: SocketAddr) -> Option<(u8, u8)> {
    app.udp(to, b"hello").await.map(|i: Icmp| (i.kind, i.code))
}

#[tokio::test]
async fn udp_to_a_routed_address_round_trips_through_a_flow() {
    let rig = rig(&["10.99.0.0/16", "fd99::/64"]);
    let echo = udp_echo_server().await.unwrap();
    rig.tunnel.udp("10.99.0.5", 9999, echo);
    rig.tunnel.udp("fd99::5", 9999, echo);

    let v4 = rig.app.exchange(at("10.99.0.5", 9999), b"hello over v4").await;
    let v6 = rig.app.exchange(at("fd99::5", 9999), b"hello over v6").await;

    assert_eq!(v4.as_deref(), Some(&b"hello over v4"[..]));
    assert_eq!(v6.as_deref(), Some(&b"hello over v6"[..]));
    assert_eq!(rig.tunnel.flows(), [udp_flow("10.99.0.5", 9999), udp_flow("fd99::5", 9999)]);
}

#[tokio::test]
async fn udp_to_an_unrouted_address_is_admin_prohibited() {
    let rig = rig(&["10.99.0.0/16"]);

    assert_eq!(udp_refusal(&rig.app, at("192.0.2.1", 9999)).await, Some((3, 13)));
    assert_eq!(rig.tunnel.flows(), []);
}

#[tokio::test]
async fn udp_to_a_fake_address_opens_a_flow_by_name() {
    let rig = rig(&["*.corp.example"]);
    rig.tunnel.udp("wiki.corp.example", 5353, udp_echo_server().await.unwrap());
    let fake = rig.router.names().address("wiki.corp.example", today());

    let answer = rig.app.exchange(SocketAddr::new(fake.into(), 5353), b"by name").await;

    assert_eq!(answer.as_deref(), Some(&b"by name"[..]));
    assert_eq!(rig.tunnel.flows(), [udp_flow("wiki.corp.example", 5353)]);
}

#[tokio::test(start_paused = true)]
async fn udp_before_the_open_is_held_and_sent_after() {
    let rig = rig(&["10.99.0.0/16"]);
    let gate = rig.tunnel.udp_gate("10.99.0.5", 9999, udp_echo_server().await.unwrap());
    let to = at("10.99.0.5", 9999);

    let app = Arc::new(rig.app);
    let exchanges: Vec<_> = ["one", "two", "three"]
        .into_iter()
        .map(|payload| {
            let app = Arc::clone(&app);
            tokio::spawn(async move { app.exchange_from(41_000, to, payload.as_bytes()).await })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(200)).await;
    // One open for all three, and nothing back while it runs.
    assert_eq!(rig.tunnel.flows(), [udp_flow("10.99.0.5", 9999)]);
    assert_eq!(udp_to(&app, 41_000), Vec::<Bytes>::new());

    gate.open();
    for exchange in exchanges {
        assert!(exchange.await.unwrap().is_some());
    }
    assert_eq!(udp_to(&app, 41_000), ["one", "two", "three"]);
}

#[tokio::test]
async fn a_refused_udp_open_is_port_unreachable() {
    let rig = rig(&["10.99.0.0/16", "fd99::/64"]);
    rig.tunnel.udp_reject("10.99.0.5", 9999, OpenErrKind::Refused);
    rig.tunnel.udp_reject("fd99::5", 9999, OpenErrKind::Refused);

    // Port unreachable in each family, which a connected socket reads as ECONNREFUSED; an open
    // that fails any other way (here, one nothing is scripted for) reads the same.
    assert_eq!(udp_refusal(&rig.app, at("10.99.0.5", 9999)).await, Some((3, 3)));
    assert_eq!(udp_refusal(&rig.app, at("fd99::5", 9999)).await, Some((1, 4)));
    assert_eq!(udp_refusal(&rig.app, at("10.99.0.6", 9999)).await, Some((3, 3)));
}

#[tokio::test]
async fn an_unreachable_udp_open_is_host_unreachable() {
    let rig = rig(&["10.99.0.0/16", "fd99::/64"]);
    rig.tunnel.udp_reject("10.99.0.5", 9999, OpenErrKind::Unreachable);
    rig.tunnel.udp_reject("fd99::5", 9999, OpenErrKind::Unreachable);

    assert_eq!(udp_refusal(&rig.app, at("10.99.0.5", 9999)).await, Some((3, 1)));
    assert_eq!(udp_refusal(&rig.app, at("fd99::5", 9999)).await, Some((1, 3)));
}

#[tokio::test(start_paused = true)]
async fn a_timed_out_udp_open_is_silent() {
    let rig = rig(&["10.99.0.0/16"]);
    rig.tunnel.udp_reject("10.99.0.5", 9999, OpenErrKind::TimedOut);

    assert_eq!(udp_refusal(&rig.app, at("10.99.0.5", 9999)).await, None);
    assert_eq!(rig.tunnel.flows(), [udp_flow("10.99.0.5", 9999)]);
    assert_eq!(rig.app.tap(), []);
}

#[tokio::test]
async fn a_udp_flow_error_is_icmp_quoting_the_last_datagram() {
    let rig = rig(&["10.99.0.0/16", "fd99::/64"]);
    // Nothing listens there, so the flow's socket hears port unreachable, as the relay's would.
    let closed = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    rig.tunnel.udp("10.99.0.5", 9999, closed);
    rig.tunnel.udp("fd99::5", 9999, closed);

    for (to, unreachable) in [(at("10.99.0.5", 9999), (3, 3)), (at("fd99::5", 9999), (1, 4))] {
        let icmp = rig.app.udp(to, b"anyone there?").await.expect("an ICMP error");
        assert_eq!((icmp.kind, icmp.code), unreachable, "{to}");
        let (app, remote, proto) = icmp.about.unwrap();
        assert_eq!((app.ip().is_ipv4(), remote, proto), (to.is_ipv4(), to, IpProtocol::Udp));
    }
}

#[tokio::test(start_paused = true)]
async fn a_udp_flow_idles_out_and_resets_its_relay_flow() {
    let rig = rig(&["10.99.0.0/16"]);
    // Bound and never read, so nothing answers and nothing refuses.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    rig.tunnel.udp("10.99.0.5", 9999, silent.local_addr().unwrap());

    rig.app.send(datagram(41_000)).await.unwrap();
    until(|| rig.tunnel.live_flows() == 1).await.unwrap();
    tokio::time::sleep(Duration::from_secs(29)).await;
    assert_eq!(rig.tunnel.live_flows(), 1);

    // Past 30 s with no reply: the flow goes, and dropping it resets the relay's end.
    tokio::time::sleep(Duration::from_secs(2)).await;
    until(|| rig.tunnel.live_flows() == 0).await.unwrap();
}

#[tokio::test]
async fn a_udp_flow_the_relay_ends_opens_afresh() {
    let rig = rig(&["10.99.0.0/16"]);
    rig.tunnel.udp_hangup("10.99.0.5", 9999);

    rig.app.send(datagram(41_000)).await.unwrap();
    until(|| rig.tunnel.flows().len() == 1 && rig.tunnel.live_flows() == 0).await.unwrap();
    // Its entry went with it, so the app's next datagram opens a fresh flow rather than feeding the
    // dead one.
    rig.app.send(datagram(41_000)).await.unwrap();
    until(|| rig.tunnel.flows().len() == 2).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn udp_an_open_whose_flow_idled_out_is_cancelled() {
    let rig = rig(&["10.99.0.0/16"]);
    let gate = rig.tunnel.udp_gate("10.99.0.5", 9999, udp_echo_server().await.unwrap());

    rig.app.send(datagram(41_000)).await.unwrap();
    until(|| rig.tunnel.flows().len() == 1).await.unwrap();
    // Its entry idles out while the open waits, and takes the open with it.
    tokio::time::sleep(Duration::from_secs(31)).await;

    // So it never finishes, though its gate opens; the app socket's next datagram opens afresh.
    gate.open();
    let back = rig.app.exchange_from(41_000, at("10.99.0.5", 9999), b"two").await;
    assert_eq!(back.as_deref(), Some(&b"two"[..]));
    assert_eq!((rig.tunnel.flows().len(), rig.tunnel.flows_opened(), rig.tunnel.live_flows()), (2, 1, 1));
}

/// Review Focus 1: an open whose result is in before its entry goes is past aborting, so only the
/// entry's generation keeps it off the flow the app opened under the same key since.
#[tokio::test(start_paused = true)]
async fn udp_an_open_finished_before_its_flow_was_evicted_is_dropped() {
    let rig = rig(&["10.99.0.0/16"]);
    let to = at("10.99.0.5", 9999);
    let first = rig.tunnel.udp_gate("10.99.0.5", 9999, udp_stale_server().await.unwrap());
    // Flows up to the cap whose opens never finish, the first one the least recently used.
    let _never = rig.tunnel.udp_gate("10.99.0.5", 7, to);
    rig.app.send(datagram(41_000)).await.unwrap();
    for port in 1..u16::try_from(MAX_FLOWS).unwrap() {
        rig.app.send(datagram_to(port, 7)).await.unwrap();
    }
    until(|| rig.tunnel.flows().len() == MAX_FLOWS).await.unwrap();
    rig.tunnel.udp("10.99.0.5", 9999, udp_echo_server().await.unwrap());

    // The first open's task runs before the stack's next pass, which reads a new flow (evicting
    // the first) and the app socket's next datagram (a fresh entry under its key) before it takes
    // the open's result.
    first.open();
    rig.app.send(datagram_to(5_000, 7)).await.unwrap();
    let back = rig.app.exchange_from(41_000, to, b"two").await;

    assert_eq!(back.as_deref(), Some(&b"two"[..]));
    assert_eq!(rig.tunnel.live_flows(), 1);
}

#[tokio::test]
async fn icmp_to_a_routed_address_is_admin_prohibited() {
    let rig = rig(&["10.99.0.0/16", "fd99::/64"]);

    let v4 = rig.app.ping("10.99.0.5".parse().unwrap()).await.map(|i| (i.kind, i.code));
    let v6 = rig.app.ping("fd99::5".parse().unwrap()).await.map(|i| (i.kind, i.code));

    assert_eq!(v4, Some((3, 13)));
    assert_eq!(v6, Some((1, 1)));
}

#[tokio::test]
async fn dns_queries_reach_the_dns_server() {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let dns = FixedDns {
        answer: Bytes::from_static(b"a fixed answer"),
        asked: Arc::clone(&asked),
    };
    let rig = rig_with(&["*.corp.example"], dns);

    let answer = rig.app.exchange(SocketAddr::new(DNS_ADDR.into(), 53), b"a query").await;

    assert_eq!(answer.as_deref(), Some(&b"a fixed answer"[..]));
    assert_eq!(*asked.lock().unwrap(), [Bytes::from_static(b"a query")]);
    // Only port 53 is the DNS server.
    let elsewhere = rig.app.udp(SocketAddr::new(DNS_ADDR.into(), 5353), b"a query").await.map(|i| (i.kind, i.code));
    assert_eq!(elsewhere, Some((3, 13)));
}

#[tokio::test(start_paused = true)]
async fn dns_queries_beyond_the_cap_are_dropped() {
    const FLOOD: usize = 300;
    let (asked, mut counted) = watch::channel(0);
    let (open, release) = watch::channel(false);
    let rig = rig_with(&["*.corp.example"], GatedDns { asked, release });
    let dns = SocketAddr::new(DNS_ADDR.into(), 53);

    let app = Arc::new(rig.app);
    let flood: Vec<_> = (0..FLOOD)
        .map(|i| {
            let app = Arc::clone(&app);
            tokio::spawn(async move { app.exchange(dns, format!("query {i}").as_bytes()).await })
        })
        .collect();
    counted.wait_for(|asked| *asked >= MAX_QUERIES).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(*counted.borrow(), MAX_QUERIES);

    open.send_replace(true);
    let mut answered = 0;
    for exchange in flood {
        answered += usize::from(exchange.await.unwrap().is_some());
    }
    assert_eq!(answered, MAX_QUERIES);
}

#[tokio::test(start_paused = true)]
async fn multicast_broadcast_and_icmp_errors_get_no_answer() {
    let rig = rig(&["10.99.0.0/16", "fd99::/64"]);

    // What a kernel sends on any link: LLMNR, broadcasts, router solicitations.
    assert_eq!(rig.app.udp(at("224.0.0.252", 5355), b"llmnr").await, None);
    assert_eq!(rig.app.udp(at("255.255.255.255", 9), b"hello").await, None);
    assert_eq!(rig.app.udp(at("198.19.255.255", 9), b"hello").await, None);
    assert_eq!(rig.app.ping("ff02::2".parse().unwrap()).await, None);
    // Never an ICMP error about an ICMP error.
    rig.app.send(port_unreachable()).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;

    assert_eq!(rig.app.tap(), []);
}

#[tokio::test(start_paused = true)]
async fn a_port_reused_during_time_wait_connects_at_once() {
    let rig = rig(&["10.99.0.0/16"]);
    rig.tunnel.hangup("10.99.0.5", 80);
    let to = at("10.99.0.5", 80);

    // The remote end closes first, so the stack's end of the connection lingers in TIME-WAIT.
    let mut first = rig.app.connect_from(41_000, to).await.unwrap();
    assert_eq!(first.read(&mut [0; 1]).await.unwrap(), 0);
    drop(first);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let started = tokio::time::Instant::now();
    rig.app.connect_from(41_000, to).await.unwrap();
    assert!(started.elapsed() < Duration::from_millis(500), "took {:?}", started.elapsed());
    assert_eq!(rig.tunnel.opens().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn the_stack_reads_on_after_a_device_backlog() {
    const N: u16 = 200;
    // Nothing routes the datagrams' destination, so the stack answers each as it reads it.
    let (router, _state) = router(&["fd99::/64"]);
    // A device that takes fewer packets at a time than the stack queues for it, in bursts.
    let (to_stack, rx) = mpsc::channel(1024);
    let (tx, mut from_stack) = mpsc::channel(64);
    tokio::spawn(stack::run(Packets { rx, tx }, FakeTunnel::new(), router, Arc::new(NoDns)));

    for port in 0..N {
        to_stack.send(datagram(40_000 + port)).await.unwrap();
    }
    let mut answered = 0;
    loop {
        // Let the stack run until it waits on the device, then take everything it wrote.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut burst = 0;
        while from_stack.try_recv().is_ok() {
            burst += 1;
        }
        if burst == 0 {
            break;
        }
        answered += burst;
    }
    assert_eq!(answered, N, "the stack stopped reading its device");

    to_stack.send(datagram(50_000)).await.unwrap();
    assert!(timeout(Duration::from_secs(5), from_stack.recv()).await.is_ok(), "a later packet went unread");
}

#[tokio::test(start_paused = true)]
async fn a_late_failure_on_a_reused_port_leaves_the_new_connection_alone() {
    let rig = rig(&["10.99.0.0/16"]);
    let fail = rig.tunnel.fail_late("10.99.0.5", 80);
    let to = at("10.99.0.5", 80);

    // Both ends close the first connection, leaving the stack's end in TIME-WAIT and its relay
    // stream yet to fail.
    let mut first = rig.app.connect_from(41_000, to).await.unwrap();
    assert_eq!(first.read(&mut [0; 1]).await.unwrap(), 0);
    drop(first);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The port's next connection takes over the 4-tuple; then the first one's stream fails.
    let _second = rig.app.connect_from(41_000, to).await.unwrap();
    let before = rig.app.tap().len();
    fail.open();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let after = rig.app.tap().split_off(before);
    assert!(!after.iter().any(|p| matches!(p, Sent::Tcp { rst: true, .. })), "the new connection was reset: {after:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reset_from_the_remote_resets_the_app() {
    let rig = rig(&["10.99.0.0/16"]);
    let resetter = TcpListener::bind("127.0.0.1:0").await.unwrap();
    rig.tunnel.dial("10.99.0.5", 80, resetter.local_addr().unwrap());
    tokio::spawn(async move {
        let (mut socket, _) = resetter.accept().await.unwrap();
        let _ = socket.read_u8().await;
        socket.set_zero_linger().unwrap();
    });

    let mut conn = rig.app.connect(at("10.99.0.5", 80)).await.unwrap();
    conn.write_all(b"x").await.unwrap();

    assert!(reset_from(&rig.app, at("10.99.0.5", 80)).await, "no RST reached the app");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_connection_stalls_only_itself() {
    let rig = rig(&["10.99.0.0/16"]);
    let echo = echo_server().await.unwrap();
    rig.tunnel.stall("10.99.0.6", 80);
    rig.tunnel.dial("10.99.0.5", 80, echo);

    let mut stalled = rig.app.connect(at("10.99.0.6", 80)).await.unwrap();
    let writer = tokio::spawn(async move { stalled.write_all(&pattern(1, 8 * 1024 * 1024)).await });
    // Its relay stream isn't reading, so its pipe fills and then its window closes.
    assert!(window_closed_from(&rig.app, at("10.99.0.6", 80)).await, "the window never closed");

    assert_echoes(&rig.app, at("10.99.0.5", 80), 1024 * 1024).await;
    assert!(!writer.is_finished(), "the stalled connection moved");
}

#[tokio::test(start_paused = true)]
async fn held_syns_beyond_the_cap_are_dropped() {
    const STORM: usize = 300;
    let rig = rig(&["10.99.0.0/16"]);
    let gate = rig.tunnel.gate("10.99.0.5", 80);

    let app = Arc::new(rig.app);
    let storm: Vec<_> = (0..STORM)
        .map(|_| {
            let app = Arc::clone(&app);
            tokio::spawn(async move { app.connect(at("10.99.0.5", 80)).await.map(drop) })
        })
        .collect();
    rig.tunnel.wait_for_opens(MAX_HELD).await;
    // Well inside the app's first SYN retransmit (1 s), so every SYN has been seen exactly once.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(rig.tunnel.opens().len(), MAX_HELD);

    // The held ones complete; the dropped ones retransmit and complete behind them.
    gate.open();
    for connecting in storm {
        assert_eq!(connecting.await.unwrap(), Ok(()));
    }
    assert_eq!(rig.tunnel.opens().len(), STORM);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "a throughput probe, run by hand with --release"]
async fn stack_throughput_in_memory() {
    const LEN: usize = 256 * 1024 * 1024;
    let rig = rig(&["10.99.0.0/16"]);
    let echo = echo_server().await.unwrap();
    rig.tunnel.dial("10.99.0.5", 80, echo);

    let conn = rig.app.connect(at("10.99.0.5", 80)).await.unwrap();
    let (mut r, mut w) = tokio::io::split(conn);
    let chunk = pattern(7, 1024 * 1024);
    let started = tokio::time::Instant::now();
    let writer = tokio::spawn(async move {
        for _ in 0..LEN / chunk.len() {
            w.write_all(&chunk).await.unwrap();
        }
        w.shutdown().await.unwrap();
    });
    let mut buf = vec![0; 1024 * 1024];
    let mut received = 0;
    loop {
        let n = r.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        received += n;
    }
    writer.await.unwrap();
    let elapsed = started.elapsed();

    assert_eq!(received, LEN);
    let rate = f64::from(u32::try_from(LEN / (1024 * 1024)).unwrap()) / elapsed.as_secs_f64();
    println!("stack_throughput_in_memory: 256 MiB echoed in {elapsed:?}, {rate:.0} MiB/s each way");
}
