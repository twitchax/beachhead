//! The DNS server against a scripted tunnel (`FakeTunnel`) and local UDP and TCP stubs standing in
//! for the normal upstream. Every test is a top-level function, so the PRD's filters see the bare
//! names.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use pretty_assertions::assert_eq;
use simple_dns::{
    CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, RCODE, ResourceRecord, TYPE,
    rdata::{A, AAAA, HTTPS, MX, NS, PTR, RData, SOA, SRV, SVCB, TXT},
};
use sshunnel::{
    route::{
        FAKE_RANGE6,
        dns::{QUERY_TIMEOUT, Server, TCP_IDLE, TTL, serve_tcp},
        names::{self, FakeMap, today},
        reverse,
        router::Router,
        stack::Dns,
        targets::Targets,
    },
    tests::{FakeTunnel, framed_dns, read_framed_dns},
};
use sshunnel_mux::{
    QueryError,
    frame::{ResolveErrKind, Transport},
};
use tempfile::TempDir;
use tokio::{
    io::AsyncWriteExt as _,
    net::{TcpListener, UdpSocket},
    sync::mpsc::{UnboundedReceiver, unbounded_channel},
    time::{Instant, advance, timeout},
};

struct Fixture {
    tunnel: FakeTunnel,
    server: Arc<Server<FakeTunnel>>,
    _state: TempDir,
}

/// `fake_v6` as the helper reports it: whether the machine gives matched names v6 fakes.
fn fixture(include: &[&str], exclude: &[&str], upstreams: Vec<SocketAddr>, fake_v6: bool) -> Fixture {
    let state = TempDir::new().unwrap();
    let owned = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let targets = Targets::parse(&owned(include), &owned(exclude)).unwrap();
    let names = FakeMap::load(state.path().join("names"), today()).unwrap();
    let router = Arc::new(Router::new(targets, names));
    let tunnel = FakeTunnel::new();
    let server = Arc::new(Server::new(tunnel.clone(), router, upstreams, fake_v6));
    Fixture { tunnel, server, _state: state }
}

fn corp() -> Fixture {
    fixture(&["*.corp.example"], &["private.corp.example"], Vec::new(), true)
}

fn query(id: u16, name: &str, qtype: TYPE) -> Bytes {
    let mut packet = Packet::new_query(id);
    packet.set_flags(PacketFlag::RECURSION_DESIRED);
    packet.questions.push(Question::new(Name::new_unchecked(name), QTYPE::TYPE(qtype), QCLASS::CLASS(CLASS::IN), false));
    Bytes::from(packet.build_bytes_vec().unwrap())
}

/// A query for an A record built by hand, because simple-dns won't build every name worth testing.
fn raw_query(id: u16, name: &str) -> Bytes {
    let mut wire = Vec::from(id.to_be_bytes());
    wire.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        wire.push(u8::try_from(label.len()).unwrap());
        wire.extend_from_slice(label.as_bytes());
    }
    wire.extend_from_slice(&[0, 0, 1, 0, 1]);
    Bytes::from(wire)
}

async fn ask(server: &Server<FakeTunnel>, id: u16, name: &str, qtype: TYPE) -> Vec<u8> {
    server.answer(query(id, name, qtype), Transport::Udp).await.expect("an answer").to_vec()
}

fn soa_minimum(packet: &Packet<'_>) -> Option<u32> {
    packet.name_servers.iter().find_map(|rr| match &rr.rdata {
        RData::SOA(soa) => Some(soa.minimum),
        _ => None,
    })
}

#[tokio::test]
async fn a_matched_name_gets_its_fake_address() {
    let f = corp();
    f.tunnel.name("wiki.corp.example", Ok(()));

    let bytes = ask(&f.server, 0x1234, "wiki.corp.example", TYPE::A).await;
    let reply = Packet::parse(&bytes).unwrap();

    assert_eq!(reply.id(), 0x1234);
    assert!(reply.has_flags(PacketFlag::RESPONSE));
    assert_eq!(reply.rcode(), RCODE::NoError);
    assert_eq!(reply.questions.len(), 1);
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(u64::from(reply.answers[0].ttl), TTL.as_secs());
    let RData::A(a) = &reply.answers[0].rdata else {
        panic!("not an A record: {:?}", reply.answers[0])
    };
    assert_eq!(std::net::Ipv4Addr::from(a.address), names::slot("wiki.corp.example"));
}

#[tokio::test]
async fn fake_v6_aaaa_answers_when_on() {
    let f = corp();
    f.tunnel.name("wiki.corp.example", Ok(()));

    // AAAA first: it hands out the name's v4 fake too, so the two pair whichever comes first.
    let aaaa = ask(&f.server, 1, "wiki.corp.example", TYPE::AAAA).await;
    let a = ask(&f.server, 2, "wiki.corp.example", TYPE::A).await;
    let (aaaa, a) = (Packet::parse(&aaaa).unwrap(), Packet::parse(&a).unwrap());

    assert_eq!(aaaa.rcode(), RCODE::NoError);
    assert_eq!(aaaa.answers.len(), 1);
    assert_eq!(u64::from(aaaa.answers[0].ttl), TTL.as_secs());
    let RData::AAAA(v6) = &aaaa.answers[0].rdata else {
        panic!("not an AAAA record: {:?}", aaaa.answers[0])
    };
    let RData::A(v4) = &a.answers[0].rdata else { panic!("not an A record: {:?}", a.answers[0]) };
    let v6 = Ipv6Addr::from(v6.address);
    assert_eq!(v6, names::fake_v6(Ipv4Addr::from(v4.address)));
    assert!(FAKE_RANGE6.contains(&v6), "{v6}");
    assert_eq!(f.tunnel.resolves(), vec!["wiki.corp.example"]);
}

#[tokio::test]
async fn fake_v6_aaaa_is_nodata_when_off() {
    let f = fixture(&["*.corp.example"], &[], Vec::new(), false);
    f.tunnel.name("wiki.corp.example", Ok(()));

    let bytes = ask(&f.server, 1, "wiki.corp.example", TYPE::AAAA).await;
    let reply = Packet::parse(&bytes).unwrap();

    assert_eq!(reply.rcode(), RCODE::NoError);
    assert_eq!(reply.answers.len(), 0);
    assert_eq!(soa_minimum(&reply), Some(5));
}

#[tokio::test]
async fn a_missing_name_is_nxdomain() {
    let f = corp();

    let bytes = ask(&f.server, 7, "nope.corp.example", TYPE::A).await;
    let reply = Packet::parse(&bytes).unwrap();

    assert_eq!(reply.id(), 7);
    assert_eq!(reply.rcode(), RCODE::NameError);
    assert_eq!(reply.answers.len(), 0);
    assert_eq!(soa_minimum(&reply), Some(5));
}

#[tokio::test]
async fn a_failed_lookup_is_servfail() {
    let f = corp();
    f.tunnel.name("flaky.corp.example", Err(ResolveErrKind::Failed));

    let bytes = ask(&f.server, 9, "flaky.corp.example", TYPE::A).await;
    let reply = Packet::parse(&bytes).unwrap();

    assert_eq!(reply.id(), 9);
    assert_eq!(reply.rcode(), RCODE::ServerFailure);
    assert_eq!(reply.answers.len(), 0);
}

#[tokio::test(start_paused = true)]
async fn the_relay_is_asked_once_per_minute() {
    let f = corp();
    f.tunnel.name("wiki.corp.example", Ok(()));

    ask(&f.server, 1, "wiki.corp.example", TYPE::A).await;
    advance(Duration::from_secs(59)).await;
    ask(&f.server, 2, "wiki.corp.example", TYPE::AAAA).await;
    assert_eq!(f.tunnel.resolves(), vec!["wiki.corp.example"]);

    advance(Duration::from_secs(2)).await;
    ask(&f.server, 3, "wiki.corp.example", TYPE::A).await;
    assert_eq!(f.tunnel.resolves(), vec!["wiki.corp.example", "wiki.corp.example"]);
}

#[tokio::test(start_paused = true)]
async fn a_missing_name_is_cached_too() {
    let f = corp();

    ask(&f.server, 1, "nope.corp.example", TYPE::A).await;
    ask(&f.server, 2, "nope.corp.example", TYPE::A).await;

    assert_eq!(f.tunnel.resolves(), vec!["nope.corp.example"]);
}

/// A UDP stub that answers every query with `canned`, its id swapped for the query's, and reports
/// the queries it saw.
async fn stub(canned: &'static [u8]) -> (SocketAddr, UnboundedReceiver<Vec<u8>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    (socket.local_addr().unwrap(), udp_stub_on(socket, canned))
}

fn udp_stub_on(socket: UdpSocket, canned: &'static [u8]) -> UnboundedReceiver<Vec<u8>> {
    let (seen, queries) = unbounded_channel();
    tokio::spawn(async move {
        let mut buf = [0_u8; 512];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let mut reply = canned.to_vec();
            reply[..2].copy_from_slice(&buf[..2]);
            seen.send(buf[..n].to_vec()).ok();
            socket.send_to(&reply, from).await.ok();
        }
    });
    queries
}

/// [`stub`] over UDP and over TCP on one port, as an upstream serves both: `udp` answers the
/// first, `tcp` the second (RFC 7766's framing, a connection per query). Returns the port's address
/// and the queries each saw.
async fn stubs(udp: &'static [u8], tcp: &'static [u8]) -> (SocketAddr, UnboundedReceiver<Vec<u8>>, UnboundedReceiver<Vec<u8>>) {
    let (listener, socket) = loop {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        // Another test may hold the UDP side of the port; then try another.
        if let Ok(socket) = UdpSocket::bind(listener.local_addr().unwrap()).await {
            break (listener, socket);
        }
    };
    let addr = listener.local_addr().unwrap();
    let (seen, tcp_queries) = unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let Ok(query) = read_framed_dns(&mut conn).await else { continue };
            let mut reply = tcp.to_vec();
            reply[..2].copy_from_slice(&query[..2]);
            seen.send(query.to_vec()).ok();
            conn.write_all(&framed_dns(&reply).unwrap()).await.ok();
        }
    });
    (addr, udp_stub_on(socket, udp), tcp_queries)
}

const CANNED: &[u8] = b"\x00\x00\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00 the stub's own bytes";

#[tokio::test]
async fn an_excluded_name_is_answered_by_the_upstream() {
    let (upstream, mut queries) = stub(CANNED).await;
    let f = fixture(&["*.corp.example"], &["private.corp.example"], vec![upstream], true);
    let asked = query(0xbeef, "private.corp.example", TYPE::A);

    let answer = f.server.answer(asked.clone(), Transport::Udp).await.unwrap();

    let mut expected = CANNED.to_vec();
    expected[..2].copy_from_slice(&[0xbe, 0xef]);
    assert_eq!(answer.to_vec(), expected);
    assert_eq!(queries.recv().await.unwrap(), asked.to_vec());
    assert_eq!(f.tunnel.resolves().len(), 0);
}

/// An answer past 4 KiB, as large TXT answers and names with many records get.
static LARGE: [u8; 6000] = [0x2a; 6000];

#[tokio::test]
async fn a_large_upstream_answer_is_relayed_whole() {
    let (upstream, _queries) = stub(&LARGE).await;
    let f = fixture(&["*.corp.example"], &["private.corp.example"], vec![upstream], true);

    let answer = f.server.answer(query(0xbeef, "private.corp.example", TYPE::TXT), Transport::Udp).await.unwrap();

    assert_eq!(answer.len(), LARGE.len());
    assert!(answer[2..] == LARGE[2..], "the answer changed on the way");
}

#[tokio::test]
async fn an_unmatched_name_under_an_exact_target_goes_upstream() {
    let (upstream, _queries) = stub(CANNED).await;
    let f = fixture(&["host.corp.example"], &[], vec![upstream], true);

    let answer = f.server.answer(query(5, "a.host.corp.example", TYPE::A), Transport::Udp).await.unwrap();

    assert_eq!(&answer[2..], &CANNED[2..]);
    assert_eq!(f.tunnel.resolves().len(), 0);
}

#[tokio::test]
async fn dns_names_are_case_insensitive() {
    let f = corp();
    f.tunnel.name("wiki.corp.example", Ok(()));

    let bytes = ask(&f.server, 1, "WIKI.corp.example.", TYPE::A).await;
    let reply = Packet::parse(&bytes).unwrap();

    let RData::A(a) = &reply.answers[0].rdata else { panic!("not an A record") };
    assert_eq!(std::net::Ipv4Addr::from(a.address), names::slot("wiki.corp.example"));
    assert_eq!(f.tunnel.resolves(), vec!["wiki.corp.example"]);
}

#[tokio::test(start_paused = true)]
async fn no_upstream_answers_is_servfail() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstreams = vec![dead.local_addr().unwrap(), silent.local_addr().unwrap()];
    drop(dead);
    let f = fixture(&["*.corp.example"], &[], upstreams, true);

    let bytes = ask(&f.server, 3, "elsewhere.example", TYPE::A).await;
    let reply = Packet::parse(&bytes).unwrap();

    assert_eq!(reply.id(), 3);
    assert_eq!(reply.rcode(), RCODE::ServerFailure);
    assert_eq!(reply.questions.len(), 1);
}

#[tokio::test]
async fn garbage_gets_no_answer() {
    let f = corp();

    assert!(f.server.answer(Bytes::from_static(b"\x01\x02\x03"), Transport::Udp).await.is_none());
    assert!(f.server.answer(Bytes::new(), Transport::Udp).await.is_none());
}

#[tokio::test]
async fn an_implausible_name_is_nxdomain_without_a_lookup() {
    let f = corp();

    for name in ["bad name.corp.example", "new\nline.corp.example", "caf\u{e9}.corp.example", "a\tb.corp.example"] {
        let bytes = f.server.answer(raw_query(1, name), Transport::Udp).await.expect("an answer");
        let reply = Packet::parse(&bytes).unwrap();
        assert_eq!(reply.rcode(), RCODE::NameError, "{name:?}");
    }
    assert_eq!(f.tunnel.resolves().len(), 0);
}

#[tokio::test]
async fn a_failed_lookup_is_not_cached() {
    let f = corp();
    f.tunnel.name("flaky.corp.example", Err(ResolveErrKind::Failed));

    let bytes = ask(&f.server, 1, "flaky.corp.example", TYPE::A).await;
    assert_eq!(Packet::parse(&bytes).unwrap().rcode(), RCODE::ServerFailure);

    f.tunnel.name("flaky.corp.example", Ok(()));
    let bytes = ask(&f.server, 2, "flaky.corp.example", TYPE::A).await;
    let reply = Packet::parse(&bytes).unwrap();

    assert_eq!(reply.rcode(), RCODE::NoError);
    let RData::A(a) = &reply.answers[0].rdata else { panic!("not an A record") };
    assert_eq!(std::net::Ipv4Addr::from(a.address), names::slot("flaky.corp.example"));
    assert_eq!(f.tunnel.resolves(), vec!["flaky.corp.example", "flaky.corp.example"]);
}

#[tokio::test]
async fn responses_and_multi_question_packets_get_no_answer() {
    let f = corp();
    f.tunnel.name("wiki.corp.example", Ok(()));

    let mut response = Packet::new_reply(1);
    response
        .questions
        .push(Question::new(Name::new_unchecked("wiki.corp.example"), QTYPE::TYPE(TYPE::A), QCLASS::CLASS(CLASS::IN), false));
    let response = Bytes::from(response.build_bytes_vec().unwrap());
    assert!(f.server.answer(response, Transport::Udp).await.is_none());

    let mut two = Packet::new_query(2);
    for name in ["wiki.corp.example", "other.corp.example"] {
        two.questions.push(Question::new(Name::new_unchecked(name), QTYPE::TYPE(TYPE::A), QCLASS::CLASS(CLASS::IN), false));
    }
    let two = Bytes::from(two.build_bytes_vec().unwrap());
    assert!(f.server.answer(two, Transport::Udp).await.is_none());

    assert_eq!(f.tunnel.resolves().len(), 0);
}

/// A record as the remote's resolver would send it, with a TTL of its own.
fn record(name: &'static str, rdata: RData<'static>) -> ResourceRecord<'static> {
    ResourceRecord::new(Name::new_unchecked(name), CLASS::IN, 300, rdata)
}

fn a(addr: &str) -> RData<'static> {
    RData::A(A::from(addr.parse::<Ipv4Addr>().unwrap()))
}

fn aaaa(addr: &str) -> RData<'static> {
    RData::AAAA(AAAA::from(addr.parse::<Ipv6Addr>().unwrap()))
}

fn txt(text: &'static str) -> RData<'static> {
    RData::TXT(TXT::new().with_string(text).unwrap())
}

fn remote_soa() -> ResourceRecord<'static> {
    let rdata = SOA {
        mname: Name::new_unchecked("ns1.corp.example"),
        rname: Name::new_unchecked("hostmaster.corp.example"),
        serial: 7,
        refresh: 3600,
        retry: 600,
        expire: 86400,
        minimum: 300,
    };
    record("corp.example", RData::SOA(rdata))
}

/// The remote's resolver, for [`FakeTunnel::answer_queries`]: it answers each query with its id
/// and question, and whatever `fill` adds given the question's type.
fn resolver(fill: impl Fn(QTYPE, &mut Packet<'_>) + Send + Sync + 'static) -> impl Fn(&[u8], Transport) -> Result<Bytes, QueryError> + Send + Sync + 'static {
    move |query, _| {
        let query = Packet::parse(query).unwrap();
        let mut answer = Packet::new_reply(query.id());
        answer.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        answer.questions.clone_from(&query.questions);
        fill(query.questions[0].qtype, &mut answer);
        Ok(Bytes::from(answer.build_bytes_vec().unwrap()))
    }
}

fn has_addresses(records: &[ResourceRecord<'_>]) -> bool {
    records.iter().any(|rr| matches!(rr.rdata, RData::A(_) | RData::AAAA(_)))
}

#[tokio::test]
async fn dns_records_srv_comes_from_the_remote() {
    let f = corp();
    f.tunnel.answer_queries(resolver(|_, answer| {
        let target = Name::new_unchecked("dc1.corp.example");
        answer.answers.push(record(
            "_ldap._tcp.corp.example",
            RData::SRV(SRV {
                priority: 0,
                weight: 100,
                port: 389,
                target,
            }),
        ));
        answer.additional_records.push(record("dc1.corp.example", a("10.99.0.5")));
    }));
    let asked = query(0x5151, "_ldap._tcp.corp.example", TYPE::SRV);

    let bytes = f.server.answer(asked.clone(), Transport::Udp).await.expect("an answer");
    let reply = Packet::parse(&bytes).unwrap();

    assert_eq!(reply.id(), 0x5151);
    assert_eq!(reply.rcode(), RCODE::NoError);
    assert_eq!(reply.answers.len(), 1);
    let RData::SRV(srv) = &reply.answers[0].rdata else {
        panic!("not an SRV record: {:?}", reply.answers[0])
    };
    assert_eq!((srv.target.to_string().as_str(), srv.port), ("dc1.corp.example", 389));
    assert!(!has_addresses(&reply.additional_records), "{:?}", reply.additional_records);
    assert_eq!(f.tunnel.queries(), vec![(asked, Transport::Udp)]);
    // The remote answered, so its verdict stands without a lookup.
    assert_eq!(f.tunnel.resolves().len(), 0);
}

#[tokio::test]
async fn dns_records_txt_and_mx_come_from_the_remote() {
    let f = corp();
    f.tunnel.answer_queries(resolver(|qtype, answer| {
        if qtype == QTYPE::TYPE(TYPE::TXT) {
            answer.answers.push(record("corp.example", txt("v=spf1 -all")));
        } else {
            let exchange = Name::new_unchecked("mail.corp.example");
            answer.answers.push(record("corp.example", RData::MX(MX { preference: 10, exchange })));
        }
    }));

    let txt_reply = ask(&f.server, 1, "corp.example", TYPE::TXT).await;
    let mx_reply = ask(&f.server, 2, "corp.example", TYPE::MX).await;
    let (txt_reply, mx_reply) = (Packet::parse(&txt_reply).unwrap(), Packet::parse(&mx_reply).unwrap());

    assert_eq!((txt_reply.id(), txt_reply.rcode()), (1, RCODE::NoError));
    let RData::TXT(text) = &txt_reply.answers[0].rdata else {
        panic!("not a TXT record: {:?}", txt_reply.answers[0])
    };
    assert_eq!(String::try_from(text.clone()).unwrap(), "v=spf1 -all");
    assert_eq!((mx_reply.id(), mx_reply.rcode()), (2, RCODE::NoError));
    let RData::MX(mx) = &mx_reply.answers[0].rdata else {
        panic!("not an MX record: {:?}", mx_reply.answers[0])
    };
    assert_eq!((mx.preference, mx.exchange.to_string().as_str()), (10, "mail.corp.example"));
    assert_eq!(f.tunnel.queries().len(), 2);
}

#[tokio::test]
async fn dns_records_https_and_svcb_are_nodata() {
    let f = corp();
    f.tunnel.name("wiki.corp.example", Ok(()));
    f.tunnel.answer_queries(resolver(|_, _| panic!("HTTPS and SVCB never reach the remote")));

    for qtype in [TYPE::HTTPS, TYPE::SVCB] {
        let bytes = ask(&f.server, 1, "wiki.corp.example", qtype).await;
        let reply = Packet::parse(&bytes).unwrap();

        assert_eq!(reply.rcode(), RCODE::NoError, "{qtype:?}");
        assert_eq!(reply.answers.len(), 0, "{qtype:?}");
        assert_eq!(soa_minimum(&reply), Some(5), "{qtype:?}");
    }
    assert_eq!(f.tunnel.queries().len(), 0);
}

#[tokio::test]
async fn dns_records_strip_a_and_aaaa_everywhere() {
    let f = corp();
    f.tunnel.answer_queries(resolver(|_, answer| {
        let exchange = Name::new_unchecked("mail.corp.example");
        answer.answers.push(record("corp.example", RData::MX(MX { preference: 10, exchange })));
        answer.answers.push(record("corp.example", a("10.99.0.1")));
        answer.answers.push(record("corp.example", aaaa("fd99::1")));
        answer.name_servers.push(record("corp.example", RData::NS(NS(Name::new_unchecked("ns1.corp.example")))));
        answer.name_servers.push(record("ns1.corp.example", a("10.99.0.53")));
        answer.name_servers.push(record("ns1.corp.example", aaaa("fd99::53")));
        answer.additional_records.push(record("mail.corp.example", a("10.99.0.25")));
        answer.additional_records.push(record("mail.corp.example", aaaa("fd99::25")));
        answer.additional_records.push(record("mail.corp.example", txt("kept")));
    }));

    let bytes = ask(&f.server, 1, "corp.example", TYPE::MX).await;
    let reply = Packet::parse(&bytes).unwrap();

    assert_eq!(reply.rcode(), RCODE::NoError);
    let kinds = |records: &[ResourceRecord<'_>]| records.iter().map(|rr| rr.rdata.type_code()).collect::<Vec<_>>();
    assert_eq!(kinds(&reply.answers), [TYPE::MX]);
    assert_eq!(kinds(&reply.name_servers), [TYPE::NS]);
    assert_eq!(kinds(&reply.additional_records), [TYPE::TXT]);
}

#[tokio::test]
async fn dns_records_strip_https_and_svcb_everywhere() {
    let f = corp();
    f.tunnel.answer_queries(resolver(|_, answer| {
        let mut https = SVCB::new(1, Name::new_unchecked("."));
        https.set_ipv4hint(&[u32::from("10.99.0.80".parse::<Ipv4Addr>().unwrap())]);
        let mut svcb = SVCB::new(1, Name::new_unchecked("."));
        svcb.set_ipv6hint(&[u128::from("fd99::80".parse::<Ipv6Addr>().unwrap())]);
        answer.answers.push(record("wiki.corp.example", RData::HTTPS(HTTPS(https))));
        answer.answers.push(record("wiki.corp.example", txt("kept")));
        answer.name_servers.push(record("wiki.corp.example", RData::SVCB(svcb.clone())));
        answer.additional_records.push(record("_8443._https.wiki.corp.example", RData::SVCB(svcb)));
        answer.additional_records.push(record("wiki.corp.example", txt("kept too")));
    }));
    // ANY reaches the remote, and its HTTPS and SVCB records carry real addresses in their hints.
    let mut any = Packet::new_query(1);
    any.questions.push(Question::new(Name::new_unchecked("wiki.corp.example"), QTYPE::ANY, QCLASS::CLASS(CLASS::IN), false));

    let bytes = f.server.answer(Bytes::from(any.build_bytes_vec().unwrap()), Transport::Udp).await.expect("an answer");
    let reply = Packet::parse(&bytes).unwrap();

    assert_eq!(reply.rcode(), RCODE::NoError);
    let kinds = |records: &[ResourceRecord<'_>]| records.iter().map(|rr| rr.rdata.type_code()).collect::<Vec<_>>();
    assert_eq!(kinds(&reply.answers), [TYPE::TXT]);
    assert_eq!(kinds(&reply.name_servers), []);
    assert_eq!(kinds(&reply.additional_records), [TYPE::TXT]);
    assert_eq!(f.tunnel.queries().len(), 1);
}

#[tokio::test]
async fn dns_records_remote_nxdomain_for_a_found_name_is_nodata() {
    let f = corp();
    // Only in the remote's /etc/hosts: the relay finds it, its nameservers don't.
    f.tunnel.name("hosts-only.corp.example", Ok(()));
    f.tunnel.answer_queries(resolver(|_, answer| {
        *answer.rcode_mut() = RCODE::NameError;
        answer.name_servers.push(remote_soa());
    }));

    let bytes = ask(&f.server, 4, "hosts-only.corp.example", TYPE::TXT).await;
    let reply = Packet::parse(&bytes).unwrap();

    assert_eq!((reply.id(), reply.rcode()), (4, RCODE::NoError));
    assert_eq!(reply.answers.len(), 0);
    assert_eq!(f.tunnel.queries().len(), 1);
    assert_eq!(f.tunnel.resolves(), vec!["hosts-only.corp.example"]);
}

#[tokio::test]
async fn dns_records_remote_nxdomain_for_a_missing_name_stays_nxdomain() {
    let f = corp();
    f.tunnel.answer_queries(resolver(|_, answer| {
        *answer.rcode_mut() = RCODE::NameError;
        answer.name_servers.push(remote_soa());
    }));

    let bytes = ask(&f.server, 5, "nope.corp.example", TYPE::TXT).await;
    let reply = Packet::parse(&bytes).unwrap();

    assert_eq!((reply.id(), reply.rcode()), (5, RCODE::NameError));
    assert_eq!(reply.answers.len(), 0);
    assert_eq!(f.tunnel.queries().len(), 1);
    assert_eq!(f.tunnel.resolves(), vec!["nope.corp.example"]);
}

#[tokio::test]
async fn dns_records_remote_nxdomain_with_a_failed_lookup_is_servfail() {
    let f = corp();
    f.tunnel.name("flaky.corp.example", Err(ResolveErrKind::Failed));
    f.tunnel.answer_queries(resolver(|_, answer| *answer.rcode_mut() = RCODE::NameError));

    let bytes = ask(&f.server, 5, "flaky.corp.example", TYPE::TXT).await;
    let reply = Packet::parse(&bytes).unwrap();

    // The remote's NXDOMAIN could be cached for as long as its SOA says, hiding the name's fake A.
    assert_eq!((reply.id(), reply.rcode()), (5, RCODE::ServerFailure));
    assert_eq!(f.tunnel.resolves(), vec!["flaky.corp.example"]);
}

#[tokio::test]
async fn dns_records_other_rcodes_pass_through() {
    let f = corp();
    f.tunnel.answer_queries(resolver(|_, answer| *answer.rcode_mut() = RCODE::Refused));

    let bytes = ask(&f.server, 6, "wiki.corp.example", TYPE::TXT).await;
    let reply = Packet::parse(&bytes).unwrap();

    assert_eq!((reply.id(), reply.rcode()), (6, RCODE::Refused));
    assert_eq!(f.tunnel.resolves().len(), 0);
}

#[tokio::test(start_paused = true)]
async fn dns_records_a_failed_query_is_servfail() {
    let f = corp();
    let servfail = async |id| {
        let bytes = ask(&f.server, id, "wiki.corp.example", TYPE::TXT).await;
        let reply = Packet::parse(&bytes).unwrap();
        assert_eq!((reply.id(), reply.rcode()), (id, RCODE::ServerFailure));
        assert_eq!(reply.questions.len(), 1);
    };

    f.tunnel.answer_queries(|_, _| Err(QueryError { reason: "no nameserver answered".into() }));
    servfail(1).await;

    f.tunnel.answer_queries(|_, _| Ok(Bytes::from_static(b"\x00\x02\x81\x80 not DNS")));
    servfail(2).await;

    f.tunnel.stall_queries();
    let start = Instant::now();
    servfail(3).await;
    assert!(start.elapsed() >= QUERY_TIMEOUT, "{:?}", start.elapsed());

    assert_eq!(f.tunnel.queries().len(), 3);
}

#[tokio::test]
async fn dns_records_truncated_answers_pass_back_truncated() {
    let f = corp();
    f.tunnel.answer_queries(resolver(|_, answer| {
        answer.set_flags(PacketFlag::TRUNCATION);
        answer.answers.push(record("corp.example", txt("the first of many")));
    }));

    let bytes = ask(&f.server, 7, "corp.example", TYPE::TXT).await;
    let reply = Packet::parse(&bytes).unwrap();

    assert_eq!((reply.id(), reply.rcode()), (7, RCODE::NoError));
    assert!(reply.has_flags(PacketFlag::TRUNCATION));
    assert_eq!(reply.answers.len(), 1);
}

/// The fake addresses `name` gets, v4 and v6, by asking for them.
async fn fakes(server: &Server<FakeTunnel>, name: &str) -> (IpAddr, IpAddr) {
    let a = Packet::parse(&ask(server, 1, name, TYPE::A).await).unwrap().answers[0].rdata.clone().into_owned();
    let aaaa = Packet::parse(&ask(server, 2, name, TYPE::AAAA).await).unwrap().answers[0].rdata.clone().into_owned();
    let (RData::A(a), RData::AAAA(aaaa)) = (a, aaaa) else { panic!("not fake addresses") };
    (IpAddr::V4(a.address.into()), IpAddr::V6(aaaa.address.into()))
}

#[tokio::test]
async fn ptr_of_an_assigned_fake_answers_its_name() {
    let f = corp();
    f.tunnel.name("wiki.corp.example", Ok(()));
    let (v4, v6) = fakes(&f.server, "wiki.corp.example").await;

    for addr in [v4, v6] {
        let reverse = reverse::name(addr);
        let bytes = ask(&f.server, 9, &reverse, TYPE::PTR).await;
        let reply = Packet::parse(&bytes).unwrap();

        assert_eq!((reply.id(), reply.rcode()), (9, RCODE::NoError), "{addr}");
        assert_eq!(reply.answers.len(), 1, "{addr}");
        assert_eq!(reply.answers[0].name.to_string(), reverse);
        assert_eq!(u64::from(reply.answers[0].ttl), TTL.as_secs());
        let RData::PTR(PTR(name)) = &reply.answers[0].rdata else {
            panic!("not a PTR record: {:?}", reply.answers[0])
        };
        assert_eq!(name.to_string(), "wiki.corp.example");

        // Any other type at the address's name is NODATA: the name exists, with a PTR only.
        let bytes = ask(&f.server, 10, &reverse, TYPE::TXT).await;
        let reply = Packet::parse(&bytes).unwrap();
        assert_eq!((reply.rcode(), reply.answers.len()), (RCODE::NoError, 0), "{addr}");
        assert_eq!(soa_minimum(&reply), Some(5));
    }
    assert_eq!(f.tunnel.queries().len(), 0);
}

#[tokio::test]
async fn ptr_of_an_unassigned_fake_is_nxdomain() {
    let f = corp();

    let unassigned = ["198.19.255.254".parse().unwrap(), IpAddr::V6(names::fake_v6("198.19.255.254".parse().unwrap()))];
    // Inside 2001:2::/96, but with low bits no v4 fake has.
    let outside_v4 = "2001:2::1".parse().unwrap();
    for addr in unassigned.into_iter().chain([outside_v4]) {
        let bytes = ask(&f.server, 3, &reverse::name(addr), TYPE::PTR).await;
        let reply = Packet::parse(&bytes).unwrap();

        assert_eq!((reply.id(), reply.rcode()), (3, RCODE::NameError), "{addr}");
        assert_eq!(soa_minimum(&reply), Some(5));
    }
    assert_eq!(f.tunnel.queries().len(), 0);
}

#[tokio::test]
async fn ptr_zone_names_short_of_an_address_are_nodata() {
    let f = corp();
    let zone6 = reverse::zones(true).pop().unwrap();

    for name in ["18.198.in-addr.arpa", "0.19.198.in-addr.arpa", zone6.as_str(), &format!("c.6.{zone6}")] {
        let bytes = ask(&f.server, 8, name, TYPE::PTR).await;
        let reply = Packet::parse(&bytes).unwrap();

        assert_eq!((reply.rcode(), reply.answers.len()), (RCODE::NoError, 0), "{name}");
        assert_eq!(soa_minimum(&reply), Some(5), "{name}");
    }
}

#[tokio::test]
async fn ptr_outside_the_fake_ranges_goes_upstream() {
    let (upstream, mut queries) = stub(CANNED).await;
    let f = fixture(&["*.corp.example"], &[], vec![upstream], true);
    let asked = query(0xbeef, "10.2.0.192.in-addr.arpa", TYPE::PTR);

    let answer = f.server.answer(asked.clone(), Transport::Udp).await.unwrap();

    assert_eq!(&answer[2..], &CANNED[2..]);
    assert_eq!(queries.recv().await.unwrap(), asked.to_vec());
}

/// What the TCP stub answers, so an answer shows which transport it came over.
const OVER_TCP: &[u8] = b"\x00\x00\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00 the stub's bytes over TCP";
/// A truncated answer (TC), as an upstream sends one too large for UDP.
const TRUNCATED: &[u8] = b"\x00\x00\x83\x80\x00\x00\x00\x00\x00\x00\x00\x00";

/// `canned` with `id` in place of its own.
fn with_id(id: u16, canned: &[u8]) -> Vec<u8> {
    [&id.to_be_bytes()[..], &canned[2..]].concat()
}

#[tokio::test]
async fn dns_over_tcp_forwards_upstream_over_tcp() {
    let (upstream, mut udp_queries, mut tcp_queries) = stubs(CANNED, OVER_TCP).await;
    let f = fixture(&["*.corp.example"], &["private.corp.example"], vec![upstream], true);
    let asked = query(0xbeef, "private.corp.example", TYPE::A);

    let answer = f.server.answer(asked.clone(), Transport::Tcp).await.unwrap();

    assert_eq!(answer.to_vec(), with_id(0xbeef, OVER_TCP));
    assert_eq!(tcp_queries.recv().await.unwrap(), asked.to_vec());
    assert!(udp_queries.try_recv().is_err(), "the query went over UDP too");
    assert_eq!(f.tunnel.resolves().len(), 0);
}

#[tokio::test]
async fn dns_over_tcp_retries_a_truncated_answer() {
    let (upstream, _udp_queries, _tcp_queries) = stubs(TRUNCATED, &LARGE).await;
    let f = fixture(&["*.corp.example"], &["private.corp.example"], vec![upstream], true);
    let asked = query(0x7c7c, "private.corp.example", TYPE::TXT);

    let over_udp = f.server.answer(asked.clone(), Transport::Udp).await.unwrap();
    let over_tcp = f.server.answer(asked, Transport::Tcp).await.unwrap();

    // The resolver sees TC over UDP and retries over TCP, which gets the whole answer.
    assert_eq!(over_udp.to_vec(), with_id(0x7c7c, TRUNCATED));
    assert_eq!(over_tcp.len(), LARGE.len());
    assert!(over_tcp[..2] == [0x7c, 0x7c] && over_tcp[2..] == LARGE[2..], "the answer changed on the way");
}

#[tokio::test]
async fn dns_over_tcp_queries_a_matched_name_over_tcp() {
    let f = corp();
    let truncated = resolver(|_, answer| {
        answer.set_flags(PacketFlag::TRUNCATION);
        answer.answers.push(record("corp.example", txt("the first of many")));
    });
    let whole = resolver(|_, answer| {
        for text in ["the first of many", "the second", "the third"] {
            answer.answers.push(record("corp.example", txt(text)));
        }
    });
    // The remote's resolver truncates over UDP and answers in full over TCP.
    f.tunnel.answer_queries(move |query, transport| match transport {
        Transport::Udp => truncated(query, transport),
        Transport::Tcp => whole(query, transport),
    });
    let asked = query(7, "corp.example", TYPE::TXT);

    let over_udp = f.server.answer(asked.clone(), Transport::Udp).await.expect("an answer");
    let over_tcp = f.server.answer(asked.clone(), Transport::Tcp).await.expect("an answer");
    let (over_udp, over_tcp) = (Packet::parse(&over_udp).unwrap(), Packet::parse(&over_tcp).unwrap());

    assert!(over_udp.has_flags(PacketFlag::TRUNCATION));
    assert_eq!(over_udp.answers.len(), 1);
    assert!(!over_tcp.has_flags(PacketFlag::TRUNCATION));
    assert_eq!((over_tcp.id(), over_tcp.rcode(), over_tcp.answers.len()), (7, RCODE::NoError, 3));
    assert_eq!(f.tunnel.queries(), vec![(asked.clone(), Transport::Udp), (asked, Transport::Tcp)]);
}

#[tokio::test(start_paused = true)]
async fn dns_over_tcp_ends_a_connection_whose_asker_stops_reading() {
    let f = corp();
    f.tunnel.name("wiki.corp.example", Ok(()));
    // Room for all six queries but only four answers, so the server waits on the asker.
    let (mut asker, io) = tokio::io::duplex(256);
    let served = tokio::spawn(serve_tcp(Arc::clone(&f.server), io));
    let queries: Vec<u8> = (0..6).flat_map(|id| framed_dns(&query(id, "wiki.corp.example", TYPE::A)).unwrap()).collect();
    asker.write_all(&queries).await.unwrap();

    tokio::time::sleep(TCP_IDLE.saturating_sub(Duration::from_secs(1))).await;
    assert!(!served.is_finished(), "gave up on the asker early");

    let ended = timeout(Duration::from_secs(2), served).await.expect("ended once the asker took nothing for TCP_IDLE").unwrap();
    assert!(ended.is_err(), "{ended:?}");
}

#[tokio::test]
async fn serve_tcp_reads_a_length_and_body_written_apart() {
    let f = corp();
    f.tunnel.name("wiki.corp.example", Ok(()));
    let (mut asker, io) = tokio::io::duplex(1024);
    let served = tokio::spawn(serve_tcp(Arc::clone(&f.server), io));
    let framed = framed_dns(&query(9, "wiki.corp.example", TYPE::A)).unwrap();

    // The length alone first: the server has to wait for the body behind it.
    asker.write_all(&framed[..2]).await.unwrap();
    asker.flush().await.unwrap();
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    asker.write_all(&framed[2..]).await.unwrap();

    let answer = read_framed_dns(&mut asker).await.unwrap();
    let answer = Packet::parse(&answer).unwrap();
    assert_eq!((answer.id(), answer.rcode(), answer.answers.len()), (9, RCODE::NoError, 1));

    drop(asker);
    served.await.unwrap().unwrap();
}

#[tokio::test]
async fn serve_tcp_handles_a_zero_length_message() {
    let f = corp();
    let (mut asker, io) = tokio::io::duplex(1024);
    let served = tokio::spawn(serve_tcp(Arc::clone(&f.server), io));

    // An empty message isn't a query: the connection closes with no answer, and no error.
    asker.write_all(&0_u16.to_be_bytes()).await.unwrap();

    served.await.unwrap().unwrap();
    assert!(read_framed_dns(&mut asker).await.is_err(), "an answer to an empty message");
}
