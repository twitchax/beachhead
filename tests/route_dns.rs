//! The DNS server against a scripted tunnel (`FakeTunnel`) and a local UDP stub standing in for the
//! normal upstream. Every test is a top-level function, so the PRD's filters see the bare names.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use pretty_assertions::assert_eq;
use simple_dns::{CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, RCODE, TYPE, rdata::RData};
use sshunnel::{
    route::{
        dns::{Server, TTL},
        names::{self, FakeMap, today},
        router::Router,
        stack::Dns,
        targets::Targets,
    },
    tests::FakeTunnel,
};
use sshunnel_mux::frame::ResolveErrKind;
use tempfile::TempDir;
use tokio::{net::UdpSocket, time::advance};

struct Fixture {
    tunnel: FakeTunnel,
    server: Server<FakeTunnel>,
    _state: TempDir,
}

fn fixture(include: &[&str], exclude: &[&str], upstreams: Vec<SocketAddr>) -> Fixture {
    let state = TempDir::new().unwrap();
    let owned = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let targets = Targets::parse(&owned(include), &owned(exclude)).unwrap();
    let names = FakeMap::load(state.path().join("names"), today()).unwrap();
    let router = Arc::new(Router::new(targets, names));
    let tunnel = FakeTunnel::new();
    let server = Server::new(tunnel.clone(), router, upstreams);
    Fixture { tunnel, server, _state: state }
}

fn corp() -> Fixture {
    fixture(&["*.corp.example"], &["private.corp.example"], Vec::new())
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
    server.answer(query(id, name, qtype)).await.expect("an answer").to_vec()
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
async fn aaaa_for_a_matched_name_is_nodata() {
    let f = corp();
    f.tunnel.name("wiki.corp.example", Ok(()));

    let bytes = ask(&f.server, 1, "wiki.corp.example", TYPE::AAAA).await;
    let reply = Packet::parse(&bytes).unwrap();

    assert_eq!(reply.rcode(), RCODE::NoError);
    assert_eq!(reply.answers.len(), 0);
    assert_eq!(soa_minimum(&reply), Some(5));
}

#[tokio::test]
async fn mx_for_a_matched_name_is_nodata() {
    let f = corp();
    f.tunnel.name("wiki.corp.example", Ok(()));

    let bytes = ask(&f.server, 1, "wiki.corp.example", TYPE::MX).await;
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
async fn stub(canned: &'static [u8]) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (seen, queries) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buf = [0_u8; 512];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let mut reply = canned.to_vec();
            reply[..2].copy_from_slice(&buf[..2]);
            seen.send(buf[..n].to_vec()).ok();
            socket.send_to(&reply, from).await.ok();
        }
    });
    (addr, queries)
}

const CANNED: &[u8] = b"\x00\x00\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00 the stub's own bytes";

#[tokio::test]
async fn an_excluded_name_is_answered_by_the_upstream() {
    let (upstream, mut queries) = stub(CANNED).await;
    let f = fixture(&["*.corp.example"], &["private.corp.example"], vec![upstream]);
    let asked = query(0xbeef, "private.corp.example", TYPE::A);

    let answer = f.server.answer(asked.clone()).await.unwrap();

    let mut expected = CANNED.to_vec();
    expected[..2].copy_from_slice(&[0xbe, 0xef]);
    assert_eq!(answer.to_vec(), expected);
    assert_eq!(queries.recv().await.unwrap(), asked.to_vec());
    assert_eq!(f.tunnel.resolves().len(), 0);
}

#[tokio::test]
async fn an_unmatched_name_under_an_exact_target_goes_upstream() {
    let (upstream, _queries) = stub(CANNED).await;
    let f = fixture(&["host.corp.example"], &[], vec![upstream]);

    let answer = f.server.answer(query(5, "a.host.corp.example", TYPE::A)).await.unwrap();

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
    let f = fixture(&["*.corp.example"], &[], upstreams);

    let bytes = ask(&f.server, 3, "elsewhere.example", TYPE::A).await;
    let reply = Packet::parse(&bytes).unwrap();

    assert_eq!(reply.id(), 3);
    assert_eq!(reply.rcode(), RCODE::ServerFailure);
    assert_eq!(reply.questions.len(), 1);
}

#[tokio::test]
async fn garbage_gets_no_answer() {
    let f = corp();

    assert!(f.server.answer(Bytes::from_static(b"\x01\x02\x03")).await.is_none());
    assert!(f.server.answer(Bytes::new()).await.is_none());
}

#[tokio::test]
async fn an_implausible_name_is_nxdomain_without_a_lookup() {
    let f = corp();

    for name in ["bad name.corp.example", "new\nline.corp.example", "caf\u{e9}.corp.example", "a\tb.corp.example"] {
        let bytes = f.server.answer(raw_query(1, name)).await.expect("an answer");
        let reply = Packet::parse(&bytes).unwrap();
        assert_eq!(reply.rcode(), RCODE::NameError, "{name:?}");
    }
    assert_eq!(f.tunnel.resolves().len(), 0);
}
