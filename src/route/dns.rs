//! The DNS server behind [`DNS_ADDR`](crate::route::DNS_ADDR). The resolver sends it only queries
//! under the routed domains. A name the targets route is checked on the remote through the relay
//! and, if it exists, an `A` query gets the name's fake address; every other name goes, byte for
//! byte, to the normal upstream servers.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use anyhow::Context as _;
use bytes::Bytes;
use simple_dns::{
    CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, RCODE, ResourceRecord, TYPE,
    rdata::{A, RData, SOA},
};
use sshunnel_mux::frame::ResolveErrKind;
use tokio::{
    net::UdpSocket,
    time::{Instant, timeout},
};

use crate::{
    base::Res,
    route::{names::today, router::Router, stack::Dns, targets::normalize},
    tunnel::Tunnel,
};

/// How long an answer built here may be cached by the app: short, so a stale fake address fades
/// soon after an exit.
pub const TTL: Duration = Duration::from_secs(5);
/// How long the relay's verdict on a name is reused, found or not.
pub const CACHE: Duration = Duration::from_secs(60);
/// How long each upstream gets to answer a forwarded query.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
/// Large enough for any answer the stack would deliver in one UDP datagram from an EDNS upstream.
const UPSTREAM_BUF: usize = 4096;
/// The zone negative answers claim to come from; `.invalid` can never exist, so it can't clash.
const SOA_ZONE: &str = "sshunnel.invalid";
const MAX_NAME: usize = 253;
const MAX_LABEL: usize = 63;

/// Answers the queries the netstack hands it.
pub struct Server<T: Tunnel> {
    tunnel: T,
    router: Arc<Router>,
    upstreams: Vec<SocketAddr>,
    /// Normalized name to when the relay last said whether it exists. Holds only the last
    /// [`CACHE`] of names: inserting prunes the rest.
    cache: Mutex<HashMap<String, (Instant, bool)>>,
}

impl<T: Tunnel> Server<T> {
    /// A server whose unrouted names go to `upstreams`, tried in order.
    #[must_use]
    pub fn new(tunnel: T, router: Arc<Router>, upstreams: Vec<SocketAddr>) -> Self {
        Self {
            tunnel,
            router,
            upstreams,
            cache: Mutex::new(HashMap::new()),
        }
    }

    async fn respond(&self, query: &Bytes) -> Option<Bytes> {
        let packet = Packet::parse(query).ok()?;
        if packet.has_flags(PacketFlag::RESPONSE) {
            return None;
        }
        let [question] = packet.questions.as_slice() else { return None };
        let name = question.qname.to_string();

        if !self.router.targets().routes_name(&name) {
            return match self.forward(query).await {
                Some(answer) => Some(answer),
                None => reply(&packet, RCODE::ServerFailure, Vec::new(), false),
            };
        }

        // The fake map's state file is whitespace-separated, and the remote couldn't resolve such
        // a name anyway.
        let name = normalize(&name);
        if !plausible(&name) {
            return reply(&packet, RCODE::NameError, Vec::new(), true);
        }

        match self.exists(&name).await {
            Ok(false) => reply(&packet, RCODE::NameError, Vec::new(), true),
            Err(()) => reply(&packet, RCODE::ServerFailure, Vec::new(), false),
            Ok(true) if is_a_in(question) => {
                let addr = self.router.names().address(&name, today());
                let record = ResourceRecord::new(question.qname.clone(), CLASS::IN, ttl_secs(), RData::A(A::from(addr)));
                reply(&packet, RCODE::NoError, vec![record], false)
            }
            Ok(true) => reply(&packet, RCODE::NoError, Vec::new(), true),
        }
    }

    /// Whether the relay finds `name`, from the cache when it asked within [`CACHE`]. A failed
    /// lookup is `Err` and isn't cached: it may be transient.
    async fn exists(&self, name: &str) -> Result<bool, ()> {
        if let Some(found) = self.cached(name) {
            return Ok(found);
        }

        let found = match self.tunnel.resolve(name).await {
            Ok(()) => true,
            Err(e) if e.kind == ResolveErrKind::NoSuchName => false,
            Err(e) => {
                tracing::debug!(name, error = %e.reason, "the relay could not look up the name");
                return Err(());
            }
        };

        let mut cache = self.cache();
        cache.retain(|_, (at, _)| at.elapsed() < CACHE);
        cache.insert(name.to_owned(), (Instant::now(), found));
        Ok(found)
    }

    fn cached(&self, name: &str) -> Option<bool> {
        self.cache().get(name).filter(|(at, _)| at.elapsed() < CACHE).map(|&(_, found)| found)
    }

    /// Poisoning can't leave the map inconsistent (each update is one insert).
    fn cache(&self) -> std::sync::MutexGuard<'_, HashMap<String, (Instant, bool)>> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The first answer to the unchanged query from any upstream, tried in turn.
    async fn forward(&self, query: &Bytes) -> Option<Bytes> {
        for &upstream in &self.upstreams {
            match timeout(UPSTREAM_TIMEOUT, ask_upstream(upstream, query)).await {
                Ok(Ok(answer)) => return Some(answer),
                Ok(Err(e)) => tracing::debug!(%upstream, error = %format!("{e:#}"), "the upstream failed"),
                Err(_) => tracing::debug!(%upstream, "the upstream timed out"),
            }
        }
        None
    }
}

impl<T: Tunnel> Dns for Server<T> {
    async fn answer(&self, query: Bytes) -> Option<Bytes> {
        self.respond(&query).await
    }
}

/// Sends `query` to `upstream` from a fresh ephemeral socket and returns the first reply whose id
/// matches. The socket is connected, so the kernel drops datagrams from anyone else.
async fn ask_upstream(upstream: SocketAddr, query: &[u8]) -> Res<Bytes> {
    let local: SocketAddr = if upstream.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(local).await.context("binding a socket for the upstream")?;
    socket.connect(upstream).await.context("connecting to the upstream")?;
    socket.send(query).await.context("sending the query to the upstream")?;

    let mut buf = vec![0_u8; UPSTREAM_BUF];
    loop {
        let n = socket.recv(&mut buf).await.context("reading the upstream's answer")?;
        if n >= 2 && buf[..2] == query[..2] {
            return Ok(Bytes::copy_from_slice(&buf[..n]));
        }
    }
}

/// Builds the reply to `query`: its id and question echoed, `answers`, and for a negative answer
/// (`negative`) the synthetic SOA that sets the negative-cache time.
fn reply(query: &Packet<'_>, rcode: RCODE, answers: Vec<ResourceRecord<'_>>, negative: bool) -> Option<Bytes> {
    let mut packet = Packet::new_reply(query.id());
    packet.set_flags(PacketFlag::RECURSION_AVAILABLE);
    if query.has_flags(PacketFlag::RECURSION_DESIRED) {
        packet.set_flags(PacketFlag::RECURSION_DESIRED);
    }
    *packet.rcode_mut() = rcode;
    packet.questions.clone_from(&query.questions);
    packet.answers = answers;
    if negative {
        packet.name_servers.push(soa());
    }

    match packet.build_bytes_vec() {
        Ok(bytes) => Some(Bytes::from(bytes)),
        Err(e) => {
            tracing::warn!(error = %e, "building a DNS reply failed");
            None
        }
    }
}

fn soa() -> ResourceRecord<'static> {
    let zone = Name::new_unchecked(SOA_ZONE);
    let rdata = SOA {
        mname: zone.clone(),
        rname: Name::new_unchecked("hostmaster.sshunnel.invalid"),
        serial: 1,
        refresh: 3600,
        retry: 600,
        expire: 86400,
        minimum: ttl_secs(),
    };
    ResourceRecord::new(zone, CLASS::IN, ttl_secs(), RData::SOA(rdata))
}

#[allow(clippy::cast_possible_truncation, reason = "TTL is five seconds")]
const fn ttl_secs() -> u32 {
    TTL.as_secs() as u32
}

fn is_a_in(question: &Question<'_>) -> bool {
    question.qtype == QTYPE::TYPE(TYPE::A) && matches!(question.qclass, QCLASS::CLASS(CLASS::IN) | QCLASS::ANY)
}

/// Whether `name` (already normalized) could be a hostname: ASCII letters, digits, `-`, `_`,
/// labels of 1 to 63 bytes, and at most 253 bytes in all.
fn plausible(name: &str) -> bool {
    name.len() <= MAX_NAME
        && name
            .split('.')
            .all(|label| (1..=MAX_LABEL).contains(&label.len()) && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
}

#[cfg(test)]
mod unit {
    use super::plausible;

    // The wire format already caps labels at 63 bytes and names at 253, so the parser never lets
    // these through; the length checks are a backstop that these pin down.
    #[test]
    fn plausible_names_are_hostnames() {
        assert!(plausible("wiki.corp.example"));
        assert!(plausible("_dmarc.a-b.corp.example"));
        assert!(plausible(&format!("{}.example", "a".repeat(63))));
        assert!(plausible(&vec!["a".repeat(61); 4].join(".")));

        assert!(!plausible(""));
        assert!(!plausible("a..b"));
        assert!(!plausible("bad name"));
        assert!(!plausible("caf\u{e9}.example"));
        assert!(!plausible(&format!("{}.example", "a".repeat(64))));
        assert!(!plausible(&format!("{}.example", vec!["a".repeat(60); 5].join("."))));
    }
}
