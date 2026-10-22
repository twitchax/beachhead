//! The DNS server behind [`DNS_ADDR`](crate::route::DNS_ADDR). The resolver sends it only queries
//! under the routed domains and the fake ranges' reverse zones. A fake address's reverse name is
//! answered here, from the fake-address map. A name the targets route is checked on the remote
//! through the relay and, if it exists, an `A` query gets the name's fake address, and with fake v6
//! on an `AAAA` query gets its v6 fake; `HTTPS` and `SVCB` get nothing, and every other type goes to
//! the remote's resolver, with any real address taken out of its answer. Every other name goes,
//! byte for byte, to the normal upstream servers.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use anyhow::Context as _;
use bytes::Bytes;
use simple_dns::{
    CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, RCODE, ResourceRecord, TYPE,
    rdata::{A, AAAA, PTR, RData, SOA},
};
use sshunnel_mux::frame::{ResolveErrKind, Transport};
use tokio::{
    net::UdpSocket,
    time::{Instant, timeout},
};

use crate::{
    base::Res,
    route::{
        FAKE_RANGE, FAKE_RANGE6,
        names::{fake_v4, fake_v6, today},
        reverse::{self, Reverse},
        router::Router,
        stack::Dns,
        targets::{normalize, plausible},
    },
    tunnel::Tunnel,
};

/// How long an answer built here may be cached by the app: short, so a stale fake address fades
/// soon after an exit.
pub const TTL: Duration = Duration::from_secs(5);
/// How long the relay's verdict on a name is reused, found or not.
pub const CACHE: Duration = Duration::from_secs(60);
/// How long the remote's resolver gets to answer a matched name's query, through the relay.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// How long each upstream gets to answer a forwarded query.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
/// The largest DNS message UDP can carry, so no upstream answer is cut short. Forwarding is UDP
/// only: an answer too large for it comes back truncated (TC), and the resolver's retry over TCP
/// fails.
const UPSTREAM_BUF: usize = 65535;
/// The zone negative answers claim to come from; `.invalid` can never exist, so it can't clash.
const SOA_ZONE: &str = "sshunnel.invalid";
/// The types a matched name gets answered here and never from the remote: A and AAAA get fakes;
/// HTTPS and SVCB get NODATA, since their address hints would hand apps real addresses (browsers
/// fall back to A and AAAA).
const LOCAL: [TYPE; 4] = [TYPE::A, TYPE::AAAA, TYPE::HTTPS, TYPE::SVCB];

/// Answers the queries the netstack hands it.
pub struct Server<T: Tunnel> {
    tunnel: T,
    router: Arc<Router>,
    upstreams: Vec<SocketAddr>,
    /// Whether AAAA answers a matched name's v6 fake, as the helper decided; NODATA otherwise.
    fake_v6: bool,
    /// Normalized name to when the relay last said whether it exists. Holds only the last
    /// [`CACHE`] of names: inserting prunes the rest.
    cache: Mutex<HashMap<String, (Instant, bool)>>,
}

impl<T: Tunnel> Server<T> {
    /// A server whose unrouted names go to `upstreams`, tried in order, and whose matched names get
    /// AAAA answers when `fake_v6` is on.
    #[must_use]
    pub fn new(tunnel: T, router: Arc<Router>, upstreams: Vec<SocketAddr>, fake_v6: bool) -> Self {
        Self {
            tunnel,
            router,
            upstreams,
            fake_v6,
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

        match reverse::parse(&name) {
            Reverse::Addr(addr) if is_fake(addr) => return self.reverse(&packet, question, addr),
            // No address's name, but in a fake zone: NODATA, since an NXDOMAIN for a name short of
            // an address would tell an RFC 8020 resolver every address under it is unassigned.
            Reverse::InZone => return reply(&packet, RCODE::NoError, Vec::new(), true),
            Reverse::Addr(_) | Reverse::Outside => {}
        }

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

        if LOCAL.into_iter().any(|local| question.qtype == QTYPE::TYPE(local)) {
            self.fake(&packet, question, &name).await
        } else {
            self.remote(query, &packet, &name).await
        }
    }

    /// The query for the reverse name of `addr`, a fake address: PTR answers the name it was handed
    /// out for, and any other type gets NODATA. An address no name holds is NXDOMAIN.
    fn reverse(&self, packet: &Packet<'_>, question: &Question<'_>, addr: IpAddr) -> Option<Bytes> {
        let v4 = match addr {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(v6) => fake_v4(v6),
        };
        let Some(name) = v4.and_then(|v4| self.router.names().name(v4).map(str::to_owned)) else {
            return reply(packet, RCODE::NameError, Vec::new(), true);
        };
        if !is_in(question, TYPE::PTR) {
            return reply(packet, RCODE::NoError, Vec::new(), true);
        }
        let record = ResourceRecord::new(question.qname.clone(), CLASS::IN, ttl_secs(), RData::PTR(PTR(Name::new_unchecked(&name))));
        reply(packet, RCODE::NoError, vec![record], false)
    }

    /// A matched name's [`LOCAL`] types, by whether the relay finds it.
    async fn fake(&self, packet: &Packet<'_>, question: &Question<'_>, name: &str) -> Option<Bytes> {
        match self.exists(name).await {
            Ok(false) => reply(packet, RCODE::NameError, Vec::new(), true),
            Err(()) => reply(packet, RCODE::ServerFailure, Vec::new(), false),
            Ok(true) if is_in(question, TYPE::A) => {
                let addr = self.router.names().address(name, today());
                let record = ResourceRecord::new(question.qname.clone(), CLASS::IN, ttl_secs(), RData::A(A::from(addr)));
                reply(packet, RCODE::NoError, vec![record], false)
            }
            Ok(true) if self.fake_v6 && is_in(question, TYPE::AAAA) => {
                let addr = fake_v6(self.router.names().address(name, today()));
                let record = ResourceRecord::new(question.qname.clone(), CLASS::IN, ttl_secs(), RData::AAAA(AAAA::from(addr)));
                reply(packet, RCODE::NoError, vec![record], false)
            }
            Ok(true) => reply(packet, RCODE::NoError, Vec::new(), true),
        }
    }

    /// Any other type for a matched name, asked of the remote's resolver as it came. The answer
    /// keeps its id, flags (TC included), rcode and records, but loses every record that
    /// [`carries_address`], so neither glue nor an ANY answer can hand out a real address: the app
    /// asks for the target's A and gets its fake. The
    /// remote's nameservers don't know a name only its `/etc/hosts` has, so their NXDOMAIN for a
    /// name the relay finds becomes NODATA, which keeps that name's fake A from hiding behind it.
    async fn remote(&self, query: &Bytes, packet: &Packet<'_>, name: &str) -> Option<Bytes> {
        let servfail = || reply(packet, RCODE::ServerFailure, Vec::new(), false);
        let answer = match timeout(QUERY_TIMEOUT, self.tunnel.query(query.clone(), Transport::Udp)).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(e)) => {
                tracing::debug!(name, error = %e.reason, "the remote's resolver failed");
                return servfail();
            }
            Err(_) => {
                tracing::debug!(name, "the remote's resolver timed out");
                return servfail();
            }
        };
        let mut answer = match Packet::parse(&answer) {
            Ok(answer) => answer,
            Err(e) => {
                tracing::debug!(name, error = %e, "the remote's resolver sent something other than DNS");
                return servfail();
            }
        };

        for section in [&mut answer.answers, &mut answer.name_servers, &mut answer.additional_records] {
            section.retain(|record| !carries_address(record));
        }
        if answer.rcode() == RCODE::NameError {
            match self.exists(name).await {
                Ok(true) => *answer.rcode_mut() = RCODE::NoError,
                Ok(false) => {}
                // An NXDOMAIN cached on a failed lookup could hide the name's fake A for as long as
                // the remote's SOA says; SERVFAIL isn't cached for long.
                Err(()) => return servfail(),
            }
        }
        encode(&answer)
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
    encode(&packet)
}

/// `packet` on the wire, its names compressed where their types allow it.
fn encode(packet: &Packet<'_>) -> Option<Bytes> {
    match packet.build_bytes_vec_compressed() {
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

/// Whether `question` asks for `qtype` in class IN (or any class).
fn is_in(question: &Question<'_>, qtype: TYPE) -> bool {
    question.qtype == QTYPE::TYPE(qtype) && matches!(question.qclass, QCLASS::CLASS(CLASS::IN) | QCLASS::ANY)
}

/// Whether `addr` is inside a fake range, whose reverse zone is answered here.
fn is_fake(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => FAKE_RANGE.contains(&v4),
        IpAddr::V6(v6) => FAKE_RANGE6.contains(&v6),
    }
}

/// Whether `record` can hand out a real address: A and AAAA, and HTTPS and SVCB through their
/// `ipv4hint` and `ipv6hint`.
fn carries_address(record: &ResourceRecord<'_>) -> bool {
    matches!(record.rdata, RData::A(_) | RData::AAAA(_) | RData::HTTPS(_) | RData::SVCB(_))
}
