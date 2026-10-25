//! Local forwards, `ssh -L` style: listen locally; for TCP, open a stream through the relay for
//! each connection and pump it; for UDP, open a flow for each local sender and carry its datagrams
//! both ways.

use std::{
    future::Future,
    io::ErrorKind,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context as _, anyhow, bail, ensure};
use bytes::Bytes;
use sshunnel_mux::{
    FlowEvent,
    base::{Err, Res, Void},
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::Notify,
    time::Instant,
};
use tracing::{debug, warn};

use crate::{
    flows::{FlowTable, FlowTask, Held},
    tunnel::{Conn as _, Flow, FlowSender as _, SenderOf, Tunnel},
};

/// What a forward carries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Proto {
    #[default]
    Tcp,
    Udp,
}

/// One `-L [bind_address:]port:host:hostport[/udp]` spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forward {
    /// Where to listen locally; `localhost` (each family's loopback) unless the spec names one.
    pub bind: String,
    /// The local port; 0 picks a free one.
    pub bind_port: u16,
    /// The host the relay dials, resolved on the remote.
    pub host: String,
    /// The port the relay dials.
    pub port: u16,
    /// What the forward carries.
    pub proto: Proto,
}

impl FromStr for Forward {
    type Err = Err;

    fn from_str(spec: &str) -> Res<Self> {
        // Docker's suffix: no address or host has a `/` in it.
        let (body, proto) = match spec.split_once('/') {
            None => (spec, Proto::Tcp),
            Some((body, "tcp")) => (body, Proto::Tcp),
            Some((body, "udp")) => (body, Proto::Udp),
            Some((_, suffix)) => bail!("`{spec}` ends in `/{suffix}`, not /tcp or /udp"),
        };
        let parts = split_outside_brackets(body);
        let (bind, bind_port, host, port) = match parts.as_slice() {
            [bind_port, host, port] => ("localhost", *bind_port, *host, *port),
            [bind, bind_port, host, port] => (*bind, *bind_port, *host, *port),
            _ => bail!("`{spec}` is not [bind_address:]port:host:hostport[/udp]"),
        };
        let port_of = |s: &str| s.parse::<u16>().map_err(|e| anyhow!("`{s}` in `{spec}` is not a port: {e}"));
        let unbracket = |s: &str| s.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(s).to_owned();
        let (bind, host) = (unbracket(bind), unbracket(host));
        if bind.is_empty() || host.is_empty() {
            bail!("`{spec}` has an empty address");
        }
        Ok(Self {
            bind,
            bind_port: port_of(bind_port)?,
            host,
            port: port_of(port)?,
            proto,
        })
    }
}

impl std::fmt::Display for Forward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{} -> {}:{}", self.bind, self.bind_port, self.host, self.port)?;
        match self.proto {
            Proto::Tcp => Ok(()),
            Proto::Udp => f.write_str("/udp"),
        }
    }
}

/// Splits on `:` except inside `[...]`, so IPv6 literals survive.
fn split_outside_brackets(spec: &str) -> Vec<&str> {
    let mut parts = Vec::with_capacity(4);
    let (mut depth, mut start) = (0u32, 0);
    for (i, c) in spec.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            ':' if depth == 0 => {
                parts.push(&spec[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&spec[start..]);
    parts
}

impl Forward {
    /// Binds the local listeners, one per address and all on one port. As for `ssh -L`,
    /// `localhost` means each family's loopback (`127.0.0.1` and `::1`), whatever the resolver
    /// says it is; any other name binds every address it resolves to. An address that won't bind
    /// (no IPv6 on this host, the port taken on one family) is skipped, as long as one binds.
    ///
    /// # Errors
    ///
    /// Fails for a UDP forward, or when the name doesn't resolve or no address binds.
    pub async fn bind(&self) -> Res<Vec<TcpListener>> {
        ensure!(self.proto == Proto::Tcp, "`{self}` is a UDP forward");
        self.listen().await
    }

    /// Binds the local UDP sockets, one per address and all on one port, by [`Self::bind`]'s rules.
    ///
    /// # Errors
    ///
    /// Fails for a TCP forward, or when the name doesn't resolve or no address binds.
    pub async fn bind_udp(&self) -> Res<Vec<UdpSocket>> {
        ensure!(self.proto == Proto::Udp, "`{self}` is a TCP forward");
        self.listen().await
    }

    async fn listen<S: Listen>(&self) -> Res<Vec<S>> {
        let addrs: Vec<SocketAddr> = if self.bind.eq_ignore_ascii_case("localhost") {
            vec![(Ipv4Addr::LOCALHOST, self.bind_port).into(), (Ipv6Addr::LOCALHOST, self.bind_port).into()]
        } else {
            tokio::net::lookup_host((self.bind.as_str(), self.bind_port))
                .await
                .with_context(|| format!("resolving {}", self.bind))?
                .collect()
        };
        let mut listeners: Vec<S> = Vec::with_capacity(addrs.len());
        let mut failed = None;
        for mut addr in addrs {
            // Port 0 picks a free port once; every other address shares it.
            if let Some(first) = listeners.first() {
                addr.set_port(first.local_addr().context("reading a listener's address")?.port());
            }
            match S::bind(addr).await {
                Ok(listener) => listeners.push(listener),
                Err(e) => {
                    // A port taken on one family is worth a word, since a client may well reach
                    // whatever holds it. A family the host lacks (a container without IPv6, a
                    // kernel booted with it disabled) is routine, whichever errno says so.
                    if e.kind() == ErrorKind::AddrInUse {
                        warn!("not listening on {addr}: {e}");
                    } else {
                        debug!(%addr, "not listening: {e}");
                    }
                    failed.get_or_insert(Err::new(e).context(format!("listening on {addr}")));
                }
            }
        }
        match failed {
            Some(e) if listeners.is_empty() => Err(e),
            _ if listeners.is_empty() => bail!("{} resolves to no address", self.bind),
            _ => Ok(listeners),
        }
    }
}

/// What a forward listens with, bound alike whatever it carries.
trait Listen: Sized {
    fn bind(addr: SocketAddr) -> impl Future<Output = std::io::Result<Self>> + Send;
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
}

impl Listen for TcpListener {
    fn bind(addr: SocketAddr) -> impl Future<Output = std::io::Result<Self>> + Send {
        Self::bind(addr)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Self::local_addr(self)
    }
}

impl Listen for UdpSocket {
    fn bind(addr: SocketAddr) -> impl Future<Output = std::io::Result<Self>> + Send {
        Self::bind(addr)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Self::local_addr(self)
    }
}

/// The pause after a failed accept, doubling with each failure in a row up to [`MAX_BACKOFF`].
const MIN_BACKOFF: Duration = Duration::from_millis(5);
const MAX_BACKOFF: Duration = Duration::from_secs(1);

/// Accepts connections on `listener` until dropped, opening a stream to `host:port` for each.
///
/// # Errors
///
/// None: like `ssh -L`, it outlives a failed accept (EMFILE once the process is out of
/// descriptors) by logging it and retrying after a backoff, and a failed connection is logged and
/// dropped.
pub async fn serve<T: Tunnel>(tunnel: T, listener: TcpListener, host: Arc<str>, port: u16) -> Void {
    let mut backoff = MIN_BACKOFF;
    loop {
        let (mut socket, peer) = match listener.accept().await {
            Ok(accepted) => {
                backoff = MIN_BACKOFF;
                accepted
            }
            Err(e) => {
                // Out of descriptors, the connection stays queued and the next accept fails the
                // same way at once: wait for live connections to close rather than spin.
                warn!("accepting a local connection: {e}; retrying in {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };
        let (tunnel, host) = (tunnel.clone(), Arc::clone(&host));
        tokio::spawn(async move {
            // Frames already batch; Nagle would only add latency on top.
            let _ = socket.set_nodelay(true);
            match tunnel.open(&host, port).await {
                Ok(conn) => match conn.pump(&mut socket).await {
                    Ok(traffic) => debug!(%peer, sent = traffic.sent, received = traffic.received, "connection closed"),
                    Err(e) => {
                        // The remote reset (or the session ended): a clean close here would let an
                        // app reading to EOF take the cut-short stream for a whole one.
                        let _ = socket.set_zero_linger();
                        debug!(%peer, "connection failed: {e:#}");
                    }
                },
                Err(e) => warn!(%peer, "{e:#}"),
            }
        });
    }
}

/// A UDP forward's flow: the listener a datagram came in on, and the local sender it came from.
type FlowKey = (SocketAddr, SocketAddr);

/// The session's UDP forwards: one flow table across every UDP listener, keyed by (listener
/// address, sender address), so the cap counts every flow the session holds.
#[derive(Clone)]
pub struct UdpForwards<T: Tunnel> {
    tunnel: T,
    shared: Arc<Shared<SenderOf<T>>>,
}

struct Shared<S> {
    table: Mutex<FlowTable<FlowKey, Entry<S>>>,
    /// Tells an entry from earlier ones under its key, so an open that finishes after its entry
    /// went can't take a newer entry's place.
    generations: AtomicU64,
    /// Wakes the sweep for a new flow, whose deadline may come first.
    added: Notify,
}

struct Entry<S> {
    generation: u64,
    state: State<S>,
}

enum State<S> {
    /// The relay hasn't answered yet: the sender's datagrams wait here.
    Opening { held: Held, _open: FlowTask },
    /// Datagrams go straight to the flow, and a task carries its replies back.
    Open { sender: S, _replies: FlowTask },
}

impl<T: Tunnel> UdpForwards<T> {
    #[must_use]
    pub fn new(tunnel: T) -> Self {
        Self {
            tunnel,
            shared: Arc::new(Shared {
                table: Mutex::new(FlowTable::new()),
                generations: AtomicU64::new(0),
                added: Notify::new(),
            }),
        }
    }

    fn table(&self) -> MutexGuard<'_, FlowTable<FlowKey, Entry<SenderOf<T>>>> {
        self.shared.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Carries datagrams between `socket`, one of the session's UDP listeners, and `host:port`
    /// on the remote. Each local sender is a flow, opened by its first datagram; its replies go
    /// back to it from `socket`.
    ///
    /// # Errors
    ///
    /// Fails only when `socket` has no address. Like [`serve`], it outlives a failed receive by
    /// logging it and retrying after a backoff, and a failed open is logged and its datagrams
    /// dropped.
    pub async fn serve(self, socket: UdpSocket, host: Arc<str>, port: u16) -> Void {
        let listener = socket.local_addr().context("reading a UDP listener's address")?;
        let socket = Arc::new(socket);
        // A datagram can be 65 535 bytes; untouched pages of this buffer cost nothing.
        let mut buf = vec![0u8; 65_535];
        let mut backoff = MIN_BACKOFF;
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, sender)) => {
                    backoff = MIN_BACKOFF;
                    self.datagram(&socket, (listener, sender), Bytes::copy_from_slice(&buf[..n]), &host, port);
                }
                Err(e) => {
                    warn!("receiving on {listener}: {e}; retrying in {backoff:?}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    }

    /// Idles flows out at the table's deadline, for as long as the session runs. An idle flow
    /// resets as it drops.
    ///
    /// # Errors
    ///
    /// None: it runs until dropped.
    pub async fn sweep(self) -> Void {
        loop {
            let added = self.shared.added.notified();
            let deadline = self.table().deadline();
            match deadline {
                Some(deadline) => tokio::select! {
                    () = tokio::time::sleep_until(deadline) => {
                        // A deadline that passed may since have moved later: nothing expires.
                        let idle = self.table().expire(Instant::now());
                        if !idle.is_empty() {
                            debug!(flows = idle.len(), "idled out");
                        }
                    }
                    () = added => {}
                },
                None => added.await,
            }
        }
    }

    /// Sends `key`'s datagram on: through its open flow, into the hold of one still opening, or
    /// opening a flow for it. Never waits: a full queue or hold drops it.
    fn datagram(&self, socket: &Arc<UdpSocket>, key: FlowKey, datagram: Bytes, host: &Arc<str>, port: u16) {
        let now = Instant::now();
        let mut table = self.table();
        if let Some(entry) = table.get_mut(&key) {
            match &mut entry.state {
                State::Opening { held, .. } => held.push(datagram),
                State::Open { sender, .. } => {
                    sender.try_send(datagram);
                }
            }
            // Opening or open, the sender is still sending: a slow open mustn't idle out under it.
            table.sent(&key, now);
            return;
        }
        let generation = self.shared.generations.fetch_add(1, Ordering::Relaxed);
        // Spawned under the lock, so the open can't look for its entry before the entry is in.
        let open = tokio::spawn(self.clone().open(Arc::clone(socket), key, generation, Arc::clone(host), port));
        let mut held = Held::default();
        held.push(datagram);
        let state = State::Opening {
            held,
            _open: FlowTask(open.abort_handle()),
        };
        let evicted = table.insert(key, Entry { generation, state }, now);
        drop(table);
        // The least recently used flow, at the cap: it resets as it drops, and so does its open,
        // outside the lock.
        drop(evicted);
        self.shared.added.notify_one();
    }

    /// Opens `key`'s flow and, when its entry is still the one that asked, sends what it holds
    /// and starts carrying replies.
    async fn open(self, socket: Arc<UdpSocket>, key: FlowKey, generation: u64, host: Arc<str>, port: u16) {
        let opened = self.tunnel.open_udp(&host, port).await;
        let mut table = self.table();
        // Its entry going aborts this task, but only where it waits: past its open, on another
        // worker, it can still get here after its entry idled out or was evicted, and its sender
        // may have opened another since. The flow drops either way, which resets it. No
        // deterministic test reaches this; the abort is what the tests see.
        let Some(entry) = table.get_mut(&key).filter(|entry| entry.generation == generation) else {
            return;
        };
        match opened {
            Ok(flow) => {
                let State::Opening { held, .. } = &mut entry.state else { return };
                let held = held.take();
                let sender = flow.sender();
                for datagram in held {
                    sender.try_send(datagram);
                }
                let replies = tokio::spawn(self.clone().replies(flow, socket, key, generation));
                // Replacing `Opening` drops its `_open`, which would abort this task, but it no longer
                // waits, so it finishes.
                entry.state = State::Open {
                    sender,
                    _replies: FlowTask(replies.abort_handle()),
                };
                table.sent(&key, Instant::now());
            }
            Err(e) => {
                table.remove(&key);
                drop(table);
                warn!(sender = %key.1, "{e:#}");
            }
        }
    }

    /// Carries `flow`'s replies to `key`'s sender, from the listener it sent to, until the flow
    /// ends. Its entry goes with it, so the sender's next datagram opens a fresh flow.
    async fn replies(self, mut flow: T::Flow, socket: Arc<UdpSocket>, key: FlowKey, generation: u64) {
        let (listener, sender) = key;
        loop {
            match flow.recv().await {
                Some(FlowEvent::Datagram(datagram)) => {
                    if let Err(e) = socket.send_to(&datagram, sender).await {
                        debug!(%listener, %sender, "replying: {e}");
                    }
                    let mut table = self.table();
                    if table.get_mut(&key).is_some_and(|entry| entry.generation == generation) {
                        table.replied(&key, Instant::now());
                    }
                }
                // User space has no ICMP to tell a local sender with, so the flow just ends.
                Some(FlowEvent::Error(kind)) => {
                    debug!(%listener, %sender, "the flow failed: {kind:?}");
                    break;
                }
                None => {
                    debug!(%listener, %sender, "the relay ended the flow");
                    break;
                }
            }
        }
        let ended = {
            let mut table = self.table();
            let current = table.get_mut(&key).is_some_and(|entry| entry.generation == generation);
            current.then(|| table.remove(&key))
        };
        // Its reply task is this one, which is finishing anyway.
        drop(ended);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.table().len()
    }
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpSocket, TcpStream},
        time::timeout,
    };

    use super::*;
    use sshunnel_mux::frame::OpenErrKind;

    use crate::tests::{self, FakeTunnel, until};

    fn fwd(bind: &str, bind_port: u16, host: &str, port: u16) -> Forward {
        Forward {
            bind: bind.to_owned(),
            bind_port,
            host: host.to_owned(),
            port,
            proto: Proto::Tcp,
        }
    }

    fn udp(bind: &str, bind_port: u16, host: &str, port: u16) -> Forward {
        Forward {
            proto: Proto::Udp,
            ..fwd(bind, bind_port, host, port)
        }
    }

    #[test]
    fn specs_parse_like_ssh_dash_l() {
        assert_eq!("8080:server.lan:80".parse::<Forward>().unwrap(), fwd("localhost", 8080, "server.lan", 80));
        assert_eq!("0.0.0.0:8080:10.0.0.5:22".parse::<Forward>().unwrap(), fwd("0.0.0.0", 8080, "10.0.0.5", 22));
        assert_eq!("[::1]:8080:[fd00::5]:443".parse::<Forward>().unwrap(), fwd("::1", 8080, "fd00::5", 443));
        assert_eq!("0:localhost:5432".parse::<Forward>().unwrap(), fwd("localhost", 0, "localhost", 5432));
    }

    fn has_ipv6_loopback() -> bool {
        std::net::TcpListener::bind("[::1]:0").is_ok()
    }

    fn addrs(listeners: &[TcpListener]) -> Vec<SocketAddr> {
        listeners.iter().map(|l| l.local_addr().unwrap()).collect()
    }

    #[tokio::test]
    async fn localhost_listens_on_each_loopback_on_one_port() {
        let listeners = "0:h:1".parse::<Forward>().unwrap().bind().await.unwrap();
        let port = listeners[0].local_addr().unwrap().port();
        let mut want = vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))];
        if has_ipv6_loopback() {
            want.push((Ipv6Addr::LOCALHOST, port).into());
        }
        assert_eq!(addrs(&listeners), want);
    }

    #[tokio::test]
    async fn a_port_taken_on_one_loopback_still_binds_the_other() {
        if !has_ipv6_loopback() {
            return;
        }
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = taken.local_addr().unwrap().port();
        let listeners = format!("{port}:h:1").parse::<Forward>().unwrap().bind().await.unwrap();
        assert_eq!(addrs(&listeners), [SocketAddr::from((Ipv6Addr::LOCALHOST, port))]);
    }

    #[tokio::test]
    async fn a_port_taken_on_every_loopback_fails() {
        let v4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = v4.local_addr().unwrap().port();
        let _v6 = std::net::TcpListener::bind((Ipv6Addr::LOCALHOST, port));
        let err = format!("{port}:h:1").parse::<Forward>().unwrap().bind().await.unwrap_err();
        assert!(format!("{err:#}").contains(&format!("listening on 127.0.0.1:{port}")), "{err:#}");
    }

    #[test]
    fn bad_specs_are_rejected() {
        for spec in ["8080", "8080:host", "a:b:c:d:e", "x:host:80", "8080:host:99999", "8080::80", ":8080:host:80"] {
            assert!(spec.parse::<Forward>().is_err(), "{spec} parsed");
        }
    }

    #[test]
    fn udp_specs_parse_with_a_suffix() {
        assert_eq!("5353:dns.corp.example:53/udp".parse::<Forward>().unwrap(), udp("localhost", 5353, "dns.corp.example", 53));
        assert_eq!("8080:server.lan:80/tcp".parse::<Forward>().unwrap(), fwd("localhost", 8080, "server.lan", 80));
        assert_eq!("[::1]:5353:[fd99::5]:53/udp".parse::<Forward>().unwrap(), udp("::1", 5353, "fd99::5", 53));
    }

    #[test]
    fn bad_suffixes_are_rejected() {
        for suffix in ["/sctp", "/", "/UDP", "/udp/udp"] {
            let err = format!("8080:server.lan:80{suffix}").parse::<Forward>().unwrap_err();
            assert!(format!("{err:#}").contains(&format!("`{suffix}`")), "{suffix}: {err:#}");
        }
    }

    #[test]
    fn a_udp_spec_displays_its_suffix() {
        assert_eq!(udp("localhost", 5353, "dns.corp.example", 53).to_string(), "localhost:5353 -> dns.corp.example:53/udp");
        assert_eq!(fwd("localhost", 8080, "server.lan", 80).to_string(), "localhost:8080 -> server.lan:80");
    }

    #[tokio::test]
    async fn bind_udp_listens_on_each_loopback_on_one_port() {
        let sockets = "0:h:1/udp".parse::<Forward>().unwrap().bind_udp().await.unwrap();
        let port = sockets[0].local_addr().unwrap().port();
        let mut want = vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))];
        if has_ipv6_loopback() {
            want.push((Ipv6Addr::LOCALHOST, port).into());
        }
        assert_eq!(sockets.iter().map(|s| s.local_addr().unwrap()).collect::<Vec<_>>(), want);
    }

    #[tokio::test]
    async fn bind_refuses_the_other_protocol() {
        assert!("0:h:1/udp".parse::<Forward>().unwrap().bind().await.is_err());
        assert!("0:h:1".parse::<Forward>().unwrap().bind_udp().await.is_err());
        assert!("0:h:1/tcp".parse::<Forward>().unwrap().bind_udp().await.is_err());
    }

    /// Waits up to 5 s of real time for `done` to hold.
    async fn eventually(mut done: impl FnMut() -> bool) {
        for _ in 0..500 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the condition never held");
    }

    /// Serves a forward of `dns.corp.example:80` to `target` on a loopback listener; returns the
    /// listener's address.
    async fn forwarded_to(target: SocketAddr) -> SocketAddr {
        let tunnel = FakeTunnel::new();
        tunnel.dial("dns.corp.example", 80, target);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(tunnel, listener, Arc::from("dns.corp.example"), 80));
        addr
    }

    /// An app connected to a forward of `target`.
    async fn app_through(target: SocketAddr) -> TcpStream {
        TcpStream::connect(forwarded_to(target).await).await.unwrap()
    }

    #[tokio::test]
    async fn a_remote_reset_resets_the_app() {
        let target = tests::resetting_server(b"partial").await.unwrap();
        let mut app = app_through(target).await;

        let mut partial = [0u8; 7];
        app.read_exact(&mut partial).await.unwrap();
        assert_eq!(&partial, b"partial");
        // The server resets once it has the byte, so the payload is read before the reset.
        app.write_all(b"!").await.unwrap();
        let next = timeout(Duration::from_secs(5), app.read(&mut partial)).await.expect("the app's read ends");
        assert_eq!(next.unwrap_err().kind(), ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn a_remote_close_still_ends_the_app_with_eof() {
        // Enough that a slow app leaves bytes queued in the forward's socket when the pump ends.
        let data = tests::pattern(7, 64 * 1024);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let sent = data.clone();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&sent).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let forward = forwarded_to(target).await;

        // A small receive window keeps the bytes queued, and the app's own half-close lets the pump
        // finish while they are: a zero-linger close then would discard them.
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        let mut app = socket.connect(forward).await.unwrap();
        app.shutdown().await.unwrap();

        let mut everything = Vec::new();
        let read = timeout(Duration::from_secs(10), app.read_to_end(&mut everything)).await.expect("the app's read ends");
        assert_eq!(read.unwrap(), data.len());
        assert!(everything == data, "every byte arrives, then EOF");
    }

    #[tokio::test]
    async fn udp_a_flow_error_ends_the_flow() {
        let closed = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let tunnel = FakeTunnel::new();
        tunnel.udp("dns.corp.example", 53, closed);
        let forwards = UdpForwards::new(tunnel.clone());
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        app.connect(listener.local_addr().unwrap()).await.unwrap();
        tokio::spawn(forwards.clone().serve(listener, Arc::from("dns.corp.example"), 53));

        // The closed port's ICMP comes back as a flow error, which ends the flow and its entry.
        app.send(b"one").await.unwrap();
        eventually(|| tunnel.flows().len() == 1 && tunnel.live_flows() == 0 && forwards.len() == 0).await;
        // So the sender's next datagram opens a fresh flow rather than feeding the dead one.
        app.send(b"two").await.unwrap();
        eventually(|| tunnel.flows().len() == 2).await;
    }

    #[tokio::test]
    async fn udp_a_flow_the_relay_ended_reopens_on_the_next_datagram() {
        let tunnel = FakeTunnel::new();
        tunnel.udp_hangup("dns.corp.example", 53);
        let forwards = UdpForwards::new(tunnel.clone());
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        app.connect(listener.local_addr().unwrap()).await.unwrap();
        tokio::spawn(forwards.clone().serve(listener, Arc::from("dns.corp.example"), 53));

        app.send(b"one").await.unwrap();
        eventually(|| tunnel.flows().len() == 1 && tunnel.live_flows() == 0 && forwards.len() == 0).await;
        // Its entry went with it, so the sender's next datagram opens a fresh flow rather than
        // feeding the dead one.
        app.send(b"two").await.unwrap();
        eventually(|| tunnel.flows().len() == 2).await;
    }

    /// Review Focus 1: an open whose flow idles out first is cancelled with it, so opens in flight
    /// stay within the table's cap and can't take a newer flow's place, and the sender's next
    /// datagram opens a fresh flow. (The generation check in `open` covers only an open already
    /// past its wait on another worker, which no deterministic test can reach.)
    #[tokio::test(start_paused = true)]
    async fn udp_an_open_whose_flow_idled_out_is_cancelled() {
        let tunnel = FakeTunnel::new();
        let gate = tunnel.udp_gate("dns.corp.example", 53, tests::udp_echo_server().await.unwrap());
        let forwards = UdpForwards::new(tunnel.clone());
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        app.connect(listener.local_addr().unwrap()).await.unwrap();
        tokio::spawn(forwards.clone().serve(listener, Arc::from("dns.corp.example"), 53));
        let sweep = tokio::spawn(forwards.clone().sweep());

        app.send(b"one").await.unwrap();
        until(|| tunnel.flows().len() == 1).await.unwrap();
        tokio::time::advance(Duration::from_secs(31)).await;
        until(|| forwards.len() == 0).await.unwrap();
        // Past here the test waits on real sockets, and a paused clock jumps to any pending timer
        // whenever the runtime idles: the sweep would idle the second flow out mid-exchange.
        sweep.abort();

        // The first open never finishes, though its gate opens; the second goes straight through.
        gate.open();
        app.send(b"two").await.unwrap();
        let mut buf = [0; 64];
        let n = app.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"two");
        assert_eq!((tunnel.flows().len(), tunnel.flows_opened(), tunnel.live_flows()), (2, 1, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn udp_datagrams_while_opening_keep_the_flow() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tunnel = FakeTunnel::new();
        let gate = tunnel.udp_gate("dns.corp.example", 53, target.local_addr().unwrap());
        let forwards = UdpForwards::new(tunnel.clone());
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        app.connect(listener.local_addr().unwrap()).await.unwrap();
        tokio::spawn(forwards.clone().serve(listener, Arc::from("dns.corp.example"), 53));
        let sweep = tokio::spawn(forwards.clone().sweep());

        // Each lands before the clock moves on: 20 s apart, so only the refresh keeps the entry
        // past 30 s.
        app.send(b"one").await.unwrap();
        until(|| tunnel.flows().len() == 1).await.unwrap();
        tokio::time::advance(Duration::from_secs(20)).await;
        app.send(b"two").await.unwrap();
        tokio::time::advance(Duration::from_secs(20)).await;
        app.send(b"three").await.unwrap();
        tokio::time::advance(Duration::from_secs(5)).await;
        // Past here the test waits on real sockets, and a paused clock jumps to any pending timer.
        sweep.abort();

        gate.open();
        let mut got = Vec::new();
        let mut buf = [0; 64];
        for _ in 0..3 {
            let n = timeout(Duration::from_secs(5), target.recv(&mut buf)).await.expect("a held datagram arrives").unwrap();
            got.push(buf[..n].to_vec());
        }
        assert_eq!(got, [b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]);
        assert_eq!((tunnel.flows().len(), tunnel.flows_opened()), (1, 1));
    }

    #[tokio::test]
    async fn udp_a_failed_open_lets_the_next_datagram_open_again() {
        let tunnel = FakeTunnel::new();
        tunnel.udp_reject("dns.corp.example", 53, OpenErrKind::Refused);
        let forwards = UdpForwards::new(tunnel.clone());
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        app.connect(listener.local_addr().unwrap()).await.unwrap();
        tokio::spawn(forwards.clone().serve(listener, Arc::from("dns.corp.example"), 53));

        app.send(b"one").await.unwrap();
        eventually(|| tunnel.flows().len() == 1 && forwards.len() == 0).await;
        // The failed open took its entry with it, so this one opens afresh.
        app.send(b"two").await.unwrap();
        eventually(|| tunnel.flows().len() == 2).await;
    }
}
