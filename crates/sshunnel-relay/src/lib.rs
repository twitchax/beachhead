//! sshunnel's remote half: speak the mux over stdio and dial TCP for each stream the client opens.
//!
//! stdout carries frames and nothing else; anything human-readable goes to stderr, which ssh hands
//! back to the client's terminal.

pub mod ping;
pub mod query;

use std::{
    borrow::Cow,
    ffi::CString,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ptr,
    sync::Arc,
};

use anyhow::Context as _;
use bytes::{Bytes, BytesMut};
use sshunnel_mux::{
    Config, Flow, FlowEvent, FlowKind, FlowRequest, Incoming, OpenError, OpenRequest, Request, ResolveError, ResolveRequest, Role,
    base::Void,
    frame::{Capabilities, FlowErrKind, MAX_HOST, OpenErrKind, ResolveErrKind},
    hello::{recv_hello, send_hello},
    pump, start,
};
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::Semaphore,
};

/// How many lookups may block at once. Stdio reads and writes share tokio's blocking pool with
/// `getaddrinfo`, so a slow resolver must not be able to take every thread and stall the pipe.
const MAX_LOOKUPS: usize = 32;

/// What `--probe` prints: proof the binary executes here, which a `noexec` mount would deny.
#[must_use]
pub fn probe() -> String {
    format!("sshunnel-relay {} protocol {}", env!("CARGO_PKG_VERSION"), sshunnel_mux::frame::VERSION)
}

/// Serves the client over stdin and stdout until the client hangs up.
///
/// # Errors
///
/// Fails when the handshake fails or the pipe breaks mid-connection.
pub fn run_stdio() -> Void {
    // Flows and streams each hold a descriptor, and many systems start the soft limit at 1024.
    if let Err(e) = raise_fd_limit() {
        eprintln!("sshunnel-relay: could not raise the open-file limit: {e}");
    }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_io().enable_time().build().context("starting the runtime")?;
    let result = runtime.block_on(async {
        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let config = Config::default();
        // The relay speaks first: the client stays quiet until this Hello arrives.
        let capabilities = ping::probe();
        send_hello(&mut stdout, config.window(), capabilities).await?;
        let mut buf = BytesMut::new();
        let client = recv_hello(&mut stdin, &mut buf).await?;
        let (_mux, incoming, driver) = start(stdin, buf, stdout, Role::Relay, config, client);
        tokio::spawn(serve(incoming, capabilities));
        driver.await
    });
    // A stdin read parked on the blocking pool would make an orderly shutdown wait on it forever.
    runtime.shutdown_background();
    result
}

/// Raises `RLIMIT_NOFILE`'s soft limit to its hard limit, and returns the new soft limit.
///
/// # Errors
///
/// Fails when the limit can't be read or set.
pub fn raise_fd_limit() -> std::io::Result<u64> {
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `limit` is a valid out-pointer for the duration of the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    limit.rlim_cur = limit.rlim_max;
    // SAFETY: `limit` is a valid, initialized `rlimit` that the call only reads.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(limit.rlim_cur)
}

/// Serves each request the client makes: dial a host, open a flow, resolve a name, or ask the
/// remote's nameservers. `capabilities` is what the `Hello` promised about ping.
pub async fn serve(mut incoming: Incoming, capabilities: Capabilities) {
    let lookups = Arc::new(Semaphore::new(MAX_LOOKUPS));
    while let Some(request) = incoming.next().await {
        match request {
            Request::Open(request) => {
                tokio::spawn(dial(request, Arc::clone(&lookups)));
            }
            Request::Resolve(request) => {
                tokio::spawn(resolve(request, Arc::clone(&lookups)));
            }
            Request::OpenFlow(request) if request.kind() == FlowKind::Udp => {
                tokio::spawn(udp(request, Arc::clone(&lookups)));
            }
            Request::OpenFlow(request) => {
                tokio::spawn(echo(request, Arc::clone(&lookups), capabilities));
            }
            Request::Query(request) => {
                tokio::spawn(query::serve(request));
            }
        }
    }
}

async fn dial(mut request: OpenRequest, permits: Arc<Semaphore>) {
    // Owned, because waiting on `cancelled` borrows the request for the whole dial.
    let (host, port) = (request.host().to_owned(), request.port());
    let dialing = async {
        let found = addresses(&permits, &host, port).await?;
        connect_first(&found).await.map_err(|e| OpenError {
            kind: open_err_kind(&e),
            reason: format!("dialing {host}:{port}: {e}"),
        })
    };
    let result = tokio::select! {
        result = dialing => result,
        // The client dropped its open (a `route` dial evicted past the held-dial cap, say), so
        // nothing waits on this connect, which could otherwise take the OS connect timeout. The
        // request drops unanswered, which says nothing: the client has no stream left to answer.
        // No `debug!`: the relay has no log, as its stderr is the user's terminal.
        () = request.cancelled() => return,
    };
    match result {
        Ok(socket) => {
            // Frames already batch; Nagle would only add latency on top.
            let _ = socket.set_nodelay(true);
            // The pump resets the stream itself on failure, which tells the client why.
            let _ = pump(request.accept(), socket).await;
        }
        Err(e) => request.reject(e.kind, &e.reason),
    }
}

/// Connects to each address in turn; the error is the last one's.
async fn connect_first(found: &[SocketAddr]) -> std::io::Result<TcpStream> {
    let mut last = None;
    for &addr in found {
        match TcpStream::connect(addr).await {
            Ok(socket) => return Ok(socket),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::new(ErrorKind::NotFound, "the name has no addresses")))
}

/// Every address `host:port` names: an IP literal at once, a name through the lookup limit
/// (`getaddrinfo` on the blocking pool). Every open comes through here, so no connect does a
/// lookup the limit doesn't see.
///
/// # Errors
///
/// An [`OpenError`] of kind `Other` when the name doesn't resolve.
pub async fn addresses(permits: &Semaphore, host: &str, port: u16) -> Result<Vec<SocketAddr>, OpenError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let name = host.to_owned();
    let found = bounded_lookup(permits, move || resolve_all(&name)).await;
    match found {
        Ok(ips) => Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect()),
        Err(e) => Err(OpenError {
            kind: OpenErrKind::Other,
            reason: format!("resolving {host}: {}", e.reason),
        }),
    }
}

/// A UDP flow: a connected socket to the first address that takes one, with datagrams carried
/// both ways until the client ends the flow.
async fn udp(request: FlowRequest, permits: Arc<Semaphore>) {
    let found = match addresses(&permits, request.host(), request.port()).await {
        Ok(found) => found,
        Err(e) => {
            request.reject(e.kind, &e.reason);
            return;
        }
    };
    let socket = match connect_udp(&found).await {
        Ok(socket) => socket,
        Err(e) => {
            let reason = format!("opening a UDP socket to {}:{}: {e}", request.host(), request.port());
            request.reject(open_err_kind(&e), &reason);
            return;
        }
    };
    carry(request.accept(), &socket, |datagram| Some(Cow::Borrowed(datagram)), |packet| Some(Bytes::copy_from_slice(packet))).await;
}

/// An echo flow: a connected ping socket of the first address's family the remote may ping over,
/// with each datagram (a sequence, then a payload) carried as an echo request, and each echo
/// reply back as one.
async fn echo(request: FlowRequest, permits: Arc<Semaphore>, capabilities: Capabilities) {
    let found = match addresses(&permits, request.host(), 0).await {
        Ok(found) => found,
        Err(e) => {
            request.reject(e.kind, &e.reason);
            return;
        }
    };
    let Some(addr) = found.iter().find(|a| if a.is_ipv6() { capabilities.ping6 } else { capabilities.ping4 }) else {
        let reason = match found.first() {
            Some(a) if a.is_ipv6() => "the remote can't ping over IPv6",
            Some(_) => "the remote can't ping over IPv4",
            None => "the name has no addresses",
        };
        request.reject(OpenErrKind::Other, reason);
        return;
    };
    let v6 = addr.is_ipv6();
    let socket = match ping::open(*addr) {
        Ok(socket) => socket,
        Err(e) => {
            let reason = format!("opening a ping socket to {}: {e}", request.host());
            request.reject(open_err_kind(&e), &reason);
            return;
        }
    };
    carry(
        request.accept(),
        &socket,
        |datagram| ping::echo_request(datagram, v6).map(Cow::Owned),
        |packet| ping::echo_reply(packet, v6),
    )
    .await;
}

/// Carries a flow's datagrams to `socket` and back until the client ends the flow. `outbound`
/// turns a datagram into what the socket sends, `inbound` what it received into a datagram;
/// either returns `None` for what the flow has no use for, which is dropped.
async fn carry<O, I>(mut flow: Flow, socket: &UdpSocket, outbound: O, inbound: I)
where
    O: for<'a> Fn(&'a [u8]) -> Option<Cow<'a, [u8]>>,
    I: Fn(&[u8]) -> Option<Bytes>,
{
    let sender = flow.sender();
    let mut errors = SocketErrors::default();
    // A datagram can be 65 535 bytes; untouched pages of this buffer cost nothing.
    let mut buf = vec![0u8; 65_535];
    loop {
        let result = tokio::select! {
            event = flow.recv() => match event {
                Some(FlowEvent::Datagram(datagram)) => match outbound(&datagram) {
                    Some(packet) => socket.send(&packet).await.map(drop),
                    None => continue,
                },
                // The relay's end has no use for the peer's errors.
                Some(FlowEvent::Error(_)) => continue,
                None => return,
            },
            read = socket.recv(&mut buf) => read.map(|n| {
                // A full queue drops the datagram: UDP may lose it, and the relay mustn't wait.
                if let Some(datagram) = inbound(&buf[..n]) {
                    sender.try_send(datagram);
                }
            }),
        };
        match result {
            Ok(()) => errors.succeeded(),
            Err(e) => match errors.failed(&e) {
                OnError::Report(kind) => sender.report(kind),
                // What failed is lost, as UDP may lose any datagram.
                OnError::Drop => {}
                OnError::End => return,
            },
        }
    }
}

/// Socket errors in a row, with no send or receive working between them, that a flow outlives
/// unreported. Linux clears a socket's pending error once a call returns it, so a run this long
/// means the socket fails every time.
const MAX_UNREPORTED: u32 = 64;

/// What a flow does about a socket error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OnError {
    /// Tells the client, which can act on it, and carries on.
    Report(FlowErrKind),
    /// Carries on without the datagram.
    Drop,
    /// Ends the flow.
    End,
}

/// A flow's run of socket errors the client can't be told about. One of those (`EMSGSIZE` once
/// ICMP lowers the path's MTU, `EPERM` from the remote's egress firewall) loses only its datagram:
/// ending the flow would lose the app's next datagrams too and move its remote source port. The
/// relay has no log to note the loss in, since its stderr is the user's terminal.
#[derive(Default)]
struct SocketErrors {
    unreported: u32,
}

impl SocketErrors {
    /// A send or receive worked: the socket isn't failing for good.
    fn succeeded(&mut self) {
        self.unreported = 0;
    }

    /// What to do about `e`: report it if the client can act on it, else drop the datagram, until
    /// [`MAX_UNREPORTED`] such errors in a row end the flow.
    fn failed(&mut self, e: &std::io::Error) -> OnError {
        if let Some(kind) = FlowErrKind::from_io(e) {
            return OnError::Report(kind);
        }
        self.unreported += 1;
        if self.unreported > MAX_UNREPORTED { OnError::End } else { OnError::Drop }
    }
}

/// A UDP socket connected to the first address that accepts one, on the unspecified address of
/// its family; the error is the last one's.
async fn connect_udp(found: &[SocketAddr]) -> std::io::Result<UdpSocket> {
    let mut last = None;
    for addr in found {
        let local = match addr {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let attempt = async {
            let socket = UdpSocket::bind(local).await?;
            socket.connect(addr).await?;
            Ok(socket)
        };
        match attempt.await {
            Ok(socket) => return Ok(socket),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::new(ErrorKind::NotFound, "the name has no addresses")))
}

/// What a failed dial tells the client, so it can tell a closed port from a dead route.
#[must_use]
pub fn open_err_kind(e: &std::io::Error) -> OpenErrKind {
    match e.kind() {
        ErrorKind::ConnectionRefused => OpenErrKind::Refused,
        ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => OpenErrKind::Unreachable,
        ErrorKind::TimedOut => OpenErrKind::TimedOut,
        _ => OpenErrKind::Other,
    }
}

async fn resolve(request: ResolveRequest, permits: Arc<Semaphore>) {
    let host = request.host().to_owned();
    request.answer(bounded_lookup(&permits, move || lookup(&host)).await);
}

/// Runs `lookup` on the blocking pool once a permit is free. Waiting happens here, in the
/// request's own task, never in the serve loop.
async fn bounded_lookup<T, F>(permits: &Semaphore, lookup: F) -> Result<T, ResolveError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ResolveError> + Send + 'static,
{
    let failed = |reason: String| ResolveError { kind: ResolveErrKind::Failed, reason };
    let _permit = permits.acquire().await.map_err(|e| failed(format!("the lookup limiter closed: {e}")))?;
    // getaddrinfo blocks, and may for seconds on a slow resolver.
    tokio::task::spawn_blocking(lookup).await.unwrap_or_else(|e| Err(failed(format!("the lookup task failed: {e}"))))
}

/// Resolves `host` with the platform resolver (musl's `getaddrinfo` in the shipped relay), which
/// reads `/etc/hosts` and `/etc/resolv.conf` on the remote.
///
/// # Errors
///
/// [`ResolveErrKind::NoSuchName`] when the resolver says the name doesn't exist, and
/// [`ResolveErrKind::Failed`] for everything else, including a name `getaddrinfo` can't be given.
pub fn lookup(host: &str) -> Result<(), ResolveError> {
    resolve_all(host).map(|_| ())
}

/// The addresses `getaddrinfo` finds for `host`, deduplicated and in the resolver's order.
fn resolve_all(host: &str) -> Result<Vec<IpAddr>, ResolveError> {
    let failed = |reason: String| ResolveError { kind: ResolveErrKind::Failed, reason };
    if host.len() > MAX_HOST {
        return Err(failed(format!("host is longer than {MAX_HOST} bytes")));
    }
    let name = CString::new(host).map_err(|_| failed("host contains a NUL byte".to_owned()))?;

    // AI_ADDRCONFIG stays unset: the answer is about the name, not about which families this
    // host happens to have addresses for.
    // SAFETY: an all-zero `addrinfo` is valid (null pointers, zero flags); the fields that matter
    // are set below.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_flags = 0;
    hints.ai_family = libc::AF_UNSPEC;
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut found: *mut libc::addrinfo = ptr::null_mut();
    // SAFETY: `name` is a NUL-terminated string and `hints` a valid `addrinfo`, both alive for the
    // call; the service is null (allowed); `found` is a valid out-pointer.
    let code = unsafe { libc::getaddrinfo(name.as_ptr(), ptr::null(), &raw const hints, &raw mut found) };
    match code {
        0 => {
            let ips = collect_ips(found);
            // SAFETY: `found` is the list the successful call above returned, and `collect_ips`
            // kept nothing that points into it. It is freed exactly once, here.
            unsafe { libc::freeaddrinfo(found) };
            Ok(ips)
        }
        libc::EAI_NONAME | libc::EAI_NODATA => Err(ResolveError {
            kind: ResolveErrKind::NoSuchName,
            reason: format!("{host}: no such name"),
        }),
        other => Err(failed(format!("{host}: {}", gai_message(other)))),
    }
}

/// Copies the IPv4 and IPv6 addresses out of a `getaddrinfo` list, without repeats.
fn collect_ips(list: *const libc::addrinfo) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: `entry` is non-null and, by the caller's contract, a node of a live list that
        // `getaddrinfo` returned.
        let info = unsafe { &*entry };
        let ip = match info.ai_family {
            // SAFETY: for `AF_INET` and `AF_INET6`, `ai_addr` points to a `sockaddr_in` or
            // `sockaddr_in6` of that size; `read_unaligned` makes no assumption about alignment.
            libc::AF_INET => Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                unsafe { info.ai_addr.cast::<libc::sockaddr_in>().read_unaligned() }.sin_addr.s_addr,
            )))),
            // SAFETY: as above.
            libc::AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(unsafe { info.ai_addr.cast::<libc::sockaddr_in6>().read_unaligned() }.sin6_addr.s6_addr))),
            _ => None,
        };
        if let Some(ip) = ip.filter(|ip| !ips.contains(ip)) {
            ips.push(ip);
        }
        entry = info.ai_next;
    }
    ips
}

/// `gai_strerror`, owned.
fn gai_message(code: i32) -> String {
    // SAFETY: `gai_strerror` returns a pointer to a static NUL-terminated string for any code.
    unsafe { std::ffi::CStr::from_ptr(libc::gai_strerror(code)) }.to_string_lossy().into_owned()
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::io::{Error, ErrorKind};

    use pretty_assertions::assert_eq;
    use sshunnel_mux::hello::PeerHello;

    use super::*;

    #[test]
    fn a_flow_outlives_a_run_of_unreported_socket_errors_up_to_the_cap() {
        let mut errors = SocketErrors::default();
        let unreported = || Error::from_raw_os_error(libc::EMSGSIZE);
        for _ in 0..MAX_UNREPORTED {
            assert_eq!(errors.failed(&unreported()), OnError::Drop);
        }
        // An error the client is told about neither counts nor breaks the run.
        assert_eq!(errors.failed(&Error::from(ErrorKind::ConnectionRefused)), OnError::Report(FlowErrKind::PortUnreachable));
        assert_eq!(errors.failed(&unreported()), OnError::End);
    }

    #[test]
    fn a_working_send_or_receive_restarts_the_run() {
        let mut errors = SocketErrors::default();
        let unreported = || Error::from_raw_os_error(libc::EPERM);
        for _ in 0..MAX_UNREPORTED {
            assert_eq!(errors.failed(&unreported()), OnError::Drop);
        }
        errors.succeeded();
        for _ in 0..MAX_UNREPORTED {
            assert_eq!(errors.failed(&unreported()), OnError::Drop);
        }
        assert_eq!(errors.failed(&unreported()), OnError::End);
    }

    #[test]
    fn connect_errors_map_to_kinds() {
        let kind = |k: ErrorKind| open_err_kind(&Error::from(k));
        assert_eq!(kind(ErrorKind::ConnectionRefused), OpenErrKind::Refused);
        assert_eq!(kind(ErrorKind::HostUnreachable), OpenErrKind::Unreachable);
        assert_eq!(kind(ErrorKind::NetworkUnreachable), OpenErrKind::Unreachable);
        assert_eq!(kind(ErrorKind::TimedOut), OpenErrKind::TimedOut);
        assert_eq!(kind(ErrorKind::PermissionDenied), OpenErrKind::Other);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn permits_bound_concurrent_lookups() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let permits = Arc::new(Semaphore::new(2));
        let open = Arc::new(AtomicBool::new(false));
        let (running, peak, done) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let mut tasks = Vec::new();
        for _ in 0..6 {
            let (permits, open, running, peak, done) = (Arc::clone(&permits), Arc::clone(&open), Arc::clone(&running), Arc::clone(&peak), Arc::clone(&done));
            tasks.push(tokio::spawn(async move {
                bounded_lookup(&permits, move || {
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    while !open.load(Ordering::SeqCst) {
                        std::thread::yield_now();
                    }
                    running.fetch_sub(1, Ordering::SeqCst);
                    done.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .await
            }));
        }
        // Two lookups hold permits and wait on the gate; the other four must be parked on permits.
        while running.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
        assert_eq!(permits.available_permits(), 0);
        open.store(true, Ordering::SeqCst);
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(done.load(Ordering::SeqCst), 6);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn an_ip_literal_skips_the_lookup_limit() {
        let permits = Semaphore::new(0);
        let found = addresses(&permits, "127.0.0.1", 80).await.unwrap();
        assert_eq!(found, vec!["127.0.0.1:80".parse::<SocketAddr>().unwrap()]);
        let found = addresses(&permits, "::1", 80).await.unwrap();
        assert_eq!(found, vec!["[::1]:80".parse::<SocketAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn a_name_waits_for_a_lookup_permit() {
        let permits = Semaphore::new(0);
        let waiting = tokio::time::timeout(std::time::Duration::from_millis(200), addresses(&permits, "localhost", 80)).await;
        assert!(waiting.is_err(), "a name resolved without a permit");
    }

    #[tokio::test]
    async fn a_name_resolves_to_its_addresses() {
        let permits = Semaphore::new(1);
        let found = addresses(&permits, "localhost", 80).await.unwrap();
        assert!(found.contains(&"127.0.0.1:80".parse::<SocketAddr>().unwrap()), "{found:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_dial_given_up_stops() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        let config = Config::default();
        let hello = PeerHello {
            window: config.window(),
            capabilities: Capabilities::default(),
        };
        let (client, _client_incoming, client_driver) = start(ar, BytesMut::new(), aw, Role::Client, config, hello);
        let (_relay, mut incoming, relay_driver) = start(br, BytesMut::new(), bw, Role::Relay, config, hello);
        tokio::spawn(client_driver);
        tokio::spawn(relay_driver);
        let opener = {
            let client = client.clone();
            tokio::spawn(async move { client.open("localhost", 80).await })
        };
        let Some(Request::Open(request)) = incoming.next().await else {
            panic!("expected an open request")
        };

        // A name waits for a lookup permit, and there are none: only the client giving up ends it.
        let permits = Arc::new(Semaphore::new(0));
        opener.abort();
        tokio::time::timeout(std::time::Duration::from_secs(1), dial(request, permits)).await.unwrap();
    }

    #[tokio::test]
    async fn an_unknown_name_is_an_open_error() {
        let permits = Semaphore::new(1);
        let err = addresses(&permits, "nonexistent.invalid", 80).await.unwrap_err();
        assert_eq!(err.kind, OpenErrKind::Other, "{err}");
    }

    #[test]
    fn raising_the_fd_limit_reaches_the_hard_limit() {
        let soft = raise_fd_limit().unwrap();
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: `limit` is a valid out-pointer for the call.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) }, 0);
        assert_eq!(limit.rlim_cur, limit.rlim_max);
        assert_eq!(limit.rlim_cur, soft);
    }

    #[test]
    fn lookup_finds_localhost() {
        lookup("localhost").unwrap();
    }

    #[test]
    fn lookup_of_an_invalid_name_is_no_such_name() {
        let err = lookup("nonexistent.invalid").unwrap_err();
        assert_eq!(err.kind, ResolveErrKind::NoSuchName, "{err}");
    }

    #[test]
    fn lookup_refuses_names_it_cannot_pass_to_getaddrinfo() {
        for host in ["a\0b".to_owned(), "a".repeat(MAX_HOST + 1)] {
            let err = lookup(&host).unwrap_err();
            assert_eq!(err.kind, ResolveErrKind::Failed, "{err}");
        }
    }
}
