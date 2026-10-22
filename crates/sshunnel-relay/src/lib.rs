//! sshunnel's remote half: speak the mux over stdio and dial TCP for each stream the client opens.
//!
//! stdout carries frames and nothing else; anything human-readable goes to stderr, which ssh hands
//! back to the client's terminal.

use std::{ffi::CString, io::ErrorKind, ptr, sync::Arc};

use anyhow::Context as _;
use bytes::BytesMut;
use sshunnel_mux::{
    Config, Incoming, OpenRequest, Request, ResolveError, ResolveRequest, Role,
    base::Void,
    frame::{Capabilities, MAX_HOST, OpenErrKind, ResolveErrKind},
    hello::{recv_hello, send_hello},
    pump, start,
};
use tokio::{net::TcpStream, sync::Semaphore};

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
    let runtime = tokio::runtime::Builder::new_current_thread().enable_io().build().context("starting the runtime")?;
    let result = runtime.block_on(async {
        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let config = Config::default();
        // The relay speaks first: the client stays quiet until this Hello arrives.
        send_hello(&mut stdout, config.window(), Capabilities::default()).await?;
        let mut buf = BytesMut::new();
        let client = recv_hello(&mut stdin, &mut buf).await?;
        let (_mux, incoming, driver) = start(stdin, buf, stdout, Role::Relay, config, client);
        tokio::spawn(serve(incoming));
        driver.await
    });
    // A stdin read parked on the blocking pool would make an orderly shutdown wait on it forever.
    runtime.shutdown_background();
    result
}

/// Serves each request the client makes: dial a host, or resolve a name.
pub async fn serve(mut incoming: Incoming) {
    let lookups = Arc::new(Semaphore::new(MAX_LOOKUPS));
    while let Some(request) = incoming.next().await {
        match request {
            Request::Open(request) => {
                tokio::spawn(dial(request));
            }
            Request::Resolve(request) => {
                tokio::spawn(resolve(request, Arc::clone(&lookups)));
            }
        }
    }
}

async fn dial(request: OpenRequest) {
    match TcpStream::connect((request.host(), request.port())).await {
        Ok(socket) => {
            // Frames already batch; Nagle would only add latency on top.
            let _ = socket.set_nodelay(true);
            // The pump resets the stream itself on failure, which tells the client why.
            let _ = pump(request.accept(), socket).await;
        }
        Err(e) => {
            let reason = format!("dialing {}:{}: {e}", request.host(), request.port());
            request.reject(open_err_kind(&e), &reason);
        }
    }
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
async fn bounded_lookup<F>(permits: &Semaphore, lookup: F) -> Result<(), ResolveError>
where
    F: FnOnce() -> Result<(), ResolveError> + Send + 'static,
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
    // call; the service is null (allowed); `found` is a valid out-pointer. On success the list it
    // receives is freed exactly once, right here, and never read.
    let code = unsafe {
        let code = libc::getaddrinfo(name.as_ptr(), ptr::null(), &raw const hints, &raw mut found);
        if code == 0 {
            libc::freeaddrinfo(found);
        }
        code
    };
    match code {
        0 => Ok(()),
        libc::EAI_NONAME | libc::EAI_NODATA => Err(ResolveError {
            kind: ResolveErrKind::NoSuchName,
            reason: format!("{host}: no such name"),
        }),
        other => Err(failed(format!("{host}: {}", gai_message(other)))),
    }
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

    use super::*;

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
