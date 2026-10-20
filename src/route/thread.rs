//! The netstack on a thread of its own: the device's reader and writer, the packet loop with its
//! connections, and the DNS server, all on one current-thread runtime. Each segment's round trip
//! (a device read or write, a smoltcp pass, a connection's pipe) then stays on one core instead of
//! waking a different worker of the main runtime at every step, which is what held route's
//! download under forward mode's. The mux, the session, the helper and the signals stay on the
//! main runtime; tokio's channels and the mux's streams work across the two.

use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    os::fd::OwnedFd,
    sync::{
        Arc,
        mpsc::{self as std_mpsc, RecvTimeoutError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use anyhow::{Context as _, anyhow, bail};
use tokio::{runtime::Builder, sync::oneshot, task::JoinSet};

use crate::{
    base::{Err, Res, Void},
    route::{
        device, dns,
        router::Router,
        stack::{self, DNS_PORT},
    },
    tunnel::Tunnel,
};

/// The thread's name; the kernel keeps 15 bytes of it.
const NAME: &str = "sshunnel-stack";
/// How long stopping waits for the thread before teardown goes on without it.
const STOP_LIMIT: Duration = Duration::from_secs(2);

/// The running netstack. Dropping it asks the thread to end without waiting; [`Self::stop`]
/// waits.
pub(crate) struct Netstack {
    /// Sent, or dropped with the handle, to ask the thread to end.
    quit: oneshot::Sender<()>,
    /// How the work ended, when it ended by itself; `None` once reported.
    ended: Option<oneshot::Receiver<Void>>,
    /// Disconnects once the thread is done with its runtime, and so with the device's fd.
    finished: std_mpsc::Receiver<Infallible>,
    thread: JoinHandle<()>,
}

impl Netstack {
    /// Starts the netstack on `tun`: the device's reader and writer, the packet loop dialing through
    /// `tunnel`, and the DNS server, which forwards names it doesn't route to `upstreams`.
    ///
    /// # Errors
    ///
    /// Fails when the thread or its runtime can't start, or the device can't join the runtime.
    pub(crate) async fn start<T: Tunnel>(tun: OwnedFd, tunnel: T, router: Arc<Router>, upstreams: &[IpAddr]) -> Res<Self> {
        let upstreams = upstreams.iter().map(|&addr| SocketAddr::new(addr, DNS_PORT)).collect();
        Self::spawn(move |tasks| {
            let packets = device::spawn(tun, tasks)?;
            let dns = Arc::new(dns::Server::new(tunnel.clone(), Arc::clone(&router), upstreams));
            tasks.spawn(stack::run(packets, tunnel, router, dns));
            Ok(())
        })
        .await
    }

    /// Runs `start` on a new thread, inside that thread's runtime, and returns once it has. `start`
    /// spawns the netstack's tasks into the set it is given, and the first of them to end ends the
    /// netstack.
    async fn spawn(start: impl FnOnce(&mut JoinSet<Void>) -> Void + Send + 'static) -> Res<Self> {
        let (started_tx, started) = oneshot::channel();
        let (quit, quit_rx) = oneshot::channel();
        let (ended_tx, ended) = oneshot::channel();
        let (finished_tx, finished) = std_mpsc::channel();
        let thread = thread::Builder::new()
            .name(NAME.to_owned())
            .spawn(move || {
                // Named, so it drops last: after `run` has dropped the runtime and its tasks.
                let _finished = finished_tx;
                run(start, started_tx, quit_rx, ended_tx);
            })
            .context("starting the netstack's thread")?;
        let netstack = Self {
            quit,
            ended: Some(ended),
            finished,
            thread,
        };
        started.await.unwrap_or_else(|_| Err(panicked()))?;
        Ok(netstack)
    }

    /// Resolves when the netstack ends by itself: the first of its tasks to end, with that task's
    /// error, or an error naming the netstack when it panicked. It resolves once; later calls wait
    /// forever.
    pub(crate) async fn closed(&mut self) -> Void {
        let Some(ended) = self.ended.as_mut() else {
            return std::future::pending().await;
        };
        let ended = ended.await.unwrap_or_else(|_| Err(panicked()));
        self.ended = None;
        ended
    }

    /// Asks the netstack to end and joins its thread, which closes the client's fd on the device.
    /// Blocks for at most [`STOP_LIMIT`].
    ///
    /// # Errors
    ///
    /// Fails when the thread panicked, or is still running at the limit: teardown then goes on
    /// without it, and the fd closes when the process exits.
    pub(crate) fn stop(self) -> Void {
        self.stop_within(STOP_LIMIT)
    }

    fn stop_within(self, limit: Duration) -> Void {
        let Self { quit, finished, thread, .. } = self;
        // Gone already when the thread has ended.
        let _ = quit.send(());
        match finished.recv_timeout(limit) {
            Ok(never) => match never {},
            Err(RecvTimeoutError::Timeout) => bail!("the netstack's thread didn't stop within {limit:?}; leaving it behind"),
            Err(RecvTimeoutError::Disconnected) => thread.join().map_err(|_| panicked()),
        }
    }
}

/// The thread's body: `start` inside a runtime of the thread's own, then its tasks until the first
/// ends (reported on `ended`) or `quit` resolves. Dropping the runtime then drops every task left
/// on it, and the device's fd with the last of them.
fn run(start: impl FnOnce(&mut JoinSet<Void>) -> Void, started: oneshot::Sender<Void>, quit: oneshot::Receiver<()>, ended: oneshot::Sender<Void>) {
    let runtime = match Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            let _ = started.send(Err(e).context("starting the netstack's runtime"));
            return;
        }
    };
    let mut tasks = JoinSet::new();
    // Inside the runtime, so the tasks, and the device's registration with a reactor, are its own.
    let begun = {
        let _inside = runtime.enter();
        start(&mut tasks)
    };
    if let Err(e) = begun {
        // So the device's fd is closed by the time the caller hears.
        drop(tasks);
        drop(runtime);
        let _ = started.send(Err(e));
        return;
    }
    let _ = started.send(Ok(()));
    let first = runtime.block_on(async {
        tokio::select! {
            biased;
            _ = quit => None,
            done = tasks.join_next() => Some(done),
        }
    });
    // Reported before the runtime drops, so a task that wedges as it drops can't hide the end.
    if let Some(done) = first {
        let _ = ended.send(match done {
            Some(done) => done.context("a netstack task panicked").and_then(|ended| ended),
            None => Ok(()),
        });
    }
}

fn panicked() -> Err {
    anyhow!("the netstack's thread panicked")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::{sync::mpsc as std_mpsc, time::Instant};

    use bytes::Bytes;
    use pretty_assertions::assert_eq;
    use rustix::thread::gettid;
    use sshunnel_mux::{
        OpenError, ResolveError,
        frame::{OpenErrKind, ResolveErrKind},
    };
    use tempfile::TempDir;
    use tokio::{net::UnixDatagram, sync::mpsc, task::JoinHandle, time::timeout};

    use super::*;
    use crate::{
        route::{
            DEVICE, MTU,
            names::{FakeMap, today},
            stack::Packets,
            targets::Targets,
        },
        tests::{AppStack, Connect, FakeConn, device_pair},
    };

    /// Refuses every open, saying which thread (by its kernel id) the open ran on.
    #[derive(Clone)]
    struct Recorder(mpsc::UnboundedSender<i32>);

    impl Tunnel for Recorder {
        type Conn = FakeConn;

        fn open(&self, host: &str, port: u16) -> impl Future<Output = Result<FakeConn, OpenError>> + Send {
            // The stack calls this inside the dial's task.
            let _ = self.0.send(tid());
            std::future::ready(Err(OpenError {
                kind: OpenErrKind::Refused,
                reason: format!("{host}:{port}: refused"),
            }))
        }

        fn resolve(&self, host: &str) -> impl Future<Output = Result<(), ResolveError>> + Send {
            std::future::ready(Err(ResolveError {
                kind: ResolveErrKind::NoSuchName,
                reason: format!("{host}: no such name"),
            }))
        }
    }

    /// A netstack on a stand-in device, with an app on the device's far end.
    struct Rig {
        netstack: Netstack,
        app: AppStack,
        /// The thread each dial ran on.
        dials: mpsc::UnboundedReceiver<i32>,
        /// Carries packets between the app and the device; ends once the device's fd closes.
        wire: JoinHandle<()>,
        _state: TempDir,
    }

    async fn rig() -> Rig {
        let state = TempDir::new().unwrap();
        let names = FakeMap::load(state.path().join("names"), today()).unwrap();
        let router = Arc::new(Router::new(Targets::parse(&["10.99.0.0/16".to_owned()], &[]).unwrap(), names));
        let (dialed, dials) = mpsc::unbounded_channel();
        let (tun, kernel) = device_pair().unwrap();
        let netstack = Netstack::start(tun, Recorder(dialed), router, &[]).await.unwrap();
        let (app, packets) = AppStack::new().unwrap();
        let wire = tokio::spawn(carry(kernel, packets));
        Rig {
            netstack,
            app,
            dials,
            wire,
            _state: state,
        }
    }

    /// Carries the app's packets to the device's far end and the device's back, until the device
    /// closes.
    async fn carry(kernel: UnixDatagram, mut app: Packets) {
        let mut buf = vec![0; usize::from(MTU)];
        loop {
            tokio::select! {
                Some(packet) = app.rx.recv() => {
                    if kernel.send(&packet).await.is_err() {
                        return;
                    }
                }
                read = kernel.recv(&mut buf) => match read {
                    Ok(n) if n > 0 => {
                        let _ = app.tx.send(Bytes::copy_from_slice(&buf[..n])).await;
                    }
                    _ => return,
                },
            }
        }
    }

    /// The calling thread's kernel id.
    fn tid() -> i32 {
        gettid().as_raw_nonzero().get()
    }

    /// The kernel's name for thread `tid` of this process, while it exists.
    fn comm(tid: i32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/self/task/{tid}/comm")).ok().map(|name| name.trim_end().to_owned())
    }

    /// Connects through the netstack, which the recorder refuses, and returns the thread the dial
    /// ran on.
    async fn dial_thread(rig: &mut Rig) -> i32 {
        let refused = rig.app.connect("10.99.0.5:80".parse().unwrap()).await;
        assert!(matches!(refused, Err(Connect::Refused)), "the refusal didn't cross the device: {refused:?}");
        rig.dials.recv().await.unwrap()
    }

    async fn falls_over() -> Void {
        tokio::task::yield_now().await;
        panic!("the stack fell over")
    }

    #[tokio::test]
    async fn the_netstack_runs_on_a_thread_of_its_own() {
        let mut rig = rig().await;

        let dialed_on = dial_thread(&mut rig).await;

        assert_ne!(dialed_on, tid(), "the dial ran on the caller's thread");
        assert_eq!(comm(dialed_on).as_deref(), Some(NAME));
        rig.netstack.stop().unwrap();
    }

    #[tokio::test]
    async fn stopping_the_netstack_joins_its_thread() {
        let mut rig = rig().await;
        let dialed_on = dial_thread(&mut rig).await;
        assert_eq!(comm(dialed_on).as_deref(), Some(NAME));

        rig.netstack.stop().unwrap();

        // The kernel reaps a thread a moment after the join that waited on it returns.
        let deadline = Instant::now() + Duration::from_secs(1);
        while comm(dialed_on).is_some() && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert_eq!(comm(dialed_on), None, "the netstack's thread outlived its stop");
        // The far end reads the device's end only once its fd has closed.
        timeout(Duration::from_secs(5), rig.wire).await.expect("the device's fd outlived the stop").unwrap();
    }

    #[tokio::test]
    async fn a_netstack_error_ends_closed() {
        let mut rig = rig().await;

        // Takes the device's far end with it: the device's reader fails.
        rig.wire.abort();

        let ended = timeout(Duration::from_secs(5), rig.netstack.closed()).await.expect("the netstack's end went unreported");
        let error = format!("{:#}", ended.unwrap_err());
        assert!(error.contains(&format!("{DEVICE} closed")), "{error}");
        rig.netstack.stop().unwrap();
    }

    #[tokio::test]
    async fn a_netstack_panic_is_an_error() {
        let mut netstack = Netstack::spawn(|tasks| {
            tasks.spawn(falls_over());
            Ok(())
        })
        .await
        .unwrap();

        let ended = timeout(Duration::from_secs(5), netstack.closed()).await.expect("the netstack's panic went unreported");
        let error = format!("{:#}", ended.unwrap_err());
        assert!(error.contains("netstack") && error.contains("the stack fell over"), "{error}");
        netstack.stop().unwrap();
    }

    #[tokio::test]
    async fn a_wedged_netstack_doesnt_hang_the_stop() {
        let (running, wedged) = std_mpsc::channel();
        let (release, held) = std_mpsc::channel::<()>();
        let netstack = Netstack::spawn(move |tasks| {
            tasks.spawn(async move {
                running.send(()).unwrap();
                // Blocks the thread, as a stuck syscall would.
                let _ = held.recv();
                Ok(())
            });
            Ok(())
        })
        .await
        .unwrap();
        wedged.recv_timeout(Duration::from_secs(5)).expect("the netstack never ran its work");

        let started = Instant::now();
        let stopped = netstack.stop_within(Duration::from_millis(100));
        drop(release);

        let error = stopped.unwrap_err().to_string();
        assert!(error.contains("didn't stop"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(1), "the stop took {:?}", started.elapsed());
    }
}
