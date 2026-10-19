//! [`FakeTunnel`]: a [`Tunnel`] scripted per target, standing in for the relay in the route tests.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use anyhow::{Context as _, bail};
use sshunnel_mux::{OpenError, ResolveError, Traffic, base::Res, frame::OpenErrKind, frame::ResolveErrKind};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, copy, copy_bidirectional, sink, split},
    net::TcpStream,
    sync::{Notify, watch},
};

use crate::tunnel::{Conn, Tunnel};

/// What an open of one `(host, port)` does.
#[derive(Clone)]
enum Dial {
    /// Dials this local address.
    To(SocketAddr),
    /// Fails with this kind.
    Reject(OpenErrKind),
    /// Waits for the gate, then echoes in memory.
    Gated(watch::Receiver<bool>),
    /// Succeeds with a connection that never reads or writes.
    Stall,
    /// Succeeds with a connection whose remote end closes at once.
    Hangup,
    /// Like `Hangup`, then fails once the app has closed too and the gate opens.
    FailLate(watch::Receiver<bool>),
}

#[derive(Default)]
struct Script {
    dials: HashMap<(String, u16), Dial>,
    names: HashMap<String, Result<(), ResolveErrKind>>,
    opens: Vec<(String, u16)>,
    resolves: Vec<String>,
}

/// A tunnel whose opens and lookups follow a script, recording every target it is asked for. An
/// unscripted open fails with [`OpenErrKind::Other`]; an unscripted name doesn't exist.
#[derive(Clone, Default)]
pub struct FakeTunnel {
    script: Arc<Mutex<Script>>,
    asked: Arc<Notify>,
}

/// Holds the opens of one gated target until [`Gate::open`].
pub struct Gate(watch::Sender<bool>);

impl Gate {
    /// Lets every waiting and future open through.
    pub fn open(&self) {
        self.0.send_replace(true);
    }
}

impl FakeTunnel {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens of `host:port` reach the local address `to`.
    pub fn dial(&self, host: &str, port: u16, to: SocketAddr) {
        self.script().dials.insert((host.to_owned(), port), Dial::To(to));
    }

    /// Opens of `host:port` fail with `kind`.
    pub fn reject(&self, host: &str, port: u16, kind: OpenErrKind) {
        self.script().dials.insert((host.to_owned(), port), Dial::Reject(kind));
    }

    /// Opens of `host:port` wait until the returned gate opens, then succeed with a connection
    /// that echoes in memory. No real I/O, so paused-time tests stay deterministic: tokio advances
    /// a paused clock whenever the runtime idles, even while a socket is still connecting.
    #[must_use]
    pub fn gate(&self, host: &str, port: u16) -> Gate {
        let (gate, waiting) = watch::channel(false);
        self.script().dials.insert((host.to_owned(), port), Dial::Gated(waiting));
        Gate(gate)
    }

    /// Opens of `host:port` succeed with a connection that never moves a byte: a relay stream
    /// whose remote end has stopped reading.
    pub fn stall(&self, host: &str, port: u16) {
        self.script().dials.insert((host.to_owned(), port), Dial::Stall);
    }

    /// Opens of `host:port` succeed with a connection whose remote end closes at once, so the
    /// stack's side of it closes first.
    pub fn hangup(&self, host: &str, port: u16) {
        self.script().dials.insert((host.to_owned(), port), Dial::Hangup);
    }

    /// Opens of `host:port` succeed with a connection whose remote end closes at once and which
    /// fails only after the app has closed its end too and the returned gate opens: a relay
    /// stream that resets after the app is done with it.
    #[must_use]
    pub fn fail_late(&self, host: &str, port: u16) -> Gate {
        let (gate, waiting) = watch::channel(false);
        self.script().dials.insert((host.to_owned(), port), Dial::FailLate(waiting));
        Gate(gate)
    }

    /// Lookups of `name` answer `answer`.
    pub fn name(&self, name: &str, answer: Result<(), ResolveErrKind>) {
        self.script().names.insert(name.to_owned(), answer);
    }

    /// Every open asked for so far, in order.
    #[must_use]
    pub fn opens(&self) -> Vec<(String, u16)> {
        self.script().opens.clone()
    }

    /// Every lookup asked for so far, in order.
    #[must_use]
    pub fn resolves(&self) -> Vec<String> {
        self.script().resolves.clone()
    }

    /// Returns once at least `n` opens have been asked for.
    pub async fn wait_for_opens(&self, n: usize) {
        loop {
            let asked = self.asked.notified();
            if self.script().opens.len() >= n {
                return;
            }
            asked.await;
        }
    }

    fn script(&self) -> MutexGuard<'_, Script> {
        self.script.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A [`FakeTunnel`] connection.
pub enum FakeConn {
    /// A plain TCP stream to the scripted address.
    Tcp(TcpStream),
    /// Echoes what it's sent, in memory.
    Echo,
    /// Never moves a byte.
    Stall,
    /// Closes at once.
    Hangup,
    /// Closes its sending side at once, then fails once the app has closed and the gate opens.
    FailLate(watch::Receiver<bool>),
}

impl Tunnel for FakeTunnel {
    type Conn = FakeConn;

    async fn open(&self, host: &str, port: u16) -> Result<FakeConn, OpenError> {
        let dial = {
            let mut script = self.script();
            script.opens.push((host.to_owned(), port));
            script.dials.get(&(host.to_owned(), port)).cloned()
        };
        self.asked.notify_waiters();
        let fail = |kind, reason: String| OpenError { kind, reason };
        match dial {
            None => Err(fail(OpenErrKind::Other, format!("nothing scripted for {host}:{port}"))),
            Some(Dial::Reject(kind)) => Err(fail(kind, format!("dialing {host}:{port}: scripted {kind:?}"))),
            Some(Dial::To(to)) => TcpStream::connect(to).await.map(FakeConn::Tcp).map_err(|e| fail(OpenErrKind::Other, format!("dialing {to}: {e}"))),
            Some(Dial::Gated(mut gate)) => {
                gate.wait_for(|open| *open).await.map_err(|_| fail(OpenErrKind::Other, "the gate was dropped".to_owned()))?;
                Ok(FakeConn::Echo)
            }
            Some(Dial::Stall) => Ok(FakeConn::Stall),
            Some(Dial::Hangup) => Ok(FakeConn::Hangup),
            Some(Dial::FailLate(gate)) => Ok(FakeConn::FailLate(gate)),
        }
    }

    fn resolve(&self, host: &str) -> impl Future<Output = Result<(), ResolveError>> + Send {
        let answer = {
            let mut script = self.script();
            script.resolves.push(host.to_owned());
            script.names.get(host).copied().unwrap_or(Err(ResolveErrKind::NoSuchName))
        };
        std::future::ready(answer.map_err(|kind| ResolveError {
            kind,
            reason: format!("resolving {host}: scripted {kind:?}"),
        }))
    }
}

impl Conn for FakeConn {
    async fn pump<IO>(self, mut io: IO) -> Res<Traffic>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send,
    {
        match self {
            Self::Tcp(mut stream) => {
                let (sent, received) = copy_bidirectional(&mut io, &mut stream).await.context("copying")?;
                Ok(Traffic { sent, received })
            }
            Self::Echo => {
                let (mut r, mut w) = split(io);
                let echoed = copy(&mut r, &mut w).await.context("echoing")?;
                w.shutdown().await.context("closing the echo")?;
                Ok(Traffic { sent: echoed, received: echoed })
            }
            Self::Stall => std::future::pending().await,
            Self::Hangup => {
                drop(io);
                Ok(Traffic::default())
            }
            Self::FailLate(mut gate) => {
                let (mut r, mut w) = split(io);
                w.shutdown().await.context("closing")?;
                let sent = copy(&mut r, &mut sink()).await.context("draining")?;
                let _ = gate.wait_for(|open| *open).await;
                bail!("the remote reset after {sent} bytes")
            }
        }
    }
}
