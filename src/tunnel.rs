//! The transport boundary: what `forward` (and later `route`) need from the way bytes reach the
//! remote, without naming the mux. A different backend implements [`Tunnel`] with its own native
//! streams and nothing above this seam changes.

use std::future::Future;

use sshunnel_mux::{Mux, OpenError, ResolveError, Stream, Traffic, base::Res};
use tokio::io::{AsyncRead, AsyncWrite};

/// A way to reach hosts from the remote end: dial them and resolve their names there.
pub trait Tunnel: Clone + Send + Sync + 'static {
    /// One open connection to a remote target.
    type Conn: Conn;

    /// Dials `host:port` from the remote; `host` is resolved there too.
    fn open(&self, host: &str, port: u16) -> impl Future<Output = Result<Self::Conn, OpenError>> + Send;

    /// Resolves `host` on the remote, to learn whether it exists there.
    fn resolve(&self, host: &str) -> impl Future<Output = Result<(), ResolveError>> + Send;
}

/// An open connection to a remote target, ready to be joined to a local byte stream.
pub trait Conn: Send + 'static {
    /// Copies bytes both ways between the remote target and `io` until both directions close.
    fn pump<IO>(self, io: IO) -> impl Future<Output = Res<Traffic>> + Send
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send;
}

impl Tunnel for Mux {
    type Conn = Stream;

    fn open(&self, host: &str, port: u16) -> impl Future<Output = Result<Stream, OpenError>> + Send {
        Self::open(self, host, port)
    }

    fn resolve(&self, host: &str) -> impl Future<Output = Result<(), ResolveError>> + Send {
        Self::resolve(self, host)
    }
}

impl Conn for Stream {
    fn pump<IO>(self, io: IO) -> impl Future<Output = Res<Traffic>> + Send
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send,
    {
        sshunnel_mux::pump(self, io)
    }
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::{net::SocketAddr, sync::Arc};

    use anyhow::Context as _;
    use sshunnel_mux::frame::OpenErrKind;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
        net::{TcpListener, TcpStream},
    };

    use super::*;
    use crate::{forward, tests};

    /// Ignores the target and dials a fixed local address, as a stand-in transport.
    #[derive(Clone)]
    struct Local(SocketAddr);

    struct Plain(TcpStream);

    impl Tunnel for Local {
        type Conn = Plain;

        async fn open(&self, host: &str, port: u16) -> Result<Plain, OpenError> {
            TcpStream::connect(self.0).await.map(Plain).map_err(|e| OpenError {
                kind: OpenErrKind::Other,
                reason: format!("{host}:{port}: {e}"),
            })
        }

        fn resolve(&self, _host: &str) -> impl Future<Output = Result<(), ResolveError>> + Send {
            std::future::ready(Ok(()))
        }
    }

    impl Conn for Plain {
        async fn pump<IO>(mut self, mut io: IO) -> Res<Traffic>
        where
            IO: AsyncRead + AsyncWrite + Unpin + Send,
        {
            let (sent, received) = copy_bidirectional(&mut io, &mut self.0).await.context("copying")?;
            Ok(Traffic { sent, received })
        }
    }

    #[tokio::test]
    async fn forward_serves_through_any_tunnel() {
        let echo = tests::echo_server().await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(forward::serve(Local(echo), listener, Arc::from("anywhere.example"), 7));

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"hello tunnel").await.unwrap();
        client.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).await.unwrap();

        assert_eq!(echoed, b"hello tunnel");
        server.abort();
    }
}
