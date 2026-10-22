//! The transport boundary: what `forward` (and later `route`) need from the way bytes reach the
//! remote, without naming the mux. A different backend implements [`Tunnel`] with its own native
//! streams and datagrams, and nothing above this seam changes.

use std::future::Future;

use bytes::Bytes;
use sshunnel_mux::{
    FlowEvent, Mux, OpenError, QueryError, ResolveError, Stream, Traffic,
    base::Res,
    frame::{Capabilities, Transport},
};
use tokio::io::{AsyncRead, AsyncWrite};

/// A way to reach hosts from the remote end: dial them, exchange datagrams with them, and ask the
/// remote's resolvers about their names.
pub trait Tunnel: Clone + Send + Sync + 'static {
    /// One open connection to a remote target.
    type Conn: Conn;
    /// One datagram flow to a remote target.
    type Flow: Flow;

    /// Dials `host:port` from the remote; `host` is resolved there too.
    fn open(&self, host: &str, port: u16) -> impl Future<Output = Result<Self::Conn, OpenError>> + Send;

    /// Resolves `host` on the remote, to learn whether it exists there.
    fn resolve(&self, host: &str) -> impl Future<Output = Result<(), ResolveError>> + Send;

    /// Opens a UDP flow to `host:port` from the remote; `host` is resolved there too.
    fn open_udp(&self, host: &str, port: u16) -> impl Future<Output = Result<Self::Flow, OpenError>> + Send;

    /// Opens an ICMP echo flow to `host` from the remote; `host` is resolved there too.
    fn open_echo(&self, host: &str) -> impl Future<Output = Result<Self::Flow, OpenError>> + Send;

    /// Asks the remote's resolvers a raw DNS `message`, over the `transport` its asker used.
    fn query(&self, message: Bytes, transport: Transport) -> impl Future<Output = Result<Bytes, QueryError>> + Send;

    /// What the remote end can do, such as ping.
    fn capabilities(&self) -> Capabilities;
}

/// An open connection to a remote target, ready to be joined to a local byte stream.
pub trait Conn: Send + 'static {
    /// Copies bytes both ways between the remote target and `io` until both directions close.
    fn pump<IO>(self, io: IO) -> impl Future<Output = Res<Traffic>> + Send
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send;
}

/// A datagram flow to a remote target. Dropping it ends the flow.
pub trait Flow: Send + 'static {
    /// The flow's sending half.
    type Sender: FlowSender;

    /// A sending half; any number may exist, and none keeps the flow open.
    fn sender(&self) -> Self::Sender;

    /// The next datagram or flow error from the remote, or `None` once the flow is over.
    fn recv(&mut self) -> impl Future<Output = Option<FlowEvent>> + Send;
}

/// The sending half of a tunnel's flows.
pub(crate) type SenderOf<T> = <<T as Tunnel>::Flow as Flow>::Sender;

/// A flow's sending half.
pub trait FlowSender: Clone + Send + Sync + 'static {
    /// Sends a datagram without waiting; `false` when it was dropped instead.
    fn try_send(&self, datagram: Bytes) -> bool;
}

impl Tunnel for Mux {
    type Conn = Stream;
    type Flow = sshunnel_mux::Flow;

    fn open(&self, host: &str, port: u16) -> impl Future<Output = Result<Stream, OpenError>> + Send {
        Self::open(self, host, port)
    }

    fn resolve(&self, host: &str) -> impl Future<Output = Result<(), ResolveError>> + Send {
        Self::resolve(self, host)
    }

    fn open_udp(&self, host: &str, port: u16) -> impl Future<Output = Result<sshunnel_mux::Flow, OpenError>> + Send {
        Self::open_udp(self, host, port)
    }

    fn open_echo(&self, host: &str) -> impl Future<Output = Result<sshunnel_mux::Flow, OpenError>> + Send {
        Self::open_echo(self, host)
    }

    fn query(&self, message: Bytes, transport: Transport) -> impl Future<Output = Result<Bytes, QueryError>> + Send {
        Self::query(self, message, transport)
    }

    fn capabilities(&self) -> Capabilities {
        Self::capabilities(self)
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

impl Flow for sshunnel_mux::Flow {
    type Sender = sshunnel_mux::FlowSender;

    fn sender(&self) -> sshunnel_mux::FlowSender {
        Self::sender(self)
    }

    fn recv(&mut self) -> impl Future<Output = Option<FlowEvent>> + Send {
        Self::recv(self)
    }
}

impl FlowSender for sshunnel_mux::FlowSender {
    fn try_send(&self, datagram: Bytes) -> bool {
        Self::try_send(self, datagram)
    }
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::{net::SocketAddr, sync::Arc};

    use anyhow::Context as _;
    use bytes::BytesMut;
    use sshunnel_mux::{Config, Request, Role, frame::OpenErrKind, hello::PeerHello};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
        net::{TcpListener, TcpStream},
    };

    use super::*;
    use crate::{forward, tests, tests::NoFlow};

    /// Ignores the target and dials a fixed local address, as a stand-in transport.
    #[derive(Clone)]
    struct Local(SocketAddr);

    struct Plain(TcpStream);

    impl Tunnel for Local {
        type Conn = Plain;
        type Flow = NoFlow;

        async fn open(&self, host: &str, port: u16) -> Result<Plain, OpenError> {
            TcpStream::connect(self.0).await.map(Plain).map_err(|e| OpenError {
                kind: OpenErrKind::Other,
                reason: format!("{host}:{port}: {e}"),
            })
        }

        fn resolve(&self, _host: &str) -> impl Future<Output = Result<(), ResolveError>> + Send {
            std::future::ready(Ok(()))
        }

        fn open_udp(&self, host: &str, port: u16) -> impl Future<Output = Result<NoFlow, OpenError>> + Send {
            NoFlow::refuse(&format!("UDP {host}:{port}"))
        }

        fn open_echo(&self, host: &str) -> impl Future<Output = Result<NoFlow, OpenError>> + Send {
            NoFlow::refuse(&format!("echo {host}"))
        }

        fn query(&self, _message: Bytes, _transport: Transport) -> impl Future<Output = Result<Bytes, QueryError>> + Send {
            NoFlow::unanswered()
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities::default()
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

    /// Sends one datagram through a flow and one query, through nothing but the traits.
    async fn exchange<T: Tunnel>(tunnel: &T) -> (Option<FlowEvent>, Result<Bytes, QueryError>) {
        let mut flow = tunnel.open_udp("h", 53).await.unwrap();
        assert!(flow.sender().try_send(Bytes::from_static(b"ping")));
        (flow.recv().await, tunnel.query(Bytes::from_static(b"q"), Transport::Tcp).await)
    }

    #[tokio::test]
    async fn a_mux_carries_flows_and_queries_through_the_trait() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let ((ar, aw), (br, bw)) = (tokio::io::split(a), tokio::io::split(b));
        let config = Config::default();
        let relay_hello = PeerHello {
            window: config.window(),
            capabilities: Capabilities { ping4: true, ping6: false },
        };
        let client_hello = PeerHello {
            window: config.window(),
            capabilities: Capabilities::default(),
        };
        let (client, _client_incoming, client_driver) = sshunnel_mux::start(ar, BytesMut::new(), aw, Role::Client, config, relay_hello);
        let (_relay, mut relay_incoming, relay_driver) = sshunnel_mux::start(br, BytesMut::new(), bw, Role::Relay, config, client_hello);
        tokio::spawn(client_driver);
        tokio::spawn(relay_driver);
        // The relay echoes datagrams back and answers queries with their transport.
        tokio::spawn(async move {
            while let Some(request) = relay_incoming.next().await {
                match request {
                    Request::OpenFlow(request) => {
                        let mut flow = request.accept();
                        tokio::spawn(async move {
                            while let Some(FlowEvent::Datagram(datagram)) = flow.recv().await {
                                flow.sender().try_send(datagram);
                            }
                        });
                    }
                    Request::Query(query) => {
                        let answer = format!("{:?}", query.transport());
                        query.answer(Ok(Bytes::from(answer)));
                    }
                    Request::Open(_) | Request::Resolve(_) => panic!("unexpected request"),
                }
            }
        });

        let (echoed, answer) = exchange(&client).await;
        assert_eq!(echoed, Some(FlowEvent::Datagram(Bytes::from_static(b"ping"))));
        assert_eq!(answer.unwrap(), Bytes::from_static(b"Tcp"));
        assert_eq!(Tunnel::capabilities(&client), Capabilities { ping4: true, ping6: false });
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
