//! sshunnel's wire protocol and stream multiplexer, shared by the client and the relay.
//!
//! [`frame`] is the wire format, [`hello`] the handshake, [`start`] runs a connection, [`pump`]
//! joins one stream to a socket, and a [`Flow`] carries datagrams outside credit.

pub mod base;
mod flow;
pub mod frame;
pub mod hello;
mod mux;
mod stream;

pub use flow::{FLOW_QUEUE, FLOW_QUEUE_BYTES, Flow, FlowEvent, FlowKind, FlowSender};
pub use mux::{Config, FlowRequest, Incoming, Mux, OpenError, OpenRequest, QueryError, QueryRequest, Request, ResolveError, ResolveRequest, Role, start};
pub use stream::{Stream, Traffic, pump};
