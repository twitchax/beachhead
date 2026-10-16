//! beachhead's wire protocol and stream multiplexer, shared by the client and the relay.
//!
//! [`frame`] is the wire format, [`hello`] the handshake, [`start`] runs a connection, and [`pump`]
//! joins one stream to a socket.

pub mod base;
pub mod frame;
pub mod hello;
mod mux;
mod stream;

pub use mux::{Config, Incoming, Mux, OpenRequest, Role, start};
pub use stream::{Stream, Traffic, pump};
