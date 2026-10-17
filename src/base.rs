//! The small vocabulary every module shares: the `anyhow` error aliases, defined once in
//! `sshunnel-mux` so the client and the relay agree.

pub use sshunnel_mux::base::{Err, Res, Void};
