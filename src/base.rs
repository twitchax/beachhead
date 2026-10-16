//! The small vocabulary every module shares: the `anyhow` error aliases, defined once in
//! `beachhead-mux` so the client and the relay agree.

pub use beachhead_mux::base::{Err, Res, Void};
