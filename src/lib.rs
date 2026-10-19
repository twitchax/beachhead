//! A userspace VPN over plain SSH: push-exec a static musl relay, cache it by hash, route through it.
//!
//! [`session::Session`] runs the system `ssh` with the [`bootstrap`] script, which finds or
//! receives the relay and execs it; the mux from `sshunnel-mux` then carries streams over that
//! one session. [`tunnel::Tunnel`] is the seam between that transport and its users; [`forward`]
//! turns local TCP listeners into streams through it.

pub mod arch;
pub mod base;
pub mod bootstrap;
pub mod forward;
pub mod relays;
pub mod route;
pub mod session;
pub mod tests;
pub mod tunnel;
