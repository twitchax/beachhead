//! `sshunnel route`: a userspace VPN for chosen targets. [`targets`] holds the pure parts (parsing,
//! matching, refusals) that the client and the root helper both run, so they cannot disagree; `run`
//! (Linux only) is the command from start to exit.

use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

mod datagrams;
#[cfg(target_os = "linux")]
mod device;
pub mod dns;
#[cfg(target_os = "linux")]
pub mod helper;
#[cfg(target_os = "linux")]
mod lifecycle;
pub mod names;
#[cfg(target_os = "linux")]
pub mod peers;
pub mod router;
pub mod stack;
#[cfg(target_os = "linux")]
pub mod system;
pub mod targets;
#[cfg(target_os = "linux")]
mod thread;

#[cfg(target_os = "linux")]
pub use lifecycle::{Options, run};

/// The TUN device's name.
pub const DEVICE: &str = "sshunnel0";
/// The range fake addresses for routed names are drawn from; `198.18.0.0/24` is reserved.
pub const FAKE_RANGE: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(198, 18, 0, 0), 15);
/// The range fake IPv6 addresses for routed names live in, inside RFC 5180's benchmarking range: each
/// is a name's v4 fake in the low 32 bits ([`names::fake_v6`]).
pub const FAKE_RANGE6: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 2, 0, 0, 0, 0, 0, 0), 96);
/// The device's IPv4 address, inside [`FAKE_RANGE`].
pub const TUN_ADDR: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
/// Where the in-process DNS server answers.
pub const DNS_ADDR: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
/// The device's unique-local IPv6 address and prefix.
pub const TUN_ADDR6: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0xfd73, 0x7368, 0, 0, 0, 0, 0, 1), 64);
/// The device's MTU.
pub const MTU: u16 = 65535;
/// The routing protocol number tagging pinned host routes, so teardown finds exactly its own.
pub const PIN_PROTO: u8 = 222;
/// What `route` warns once its routes are up, when the relay may ping over neither family.
pub const PING_WARNING: &str = "the remote doesn't allow unprivileged ping (net.ipv4.ping_group_range), so ping through the tunnel gets administratively prohibited";
