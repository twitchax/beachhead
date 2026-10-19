//! `sshunnel route`: a userspace VPN for chosen targets. [`targets`] holds the pure parts (parsing,
//! matching, refusals) that the client and the root helper both run, so they cannot disagree.

use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

pub mod dns;
#[cfg(target_os = "linux")]
pub mod helper;
pub mod names;
pub mod router;
pub mod stack;
#[cfg(target_os = "linux")]
pub mod system;
pub mod targets;

/// The TUN device's name.
pub const DEVICE: &str = "sshunnel0";
/// The range fake addresses for routed names are drawn from; `198.18.0.0/24` is reserved.
pub const FAKE_RANGE: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(198, 18, 0, 0), 15);
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
