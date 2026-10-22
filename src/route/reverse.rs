//! Reverse-lookup names (`in-addr.arpa`, `ip6.arpa`) and the zones of the fake ranges, which the
//! DNS server answers itself: a fake address's PTR is the name it was handed out for.

use std::net::{IpAddr, Ipv6Addr};

use ipnet::IpNet;

use crate::route::{FAKE_RANGE, FAKE_RANGE6, targets::normalize};

const V4_SUFFIX: &str = "in-addr.arpa";
const V6_SUFFIX: &str = "ip6.arpa";

/// What a name is to the reverse zones of the fake ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reverse {
    /// The reverse name of this address, in a fake range's zone or not.
    Addr(IpAddr),
    /// In a fake range's zone, but no address's name: shorter than one, or no name [`name`] writes.
    InZone,
    /// Neither.
    Outside,
}

/// The reverse zones of [`FAKE_RANGE`], and with fake v6 of [`FAKE_RANGE6`]. A zone ends on a
/// label, so a range whose prefix doesn't (v4's `/15`) takes one zone per subnet at the next label.
#[must_use]
pub fn zones(fake_v6: bool) -> Vec<String> {
    let mut ranges = vec![IpNet::V4(FAKE_RANGE)];
    if fake_v6 {
        ranges.push(IpNet::V6(FAKE_RANGE6));
    }
    ranges.into_iter().flat_map(range_zones).collect()
}

/// The reverse-lookup name of `addr`: `2.1.18.198.in-addr.arpa` for `198.18.1.2`.
#[must_use]
pub fn name(addr: IpAddr) -> String {
    let labels = digits(addr).len();
    reversed(addr, labels)
}

/// What `name` is to the fake ranges' zones, ignoring case and a trailing dot. Each label must be
/// written as [`name`] writes it: `05` is no octet, and `c` is a nibble but `0c` isn't.
#[must_use]
pub fn parse(name: &str) -> Reverse {
    let name = normalize(name);
    let addr = if let Some(labels) = labels_under(&name, V4_SUFFIX) {
        v4(labels)
    } else if let Some(labels) = labels_under(&name, V6_SUFFIX) {
        v6(labels)
    } else {
        return Reverse::Outside;
    };
    match addr {
        Some(addr) => Reverse::Addr(addr),
        None if zones(true).iter().any(|zone| within(&name, zone)) => Reverse::InZone,
        None => Reverse::Outside,
    }
}

fn range_zones(range: IpNet) -> impl Iterator<Item = String> {
    let bits = label_bits(range.addr());
    let labels = range.prefix_len().div_ceil(bits);
    // Never an error: the new prefix lies between the range's and the address's length.
    range.subnets(labels * bits).into_iter().flatten().map(move |zone| reversed(zone.network(), usize::from(labels)))
}

/// The bits one label of a reverse name carries: an octet for v4, a nibble for v6.
fn label_bits(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 8 } else { 4 }
}

/// `addr`'s labels, most significant first: v4's octets in decimal, v6's nibbles in hex.
fn digits(addr: IpAddr) -> Vec<String> {
    match addr {
        IpAddr::V4(v4) => v4.octets().iter().map(u8::to_string).collect(),
        IpAddr::V6(v6) => v6.octets().iter().flat_map(|byte| [byte >> 4, byte & 0xf]).map(|nibble| format!("{nibble:x}")).collect(),
    }
}

/// The reverse name of `addr`'s first `labels` labels.
fn reversed(addr: IpAddr, labels: usize) -> String {
    let mut name = digits(addr);
    name.truncate(labels);
    name.reverse();
    name.push((if addr.is_ipv4() { V4_SUFFIX } else { V6_SUFFIX }).to_owned());
    name.join(".")
}

/// The labels of `name` under `suffix`, least significant first.
fn labels_under<'a>(name: &'a str, suffix: &str) -> Option<std::str::Split<'a, char>> {
    Some(name.strip_suffix(suffix)?.strip_suffix('.')?.split('.'))
}

fn within(name: &str, zone: &str) -> bool {
    name.strip_suffix(zone).is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
}

fn v4(labels: std::str::Split<'_, char>) -> Option<IpAddr> {
    let octets: Vec<u8> = labels.rev().map(octet).collect::<Option<_>>()?;
    let octets: [u8; 4] = octets.try_into().ok()?;
    Some(IpAddr::from(octets))
}

fn v6(labels: std::str::Split<'_, char>) -> Option<IpAddr> {
    let nibbles: Vec<u8> = labels.rev().map(nibble).collect::<Option<_>>()?;
    let nibbles: [u8; 32] = nibbles.try_into().ok()?;
    Some(IpAddr::V6(Ipv6Addr::from(nibbles.iter().fold(0_u128, |bits, &nibble| (bits << 4) | u128::from(nibble)))))
}

/// An octet in decimal, with no sign or leading zero.
fn octet(label: &str) -> Option<u8> {
    let canonical = label.bytes().all(|b| b.is_ascii_digit()) && (label == "0" || !label.starts_with('0'));
    if canonical { label.parse().ok() } else { None }
}

/// A nibble: one hex digit.
fn nibble(label: &str) -> Option<u8> {
    let [digit] = label.as_bytes() else { return None };
    char::from(*digit).to_digit(16).and_then(|n| u8::try_from(n).ok())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::net::{Ipv4Addr, Ipv6Addr};

    use pretty_assertions::assert_eq;

    use super::*;

    /// `2001:2::/96`'s zone: its 24 nibbles, least significant first.
    const ZONE6: &str = "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.1.0.0.2.ip6.arpa";

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    #[test]
    fn ptr_zones_cover_the_fake_ranges() {
        assert_eq!(zones(false), ["18.198.in-addr.arpa", "19.198.in-addr.arpa"]);
        assert_eq!(zones(true), ["18.198.in-addr.arpa", "19.198.in-addr.arpa", ZONE6]);
    }

    #[test]
    fn ptr_names_parse_both_families() {
        let fake6 = format!("2.0.1.0.2.1.6.c.{ZONE6}");
        assert_eq!(name(v4("198.18.1.2")), "2.1.18.198.in-addr.arpa");
        assert_eq!(name(v6("2001:2::c612:102")), fake6);
        assert_eq!(name(v4("192.0.2.10")), "10.2.0.192.in-addr.arpa");

        assert_eq!(parse("2.1.18.198.in-addr.arpa"), Reverse::Addr(v4("198.18.1.2")));
        assert_eq!(parse("2.1.18.198.IN-ADDR.ARPA."), Reverse::Addr(v4("198.18.1.2")));
        assert_eq!(parse(&fake6), Reverse::Addr(v6("2001:2::c612:102")));
        assert_eq!(parse(&format!("{}.", fake6.to_uppercase())), Reverse::Addr(v6("2001:2::c612:102")));
        // Outside the fake ranges a name is still an address's; the server decides what that means.
        assert_eq!(parse("10.2.0.192.in-addr.arpa"), Reverse::Addr(v4("192.0.2.10")));

        for addr in [v4("198.19.255.254"), v4("0.0.0.0"), v4("255.255.255.255"), v6("2001:2::c613:fffe"), v6("fd99::1"), v6("::")] {
            assert_eq!(parse(&name(addr)), Reverse::Addr(addr), "{addr}");
        }
    }

    #[test]
    fn ptr_names_in_a_zone_but_short_of_an_address_are_in_zone() {
        for name in [
            "18.198.in-addr.arpa",
            "19.198.in-addr.arpa.",
            "0.18.198.in-addr.arpa",
            "255.19.198.IN-ADDR.ARPA",
            ZONE6,
            &format!("c.{ZONE6}"),
            &format!("2.1.6.c.{ZONE6}"),
        ] {
            assert_eq!(parse(name), Reverse::InZone, "{name}");
        }
    }

    #[test]
    fn ptr_names_in_a_zone_that_name_no_address_are_in_zone() {
        for name in [
            "x.0.18.198.in-addr.arpa",
            "05.0.18.198.in-addr.arpa",
            "+5.0.18.198.in-addr.arpa",
            "256.0.18.198.in-addr.arpa",
            "1.2.0.18.198.in-addr.arpa",
            "_dns-sd._udp.0.18.198.in-addr.arpa",
            &format!("g.0.0.0.0.0.0.0.{ZONE6}"),
            &format!("10.0.0.0.0.0.0.0.{ZONE6}"),
            &format!("0.0.0.0.0.0.0.0.0.{ZONE6}"),
        ] {
            assert_eq!(parse(name), Reverse::InZone, "{name}");
        }
    }

    #[test]
    fn ptr_names_outside_the_zones_are_outside() {
        for name in [
            "wiki.corp.example",
            "in-addr.arpa",
            "198.in-addr.arpa",
            "17.198.in-addr.arpa",
            "0.20.198.in-addr.arpa",
            "x.4.3.2.1.in-addr.arpa",
            "18.198.in-addr.arpa.example",
            "a18.198.in-addr.arpa",
            "ip6.arpa",
            "0.0.2.0.0.0.1.0.0.2.ip6.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.1.0.0.2.ip6.arpa",
            "",
            ".",
        ] {
            assert_eq!(parse(name), Reverse::Outside, "{name}");
        }
    }
}
