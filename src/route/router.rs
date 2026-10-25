//! The routing decision for one destination address: what the relay should dial for it, if
//! anything. The netstack asks it for every new connection; the DNS server shares its fake-address
//! map.

use std::{
    net::IpAddr,
    sync::{Mutex, MutexGuard, PoisonError},
};

use crate::route::{
    names::{FakeMap, fake_v4_of},
    targets::Targets,
};

/// A session's targets and the fake-address map they route names through.
#[derive(Debug)]
pub struct Router {
    targets: Targets,
    names: Mutex<FakeMap>,
}

impl Router {
    #[must_use]
    pub fn new(targets: Targets, names: FakeMap) -> Self {
        Self { targets, names: Mutex::new(names) }
    }

    /// The host the relay should dial for a connection to `addr`: the name behind a fake address
    /// (a v6 fake through its v4 one) when the targets route that name, the address itself when the
    /// targets route it, else `None`. A fake address with no name, or a name this session doesn't
    /// route, is `None`.
    #[must_use]
    pub fn destination(&self, addr: IpAddr) -> Option<String> {
        match fake_v4_of(addr) {
            Some(v4) => {
                let names = self.names();
                let name = names.name(v4)?;
                self.targets.routes_name(name).then(|| name.to_owned())
            }
            None => self.targets.routes_addr(addr).then(|| addr.to_string()),
        }
    }

    #[must_use]
    pub fn targets(&self) -> &Targets {
        &self.targets
    }

    /// The fake-address map. A panic while it was held can't leave it inconsistent (each update
    /// is one insert pair), so a poisoned lock is taken as is.
    pub fn names(&self) -> MutexGuard<'_, FakeMap> {
        self.names.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::net::Ipv4Addr;

    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    use super::*;
    use crate::route::{
        DNS_ADDR, TUN_ADDR,
        names::{fake_v6, today},
    };

    fn router(include: &[&str], exclude: &[&str]) -> (Router, TempDir) {
        let state = TempDir::new().unwrap();
        let own = |list: &[&str]| list.iter().map(|t| (*t).to_owned()).collect::<Vec<_>>();
        let targets = Targets::parse(&own(include), &own(exclude)).unwrap();
        let names = FakeMap::load(state.path().join("names"), today()).unwrap();
        (Router::new(targets, names), state)
    }

    #[test]
    fn a_routed_address_is_dialed_as_itself() {
        let (router, _state) = router(&["10.99.0.0/16", "fd99::/64"], &["10.99.7.0/24"]);

        assert_eq!(router.destination("10.99.0.5".parse().unwrap()), Some("10.99.0.5".to_owned()));
        assert_eq!(router.destination("fd99::5".parse().unwrap()), Some("fd99::5".to_owned()));
        assert_eq!(router.destination("10.99.7.1".parse().unwrap()), None);
        assert_eq!(router.destination("192.0.2.1".parse().unwrap()), None);
    }

    #[test]
    fn a_fake_address_is_dialed_by_its_name_when_the_name_is_routed() {
        let (router, _state) = router(&["*.corp.example"], &["secret.corp.example"]);
        let wiki = router.names().address("wiki.corp.example", today());
        let secret = router.names().address("secret.corp.example", today());
        let other = router.names().address("wiki.other.example", today());

        assert_eq!(router.destination(wiki.into()), Some("wiki.corp.example".to_owned()));
        assert_eq!(router.destination(secret.into()), None);
        assert_eq!(router.destination(other.into()), None);
    }

    #[test]
    fn the_fake_range_is_never_routed_by_address() {
        // A CIDR target containing the fake range doesn't reach its unassigned or reserved addresses.
        let (router, _state) = router(&["198.16.0.0/12"], &[]);

        assert_eq!(router.destination(Ipv4Addr::new(198, 18, 200, 7).into()), None);
        assert_eq!(router.destination(DNS_ADDR.into()), None);
        assert_eq!(router.destination(TUN_ADDR.into()), None);
        assert_eq!(router.destination(Ipv4Addr::new(198, 17, 0, 1).into()), Some("198.17.0.1".to_owned()));
    }

    #[test]
    fn fake_v6_addresses_dial_by_name() {
        let (router, _state) = router(&["*.corp.example"], &["secret.corp.example"]);
        let wiki = router.names().address("wiki.corp.example", today());
        let secret = router.names().address("secret.corp.example", today());

        assert_eq!(router.destination(fake_v6(wiki).into()), Some("wiki.corp.example".to_owned()));
        assert_eq!(router.destination(fake_v6(secret).into()), None);
        assert_eq!(router.destination(fake_v6(Ipv4Addr::new(198, 18, 200, 7)).into()), None);
    }

    #[test]
    fn fake_v6_range_is_never_routed_by_address() {
        // A CIDR target containing the v6 fake range reaches neither its unassigned fakes nor the
        // addresses whose low bits fall outside the v4 range.
        let (router, _state) = router(&["2001::/16"], &[]);

        assert_eq!(router.destination(fake_v6(Ipv4Addr::new(198, 18, 200, 7)).into()), None);
        assert_eq!(router.destination(fake_v6(DNS_ADDR).into()), None);
        assert_eq!(router.destination("2001:2::1".parse().unwrap()), None);
        assert_eq!(router.destination("2001:3::1".parse().unwrap()), Some("2001:3::1".to_owned()));
    }
}
