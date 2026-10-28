//! The fake-address map: each routed name gets a stable address in [`FAKE_RANGE`], so the DNS
//! server can hand it out and the netstack can map it back to a name.
//!
//! An address starts at the name's hash slot and probes past collisions. The assignment is
//! persisted, and the persisted entry wins over the hash, so a collided name keeps its probed
//! address across restarts. Entries unused for `PRUNE_AFTER_DAYS` are dropped on load.
//!
//! A name's v6 fake ([`fake_v6`]) derives from its v4 one, so it needs no state of its own and the
//! two always pair.

use std::{
    collections::HashMap,
    ffi::OsString,
    fmt::Write as _,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use sha2::{Digest as _, Sha256};

use crate::{
    base::{Res, Void},
    route::{FAKE_RANGE, FAKE_RANGE6, targets::normalize},
};

/// The first assignable address; `198.18.0.0/24` stays reserved for the device and the DNS server.
const FIRST_SLOT: Ipv4Addr = Ipv4Addr::new(198, 18, 1, 0);
/// `198.18.1.0` through `198.19.255.254`: the range minus its reserved `/24` and its broadcast address.
const SLOTS: u32 = 130_815;
/// An entry unused for more than this many days is dropped on load.
const PRUNE_AFTER_DAYS: u32 = 30;
const SECS_PER_DAY: u64 = 86_400;

#[derive(Debug, Clone, Copy)]
struct Entry {
    addr: Ipv4Addr,
    last_used: u32,
}

/// Names and their fake addresses, backed by a state file.
#[derive(Debug)]
pub struct FakeMap {
    by_name: HashMap<String, Entry>,
    by_addr: HashMap<Ipv4Addr, String>,
    path: PathBuf,
    dirty: bool,
}

impl FakeMap {
    /// Reads the state file (a missing one is an empty map), skipping malformed lines and dropping
    /// entries unused for more than 30 days as of `today`.
    ///
    /// # Errors
    /// Fails when the file exists but cannot be read.
    pub fn load(path: PathBuf, today: u32) -> Res<Self> {
        let mut map = Self {
            by_name: HashMap::new(),
            by_addr: HashMap::new(),
            path,
            dirty: false,
        };

        let text = match fs::read_to_string(&map.path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(map),
            Err(e) => return Err(e).with_context(|| format!("reading {}", map.path.display())),
        };

        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let Some((addr, name, last_used)) = parse_line(line) else {
                tracing::warn!(line, "skipping a malformed line in the names file");
                map.dirty = true;
                continue;
            };
            if today.saturating_sub(last_used) > PRUNE_AFTER_DAYS {
                map.dirty = true;
                continue;
            }
            if map.by_name.contains_key(&name) || map.by_addr.contains_key(&addr) {
                tracing::warn!(line, "skipping a duplicate line in the names file");
                map.dirty = true;
                continue;
            }
            map.by_addr.insert(addr, name.clone());
            map.by_name.insert(name, Entry { addr, last_used });
        }

        Ok(map)
    }

    /// The name's address: its persisted one, else its hash slot, else the next free slot after it
    /// (wrapping). Marks the name used on `today`.
    pub fn address(&mut self, name: &str, today: u32) -> Ipv4Addr {
        let name = normalize(name);

        if let Some(entry) = self.by_name.get_mut(&name) {
            if entry.last_used != today {
                entry.last_used = today;
                self.dirty = true;
            }
            return entry.addr;
        }

        let start = slot_index(&name);
        let free = (0..SLOTS).map(|i| slot_addr((start + i) % SLOTS)).find(|a| !self.by_addr.contains_key(a));
        let addr = free.unwrap_or_else(|| self.evict_least_recently_used());

        self.by_addr.insert(addr, name.clone());
        self.by_name.insert(name, Entry { addr, last_used: today });
        self.dirty = true;
        addr
    }

    /// Frees the address of the stalest entry (the lowest address among ties, to stay deterministic)
    /// and returns it. Only reached when every slot is owned, so a name never shares an address.
    fn evict_least_recently_used(&mut self) -> Ipv4Addr {
        let (name, addr) = self
            .by_name
            .iter()
            .map(|(name, e)| (name, e.addr, e.last_used))
            .min_by_key(|&(_, addr, last_used)| (last_used, addr))
            .map_or_else(|| (String::new(), slot_addr(0)), |(name, addr, _)| (name.clone(), addr));
        tracing::warn!(name, %addr, "the fake address range is exhausted; evicting the least recently used name");
        self.by_name.remove(&name);
        self.by_addr.remove(&addr);
        addr
    }

    /// The name a fake address was handed out for.
    #[must_use]
    pub fn name(&self, addr: Ipv4Addr) -> Option<&str> {
        self.by_addr.get(&addr).map(String::as_str)
    }

    /// Writes the state file through a temp file and a rename; a no-op when nothing changed.
    ///
    /// # Errors
    /// Fails when the directory or file cannot be written.
    pub fn save(&self) -> Void {
        if !self.dirty {
            return Ok(());
        }

        let mut entries: Vec<_> = self.by_name.iter().collect();
        entries.sort_unstable_by_key(|(_, e)| e.addr);
        let mut text = String::new();
        for (name, e) in entries {
            writeln!(text, "{} {name} {}", e.addr, e.last_used).context("formatting the names file")?;
        }

        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, &self.path).with_context(|| format!("replacing {}", self.path.display()))?;
        Ok(())
    }
}

/// The v6 fake paired with a v4 one: [`FAKE_RANGE6`] with the v4 fake in its low 32 bits.
#[must_use]
pub fn fake_v6(v4: Ipv4Addr) -> Ipv6Addr {
    Ipv6Addr::from_bits(FAKE_RANGE6.network().to_bits() | u128::from(v4.to_bits()))
}

/// The v4 fake inside a v6 one: `None` outside [`FAKE_RANGE6`], or when the low 32 bits fall
/// outside [`FAKE_RANGE`].
#[must_use]
pub fn fake_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let [.., a, b, c, d] = v6.octets();
    let v4 = Ipv4Addr::new(a, b, c, d);
    (FAKE_RANGE6.contains(&v6) && FAKE_RANGE.contains(&v4)).then_some(v4)
}

/// The v4 fake behind a fake address of either family: a v4 one inside [`FAKE_RANGE`], or a v6 one
/// inside [`FAKE_RANGE6`] through [`fake_v4`]. `None` for any other address.
#[must_use]
pub fn fake_v4_of(addr: IpAddr) -> Option<Ipv4Addr> {
    match addr {
        IpAddr::V4(v4) => FAKE_RANGE.contains(&v4).then_some(v4),
        IpAddr::V6(v6) => fake_v4(v6),
    }
}

/// The address a name hashes to before probing.
#[must_use]
pub fn slot(name: &str) -> Ipv4Addr {
    slot_addr(slot_index(&normalize(name)))
}

/// `$XDG_STATE_HOME/sshunnel/names`, defaulting to `~/.local/state/sshunnel/names`.
///
/// # Errors
/// Fails when neither `XDG_STATE_HOME` nor `HOME` is set.
pub fn state_path() -> Res<PathBuf> {
    state_path_from(std::env::var_os("XDG_STATE_HOME"), std::env::var_os("HOME"))
}

/// An empty variable counts as unset, per the XDG base directory spec.
fn state_path_from(xdg_state_home: Option<OsString>, home: Option<OsString>) -> Res<PathBuf> {
    let base = if let Some(dir) = xdg_state_home.filter(|v| !v.is_empty()) {
        PathBuf::from(dir)
    } else {
        let home = home.filter(|v| !v.is_empty()).context("neither XDG_STATE_HOME nor HOME is set")?;
        PathBuf::from(home).join(".local/state")
    };
    Ok(base.join("sshunnel").join("names"))
}

/// Days since the Unix epoch.
#[must_use]
pub fn today() -> u32 {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    u32::try_from(secs / SECS_PER_DAY).unwrap_or(u32::MAX)
}

/// The first 8 bytes of the SHA-256 of an already-normalized name, big-endian, modulo [`SLOTS`].
fn slot_index(normalized: &str) -> u32 {
    let digest = Sha256::digest(normalized.as_bytes());
    let mut head = [0_u8; 8];
    head.copy_from_slice(&digest[..8]);
    // The remainder is below SLOTS, which fits a u32.
    u32::try_from(u64::from_be_bytes(head) % u64::from(SLOTS)).unwrap_or(0)
}

fn slot_addr(index: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(FIRST_SLOT) + index)
}

/// `address name last-used-day`, with the address inside the slot space.
fn parse_line(line: &str) -> Option<(Ipv4Addr, String, u32)> {
    let mut parts = line.split_whitespace();
    let addr: Ipv4Addr = parts.next()?.parse().ok()?;
    let name = parts.next()?;
    let last_used: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let offset = u32::from(addr).checked_sub(u32::from(FIRST_SLOT))?;
    (offset < SLOTS).then(|| (addr, normalize(name), last_used))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    use super::*;

    fn map_in(dir: &TempDir, today: u32) -> FakeMap {
        FakeMap::load(dir.path().join("names"), today).unwrap()
    }

    /// Two distinct names with the same hash slot, found by search.
    fn colliding_pair() -> (String, String) {
        let mut seen: HashMap<Ipv4Addr, String> = HashMap::new();
        for i in 0.. {
            let name = format!("host{i}.corp.example");
            if let Some(other) = seen.insert(slot(&name), name.clone()) {
                return (other, name);
            }
        }
        unreachable!()
    }

    #[test]
    fn fake_address_is_the_names_slot() {
        let dir = TempDir::new().unwrap();
        let mut map = map_in(&dir, 0);
        let addr = map.address("wiki.corp.example", 0);
        assert_eq!(addr, slot("wiki.corp.example"));
        assert!(FAKE_RANGE.contains(&addr));
    }

    #[test]
    fn fake_address_ignores_case_and_trailing_dot() {
        let dir = TempDir::new().unwrap();
        let mut map = map_in(&dir, 0);
        let plain = map.address("wiki.corp.example", 0);
        assert_eq!(map.address("WIKI.Corp.Example.", 0), plain);
        assert_eq!(slot("WIKI.Corp.Example."), slot("wiki.corp.example"));
    }

    #[test]
    fn fake_address_survives_a_restart() {
        let dir = TempDir::new().unwrap();
        let mut map = map_in(&dir, 0);
        let addr = map.address("wiki.corp.example", 0);
        map.save().unwrap();

        let mut reloaded = map_in(&dir, 1);
        assert_eq!(reloaded.address("wiki.corp.example", 1), addr);
        assert_eq!(reloaded.name(addr), Some("wiki.corp.example"));
    }

    #[test]
    fn fake_address_collision_keeps_its_slot_after_restart() {
        let (a, b) = colliding_pair();
        let dir = TempDir::new().unwrap();
        let mut map = map_in(&dir, 0);
        let first = map.address(&a, 0);
        let second = map.address(&b, 0);
        assert_eq!(first, slot(&a));
        assert_ne!(second, first);
        assert_eq!(u32::from(second), u32::from(first) + 1);
        map.save().unwrap();

        // Asking for B first must not hand it A's slot: the persisted entry wins over the hash.
        let mut reloaded = map_in(&dir, 0);
        assert_eq!(reloaded.address(&b, 0), second);
        assert_eq!(reloaded.address(&a, 0), first);
    }

    #[test]
    fn fake_address_unused_for_30_days_is_pruned() {
        let dir = TempDir::new().unwrap();
        let mut map = map_in(&dir, 0);
        let addr = map.address("wiki.corp.example", 0);
        map.save().unwrap();

        assert_eq!(map_in(&dir, 30).name(addr), Some("wiki.corp.example"));
        assert_eq!(map_in(&dir, 31).name(addr), None);
    }

    #[test]
    fn fake_address_use_refreshes_the_prune_clock() {
        let dir = TempDir::new().unwrap();
        let mut map = map_in(&dir, 0);
        let addr = map.address("wiki.corp.example", 0);
        map.save().unwrap();

        let mut later = map_in(&dir, 20);
        later.address("wiki.corp.example", 20);
        later.save().unwrap();
        assert_eq!(map_in(&dir, 45).name(addr), Some("wiki.corp.example"));
    }

    #[test]
    fn fake_address_name_is_the_reverse_lookup() {
        let dir = TempDir::new().unwrap();
        let mut map = map_in(&dir, 0);
        let addr = map.address("Wiki.Corp.Example.", 0);
        assert_eq!(map.name(addr), Some("wiki.corp.example"));
        assert_eq!(map.name(Ipv4Addr::new(198, 18, 9, 9)), None);
    }

    #[test]
    fn fake_address_never_uses_the_reserved_24() {
        let first = u32::from(FIRST_SLOT);
        for i in 0..20_000 {
            let addr = slot(&format!("n{i}.corp.example"));
            assert!(FAKE_RANGE.contains(&addr));
            assert!(u32::from(addr) >= first, "{addr} is in the reserved /24");
            assert_ne!(addr, Ipv4Addr::new(198, 19, 255, 255));
        }
        // Probing wraps from the last slot to the first.
        assert_eq!(slot_addr(0), FIRST_SLOT);
        assert_eq!(slot_addr(SLOTS - 1), Ipv4Addr::new(198, 19, 255, 254));
    }

    #[test]
    fn fake_address_probing_wraps_from_the_last_slot() {
        let dir = TempDir::new().unwrap();
        let mut map = map_in(&dir, 0);
        let name = "wrap.corp.example";
        let start = slot_index(name);
        // Occupy the name's slot through the end of the space, so its probe must wrap.
        for i in start..SLOTS {
            let addr = slot_addr(i);
            map.by_addr.insert(addr, format!("squat{i}"));
        }
        assert_eq!(map.address(name, 0), FIRST_SLOT);
    }

    #[test]
    fn fake_address_load_skips_malformed_and_out_of_range_lines() {
        let dir = TempDir::new().unwrap();
        let text = "198.18.5.5 good.corp.example 0\n\
                    garbage\n\
                    198.18.0.7 reserved.corp.example 0\n\
                    198.19.255.255 broadcast.corp.example 0\n\
                    198.18.6.6 short.corp.example\n";
        fs::write(dir.path().join("names"), text).unwrap();
        let map = map_in(&dir, 0);
        assert_eq!(map.name(Ipv4Addr::new(198, 18, 5, 5)), Some("good.corp.example"));
        assert_eq!(map.by_name.len(), 1);
    }

    #[test]
    fn fake_address_save_is_a_noop_when_unchanged_and_creates_the_directory() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nested/state/names");
        let mut map = FakeMap::load(path.clone(), 0).unwrap();
        map.save().unwrap();
        assert!(!path.exists());

        map.address("wiki.corp.example", 0);
        map.save().unwrap();
        assert!(path.exists());
        assert!(!path.with_extension("tmp").exists());
    }

    #[test]
    fn fake_address_exhaustion_evicts_the_least_recently_used() {
        let dir = TempDir::new().unwrap();
        let mut map = map_in(&dir, 0);
        for i in 0..SLOTS {
            let name = format!("full{i}.corp.example");
            let addr = slot_addr(i);
            // Slot 7 is the stalest; every other entry was used more recently.
            let last_used = if i == 7 { 1 } else { 100 };
            map.by_addr.insert(addr, name.clone());
            map.by_name.insert(name, Entry { addr, last_used });
        }

        let addr = map.address("newcomer.corp.example", 200);
        assert_eq!(addr, slot_addr(7));
        assert_eq!(map.name(addr), Some("newcomer.corp.example"));
        assert!(!map.by_name.contains_key("full7.corp.example"));
        assert_eq!(map.by_name.len(), map.by_addr.len());
        // No other name lost its address, and the newcomer keeps this one.
        assert_eq!(map.address("full8.corp.example", 200), slot_addr(8));
        assert_eq!(map.address("newcomer.corp.example", 200), addr);
    }

    #[test]
    fn fake_v4_of_maps_both_families() {
        let v4 = Ipv4Addr::new(198, 18, 0, 5);

        assert_eq!(fake_v4_of(v4.into()), Some(v4));
        assert_eq!(fake_v4_of("2001:2::c612:5".parse().unwrap()), Some(v4));
        assert_eq!(fake_v4_of("10.99.0.5".parse().unwrap()), None);
        assert_eq!(fake_v4_of("fd99::1".parse().unwrap()), None);
        // Low bits that look like a v4 fake, behind a prefix that is not the v6 range.
        assert_eq!(fake_v4_of("2001:3::c612:5".parse().unwrap()), None);
    }

    #[test]
    fn fake_v6_embeds_the_v4_fake() {
        let v4 = Ipv4Addr::new(198, 18, 1, 2);
        let v6: Ipv6Addr = "2001:2::c612:102".parse().unwrap();

        assert_eq!(fake_v6(v4), v6);
        assert_eq!(fake_v4(v6), Some(v4));
        let last = Ipv4Addr::new(198, 19, 255, 254);
        assert_eq!(fake_v4(fake_v6(last)), Some(last));
        assert!(FAKE_RANGE6.contains(&fake_v6(last)));

        // Low bits outside the v4 range, and an address outside the v6 one.
        assert_eq!(fake_v4("2001:2::1".parse().unwrap()), None);
        assert_eq!(fake_v4("2001:3::c612:102".parse().unwrap()), None);
    }

    #[test]
    fn fake_address_state_path_uses_xdg_state_home() {
        let path = state_path_from(Some("/x/state".into()), Some("/home/u".into())).unwrap();
        assert_eq!(path, PathBuf::from("/x/state/sshunnel/names"));
    }

    #[test]
    fn fake_address_state_path_defaults_under_home() {
        let path = state_path_from(None, Some("/home/u".into())).unwrap();
        assert_eq!(path, PathBuf::from("/home/u/.local/state/sshunnel/names"));
    }

    #[test]
    fn fake_address_state_path_treats_an_empty_xdg_as_unset() {
        let path = state_path_from(Some(OsString::new()), Some("/home/u".into())).unwrap();
        assert_eq!(path, PathBuf::from("/home/u/.local/state/sshunnel/names"));
    }

    #[test]
    fn fake_address_state_path_needs_xdg_or_home() {
        assert!(state_path_from(None, None).is_err());
        assert!(state_path_from(Some(OsString::new()), Some(OsString::new())).is_err());
    }
}
