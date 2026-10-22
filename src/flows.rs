//! The table of datagram flows `forward`'s UDP and `route`'s UDP and echo share.
//!
//! Plain data with no locks and no awaits, so the netstack's thread can use it without blocking.
//! Time comes in as an argument, which is what lets the tests drive it on tokio's paused clock.
//! Entries leave through return values (`insert`'s eviction, `expire`) instead of being dropped,
//! because a flow's value closes its relay socket when it goes and the caller decides how.

use std::{
    collections::{BTreeMap, HashMap},
    hash::Hash,
    time::Duration,
};

use tokio::time::Instant;

/// The most flows one session holds; the next insert evicts the least recently used.
pub const MAX_FLOWS: usize = 4096;
/// How long a flow lives without traffic until it has carried more than one reply.
pub const IDLE: Duration = Duration::from_secs(30);
/// How long a flow lives without traffic once it has carried more than one reply.
pub const IDLE_REPLIED: Duration = Duration::from_secs(120);

struct Entry<V> {
    value: V,
    replies: u32,
    /// The ordinal of the last touch; names this entry in both indexes.
    seq: u64,
    deadline: Instant,
}

impl<V> Entry<V> {
    fn timeout(&self) -> Duration {
        if self.replies > 1 { IDLE_REPLIED } else { IDLE }
    }
}

/// Flows by key, after conntrack: idle out at [`IDLE`] until a flow has carried more than one
/// reply, then at [`IDLE_REPLIED`]; at [`MAX_FLOWS`], inserting evicts the least recently used.
///
/// Two ordered indexes keep every per-datagram operation O(log n): by deadline for expiry and by
/// last use for eviction. A touch's sequence number breaks ties, since many flows share one
/// `Instant` under paused time.
pub struct FlowTable<K, V> {
    entries: HashMap<K, Entry<V>>,
    by_deadline: BTreeMap<(Instant, u64), K>,
    by_use: BTreeMap<u64, K>,
    next_seq: u64,
}

impl<K: Clone + Eq + Hash, V> Default for FlowTable<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Clone + Eq + Hash, V> FlowTable<K, V> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            by_deadline: BTreeMap::new(),
            by_use: BTreeMap::new(),
            next_seq: 0,
        }
    }

    /// Adds a flow. Returns the entry it displaced: the least recently used one when the table is
    /// full, or the old entry when `key` was already present.
    pub fn insert(&mut self, key: K, value: V, now: Instant) -> Option<(K, V)> {
        let replaced = self.remove_entry(&key).map(|old| (key.clone(), old));
        let evicted = if replaced.is_none() && self.entries.len() >= MAX_FLOWS { self.evict_lru() } else { None };

        let seq = self.take_seq();
        let entry = Entry {
            value,
            replies: 0,
            seq,
            deadline: now + IDLE,
        };
        self.by_deadline.insert((entry.deadline, seq), key.clone());
        self.by_use.insert(seq, key.clone());
        self.entries.insert(key, entry);

        replaced.or(evicted)
    }

    /// The flow's value without counting as traffic.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries.get_mut(key).map(|entry| &mut entry.value)
    }

    /// App to remote traffic: pushes the flow's deadline out.
    pub fn sent(&mut self, key: &K, now: Instant) -> Option<&mut V> {
        self.touch(key, now, 0)
    }

    /// Remote to app traffic: pushes the deadline out and counts a reply.
    pub fn replied(&mut self, key: &K, now: Instant) -> Option<&mut V> {
        self.touch(key, now, 1)
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.remove_entry(key)
    }

    /// Removes and returns every flow whose deadline is at or before `now`.
    pub fn expire(&mut self, now: Instant) -> Vec<(K, V)> {
        let mut gone = Vec::new();
        while let Some(entry) = self.by_deadline.first_entry() {
            if entry.key().0 > now {
                break;
            }
            let key = entry.get().clone();
            if let Some(value) = self.remove_entry(&key) {
                gone.push((key, value));
            }
        }
        gone
    }

    /// The earliest instant a flow expires, for the owner's timer.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        self.by_deadline.first_key_value().map(|((deadline, _), _)| *deadline)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn take_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }

    fn touch(&mut self, key: &K, now: Instant, replies: u32) -> Option<&mut V> {
        let seq = self.take_seq();
        let entry = self.entries.get_mut(key)?;

        self.by_deadline.remove(&(entry.deadline, entry.seq));
        self.by_use.remove(&entry.seq);

        entry.replies = entry.replies.saturating_add(replies);
        entry.seq = seq;
        entry.deadline = now + entry.timeout();
        self.by_deadline.insert((entry.deadline, seq), key.clone());
        self.by_use.insert(seq, key.clone());

        Some(&mut entry.value)
    }

    fn remove_entry(&mut self, key: &K) -> Option<V> {
        let entry = self.entries.remove(key)?;
        self.by_deadline.remove(&(entry.deadline, entry.seq));
        self.by_use.remove(&entry.seq);
        Some(entry.value)
    }

    fn evict_lru(&mut self) -> Option<(K, V)> {
        let key = self.by_use.first_key_value().map(|(_, key)| key.clone())?;
        let value = self.remove_entry(&key)?;
        Some((key, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: f64) -> Duration {
        Duration::from_secs_f64(n)
    }

    #[tokio::test(start_paused = true)]
    async fn flow_table_idles_out_at_30s_without_replies() {
        let mut table = FlowTable::new();
        let t = Instant::now();
        table.insert("a", 1, t);
        assert!(table.sent(&"a", t + secs(10.0)).is_some());

        assert_eq!(table.expire(t + secs(39.9)).len(), 0);
        assert_eq!(table.expire(t + secs(40.0)), vec![("a", 1)]);
        assert!(table.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn flow_table_one_reply_still_idles_out_at_30s() {
        let mut table = FlowTable::new();
        let t = Instant::now();
        table.insert("a", 1, t);
        table.replied(&"a", t + secs(1.0));

        assert_eq!(table.expire(t + secs(30.9)).len(), 0);
        assert_eq!(table.expire(t + secs(31.0)).len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn flow_table_idles_out_at_120s_after_two_replies() {
        let mut table = FlowTable::new();
        let t = Instant::now();
        table.insert("a", 1, t);
        table.replied(&"a", t + secs(1.0));
        table.replied(&"a", t + secs(2.0));

        assert_eq!(table.expire(t + secs(121.9)).len(), 0);
        assert_eq!(table.expire(t + secs(122.0)).len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn flow_table_the_4097th_flow_evicts_the_least_recently_used() {
        let mut table = FlowTable::new();
        let t = Instant::now();
        for key in 0..MAX_FLOWS {
            // One instant for every key: the order must come from the touches, not the clock.
            assert!(table.insert(key, key, t).is_none());
        }
        assert!(table.sent(&0, t).is_some());

        assert_eq!(table.insert(MAX_FLOWS, MAX_FLOWS, t), Some((1, 1)));
        assert_eq!(table.len(), MAX_FLOWS);
        assert!(table.get_mut(&0).is_some());
        assert!(table.get_mut(&1).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn flow_table_deadline_is_the_earliest_expiry() {
        let mut table = FlowTable::new();
        let t = Instant::now();
        assert_eq!(table.deadline(), None);
        table.insert("a", 1, t);
        table.insert("b", 2, t + secs(5.0));
        assert_eq!(table.deadline(), Some(t + IDLE));

        table.sent(&"a", t + secs(20.0));
        assert_eq!(table.deadline(), Some(t + secs(5.0) + IDLE));
    }

    #[tokio::test(start_paused = true)]
    async fn flow_table_remove_forgets_a_flow() {
        let mut table = FlowTable::new();
        let t = Instant::now();
        table.insert("a", 1, t);

        assert_eq!(table.remove(&"a"), Some(1));
        assert_eq!(table.remove(&"a"), None);
        assert_eq!(table.deadline(), None);
        assert_eq!(table.expire(t + secs(1000.0)).len(), 0);
        assert!(table.sent(&"a", t).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn flow_table_inserting_a_present_key_replaces_it() {
        let mut table = FlowTable::new();
        let t = Instant::now();
        table.insert("a", 1, t);
        table.replied(&"a", t);
        table.replied(&"a", t);

        assert_eq!(table.insert("a", 2, t + secs(1.0)), Some(("a", 1)));
        assert_eq!(table.len(), 1);
        assert_eq!(table.get_mut(&"a"), Some(&mut 2));
        // The replacement starts over: no replies yet, so it idles out at 30 s.
        assert_eq!(table.deadline(), Some(t + secs(1.0) + IDLE));
    }

    #[tokio::test(start_paused = true)]
    async fn flow_table_replacing_at_the_cap_evicts_nothing() {
        let mut table = FlowTable::new();
        let t = Instant::now();
        for key in 0..MAX_FLOWS {
            table.insert(key, key, t);
        }

        assert_eq!(table.insert(7, 70, t), Some((7, 7)));
        assert_eq!(table.len(), MAX_FLOWS);
    }
}
