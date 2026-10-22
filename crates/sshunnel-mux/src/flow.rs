//! Datagram flows: a UDP or ICMP echo exchange with one remote target, carried in `Datagram`
//! frames outside credit. Each end keeps a small bounded queue per flow each way and drops a
//! datagram that finds its queue full, so a flood costs only its own flow and the reader never
//! waits.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use bytes::Bytes;
use tokio::sync::Notify;

use crate::{
    frame::{FlowErrKind, Frame, MAX_PAYLOAD, StreamId},
    mux::Shared,
};

/// Datagrams a flow's queue holds, each way.
pub const FLOW_QUEUE: usize = 32;
/// Bytes a flow's queue holds, each way. An empty queue takes one datagram of any size, so a
/// datagram as large as a frame allows always fits on its own.
pub const FLOW_QUEUE_BYTES: usize = 64 * 1024;

/// What a flow delivers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlowEvent {
    /// One datagram from the peer.
    Datagram(Bytes),
    /// The peer's socket reported an error; the flow stays open.
    Error(FlowErrKind),
}

/// What a flow carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowKind {
    /// UDP datagrams to a host and port.
    Udp,
    /// ICMP echoes to a host.
    Echo,
}

/// One flow's datagrams in one direction, bounded by [`FLOW_QUEUE`] and [`FLOW_QUEUE_BYTES`].
#[derive(Default)]
struct Queue {
    datagrams: VecDeque<Bytes>,
    bytes: usize,
}

impl Queue {
    /// Queues `datagram`, or drops it and returns `false` when the queue is full.
    fn push(&mut self, datagram: Bytes) -> bool {
        let over_bytes = !self.datagrams.is_empty() && self.bytes + datagram.len() > FLOW_QUEUE_BYTES;
        if self.datagrams.len() >= FLOW_QUEUE || over_bytes {
            return false;
        }
        self.bytes += datagram.len();
        self.datagrams.push_back(datagram);
        true
    }

    fn pop(&mut self) -> Option<Bytes> {
        let datagram = self.datagrams.pop_front()?;
        self.bytes -= datagram.len();
        Some(datagram)
    }

    fn is_empty(&self) -> bool {
        self.datagrams.is_empty()
    }
}

/// A flow's receiving side: what the reader hands over, waiting for the flow's owner.
#[derive(Default)]
pub(crate) struct Inbox {
    state: Mutex<InboxState>,
    /// Wakes the owner. It holds a permit for a push made while the owner wasn't waiting.
    ready: Notify,
}

#[derive(Default)]
struct InboxState {
    queue: Queue,
    /// A flow error waits here rather than in the queue, so a flood can't crowd it out.
    error: Option<FlowErrKind>,
    closed: bool,
}

impl Inbox {
    fn state(&self) -> MutexGuard<'_, InboxState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hands over a datagram without waiting; `false` when it was dropped instead (the queue is
    /// full or the flow is over).
    pub(crate) fn push(&self, datagram: Bytes) -> bool {
        let pushed = {
            let mut state = self.state();
            !state.closed && state.queue.push(datagram)
        };
        if pushed {
            self.ready.notify_one();
        }
        pushed
    }

    /// Records the peer's flow error, to be delivered ahead of any queued datagram.
    pub(crate) fn report(&self, kind: FlowErrKind) {
        {
            let mut state = self.state();
            if state.closed {
                return;
            }
            state.error = Some(kind);
        }
        self.ready.notify_one();
    }

    /// Ends the flow: what's queued is dropped, and [`Self::recv`] returns `None` from here on.
    pub(crate) fn close(&self) {
        *self.state() = InboxState { closed: true, ..InboxState::default() };
        self.ready.notify_one();
    }

    async fn recv(&self) -> Option<FlowEvent> {
        loop {
            {
                let mut state = self.state();
                if let Some(kind) = state.error.take() {
                    return Some(FlowEvent::Error(kind));
                }
                if let Some(datagram) = state.queue.pop() {
                    return Some(FlowEvent::Datagram(datagram));
                }
                if state.closed {
                    return None;
                }
            }
            self.ready.notified().await;
        }
    }
}

/// Every flow's sending side, for the writer: a queue per flow, and a ring of the flows with
/// datagrams waiting, which the writer serves one datagram per turn.
#[derive(Default)]
pub(crate) struct Outbox {
    state: Mutex<OutboxState>,
    /// Wakes the writer. It holds a permit for a push made while the writer wasn't waiting.
    ready: Notify,
}

#[derive(Default)]
struct OutboxState {
    queues: HashMap<StreamId, Queue>,
    /// Exactly the flows whose queues aren't empty, each once, in the order the writer serves them.
    ring: VecDeque<StreamId>,
}

impl Outbox {
    fn state(&self) -> MutexGuard<'_, OutboxState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Gives flow `id` a send queue.
    pub(crate) fn open(&self, id: StreamId) {
        self.state().queues.insert(id, Queue::default());
    }

    /// Drops flow `id`'s send queue and whatever waits in it.
    pub(crate) fn close(&self, id: StreamId) {
        let mut state = self.state();
        if state.queues.remove(&id).is_some_and(|queue| !queue.is_empty()) {
            state.ring.retain(|waiting| *waiting != id);
        }
    }

    /// Drops every flow's send queue.
    pub(crate) fn clear(&self) {
        *self.state() = OutboxState::default();
    }

    /// Whether flow `id` is still live here.
    pub(crate) fn contains(&self, id: StreamId) -> bool {
        self.state().queues.contains_key(&id)
    }

    /// Queues a datagram on flow `id` without waiting; `false` when it was dropped instead (the
    /// queue is full or the flow is over).
    pub(crate) fn push(&self, id: StreamId, datagram: Bytes) -> bool {
        {
            let mut guard = self.state();
            let state = &mut *guard;
            let Some(queue) = state.queues.get_mut(&id) else { return false };
            let was_empty = queue.is_empty();
            if !queue.push(datagram) {
                return false;
            }
            if was_empty {
                state.ring.push_back(id);
            }
        }
        self.ready.notify_one();
        true
    }

    /// The next datagram, from the flow at the front of the ring, which goes to the back while it
    /// has more.
    pub(crate) fn pop(&self) -> Option<Frame> {
        let mut guard = self.state();
        let state = &mut *guard;
        while let Some(id) = state.ring.pop_front() {
            // `close` keeps the ring to live flows with datagrams; skipping guards the writer anyway.
            let Some(queue) = state.queues.get_mut(&id) else { continue };
            let Some(data) = queue.pop() else { continue };
            if !queue.is_empty() {
                state.ring.push_back(id);
            }
            return Some(Frame::Datagram { stream: id, data });
        }
        None
    }

    /// Whether no flow has a datagram waiting.
    pub(crate) fn is_empty(&self) -> bool {
        self.state().ring.is_empty()
    }

    /// Returns once a datagram may be waiting.
    pub(crate) async fn ready(&self) {
        self.ready.notified().await;
    }
}

/// A datagram flow's receiving half; [`Flow::sender`] hands out its sending half. Dropping it ends
/// the flow for the peer (a `Rst`), unless the peer already did.
pub struct Flow {
    id: StreamId,
    inbox: Arc<Inbox>,
    shared: Arc<Shared>,
}

impl Flow {
    pub(crate) fn new(id: StreamId, inbox: Arc<Inbox>, shared: Arc<Shared>) -> Self {
        Self { id, inbox, shared }
    }

    /// This flow's id on the wire.
    #[must_use]
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// A sending half. Any number may exist; none of them keeps the flow open.
    #[must_use]
    pub fn sender(&self) -> FlowSender {
        FlowSender {
            id: self.id,
            shared: Arc::clone(&self.shared),
        }
    }

    /// The next datagram or flow error from the peer, or `None` once the flow is reset or the
    /// connection is gone.
    pub async fn recv(&mut self) -> Option<FlowEvent> {
        self.inbox.recv().await
    }
}

impl std::fmt::Debug for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Flow").field("id", &self.id).finish_non_exhaustive()
    }
}

impl Drop for Flow {
    fn drop(&mut self) {
        if self.shared.forget_flow(self.id) {
            self.shared.control(Frame::Rst {
                stream: self.id,
                reason: "flow dropped".to_owned(),
            });
        }
    }
}

/// A flow's sending half.
#[derive(Clone)]
pub struct FlowSender {
    id: StreamId,
    shared: Arc<Shared>,
}

impl FlowSender {
    /// Queues a datagram for the peer without waiting. Returns `false` when it was dropped instead:
    /// the flow's queue is full, the datagram is over [`MAX_PAYLOAD`], or the flow is over.
    pub fn try_send(&self, datagram: Bytes) -> bool {
        datagram.len() <= MAX_PAYLOAD && self.shared.outbox.push(self.id, datagram)
    }

    /// Tells the peer this end's socket reported `kind`. It rides the control path, so no queue
    /// can drop it; a flow that's over sends nothing.
    pub fn report(&self, kind: FlowErrKind) {
        if self.shared.outbox.contains(self.id) {
            self.shared.control(Frame::FlowErr { stream: self.id, kind });
        }
    }
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;

    use super::*;

    fn bytes(len: usize) -> Bytes {
        Bytes::from(vec![0; len])
    }

    #[test]
    fn a_queue_holds_flow_queue_datagrams() {
        let mut queue = Queue::default();
        for _ in 0..FLOW_QUEUE {
            assert!(queue.push(bytes(1)));
        }
        assert!(!queue.push(bytes(1)));
        queue.pop().unwrap();
        assert!(queue.push(bytes(1)), "a pop makes room");
    }

    #[test]
    fn a_queue_holds_flow_queue_bytes() {
        let mut queue = Queue::default();
        assert!(queue.push(bytes(FLOW_QUEUE_BYTES / 2)));
        assert!(queue.push(bytes(FLOW_QUEUE_BYTES / 2)));
        assert!(!queue.push(bytes(1)), "the byte budget is spent");
        queue.pop().unwrap();
        assert!(queue.push(bytes(FLOW_QUEUE_BYTES / 2)));
    }

    #[test]
    fn an_empty_queue_takes_one_datagram_of_any_size() {
        let mut queue = Queue::default();
        assert!(queue.push(bytes(MAX_PAYLOAD)));
        assert!(!queue.push(bytes(1)));
    }

    #[test]
    fn the_outbox_serves_its_flows_round_robin() {
        let outbox = Outbox::default();
        let (a, b) = (StreamId(1), StreamId(3));
        outbox.open(a);
        outbox.open(b);
        for _ in 0..3 {
            assert!(outbox.push(a, bytes(1)));
        }
        assert!(outbox.push(b, bytes(1)));
        let order: Vec<StreamId> = std::iter::from_fn(|| outbox.pop())
            .map(|frame| match frame {
                Frame::Datagram { stream, .. } => stream,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(order, [a, b, a, a]);
        assert!(outbox.is_empty());
    }

    #[test]
    fn a_closed_flow_leaves_the_ring() {
        let outbox = Outbox::default();
        let (a, b) = (StreamId(1), StreamId(3));
        outbox.open(a);
        outbox.open(b);
        assert!(outbox.push(a, bytes(1)));
        outbox.close(a);
        assert!(outbox.is_empty(), "nothing waits once the only waiting flow is gone");
        assert!(!outbox.push(a, bytes(1)), "a closed flow takes no datagrams");
        assert!(outbox.push(b, bytes(1)));
        assert!(matches!(outbox.pop(), Some(Frame::Datagram { stream, .. }) if stream == b));
    }
}
