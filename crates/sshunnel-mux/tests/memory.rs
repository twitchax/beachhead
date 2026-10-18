//! What queued data costs in heap, measured by a counting global allocator. A file of its own, so
//! the allocator counts only this binary's tests, and nextest runs each test in its own process.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use bytes::BytesMut;
use sshunnel_mux::{Config, Role, pump, start};
use tokio::{
    io::{AsyncWriteExt as _, duplex, split},
    time::sleep,
};

/// Live heap bytes: every allocation adds its size, every free takes it back.
static LIVE: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: forwards every call to `System` unchanged; the counter only observes sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds `alloc`'s contract, which `System.alloc` shares.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `alloc` above, so from `System`, with this layout.
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const WINDOW: u32 = 16 * 1024;
const CHUNK: usize = 4 * 1024;
/// A chatty source: a log tail, SSE, websocket pings.
const WRITE: usize = 100;

#[tokio::test(start_paused = true)]
async fn stalled_stream_heap_is_bounded_by_its_window() {
    let config = Config::new(WINDOW, CHUNK).unwrap();
    let (a, b) = duplex(64 * 1024);
    let ((ar, aw), (br, bw)) = (split(a), split(b));
    let (client, _client_incoming, client_driver) = start(ar, BytesMut::new(), aw, Role::Client, config);
    let (_relay, mut relay_incoming, relay_driver) = start(br, BytesMut::new(), bw, Role::Relay, config);
    tokio::spawn(client_driver);
    tokio::spawn(relay_driver);
    // The stalled consumer: accepted, then never pumped, so every byte stays queued in the mux.
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(request) = relay_incoming.next().await {
            held.push(request.accept());
        }
    });
    let stream = client.open("sink", 7).await.unwrap();
    let (near, mut far) = duplex(4 * 1024);
    tokio::spawn(pump(stream, near));

    // With the clock paused, the sleep returns only once every task is blocked, so each write
    // reaches the relay as a frame of its own, in a read of its own.
    let write = async |far: &mut tokio::io::DuplexStream| {
        far.write_all(&[0x5A; WRITE]).await.unwrap();
        sleep(Duration::from_secs(1)).await;
    };
    write(&mut far).await;
    let before = LIVE.load(Ordering::Relaxed);
    let writes = WINDOW as usize / WRITE - 1;
    for _ in 0..writes {
        write(&mut far).await;
    }
    let grown = LIVE.load(Ordering::Relaxed).saturating_sub(before);

    // Credit lets the relay queue at most one window of payload. Allow as much again for the
    // channel's own bookkeeping; a read buffer pinned per frame would be ~64 KiB times `writes`.
    let queued = writes * WRITE;
    assert!(grown <= 2 * WINDOW as usize, "{queued} queued payload bytes grew the heap by {grown} bytes");
}
