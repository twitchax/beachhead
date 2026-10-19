//! The TUN device's fd as the netstack's [`Packets`]. The fd goes non-blocking under tokio's
//! reactor; one task reads it and one writes it, and each read or write is one whole IP packet
//! (the device has no packet-info header).

use std::{io, os::fd::OwnedFd, sync::Arc};

use anyhow::{Context as _, ensure};
use bytes::Bytes;
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::mpsc,
    task::JoinSet,
};

use crate::{
    base::{Res, Void},
    route::{DEVICE, MTU, stack::Packets},
};

/// Packets queued each way between the device and the stack.
const QUEUE: usize = 256;

/// Starts the reader and the writer on `tun` in `tasks` and returns the stack's end. A failed read
/// or write, or a short write, ends its task with the error; the fd closes once both tasks are gone.
///
/// # Errors
///
/// Fails when the fd can't be made non-blocking or registered with the runtime.
pub(crate) fn spawn(tun: OwnedFd, tasks: &mut JoinSet<Void>) -> Res<Packets> {
    let flags = fcntl_getfl(&tun).with_context(|| format!("reading {DEVICE}'s flags"))?;
    fcntl_setfl(&tun, flags | OFlags::NONBLOCK).with_context(|| format!("making {DEVICE} non-blocking"))?;
    // SAFETY: `register` needs the fd to stay open and the same until the `AsyncFd` drops; an
    // `OwnedFd` owns its fd, never changes it, and closes it only when dropped with the `AsyncFd`.
    let registered = unsafe { AsyncFd::register(tun) };
    let device = Arc::new(registered.map_err(|e| e.into_parts().1).with_context(|| format!("watching {DEVICE}"))?);

    let (to_stack, rx) = mpsc::channel(QUEUE);
    let (tx, from_stack) = mpsc::channel(QUEUE);
    tasks.spawn(read(Arc::clone(&device), to_stack));
    tasks.spawn(write(device, from_stack));
    Ok(Packets { rx, tx })
}

/// Hands each packet the device reads to the stack, until the stack is gone.
async fn read(device: Arc<AsyncFd<OwnedFd>>, to_stack: mpsc::Sender<Bytes>) -> Void {
    let mut buf = vec![0; usize::from(MTU)];
    // A deleted device polls as an error alone, never as readable, so the read must wake on errors
    // too to find out (EBADFD).
    let readable = Interest::READABLE | Interest::ERROR;
    loop {
        let n = device
            .async_io(readable, |fd| rustix::io::read(fd, &mut buf[..]).map_err(io::Error::from))
            .await
            .with_context(|| format!("reading from {DEVICE}"))?;
        ensure!(n > 0, "{DEVICE} closed");
        // Sized to the packet: a small one shouldn't hold an MTU-sized buffer while it waits.
        if to_stack.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
            return Ok(());
        }
    }
}

/// Writes each packet the stack sends to the device, until the stack is gone.
async fn write(device: Arc<AsyncFd<OwnedFd>>, mut from_stack: mpsc::Receiver<Bytes>) -> Void {
    while let Some(packet) = from_stack.recv().await {
        let n = device
            .async_io(Interest::WRITABLE, |fd| rustix::io::write(fd, &packet).map_err(io::Error::from))
            .await
            .with_context(|| format!("writing to {DEVICE}"))?;
        // The device takes a packet whole or not at all; less would be half a packet on the wire.
        ensure!(n == packet.len(), "writing to {DEVICE}: it took {n} of a {}-byte packet", packet.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;
    use std::time::Duration;

    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair, sockopt::set_socket_send_buffer_size};
    use tokio::net::UnixDatagram;

    use super::*;

    /// A stand-in for the TUN fd that keeps packet boundaries, and the far end of it, as the kernel.
    fn device_pair() -> (OwnedFd, UnixDatagram) {
        let (tun, kernel) = socketpair(AddressFamily::UNIX, SocketType::SEQPACKET, SocketFlags::CLOEXEC, None).unwrap();
        let kernel = std::os::unix::net::UnixDatagram::from(kernel);
        kernel.set_nonblocking(true).unwrap();
        (tun, UnixDatagram::from_std(kernel).unwrap())
    }

    #[tokio::test]
    async fn packets_cross_whole_each_way() {
        let (tun, kernel) = device_pair();
        let mut tasks = JoinSet::new();
        let Packets { mut rx, tx } = spawn(tun, &mut tasks).unwrap();
        let largest = vec![7; usize::from(MTU)];

        kernel.send(b"one").await.unwrap();
        kernel.send(&largest).await.unwrap();
        assert_eq!(rx.recv().await.unwrap(), &b"one"[..]);
        assert_eq!(rx.recv().await.unwrap(), largest);

        tx.send(Bytes::from_static(b"back")).await.unwrap();
        let mut buf = [0; 16];
        let n = kernel.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"back");
    }

    #[tokio::test]
    async fn a_device_that_ends_ends_the_reader_with_an_error() {
        let (tun, kernel) = device_pair();
        let mut tasks = JoinSet::new();
        let _packets = spawn(tun, &mut tasks).unwrap();

        drop(kernel);

        let error = tasks.join_next().await.unwrap().unwrap().unwrap_err();
        assert!(format!("{error:#}").contains(DEVICE), "{error:#}");
    }

    #[tokio::test]
    async fn a_device_that_fails_ends_the_reader_with_an_error() {
        // A deleted TUN device polls as EPOLLERR alone, and reads fail (EBADFD). So does a connected
        // UDP socket whose datagram drew a port unreachable, its reads failing with ECONNREFUSED.
        let closed = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let tun = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        tun.connect(closed).unwrap();
        tun.send(b"anyone?").unwrap();
        let mut tasks = JoinSet::new();
        let _packets = spawn(tun.into(), &mut tasks).unwrap();

        let ended = tokio::time::timeout(Duration::from_secs(5), tasks.join_next()).await.expect("the failed device went unnoticed");
        let error = ended.unwrap().unwrap().unwrap_err();
        assert!(format!("{error:#}").contains(&format!("reading from {DEVICE}")), "{error:#}");
    }

    #[tokio::test]
    async fn a_short_write_ends_the_writer_with_an_error() {
        // A stream with almost no send buffer takes part of a large packet and stops: what a
        // truncated packet would look like, which a TUN device never does.
        let (tun, _kernel) = socketpair(AddressFamily::UNIX, SocketType::STREAM, SocketFlags::CLOEXEC, None).unwrap();
        set_socket_send_buffer_size(&tun, 4096).unwrap();
        let mut tasks = JoinSet::new();
        let packets = spawn(tun, &mut tasks).unwrap();

        packets.tx.send(Bytes::from(vec![7; usize::from(MTU)])).await.unwrap();

        let ended = tokio::time::timeout(Duration::from_secs(5), tasks.join_next()).await.expect("the short write went unnoticed");
        let error = ended.unwrap().unwrap().unwrap_err();
        assert!(format!("{error:#}").contains(&format!("writing to {DEVICE}")), "{error:#}");
    }

    #[tokio::test]
    async fn the_tasks_end_with_the_stack() {
        let (tun, kernel) = device_pair();
        let mut tasks = JoinSet::new();
        let packets = spawn(tun, &mut tasks).unwrap();

        drop(packets);
        // The reader learns the stack is gone at its next packet.
        kernel.send(b"late").await.unwrap();

        while let Some(done) = tasks.join_next().await {
            done.unwrap().unwrap();
        }
    }
}
