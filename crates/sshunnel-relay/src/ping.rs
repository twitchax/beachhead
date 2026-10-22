//! ICMP echo over the kernel's unprivileged ping sockets (`SOCK_DGRAM` / `IPPROTO_ICMP`).
//!
//! The kernel owns the identifier and the checksum on these sockets, so the relay only builds the
//! echo header around the sequence and payload the client hands it.

use std::net::SocketAddr;

use bytes::Bytes;
use socket2::{Domain, Protocol, Socket, Type};
use sshunnel_mux::frame::Capabilities;
use tokio::net::UdpSocket;

const ECHO_REQUEST: u8 = 8;
const ECHO_REQUEST_V6: u8 = 128;
const ECHO_REPLY: u8 = 0;
const ECHO_REPLY_V6: u8 = 129;
/// Type, code, checksum, identifier and sequence.
const HEADER: usize = 8;

/// Which families this process may open `SOCK_DGRAM` / `IPPROTO_ICMP(V6)` sockets for.
#[must_use]
pub fn probe() -> Capabilities {
    Capabilities {
        ping4: socket(false).is_ok(),
        ping6: socket(true).is_ok(),
    }
}

fn socket(v6: bool) -> std::io::Result<Socket> {
    let (domain, protocol) = if v6 { (Domain::IPV6, Protocol::ICMPV6) } else { (Domain::IPV4, Protocol::ICMPV4) };
    Socket::new(domain, Type::DGRAM, Some(protocol))
}

/// A ping socket connected to `addr`, ready for the runtime.
///
/// # Errors
///
/// Fails when the kernel refuses the socket (no `ping_group_range` access) or the connect.
pub fn open(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = socket(addr.is_ipv6())?;
    socket.set_nonblocking(true)?;
    // The port is meaningless for ICMP; the kernel ignores it.
    socket.connect(&addr.into())?;
    UdpSocket::from_std(socket.into())
}

/// ICMP echo request bytes (type 8, or 128 for v6; code 0; checksum and identifier 0, which the
/// kernel fills) around `seq_payload` (a 2-byte sequence, then the payload); `None` under 2 bytes.
#[must_use]
pub fn echo_request(seq_payload: &[u8], v6: bool) -> Option<Vec<u8>> {
    let (seq, payload) = seq_payload.split_first_chunk::<2>()?;
    let mut packet = Vec::with_capacity(HEADER + payload.len());
    packet.extend_from_slice(&[if v6 { ECHO_REQUEST_V6 } else { ECHO_REQUEST }, 0, 0, 0, 0, 0]);
    packet.extend_from_slice(seq);
    packet.extend_from_slice(payload);
    Some(packet)
}

/// From a ping socket's echo reply (type 0, or 129), the sequence and payload; `None` for anything
/// else, including the errors ICMP reports about a request.
#[must_use]
pub fn echo_reply(packet: &[u8], v6: bool) -> Option<Bytes> {
    let wanted = if v6 { ECHO_REPLY_V6 } else { ECHO_REPLY };
    if packet.len() < HEADER || packet[0] != wanted {
        return None;
    }
    let mut out = Vec::with_capacity(packet.len() - HEADER + 2);
    out.extend_from_slice(&packet[HEADER - 2..HEADER]);
    out.extend_from_slice(&packet[HEADER..]);
    Some(Bytes::from(out))
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn echo_requests_carry_the_sequence_and_payload() {
        assert_eq!(echo_request(&[1, 2, b'h', b'i'], false).unwrap(), [8, 0, 0, 0, 0, 0, 0x01, 0x02, b'h', b'i']);
        assert_eq!(echo_request(&[1, 2], true).unwrap(), [128, 0, 0, 0, 0, 0, 0x01, 0x02]);
        assert_eq!(echo_request(&[1], false), None);
    }

    #[test]
    fn echo_replies_give_back_the_sequence_and_payload() {
        let reply = [0, 0, 0xAB, 0xCD, 0x11, 0x22, 0x01, 0x02, b'h', b'i'];
        assert_eq!(echo_reply(&reply, false).unwrap(), Bytes::from_static(&[1, 2, b'h', b'i']));
        let mut request = reply;
        request[0] = 8;
        assert_eq!(echo_reply(&request, false), None);
        // A v6 reply is not a v4 one, and the other way round.
        let mut v6 = reply;
        v6[0] = 129;
        assert_eq!(echo_reply(&v6, true).unwrap(), Bytes::from_static(&[1, 2, b'h', b'i']));
        assert_eq!(echo_reply(&v6, false), None);
        assert_eq!(echo_reply(&reply[..7], false), None);
    }
}
