//! The wire format: a 9-byte header (`stream: u32 BE | kind: u8 | len: u32 BE`) and a payload of at
//! most [`MAX_PAYLOAD`] bytes. Decoding is incremental over a `BytesMut`, the tokio-util `Decoder`
//! shape. Each payload is copied out into a `Bytes` of its own, so a queued `Data` frame holds
//! exactly the bytes its credit paid for.

use anyhow::{anyhow, bail};
use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};

use crate::base::{Res, Void};

/// Header length: stream (4) + kind (1) + payload length (4).
pub const HEADER_LEN: usize = 9;
/// The largest payload a decoder accepts, so a garbage length can't make it allocate.
pub const MAX_PAYLOAD: usize = 64 * 1024;
/// The longest `Query` message: a payload, less the transport byte ahead of it.
pub const MAX_QUERY: usize = MAX_PAYLOAD - 1;
/// The longest `Open` or `Resolve` host, matching DNS's own limit.
pub const MAX_HOST: usize = 255;
/// `OpenErr`, `ResolveErr` and `Rst` reasons are cut to this many bytes (on a char boundary) when encoded.
pub const MAX_REASON: usize = 1024;
/// The first bytes of every `Hello`.
pub const MAGIC: [u8; 4] = *b"SSHN";
/// The protocol version both ends must agree on.
pub const VERSION: u16 = 4;

/// Why a dial failed, as one wire byte ahead of the `OpenErr` reason. The discriminants are the wire
/// values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OpenErrKind {
    /// The host answered and nothing listens on the port.
    Refused = 0,
    /// No route to the host or network.
    Unreachable = 1,
    /// The dial timed out.
    TimedOut = 2,
    /// Anything else, including a name that doesn't resolve.
    Other = 3,
}

impl TryFrom<u8> for OpenErrKind {
    type Error = crate::base::Err;

    fn try_from(byte: u8) -> Res<Self> {
        Ok(match byte {
            0 => Self::Refused,
            1 => Self::Unreachable,
            2 => Self::TimedOut,
            3 => Self::Other,
            other => bail!("unknown OpenErr kind {other}"),
        })
    }
}

/// Why a name lookup failed, as one wire byte ahead of the `ResolveErr` reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ResolveErrKind {
    /// The resolver says the name does not exist.
    NoSuchName = 0,
    /// The lookup failed for any other reason.
    Failed = 1,
}

impl TryFrom<u8> for ResolveErrKind {
    type Error = crate::base::Err;

    fn try_from(byte: u8) -> Res<Self> {
        Ok(match byte {
            0 => Self::NoSuchName,
            1 => Self::Failed,
            other => bail!("unknown ResolveErr kind {other}"),
        })
    }
}

/// What the relay can do beyond the basics, as one byte in its `Hello`. Bits this side does not know
/// are ignored, so a newer relay may announce more without breaking an older client.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// Bit 0: the relay can ping over IPv4.
    pub ping4: bool,
    /// Bit 1: the relay can ping over IPv6.
    pub ping6: bool,
}

impl Capabilities {
    const PING4: u8 = 0b01;
    const PING6: u8 = 0b10;

    /// The wire byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        (if self.ping4 { Self::PING4 } else { 0 }) | (if self.ping6 { Self::PING6 } else { 0 })
    }

    /// Reads the wire byte, ignoring bits this side does not know.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        Self {
            ping4: byte & Self::PING4 != 0,
            ping6: byte & Self::PING6 != 0,
        }
    }
}

/// What a connected socket reported on a live flow, as the one wire byte of a `FlowErr`. The
/// discriminants are the wire values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FlowErrKind {
    /// `ECONNREFUSED`: the far host answered a datagram with port unreachable.
    PortUnreachable = 0,
    /// `EHOSTUNREACH`.
    HostUnreachable = 1,
    /// `ENETUNREACH`.
    NetUnreachable = 2,
}

impl FlowErrKind {
    /// The flow error a socket error stands for, or `None` for any other error.
    #[must_use]
    pub fn from_io(e: &std::io::Error) -> Option<Self> {
        match e.kind() {
            std::io::ErrorKind::ConnectionRefused => Some(Self::PortUnreachable),
            std::io::ErrorKind::HostUnreachable => Some(Self::HostUnreachable),
            std::io::ErrorKind::NetworkUnreachable => Some(Self::NetUnreachable),
            _ => None,
        }
    }
}

impl TryFrom<u8> for FlowErrKind {
    type Error = crate::base::Err;

    fn try_from(byte: u8) -> Res<Self> {
        Ok(match byte {
            0 => Self::PortUnreachable,
            1 => Self::HostUnreachable,
            2 => Self::NetUnreachable,
            other => bail!("unknown FlowErr kind {other}"),
        })
    }
}

/// The transport a `Query` was asked over, as one wire byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Transport {
    /// The relay asks its resolver over UDP.
    Udp = 0,
    /// The relay asks its resolver over TCP.
    Tcp = 1,
}

impl TryFrom<u8> for Transport {
    type Error = crate::base::Err;

    fn try_from(byte: u8) -> Res<Self> {
        Ok(match byte {
            0 => Self::Udp,
            1 => Self::Tcp,
            other => bail!("unknown Query transport {other}"),
        })
    }
}

/// A stream's id. The opener allocates them monotonically and never reuses one, so a late frame for
/// a finished stream can be ignored. Id 0 is the connection itself (`Hello`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub u32);

impl StreamId {
    /// The connection-level id that carries `Hello`.
    pub const CONNECTION: Self = Self(0);
}

impl std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// One frame on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// The first frame in each direction, on [`StreamId::CONNECTION`]: the protocol version, and
    /// the sender's receive window, the most it lets the peer have in flight on one stream, and
    /// what the sender can do (the relay's, in practice).
    Hello { version: u16, window: u32, capabilities: Capabilities },
    /// Ask the peer to dial `host:port` for a new stream.
    Open { stream: StreamId, host: String, port: u16 },
    /// The peer dialed; data may flow.
    OpenOk { stream: StreamId },
    /// The peer could not dial.
    OpenErr { stream: StreamId, kind: OpenErrKind, reason: String },
    /// Ask the peer to resolve `host` with its own resolver. Rides a fresh stream id, like `Open`.
    Resolve { stream: StreamId, host: String },
    /// The name resolved.
    Resolved { stream: StreamId },
    /// The name did not resolve.
    ResolveErr { stream: StreamId, kind: ResolveErrKind, reason: String },
    /// Stream bytes, at most [`MAX_PAYLOAD`] of them; the receiver's credit pays for each one.
    Data { stream: StreamId, data: Bytes },
    /// Return `credit` bytes of send credit to the peer.
    Window { stream: StreamId, credit: u32 },
    /// The sender is done writing (a TCP half-close).
    Fin { stream: StreamId },
    /// Abort the stream in both directions.
    Rst { stream: StreamId, reason: String },
    /// Ask the peer to open a UDP flow to `host:port`. Answered like `Open`.
    OpenUdp { stream: StreamId, host: String, port: u16 },
    /// Ask the peer to open an ICMP echo flow to `host`. Answered like `Open`.
    OpenEcho { stream: StreamId, host: String },
    /// One datagram on a flow, at most [`MAX_PAYLOAD`]; outside credit, and dropped when the
    /// receiving flow's queue is full.
    Datagram { stream: StreamId, data: Bytes },
    /// A socket error on a live flow; the flow stays open.
    FlowErr { stream: StreamId, kind: FlowErrKind },
    /// One raw DNS message for the peer's resolvers, asked over `transport`. Rides a fresh stream id.
    Query { stream: StreamId, transport: Transport, message: Bytes },
    /// The raw DNS message that answers a `Query`.
    Answer { stream: StreamId, message: Bytes },
    /// A `Query` that got no answer.
    QueryErr { stream: StreamId, reason: String },
}

impl Frame {
    /// The frame's kind, for messages that shouldn't print a payload.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "Hello",
            Self::Open { .. } => "Open",
            Self::OpenOk { .. } => "OpenOk",
            Self::OpenErr { .. } => "OpenErr",
            Self::Resolve { .. } => "Resolve",
            Self::Resolved { .. } => "Resolved",
            Self::ResolveErr { .. } => "ResolveErr",
            Self::Data { .. } => "Data",
            Self::Window { .. } => "Window",
            Self::Fin { .. } => "Fin",
            Self::Rst { .. } => "Rst",
            Self::OpenUdp { .. } => "OpenUdp",
            Self::OpenEcho { .. } => "OpenEcho",
            Self::Datagram { .. } => "Datagram",
            Self::FlowErr { .. } => "FlowErr",
            Self::Query { .. } => "Query",
            Self::Answer { .. } => "Answer",
            Self::QueryErr { .. } => "QueryErr",
        }
    }

    /// Decodes one frame from the front of `buf`, or returns `None` (reserving room for the rest)
    /// when the frame isn't complete yet.
    ///
    /// # Errors
    ///
    /// Fails on an oversized length, an unknown kind, or a malformed payload: the stream of frames
    /// can't be trusted after any of these.
    pub fn decode(buf: &mut BytesMut) -> Res<Option<Self>> {
        let Some(header) = buf.first_chunk::<HEADER_LEN>() else {
            return Ok(None);
        };
        let stream = StreamId(u32::from_be_bytes([header[0], header[1], header[2], header[3]]));
        let kind = header[4];
        let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
        if len > MAX_PAYLOAD {
            bail!("frame length {len} exceeds the {MAX_PAYLOAD}-byte limit");
        }
        if buf.len() < HEADER_LEN + len {
            buf.reserve(HEADER_LEN + len - buf.len());
            return Ok(None);
        }

        buf.advance(HEADER_LEN);
        // A copy, not a view: a payload frozen out of `buf` would keep the reader's whole read
        // buffer alive for as long as it sat queued, so credit would no longer bound memory.
        let payload = Bytes::copy_from_slice(&buf[..len]);
        buf.advance(len);
        Self::parse(stream, kind, payload).map(Some)
    }

    fn parse(stream: StreamId, kind: u8, mut payload: Bytes) -> Res<Self> {
        let kind = Kind::try_from(kind)?;
        if (kind == Kind::Hello) != (stream == StreamId::CONNECTION) {
            bail!("{kind:?} frame on stream {stream}: only Hello rides the connection id");
        }
        let fixed = |want: usize| -> Void {
            if payload.len() == want {
                Ok(())
            } else {
                Err(anyhow!("{kind:?} payload is {} bytes, expected {want}", payload.len()))
            }
        };

        Ok(match kind {
            Kind::OpenUdp | Kind::OpenEcho | Kind::Datagram | Kind::FlowErr | Kind::Query | Kind::Answer | Kind::QueryErr => {
                return Self::parse_v4(stream, kind, payload);
            }
            Kind::Hello => {
                if payload.len() < 6 || payload[..4] != MAGIC {
                    bail!("bad Hello magic {:?}", &payload[..payload.len().min(4)]);
                }
                let version = payload.get_u16_at(4);
                if version != VERSION {
                    // Another version may lay out the rest differently: report the version alone,
                    // and let the handshake refuse it by name rather than trip on the layout.
                    return Ok(Self::Hello {
                        version,
                        window: 0,
                        capabilities: Capabilities::default(),
                    });
                }
                fixed(11)?;
                Self::Hello {
                    version,
                    window: u32::from_be_bytes([payload[6], payload[7], payload[8], payload[9]]),
                    capabilities: Capabilities::from_byte(payload[10]),
                }
            }
            Kind::Open => {
                let (host, port) = split_host_port(kind, &mut payload)?;
                Self::Open { stream, host, port }
            }
            Kind::OpenOk => {
                fixed(0)?;
                Self::OpenOk { stream }
            }
            Kind::OpenErr => {
                let (kind, reason) = split_kind(kind, &payload)?;
                Self::OpenErr {
                    stream,
                    kind: OpenErrKind::try_from(kind)?,
                    reason,
                }
            }
            Kind::Resolve => {
                let host = host(Kind::Resolve, &payload)?;
                Self::Resolve { stream, host }
            }
            Kind::Resolved => {
                fixed(0)?;
                Self::Resolved { stream }
            }
            Kind::ResolveErr => {
                let (kind, reason) = split_kind(kind, &payload)?;
                Self::ResolveErr {
                    stream,
                    kind: ResolveErrKind::try_from(kind)?,
                    reason,
                }
            }
            Kind::Data => Self::Data { stream, data: payload },
            Kind::Window => {
                fixed(4)?;
                Self::Window {
                    stream,
                    credit: u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]),
                }
            }
            Kind::Fin => {
                fixed(0)?;
                Self::Fin { stream }
            }
            Kind::Rst => Self::Rst {
                stream,
                reason: String::from_utf8_lossy(&payload).into_owned(),
            },
        })
    }

    /// The kinds protocol v4 added, apart from [`Self::parse`] to keep each readable.
    fn parse_v4(stream: StreamId, kind: Kind, mut payload: Bytes) -> Res<Self> {
        Ok(match kind {
            Kind::OpenUdp => {
                let (host, port) = split_host_port(kind, &mut payload)?;
                Self::OpenUdp { stream, host, port }
            }
            Kind::OpenEcho => {
                let host = host(Kind::OpenEcho, &payload)?;
                Self::OpenEcho { stream, host }
            }
            Kind::Datagram => Self::Datagram { stream, data: payload },
            Kind::FlowErr => {
                if payload.len() != 1 {
                    bail!("FlowErr payload is {} bytes, expected 1", payload.len());
                }
                Self::FlowErr {
                    stream,
                    kind: FlowErrKind::try_from(payload[0])?,
                }
            }
            Kind::Query => {
                let Some(&transport) = payload.first() else {
                    bail!("Query payload is empty, expected a transport byte");
                };
                payload.advance(1);
                Self::Query {
                    stream,
                    transport: Transport::try_from(transport)?,
                    message: payload,
                }
            }
            Kind::Answer => Self::Answer { stream, message: payload },
            Kind::QueryErr => Self::QueryErr {
                stream,
                reason: String::from_utf8_lossy(&payload).into_owned(),
            },
            other => bail!("{other:?} is not a v4 kind"),
        })
    }

    /// Appends this frame's encoding to `buf`.
    ///
    /// # Errors
    ///
    /// Fails when a `Data`, `Datagram`, `Answer` or `Query` payload or an `Open` host exceeds its limit.
    pub fn encode(&self, buf: &mut BytesMut) -> Void {
        match self {
            Self::Hello { version, window, capabilities } => {
                put_header(buf, StreamId::CONNECTION, Kind::Hello, 11);
                buf.put_slice(&MAGIC);
                buf.put_u16(*version);
                buf.put_u32(*window);
                buf.put_u8(capabilities.to_byte());
            }
            Self::Open { stream, host, port } => {
                check_host(Kind::Open, host.len())?;
                put_header(buf, *stream, Kind::Open, 2 + host.len());
                buf.put_u16(*port);
                buf.put_slice(host.as_bytes());
            }
            Self::OpenOk { stream } => put_header(buf, *stream, Kind::OpenOk, 0),
            Self::OpenErr { stream, kind, reason } => put_reason(buf, *stream, Kind::OpenErr, Some(*kind as u8), reason),
            Self::Resolve { stream, host } => {
                check_host(Kind::Resolve, host.len())?;
                put_header(buf, *stream, Kind::Resolve, host.len());
                buf.put_slice(host.as_bytes());
            }
            Self::Resolved { stream } => put_header(buf, *stream, Kind::Resolved, 0),
            Self::ResolveErr { stream, kind, reason } => put_reason(buf, *stream, Kind::ResolveErr, Some(*kind as u8), reason),
            Self::Data { stream, data } => {
                if data.len() > MAX_PAYLOAD {
                    bail!("Data payload is {} bytes, over the {MAX_PAYLOAD}-byte limit", data.len());
                }
                put_header(buf, *stream, Kind::Data, data.len());
                buf.put_slice(data);
            }
            Self::Window { stream, credit } => {
                put_header(buf, *stream, Kind::Window, 4);
                buf.put_u32(*credit);
            }
            Self::Fin { stream } => put_header(buf, *stream, Kind::Fin, 0),
            Self::Rst { stream, reason } => put_reason(buf, *stream, Kind::Rst, None, reason),
            Self::OpenUdp { stream, host, port } => {
                check_host(Kind::OpenUdp, host.len())?;
                put_header(buf, *stream, Kind::OpenUdp, 2 + host.len());
                buf.put_u16(*port);
                buf.put_slice(host.as_bytes());
            }
            Self::OpenEcho { stream, host } => {
                check_host(Kind::OpenEcho, host.len())?;
                put_header(buf, *stream, Kind::OpenEcho, host.len());
                buf.put_slice(host.as_bytes());
            }
            Self::Datagram { stream, data } => {
                if data.len() > MAX_PAYLOAD {
                    bail!("Datagram payload is {} bytes, over the {MAX_PAYLOAD}-byte limit", data.len());
                }
                put_header(buf, *stream, Kind::Datagram, data.len());
                buf.put_slice(data);
            }
            Self::FlowErr { stream, kind } => {
                put_header(buf, *stream, Kind::FlowErr, 1);
                buf.put_u8(*kind as u8);
            }
            Self::Query { stream, transport, message } => {
                if message.len() > MAX_QUERY {
                    bail!("Query message is {} bytes, over the {MAX_QUERY}-byte limit", message.len());
                }
                put_header(buf, *stream, Kind::Query, 1 + message.len());
                buf.put_u8(*transport as u8);
                buf.put_slice(message);
            }
            Self::Answer { stream, message } => {
                if message.len() > MAX_PAYLOAD {
                    bail!("Answer message is {} bytes, over the {MAX_PAYLOAD}-byte limit", message.len());
                }
                put_header(buf, *stream, Kind::Answer, message.len());
                buf.put_slice(message);
            }
            Self::QueryErr { stream, reason } => put_reason(buf, *stream, Kind::QueryErr, None, reason),
        }
        Ok(())
    }
}

/// The kind byte. The discriminants are the wire values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Kind {
    Hello = 0,
    Open = 1,
    OpenOk = 2,
    OpenErr = 3,
    Data = 4,
    Window = 5,
    Fin = 6,
    Rst = 7,
    Resolve = 8,
    Resolved = 9,
    ResolveErr = 10,
    OpenUdp = 11,
    OpenEcho = 12,
    Datagram = 13,
    FlowErr = 14,
    Query = 15,
    Answer = 16,
    QueryErr = 17,
}

impl TryFrom<u8> for Kind {
    type Error = crate::base::Err;

    fn try_from(byte: u8) -> Res<Self> {
        Ok(match byte {
            0 => Self::Hello,
            1 => Self::Open,
            2 => Self::OpenOk,
            3 => Self::OpenErr,
            4 => Self::Data,
            5 => Self::Window,
            6 => Self::Fin,
            7 => Self::Rst,
            8 => Self::Resolve,
            9 => Self::Resolved,
            10 => Self::ResolveErr,
            11 => Self::OpenUdp,
            12 => Self::OpenEcho,
            13 => Self::Datagram,
            14 => Self::FlowErr,
            15 => Self::Query,
            16 => Self::Answer,
            17 => Self::QueryErr,
            other => bail!("unknown frame kind {other}"),
        })
    }
}

/// Callers check `len` against its limit first, so the cast can't truncate.
fn put_header(buf: &mut BytesMut, stream: StreamId, kind: Kind, len: usize) {
    buf.reserve(HEADER_LEN + len);
    buf.put_u32(stream.0);
    buf.put_u8(kind as u8);
    #[allow(clippy::cast_possible_truncation, reason = "every caller bounds len by MAX_PAYLOAD")]
    buf.put_u32(len as u32);
}

/// A reason frame: an optional kind byte, then the reason cut to [`MAX_REASON`].
fn put_reason(buf: &mut BytesMut, stream: StreamId, kind: Kind, detail: Option<u8>, reason: &str) {
    let mut end = reason.len().min(MAX_REASON);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    put_header(buf, stream, kind, end + usize::from(detail.is_some()));
    if let Some(detail) = detail {
        buf.put_u8(detail);
    }
    buf.put_slice(&reason.as_bytes()[..end]);
}

/// Splits a kind-prefixed reason payload into the kind byte and the reason.
fn split_kind(frame: Kind, payload: &[u8]) -> Res<(u8, String)> {
    let Some((&kind, reason)) = payload.split_first() else {
        bail!("{frame:?} payload is empty, expected a kind byte");
    };
    Ok((kind, String::from_utf8_lossy(reason).into_owned()))
}

/// Refuses a host over [`MAX_HOST`] bytes, naming the `kind` of frame that carried it, formatted only on that error.
fn check_host(kind: Kind, len: usize) -> Void {
    if len > MAX_HOST {
        bail!("{kind:?} host is {len} bytes, over the {MAX_HOST}-byte limit");
    }
    Ok(())
}

/// Reads a frame's host from `bytes`: at most [`MAX_HOST`] bytes of UTF-8, else an error naming
/// the `kind` of frame.
fn host(kind: Kind, bytes: &[u8]) -> Res<String> {
    check_host(kind, bytes.len())?;
    Ok(std::str::from_utf8(bytes).map_err(|e| anyhow!("{kind:?} host is not UTF-8: {e}"))?.to_owned())
}

/// Splits an `Open`-shaped payload (`port(2) host`) into its host and port, checking the host.
fn split_host_port(frame: Kind, payload: &mut Bytes) -> Res<(String, u16)> {
    if payload.len() < 2 {
        bail!("{frame:?} payload is {} bytes, too short for a port", payload.len());
    }
    let port = payload.get_u16_at(0);
    payload.advance(2);
    let host = host(frame, payload)?;
    Ok((host, port))
}

/// Big-endian reads at an offset, for payloads whose length was already checked.
trait GetAt {
    fn get_u16_at(&self, at: usize) -> u16;
}

impl GetAt for Bytes {
    fn get_u16_at(&self, at: usize) -> u16 {
        u16::from_be_bytes([self[at], self[at + 1]])
    }
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;

    use super::*;

    fn encoded(frame: &Frame) -> BytesMut {
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        buf
    }

    fn header(stream: u32, kind: u8, len: u32) -> Vec<u8> {
        let mut h = stream.to_be_bytes().to_vec();
        h.push(kind);
        h.extend_from_slice(&len.to_be_bytes());
        h
    }

    fn every_kind() -> Vec<Frame> {
        let s = StreamId(7);
        vec![
            Frame::Hello {
                version: VERSION,
                window: 1 << 20,
                capabilities: Capabilities { ping4: true, ping6: false },
            },
            Frame::Open {
                stream: s,
                host: "server.lan".into(),
                port: 443,
            },
            Frame::OpenOk { stream: s },
            Frame::OpenErr {
                stream: s,
                kind: OpenErrKind::Refused,
                reason: "connection refused".into(),
            },
            Frame::Resolve { stream: s, host: "server.lan".into() },
            Frame::Resolved { stream: s },
            Frame::ResolveErr {
                stream: s,
                kind: ResolveErrKind::NoSuchName,
                reason: "no such name".into(),
            },
            Frame::Data {
                stream: s,
                data: Bytes::from_static(b"hello, world"),
            },
            Frame::Window { stream: s, credit: 131_072 },
            Frame::Fin { stream: s },
            Frame::Rst {
                stream: s,
                reason: "reset by peer".into(),
            },
            Frame::OpenUdp {
                stream: s,
                host: "dns.corp.example".into(),
                port: 53,
            },
            Frame::OpenEcho { stream: s, host: "192.0.2.1".into() },
            Frame::Datagram {
                stream: s,
                data: Bytes::from_static(b"ping"),
            },
            Frame::FlowErr {
                stream: s,
                kind: FlowErrKind::PortUnreachable,
            },
            Frame::Query {
                stream: s,
                transport: Transport::Tcp,
                message: Bytes::from_static(b"\x12\x34"),
            },
            Frame::Answer {
                stream: s,
                message: Bytes::from_static(b"\x12\x34\x81\x80"),
            },
            Frame::QueryErr { stream: s, reason: "timed out".into() },
        ]
    }

    #[test]
    fn v3_frames_round_trip() {
        let s = StreamId(9);
        let mut frames = vec![
            Frame::Resolve {
                stream: s,
                host: "wiki.corp.example".into(),
            },
            Frame::Resolved { stream: s },
        ];
        for kind in [OpenErrKind::Refused, OpenErrKind::Unreachable, OpenErrKind::TimedOut, OpenErrKind::Other] {
            frames.push(Frame::OpenErr {
                stream: s,
                kind,
                reason: "no route".into(),
            });
        }
        for kind in [ResolveErrKind::NoSuchName, ResolveErrKind::Failed] {
            frames.push(Frame::ResolveErr {
                stream: s,
                kind,
                reason: "lookup failed".into(),
            });
        }
        for frame in frames {
            let mut buf = encoded(&frame);
            assert_eq!(Frame::decode(&mut buf).unwrap(), Some(frame));
            assert!(buf.is_empty());
        }
    }

    #[test]
    fn v3_wire_layout_is_pinned() {
        let err = encoded(&Frame::OpenErr {
            stream: StreamId(1),
            kind: OpenErrKind::TimedOut,
            reason: "x".into(),
        });
        assert_eq!(&err[..], &[0, 0, 0, 1, 3, 0, 0, 0, 2, 2, b'x'][..]);
        let resolve = encoded(&Frame::Resolve { stream: StreamId(1), host: "h".into() });
        assert_eq!(&resolve[..], &[0, 0, 0, 1, 8, 0, 0, 0, 1, b'h'][..]);
        assert_eq!(&encoded(&Frame::Resolved { stream: StreamId(1) })[..], &[0, 0, 0, 1, 9, 0, 0, 0, 0][..]);
        let rerr = encoded(&Frame::ResolveErr {
            stream: StreamId(1),
            kind: ResolveErrKind::Failed,
            reason: String::new(),
        });
        assert_eq!(&rerr[..], &[0, 0, 0, 1, 10, 0, 0, 0, 1, 1][..]);
    }

    #[test]
    fn an_unknown_open_err_kind_is_rejected() {
        let raw = [header(1, 3, 2), vec![9, b'x']].concat();
        assert!(Frame::decode(&mut BytesMut::from(&raw[..])).is_err());
        let raw = [header(1, 10, 2), vec![9, b'x']].concat();
        assert!(Frame::decode(&mut BytesMut::from(&raw[..])).is_err());
        // A kind byte is required.
        assert!(Frame::decode(&mut BytesMut::from(&header(1, 3, 0)[..])).is_err());
    }

    #[test]
    fn resolve_hosts_over_max_host_are_rejected() {
        let long = Frame::Resolve {
            stream: StreamId(1),
            host: "a".repeat(MAX_HOST + 1),
        };
        assert!(long.encode(&mut BytesMut::new()).is_err());
        let on_wire = [header(1, 8, 256), vec![b'a'; 256]].concat();
        assert!(Frame::decode(&mut BytesMut::from(&on_wire[..])).is_err());
        let resolved_with_payload = [header(1, 9, 1), vec![0]].concat();
        assert!(Frame::decode(&mut BytesMut::from(&resolved_with_payload[..])).is_err());
    }

    #[test]
    fn every_kind_round_trips() {
        for frame in every_kind() {
            let mut buf = encoded(&frame);
            assert_eq!(Frame::decode(&mut buf).unwrap(), Some(frame));
            assert!(buf.is_empty(), "decode consumes exactly one frame");
        }
    }

    #[test]
    fn wire_layout_is_pinned() {
        let window = encoded(&Frame::Window { stream: StreamId(7), credit: 0x0102_0304 });
        assert_eq!(&window[..], &[0, 0, 0, 7, 5, 0, 0, 0, 4, 1, 2, 3, 4][..]);

        let hello = encoded(&Frame::Hello {
            version: 1,
            window: 0x0010_0000,
            capabilities: Capabilities::default(),
        });
        assert_eq!(&hello[..], &[0, 0, 0, 0, 0, 0, 0, 0, 11, b'S', b'S', b'H', b'N', 0, 1, 0, 0x10, 0, 0, 0][..]);

        let open = encoded(&Frame::Open {
            stream: StreamId(1),
            host: "h".into(),
            port: 80,
        });
        assert_eq!(&open[..], &[0, 0, 0, 1, 1, 0, 0, 0, 3, 0, 80, b'h'][..]);
    }

    #[test]
    fn partial_frames_wait_for_more_bytes() {
        let full = encoded(&Frame::Data {
            stream: StreamId(3),
            data: Bytes::from_static(b"abcdef"),
        });
        for cut in 0..full.len() {
            let mut buf = BytesMut::from(&full[..cut]);
            assert_eq!(Frame::decode(&mut buf).unwrap(), None, "cut at {cut}");
            assert_eq!(buf.len(), cut, "a partial frame is left in place");
        }
    }

    #[test]
    fn back_to_back_frames_decode_in_order() {
        let mut buf = BytesMut::new();
        for frame in every_kind() {
            frame.encode(&mut buf).unwrap();
        }
        for frame in every_kind() {
            assert_eq!(Frame::decode(&mut buf).unwrap(), Some(frame));
        }
        assert_eq!(Frame::decode(&mut buf).unwrap(), None);
    }

    #[test]
    fn oversized_length_is_rejected_before_allocating() {
        let mut buf = BytesMut::from(&header(1, 4, u32::MAX)[..]);
        let err = Frame::decode(&mut buf).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err:#}");
        assert!(buf.capacity() < MAX_PAYLOAD, "no allocation for a garbage length");
    }

    #[test]
    fn a_max_size_payload_is_accepted() {
        let data = Bytes::from(vec![0xAB; MAX_PAYLOAD]);
        let mut buf = encoded(&Frame::Data { stream: StreamId(1), data: data.clone() });
        assert_eq!(Frame::decode(&mut buf).unwrap(), Some(Frame::Data { stream: StreamId(1), data }));
    }

    #[test]
    fn unknown_kind_is_rejected() {
        let mut buf = BytesMut::from(&header(1, 200, 0)[..]);
        assert!(Frame::decode(&mut buf).unwrap_err().to_string().contains("kind"));
    }

    #[test]
    fn hello_with_bad_magic_is_rejected() {
        let mut raw = header(0, 0, 11);
        raw.extend_from_slice(b"SSH-\x00\x04\x00\x10\x00\x00\x00");
        assert!(Frame::decode(&mut BytesMut::from(&raw[..])).unwrap_err().to_string().contains("magic"));
    }

    #[test]
    fn hello_must_ride_the_connection_id_and_streams_must_not() {
        let mut hello = header(5, 0, 11);
        hello.extend_from_slice(b"SSHN\x00\x04\x00\x10\x00\x00\x00");
        assert!(Frame::decode(&mut BytesMut::from(&hello[..])).is_err());

        let fin_on_zero = header(0, 6, 0);
        assert!(Frame::decode(&mut BytesMut::from(&fin_on_zero[..])).is_err());
    }

    #[test]
    fn malformed_fixed_size_payloads_are_rejected() {
        let window_short = [header(1, 5, 2), vec![0, 1]].concat();
        assert!(Frame::decode(&mut BytesMut::from(&window_short[..])).is_err());

        let fin_with_payload = [header(1, 6, 1), vec![9]].concat();
        assert!(Frame::decode(&mut BytesMut::from(&fin_with_payload[..])).is_err());

        let open_without_port = [header(1, 1, 1), vec![0]].concat();
        assert!(Frame::decode(&mut BytesMut::from(&open_without_port[..])).is_err());
    }

    #[test]
    fn open_hosts_must_be_short_utf8() {
        let long = Frame::Open {
            stream: StreamId(1),
            host: "a".repeat(MAX_HOST + 1),
            port: 1,
        };
        assert!(long.encode(&mut BytesMut::new()).is_err());

        let bad_utf8 = [header(1, 1, 3), vec![0, 80, 0xFF]].concat();
        assert!(Frame::decode(&mut BytesMut::from(&bad_utf8[..])).is_err());

        let long_on_wire = [header(1, 1, 258), vec![0, 80], vec![b'a'; 256]].concat();
        assert!(Frame::decode(&mut BytesMut::from(&long_on_wire[..])).is_err());
    }

    #[test]
    fn oversized_data_is_refused_by_the_encoder() {
        let frame = Frame::Data {
            stream: StreamId(1),
            data: Bytes::from(vec![0; MAX_PAYLOAD + 1]),
        };
        assert!(frame.encode(&mut BytesMut::new()).is_err());
    }

    #[test]
    fn long_reasons_are_cut_on_a_char_boundary() {
        // 'é' is two bytes, so MAX_REASON / 2 + 1 of them straddle the limit.
        let reason = "é".repeat(MAX_REASON / 2 + 1);
        let mut buf = encoded(&Frame::Rst { stream: StreamId(1), reason });
        let Some(Frame::Rst { reason, .. }) = Frame::decode(&mut buf).unwrap() else {
            panic!("expected Rst")
        };
        assert!(reason.len() <= MAX_REASON);
        assert!(reason.chars().all(|c| c == 'é'));
    }

    #[test]
    fn v4_frames_round_trip() {
        let s = StreamId(9);
        let mut frames = vec![
            Frame::Hello {
                version: VERSION,
                window: 1024,
                capabilities: Capabilities { ping4: true, ping6: true },
            },
            Frame::OpenUdp {
                stream: s,
                host: "fd99::1".into(),
                port: 5353,
            },
            Frame::OpenEcho {
                stream: s,
                host: "wiki.corp.example".into(),
            },
            Frame::Datagram { stream: s, data: Bytes::new() },
            Frame::Answer { stream: s, message: Bytes::new() },
            Frame::QueryErr { stream: s, reason: String::new() },
        ];
        for kind in [FlowErrKind::PortUnreachable, FlowErrKind::HostUnreachable, FlowErrKind::NetUnreachable] {
            frames.push(Frame::FlowErr { stream: s, kind });
        }
        for transport in [Transport::Udp, Transport::Tcp] {
            frames.push(Frame::Query {
                stream: s,
                transport,
                message: Bytes::from_static(b"q"),
            });
        }
        for frame in frames {
            let mut buf = encoded(&frame);
            assert_eq!(Frame::decode(&mut buf).unwrap(), Some(frame));
            assert!(buf.is_empty());
        }
    }

    #[test]
    fn v4_wire_layout_is_pinned() {
        let s = StreamId(1);
        let datagram = encoded(&Frame::Datagram {
            stream: s,
            data: Bytes::from_static(b"x"),
        });
        assert_eq!(&datagram[..], &[0, 0, 0, 1, 13, 0, 0, 0, 1, b'x'][..]);
        let flow_err = encoded(&Frame::FlowErr {
            stream: s,
            kind: FlowErrKind::NetUnreachable,
        });
        assert_eq!(&flow_err[..], &[0, 0, 0, 1, 14, 0, 0, 0, 1, 2][..]);
        let query = encoded(&Frame::Query {
            stream: s,
            transport: Transport::Tcp,
            message: Bytes::from_static(b"q"),
        });
        assert_eq!(&query[..], &[0, 0, 0, 1, 15, 0, 0, 0, 2, 1, b'q'][..]);
        let open_udp = encoded(&Frame::OpenUdp { stream: s, host: "h".into(), port: 53 });
        assert_eq!(&open_udp[..], &[0, 0, 0, 1, 11, 0, 0, 0, 3, 0, 53, b'h'][..]);
        let open_echo = encoded(&Frame::OpenEcho { stream: s, host: "h".into() });
        assert_eq!(&open_echo[..], &[0, 0, 0, 1, 12, 0, 0, 0, 1, b'h'][..]);
        let answer = encoded(&Frame::Answer {
            stream: s,
            message: Bytes::from_static(b"a"),
        });
        assert_eq!(&answer[..], &[0, 0, 0, 1, 16, 0, 0, 0, 1, b'a'][..]);
        let query_err = encoded(&Frame::QueryErr { stream: s, reason: "x".into() });
        assert_eq!(&query_err[..], &[0, 0, 0, 1, 17, 0, 0, 0, 1, b'x'][..]);
        let hello = encoded(&Frame::Hello {
            version: VERSION,
            window: 1,
            capabilities: Capabilities { ping4: false, ping6: true },
        });
        assert_eq!(&hello[..], &[0, 0, 0, 0, 0, 0, 0, 0, 11, b'S', b'S', b'H', b'N', 0, 4, 0, 0, 0, 1, 0b10][..]);
    }

    #[test]
    fn a_query_message_fills_a_frame() {
        let fits = Frame::Query {
            stream: StreamId(1),
            transport: Transport::Udp,
            message: Bytes::from(vec![7; MAX_QUERY]),
        };
        let mut buf = encoded(&fits);
        assert_eq!(Frame::decode(&mut buf).unwrap(), Some(fits));

        let too_long = Frame::Query {
            stream: StreamId(1),
            transport: Transport::Udp,
            message: Bytes::from(vec![7; MAX_QUERY + 1]),
        };
        assert!(too_long.encode(&mut BytesMut::new()).is_err());
        // A decoded Query needs at least its transport byte.
        assert!(Frame::decode(&mut BytesMut::from(&header(1, 15, 0)[..])).is_err());
    }

    #[test]
    fn unknown_flow_err_kinds_and_transports_are_rejected() {
        let flow_err = [header(1, 14, 1), vec![9]].concat();
        assert!(Frame::decode(&mut BytesMut::from(&flow_err[..])).is_err());
        let query = [header(1, 15, 2), vec![9, b'q']].concat();
        assert!(Frame::decode(&mut BytesMut::from(&query[..])).is_err());
    }

    #[test]
    fn capabilities_ignore_unknown_bits() {
        assert_eq!(Capabilities::from_byte(0xFF), Capabilities { ping4: true, ping6: true });
        assert_eq!(Capabilities::from_byte(0b100), Capabilities::default());
        assert_eq!(Capabilities { ping4: true, ping6: false }.to_byte(), 0b01);
    }

    #[test]
    fn flow_err_kinds_come_from_socket_errors() {
        use std::io::{Error, ErrorKind};
        assert_eq!(FlowErrKind::from_io(&Error::from(ErrorKind::ConnectionRefused)), Some(FlowErrKind::PortUnreachable));
        assert_eq!(FlowErrKind::from_io(&Error::from(ErrorKind::HostUnreachable)), Some(FlowErrKind::HostUnreachable));
        assert_eq!(FlowErrKind::from_io(&Error::from(ErrorKind::NetworkUnreachable)), Some(FlowErrKind::NetUnreachable));
        assert_eq!(FlowErrKind::from_io(&Error::from(ErrorKind::PermissionDenied)), None);
    }

    #[test]
    fn a_v4_hello_of_the_wrong_length_is_refused() {
        for len in [10, 12] {
            let mut bytes = header(0, 0, len);
            bytes.extend_from_slice(&MAGIC);
            bytes.extend_from_slice(&VERSION.to_be_bytes());
            bytes.resize(HEADER_LEN + len as usize, 0);
            assert!(Frame::decode(&mut BytesMut::from(&bytes[..])).is_err(), "a {len}-byte Hello decoded");
        }
    }

    #[test]
    fn udp_and_echo_hosts_must_be_short_utf8() {
        let long = Frame::OpenUdp {
            stream: StreamId(1),
            host: "a".repeat(MAX_HOST + 1),
            port: 1,
        };
        assert!(long.encode(&mut BytesMut::new()).is_err());
        let long = Frame::OpenEcho {
            stream: StreamId(1),
            host: "a".repeat(MAX_HOST + 1),
        };
        assert!(long.encode(&mut BytesMut::new()).is_err());
        let bad_utf8 = [header(1, 11, 3), vec![0, 80, 0xFF]].concat();
        assert!(Frame::decode(&mut BytesMut::from(&bad_utf8[..])).is_err());
        let bad_utf8 = [header(1, 12, 1), vec![0xFF]].concat();
        assert!(Frame::decode(&mut BytesMut::from(&bad_utf8[..])).is_err());
    }
}
