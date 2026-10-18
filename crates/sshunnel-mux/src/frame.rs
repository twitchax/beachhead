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
/// The longest `Open` host, matching DNS's own limit.
pub const MAX_HOST: usize = 255;
/// `OpenErr` and `Rst` reasons are cut to this many bytes (on a char boundary) when encoded.
pub const MAX_REASON: usize = 1024;
/// The first bytes of every `Hello`.
pub const MAGIC: [u8; 4] = *b"SSHN";
/// The protocol version both ends must agree on.
pub const VERSION: u16 = 1;

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
    /// The first frame in each direction, on [`StreamId::CONNECTION`].
    Hello { version: u16 },
    /// Ask the peer to dial `host:port` for a new stream.
    Open { stream: StreamId, host: String, port: u16 },
    /// The peer dialed; data may flow.
    OpenOk { stream: StreamId },
    /// The peer could not dial.
    OpenErr { stream: StreamId, reason: String },
    /// Stream bytes, at most [`MAX_PAYLOAD`] of them; the receiver's credit pays for each one.
    Data { stream: StreamId, data: Bytes },
    /// Return `credit` bytes of send credit to the peer.
    Window { stream: StreamId, credit: u32 },
    /// The sender is done writing (a TCP half-close).
    Fin { stream: StreamId },
    /// Abort the stream in both directions.
    Rst { stream: StreamId, reason: String },
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
            Self::Data { .. } => "Data",
            Self::Window { .. } => "Window",
            Self::Fin { .. } => "Fin",
            Self::Rst { .. } => "Rst",
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
            Kind::Hello => {
                fixed(6)?;
                if payload[..4] != MAGIC {
                    bail!("bad Hello magic {:?}", &payload[..4]);
                }
                Self::Hello { version: payload.get_u16_at(4) }
            }
            Kind::Open => {
                if payload.len() < 2 {
                    bail!("Open payload is {} bytes, too short for a port", payload.len());
                }
                let port = payload.get_u16_at(0);
                payload.advance(2);
                if payload.len() > MAX_HOST {
                    bail!("Open host is {} bytes, over the {MAX_HOST}-byte limit", payload.len());
                }
                let host = std::str::from_utf8(&payload).map_err(|e| anyhow!("Open host is not UTF-8: {e}"))?.to_owned();
                Self::Open { stream, host, port }
            }
            Kind::OpenOk => {
                fixed(0)?;
                Self::OpenOk { stream }
            }
            Kind::OpenErr => Self::OpenErr {
                stream,
                reason: String::from_utf8_lossy(&payload).into_owned(),
            },
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

    /// Appends this frame's encoding to `buf`.
    ///
    /// # Errors
    ///
    /// Fails when a `Data` payload or an `Open` host exceeds its limit.
    pub fn encode(&self, buf: &mut BytesMut) -> Void {
        match self {
            Self::Hello { version } => {
                put_header(buf, StreamId::CONNECTION, Kind::Hello, 6);
                buf.put_slice(&MAGIC);
                buf.put_u16(*version);
            }
            Self::Open { stream, host, port } => {
                if host.len() > MAX_HOST {
                    bail!("Open host is {} bytes, over the {MAX_HOST}-byte limit", host.len());
                }
                put_header(buf, *stream, Kind::Open, 2 + host.len());
                buf.put_u16(*port);
                buf.put_slice(host.as_bytes());
            }
            Self::OpenOk { stream } => put_header(buf, *stream, Kind::OpenOk, 0),
            Self::OpenErr { stream, reason } => put_reason(buf, *stream, Kind::OpenErr, reason),
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
            Self::Rst { stream, reason } => put_reason(buf, *stream, Kind::Rst, reason),
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

fn put_reason(buf: &mut BytesMut, stream: StreamId, kind: Kind, reason: &str) {
    let mut end = reason.len().min(MAX_REASON);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    put_header(buf, stream, kind, end);
    buf.put_slice(&reason.as_bytes()[..end]);
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
            Frame::Hello { version: VERSION },
            Frame::Open {
                stream: s,
                host: "server.lan".into(),
                port: 443,
            },
            Frame::OpenOk { stream: s },
            Frame::OpenErr {
                stream: s,
                reason: "connection refused".into(),
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
        ]
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

        let hello = encoded(&Frame::Hello { version: 1 });
        assert_eq!(&hello[..], &[0, 0, 0, 0, 0, 0, 0, 0, 6, b'S', b'S', b'H', b'N', 0, 1][..]);

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
        let mut raw = header(0, 0, 6);
        raw.extend_from_slice(b"SSH-\x00\x01");
        assert!(Frame::decode(&mut BytesMut::from(&raw[..])).unwrap_err().to_string().contains("magic"));
    }

    #[test]
    fn hello_must_ride_the_connection_id_and_streams_must_not() {
        let mut hello = header(5, 0, 6);
        hello.extend_from_slice(b"SSHN\x00\x01");
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
}
