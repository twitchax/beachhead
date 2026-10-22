//! Raw DNS queries answered from the relay's own `/etc/resolv.conf`: the remote's resolver, which
//! may well be on its loopback, is the one the client wants to hear from.

use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use bytes::Bytes;
use sshunnel_mux::{QueryError, QueryRequest, frame::Transport};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

/// How long each nameserver gets before the next is tried.
pub const NAMESERVER_TIMEOUT: Duration = Duration::from_secs(2);

const RESOLV_CONF: &str = "/etc/resolv.conf";

/// Answers `request` from the nameservers in `/etc/resolv.conf`, read afresh each time since DHCP
/// rewrites it.
pub async fn serve(request: QueryRequest) {
    // Read on the blocking pool: the file may sit on a slow mount, and nothing here may stall the pipe.
    let conf = tokio::task::spawn_blocking(|| std::fs::read_to_string(RESOLV_CONF)).await;
    let result = match conf {
        Ok(Ok(text)) => {
            let servers = nameservers(&text);
            if servers.is_empty() {
                Err(QueryError {
                    reason: format!("{RESOLV_CONF} names no nameserver"),
                })
            } else {
                ask(&servers, request.message(), request.transport()).await
            }
        }
        Ok(Err(e)) => Err(QueryError {
            reason: format!("reading {RESOLV_CONF}: {e}"),
        }),
        Err(e) => Err(QueryError {
            reason: format!("reading {RESOLV_CONF}: {e}"),
        }),
    };
    request.answer(result);
}

/// The `nameserver` lines of a resolv.conf, on port 53; unparsable ones are skipped (a `%scope`
/// suffix is dropped).
#[must_use]
pub fn nameservers(resolv_conf: &str) -> Vec<SocketAddr> {
    resolv_conf
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            if words.next()? != "nameserver" {
                return None;
            }
            let address = words.next()?;
            let ip: IpAddr = address.split_once('%').map_or(address, |(ip, _scope)| ip).parse().ok()?;
            Some(SocketAddr::new(ip, 53))
        })
        .collect()
}

/// Asks each server in turn, [`NAMESERVER_TIMEOUT`] each, over `transport`, and returns the first
/// answer whose id matches the question's, as it came (a truncated UDP answer included: the asker
/// retries over TCP).
///
/// # Errors
///
/// A [`QueryError`] naming each server's failure when none answers.
pub async fn ask(servers: &[SocketAddr], message: &[u8], transport: Transport) -> Result<Bytes, QueryError> {
    let Some(id) = message.get(..2) else {
        return Err(QueryError {
            reason: "the DNS message is under 2 bytes".to_owned(),
        });
    };
    let mut failures = Vec::new();
    for &server in servers {
        let attempt = async {
            match transport {
                Transport::Udp => ask_udp(server, message, id).await,
                Transport::Tcp => ask_tcp(server, message, id).await,
            }
        };
        match timeout(NAMESERVER_TIMEOUT, attempt).await {
            Ok(Ok(answer)) => return Ok(answer),
            Ok(Err(e)) => failures.push(format!("{server}: {e}")),
            Err(_) => failures.push(format!("{server}: no answer in {} s", NAMESERVER_TIMEOUT.as_secs())),
        }
    }
    let reason = if failures.is_empty() { "no nameserver to ask".to_owned() } else { failures.join("; ") };
    Err(QueryError { reason })
}

async fn ask_udp(server: SocketAddr, message: &[u8], id: &[u8]) -> std::io::Result<Bytes> {
    let local = if server.is_ipv4() { IpAddr::V4(Ipv4Addr::UNSPECIFIED) } else { IpAddr::V6(Ipv6Addr::UNSPECIFIED) };
    let socket = UdpSocket::bind(SocketAddr::new(local, 0)).await?;
    socket.connect(server).await?;
    socket.send(message).await?;
    let mut buf = vec![0u8; 65_535];
    loop {
        let n = socket.recv(&mut buf).await?;
        // A stray or spoofed datagram doesn't end the wait; the timeout does.
        if buf[..n].starts_with(id) {
            return Ok(Bytes::copy_from_slice(&buf[..n]));
        }
    }
}

/// One connection per attempt, with RFC 7766's two-byte length before each message.
async fn ask_tcp(server: SocketAddr, message: &[u8], id: &[u8]) -> std::io::Result<Bytes> {
    let length = u16::try_from(message.len()).map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "the message is over 65535 bytes"))?;
    let mut socket = TcpStream::connect(server).await?;
    let mut framed = Vec::with_capacity(2 + message.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(message);
    socket.write_all(&framed).await?;
    loop {
        let len = socket.read_u16().await?;
        let mut answer = vec![0u8; usize::from(len)];
        socket.read_exact(&mut answer).await?;
        if answer.starts_with(id) {
            return Ok(Bytes::from(answer));
        }
    }
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;
    use tokio::net::TcpListener;

    use super::*;

    const QUESTION: [u8; 6] = [0x12, 0x34, 0x01, 0x00, 0xAA, 0xBB];

    /// What a nameserver says to `question`: the same bytes with the response bit set.
    fn response(question: &[u8]) -> Vec<u8> {
        let mut answer = question.to_vec();
        answer[2] |= 0x80;
        answer
    }

    /// A loopback UDP nameserver; `replies` turns each question into the datagrams it sends back.
    async fn udp_stub(replies: fn(&[u8]) -> Vec<Vec<u8>>) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                let (n, from) = socket.recv_from(&mut buf).await.unwrap();
                for reply in replies(&buf[..n]) {
                    socket.send_to(&reply, from).await.unwrap();
                }
            }
        });
        addr
    }

    #[test]
    fn nameservers_come_from_nameserver_lines() {
        let conf = "# generated\n; also a comment\nsearch corp.example\noptions edns0\nnameserver 192.0.2.53\nnameserver fe80::1%eth0 # link-local\nnameserver not-an-address\nnameserver\n";
        assert_eq!(nameservers(conf), vec!["192.0.2.53:53".parse::<SocketAddr>().unwrap(), "[fe80::1]:53".parse().unwrap()]);
    }

    #[tokio::test]
    async fn ask_returns_the_first_answer_over_udp() {
        let server = udp_stub(|q| vec![response(q)]).await;
        let answer = ask(&[server], &QUESTION, Transport::Udp).await.unwrap();
        assert_eq!(answer.as_ref(), response(&QUESTION));
    }

    #[tokio::test]
    async fn ask_over_tcp_frames_messages_with_their_length() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let len = socket.read_u16().await.unwrap();
            let mut question = vec![0u8; usize::from(len)];
            socket.read_exact(&mut question).await.unwrap();
            let answer = response(&question);
            socket.write_all(&u16::try_from(answer.len()).unwrap().to_be_bytes()).await.unwrap();
            socket.write_all(&answer).await.unwrap();
        });
        let answer = ask(&[server], &QUESTION, Transport::Tcp).await.unwrap();
        assert_eq!(answer.as_ref(), response(&QUESTION));
    }

    #[tokio::test(start_paused = true)]
    async fn ask_moves_on_from_a_silent_nameserver() {
        let silent = udp_stub(|_| Vec::new()).await;
        let live = udp_stub(|q| vec![response(q)]).await;
        let answer = ask(&[silent, live], &QUESTION, Transport::Udp).await.unwrap();
        assert_eq!(answer.as_ref(), response(&QUESTION));
    }

    #[tokio::test]
    async fn ask_ignores_a_reply_with_another_id() {
        let server = udp_stub(|q| {
            let mut stray = response(q);
            stray[0] ^= 0xFF;
            vec![stray, response(q)]
        })
        .await;
        let answer = ask(&[server], &QUESTION, Transport::Udp).await.unwrap();
        assert_eq!(answer.as_ref(), response(&QUESTION));
    }

    #[tokio::test]
    async fn a_truncated_udp_answer_comes_back_as_it_is() {
        let server = udp_stub(|q| {
            let mut truncated = response(q);
            truncated[2] |= 0x02;
            vec![truncated]
        })
        .await;
        let answer = ask(&[server], &QUESTION, Transport::Udp).await.unwrap();
        assert_eq!(answer.as_ref(), [0x12, 0x34, 0x83, 0x00, 0xAA, 0xBB]);
    }

    #[tokio::test(start_paused = true)]
    async fn ask_with_no_answer_is_a_query_error() {
        let silent = udp_stub(|_| Vec::new()).await;
        let err = ask(&[silent], &QUESTION, Transport::Udp).await.unwrap_err();
        assert!(err.reason.contains("no answer"), "{err}");
        assert!(ask(&[], &QUESTION, Transport::Udp).await.is_err());
    }
}
