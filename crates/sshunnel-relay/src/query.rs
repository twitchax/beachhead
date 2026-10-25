//! Raw DNS queries answered from the relay's own `/etc/resolv.conf`: the remote's resolver, which
//! may well be on its loopback, is the one the client wants to hear from.

use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    path::Path,
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

/// The most nameservers asked: glibc's and musl's `MAXNS`, as both ignore the rest.
const MAXNS: usize = 3;

/// Answers `request` from the nameservers in `/etc/resolv.conf`, read afresh each time since DHCP
/// rewrites it.
pub async fn serve(request: QueryRequest) {
    // Read and parse on the blocking pool: the file may sit on a slow mount, a scope's interface is
    // looked up in sysfs, and nothing here may stall the pipe.
    let servers = tokio::task::spawn_blocking(|| std::fs::read_to_string(RESOLV_CONF).map(|text| nameservers(&text)))
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e)));
    let result = answer_from(servers, request.message(), request.transport()).await;
    request.answer(result);
}

/// The answer to `message` from the nameservers reading resolv.conf found, or why there is none.
/// A malformed message is the client's error, whatever resolv.conf says, so it is refused first.
async fn answer_from(servers: std::io::Result<Vec<SocketAddr>>, message: &[u8], transport: Transport) -> Result<Bytes, QueryError> {
    question_id(message)?;
    match servers {
        Err(e) => Err(QueryError {
            reason: format!("reading {RESOLV_CONF}: {e}"),
        }),
        Ok(servers) if servers.is_empty() => Err(QueryError {
            reason: format!("{RESOLV_CONF} names no nameserver"),
        }),
        Ok(servers) => ask(&servers, message, transport).await,
    }
}

/// The first [`MAXNS`] `nameserver` lines of a resolv.conf that parse, on port 53. An IPv6 server
/// keeps its `%scope`, a number or an interface's name; as musl does, a server whose interface isn't
/// there is skipped, and so is an IPv4 server with a scope. An interface's index is read from
/// sysfs, so this may block.
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
            match address.split_once('%') {
                None => Some(SocketAddr::new(address.parse().ok()?, 53)),
                Some((ip, scope)) => Some(SocketAddr::V6(SocketAddrV6::new(ip.parse().ok()?, 53, 0, scope_id(scope)?))),
            }
        })
        .take(MAXNS)
        .collect()
}

/// A `%scope`'s index: the number it is, or the index of the interface it names, from sysfs (Linux
/// only: elsewhere a name finds nothing).
fn scope_id(scope: &str) -> Option<u32> {
    if let Ok(index) = scope.parse() {
        return Some(index);
    }
    // Linux refuses these as interface names, and each would reach outside an interface's directory.
    if scope.is_empty() || scope.contains('/') || scope == "." || scope == ".." {
        return None;
    }
    std::fs::read_to_string(Path::new("/sys/class/net").join(scope).join("ifindex")).ok()?.trim().parse().ok()
}

/// Asks each server in turn, [`NAMESERVER_TIMEOUT`] each, over `transport`, and returns the first
/// answer whose id matches the question's, as it came (a truncated UDP answer included: the asker
/// retries over TCP).
///
/// # Errors
///
/// A [`QueryError`] naming each server's failure when none answers.
pub async fn ask(servers: &[SocketAddr], message: &[u8], transport: Transport) -> Result<Bytes, QueryError> {
    let id = question_id(message)?;
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

/// The id that opens a DNS message, which its answer must repeat.
fn question_id(message: &[u8]) -> Result<&[u8], QueryError> {
    message.get(..2).ok_or_else(|| QueryError {
        reason: "the DNS message is under 2 bytes".to_owned(),
    })
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
        let conf = "# generated\n; also a comment\nsearch corp.example\noptions edns0\nnameserver 192.0.2.53\nnameserver 2001:db8::53 # documentation\nnameserver 192.0.2.54%2\nnameserver not-an-address\nnameserver\n";
        assert_eq!(nameservers(conf), vec!["192.0.2.53:53".parse::<SocketAddr>().unwrap(), "[2001:db8::53]:53".parse().unwrap()]);
    }

    #[test]
    fn nameservers_keeps_at_most_three() {
        assert_eq!(nameservers("nameserver 192.0.2.1\nnameserver 192.0.2.2\nnameserver 192.0.2.3\nnameserver 192.0.2.4\n").len(), 3);
        // A line that doesn't parse takes none of the three, as in libc.
        let first_three: Vec<SocketAddr> = (1..=3).map(|i| SocketAddr::from(([192, 0, 2, i], 53))).collect();
        assert_eq!(
            nameservers("nameserver not-an-address\nnameserver 192.0.2.1\nnameserver 192.0.2.2\nnameserver 192.0.2.3\nnameserver 192.0.2.4\n"),
            first_three
        );
    }

    #[test]
    fn nameservers_keeps_a_numeric_scope() {
        assert_eq!(nameservers("nameserver fe80::1%2"), [SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 53, 0, 2))]);
    }

    // Linux only: the interface's index comes from sysfs, which other platforms don't have.
    #[cfg(target_os = "linux")]
    #[test]
    fn nameservers_keeps_an_interface_scope() {
        let lo: u32 = std::fs::read_to_string("/sys/class/net/lo/ifindex").unwrap().trim().parse().unwrap();
        assert_eq!(nameservers("nameserver fe80::1%lo"), [SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 53, 0, lo))]);
    }

    #[test]
    fn nameservers_skips_an_unknown_interface() {
        // `lo/../lo` names lo's own sysfs file by path, but no interface: names can't hold a `/`.
        for scope in ["nosuchif0", "lo/../lo", ".", "..", ""] {
            let found = nameservers(&format!("nameserver fe80::1%{scope}"));
            assert!(found.is_empty(), "{scope:?}: {found:?}");
        }
    }

    #[tokio::test]
    async fn resolv_conf_without_nameservers_is_a_query_error() {
        let err = answer_from(Ok(vec![]), &[0x12, 0x34], Transport::Udp).await.unwrap_err();
        assert_eq!(err.reason, "/etc/resolv.conf names no nameserver");
    }

    #[tokio::test]
    async fn an_unreadable_resolv_conf_is_a_query_error() {
        let err = answer_from(Err(std::io::Error::from(ErrorKind::PermissionDenied)), &[0x12, 0x34], Transport::Udp).await.unwrap_err();
        assert!(err.reason.starts_with("reading /etc/resolv.conf"), "{err}");
    }

    #[tokio::test]
    async fn a_message_under_2_bytes_is_refused_whatever_resolv_conf_says() {
        for servers in [Err(std::io::Error::from(ErrorKind::NotFound)), Ok(vec![])] {
            let err = answer_from(servers, &[0x12], Transport::Udp).await.unwrap_err();
            assert_eq!(err.reason, "the DNS message is under 2 bytes");
        }
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
