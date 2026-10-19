//! What the machine depends on that must keep its normal route once targets go into the TUN device:
//! the remote ends of TCP sockets held by ssh's process tree (a `ProxyCommand` child included), a
//! shared-connection master found with `ssh -O check`, and the upstream DNS servers. These are
//! candidate pins; the root helper pins only those inside a target on a unicast route.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use anyhow::Context as _;
use sshunnel_mux::base::Res;
use tokio::time::timeout;

use crate::{route::system::upstream_dns, session::SshCommand};

/// How long `ssh -O check` may take; a hung ssh must not stall startup.
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// The `ESTABLISHED` state in `/proc/net/tcp`.
const ESTABLISHED: &str = "01";

/// `root` and every descendant, from the parent pids in `/proc/*/stat`. Empty when `root` is gone.
///
/// # Errors
///
/// Fails when `/proc` can't be listed.
pub fn process_tree(root: u32) -> Res<Vec<u32>> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut alive = false;
    for entry in std::fs::read_dir("/proc").context("listing /proc")?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|name| name.parse::<u32>().ok()) else {
            continue;
        };
        // A process can vanish between the listing and the read.
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        alive |= pid == root;
        if let Some(parent) = parse_ppid(&stat) {
            children.entry(parent).or_default().push(pid);
        }
    }
    if !alive {
        return Ok(Vec::new());
    }

    let mut tree = vec![root];
    let mut next = 0;
    while let Some(&pid) = tree.get(next) {
        next += 1;
        if let Some(kids) = children.get(&pid) {
            tree.extend(kids);
        }
    }
    Ok(tree)
}

/// The parent pid from a `/proc/<pid>/stat` line. The command name is parenthesized and may hold
/// spaces and parentheses, so fields are counted from the last `)`.
fn parse_ppid(stat: &str) -> Option<u32> {
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(1)?.parse().ok()
}

/// The remote addresses of the established TCP sockets `pids` hold. Processes that can't be read
/// or have exited are skipped.
///
/// # Errors
///
/// Currently infallible; the `Res` leaves room for a stricter reading of `/proc`.
pub fn tcp_peers(pids: &[u32]) -> Res<Vec<IpAddr>> {
    let mut peers = Vec::new();
    for &pid in pids {
        let inodes = socket_inodes(pid);
        if inodes.is_empty() {
            continue;
        }
        // The pid's own view, so a process in another network namespace reports its sockets.
        for (file, v6) in [("tcp", false), ("tcp6", true)] {
            let Ok(table) = std::fs::read_to_string(format!("/proc/{pid}/net/{file}")) else {
                continue;
            };
            peers.extend(parse_proc_net_tcp(&table, v6).into_iter().filter(|(inode, _)| inodes.contains(inode)).map(|(_, peer)| peer));
        }
    }
    Ok(dedupe(peers))
}

/// The inodes of the sockets in `pid`'s fd table.
fn socket_inodes(pid: u32) -> HashSet<u64> {
    let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return HashSet::new();
    };
    fds.flatten()
        .filter_map(|fd| {
            let target = std::fs::read_link(fd.path()).ok()?;
            target.to_str()?.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
        })
        .collect()
}

/// `(inode, remote address)` for each established row of a `/proc/net/tcp` or `tcp6` table. A
/// v4-mapped v6 peer is reported as the v4 address.
fn parse_proc_net_tcp(text: &str, v6: bool) -> Vec<(u64, IpAddr)> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let remote = fields.nth(2)?;
            let state = fields.next()?;
            let inode = fields.nth(5)?.parse().ok()?;
            if state != ESTABLISHED {
                return None;
            }
            let (addr, _port) = remote.split_once(':')?;
            Some((inode, parse_addr(addr, v6)?))
        })
        .collect()
}

/// An address as the kernel prints it: each 32-bit word in host byte order.
fn parse_addr(hex: &str, v6: bool) -> Option<IpAddr> {
    let word = |s: &str| u32::from_str_radix(s, 16).ok().map(u32::to_ne_bytes);
    if v6 {
        if hex.len() != 32 {
            return None;
        }
        let [a, b, c, d] = [0, 8, 16, 24].map(|at| hex.get(at..at + 8).and_then(word));
        let octets: Vec<u8> = [a?, b?, c?, d?].concat();
        let octets: [u8; 16] = octets.try_into().ok()?;
        Some(IpAddr::V6(Ipv6Addr::from(octets)).to_canonical())
    } else {
        Some(IpAddr::V4(Ipv4Addr::from(word(hex)?)))
    }
}

/// The pid of the shared-connection master for `destination`, from `ssh -O check`; `None` when
/// there is no master or anything goes wrong.
pub async fn control_master(ssh: &SshCommand, destination: &str) -> Option<u32> {
    let output = timeout(CHECK_TIMEOUT, ssh.check_command(destination).output()).await.ok()?.ok()?;
    if !output.status.success() {
        return None;
    }
    parse_master_pid(&String::from_utf8_lossy(&output.stderr))
}

/// The pid in `Master running (pid=4242)`.
fn parse_master_pid(stderr: &str) -> Option<u32> {
    let rest = &stderr[stderr.find("Master running (pid=")? + "Master running (pid=".len()..];
    let digits = rest.split(')').next()?;
    digits.trim().parse().ok()
}

/// Every address the machine depends on: the peers of ssh's process tree and of a control master's,
/// then the upstream DNS servers; and a warning for each thing that looks wrong.
///
/// # Errors
///
/// Fails when `/proc` or the resolver config can't be read.
pub async fn pins(ssh: &SshCommand, destination: &str, ssh_pid: u32) -> Res<(Vec<IpAddr>, Vec<String>)> {
    pins_with(ssh, destination, ssh_pid, upstream_dns().context("reading the upstream DNS servers")?).await
}

/// [`pins`] with the DNS servers given, so tests need no resolver config.
async fn pins_with(ssh: &SshCommand, destination: &str, ssh_pid: u32, dns: Vec<IpAddr>) -> Res<(Vec<IpAddr>, Vec<String>)> {
    let mut pids = process_tree(ssh_pid).context("finding ssh's process tree")?;
    if let Some(master) = control_master(ssh, destination).await {
        pids.extend(process_tree(master).context("finding the control master's process tree")?);
    }

    let mut addrs = tcp_peers(&pids).context("reading ssh's TCP peers")?;
    let mut warnings = Vec::new();
    if addrs.is_empty() {
        warnings.push("found no TCP peer of ssh to keep on its normal route; if the target covers its address, the session will loop".to_owned());
    }
    addrs.extend(dns);
    Ok((dedupe(addrs), warnings))
}

/// Drops repeats, keeping first-seen order.
fn dedupe(addrs: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut seen = HashSet::with_capacity(addrs.len());
    addrs.into_iter().filter(|addr| seen.insert(*addr)).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::{process::Command, time::Instant};

    use pretty_assertions::assert_eq;
    use rustix::process::{Pid, Signal, kill_process};
    use tokio::net::TcpStream;

    use super::*;
    use crate::tests::echo_server;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   100        0 22222 1 0000000000000000 100 0 0 10 0
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:1F90 B80D0120000000000000000001000000:C350 01 00000000:00000000 00:00000000 00000000  1000        0 33333 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000100007F:1F90 0000000000000000FFFF00000200A8C0:C350 01 00000000:00000000 00:00000000 00000000  1000        0 44444 1 0000000000000000 100 0 0 10 0
   2: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 55555 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn proc_net_tcp_lines_parse() {
        assert_eq!(parse_proc_net_tcp(TCP, false), vec![(11111, "127.0.0.1".parse().unwrap())]);
        assert_eq!(parse_proc_net_tcp(TCP6, true), vec![(33333, "2001:db8::1".parse().unwrap()), (44444, "192.168.0.2".parse().unwrap())]);
        assert_eq!(parse_proc_net_tcp("", false), vec![]);
    }

    #[test]
    fn master_pid_parses() {
        assert_eq!(parse_master_pid("Master running (pid=4242)\r\n"), Some(4242));
        assert_eq!(parse_master_pid("Control socket connect(/x): No such file or directory\r\n"), None);
        assert_eq!(parse_master_pid("Master running (pid=oops)"), None);
    }

    #[test]
    fn stat_parent_survives_awkward_names() {
        assert_eq!(parse_ppid("12 (a b) c) S 7 12 12 0"), Some(7));
    }

    fn kill_all(pids: &[u32]) {
        for pid in pids {
            if let Some(pid) = i32::try_from(*pid).ok().and_then(Pid::from_raw) {
                let _ = kill_process(pid, Signal::KILL);
            }
        }
    }

    #[test]
    fn process_tree_finds_a_grandchild() {
        // The inner shell has two commands, so it does not exec its way into `sleep`.
        let mut child = Command::new("sh").args(["-c", "sh -c 'sleep 30; true' & wait"]).spawn().unwrap();
        let root = child.id();

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut tree = process_tree(root).unwrap();
        while tree.len() < 3 && Instant::now() < deadline {
            std::thread::yield_now();
            tree = process_tree(root).unwrap();
        }
        kill_all(&tree);
        child.wait().unwrap();

        assert_eq!(tree.len(), 3, "sh, the inner sh and sleep: {tree:?}");
        assert_eq!(tree[0], root);
    }

    #[test]
    fn process_tree_of_a_missing_pid_is_empty() {
        assert_eq!(process_tree(u32::MAX).unwrap(), Vec::<u32>::new());
    }

    #[tokio::test]
    async fn tcp_peers_finds_this_process() {
        let server = echo_server().await.unwrap();
        let _conn = TcpStream::connect(server).await.unwrap();

        let peers = tcp_peers(&[std::process::id()]).unwrap();

        assert!(peers.contains(&server.ip()), "{peers:?}");
        assert_eq!(peers.iter().filter(|p| **p == server.ip()).count(), 1, "deduped");
    }

    #[tokio::test]
    async fn pins_include_upstream_dns_servers() {
        let server = echo_server().await.unwrap();
        let _conn = TcpStream::connect(server).await.unwrap();
        let dns: Vec<IpAddr> = vec!["192.0.2.53".parse().unwrap(), "127.0.0.1".parse().unwrap()];
        // Not ssh: any process holding a socket will do, and `true` never finds a control master.
        let ssh = SshCommand::parse("true").unwrap();

        let (addrs, warnings) = pins_with(&ssh, "corp.example", std::process::id(), dns).await.unwrap();

        assert_eq!(addrs, vec!["127.0.0.1".parse::<IpAddr>().unwrap(), "192.0.2.53".parse().unwrap()]);
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[tokio::test]
    async fn pins_warn_when_no_peer_is_found() {
        let ssh = SshCommand::parse("true").unwrap();

        let (addrs, warnings) = pins_with(&ssh, "corp.example", u32::MAX, vec!["192.0.2.53".parse().unwrap()]).await.unwrap();

        assert_eq!(addrs, vec!["192.0.2.53".parse::<IpAddr>().unwrap()]);
        assert_eq!(warnings.len(), 1);
    }
}
