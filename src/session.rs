//! The client half of a connection: spawn the system `ssh`, drive the bootstrap script, then hand
//! the same pipe to the mux.

use std::process::Stdio;

use anyhow::{Context as _, anyhow, bail};
use bytes::BytesMut;
use sshunnel_mux::{
    Config, Mux, Role,
    base::{Res, Void},
    hello::{recv_hello, send_hello},
    start,
};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    task::JoinHandle,
};
use tracing::debug;

use crate::{
    bootstrap::{self, Line},
    relays::{Relay, Relays},
};

/// How to run ssh: a program and leading arguments, split like a shell would (`--ssh-cmd`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshCommand {
    program: String,
    args: Vec<String>,
}

impl SshCommand {
    /// Splits `command` into words with shell quoting rules.
    ///
    /// # Errors
    ///
    /// Fails on unbalanced quotes or an empty command.
    pub fn parse(command: &str) -> Res<Self> {
        let words = shlex::split(command).with_context(|| format!("unbalanced quotes in ssh command `{command}`"))?;
        let (program, args) = words.split_first().context("the ssh command is empty")?;
        Ok(Self {
            program: program.clone(),
            args: args.to_vec(),
        })
    }
}

impl SshCommand {
    /// `ssh -O check <destination>` with the user's own arguments, so it sees the same config and
    /// control path as the session. Output is piped; stdin is closed.
    pub(crate) fn check_command(&self, destination: &str) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.args).args(["-O", "check", destination]).stdin(Stdio::null()).kill_on_drop(true);
        command
    }
}

impl Default for SshCommand {
    fn default() -> Self {
        Self {
            program: "ssh".to_owned(),
            args: Vec::new(),
        }
    }
}

/// How the relay came to be running on the remote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bootstrap {
    /// A cached copy in `dir` passed its checks; nothing was transferred.
    Cached { dir: String },
    /// The relay was sent and installed in `dir`, so the next run is a cache hit.
    Pushed { dir: String },
    /// Every candidate dir was noexec: the relay was sent and runs from a memfd, uncached.
    Memfd,
}

impl std::fmt::Display for Bootstrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cached { dir } => write!(f, "cached in {dir}"),
            Self::Pushed { dir } => write!(f, "pushed to {dir}"),
            Self::Memfd => f.write_str("pushed to a memfd (every cache dir is noexec; not cached)"),
        }
    }
}

/// A running relay and the mux over its session.
pub struct Session {
    mux: Mux,
    relay: Relay,
    bootstrap: Bootstrap,
    driver: JoinHandle<Void>,
    /// Held so ssh lives exactly as long as the session (`kill_on_drop`).
    ssh: Child,
}

impl Session {
    /// Runs `ssh <destination>` with the bootstrap script, pushes the relay if the remote lacks it,
    /// and shakes hands with it.
    ///
    /// # Errors
    ///
    /// Fails when ssh can't start or exits early, the bootstrap reports an error, or the handshake
    /// fails.
    pub async fn connect(ssh: &SshCommand, destination: &str, relays: &Relays) -> Res<Self> {
        let mut child = Command::new(&ssh.program)
            .args(&ssh.args)
            // No pty and no escape character: from here on the session carries binary frames.
            .args(["-T", "-e", "none", destination, &bootstrap::remote_command(relays)])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("starting `{}`", ssh.program))?;
        let stdin = child.stdin.take().context("ssh has no stdin pipe")?;
        let mut stdout = BufReader::new(child.stdout.take().context("ssh has no stdout pipe")?);

        let (relay, bootstrap, mut stdin) = match run_bootstrap(&mut stdout, stdin, relays).await {
            Ok(done) => done,
            Err(e) if e.is::<EarlyExit>() => {
                let status = child.wait().await.context("waiting for ssh")?;
                return Err(e.context(format!("ssh exited before the relay started ({status})")));
            }
            Err(e) => return Err(e),
        };

        // The relay speaks first; until its Hello arrives, `head -c` may still be reading the pipe.
        let config = Config::default();
        let mut buf = BytesMut::new();
        let relay_window = recv_hello(&mut stdout, &mut buf).await.context("waiting for the relay's Hello")?;
        send_hello(&mut stdin, config.window()).await?;
        let (mux, _incoming, driver) = start(stdout, buf, stdin, Role::Client, config, relay_window);
        Ok(Self {
            mux,
            relay,
            bootstrap,
            driver: tokio::spawn(driver),
            ssh: child,
        })
    }

    /// The pid of the ssh process carrying the session; `None` once it has been reaped.
    #[must_use]
    pub fn ssh_pid(&self) -> Option<u32> {
        self.ssh.id()
    }

    /// The handle for opening streams through the relay.
    #[must_use]
    pub fn mux(&self) -> &Mux {
        &self.mux
    }

    /// The relay that is running.
    #[must_use]
    pub fn relay(&self) -> &Relay {
        &self.relay
    }

    /// How it started.
    #[must_use]
    pub fn bootstrap(&self) -> &Bootstrap {
        &self.bootstrap
    }

    /// Resolves when the connection ends, then stops ssh.
    ///
    /// # Errors
    ///
    /// Returns why the connection ended, unless the relay simply hung up.
    pub async fn closed(self) -> Void {
        self.driver.await.map_err(|e| anyhow!("the mux driver failed: {e}"))?
    }
}

/// Marks the error for "ssh's stdout closed before READY", so the caller can add ssh's status.
#[derive(Debug)]
struct EarlyExit;

impl std::fmt::Display for EarlyExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the remote closed the session")
    }
}

impl std::error::Error for EarlyExit {}

/// Reads status lines until `READY`, pushing the relay when asked. Returns stdin once any push has
/// finished with it.
async fn run_bootstrap(stdout: &mut BufReader<ChildStdout>, stdin: ChildStdin, relays: &Relays) -> Res<(Relay, Bootstrap, ChildStdin)> {
    let mut stdin = Some(stdin);
    let mut push: Option<JoinHandle<Res<ChildStdin>>> = None;
    let mut line = Vec::new();
    loop {
        line.clear();
        if stdout.read_until(b'\n', &mut line).await.context("reading the bootstrap's output")? == 0 {
            return Err(EarlyExit.into());
        }
        let Some(status) = bootstrap::parse_line(&line) else {
            // An rc file that echoes: sshuttle's classic failure, so it is only ever noise here.
            debug!(line = %String::from_utf8_lossy(&line).trim_end(), "remote shell output");
            continue;
        };
        match status? {
            Line::Send { sha256, len } => {
                let relay = relays
                    .by_sha256(sha256)
                    .with_context(|| format!("the remote asked for relay {sha256}, which this build doesn't have"))?;
                if relay.len() != len {
                    bail!("the remote expects {len} bytes of relay {sha256}, but it is {} bytes", relay.len());
                }
                // Another SEND means the remote couldn't store the last copy (a full disk, say)
                // and drained it on its way to the next dir, so the pipe is free for one more.
                let mut pipe = reclaim(push.take(), stdin.take()).await?;
                let bytes = relay.bytes().clone();
                // Push while still reading: if the remote fails mid-transfer, its ERR line is the
                // error worth reporting, not the broken pipe.
                push = Some(tokio::spawn(async move {
                    pipe.write_all(&bytes).await.context("pushing the relay")?;
                    pipe.flush().await.context("pushing the relay")?;
                    Ok(pipe)
                }));
            }
            Line::Ready { sha256, dir } => {
                let relay = relays
                    .by_sha256(sha256)
                    .with_context(|| format!("the remote started relay {sha256}, which this build doesn't have"))?
                    .clone();
                let bootstrap = match (dir, push.is_some()) {
                    ("memfd", _) => Bootstrap::Memfd,
                    (dir, true) => Bootstrap::Pushed { dir: dir.to_owned() },
                    (dir, false) => Bootstrap::Cached { dir: dir.to_owned() },
                };
                return Ok((relay, bootstrap, reclaim(push, stdin).await?));
            }
            Line::Err(reason) => bail!("the remote bootstrap failed: {reason}"),
        }
    }
}

/// The ssh stdin pipe, back from the push holding it when there was one.
async fn reclaim(push: Option<JoinHandle<Res<ChildStdin>>>, stdin: Option<ChildStdin>) -> Res<ChildStdin> {
    match (push, stdin) {
        (Some(push), _) => push.await.map_err(|e| anyhow!("the relay push failed: {e}"))?,
        (None, Some(stdin)) => Ok(stdin),
        (None, None) => bail!("lost the ssh stdin pipe"),
    }
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn ssh_commands_split_like_a_shell() {
        let ssh = SshCommand::parse(r#"ssh -F "/tmp/my config" -o BatchMode=yes"#).unwrap();
        assert_eq!(ssh.program, "ssh");
        assert_eq!(ssh.args, ["-F", "/tmp/my config", "-o", "BatchMode=yes"]);
        assert!(SshCommand::parse("ssh 'unbalanced").is_err());
        assert!(SshCommand::parse("   ").is_err());
    }
}
