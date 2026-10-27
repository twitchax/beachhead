//! `sshunnel route` as a user runs it: not root, through the real sudo, on a terminal. What neither
//! the namespace suite nor the root tests can show: sudo starting the helper for another uid, the
//! device's fd crossing to an unprivileged client, a Ctrl-C typed at the terminal, and the
//! `route --check` probe telling a passwordless sudo apart. The remote is this machine with an `/etc/hosts` of its own (`FakeRemote::with_hosts`). `#[ignore]`d: CI's
//! route-sudo step runs them as the runner's own user, which has passwordless sudo; anywhere else
//! they skip.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs::File,
    io::Read as _,
    os::fd::OwnedFd,
    path::Path,
    process::{Command as StdCommand, Stdio},
    time::Duration,
};

use pretty_assertions::assert_eq;
use rustix::{
    fs::{Mode, OFlags, open},
    process::geteuid,
    pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt},
    termios::{LocalModes, tcgetattr},
};
use sshunnel::{
    route::helper::Sudo,
    tests::{FakeRemote, leftovers, probe_sudo_with, relay_dir, resolved_leftovers, route_command},
};
use tempfile::TempDir;
use tokio::{
    process::{Child, Command},
    sync::mpsc,
    time::{Instant, timeout, timeout_at},
};

/// How long `route` may take to bring its routes up, or to exit.
const WITHIN: Duration = Duration::from_secs(30);

/// A user other than root with passwordless sudo, or a skip; CI runs these as one, so there a skip
/// is a failure.
fn sudo_user() -> bool {
    let passwordless = || {
        StdCommand::new("sudo")
            .args(["-n", "true"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    };
    if !geteuid().is_root() && passwordless() {
        return true;
    }
    assert!(
        std::env::var_os("CI").is_none(),
        "these tests need a user other than root with passwordless sudo on CI: run them as the runner, without sudo"
    );
    eprintln!("skipped: needs a user other than root with passwordless sudo");
    false
}

/// A pseudo-terminal for `route` to run on, as a shell's job: the test types into its master and
/// reads what `route` shows there.
struct Terminal {
    master: OwnedFd,
    /// The test's one fd on the slave end, until a job takes it.
    slave: Option<OwnedFd>,
    /// What the terminal shows, as a thread reads it off the master.
    chunks: mpsc::UnboundedReceiver<Vec<u8>>,
    shown: String,
}

impl Terminal {
    /// A fresh terminal.
    fn open() -> Self {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        // NOCTTY: the job's session takes the terminal, never the test's.
        let slave = open(ptsname(&master, Vec::new()).unwrap().as_c_str(), OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC, Mode::empty()).unwrap();

        let (seen, chunks) = mpsc::unbounded_channel();
        let mut reader = File::from(master.try_clone().unwrap());
        std::thread::spawn(move || {
            let mut chunk = [0; 4096];
            // EIO once every process on the terminal has closed it.
            while let Ok(n @ 1..) = reader.read(&mut chunk) {
                if seen.send(chunk[..n].to_vec()).is_err() {
                    return;
                }
            }
        });
        Self {
            master,
            slave: Some(slave),
            chunks,
            shown: String::new(),
        }
    }

    /// Runs `command` as the terminal's foreground job: `setsid --ctty` makes it lead a session of
    /// its own with this terminal as the controlling one, so it and everything it starts are the
    /// foreground process group, which a Ctrl-C reaches. It takes the test's fd on the slave end,
    /// so the terminal closes with the job's last process.
    fn run(&mut self, command: &Command) -> Child {
        let slave = self.slave.take().expect("the terminal already runs a job");
        let command = command.as_std();
        let mut job = Command::new("setsid");
        job.arg("--ctty").arg(command.get_program()).args(command.get_args()).kill_on_drop(true);
        if let Some(dir) = command.get_current_dir() {
            job.current_dir(dir);
        }
        for (key, value) in command.get_envs() {
            match value {
                Some(value) => job.env(key, value),
                None => job.env_remove(key),
            };
        }
        job.stdin(slave.try_clone().unwrap()).stdout(slave.try_clone().unwrap()).stderr(slave);
        job.spawn().unwrap()
    }

    /// Whether `text` shows within [`WITHIN`].
    async fn shows(&mut self, text: &str) -> bool {
        let deadline = Instant::now() + WITHIN;
        while !self.shown.contains(text) {
            match timeout_at(deadline, self.chunks.recv()).await {
                Ok(Some(chunk)) => self.shown.push_str(&String::from_utf8_lossy(&chunk)),
                Ok(None) | Err(_) => return false,
            }
        }
        true
    }

    /// Everything shown, once the terminal closes or a few seconds pass.
    async fn all_shown(&mut self) -> &str {
        let Self { chunks, shown, .. } = self;
        let rest = async {
            while let Some(chunk) = chunks.recv().await {
                shown.push_str(&String::from_utf8_lossy(&chunk));
            }
        };
        let _ = timeout(Duration::from_secs(5), rest).await;
        &self.shown
    }

    /// Whether the terminal turns Ctrl-C into SIGINT: ISIG, which raw mode clears.
    fn signals(&self) -> bool {
        tcgetattr(&self.master).unwrap().local_modes.contains(LocalModes::ISIG)
    }

    fn type_keys(&self, keys: &[u8]) {
        assert_eq!(rustix::io::write(&self.master, keys).unwrap(), keys.len());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a user other than root with passwordless sudo, and the host's systemd-resolved; CI's route-sudo step runs it"]
async fn e2e_sudo_ctrl_c_at_the_terminal_ends_the_run_cleanly() {
    if !sudo_user() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let remote = FakeRemote::new(dir.path(), "sh", &[]).unwrap().with_hosts("127.0.0.1 wiki.corp.example\n").unwrap();
    let relays = relay_dir(dir.path()).unwrap();
    let route = route_command(env!("CARGO_BIN_EXE_sshunnel"), dir.path(), remote.ssh_path(), &relays, &["*.corp.example"]);
    let mut terminal = Terminal::open();
    let mut job = terminal.run(&route);

    let up = terminal.shows("sshunnel: routing ").await;
    assert!(up, "no status line; the terminal showed:\n{}", terminal.all_shown().await);
    // Had sudo put the terminal into raw mode, the Ctrl-C below would reach the helper alone, as a
    // byte, and the run would end in an error.
    let signals = terminal.signals();
    assert!(signals, "the terminal is raw; it showed:\n{}", terminal.all_shown().await);

    terminal.type_keys(b"\x03");

    let status = timeout(WITHIN, job.wait()).await.expect("route ignored the Ctrl-C").unwrap();
    let shown = terminal.all_shown().await.to_owned();
    assert!(status.success(), "{status}; the terminal showed:\n{shown}");
    assert_eq!(leftovers().unwrap(), Vec::<String>::new(), "the terminal showed:\n{shown}");
    // The link's resolver config went with the device.
    assert_eq!(resolved_leftovers().unwrap(), Vec::<String>::new());
}

#[tokio::test]
#[ignore = "needs a user other than root with passwordless sudo; CI's route-sudo step runs it"]
async fn sudo_probe_starts_the_helper_without_a_password() {
    if !sudo_user() {
        return;
    }
    let dir = TempDir::new().unwrap();

    let sudo = probe_sudo_with(Path::new(env!("CARGO_BIN_EXE_sshunnel")), dir.path()).await.unwrap();

    assert_eq!(sudo, Sudo::NoPrompt);
    // The helper the probe hung up on, and the sudo above it, are gone by the time it returns.
    // Matched by this probe's socket dir, since the other tests here run helpers of their own.
    let left = StdCommand::new("pgrep").arg("-af").arg(format!("sshunnel helper --socket {}", dir.path().display())).output().unwrap();
    assert!(!left.status.success(), "a helper is left:\n{}", String::from_utf8_lossy(&left.stdout));
}
