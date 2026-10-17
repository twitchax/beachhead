//! The bootstrap through a fake `ssh` that runs the remote side here (see `FakeRemote`): push,
//! cache, noexec fallthrough, the memfd fallback and several login shells, each proven by carrying
//! TCP through the relay it started. Named `e2e_*` because they spawn processes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{path::Path, time::Duration};

use bytes::Bytes;
use pretty_assertions::assert_eq;
use sshunnel::{
    arch::Arch,
    relays::{Relay, Relays, Source},
    session::{Bootstrap, Session},
    tests::{FakeRemote, echo_server, host_arch, noexec_relay_dir, pattern, relay_dir},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, duplex, split},
    time::timeout,
};

/// Echoes `len` bytes through a stream the session's relay dials.
async fn assert_carries_tcp(session: &Session, len: usize) {
    let echo = echo_server().await.unwrap();
    let stream = session.mux().open(&echo.ip().to_string(), echo.port()).await.unwrap();
    let (near, far) = duplex(64 * 1024);
    tokio::spawn(sshunnel_mux::pump(stream, near));
    let data = pattern(len as u64, len);
    let (mut r, mut w) = split(far);
    let sent = data.clone();
    tokio::spawn(async move {
        w.write_all(&sent).await.unwrap();
        w.shutdown().await.unwrap();
    });
    let mut reply = Vec::new();
    timeout(Duration::from_secs(30), r.read_to_end(&mut reply)).await.expect("the echo finishes").unwrap();
    assert!(reply == data, "echo differs: {} of {} bytes back", reply.len(), data.len());
}

async fn connect(remote: &FakeRemote, relays: &Relays) -> Session {
    timeout(Duration::from_secs(30), Session::connect(&remote.ssh_command().unwrap(), "fake-host", relays))
        .await
        .expect("the bootstrap finishes")
        .unwrap()
}

fn dir_of(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Files left in `dir` other than the installed relay: a staged copy that wasn't cleaned up.
fn strays(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    entries.map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).filter(|name| name.starts_with('.')).collect()
}

#[tokio::test]
async fn e2e_first_run_pushes_second_run_hits_cache() {
    let root = TempDir::new().unwrap();
    let remote = FakeRemote::new(root.path(), "sh", &[]).unwrap();
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();
    let cache = remote.home().join(".cache/sshunnel");

    let first = connect(&remote, &relays).await;
    assert_eq!(first.bootstrap(), &Bootstrap::Pushed { dir: dir_of(&cache) });
    assert_carries_tcp(&first, 300_000).await;
    let installed = cache.join(format!("relay-{}", first.relay().sha256()));
    assert_eq!(std::fs::read(&installed).unwrap().len(), first.relay().len());
    assert_eq!(strays(&cache), Vec::<String>::new());
    drop(first);

    let second = connect(&remote, &relays).await;
    assert_eq!(second.bootstrap(), &Bootstrap::Cached { dir: dir_of(&cache) });
    assert_carries_tcp(&second, 300_000).await;
}

#[tokio::test]
async fn e2e_the_client_disables_the_pty_and_escape_character() {
    let root = TempDir::new().unwrap();
    let remote = FakeRemote::new(root.path(), "sh", &[]).unwrap();
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();
    let _session = connect(&remote, &relays).await;
    let args = remote.last_ssh_args().unwrap();
    assert_eq!(&args[..4], ["-T", "-e", "none", "fake-host"]);
    assert!(args[4].starts_with("sh -c '"), "{}", args[4]);
}

#[tokio::test]
async fn e2e_a_cached_relay_with_the_wrong_bytes_is_replaced() {
    let root = TempDir::new().unwrap();
    let remote = FakeRemote::new(root.path(), "sh", &[]).unwrap();
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();
    let relay = relays.get(host_arch().unwrap()).unwrap();
    let cache = remote.home().join(".cache/sshunnel");
    std::fs::create_dir_all(&cache).unwrap();
    // Same name and size, different bytes: only the sha256 check can tell.
    let planted = cache.join(format!("relay-{}", relay.sha256()));
    let mut fake = std::fs::read(sshunnel::tests::relay_binary().unwrap()).unwrap();
    fake[0] ^= 0xFF;
    std::fs::write(&planted, &fake).unwrap();
    std::os::unix::fs::PermissionsExt::set_mode(&mut std::fs::metadata(&planted).unwrap().permissions(), 0o755);

    let session = connect(&remote, &relays).await;
    assert_eq!(session.bootstrap(), &Bootstrap::Pushed { dir: dir_of(&cache) });
    assert_carries_tcp(&session, 10_000).await;
}

#[tokio::test]
async fn e2e_noexec_cache_dir_falls_through_to_the_next_candidate() {
    let root = TempDir::new().unwrap();
    let run = root.path().join("run");
    std::fs::create_dir_all(&run).unwrap();
    let remote = FakeRemote::new(root.path(), "sh", &[("XDG_RUNTIME_DIR", &dir_of(&run))]).unwrap();
    let relays = Relays::from_dir(&noexec_relay_dir(root.path(), "*/.cache/sshunnel/*").unwrap()).unwrap();

    let first = connect(&remote, &relays).await;
    assert_eq!(first.bootstrap(), &Bootstrap::Pushed { dir: dir_of(&run.join("sshunnel")) });
    assert_carries_tcp(&first, 100_000).await;
    assert_eq!(strays(&remote.home().join(".cache/sshunnel")), Vec::<String>::new(), "the staged copy is cleaned up");
    drop(first);

    let second = connect(&remote, &relays).await;
    assert_eq!(second.bootstrap(), &Bootstrap::Cached { dir: dir_of(&run.join("sshunnel")) });
}

#[tokio::test]
async fn e2e_noexec_unwritable_cache_dir_falls_through_to_the_next_candidate() {
    let root = TempDir::new().unwrap();
    let run = root.path().join("run");
    std::fs::create_dir_all(&run).unwrap();
    // A file where the cache dir's parent should be: mkdir fails, so the dir is unusable.
    let blocked = root.path().join("not-a-dir");
    std::fs::write(&blocked, b"").unwrap();
    let remote = FakeRemote::new(root.path(), "sh", &[("XDG_CACHE_HOME", &dir_of(&blocked)), ("XDG_RUNTIME_DIR", &dir_of(&run))]).unwrap();
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();

    let session = connect(&remote, &relays).await;
    assert_eq!(session.bootstrap(), &Bootstrap::Pushed { dir: dir_of(&run.join("sshunnel")) });
    assert_carries_tcp(&session, 100_000).await;
}

#[tokio::test]
async fn e2e_noexec_everywhere_falls_back_to_memfd() {
    if !installed("python3") {
        return skip("python3");
    }
    let root = TempDir::new().unwrap();
    let remote = FakeRemote::new(root.path(), "sh", &[]).unwrap();
    // Every candidate (the cache, TMPDIR and /dev/shm) ends in a sshunnel* dir; a memfd runs as
    // /dev/fd/N, which doesn't match. /dev/shm/sshunnel-<uid> is the one dir outside the TempDir
    // this touches, and only its staged copy, which the bootstrap removes.
    let relays = Relays::from_dir(&noexec_relay_dir(root.path(), "*/sshunnel*/relay-*|*/sshunnel*/.relay-*").unwrap()).unwrap();

    let session = connect(&remote, &relays).await;
    assert_eq!(session.bootstrap(), &Bootstrap::Memfd);
    assert_carries_tcp(&session, 100_000).await;
    for dir in [remote.home().join(".cache/sshunnel"), root.path().join("tmp").join(format!("sshunnel-{}", uid()))] {
        assert!(!dir.join(format!("relay-{}", session.relay().sha256())).exists(), "a memfd run caches nothing in {}", dir.display());
        assert_eq!(strays(&dir), Vec::<String>::new(), "staged copies are cleaned up in {}", dir.display());
    }
}

#[tokio::test]
async fn e2e_rc_file_noise_on_stdout_is_skipped() {
    let root = TempDir::new().unwrap();
    let noisy = root.path().join("noisy-rc");
    // bash reads $BASH_ENV for non-interactive shells: the closest stand-in for a chatty .bashrc.
    std::fs::write(&noisy, "echo 'Welcome to fake-host!'\necho '@@beach not quite a status line'\nprintf 'no newline at all'\n").unwrap();
    let remote = FakeRemote::new(root.path(), "bash", &[("BASH_ENV", &dir_of(&noisy))]).unwrap();
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();

    let session = connect(&remote, &relays).await;
    assert!(matches!(session.bootstrap(), Bootstrap::Pushed { .. }));
    assert_carries_tcp(&session, 10_000).await;
}

#[tokio::test]
async fn e2e_a_build_without_this_arch_reports_the_remote_error() {
    let root = TempDir::new().unwrap();
    let remote = FakeRemote::new(root.path(), "sh", &[]).unwrap();
    let other = Arch::ALL.into_iter().find(|a| *a != host_arch().unwrap()).unwrap();
    let relays = Relays::new(vec![Relay::new(other, Bytes::from_static(b"not for this host"))], Source::Embedded).unwrap();

    let err = Session::connect(&remote.ssh_command().unwrap(), "fake-host", &relays).await.err().expect("no relay for this arch");
    assert!(format!("{err:#}").contains(&format!("no {} relay", host_arch().unwrap())), "{err:#}");
}

#[tokio::test]
async fn e2e_ssh_failing_to_connect_is_reported_with_its_status() {
    let relays = Relays::new(vec![Relay::new(host_arch().unwrap(), Bytes::from_static(b"x"))], Source::Embedded).unwrap();
    let ssh = sshunnel::session::SshCommand::parse("sh -c 'exit 255'").unwrap();
    let err = Session::connect(&ssh, "fake-host", &relays).await.err().expect("ssh fails");
    let err = format!("{err:#}");
    assert!(err.contains("ssh exited before the relay started") && err.contains("255"), "{err}");
}

/// Pushes and carries TCP with `login_shell` running the remote command.
async fn bootstrap_through(login_shell: &str) {
    let program = login_shell.split_whitespace().next().unwrap();
    if !installed(program) {
        return skip(program);
    }
    let root = TempDir::new().unwrap();
    let remote = FakeRemote::new(root.path(), login_shell, &[]).unwrap();
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();
    let session = connect(&remote, &relays).await;
    assert!(matches!(session.bootstrap(), Bootstrap::Pushed { .. }), "{login_shell}: {}", session.bootstrap());
    assert_carries_tcp(&session, 50_000).await;
}

#[tokio::test]
async fn e2e_login_shell_sh() {
    bootstrap_through("sh").await;
}

#[tokio::test]
async fn e2e_login_shell_dash() {
    bootstrap_through("dash").await;
}

#[tokio::test]
async fn e2e_login_shell_bash() {
    bootstrap_through("bash").await;
}

#[tokio::test]
async fn e2e_login_shell_busybox() {
    bootstrap_through("busybox sh").await;
}

#[tokio::test]
async fn e2e_login_shell_zsh() {
    bootstrap_through("zsh").await;
}

#[tokio::test]
async fn e2e_login_shell_fish() {
    bootstrap_through("fish").await;
}

#[tokio::test]
async fn e2e_login_shell_tcsh() {
    bootstrap_through("tcsh").await;
}

fn installed(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(program).is_file()))
}

/// CI installs every shell these tests name, so a missing one there is a failure; a dev box just
/// says what it skipped.
fn skip(program: &str) {
    assert!(std::env::var_os("CI").is_none(), "{program} is not installed on this CI runner");
    eprintln!("skipped: {program} is not installed");
}

fn uid() -> String {
    String::from_utf8(std::process::Command::new("id").arg("-u").output().unwrap().stdout).unwrap().trim().to_owned()
}
