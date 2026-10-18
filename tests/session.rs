//! The bootstrap through a fake `ssh` that runs the remote side here (see `FakeRemote`): push,
//! cache, noexec fallthrough, the memfd fallback and several login shells, each proven by carrying
//! TCP through the relay it started. Named `e2e_*` because they spawn processes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    os::unix::fs::PermissionsExt as _,
    path::Path,
    time::{Duration, SystemTime},
};

use bytes::Bytes;
use pretty_assertions::assert_eq;
use sshunnel::{
    arch::Arch,
    relays::{Relay, Relays, Source},
    session::{Bootstrap, Session},
    tests::{FakeRemote, echo_server, full_disk_dir, host_arch, noexec_relay_dir, path_with, pattern, relay_dir, shim_dir, wrapped_relay_dir},
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

/// Puts `contents` at `path` with `mode`, by rename: a relay that ran from `path` may still be
/// running, and writing over a running binary fails (ETXTBSY).
fn plant(path: &Path, contents: &[u8], mode: u32) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let staged = path.with_extension("planting");
    std::fs::write(&staged, contents).unwrap();
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(mode)).unwrap();
    std::fs::rename(&staged, path).unwrap();
}

/// An executable script exactly `len` bytes long that passes `--probe` and serves nothing: only the
/// sha256 can tell it from the relay it impersonates.
fn same_size_impostor(len: usize) -> Vec<u8> {
    let mut script = b"#!/bin/sh\nexit 0\n".to_vec();
    script.resize(len, b'#');
    script
}

/// Runs the bootstrap once more against a cache the previous run filled, and expects a hit.
async fn assert_cached(remote: &FakeRemote, relays: &Relays, dir: &Path) {
    let session = connect(remote, relays).await;
    assert_eq!(session.bootstrap(), &Bootstrap::Cached { dir: dir_of(dir) });
    assert_carries_tcp(&session, 10_000).await;
}

#[tokio::test]
async fn e2e_a_cached_relay_with_the_wrong_bytes_is_replaced() {
    let root = TempDir::new().unwrap();
    let remote = FakeRemote::new(root.path(), "sh", &[]).unwrap();
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();
    let relay = relays.get(host_arch().unwrap()).unwrap();
    let cache = remote.home().join(".cache/sshunnel");
    let planted = cache.join(format!("relay-{}", relay.sha256()));
    plant(&planted, &same_size_impostor(relay.len()), 0o700);

    let session = connect(&remote, &relays).await;
    assert_eq!(session.bootstrap(), &Bootstrap::Pushed { dir: dir_of(&cache) });
    assert_carries_tcp(&session, 10_000).await;
    assert!(std::fs::read(&planted).unwrap() == relay.bytes()[..], "the push replaced the impostor");
}

#[tokio::test]
async fn e2e_a_symlinked_cache_dir_is_never_used() {
    let root = TempDir::new().unwrap();
    let run = root.path().join("run");
    std::fs::create_dir_all(&run).unwrap();
    let remote = FakeRemote::new(root.path(), "sh", &[("XDG_RUNTIME_DIR", &dir_of(&run))]).unwrap();
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();
    let relay = relays.get(host_arch().unwrap()).unwrap();
    // A dir this user doesn't control, holding the genuine relay under its real name, linked into
    // the first candidate's place. Nothing in it may run, and nothing may be written to it.
    let foreign = root.path().join("foreign");
    plant(&foreign.join(format!("relay-{}", relay.sha256())), relay.bytes(), 0o755);
    std::fs::create_dir_all(remote.home().join(".cache")).unwrap();
    std::os::unix::fs::symlink(&foreign, remote.home().join(".cache/sshunnel")).unwrap();

    let session = connect(&remote, &relays).await;
    assert_eq!(session.bootstrap(), &Bootstrap::Pushed { dir: dir_of(&run.join("sshunnel")) });
    assert_carries_tcp(&session, 10_000).await;
    let left: Vec<_> = std::fs::read_dir(&foreign).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(left, [format!("relay-{}", relay.sha256())], "the foreign dir is untouched");
}

#[tokio::test]
async fn e2e_a_cached_relay_that_is_a_symlink_is_replaced() {
    let root = TempDir::new().unwrap();
    let remote = FakeRemote::new(root.path(), "sh", &[]).unwrap();
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();
    let relay = relays.get(host_arch().unwrap()).unwrap();
    // The right bytes, but somewhere else: the cache entry must be the user's own file.
    let elsewhere = root.path().join("elsewhere/relay");
    plant(&elsewhere, relay.bytes(), 0o755);
    let cache = remote.home().join(".cache/sshunnel");
    std::fs::create_dir_all(&cache).unwrap();
    let entry = cache.join(format!("relay-{}", relay.sha256()));
    std::os::unix::fs::symlink(&elsewhere, &entry).unwrap();

    let session = connect(&remote, &relays).await;
    assert_eq!(session.bootstrap(), &Bootstrap::Pushed { dir: dir_of(&cache) });
    assert!(std::fs::symlink_metadata(&entry).unwrap().file_type().is_file(), "the push replaced the link with a file");
}

/// The tools the bootstrap needs. It uses a hasher and `mktemp` too when the remote has them, so a
/// remote `PATH` with only these has no way to check a sha256.
const BOOTSTRAP_TOOLS: &[&str] = &["sh", "uname", "id", "mkdir", "chmod", "ls", "wc", "head", "cat", "cp", "mv", "rm", "find"];

/// A remote whose `PATH` holds `tools` and nothing else.
fn remote_with_tools(root: &Path, tools: &[&str]) -> FakeRemote {
    let path = path_with(root, tools).unwrap();
    FakeRemote::new(root, "sh", &[("PATH", &dir_of(&path))]).unwrap()
}

/// A remote whose `PATH` holds the bootstrap's tools, `mktemp`, and `hasher` (if any).
fn remote_with_hasher(root: &Path, hasher: Option<&str>) -> FakeRemote {
    let tools: Vec<&str> = BOOTSTRAP_TOOLS.iter().copied().chain(["mktemp"]).chain(hasher).collect();
    remote_with_tools(root, &tools)
}

/// Pushes, hits the cache, then replaces a same-size impostor: on `remote`, the cache works and
/// still checks sha256s.
async fn assert_cache_verifies(remote: &FakeRemote, relays: &Relays, label: &str) {
    let relay = relays.get(host_arch().unwrap()).unwrap();
    let cache = remote.home().join(".cache/sshunnel");

    let first = connect(remote, relays).await;
    assert_eq!(first.bootstrap(), &Bootstrap::Pushed { dir: dir_of(&cache) }, "{label}");
    drop(first);
    assert_cached(remote, relays, &cache).await;

    plant(&cache.join(format!("relay-{}", relay.sha256())), &same_size_impostor(relay.len()), 0o700);
    let replaced = connect(remote, relays).await;
    assert_eq!(replaced.bootstrap(), &Bootstrap::Pushed { dir: dir_of(&cache) }, "{label} caught the wrong bytes");
}

/// With only `hasher` to check sha256s: the cache still hits, and still rejects the wrong bytes.
async fn cache_verifies_with(hasher: &str) {
    if !installed(hasher) {
        return skip(hasher);
    }
    let root = TempDir::new().unwrap();
    let remote = remote_with_hasher(root.path(), Some(hasher));
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();
    assert_cache_verifies(&remote, &relays, hasher).await;
}

#[tokio::test]
async fn e2e_busybox_alone_runs_the_bootstrap() {
    if !installed("busybox") {
        return skip("busybox");
    }
    let root = TempDir::new().unwrap();
    // `sh` and every tool the script runs are busybox applets, as on a minimal remote: field
    // positions, mktemp, find and the hasher all come from busybox.
    let applets = root.path().join("busybox");
    std::fs::create_dir_all(&applets).unwrap();
    let status = std::process::Command::new("busybox").arg("--install").arg("-s").arg(&applets).status().unwrap();
    assert!(status.success(), "busybox --install");
    let remote = FakeRemote::new(root.path(), "sh", &[("PATH", &dir_of(&applets))]).unwrap();
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();
    assert_cache_verifies(&remote, &relays, "busybox").await;
}

/// A remote `PATH` with `shims` ahead of this machine's own.
fn path_with_shims(root: &Path, shims: &[(&str, &str)]) -> String {
    format!("{}:{}", dir_of(&shim_dir(root, shims).unwrap()), std::env::var("PATH").unwrap())
}

#[tokio::test]
async fn e2e_cache_dirs_another_user_owns_are_never_used() {
    // Every candidate belongs to the test's uid, so an `id` that answers with another uid makes
    // each of them someone else's: a genuine relay among them must not run.
    const OTHER: &str = "4242424";
    let root = TempDir::new().unwrap();
    let path = path_with_shims(root.path(), &[("id", &format!("echo {OTHER}"))]);
    let remote = FakeRemote::new(root.path(), "sh", &[("PATH", &path)]).unwrap();
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();
    let relay = relays.get(host_arch().unwrap()).unwrap();
    plant(&remote.home().join(format!(".cache/sshunnel/relay-{}", relay.sha256())), relay.bytes(), 0o755);

    let started = timeout(Duration::from_secs(30), Session::connect(&remote.ssh_command().unwrap(), "fake-host", &relays))
        .await
        .expect("the bootstrap finishes");
    // The one candidate outside the TempDir, created empty under the other uid's name.
    let _ = std::fs::remove_dir(format!("/dev/shm/sshunnel-{OTHER}"));
    let err = started.err().expect("no candidate passes the owner check");
    assert!(format!("{err:#}").contains("this user owns"), "{err:#}");
}

#[tokio::test]
async fn e2e_a_cache_dir_others_can_write_to_never_serves_a_hit() {
    let root = TempDir::new().unwrap();
    let remote = FakeRemote::new(root.path(), "sh", &[]).unwrap();
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();
    let cache = remote.home().join(".cache/sshunnel");
    drop(connect(&remote, &relays).await);
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o777)).unwrap();

    let second = connect(&remote, &relays).await;
    assert_eq!(second.bootstrap(), &Bootstrap::Pushed { dir: dir_of(&cache) }, "no hit from a dir others can write to");
    let mode = std::fs::metadata(&cache).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "the dir is made private before a relay goes in");
    drop(second);
    assert_cached(&remote, &relays, &cache).await;
}

#[tokio::test]
async fn e2e_a_cache_the_user_cannot_chmod_still_serves_hits() {
    let root = TempDir::new().unwrap();
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();
    drop(connect(&FakeRemote::new(root.path(), "sh", &[]).unwrap(), &relays).await);
    // A read-only filesystem refuses chmod even on a dir that is already private.
    let path = path_with_shims(root.path(), &[("chmod", "exit 1")]);
    let read_only = FakeRemote::new(root.path(), "sh", &[("PATH", &path)]).unwrap();
    assert_cached(&read_only, &relays, &read_only.home().join(".cache/sshunnel")).await;
}

#[tokio::test]
async fn e2e_a_broken_hasher_means_pushing_every_run() {
    let root = TempDir::new().unwrap();
    let tools: Vec<&str> = BOOTSTRAP_TOOLS.iter().copied().chain(["mktemp"]).collect();
    let real = path_with(root.path(), &tools).unwrap();
    // A sha256sum that answers, wrongly: a hasher too old for the flags the script passes, say.
    let broken = shim_dir(root.path(), &[("sha256sum", "cat > /dev/null; echo 0000  -")]).unwrap();
    let remote = FakeRemote::new(root.path(), "sh", &[("PATH", &format!("{}:{}", dir_of(&broken), dir_of(&real)))]).unwrap();
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();
    let cache = remote.home().join(".cache/sshunnel");

    for run in ["first", "second"] {
        let session = connect(&remote, &relays).await;
        assert_eq!(session.bootstrap(), &Bootstrap::Pushed { dir: dir_of(&cache) }, "{run} run");
        assert_carries_tcp(&session, 10_000).await;
    }
}

#[tokio::test]
async fn e2e_cache_hits_verify_with_shasum_when_sha256sum_is_missing() {
    cache_verifies_with("shasum").await;
}

#[tokio::test]
async fn e2e_cache_hits_verify_with_openssl_when_sha256sum_is_missing() {
    cache_verifies_with("openssl").await;
}

#[tokio::test]
async fn e2e_without_a_hasher_the_relay_is_always_pushed() {
    let root = TempDir::new().unwrap();
    let remote = remote_with_hasher(root.path(), None);
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();
    let cache = remote.home().join(".cache/sshunnel");

    for run in ["first", "second"] {
        let session = connect(&remote, &relays).await;
        assert_eq!(session.bootstrap(), &Bootstrap::Pushed { dir: dir_of(&cache) }, "{run} run");
        assert_carries_tcp(&session, 10_000).await;
    }
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

/// Every candidate (the cache, `TMPDIR` and `/dev/shm`) ends in a `sshunnel*` dir; a memfd runs as
/// `/dev/fd/N`, which doesn't match. `/dev/shm/sshunnel-<uid>` is the one dir outside the `TempDir`
/// this touches, and only with staged copies, which the bootstrap removes.
const NOEXEC_EVERYWHERE: &str = "*/sshunnel*/relay-*|*/sshunnel*/.relay-*";

/// A dir holding a `sitecustomize.py` of `code`: on a remote's `PYTHONPATH`, python3 runs it before
/// the memfd fallback's own code.
fn python_site(root: &Path, code: &str) -> String {
    let dir = root.join("python-site");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("sitecustomize.py"), code).unwrap();
    dir_of(&dir)
}

#[tokio::test]
async fn e2e_noexec_everywhere_falls_back_to_memfd() {
    if !installed("python3") {
        return skip("python3");
    }
    let root = TempDir::new().unwrap();
    let remote = FakeRemote::new(root.path(), "sh", &[]).unwrap();
    let relays = Relays::from_dir(&noexec_relay_dir(root.path(), NOEXEC_EVERYWHERE).unwrap()).unwrap();

    let session = connect(&remote, &relays).await;
    assert_eq!(session.bootstrap(), &Bootstrap::Memfd);
    assert_carries_tcp(&session, 100_000).await;
    for dir in [remote.home().join(".cache/sshunnel"), root.path().join("tmp").join(format!("sshunnel-{}", uid()))] {
        assert!(!dir.join(format!("relay-{}", session.relay().sha256())).exists(), "a memfd run caches nothing in {}", dir.display());
        assert_eq!(strays(&dir), Vec::<String>::new(), "staged copies are cleaned up in {}", dir.display());
    }
}

#[tokio::test]
async fn e2e_a_failed_memfd_fallback_leaves_no_staged_copy() {
    if !installed("python3") {
        return skip("python3");
    }
    let root = TempDir::new().unwrap();
    // A python3 without memfd_create: older than 3.8, or under a seccomp filter that denies it.
    let site = python_site(root.path(), "import os\ndel os.memfd_create\n");
    let remote = FakeRemote::new(root.path(), "sh", &[("PYTHONPATH", &site)]).unwrap();
    let relays = Relays::from_dir(&noexec_relay_dir(root.path(), NOEXEC_EVERYWHERE).unwrap()).unwrap();

    let started = timeout(Duration::from_secs(30), Session::connect(&remote.ssh_command().unwrap(), "fake-host", &relays))
        .await
        .expect("the bootstrap finishes");
    assert!(started.is_err(), "the relay can't start without memfd_create");
    for dir in [remote.home().join(".cache/sshunnel"), root.path().join("tmp").join(format!("sshunnel-{}", uid()))] {
        assert_eq!(strays(&dir), Vec::<String>::new(), "no staged copy is left in {}", dir.display());
    }
}

#[tokio::test]
async fn e2e_the_memfd_fallback_runs_under_vm_memfd_noexec_1() {
    if !installed("python3") {
        return skip("python3");
    }
    if !Path::new("/proc/sys/vm/memfd_noexec").exists() {
        return skip("a kernel with vm.memfd_noexec (Linux 6.3+)");
    }
    let root = TempDir::new().unwrap();
    // Under vm.memfd_noexec=1 the kernel seals a memfd made without MFD_EXEC (0x10) as noexec
    // (MFD_NOEXEC_SEAL, 0x8). Setting the sysctl takes root, so python plays the kernel's part.
    let site = python_site(
        root.path(),
        "import os\nreal = os.memfd_create\nos.memfd_create = lambda name, flags=os.MFD_CLOEXEC: real(name, flags if flags & 0x10 else flags | 0x8)\n",
    );
    let remote = FakeRemote::new(root.path(), "sh", &[("PYTHONPATH", &site)]).unwrap();
    let relays = Relays::from_dir(&noexec_relay_dir(root.path(), NOEXEC_EVERYWHERE).unwrap()).unwrap();

    let session = connect(&remote, &relays).await;
    assert_eq!(session.bootstrap(), &Bootstrap::Memfd);
    assert_carries_tcp(&session, 10_000).await;
}

#[tokio::test]
async fn e2e_a_full_cache_dir_falls_through_to_the_next_candidate() {
    let root = TempDir::new().unwrap();
    let run = root.path().join("run");
    std::fs::create_dir_all(&run).unwrap();
    // The bootstrap writes a relay with these; on a full disk, every one of them fails there.
    let full = full_disk_dir(root.path(), "*/.cache/sshunnel/*", &["head", "cat", "cp"]).unwrap();
    let path = format!("{}:{}", dir_of(&full), std::env::var("PATH").unwrap());
    let remote = FakeRemote::new(root.path(), "sh", &[("XDG_RUNTIME_DIR", &dir_of(&run)), ("PATH", &path)]).unwrap();
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();

    let session = connect(&remote, &relays).await;
    assert_eq!(session.bootstrap(), &Bootstrap::Pushed { dir: dir_of(&run.join("sshunnel")) });
    assert_carries_tcp(&session, 100_000).await;
    assert_eq!(strays(&remote.home().join(".cache/sshunnel")), Vec::<String>::new(), "the failed copies are cleaned up");
}

#[tokio::test]
async fn e2e_the_probe_cannot_read_the_session() {
    let root = TempDir::new().unwrap();
    let remote = FakeRemote::new(root.path(), "sh", &[]).unwrap();
    // A relay whose --probe reads stdin. Given the session, it would wait on a client that sends
    // nothing until READY (or eat the bytes the client did send).
    let relays = Relays::from_dir(&wrapped_relay_dir(root.path(), "case \"$1\" in --probe) [ -z \"$(head -c 1)\" ] || exit 1;; esac").unwrap()).unwrap();

    let session = connect(&remote, &relays).await;
    assert!(matches!(session.bootstrap(), Bootstrap::Pushed { .. }), "{}", session.bootstrap());
    assert_carries_tcp(&session, 10_000).await;
}

#[tokio::test]
async fn e2e_staging_works_without_mktemp() {
    let root = TempDir::new().unwrap();
    let tools: Vec<&str> = BOOTSTRAP_TOOLS.iter().copied().chain(["sha256sum"]).collect();
    let remote = remote_with_tools(root.path(), &tools);
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();
    let cache = remote.home().join(".cache/sshunnel");

    let first = connect(&remote, &relays).await;
    assert_eq!(first.bootstrap(), &Bootstrap::Pushed { dir: dir_of(&cache) });
    assert_eq!(strays(&cache), Vec::<String>::new());
    drop(first);
    assert_cached(&remote, &relays, &cache).await;
}

/// Sets `path`'s modification time to `days` ago.
fn age(path: &Path, days: u64) {
    let then = SystemTime::now() - Duration::from_hours(days * 24);
    std::fs::File::open(path).unwrap().set_modified(then).unwrap();
}

#[tokio::test]
async fn e2e_relays_installed_over_30_days_ago_are_evicted_on_install() {
    let root = TempDir::new().unwrap();
    let remote = FakeRemote::new(root.path(), "sh", &[]).unwrap();
    let relays = Relays::from_dir(&relay_dir(root.path()).unwrap()).unwrap();
    let cache = remote.home().join(".cache/sshunnel");
    // Two other builds' relays: one installed 40 days ago, one yesterday.
    let stale = cache.join(format!("relay-{}", "0".repeat(64)));
    let recent = cache.join(format!("relay-{}", "1".repeat(64)));
    plant(&stale, b"an old build", 0o700);
    age(&stale, 40);
    plant(&recent, b"a build still in use", 0o700);
    age(&recent, 1);

    let session = connect(&remote, &relays).await;
    assert_eq!(session.bootstrap(), &Bootstrap::Pushed { dir: dir_of(&cache) });
    assert!(!stale.exists(), "a relay installed 40 days ago is evicted");
    assert!(recent.exists(), "a relay installed yesterday stays");
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

/// CI provides every program and kernel feature these tests name, so a missing one there is a
/// failure; a dev box just says what it skipped.
fn skip(what: &str) {
    assert!(std::env::var_os("CI").is_none(), "{what} is missing on this CI runner");
    eprintln!("skipped: {what} is missing");
}

fn uid() -> String {
    String::from_utf8(std::process::Command::new("id").arg("-u").output().unwrap().stdout).unwrap().trim().to_owned()
}
