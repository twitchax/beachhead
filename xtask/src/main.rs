//! Repo tooling, run as `cargo xtask <task>` (the alias lives in `.cargo/config.toml`). Tasks are
//! Rust rather than shell or Python, so they get the same lints and tests as the product.

mod bench;

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context as _, Result, bail, ensure};
use sshunnel::{
    arch::Arch,
    relays::{Relays, build_embed::COMMIT_FILE},
};

const USAGE: &str = "usage: cargo xtask <task>

tasks:
  relay [--arch NAME]...   build static musl relays into target/relay and write SHA256SUMS
                           (every arch unless --arch narrows it)
  dist [--target TRIPLE]   write SHA256SUMS for target/relay and build the release client with
                           those relays embedded into target/dist; without --target, also check
                           its `relays` output against them
  package                  ready the crates for crates.io and build them as an install would:
                           - build every relay into relays/ with SHA256SUMS (the crate ships them)
                           - `cargo package --workspace` (all but xtask)
                           - unpack the sshunnel and sshunnel-mux .crate files outside the repo
                           - build that sshunnel on stable, offline, against the unpacked mux,
                             into target/package-check
                           - check its `relays` lists every relay as embedded
  bench [--mib N] [--runs N] [--route]
                           relay + dist, then compare `sshunnel forward -L` with `ssh -L` through
                           a throwaway non-root sshd (default 512 MiB per transfer, best of 3);
                           --route compares `sshunnel route` with `sshunnel forward -L` instead,
                           one stream each way, from network namespaces (Linux only; needs Docker
                           where user namespaces are restricted), over 15 rounds by default, and
                           fails when either direction's median is under 90% of forward mode's";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (task, rest) = args.split_first().map_or(("help", &[][..]), |(task, rest)| (task.as_str(), rest));
    match task {
        "relay" => relay(&arches(rest)?),
        "dist" => dist(target(rest)?),
        "package" => {
            ensure!(rest.is_empty(), "unexpected arguments {rest:?}\n\n{USAGE}");
            package()
        }
        "bench" => {
            let options = bench_options(rest)?;
            let host = Arch::from_name(std::env::consts::ARCH).context("no relay arch for this host")?;
            relay(&[host])?;
            dist(None)?;
            bench::run(&target_dir().join("dist").join("sshunnel"), &target_dir(), &options)
        }
        // Hidden: ssh's ProxyCommand and the client side, both in the route bench's namespaces.
        #[cfg(target_os = "linux")]
        "bridge" => match rest {
            [socket] => bench::route::bridge_stdio(Path::new(socket)),
            _ => bail!("usage: cargo xtask bridge <socket>"),
        },
        #[cfg(target_os = "linux")]
        "bench-client" => bench::route::client(rest),
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            Ok(())
        }
        other => bail!("unknown task `{other}`\n\n{USAGE}"),
    }
}

/// Builds each relay into `target/relay`, with its SHA256SUMS.
fn relay(arches: &[Arch]) -> Result<()> {
    install_relays(arches, &target_dir().join("relay"))?;
    Ok(())
}

/// Builds each relay, installs it in `out` under its arch's file name, and writes `out`'s SHA256SUMS.
fn install_relays(arches: &[Arch], out: &Path) -> Result<Relays> {
    std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    for &arch in arches {
        let built = build_relay(arch)?;
        std::fs::copy(&built, out.join(arch.file_name())).with_context(|| format!("installing the {arch} relay in {}", out.display()))?;
    }
    write_sums(out)
}

/// Hashes every relay `dir` holds, not only the ones just built (so building one arch keeps the
/// other's line), and writes its SHA256SUMS.
fn write_sums(dir: &Path) -> Result<Relays> {
    let relays = Relays::from_dir(dir)?;
    let mut sums = String::new();
    for relay in relays.iter() {
        writeln!(sums, "{}  {}", relay.sha256(), relay.arch().file_name())?;
        println!("{:<8} {:>8} bytes  sha256 {}", relay.arch().name(), relay.len(), relay.sha256());
    }
    let path = dir.join("SHA256SUMS");
    std::fs::write(&path, sums).with_context(|| format!("writing {}", path.display()))?;
    println!("wrote {}", dir.display());
    Ok(relays)
}

/// Builds one relay, checks it is static and names no builder directory, and returns its path.
///
/// Paths are trimmed on the command line, never in a manifest: a `trim-paths` profile key would ship
/// in the published `Cargo.toml` and break installs on toolchains older than the one that stabilized it.
fn build_relay(arch: Arch) -> Result<PathBuf> {
    cargo()
        .args(["build", "-p", "sshunnel-relay", "--profile", "relay", "--target", arch.triple()])
        .args(["--config", "profile.relay.trim-paths=\"all\""])
        .status_ok()?;
    let built = target_dir().join(arch.triple()).join("relay").join("sshunnel-relay");
    let bytes = std::fs::read(&built).with_context(|| format!("reading {}", built.display()))?;
    if !is_static_elf(&bytes).with_context(|| format!("inspecting {}", built.display()))? {
        bail!("{} needs a dynamic loader; the relay must be static", built.display());
    }
    if let Some(dir) = builder_paths(&bytes, &builder_dirs()) {
        bail!("the {arch} relay contains {}: trimming missed it", dir.display());
    }
    Ok(built)
}

/// The first of `dirs` that occurs in `bytes`. A relay is pushed to other machines, so none of the
/// builder's directories may survive in it. Empty and `/` are skipped: they would match anything.
fn builder_paths<'a>(bytes: &[u8], dirs: &'a [PathBuf]) -> Option<&'a Path> {
    dirs.iter().map(PathBuf::as_path).find(|dir| {
        let needle = dir.to_str().unwrap_or_default().as_bytes();
        needle.len() > 1 && bytes.windows(needle.len()).any(|window| window == needle)
    })
}

/// The directories a build on this machine can leak into a binary: home, cargo, rustup and the workspace.
fn builder_dirs() -> Vec<PathBuf> {
    let var = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty()).map(PathBuf::from);
    let home = var("HOME");
    let under_home = |name: &str| home.as_ref().map(|home| home.join(name));
    [
        home.clone(),
        var("CARGO_HOME").or_else(|| under_home(".cargo")),
        var("RUSTUP_HOME").or_else(|| under_home(".rustup")),
        Some(root().to_path_buf()),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Builds the release client with `target/relay` embedded and copies it to `target/dist`.
fn dist(target: Option<&str>) -> Result<()> {
    let relay_dir = target_dir().join("relay");
    // `build.rs` checks the relays against their SHA256SUMS, and the release downloads them without one.
    let relays = write_sums(&relay_dir).context("no relays to embed: run `cargo xtask relay` first")?;
    let mut build = cargo();
    build.args(["build", "--release", "-p", "sshunnel"]).env("SSHUNNEL_EMBED_RELAY_DIR", &relay_dir);
    if let Some(target) = target {
        build.args(["--target", target]);
    }
    build.status_ok()?;

    let release = target.map_or_else(|| target_dir().join("release"), |t| target_dir().join(t).join("release"));
    let dist = target_dir().join("dist");
    std::fs::create_dir_all(&dist).with_context(|| format!("creating {}", dist.display()))?;
    let client = dist.join("sshunnel");
    std::fs::copy(release.join("sshunnel"), &client).context("copying the client into target/dist")?;

    if target.is_none() {
        print!("{}", check_embedded(&client, &relays)?);
    }
    println!("wrote {}", client.display());
    Ok(())
}

/// Runs `<client> relays`, checks it lists every one of `relays` as embedded, and returns the listing.
fn check_embedded(client: &Path, relays: &Relays) -> Result<String> {
    let out = Command::new(client).arg("relays").output().with_context(|| format!("running `{} relays`", client.display()))?;
    let listing = String::from_utf8(out.stdout).context("`relays` printed non-UTF-8")?;
    if !out.status.success() || !listing.starts_with("relays (embedded)") {
        bail!("{} didn't embed its relays:\n{listing}{}", client.display(), String::from_utf8_lossy(&out.stderr));
    }
    for relay in relays.iter() {
        if !listing.contains(relay.sha256()) {
            bail!("{} doesn't embed the {} relay with sha256 {}:\n{listing}", client.display(), relay.arch(), relay.sha256());
        }
    }
    Ok(listing)
}

/// Builds every relay into the crate's `relays/`, packages the workspace, then builds the packaged
/// client as `cargo install` would (on stable, offline, from the .crate files alone) and checks it
/// embeds them. `relays/` stays afterwards: the publish packages it again.
fn package() -> Result<()> {
    // Before the slow build: a dirty tree fails `write_commit` at the end anyway.
    ensure_clean(root())?;
    let relay_dir = root().join("relays");
    remove_dir_if_present(&relay_dir)?;
    let relays = install_relays(&Arch::ALL, &relay_dir)?;
    if let Some(arch) = Arch::ALL.into_iter().find(|&arch| relays.get(arch).is_none()) {
        bail!("{} has no {arch} relay", relay_dir.display());
    }
    write_commit(root(), &relay_dir)?;

    // Cargo counts the gitignored relays the `include` list names as uncommitted changes. xtask is
    // `publish = false`, so packaging it would only cost a verify build.
    cargo().args(["package", "--workspace", "--exclude", "xtask", "--allow-dirty"]).status_ok()?;

    // Outside the repository: under it, cargo takes the crate for a missing member of this workspace.
    let scratch = tempfile::Builder::new().prefix("sshunnel-package-check-").tempdir().context("creating a scratch dir")?;
    let mux = unpack("sshunnel-mux", scratch.path())?;
    let client_crate = unpack("sshunnel", scratch.path())?;

    // `rustup run stable` and none of the pinned toolchain's variables (xtask runs under it), so
    // the packaged crate builds on stable exactly as an install's would.
    let mux = mux.to_str().with_context(|| format!("{} is not UTF-8", mux.display()))?;
    let build_dir = target_dir().join("package-check");
    // Not `--locked`: the patch moves the packaged lockfile's mux entry from crates.io to the
    // unpacked path, and that is the only line it changes.
    Command::new("rustup")
        .args(["run", "stable", "cargo", "build", "--release", "--offline"])
        // Debug quotes the path and escapes `"` and `\` as a TOML basic string does.
        .args(["--config", &format!("patch.crates-io.sshunnel-mux.path={mux:?}")])
        .arg("--target-dir")
        .arg(&build_dir)
        .current_dir(&client_crate)
        .env_remove("RUSTC")
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO")
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("SSHUNNEL_EMBED_RELAY_DIR")
        .status_ok()?;

    print!("{}", check_embedded(&build_dir.join("release").join("sshunnel"), &relays)?);
    Ok(())
}

/// Refuses a tree with uncommitted changes, which would make COMMIT name a commit the packaged
/// files have left. Ignored files (`relays/`, the PRD plans) don't show.
fn ensure_clean(repo: &Path) -> Result<()> {
    let status = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(repo)
        .output()
        .context("running `git status --porcelain`")?;
    ensure!(status.status.success(), "`git status --porcelain` failed: {}", String::from_utf8_lossy(&status.stderr));
    let dirty = String::from_utf8_lossy(&status.stdout);
    ensure!(
        dirty.trim().is_empty(),
        "the tree has uncommitted changes, so relays/{COMMIT_FILE} would name a commit it isn't: {}",
        dirty.trim().replace('\n', ", ")
    );
    Ok(())
}

/// Records `repo`'s HEAD in `dir`'s COMMIT, which the packaged build compares with the commit cargo
/// packaged.
fn write_commit(repo: &Path, dir: &Path) -> Result<()> {
    ensure_clean(repo)?;
    let out = Command::new("git").args(["rev-parse", "HEAD"]).current_dir(repo).output().context("running `git rev-parse HEAD`")?;
    ensure!(out.status.success(), "`git rev-parse HEAD` failed: {}", String::from_utf8_lossy(&out.stderr));
    let head = String::from_utf8(out.stdout).context("`git rev-parse HEAD` printed non-UTF-8")?;
    let path = dir.join(COMMIT_FILE);
    std::fs::write(&path, format!("{}\n", head.trim())).with_context(|| format!("writing {}", path.display()))
}

/// Unpacks `cargo package`'s `<name>-<version>.crate` into `into`, returning the crate's directory.
fn unpack(name: &str, into: &Path) -> Result<PathBuf> {
    let unpacked = format!("{name}-{}", version(name)?);
    let krate = target_dir().join("package").join(format!("{unpacked}.crate"));
    Command::new("tar").arg("-xzf").arg(&krate).arg("-C").arg(into).status_ok()?;
    Ok(into.join(unpacked))
}

/// The version of workspace package `name`, from `cargo pkgid`.
fn version(name: &str) -> Result<String> {
    let out = cargo().args(["pkgid", "-p", name]).output().with_context(|| format!("running `cargo pkgid -p {name}`"))?;
    ensure!(out.status.success(), "`cargo pkgid -p {name}` failed: {}", String::from_utf8_lossy(&out.stderr));
    let pkgid = String::from_utf8(out.stdout).context("`cargo pkgid` printed non-UTF-8")?;
    pkgid_version(&pkgid).map(str::to_owned).with_context(|| format!("no version in {name}'s pkgid `{}`", pkgid.trim()))
}

/// The version a pkgid ends with: `path+file:///dir#0.1.0`, or `path+file:///dir#name@0.1.0` when
/// the directory isn't named after the package.
fn pkgid_version(pkgid: &str) -> Option<&str> {
    let (_, spec) = pkgid.trim().rsplit_once('#')?;
    Some(spec.rsplit_once('@').map_or(spec, |(_, version)| version))
}

fn remove_dir_if_present(dir: &Path) -> Result<()> {
    match std::fs::remove_dir_all(dir) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e).with_context(|| format!("removing {}", dir.display())),
        _ => Ok(()),
    }
}

/// True when the ELF has no `PT_INTERP` header, i.e. it needs no dynamic loader. Static-pie
/// binaries still carry `PT_DYNAMIC` (for self-relocation), so that header proves nothing.
fn is_static_elf(bytes: &[u8]) -> Result<bool> {
    const PT_INTERP: u32 = 3;
    if bytes.get(..6) != Some(b"\x7fELF\x02\x01") {
        bail!("not a little-endian 64-bit ELF");
    }
    let u16_at = |at: usize| bytes.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let phoff = bytes.get(0x20..0x28).map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]));
    let (Some(phoff), Some(phentsize), Some(phnum)) = (phoff, u16_at(0x36), u16_at(0x38)) else {
        bail!("truncated ELF header");
    };
    let phoff = usize::try_from(phoff).context("program header offset overflows usize")?;
    for i in 0..usize::from(phnum) {
        let at = phoff + i * usize::from(phentsize);
        let p_type = bytes.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).context("truncated program header table")?;
        if p_type == PT_INTERP {
            return Ok(false);
        }
    }
    Ok(true)
}

fn arches(args: &[String]) -> Result<Vec<Arch>> {
    let mut arches = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--arch" => {
                let name = args.next().context("--arch needs a value")?;
                arches.push(Arch::from_name(name).with_context(|| format!("unknown arch `{name}`"))?);
            }
            other => bail!("unexpected argument `{other}`\n\n{USAGE}"),
        }
    }
    Ok(if arches.is_empty() { Arch::ALL.to_vec() } else { arches })
}

/// The plain bench's rounds when `--runs` doesn't say: it reports the best of a few.
const RUNS: usize = 3;
/// The route bench's rounds when `--runs` doesn't say: its bar is on the median, which wants more.
const ROUTE_RUNS: usize = 15;

fn bench_options(args: &[String]) -> Result<bench::Options> {
    let (mut mib, mut runs, mut route) = (512, None, false);
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = || -> Result<usize> { args.next().with_context(|| format!("{arg} needs a value"))?.parse().with_context(|| format!("{arg} needs a number")) };
        match arg.as_str() {
            "--mib" => mib = value()?.max(8),
            "--runs" => runs = Some(value()?.max(1)),
            "--route" => {
                // Checked before the relay and client builds, which take a while.
                ensure!(cfg!(target_os = "linux"), "--route is Linux only: `sshunnel route` needs a TUN device and network namespaces");
                route = true;
            }
            other => bail!("unexpected argument `{other}`\n\n{USAGE}"),
        }
    }
    let runs = runs.unwrap_or(if route { ROUTE_RUNS } else { RUNS });
    Ok(bench::Options { mib, runs, route })
}

fn target(args: &[String]) -> Result<Option<&str>> {
    match args {
        [] => Ok(None),
        [flag, triple] if flag == "--target" => Ok(Some(triple)),
        _ => bail!("unexpected arguments {args:?}\n\n{USAGE}"),
    }
}

fn root() -> &'static Path {
    // xtask lives one level below the workspace root.
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap_or_else(|| Path::new("."))
}

fn target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root().join("target"), PathBuf::from)
}

fn cargo() -> Command {
    let mut cmd = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    cmd.current_dir(root());
    cmd
}

trait StatusOk {
    fn status_ok(&mut self) -> Result<()>;
}

impl StatusOk for Command {
    fn status_ok(&mut self) -> Result<()> {
        let status = self.status().with_context(|| format!("running {self:?}"))?;
        if !status.success() {
            bail!("{self:?} failed: {status}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// A minimal ELF64 LE header with one program header of type `p_type`.
    fn elf(p_type: u32) -> Vec<u8> {
        let mut bytes = vec![0; 0x40 + 0x38];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
        bytes[0x36..0x38].copy_from_slice(&0x38u16.to_le_bytes());
        bytes[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(&p_type.to_le_bytes());
        bytes
    }

    #[test]
    fn an_interpreter_header_means_dynamic() {
        assert!(!is_static_elf(&elf(3)).unwrap());
        assert!(is_static_elf(&elf(1)).unwrap(), "PT_LOAD alone is static");
        assert!(is_static_elf(&elf(2)).unwrap(), "PT_DYNAMIC alone is static-pie");
    }

    #[test]
    fn this_test_binary_is_dynamic() {
        let me = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        assert!(!is_static_elf(&me).unwrap());
    }

    #[test]
    fn non_elf_and_truncated_input_are_errors() {
        assert!(is_static_elf(b"#!/bin/sh\n").is_err());
        assert!(is_static_elf(&elf(1)[..0x30]).is_err());
        let mut lying = elf(1);
        lying[0x38..0x3A].copy_from_slice(&9u16.to_le_bytes());
        assert!(is_static_elf(&lying).is_err(), "nine headers claimed, one present");
    }

    #[test]
    fn bench_flags_parse() {
        let plain = bench_options(&[]).unwrap();
        assert_eq!((plain.mib, plain.runs, plain.route), (512, 3, false));
        let route = bench_options(&["--route".into(), "--mib".into(), "64".into()]);
        if cfg!(target_os = "linux") {
            let route = route.unwrap();
            assert_eq!((route.mib, route.runs, route.route), (64, 15, true));
        } else {
            assert!(route.is_err_and(|e| e.to_string().contains("Linux only")));
        }
        assert!(bench_options(&["--routes".into()]).is_err());
    }

    #[test]
    fn the_route_bench_defaults_to_15_rounds() {
        let runs = |args: &[&str]| bench_options(&args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>()).unwrap().runs;

        assert_eq!(runs(&[]), 3, "the plain bench keeps its best of 3");
        assert_eq!(runs(&["--runs", "5"]), 5);
        if cfg!(target_os = "linux") {
            assert_eq!(runs(&["--route"]), 15);
            assert_eq!(runs(&["--route", "--runs", "5"]), 5);
            assert_eq!(runs(&["--runs", "5", "--route"]), 5, "in either order");
        }
    }

    #[test]
    fn arch_flags_parse() {
        assert_eq!(arches(&[]).unwrap(), Arch::ALL.to_vec());
        assert_eq!(arches(&["--arch".into(), "aarch64".into()]).unwrap(), vec![Arch::Aarch64]);
        assert!(arches(&["--arch".into(), "mips".into()]).is_err());
        assert!(arches(&["--arch".into()]).is_err());
    }

    #[test]
    fn builder_paths_finds_a_planted_home() {
        let dirs = [PathBuf::from("/home/someone")];
        let bytes = b"...panicked at /home/someone/.cargo/registry/src/x.rs...";
        assert_eq!(builder_paths(bytes, &dirs), Some(Path::new("/home/someone")));
    }

    #[test]
    fn builder_paths_passes_clean_bytes() {
        let dirs = [PathBuf::from("/home/someone"), PathBuf::from("/work/sshunnel")];
        assert_eq!(builder_paths(b"panicked at /cargo/registry/src/x.rs", &dirs), None);
    }

    #[test]
    fn builder_paths_skips_root_and_empty() {
        let dirs = [PathBuf::new(), PathBuf::from("/")];
        assert_eq!(builder_paths(b"/usr/lib/x.rs", &dirs), None);
    }

    #[test]
    fn write_sums_lists_every_relay_in_the_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("sshunnel-relay-x86_64"), b"abc").unwrap();
        std::fs::write(dir.path().join("sshunnel-relay-aarch64"), b"arm").unwrap();

        let relays = write_sums(dir.path()).unwrap();

        assert_eq!(relays.iter().count(), 2);
        let sums = std::fs::read_to_string(dir.path().join("SHA256SUMS")).unwrap();
        let lines: Vec<&str> = sums.lines().collect();
        assert_eq!(lines.len(), 2, "{sums}");
        assert!(lines.contains(&"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  sshunnel-relay-x86_64"), "{sums}");
        assert!(lines.iter().any(|line| line.ends_with("  sshunnel-relay-aarch64")), "{sums}");
    }

    /// A stand-in client whose `relays` prints `listing`.
    #[cfg(unix)]
    fn fake_client(dir: &Path, listing: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let client = dir.join("sshunnel");
        std::fs::write(&client, format!("#!/bin/sh\n[ \"$1\" = relays ] || exit 2\ncat <<'EOF'\n{listing}EOF\n")).unwrap();
        std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o755)).unwrap();
        client
    }

    #[cfg(unix)]
    #[test]
    fn check_embedded_wants_every_hash_listed_as_embedded() {
        use sshunnel::relays::{Relay, Source};

        let dir = tempfile::tempdir().unwrap();
        let x86 = Relay::new(Arch::X86_64, b"x86".to_vec().into());
        let arm = Relay::new(Arch::Aarch64, b"arm".to_vec().into());
        let (x86_hash, arm_hash) = (x86.sha256().to_owned(), arm.sha256().to_owned());
        let relays = Relays::new(vec![x86, arm], Source::Embedded).unwrap();

        let both = format!("relays (embedded):\n  x86_64   sha256 {x86_hash}\n  aarch64  sha256 {arm_hash}\n");
        assert_eq!(check_embedded(&fake_client(dir.path(), &both), &relays).unwrap(), both);

        let one = format!("relays (embedded):\n  x86_64   sha256 {x86_hash}\n");
        let err = check_embedded(&fake_client(dir.path(), &one), &relays).unwrap_err();
        assert!(err.to_string().contains("aarch64"), "{err}");

        let from_dir = format!("relays (target/relay):\n  x86_64   sha256 {x86_hash}\n  aarch64  sha256 {arm_hash}\n");
        assert!(check_embedded(&fake_client(dir.path(), &from_dir), &relays).is_err());
    }

    #[test]
    fn pkgid_version_reads_either_form() {
        assert_eq!(pkgid_version("path+file:///work/sshunnel#0.1.0"), Some("0.1.0"));
        assert_eq!(pkgid_version("path+file:///work/mux#sshunnel-mux@0.2.0\n"), Some("0.2.0"));
        assert_eq!(pkgid_version("path+file:///work/sshunnel"), None);
    }

    /// A scratch repo with one commit. The identity is local to it, so the developer's own config
    /// doesn't matter.
    fn scratch_repo() -> tempfile::TempDir {
        let repo = tempfile::tempdir().unwrap();
        for args in [
            &["init", "-q"][..],
            &["config", "user.name", "t"],
            &["config", "user.email", "t@example.com"],
            &["config", "commit.gpgsign", "false"],
        ] {
            Command::new("git").args(args).current_dir(repo.path()).status_ok().unwrap();
        }
        std::fs::write(repo.path().join("a"), "a").unwrap();
        for args in [&["add", "a"][..], &["commit", "-q", "-m", "one"]] {
            Command::new("git").args(args).current_dir(repo.path()).status_ok().unwrap();
        }
        repo
    }

    #[test]
    fn write_commit_refuses_a_dirty_tree() {
        let repo = scratch_repo();
        std::fs::write(repo.path().join("stray.txt"), "x").unwrap();
        let out = tempfile::tempdir().unwrap();

        let err = write_commit(repo.path(), out.path()).unwrap_err().to_string();

        assert!(err.contains("uncommitted changes"), "{err}");
        assert!(err.contains("stray.txt"), "{err}");
        assert!(!out.path().join(COMMIT_FILE).exists());
    }

    #[test]
    fn ensure_clean_passes_a_clean_tree_and_refuses_a_dirty_one() {
        let repo = scratch_repo();
        ensure_clean(repo.path()).unwrap();

        std::fs::write(repo.path().join("stray.txt"), "x").unwrap();
        let err = ensure_clean(repo.path()).unwrap_err().to_string();
        assert!(err.contains("stray.txt"), "{err}");
    }

    #[test]
    fn write_commit_records_head_in_a_clean_tree() {
        let repo = scratch_repo();
        let out = tempfile::tempdir().unwrap();

        write_commit(repo.path(), out.path()).unwrap();

        let head = Command::new("git").args(["rev-parse", "HEAD"]).current_dir(repo.path()).output().unwrap();
        let recorded = std::fs::read_to_string(out.path().join(COMMIT_FILE)).unwrap();
        assert_eq!(recorded, format!("{}\n", String::from_utf8(head.stdout).unwrap().trim()));
    }
}
