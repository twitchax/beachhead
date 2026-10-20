//! Repo tooling, run as `cargo xtask <task>` (the alias lives in `.cargo/config.toml`). Tasks are
//! Rust rather than shell or Python, so they get the same lints and tests as the product.

mod bench;

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context as _, Result, bail, ensure};
use sshunnel::{arch::Arch, relays::Relays};

const USAGE: &str = "usage: cargo xtask <task>

tasks:
  relay [--arch NAME]...   build static musl relays into target/relay and write SHA256SUMS
                           (every arch unless --arch narrows it)
  dist [--target TRIPLE]   build the release client with target/relay embedded into target/dist;
                           without --target, also check its `relays` output against SHA256SUMS
  bench [--mib N] [--runs N] [--route]
                           relay + dist, then compare `sshunnel forward -L` with `ssh -L` through
                           a throwaway non-root sshd (default 512 MiB per transfer, best of 3);
                           --route compares `sshunnel route` with `sshunnel forward -L` instead,
                           one stream each way, from network namespaces (Linux only; needs Docker
                           where user namespaces are restricted)";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (task, rest) = args.split_first().map_or(("help", &[][..]), |(task, rest)| (task.as_str(), rest));
    match task {
        "relay" => relay(&arches(rest)?),
        "dist" => dist(target(rest)?),
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

/// Builds each relay, checks it is static, and installs it under its arch's file name.
fn relay(arches: &[Arch]) -> Result<()> {
    let out = target_dir().join("relay");
    std::fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;
    for &arch in arches {
        cargo().args(["build", "-p", "sshunnel-relay", "--profile", "relay", "--target", arch.triple()]).status_ok()?;
        let built = target_dir().join(arch.triple()).join("relay").join("sshunnel-relay");
        let bytes = std::fs::read(&built).with_context(|| format!("reading {}", built.display()))?;
        if !is_static_elf(&bytes).with_context(|| format!("inspecting {}", built.display()))? {
            bail!("{} needs a dynamic loader; the relay must be static", built.display());
        }
        std::fs::copy(&built, out.join(arch.file_name())).with_context(|| format!("installing the {arch} relay"))?;
    }

    // Hash whatever the dir now holds, so building one arch keeps the other's line.
    let relays = Relays::from_dir(&out)?;
    let mut sums = String::new();
    for relay in relays.iter() {
        writeln!(sums, "{}  {}", relay.sha256(), relay.arch().file_name())?;
        println!("{:<8} {:>8} bytes  sha256 {}", relay.arch().name(), relay.len(), relay.sha256());
    }
    std::fs::write(out.join("SHA256SUMS"), sums).context("writing SHA256SUMS")?;
    println!("wrote {}", out.display());
    Ok(())
}

/// Builds the release client with `target/relay` embedded and copies it to `target/dist`.
fn dist(target: Option<&str>) -> Result<()> {
    let relay_dir = target_dir().join("relay");
    let relays = Relays::from_dir(&relay_dir).context("no relays to embed: run `cargo xtask relay` first")?;
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
        let out = Command::new(&client).arg("relays").output().context("running the client's `relays`")?;
        let listing = String::from_utf8(out.stdout).context("`relays` printed non-UTF-8")?;
        if !out.status.success() || !listing.starts_with("relays (embedded)") {
            bail!("the client didn't embed its relays:\n{listing}{}", String::from_utf8_lossy(&out.stderr));
        }
        for relay in relays.iter() {
            if !listing.contains(relay.sha256()) {
                bail!("the client's {} relay doesn't match target/relay:\n{listing}", relay.arch());
            }
        }
        print!("{listing}");
    }
    println!("wrote {}", client.display());
    Ok(())
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

fn bench_options(args: &[String]) -> Result<bench::Options> {
    let mut options = bench::Options { mib: 512, runs: 3, route: false };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = || -> Result<usize> { args.next().with_context(|| format!("{arg} needs a value"))?.parse().with_context(|| format!("{arg} needs a number")) };
        match arg.as_str() {
            "--mib" => options.mib = value()?.max(8),
            "--runs" => options.runs = value()?.max(1),
            "--route" => {
                // Checked before the relay and client builds, which take a while.
                ensure!(cfg!(target_os = "linux"), "--route is Linux only: `sshunnel route` needs a TUN device and network namespaces");
                options.route = true;
            }
            other => bail!("unexpected argument `{other}`\n\n{USAGE}"),
        }
    }
    Ok(options)
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
            assert_eq!((route.mib, route.runs, route.route), (64, 3, true));
        } else {
            assert!(route.is_err_and(|e| e.to_string().contains("Linux only")));
        }
        assert!(bench_options(&["--routes".into()]).is_err());
    }

    #[test]
    fn arch_flags_parse() {
        assert_eq!(arches(&[]).unwrap(), Arch::ALL.to_vec());
        assert_eq!(arches(&["--arch".into(), "aarch64".into()]).unwrap(), vec![Arch::Aarch64]);
        assert!(arches(&["--arch".into(), "mips".into()]).is_err());
        assert!(arches(&["--arch".into()]).is_err());
    }
}
