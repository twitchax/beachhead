//! The relay binaries this client can push, with their sha256: what `sshunnel relays` prints and
//! what the bootstrap script checks before it executes anything.

use std::{fmt::Write as _, path::Path};

use anyhow::{Context as _, bail};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};

use crate::{arch::Arch, base::Res};

/// One relay binary.
#[derive(Clone, Debug)]
pub struct Relay {
    arch: Arch,
    bytes: Bytes,
    sha256: String,
}

impl Relay {
    /// Wraps a relay's bytes, hashing them once.
    #[must_use]
    pub fn new(arch: Arch, bytes: Bytes) -> Self {
        let sha256 = hex(&Sha256::digest(&bytes));
        Self { arch, bytes, sha256 }
    }

    /// The arch it runs on.
    #[must_use]
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// The binary itself.
    #[must_use]
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Lowercase hex sha256 of the binary: its identity on the remote (`relay-<sha256>`).
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Size in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the binary is empty (never true for a loaded relay).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Where a set of relays came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// Read from a directory (`--relay-dir`).
    Dir(std::path::PathBuf),
    /// Compiled into this binary.
    Embedded,
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dir(dir) => write!(f, "{}", dir.display()),
            Self::Embedded => f.write_str("embedded"),
        }
    }
}

/// The relays available to push, at most one per arch.
#[derive(Clone, Debug)]
pub struct Relays {
    relays: Vec<Relay>,
    source: Source,
}

impl Relays {
    /// Builds a set from relays already in hand.
    ///
    /// # Errors
    ///
    /// Fails when the set is empty or names an arch twice.
    pub fn new(relays: Vec<Relay>, source: Source) -> Res<Self> {
        if relays.is_empty() {
            bail!("no relays in {source}");
        }
        for (i, relay) in relays.iter().enumerate() {
            if relays[..i].iter().any(|r| r.arch == relay.arch) {
                bail!("two {} relays in {source}", relay.arch);
            }
        }
        Ok(Self { relays, source })
    }

    /// Reads `sshunnel-relay-<arch>` for each arch from `dir`; a missing file means no relay for
    /// that arch.
    ///
    /// # Errors
    ///
    /// Fails when a relay can't be read, or `dir` holds none.
    pub fn from_dir(dir: &Path) -> Res<Self> {
        let mut relays = Vec::with_capacity(Arch::ALL.len());
        for arch in Arch::ALL {
            let path = dir.join(arch.file_name());
            match std::fs::read(&path) {
                Ok(bytes) if bytes.is_empty() => bail!("{} is empty", path.display()),
                Ok(bytes) => relays.push(Relay::new(arch, bytes.into())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
            }
        }
        Self::new(relays, Source::Dir(dir.to_owned()))
    }

    /// The relays compiled into this binary (see `build.rs`).
    ///
    /// # Errors
    ///
    /// Fails when the build embedded none, saying how to get relays instead.
    pub fn embedded() -> Res<Self> {
        let relays = embedded::EMBEDDED
            .iter()
            .filter_map(|(name, bytes)| Arch::ALL.into_iter().find(|arch| arch.file_name() == *name).map(|arch| Relay::new(arch, Bytes::from_static(bytes))))
            .collect::<Vec<_>>();
        if relays.is_empty() {
            bail!("this sshunnel build embeds no relays: pass --relay-dir (`cargo xtask relay` builds them into target/relay)");
        }
        Self::new(relays, Source::Embedded)
    }

    /// Reads `dir` when given, else the embedded relays.
    ///
    /// # Errors
    ///
    /// Fails as [`Relays::from_dir`] or [`Relays::embedded`] does.
    pub fn load(dir: Option<&Path>) -> Res<Self> {
        dir.map_or_else(Self::embedded, Self::from_dir)
    }

    /// The relay for `arch`, if this set has one.
    #[must_use]
    pub fn get(&self, arch: Arch) -> Option<&Relay> {
        self.relays.iter().find(|r| r.arch == arch)
    }

    /// The relay whose sha256 is `sha256`.
    #[must_use]
    pub fn by_sha256(&self, sha256: &str) -> Option<&Relay> {
        self.relays.iter().find(|r| r.sha256 == sha256)
    }

    /// Every relay in the set.
    pub fn iter(&self) -> impl Iterator<Item = &Relay> {
        self.relays.iter()
    }

    /// Where the set came from.
    #[must_use]
    pub fn source(&self) -> &Source {
        &self.source
    }
}

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded.rs"));
}

// `build.rs`'s decisions, here so its tests run with the library's, and so xtask (which builds this
// crate with `testing`) shares `COMMIT_FILE` rather than spelling it again. At the top level: a
// `#[path]` inside an inline module would resolve against that module's directory.
#[cfg(any(test, feature = "testing"))]
#[path = "../build/embed.rs"]
pub mod build_embed;

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String can't fail.
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn sha256_is_lowercase_hex_of_the_bytes() {
        let relay = Relay::new(Arch::X86_64, Bytes::from_static(b"abc"));
        assert_eq!(relay.sha256(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(relay.len(), 3);
    }

    #[test]
    fn a_dir_with_one_arch_loads_just_that_one() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("sshunnel-relay-aarch64"), b"arm").unwrap();
        let relays = Relays::from_dir(dir.path()).unwrap();
        assert!(relays.get(Arch::X86_64).is_none());
        let arm = relays.get(Arch::Aarch64).unwrap();
        assert_eq!(relays.by_sha256(arm.sha256()).unwrap().arch(), Arch::Aarch64);
        assert_eq!(relays.source(), &Source::Dir(dir.path().to_owned()));
    }

    #[test]
    fn an_empty_dir_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Relays::from_dir(dir.path()).unwrap_err().to_string().contains("no relays"));
    }

    #[test]
    fn an_empty_relay_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("sshunnel-relay-x86_64"), b"").unwrap();
        assert!(Relays::from_dir(dir.path()).unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn a_build_without_embedded_relays_says_how_to_get_them() {
        // Test builds never set SSHUNNEL_EMBED_RELAY_DIR, and a checkout's `.git` makes the build
        // ignore its `relays/`, so nothing embeds.
        assert!(Relays::embedded().unwrap_err().to_string().contains("--relay-dir"));
    }

    #[test]
    fn duplicate_arches_are_rejected() {
        let one = Relay::new(Arch::X86_64, Bytes::from_static(b"1"));
        let two = Relay::new(Arch::X86_64, Bytes::from_static(b"2"));
        assert!(Relays::new(vec![one, two], Source::Embedded).is_err());
    }

    /// A manifest dir with a `relays/`, as `cargo xtask package` leaves one.
    fn manifest_with_relays() -> tempfile::TempDir {
        let manifest = tempfile::tempdir().unwrap();
        std::fs::create_dir(manifest.path().join("relays")).unwrap();
        manifest
    }

    #[test]
    fn embed_dir_prefers_the_env_dir() {
        let manifest = manifest_with_relays();
        let env = manifest.path().join("elsewhere");
        assert_eq!(build_embed::embed_dir(Some(env.clone()), manifest.path()), Ok(Some(build_embed::RelayDir::Env(env))));
    }

    #[test]
    fn embed_dir_reads_relays_in_a_package() {
        let manifest = manifest_with_relays();
        assert_eq!(build_embed::embed_dir(None, manifest.path()), Ok(Some(build_embed::RelayDir::Package(manifest.path().join("relays")))));
    }

    #[test]
    fn embed_dir_ignores_relays_in_a_checkout() {
        let checkout = manifest_with_relays();
        std::fs::create_dir(checkout.path().join(".git")).unwrap();
        assert_eq!(build_embed::embed_dir(None, checkout.path()), Ok(None));

        // A worktree's `.git` is a file pointing at the main checkout's.
        let worktree = manifest_with_relays();
        std::fs::write(worktree.path().join(".git"), "gitdir: /elsewhere/.git/worktrees/w\n").unwrap();
        assert_eq!(build_embed::embed_dir(None, worktree.path()), Ok(None));
    }

    #[test]
    fn embed_dir_is_none_without_relays() {
        // A checkout: it has no `Cargo.toml.orig`, so it isn't a package missing its relays.
        let manifest = tempfile::tempdir().unwrap();
        assert_eq!(build_embed::embed_dir(None, manifest.path()), Ok(None));
    }

    #[test]
    fn embed_dir_refuses_a_package_without_relays() {
        // Cargo writes `Cargo.toml.orig` into every .crate, so cargo's verify build of a publish lands here.
        let package = tempfile::tempdir().unwrap();
        std::fs::write(package.path().join("Cargo.toml.orig"), "[package]\n").unwrap();
        let err = build_embed::embed_dir(None, package.path()).unwrap_err();
        assert!(err.contains("cargo xtask package"), "{err}");

        // The variable still wins.
        let env = package.path().join("elsewhere");
        assert_eq!(build_embed::embed_dir(Some(env.clone()), package.path()), Ok(Some(build_embed::RelayDir::Env(env))));
    }

    #[test]
    fn an_unresolvable_env_dir_names_the_variable() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let err = build_embed::RelayDir::Env(missing.clone()).canonicalize().unwrap_err();
        assert!(err.contains(build_embed::DIR_VAR) && err.contains(missing.to_str().unwrap()), "{err}");
        let err = build_embed::RelayDir::Package(missing).canonicalize().unwrap_err();
        assert!(!err.contains(build_embed::DIR_VAR), "{err}");
    }

    /// `(name, bytes)` pairs as `build.rs` reads them, and their `SHA256SUMS` as `cargo xtask` writes it.
    fn relays_and_sums() -> (Vec<(String, Vec<u8>)>, String) {
        let relays = vec![("sshunnel-relay-x86_64".to_owned(), b"x86".to_vec()), ("sshunnel-relay-aarch64".to_owned(), b"arm".to_vec())];
        let mut sums = String::new();
        for (name, bytes) in &relays {
            writeln!(sums, "{}  {name}", hex(&Sha256::digest(bytes))).unwrap();
        }
        (relays, sums)
    }

    #[test]
    fn embedded_sums_accept_a_matching_set() {
        let (relays, sums) = relays_and_sums();
        assert_eq!(build_embed::check_sums(&sums, &relays), Ok(()));
    }

    #[test]
    fn embedded_sums_reject_a_changed_relay() {
        let (mut relays, sums) = relays_and_sums();
        relays[1].1 = b"tampered".to_vec();
        let err = build_embed::check_sums(&sums, &relays).unwrap_err();
        assert!(err.contains("sshunnel-relay-aarch64"), "{err}");
    }

    #[test]
    fn embedded_sums_reject_a_relay_without_a_line() {
        let (relays, sums) = relays_and_sums();
        let x86_only = sums.lines().find(|line| line.ends_with("x86_64")).unwrap();
        let err = build_embed::check_sums(x86_only, &relays).unwrap_err();
        assert!(err.contains("sshunnel-relay-aarch64"), "{err}");
    }

    #[test]
    fn embedded_sums_reject_a_line_without_a_relay() {
        let (mut relays, sums) = relays_and_sums();
        relays.retain(|(name, _)| name.ends_with("x86_64"));
        let err = build_embed::check_sums(&sums, &relays).unwrap_err();
        assert!(err.contains("sshunnel-relay-aarch64"), "{err}");

        // A directory whose relays are all gone still lists them.
        let err = build_embed::check_sums(&sums, &[]).unwrap_err();
        assert!(err.contains("sshunnel-relay-"), "{err}");

        // Only relay lines need a file.
        let (relays, mut sums) = relays_and_sums();
        writeln!(sums, "{}  README.md", hex(&Sha256::digest(b"readme"))).unwrap();
        assert_eq!(build_embed::check_sums(&sums, &relays), Ok(()));
    }

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    // cargo writes .cargo_vcs_info.json pretty-printed, with "dirty" only for --allow-dirty.
    fn vcs(sha: &str) -> String {
        format!("{{\n  \"git\": {{\n    \"sha1\": \"{sha}\",\n    \"dirty\": true\n  }},\n  \"path_in_vcs\": \"\"\n}}")
    }

    #[test]
    fn relay_commit_reads_the_packaged_sha() {
        assert_eq!(build_embed::vcs_sha1(&vcs(SHA)), Some(SHA));
    }

    #[test]
    fn relay_commit_matching_the_package_builds() {
        build_embed::check_commit(Some(&format!("{SHA}\n")), Some(&vcs(SHA))).unwrap();
    }

    #[test]
    fn relay_commit_from_another_sha_is_refused() {
        let other = "fedcba9876543210fedcba9876543210fedcba98";
        let err = build_embed::check_commit(Some(other), Some(&vcs(SHA))).unwrap_err();
        assert!(err.contains(other) && err.contains(SHA) && err.contains("cargo xtask package"), "{err}");
    }

    #[test]
    fn relay_commit_missing_from_a_package_with_vcs_info_is_refused() {
        assert!(build_embed::check_commit(None, Some(&vcs(SHA))).unwrap_err().contains("COMMIT"));
    }

    #[test]
    fn relay_commit_is_unchecked_without_vcs_info() {
        build_embed::check_commit(None, None).unwrap();
    }

    #[test]
    fn relay_commit_ignores_malformed_vcs_info() {
        assert_eq!(build_embed::vcs_sha1("{\"git\":{}}"), None);
        assert!(build_embed::check_commit(Some(SHA), Some("{\"git\":{}}")).is_err());
    }
}
