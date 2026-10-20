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
        // Test builds never set SSHUNNEL_EMBED_RELAY_DIR.
        assert!(Relays::embedded().unwrap_err().to_string().contains("--relay-dir"));
    }

    #[test]
    fn duplicate_arches_are_rejected() {
        let one = Relay::new(Arch::X86_64, Bytes::from_static(b"1"));
        let two = Relay::new(Arch::X86_64, Bytes::from_static(b"2"));
        assert!(Relays::new(vec![one, two], Source::Embedded).is_err());
    }
}
