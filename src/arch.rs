//! The remote architectures sshunnel ships a relay for: the one table the bootstrap script, the
//! relay loader and `cargo xtask relay` all read.

/// A remote CPU architecture with a static musl relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// Every supported arch, in the order tools list them.
    pub const ALL: [Self; 2] = [Self::X86_64, Self::Aarch64];

    /// The short name used in file names and output.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }

    /// The Rust target the relay is built for.
    #[must_use]
    pub fn triple(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64-unknown-linux-musl",
            Self::Aarch64 => "aarch64-unknown-linux-musl",
        }
    }

    /// What `uname -m` prints on such a machine.
    #[must_use]
    pub fn unames(self) -> &'static [&'static str] {
        match self {
            Self::X86_64 => &["x86_64", "amd64"],
            Self::Aarch64 => &["aarch64", "arm64"],
        }
    }

    /// The relay's file name in a relay directory (`--relay-dir`, `target/relay`).
    #[must_use]
    pub fn file_name(self) -> &'static str {
        match self {
            Self::X86_64 => "sshunnel-relay-x86_64",
            Self::Aarch64 => "sshunnel-relay-aarch64",
        }
    }

    /// The arch whose [`Arch::name`] is `name`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|arch| arch.name() == name)
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn names_round_trip_and_file_names_carry_them() {
        for arch in Arch::ALL {
            assert_eq!(Arch::from_name(arch.name()), Some(arch));
            assert!(arch.file_name().ends_with(arch.name()));
            assert!(arch.triple().starts_with(arch.name()));
            assert!(arch.unames().contains(&arch.name()));
        }
        assert_eq!(Arch::from_name("riscv64"), None);
    }
}
