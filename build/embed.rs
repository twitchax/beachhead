//! What `build.rs` decides about embedding relays: which directory to read them from (or that a
//! package without relays mustn't build), and whether they match that directory's `SHA256SUMS`. A
//! file of its own so the library's tests can include it (`src/relays.rs`); std and `sha2` only,
//! since a build script has nothing else.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

use sha2::{Digest as _, Sha256};

/// Names a directory of relays to embed, overriding the crate's own `relays/`.
pub const DIR_VAR: &str = "SSHUNNEL_EMBED_RELAY_DIR";

/// Every relay's file name starts with this; the library maps the rest to an arch.
pub const RELAY_PREFIX: &str = "sshunnel-relay-";

/// The file in a package's `relays/` holding the commit they were built from (`cargo xtask
/// package` writes it).
pub const COMMIT_FILE: &str = "COMMIT";

/// Where the relays to embed come from.
#[derive(Debug, PartialEq, Eq)]
pub enum RelayDir {
    /// The directory [`DIR_VAR`] names.
    Env(PathBuf),
    /// A package's own `relays/`.
    Package(PathBuf),
}

impl RelayDir {
    /// The directory, resolved.
    ///
    /// # Errors
    ///
    /// Names the directory when it can't be resolved, and the variable when it came from there.
    pub fn canonicalize(&self) -> Result<PathBuf, String> {
        match self {
            Self::Env(dir) => dir.canonicalize().map_err(|e| format!("{DIR_VAR}={}: {e}", dir.display())),
            Self::Package(dir) => dir.canonicalize().map_err(|e| format!("{}: {e}", dir.display())),
        }
    }
}

/// The directory to embed relays from: `env_dir` ([`DIR_VAR`]) when set; else the crate's own
/// `relays/`, but only in a package, which has no `.git` (a checkout's directory or a worktree's
/// file) beside its manifest; else none. A checkout's `relays/` is whatever the last `cargo xtask
/// package` left, which goes stale with the next relay change.
///
/// # Errors
///
/// Refuses a package with no `relays/` and no `env_dir`: it would build a client with no relays,
/// and cargo's verify build is all that stands between that and a publish. A package is told by the
/// `Cargo.toml.orig` cargo writes into every .crate (a checkout never has one).
pub fn embed_dir(env_dir: Option<PathBuf>, manifest_dir: &Path) -> Result<Option<RelayDir>, String> {
    if let Some(dir) = env_dir {
        return Ok(Some(RelayDir::Env(dir)));
    }
    let relays = manifest_dir.join("relays");
    if !relays.is_dir() && manifest_dir.join("Cargo.toml.orig").exists() {
        // No hint at the variable: set during a publish, it would pass the verify build and upload
        // the package without relays all the same.
        return Err("this sshunnel package has no relays/, so it would build a client without relays: run `cargo xtask package` before publishing".to_owned());
    }
    Ok((relays.is_dir() && !manifest_dir.join(".git").exists()).then_some(RelayDir::Package(relays)))
}

/// Checks each `(file name, bytes)` relay against `sums`, a `SHA256SUMS` of `<hex>  <name>` lines,
/// and that every relay line names one of them.
///
/// # Errors
///
/// Names the first relay with no line, or whose bytes hash to something else, then the first relay
/// line with no relay.
pub fn check_sums(sums: &str, relays: &[(String, Vec<u8>)]) -> Result<(), String> {
    let lines = || sums.lines().filter_map(|line| line.split_once("  "));
    for (name, bytes) in relays {
        let Some((listed, _)) = lines().find(|(_, file)| file == name) else {
            return Err(format!("SHA256SUMS has no line for {name}"));
        };
        let actual = hex(&Sha256::digest(bytes));
        if !listed.eq_ignore_ascii_case(&actual) {
            return Err(format!("{name} hashes to {actual}, but SHA256SUMS says {listed}"));
        }
    }
    if let Some((_, file)) = lines().find(|(_, file)| file.starts_with(RELAY_PREFIX) && !relays.iter().any(|(name, _)| name == file)) {
        return Err(format!("SHA256SUMS lists {file}, but there is no such relay"));
    }
    Ok(())
}

/// The commit cargo packaged, from the `git.sha1` of the `.cargo_vcs_info.json` it writes into every
/// .crate; none unless it is 40 hex digits. Not a JSON parse: a build script has no parser, and
/// the one key is unambiguous in a file cargo generates.
#[must_use]
pub fn vcs_sha1(vcs_info: &str) -> Option<&str> {
    let after = &vcs_info[vcs_info.find("\"sha1\"")? + "\"sha1\"".len()..];
    let value = after.trim_start().strip_prefix(':')?.trim_start().strip_prefix('"')?;
    let sha = &value[..value.find('"')?];
    (sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit())).then_some(sha)
}

/// Checks a package's `relays/COMMIT` (`commit`) against the commit cargo packaged (`vcs_info`, the
/// text of `.cargo_vcs_info.json`). A checkout, or a package cut without git, has no `vcs_info` and
/// nothing to compare with.
///
/// # Errors
///
/// Refuses a `vcs_info` with no readable sha, a missing `commit`, and a `commit` that isn't the
/// packaged sha: relays built at another commit would ship with source they weren't built from.
pub fn check_commit(commit: Option<&str>, vcs_info: Option<&str>) -> Result<(), String> {
    let Some(vcs_info) = vcs_info else {
        return Ok(());
    };
    let sha = vcs_sha1(vcs_info).ok_or("this package's .cargo_vcs_info.json has no git sha1, so its relays can't be checked against it")?;
    let commit = commit.ok_or_else(|| format!("this package has no relays/{COMMIT_FILE}, so its relays can't be checked against its commit: run `cargo xtask package` before publishing"))?;
    let commit = commit.trim();
    if commit != sha {
        return Err(format!(
            "the relays in this package were built from {commit}, but the package is from {sha}: run `cargo xtask package` before publishing"
        ));
    }
    Ok(())
}

/// Lowercase hex, as `Relay::sha256` and `sha256sum` print it.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
        // Writing to a String can't fail.
        let _ = write!(out, "{b:02x}");
        out
    })
}
