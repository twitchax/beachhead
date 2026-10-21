//! What `build.rs` decides about embedding relays: which directory to read them from, and whether
//! they match that directory's `SHA256SUMS`. A file of its own so the library's tests can include it
//! (`src/relays.rs`); std and `sha2` only, since a build script has nothing else.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

use sha2::{Digest as _, Sha256};

/// The directory to embed relays from: `env_dir` (`SSHUNNEL_EMBED_RELAY_DIR`) when set; else the
/// crate's own `relays/`, but only in a package, which has no `.git` (a checkout's directory or a
/// worktree's file) beside its manifest; else none. A checkout's `relays/` is whatever the last
/// `cargo xtask package` left, which goes stale with the next relay change.
pub fn embed_dir(env_dir: Option<PathBuf>, manifest_dir: &Path) -> Option<PathBuf> {
    env_dir.or_else(|| {
        let relays = manifest_dir.join("relays");
        (relays.is_dir() && !manifest_dir.join(".git").exists()).then_some(relays)
    })
}

/// Checks each `(file name, bytes)` relay against `sums`, a `SHA256SUMS` of `<hex>  <name>` lines.
///
/// # Errors
///
/// Names the first relay with no line, or whose bytes hash to something else.
pub fn check_sums(sums: &str, relays: &[(String, Vec<u8>)]) -> Result<(), String> {
    for (name, bytes) in relays {
        let listed = sums.lines().find_map(|line| line.split_once("  ").filter(|(_, file)| file == name).map(|(hash, _)| hash));
        let Some(listed) = listed else {
            return Err(format!("SHA256SUMS has no line for {name}"));
        };
        let actual = hex(&Sha256::digest(bytes));
        if !listed.eq_ignore_ascii_case(&actual) {
            return Err(format!("{name} hashes to {actual}, but SHA256SUMS says {listed}"));
        }
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
