//! Embeds prebuilt relays into the client, from the first of: the directory
//! `SSHUNNEL_EMBED_RELAY_DIR` names (`cargo xtask dist` sets it to `target/relay`); the crate's own
//! `relays/`, only when building from a package (`cargo xtask package` writes it, and a package
//! has no `.git` beside its manifest); else none, and the client needs `--relay-dir`. A checkout
//! never embeds its `relays/`, which goes stale with the next relay change, and a package without
//! one fails to build, so cargo won't publish it. Every relay must match its directory's
//! `SHA256SUMS`, and every relay listed there must be present, or the build fails. The generated
//! `embedded.rs` lists every `sshunnel-relay-*` file by name; the library maps names to arches, so
//! this script needs no copy of that table.

#[path = "build/embed.rs"]
mod embed;

use std::{env, error::Error, fmt::Write as _, fs, path::PathBuf};

use embed::DIR_VAR;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-env-changed={DIR_VAR}");
    println!("cargo::rerun-if-changed=build.rs");
    let out = PathBuf::from(env::var_os("OUT_DIR").ok_or("cargo sets OUT_DIR for build scripts")?);
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("cargo sets CARGO_MANIFEST_DIR for build scripts")?);

    let mut entries = String::new();
    if let Some(dir) = embed::embed_dir(env::var_os(DIR_VAR).map(PathBuf::from), &manifest_dir)? {
        // Only paths that exist get a rerun-if-changed: cargo treats a missing one as always stale.
        let dir = dir.canonicalize()?;
        println!("cargo::rerun-if-changed={}", dir.display());
        let mut names: Vec<String> = fs::read_dir(&dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .filter(|name| name.starts_with(embed::RELAY_PREFIX))
            .collect();
        names.sort();

        let mut relays = Vec::with_capacity(names.len());
        for name in names {
            let path = dir.join(&name);
            println!("cargo::rerun-if-changed={}", path.display());
            let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            relays.push((name, bytes));
        }
        // Even with no relays: a SHA256SUMS that lists some means they went missing.
        let sums = dir.join("SHA256SUMS");
        if !relays.is_empty() || sums.exists() {
            let listed = fs::read_to_string(&sums).map_err(|e| format!("{}: {e}", sums.display()))?;
            println!("cargo::rerun-if-changed={}", sums.display());
            embed::check_sums(&listed, &relays).map_err(|e| format!("{}: {e}", dir.display()))?;
        }

        for (name, _) in &relays {
            let path = dir.join(name);
            // Debug of a str is a valid Rust string literal, escapes included.
            let path = path.to_str().ok_or_else(|| format!("{} is not UTF-8", path.display()))?;
            writeln!(entries, "    ({name:?}, include_bytes!({path:?})),")?;
        }
    }
    fs::write(out.join("embedded.rs"), format!("pub(crate) const EMBEDDED: &[(&str, &[u8])] = &[\n{entries}];\n"))?;
    Ok(())
}
