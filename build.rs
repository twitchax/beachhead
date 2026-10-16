//! Embeds prebuilt relays into the client when `BEACHHEAD_EMBED_RELAY_DIR` names a directory of
//! them (`cargo xtask relay` writes one to `target/relay`). Without it the build embeds none, and
//! the client needs `--relay-dir`. The generated `embedded.rs` lists every `beachhead-relay-*` file
//! by name; the library maps names to arches, so this script needs no copy of that table.

use std::{env, error::Error, fmt::Write as _, fs, path::PathBuf};

const DIR_VAR: &str = "BEACHHEAD_EMBED_RELAY_DIR";

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-env-changed={DIR_VAR}");
    println!("cargo::rerun-if-changed=build.rs");
    let out = PathBuf::from(env::var_os("OUT_DIR").ok_or("cargo sets OUT_DIR for build scripts")?);

    let mut entries = String::new();
    if let Some(dir) = env::var_os(DIR_VAR) {
        let dir = PathBuf::from(dir).canonicalize().map_err(|e| format!("{DIR_VAR}: {e}"))?;
        println!("cargo::rerun-if-changed={}", dir.display());
        let mut names: Vec<String> = fs::read_dir(&dir)?
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .filter(|name| name.starts_with("beachhead-relay-"))
            .collect();
        names.sort();
        for name in names {
            let path = dir.join(&name);
            println!("cargo::rerun-if-changed={}", path.display());
            // Debug of a str is a valid Rust string literal, escapes included.
            let path = path.to_str().ok_or_else(|| format!("{} is not UTF-8", path.display()))?;
            writeln!(entries, "    ({name:?}, include_bytes!({path:?})),")?;
        }
    }
    fs::write(out.join("embedded.rs"), format!("pub(crate) const EMBEDDED: &[(&str, &[u8])] = &[\n{entries}];\n"))?;
    Ok(())
}
