//! Repo tooling, run as `cargo xtask <task>` (the alias lives in `.cargo/config.toml`). Tasks are
//! Rust rather than shell or Python, so they get the same lints and tests as the product.

use anyhow::{Result, bail};

fn main() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("hello") => {
            println!("xtask is wired up; add real tasks to xtask/src/main.rs");
            Ok(())
        }
        None | Some("help") => {
            println!("usage: cargo xtask <task>\n\ntasks:\n  hello    check the wiring");
            Ok(())
        }
        Some(other) => bail!("unknown task `{other}`; run `cargo xtask help`"),
    }
}
