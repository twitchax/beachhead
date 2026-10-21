//! Single-source guards. The toolchain is pinned in exactly one place, `rust-toolchain.toml`; these
//! tests fail when a workflow or Dockerfile grows its own pin. A "keep in sync" comment is not
//! enough: conclave's and razel's rotted (ironpad's fix, generalized).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(".")
}

/// A missing file reads as empty: not every variant has a Dockerfile or release workflow.
fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel)).unwrap_or_default()
}

const PINNABLE: [&str; 3] = [".github/workflows/build.yml", ".github/workflows/release.yml", "Dockerfile"];

#[test]
fn toolchain_is_pinned_only_in_rust_toolchain_toml() {
    let toml = read("rust-toolchain.toml");
    let channel = toml
        .lines()
        .find_map(|line| line.trim().strip_prefix("channel = "))
        .expect("rust-toolchain.toml sets a channel")
        .trim_matches('"');

    for file in PINNABLE {
        let text = read(file);
        assert!(!text.contains(channel), "{file} repeats the toolchain pin `{channel}`; read rust-toolchain.toml instead");
        assert!(!text.contains("nightly-20"), "{file} pins a dated nightly; only rust-toolchain.toml may");
    }
}

/// Refs whose `action.yml` says `runs.using: node20` (GitHub forces Node 24 and annotates every run
/// that uses one). Checked against each ref's `action.yml`; upload-artifact moved at v6 and
/// download-artifact at v7.
const NODE20_ACTIONS: [&str; 4] = [
    "actions/upload-artifact@v4",
    "actions/upload-artifact@v5",
    "actions/download-artifact@v4",
    "actions/download-artifact@v6",
];

#[test]
fn workflows_use_no_node20_actions() {
    for file in &PINNABLE[..2] {
        let text = read(file);
        for action in NODE20_ACTIONS {
            assert!(!text.contains(action), "{file} uses {action}, which runs on Node 20; move to a ref whose action.yml says node24");
        }
    }
}

#[test]
fn fixtures_are_behind_the_testing_feature() {
    let lib: Vec<String> = read("src/lib.rs").lines().map(str::to_owned).collect();
    let at = lib.iter().position(|line| line.trim() == "pub mod tests;").expect("src/lib.rs declares `pub mod tests;`");
    assert!(
        at > 0 && lib[at - 1] == "#[cfg(feature = \"testing\")]",
        "`pub mod tests;` must sit directly under #[cfg(feature = \"testing\")]"
    );

    let manifest = read("Cargo.toml");
    let features = manifest.split("[features]").nth(1).expect("Cargo.toml has a [features] table");
    let default = features
        .lines()
        .take_while(|line| !line.starts_with('['))
        .find(|line| line.starts_with("default"))
        .expect("[features] sets default");
    assert!(!default.contains("testing"), "`testing` must stay out of the default features: {default}");
}

#[test]
fn dockerfile_cooks_dependencies_on_the_pinned_toolchain() {
    let dockerfile = read("Dockerfile");
    if dockerfile.is_empty() {
        return;
    }
    let copy = dockerfile.find("COPY rust-toolchain.toml").expect("Dockerfile copies rust-toolchain.toml");
    let cook = dockerfile.find("cargo chef cook").expect("Dockerfile cooks dependencies with cargo-chef");
    assert!(copy < cook, "copy rust-toolchain.toml before `cargo chef cook`, or the dependency layer builds on the wrong toolchain");
}
