//! End to end: spawn the real binary as a user would, inside a scratch directory. Tests here are
//! named `e2e_*`, which nextest serializes and retries (see `.config/nextest.toml`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::{Command, Output};

use pretty_assertions::assert_eq;
use tempfile::TempDir;

/// Runs the binary in a fresh temp dir, with the env var it reads cleared unless the test sets it.
fn run(args: &[&str], env: Option<&str>) -> Output {
    let dir = TempDir::new().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_beachhead"));
    cmd.current_dir(dir.path()).args(args).env_remove("BEACHHEAD_NAME");
    if let Some(name) = env {
        cmd.env("BEACHHEAD_NAME", name);
    }
    cmd.output().unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

#[test]
fn e2e_greets_from_a_flag() {
    let out = run(&["--name", "Ferris"], None);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(stdout(&out), "Hello, Ferris!");
}

#[test]
fn e2e_reads_the_name_from_the_environment() {
    let out = run(&[], Some("env"));
    assert_eq!(stdout(&out), "Hello, env!");
}

#[test]
fn e2e_fails_cleanly_on_an_empty_name() {
    let out = run(&["--name", " "], None);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("empty name"));
}
