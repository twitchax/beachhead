//! The command line itself: help screens and completions. Tests here spawn the real binary, so
//! they are named `e2e_*`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::{Command, Output};

/// The binary with the env vars it reads cleared, so the host environment can't leak in.
fn sshunnel() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sshunnel"));
    cmd.env_remove("SSHUNNEL_RELAY_DIR").env_remove("SSHUNNEL_SSH").env_remove("RUST_LOG");
    cmd
}

fn run(args: &[&str]) -> Output {
    sshunnel().args(args).output().unwrap()
}

#[test]
fn e2e_completions_cover_route_and_forward_not_helper() {
    for shell in ["bash", "zsh", "fish"] {
        let out = run(&["completions", shell]);
        assert!(out.status.success(), "{shell}: {}", String::from_utf8_lossy(&out.stderr));
        let script = String::from_utf8(out.stdout).unwrap();
        for name in ["forward", "relays"] {
            assert!(script.contains(name), "{shell} completes {name}");
        }
        if cfg!(target_os = "linux") {
            assert!(script.contains("route"), "{shell} completes route");
        }
        assert!(!script.contains("helper"), "{shell} must not complete the hidden helper");
    }
}

#[test]
fn e2e_help_bare_sshunnel_prints_the_summary() {
    let out = run(&[]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Usage: sshunnel <COMMAND>"), "{stderr}");
    assert!(stderr.contains("Commands:"), "{stderr}");
}
