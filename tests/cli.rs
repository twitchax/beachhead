//! The command line itself: help screens, completions, and the README's copies of the help. Tests
//! that spawn the real binary are named `e2e_*`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    path::Path,
    process::{Command, Output},
};

use pretty_assertions::assert_eq;

/// The binary with the env vars it reads cleared, so the host environment can't leak in.
/// `NO_COLOR` outranks `CLICOLOR_FORCE` and `CLICOLOR` in clap's color choice, so the help stays
/// plain text whatever the host sets.
fn sshunnel() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sshunnel"));
    cmd.env_remove("SSHUNNEL_RELAY_DIR").env_remove("SSHUNNEL_SSH").env_remove("RUST_LOG").env("NO_COLOR", "1");
    cmd
}

fn run(args: &[&str]) -> Output {
    sshunnel().args(args).output().unwrap()
}

/// The stdout of a run that must succeed.
fn stdout(args: &[&str]) -> String {
    let out = run(args);
    assert!(out.status.success(), "sshunnel {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

/// The visible subcommands this target builds: `route` and `sudoers` are Linux only.
fn subcommands() -> Vec<&'static str> {
    let mut commands = vec!["forward", "relays", "completions"];
    if cfg!(target_os = "linux") {
        commands.extend(["route", "sudoers"]);
    }
    commands
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

#[test]
fn e2e_help_long_is_the_guide() {
    let guide = stdout(&["help"]);
    assert_eq!(guide, stdout(&["--help"]));
    for part in [
        "Examples:",
        "Before route:",
        "From a script or an agent:",
        "Files and environment:",
        "route --check",
        "sshunnel sudoers",
        "sshunnel: ready",
    ] {
        assert!(guide.contains(part), "the guide lacks {part:?}:\n{guide}");
    }
}

#[test]
fn e2e_help_short_points_at_the_guide() {
    let short = stdout(&["-h"]);
    assert!(!short.contains("Examples:"), "{short}");
    assert!(short.contains("Run `sshunnel help` for the guide"), "{short}");
}

#[cfg(target_os = "linux")]
#[test]
fn e2e_help_route_covers_targets_privileges_and_troubleshooting() {
    let help = stdout(&["help", "route"]);
    assert_eq!(help, stdout(&["route", "--help"]));
    for part in ["Targets:", "Privileges:", "Troubleshooting:"] {
        assert!(help.contains(part), "route's help lacks {part:?}:\n{help}");
    }
}

/// A script gates route on `--check`'s exit status, so the help states it beside the sample.
#[cfg(target_os = "linux")]
#[test]
fn e2e_help_route_states_the_check_exit_status() {
    let help = stdout(&["help", "route"]);
    let after_sample = help.lines().skip_while(|line| *line != "    sshunnel: route can start").nth(1);
    assert_eq!(
        after_sample,
        Some("  --check exits 1 if a check fails, 0 otherwise. A sudo warn means route will ask for a password."),
        "{help}"
    );
}

#[test]
fn e2e_help_shows_the_ready_line_the_code_prints() {
    let ready = sshunnel::session::ready_line(4242);
    let commands: &[&str] = if cfg!(target_os = "linux") { &["route", "forward"] } else { &["forward"] };
    for command in commands {
        let help = stdout(&["help", command]);
        assert!(help.contains(&ready), "{command}'s help lacks {ready:?}:\n{help}");
    }
}

/// Nothing rewraps the help (no `wrap_help`), so every line has to fit as written.
#[test]
fn e2e_help_screens_fit_100_columns() {
    let commands = std::iter::once(None).chain(subcommands().into_iter().map(Some));
    for command in commands {
        for flag in ["-h", "--help"] {
            let args: Vec<&str> = command.into_iter().chain([flag]).collect();
            for line in stdout(&args).lines() {
                assert!(line.is_ascii() && line.len() <= 100, "`sshunnel {}` prints {} bytes: {line:?}", args.join(" "), line.len());
            }
        }
    }
}

/// The README's copies come from this helper, so a host forcing color mustn't put escapes in them.
#[test]
fn e2e_help_stays_plain_when_color_is_forced() {
    let out = sshunnel().arg("--help").env("CLICOLOR_FORCE", "1").output().unwrap();
    assert!(out.status.success());
    assert!(!out.stdout.contains(&0x1b), "{}", String::from_utf8_lossy(&out.stdout));
}

/// Troubleshooting quotes error messages, so each quote has to be one the code can print.
#[test]
fn help_troubleshooting_quotes_messages_the_code_prints() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let help = std::fs::read_to_string(src.join("help/route.txt")).unwrap();
    let (_, troubleshooting) = help.split_once("Troubleshooting:\n").expect("route's help has a Troubleshooting section");
    let quoted: Vec<&str> = troubleshooting
        .lines()
        .take_while(|line| line.is_empty() || line.starts_with(' '))
        .filter(|line| line.starts_with("  \""))
        .flat_map(|line| line.split('"').skip(1).step_by(2))
        .collect();
    assert!(!quoted.is_empty(), "Troubleshooting quotes no messages");

    let mut sources = Vec::new();
    rust_sources(&src, &src.join("help"), &mut sources);
    for message in quoted {
        assert!(sources.iter().any(|source| source.contains(message)), "no file under src/ prints {message:?}");
    }
}

/// Every `.rs` file under `dir`, read, except those under `skip`.
fn rust_sources(dir: &Path, skip: &Path, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.starts_with(skip) {
            continue;
        }
        if path.is_dir() {
            rust_sources(&path, skip, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(std::fs::read_to_string(&path).unwrap());
        }
    }
}

/// The first lines of the help blocks the README embeds.
#[cfg(target_os = "linux")]
const README_HELP: [&str; 5] = [
    "$ sshunnel --help",
    "$ sshunnel forward --help",
    "$ sshunnel route --help",
    "$ sshunnel sudoers --help",
    "$ sshunnel completions --help",
];

/// The help arguments of a README block's first line, `$ sshunnel <args>`: `--help` or `-h`
/// anywhere, or `help` first. Any other block is an example, not a copy of the help.
#[cfg(target_os = "linux")]
fn help_args(first: &str) -> Option<Vec<&str>> {
    let args: Vec<&str> = first.strip_prefix("$ sshunnel ")?.split_whitespace().collect();
    (args.iter().any(|arg| *arg == "--help" || *arg == "-h") || args.first() == Some(&"help")).then_some(args)
}

/// The README shows the help as the binary prints it, byte for byte, in every block of
/// [`README_HELP`]. `UPDATE_README=1` rewrites those blocks from the binary instead of comparing
/// them.
#[cfg(target_os = "linux")]
#[test]
fn e2e_readme_help_blocks_are_the_binarys_output() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md");
    let readme = std::fs::read_to_string(&path).unwrap();
    let update = std::env::var("UPDATE_README").is_ok_and(|value| value == "1");

    let mut lines = readme.lines();
    let mut rewritten = String::with_capacity(readme.len());
    let mut found = Vec::with_capacity(README_HELP.len());
    while let Some(line) = lines.next() {
        rewritten.extend([line, "\n"]);
        if line != "```text" {
            continue;
        }
        let Some(first) = lines.next() else { break };
        rewritten.extend([first, "\n"]);
        let Some(args) = help_args(first) else { continue };

        let shown: String = lines.by_ref().take_while(|line| *line != "```").flat_map(|line| [line, "\n"]).collect();
        let printed = stdout(&args);
        assert!(printed.ends_with('\n'), "`{first}` prints no final newline, so no README block can show it");
        if !update {
            assert_eq!(shown, printed, "README's `{first}` block differs from the binary's output (UPDATE_README=1 rewrites it)");
        }
        rewritten.extend([printed.as_str(), "```\n"]);
        found.push(first);
    }
    for want in README_HELP {
        assert!(found.contains(&want), "README has no ```text block that opens with `{want}`");
    }

    if update && rewritten != readme {
        std::fs::write(&path, rewritten).unwrap();
    }
}
