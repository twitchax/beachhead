//! `sshunnel route --check`: whether `route` can start, changing nothing. It runs every check
//! `route` makes before it changes anything (`preflight`), then the ones `route` only meets on the
//! way: whether [`DEVICE`] is free, whether sudo starts the root helper without asking (the
//! [`helper::probe_sudo`] probe, which hangs up before the helper changes anything), ssh and the
//! relay, and whether the relay may ping. Every check runs whatever the others found, and each
//! finding is written as soon as it is known, so the local ones show before ssh, which may take
//! minutes to give up on a host that never answers.

use std::{
    fmt::{self, Display},
    io::Write,
    path::Path,
};

use anyhow::{Context as _, bail};
use sshunnel_mux::frame::Capabilities;

use crate::{
    base::{Res, Void},
    relays::Relays,
    route::{
        DEVICE, PING_WARNING,
        helper::{self, Signals, Sudo},
        lifecycle::{Options, preflight, routed},
        targets::Targets,
    },
    session::{Session, SshCommand},
};

/// How a check went: only [`Status::Fail`] stops `route` from starting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

impl Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        })
    }
}

/// What one check found, displayed as one line: `sudo     warn: sudo asks for a password; ...`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub check: &'static str,
    pub status: Status,
    pub detail: String,
}

impl Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { check, status, detail } = self;
        write!(f, "{check:<8} {status}: {detail}")
    }
}

/// Every finding, in the order the checks ran.
#[derive(Debug)]
pub struct Report {
    findings: Vec<Finding>,
}

impl Report {
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// The failures: each one would stop `route` from starting.
    #[must_use]
    pub fn problems(&self) -> usize {
        self.findings.iter().filter(|finding| finding.status == Status::Fail).count()
    }

    /// Writes `found` to `out` a line each, flushed so a caller sees it before the next check runs.
    fn add(&mut self, out: &mut impl Write, found: impl IntoIterator<Item = Finding>) -> Void {
        for finding in found {
            writeln!(out, "{finding}").context("writing the report")?;
            self.findings.push(finding);
        }
        out.flush().context("writing the report")
    }
}

/// Checks whether `route` could start with these arguments, writing each finding to `out` as it
/// comes, and changes nothing on this machine. Only the relay's cache on the remote changes, as on
/// any run.
///
/// # Errors
///
/// Fails when a signal (SIGINT, SIGTERM, or SIGHUP unless ignored at startup) stops it, or `out`
/// can't be written. A check that fails is a [`Status::Fail`] finding, not an error.
pub async fn run(options: &Options, ssh: &SshCommand, destination: &str, relays: &Relays, out: &mut impl Write) -> Res<Report> {
    run_with(options, ssh, destination, relays, helper::probe_sudo(), out).await
}

/// [`run`] with the sudo probe chosen by the caller.
pub(crate) async fn run_with(options: &Options, ssh: &SshCommand, destination: &str, relays: &Relays, sudo: impl Future<Output = Res<Sudo>>, out: &mut impl Write) -> Res<Report> {
    // First, so a Ctrl-C at any point drops the checks, the probe's socket dir and ssh with them.
    let mut signals = Signals::respecting_nohup()?;
    tokio::select! {
        biased;
        () = signals.recv() => bail!("stopped by a signal"),
        report = checks(options, ssh, destination, relays, sudo, out) => report,
    }
}

/// The checks in order: the local ones first, then ssh.
async fn checks(options: &Options, ssh: &SshCommand, destination: &str, relays: &Relays, sudo: impl Future<Output = Res<Sudo>>, out: &mut impl Write) -> Res<Report> {
    let mut report = Report { findings: Vec::new() };
    let checked = preflight(options).map(|(targets, warnings, _)| (targets, warnings));
    report.add(out, targets_findings(checked))?;
    report.add(out, [device_finding(Path::new("/sys/class/net").join(DEVICE).exists())])?;
    report.add(out, [sudo_finding(sudo.await)])?;
    // The session is done with once it has answered: dropping it stops ssh.
    let connected = Session::connect(ssh, destination, relays).await.map(|session| (session.describe(), session.mux().capabilities()));
    report.add(out, session_findings(connected))?;
    Ok(report)
}

/// `targets`: what would be routed, or each of [`preflight`]'s warnings, or its refusal.
fn targets_findings(preflight: Res<(Targets, Vec<String>)>) -> Vec<Finding> {
    match preflight {
        Ok((targets, warnings)) if warnings.is_empty() => vec![finding("targets", Status::Ok, routed(&targets))],
        Ok((_, warnings)) => warnings.into_iter().map(|warning| finding("targets", Status::Warn, warning)).collect(),
        Err(e) => vec![finding("targets", Status::Fail, format!("{e:#}"))],
    }
}

/// `device`: one `route` runs at a time, since [`DEVICE`] has one name.
fn device_finding(exists: bool) -> Finding {
    if exists {
        finding("device", Status::Fail, format!("{DEVICE} already exists: another route is running, and one runs at a time"))
    } else {
        finding("device", Status::Ok, format!("no {DEVICE} yet"))
    }
}

/// `sudo`: a prompt only means `route` asks for a password, so it warns.
fn sudo_finding(sudo: Res<Sudo>) -> Finding {
    match sudo {
        Ok(Sudo::AlreadyRoot) => finding("sudo", Status::Ok, "running as root, so route needs no sudo"),
        Ok(Sudo::NoPrompt) => finding("sudo", Status::Ok, "sudo starts the helper without a password"),
        Ok(Sudo::Prompts) => finding("sudo", Status::Warn, "sudo asks for a password; `sshunnel sudoers` prints the setup that skips it"),
        Err(e) => finding("sudo", Status::Fail, format!("{e:#}")),
    }
}

/// `ssh`: the relay that started, as `route` describes it; then `ping`, from what the relay may do.
/// No session, no `ping`.
fn session_findings(connected: Res<(String, Capabilities)>) -> Vec<Finding> {
    let (described, can) = match connected {
        Ok(connected) => connected,
        Err(e) => return vec![finding("ssh", Status::Fail, format!("{e:#}"))],
    };
    let ping = match (can.ping4, can.ping6) {
        (true, true) => finding("ping", Status::Ok, "the remote allows unprivileged ping over IPv4 and IPv6"),
        (true, false) => finding("ping", Status::Ok, "the remote allows unprivileged ping over IPv4 only"),
        (false, true) => finding("ping", Status::Ok, "the remote allows unprivileged ping over IPv6 only"),
        (false, false) => finding("ping", Status::Warn, PING_WARNING),
    };
    vec![finding("ssh", Status::Ok, described), ping]
}

fn finding(check: &'static str, status: Status, detail: impl Into<String>) -> Finding {
    Finding { check, status, detail: detail.into() }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::{path::Path, time::Duration};

    use anyhow::anyhow;
    use bytes::Bytes;
    use pretty_assertions::assert_eq;
    use rustix::process::{Signal, getpid, kill_process};
    use tempfile::TempDir;
    use tokio::time::timeout;

    use super::*;
    use crate::{
        relays::{Relay, Source},
        tests::{host_arch, shim_dir},
    };

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn targets(include: &[&str], exclude: &[&str]) -> Targets {
        Targets::parse(&strings(include), &strings(exclude)).unwrap()
    }

    /// The one finding `found` holds.
    fn only(found: Vec<Finding>) -> Finding {
        assert_eq!(found.len(), 1, "{found:#?}");
        found.into_iter().next().unwrap()
    }

    const DESCRIBED: &str = "relay x86_64 61bf6514b25c cached in /home/me/.cache/sshunnel";

    fn pinging(ping4: bool, ping6: bool) -> Vec<Finding> {
        session_findings(Ok((DESCRIBED.to_owned(), Capabilities { ping4, ping6 })))
    }

    #[test]
    fn route_check_targets_ok() {
        let checked = Ok((targets(&["10.99.0.0/16", "*.corp.example"], &["10.99.7.0/24", "wiki.corp.example"]), Vec::new()));

        assert_eq!(
            only(targets_findings(checked)),
            finding("targets", Status::Ok, "10.99.0.0/16, *.corp.example (except 10.99.7.0/24, wiki.corp.example)")
        );
    }

    #[test]
    fn route_check_targets_that_warn_warn() {
        let warnings = strings(&[
            "'10.0.0.0/8' contains the connected subnet 10.1.0.0/16, which stays local",
            "'2001::/16' contains the fake range 2001:2::/96, which stays sshunnel's",
        ]);

        let found = targets_findings(Ok((targets(&["10.0.0.0/8", "2001::/16"], &[]), warnings.clone())));

        assert_eq!(found, warnings.iter().map(|warning| finding("targets", Status::Warn, warning.as_str())).collect::<Vec<_>>());
    }

    #[test]
    fn route_check_targets_refused_fail() {
        let refused = Err(anyhow!("'10.99.7.0/24' is inside the connected subnet 10.99.0.0/16").context("refused"));

        assert_eq!(
            only(targets_findings(refused)),
            finding("targets", Status::Fail, "refused: '10.99.7.0/24' is inside the connected subnet 10.99.0.0/16")
        );
    }

    #[test]
    fn route_check_device_free_ok() {
        assert_eq!(device_finding(false), finding("device", Status::Ok, "no sshunnel0 yet"));
    }

    #[test]
    fn route_check_device_taken_fails() {
        assert_eq!(
            device_finding(true),
            finding("device", Status::Fail, "sshunnel0 already exists: another route is running, and one runs at a time")
        );
    }

    #[test]
    fn route_check_sudo_as_root_ok() {
        assert_eq!(sudo_finding(Ok(Sudo::AlreadyRoot)), finding("sudo", Status::Ok, "running as root, so route needs no sudo"));
    }

    #[test]
    fn route_check_sudo_without_a_password_ok() {
        assert_eq!(sudo_finding(Ok(Sudo::NoPrompt)), finding("sudo", Status::Ok, "sudo starts the helper without a password"));
    }

    #[test]
    fn route_check_sudo_that_prompts_warns() {
        assert_eq!(
            sudo_finding(Ok(Sudo::Prompts)),
            finding("sudo", Status::Warn, "sudo asks for a password; `sshunnel sudoers` prints the setup that skips it")
        );
    }

    #[test]
    fn route_check_sudo_that_fails_fails() {
        let missing = Err(anyhow!("No such file or directory (os error 2)").context("starting sudo"));

        assert_eq!(sudo_finding(missing), finding("sudo", Status::Fail, "starting sudo: No such file or directory (os error 2)"));
    }

    #[test]
    fn route_check_ssh_ok() {
        assert_eq!(pinging(true, true)[0], finding("ssh", Status::Ok, DESCRIBED));
    }

    #[test]
    fn route_check_ssh_that_fails_fails_and_skips_ping() {
        let failed = Err(anyhow!("the remote closed the session").context("ssh exited before the relay started (exit status: 255)"));

        assert_eq!(
            only(session_findings(failed)),
            finding("ssh", Status::Fail, "ssh exited before the relay started (exit status: 255): the remote closed the session")
        );
    }

    #[test]
    fn route_check_ping_over_both_ok() {
        assert_eq!(pinging(true, true)[1..], [finding("ping", Status::Ok, "the remote allows unprivileged ping over IPv4 and IPv6")]);
    }

    #[test]
    fn route_check_ping_over_one_family_ok() {
        assert_eq!(pinging(true, false)[1..], [finding("ping", Status::Ok, "the remote allows unprivileged ping over IPv4 only")]);
        assert_eq!(pinging(false, true)[1..], [finding("ping", Status::Ok, "the remote allows unprivileged ping over IPv6 only")]);
    }

    #[test]
    fn route_check_ping_over_neither_warns() {
        assert_eq!(pinging(false, false)[1..], [finding("ping", Status::Warn, PING_WARNING)]);
    }

    #[test]
    fn route_check_report_displays_one_aligned_line_per_finding() {
        let mut report = Report { findings: Vec::new() };
        let mut out = Vec::new();

        report
            .add(&mut out, [finding("targets", Status::Ok, "192.0.2.0/24"), finding("device", Status::Ok, "no sshunnel0 yet")])
            .unwrap();
        report
            .add(&mut out, [finding("sudo", Status::Warn, "sudo asks for a password"), finding("ssh", Status::Fail, "ssh exited")])
            .unwrap();

        assert_eq!(
            String::from_utf8(out).unwrap(),
            "targets  ok: 192.0.2.0/24\n\
             device   ok: no sshunnel0 yet\n\
             sudo     warn: sudo asks for a password\n\
             ssh      fail: ssh exited\n"
        );
        assert_eq!(report.findings().len(), 4);
    }

    #[test]
    fn route_check_counts_only_failures_as_problems() {
        let report = Report {
            findings: vec![
                finding("targets", Status::Warn, "careful"),
                finding("device", Status::Fail, "taken"),
                finding("sudo", Status::Ok, "fine"),
                finding("ssh", Status::Fail, "down"),
            ],
        };

        assert_eq!(report.problems(), 2);
    }

    #[tokio::test]
    async fn route_check_stops_on_a_signal_and_removes_its_socket_dir() {
        let root = TempDir::new().unwrap();
        let runtime = root.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        let started = root.path().join("started");
        let sudo = shim_dir(root.path(), &[("sudo", &format!(": > '{}'\nexec sleep 30", started.display()))]).unwrap().join("sudo");
        let probe = helper::probe_with(&runtime, |_| vec![sudo.clone().into_os_string()], Duration::from_secs(30));
        let options = Options {
            include: strings(&["192.0.2.0/24"]),
            exclude: Vec::new(),
        };
        // ssh never starts: the signal comes while sudo hangs.
        let relays = Relays::new(vec![Relay::new(host_arch().unwrap(), Bytes::from_static(b"relay"))], Source::Embedded).unwrap();
        let ssh = SshCommand::parse("false").unwrap();
        let mut out = Vec::new();

        // Raised once sudo runs, by when the handlers are in place. nextest runs each test in its
        // own process, so the signal reaches this one alone.
        let raise = async {
            while !started.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            kill_process(getpid(), Signal::TERM).unwrap();
        };
        let checked = run_with(&options, &ssh, "fake-host", &relays, probe, &mut out);
        let within = Duration::from_secs(5);
        let (checked, raised) = tokio::join!(timeout(within, checked), timeout(within, raise));

        raised.expect("sudo never ran");
        let error = checked.expect("the check ignored SIGTERM").unwrap_err();
        assert!(error.to_string().contains("stopped by a signal"), "{error:#}");
        assert_eq!(std::fs::read_dir(&runtime).unwrap().count(), 0, "the socket dir is left behind");
        assert!(Path::new(&runtime).exists());
    }
}
