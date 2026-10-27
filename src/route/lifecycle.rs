//! `sshunnel route` from start to exit, in the spec's lifecycle order: check everything that can
//! refuse the run before ssh starts; start the session; find what the machine depends on; start the
//! root helper; run the netstack and the DNS server on its device, on a thread of their own; then
//! wait for a signal, the session ending, the helper dying or the netstack failing, and tear down.
//! The netstack's thread is joined and then the helper stopped, on every path once each has
//! started, so its pinned routes and the device are gone when [`run`] returns.

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, bail};
use ipnet::IpNet;
use sshunnel_mux::{Mux, frame::Capabilities};
use tokio::time::timeout;
use tracing::warn;

use crate::{
    base::{Res, Void},
    relays::Relays,
    route::{
        DEVICE, FAKE_RANGE, FAKE_RANGE6, PING_WARNING,
        helper::{Helper, Setup, Signals},
        names::{self, FakeMap, state_path, today},
        peers,
        router::Router,
        system::{self, Via},
        targets::{Snapshot, Targets},
        thread::Netstack,
    },
    session::{Session, SshCommand, ready_line},
};

/// An address in the fake range past its reserved `/24`: where the kernel sends it, it sends
/// every name's fake address. Its v6 fake does the same for the v6 range.
const FAKE_PROBE: Ipv4Addr = Ipv4Addr::new(198, 18, 1, 1);

/// What to route, as the user wrote it.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// CIDRs and domain patterns.
    pub include: Vec<String>,
    /// CIDRs and names carved out of `include` (`-x`).
    pub exclude: Vec<String>,
}

/// Routes `options`' targets through a relay on `destination` until Ctrl-C, SIGTERM or SIGHUP (unless
/// ignored at startup, as under `nohup`), the session ending, or the root helper dying.
///
/// # Errors
///
/// Fails, before ssh runs, on any target the machine refuses (all reported at once); then when the
/// session, the helper or the device fails, or the session or helper ends. A signal is a clean
/// exit.
pub async fn run(options: &Options, ssh: &SshCommand, destination: &str, relays: &Relays) -> Void {
    // First, so a signal during startup ends in an orderly exit rather than killing the client
    // midway (and leaving the helper's socket dir behind).
    let mut signals = Signals::respecting_nohup()?;
    let (targets, warnings, connected) = preflight(options)?;
    let mut warned = Warned::default();
    warned.warn(&warnings);
    let names = FakeMap::load(state_path()?, today()).context("loading the fake-address map")?;
    // Read before the device's link is configured, and once, so the pins and the forwarder agree.
    let upstreams = system::upstream_dns().context("reading the upstream DNS servers")?;

    let (session, pins) = tokio::select! {
        biased;
        () = signals.recv() => return Ok(()),
        connected = connect(ssh, destination, relays, &upstreams) => connected?,
    };
    warned.warn(&pins.warnings);
    let status = status_line(&targets, destination);
    let hint = check_hint(&targets);

    let (include, exclude) = targets.args();
    let setup = Setup { include, exclude, pins: pins.addrs };
    // Uncancellable: sudo handles a Ctrl-C itself, and the helper, which sees it too, tears down
    // right after it answers. A Ctrl-C at sudo's password prompt ends sudo, and that failure is the
    // user's stop, so the run exits cleanly.
    let mut helper = match Helper::start(&setup).await {
        Ok(helper) => helper,
        Err(e) => return startup_failed(&mut signals, e).await,
    };
    warned.warn(helper.warnings());
    let probes = probes(&targets.routes(), targets.has_names(), helper.fake_v6(), &setup.pins, &connected);

    let router = Arc::new(Router::new(targets, names));
    let mut netstack = None;
    let ended = match start(&mut helper, session.mux(), &router, &upstreams).await {
        Ok(started) => {
            warned.warn(&check_routes(probes).await);
            warned.warn(&ping_warnings(session.mux().capabilities()));
            eprintln!("{status}");
            eprintln!("{hint}");
            eprintln!("{}", ready_line(std::process::id()));
            wait(&mut signals, session, &mut helper, netstack.insert(started)).await
        }
        Err(e) => Err(e),
    };

    // The client's fd on the device closes as the netstack's thread ends. The helper deletes its
    // pins and then the device as it stops, which takes the device's addresses, routes and resolver
    // config along.
    let halted = netstack.map_or(Ok(()), Netstack::stop);
    let saved = router.names().save().context("saving the fake-address map");
    let stopped = helper.stop().await;
    first_failure([ended, halted, saved, stopped])
}

/// Everything that can refuse the run without privileges or ssh: the targets themselves, the
/// machine's connected subnets, and resolved for domain patterns. Returns the targets, the checks'
/// warnings and the connected subnets.
fn preflight(options: &Options) -> Res<(Targets, Vec<String>, Vec<IpNet>)> {
    let targets = Targets::parse(&options.include, &options.exclude)?;
    let snapshot = system::snapshot().context("reading the routing tables")?;
    let warnings = checked(&targets, &snapshot, system::has_ipv6(), system::resolved_usable)?;
    Ok((targets, warnings, snapshot.connected))
}

/// The refusals that need the machine, all in one error: `targets` against its connected subnets,
/// its IPv6 targets against its kernel (`ipv6`), and patterns against its resolver (`resolved_usable`, asked only when there are patterns).
fn checked(targets: &Targets, snapshot: &Snapshot, ipv6: bool, resolved_usable: impl FnOnce() -> Res<bool>) -> Res<Vec<String>> {
    let mut found = targets.findings(snapshot);
    found.refusals.extend(targets.ipv6_refusal(ipv6));
    if targets.has_names() && !resolved_usable()? {
        found.refusals.push(
            "domain patterns need systemd-resolved, and the system resolver doesn't go through it here \
             (/etc/resolv.conf points elsewhere and nss-resolve isn't in /etc/nsswitch.conf, or resolved isn't running); \
             route CIDRs only, or switch the resolver to systemd-resolved"
                .to_owned(),
        );
    }
    found.into_result()
}

/// The addresses to keep on their normal routes, and what looked wrong finding them.
struct Pins {
    addrs: Vec<IpAddr>,
    warnings: Vec<String>,
}

/// Starts the session on the machine's normal routes and finds ssh's peers while it is up.
async fn connect(ssh: &SshCommand, destination: &str, relays: &Relays, upstreams: &[IpAddr]) -> Res<(Session, Pins)> {
    let session = Session::connect(ssh, destination, relays).await?;
    eprintln!("sshunnel: {}", session.describe());
    let (addrs, warnings) = peers::pins(ssh, destination, session.ssh_pid(), upstreams).await?;
    Ok((session, Pins { addrs, warnings }))
}

/// Puts the device's packets through the netstack, with the DNS server on it, on its own thread.
/// The DNS server hands out v6 fakes only when the helper routed their range.
async fn start(helper: &mut Helper, mux: &Mux, router: &Arc<Router>, upstreams: &[IpAddr]) -> Res<Netstack> {
    Netstack::start(helper.take_tun()?, mux.clone(), Arc::clone(router), upstreams, helper.fake_v6()).await
}

/// Runs until a signal (a clean exit), or the session, the helper or the netstack ends (an error,
/// unless a signal follows at once: see [`SIGNAL_GRACE`]).
async fn wait(signals: &mut Signals, session: Session, helper: &mut Helper, netstack: &mut Netstack) -> Void {
    let ended = async {
        tokio::select! {
            // A Ctrl-C reaches the helper too, which then exits: the signal is the reason.
            biased;
            () = signals.recv() => Ok(()),
            closed = session.closed() => {
                closed?;
                bail!("the ssh session ended")
            }
            () = helper.closed() => bail!("the root helper exited"),
            closed = netstack.closed() => {
                closed?;
                bail!("the netstack stopped")
            }
        }
    }
    .await;
    unless_signalled(signals.recv(), ended).await
}

/// How long an end other than a signal waits for one. A terminal's Ctrl-C (or a service manager
/// stopping the whole group) reaches ssh and the helper in the same kill, and either can exit before
/// this process's handler has run: an end followed at once by a signal is the signal's doing. Longer
/// than the helper's grace because this one waits for the signal to be delivered at all, not just
/// read.
const SIGNAL_GRACE: Duration = Duration::from_millis(250);

/// `ended`, unless it is an error and `signal` resolves within [`SIGNAL_GRACE`]: then a clean exit.
async fn unless_signalled(signal: impl Future<Output = ()>, ended: Void) -> Void {
    if ended.is_err() && timeout(SIGNAL_GRACE, signal).await.is_ok() {
        return Ok(());
    }
    ended
}

/// The error from starting the helper, unless a signal arrived meanwhile: a Ctrl-C at sudo's password
/// prompt ends sudo, and that failure is the user's stop.
async fn startup_failed(signals: &mut Signals, error: anyhow::Error) -> Void {
    if signals.arrived().await { Ok(()) } else { Err(error) }
}

/// An address to look up once the routes are in, and how a warning names it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Probe {
    addr: IpAddr,
    label: String,
}

/// Each route's first address, with names a fake address, and with fake v6 on (the helper's call)
/// its v6 fake. An address that keeps its route by design is skipped: a pin, or one in a connected
/// subnet (the checks already said so).
fn probes(routes: &[IpNet], names: bool, fake_v6: bool, pins: &[IpAddr], connected: &[IpNet]) -> Vec<Probe> {
    let mut probes: Vec<Probe> = routes
        .iter()
        .map(|route| Probe {
            addr: route.network(),
            label: route.to_string(),
        })
        .filter(|probe| !pins.contains(&probe.addr) && !connected.iter().any(|net| net.contains(&probe.addr)))
        .collect();
    if names {
        probes.push(Probe {
            addr: FAKE_PROBE.into(),
            label: format!("the fake range {FAKE_RANGE}"),
        });
    }
    if fake_v6 {
        probes.push(Probe {
            addr: names::fake_v6(FAKE_PROBE).into(),
            label: format!("the fake range {FAKE_RANGE6}"),
        });
    }
    probes
}

/// Asks the kernel where each probe goes, off the async threads (`ip` is a process).
async fn check_routes(probes: Vec<Probe>) -> Vec<String> {
    tokio::task::spawn_blocking(move || route_warnings(&probes, system::route_get))
        .await
        .unwrap_or_else(|e| vec![format!("checking the routes failed: {e}")])
}

/// A warning for each probe that doesn't land on [`DEVICE`]: a more specific route, or another
/// tool's policy routing (a rule ahead of the main table), won it.
fn route_warnings(probes: &[Probe], route_get: impl Fn(IpAddr) -> Res<Via>) -> Vec<String> {
    probes
        .iter()
        .filter_map(|probe| match route_get(probe.addr) {
            Ok(via) if via.dev == DEVICE => None,
            Ok(via) => Some(format!(
                "{} goes through {}, not {DEVICE}: a more specific route or another tool's policy routing wins it",
                probe.label, via.dev
            )),
            Err(e) => Some(format!("could not check where {} goes: {e:#}", probe.label)),
        })
        .collect()
}

/// [`PING_WARNING`] when the relay may ping over neither family, so the netstack refuses every echo
/// without asking it.
fn ping_warnings(can: Capabilities) -> Vec<String> {
    if can.ping4 || can.ping6 { Vec::new() } else { vec![PING_WARNING.to_owned()] }
}

/// The one status line: what is routed, through where, on which device.
fn status_line(targets: &Targets, destination: &str) -> String {
    let (include, exclude) = targets.args();
    let except = if exclude.is_empty() { String::new() } else { format!(" (except {})", exclude.join(", ")) };
    format!("sshunnel: routing {}{except} through {destination} on {DEVICE}", include.join(", "))
}

/// A command that checks the first include target is routed: `resolvectl query` for a name,
/// `ip route get` for a CIDR's network address.
fn check_hint(targets: &Targets) -> String {
    let (include, _) = targets.args();
    let first = include.first().map_or("", String::as_str);
    let command = if let Some(domain) = first.strip_prefix("*.") {
        format!("resolvectl query <name>.{domain}")
    } else if let Some((network, _)) = first.split_once('/') {
        format!("ip route get {network}")
    } else {
        format!("resolvectl query {first}")
    };
    format!("sshunnel: check it with `{command}`")
}

/// The warnings printed so far. The client and the helper run the same checks, so the helper's
/// copy of a warning is skipped.
#[derive(Default)]
struct Warned(Vec<String>);

impl Warned {
    fn warn(&mut self, warnings: &[String]) {
        for warning in warnings {
            if !self.0.contains(warning) {
                warn!("{warning}");
                self.0.push(warning.clone());
            }
        }
    }
}

/// The first error is the run's; any after it is logged, so a failed teardown is never silent.
fn first_failure(results: impl IntoIterator<Item = Void>) -> Void {
    let mut first = Ok(());
    for result in results {
        match (&first, result) {
            (_, Ok(())) => {}
            (Ok(()), Err(e)) => first = Err(e),
            (Err(_), Err(e)) => warn!("{e:#}"),
        }
    }
    first
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use anyhow::anyhow;
    use pretty_assertions::assert_eq;
    use rustix::process::{Signal, getpid, kill_process};

    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn targets(include: &[&str], exclude: &[&str]) -> Targets {
        Targets::parse(&strings(include), &strings(exclude)).unwrap()
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn probe(addr: &str, label: &str) -> Probe {
        Probe {
            addr: self::addr(addr),
            label: label.to_owned(),
        }
    }

    fn via(dev: &str) -> Via {
        Via {
            dev: dev.to_owned(),
            gateway: None,
            unicast: true,
        }
    }

    #[test]
    fn every_refusal_the_machine_raises_comes_in_one_error() {
        let connected = Snapshot {
            connected: vec![net("10.99.0.0/16")],
            ..Snapshot::default()
        };
        let both = targets(&["10.99.7.0/24", "*.corp.example"], &[]);

        let error = checked(&both, &connected, true, || Ok(false)).unwrap_err().to_string();

        assert!(error.contains("'10.99.7.0/24' is inside the connected subnet 10.99.0.0/16"), "{error}");
        assert!(error.contains("systemd-resolved"), "{error}");
    }

    #[test]
    fn checked_without_ipv6_refuses_an_ipv6_target() {
        let v6 = targets(&["fd99::/64"], &[]);
        let none = Snapshot::default();

        let error = checked(&v6, &none, false, || Ok(true)).unwrap_err().to_string();

        assert!(error.contains("'fd99::/64' is an IPv6 target"), "{error}");
        assert!(checked(&v6, &none, true, || Ok(true)).is_ok());
    }

    #[test]
    fn the_resolver_matters_only_to_patterns() {
        let none = Snapshot::default();

        assert!(checked(&targets(&["10.99.0.0/16"], &[]), &none, true, || panic!("asked about the resolver")).is_ok());
        assert!(checked(&targets(&["*.corp.example"], &[]), &none, true, || Ok(true)).is_ok());
        assert!(checked(&targets(&["*.corp.example"], &[]), &none, true, || Ok(false)).is_err());
    }

    #[test]
    fn the_status_line_names_targets_destination_and_device() {
        assert_eq!(
            status_line(&targets(&["10.99.0.0/16", "*.corp.example"], &[]), "corp.example"),
            "sshunnel: routing 10.99.0.0/16, *.corp.example through corp.example on sshunnel0"
        );
        assert_eq!(
            status_line(&targets(&["10.99.0.0/16", "fd99::/64"], &["10.99.7.0/24", "wiki.corp.example"]), "jump"),
            "sshunnel: routing 10.99.0.0/16, fd99::/64 (except 10.99.7.0/24, wiki.corp.example) through jump on sshunnel0"
        );
    }

    #[test]
    fn check_hint_for_a_pattern_a_name_and_a_cidr() {
        let hint = |target: &str| check_hint(&targets(&[target], &[]));

        assert_eq!(hint("*.corp.example"), "sshunnel: check it with `resolvectl query <name>.corp.example`");
        assert_eq!(hint("wiki.corp.example"), "sshunnel: check it with `resolvectl query wiki.corp.example`");
        assert_eq!(hint("10.99.0.0/16"), "sshunnel: check it with `ip route get 10.99.0.0`");
        assert_eq!(hint("fd99::/64"), "sshunnel: check it with `ip route get fd99::`");
    }

    #[test]
    fn each_route_is_probed_at_its_first_address() {
        let routes = [net("10.99.0.0/16"), net("fd99::/64")];

        assert_eq!(probes(&routes, false, false, &[], &[]), [probe("10.99.0.0", "10.99.0.0/16"), probe("fd99::", "fd99::/64")]);
        assert_eq!(
            probes(&routes[..1], true, false, &[], &[]),
            [probe("10.99.0.0", "10.99.0.0/16"), probe("198.18.1.1", "the fake range 198.18.0.0/15")]
        );
    }

    #[test]
    fn fake_v6_range_is_probed_when_on() {
        let routes = [net("10.99.0.0/16")];
        let v4 = [probe("10.99.0.0", "10.99.0.0/16"), probe("198.18.1.1", "the fake range 198.18.0.0/15")];

        assert_eq!(probes(&routes, true, false, &[], &[]), v4);
        assert_eq!(
            probes(&routes, true, true, &[], &[]),
            [v4[0].clone(), v4[1].clone(), probe("2001:2::c612:101", "the fake range 2001:2::/96")]
        );
    }

    #[test]
    fn each_target_is_probed_on_its_own() {
        let routes = targets(&["10.98.0.0/16", "10.99.0.0/16"], &[]).routes();

        assert_eq!(probes(&routes, false, false, &[], &[]), [probe("10.98.0.0", "10.98.0.0/16"), probe("10.99.0.0", "10.99.0.0/16")]);
    }

    #[test]
    fn addresses_that_keep_their_route_are_not_probed() {
        // A pinned peer that is a whole target, and a target whose start is a connected subnet.
        let routes = [net("192.0.2.7/32"), net("10.0.0.0/8"), net("10.99.0.0/16")];

        let probed = probes(&routes, false, false, &[addr("192.0.2.7")], &[net("10.0.0.0/24")]);

        assert_eq!(probed, [probe("10.99.0.0", "10.99.0.0/16")]);
    }

    #[test]
    fn a_route_another_device_wins_is_named_in_a_warning() {
        let probes = [
            probe("10.99.0.0", "10.99.0.0/16"),
            probe("10.98.0.0", "10.98.0.0/16"),
            probe("198.18.1.1", "the fake range 198.18.0.0/15"),
        ];
        let route_get = |addr: IpAddr| match addr.to_string().as_str() {
            "10.99.0.0" => Ok(via(DEVICE)),
            "10.98.0.0" => Ok(via("tailscale0")),
            _ => Err(anyhow!("RTNETLINK answers: Network is unreachable")),
        };

        let warnings = route_warnings(&probes, route_get);

        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert_eq!(
            warnings[0],
            "10.98.0.0/16 goes through tailscale0, not sshunnel0: a more specific route or another tool's policy routing wins it"
        );
        assert!(warnings[1].contains("the fake range 198.18.0.0/15") && warnings[1].contains("unreachable"), "{warnings:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn an_end_just_before_a_signal_is_the_signals() {
        let ended = || Err(anyhow!("the ssh session ended"));

        // ssh died of the same Ctrl-C, a moment before this process's handler ran.
        let signal = tokio::time::sleep(Duration::from_millis(50));
        assert!(unless_signalled(signal, ended()).await.is_ok());

        // No signal: the end is the reason, once the grace has passed.
        let started = tokio::time::Instant::now();
        let error = unless_signalled(std::future::pending(), ended()).await.unwrap_err();
        assert_eq!(error.to_string(), "the ssh session ended");
        assert_eq!(started.elapsed(), SIGNAL_GRACE);

        // A clean end doesn't wait.
        let started = tokio::time::Instant::now();
        assert!(unless_signalled(std::future::pending(), Ok(())).await.is_ok());
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test]
    async fn a_signal_during_startup_is_a_clean_exit() {
        // nextest runs each test in its own process, so the signal reaches this one alone.
        let mut signals = Signals::new().unwrap();
        kill_process(getpid(), Signal::TERM).unwrap();

        let exit = startup_failed(&mut signals, anyhow!("sudo exited before the root helper started")).await;

        assert!(exit.is_ok());
    }

    #[tokio::test]
    async fn no_signal_during_startup_keeps_the_error() {
        let mut signals = Signals::new().unwrap();

        let error = startup_failed(&mut signals, anyhow!("sudo exited before the root helper started")).await.unwrap_err();

        assert!(error.to_string().contains("sudo exited"), "{error}");
    }

    #[test]
    fn the_first_failure_is_the_runs() {
        assert!(first_failure([Ok(()), Ok(())]).is_ok());

        let error = first_failure([Ok(()), Err(anyhow!("the ssh session ended")), Err(anyhow!("the root helper exited with 1"))]).unwrap_err();

        assert_eq!(error.to_string(), "the ssh session ended");
    }

    #[test]
    fn a_remote_that_can_ping_over_neither_family_earns_the_warning() {
        let only = |ping4, ping6| ping_warnings(Capabilities { ping4, ping6 });

        assert_eq!(only(false, false), [PING_WARNING]);
        // One family is enough to try: a name may resolve to it on the remote.
        assert_eq!(only(true, false), Vec::<String>::new());
        assert_eq!(only(false, true), Vec::<String>::new());
        assert_eq!(only(true, true), Vec::<String>::new());
    }

    #[test]
    fn a_warning_prints_once() {
        let mut warned = Warned::default();

        warned.warn(&strings(&["'10.0.0.0/8' contains the connected subnet 10.1.0.0/16, which stays local"]));
        warned.warn(&strings(&[
            "'10.0.0.0/8' contains the connected subnet 10.1.0.0/16, which stays local",
            "10.99.0.5/32 keeps its current route",
        ]));

        assert_eq!(warned.0.len(), 2);
    }
}
