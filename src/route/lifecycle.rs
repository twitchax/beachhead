//! `sshunnel route` from start to exit, in the spec's lifecycle order: check everything that can
//! refuse the run before ssh starts; start the session; find what the machine depends on; start the
//! root helper; run the netstack and the DNS server on its device; then wait for a signal, the
//! session ending, the helper dying or the netstack failing, and tear down. The helper is stopped
//! on every path once it has started, so its pinned routes are gone when [`run`] returns.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context as _, bail, ensure};
use ipnet::IpNet;
use sshunnel_mux::Mux;
use tokio::task::JoinSet;
use tracing::warn;

use crate::{
    base::{Res, Void},
    relays::Relays,
    route::{
        DEVICE, FAKE_RANGE, device, dns,
        helper::{Helper, Setup, Signals},
        names::{FakeMap, state_path, today},
        peers,
        router::Router,
        stack::{self, DNS_PORT},
        system::{self, Via},
        targets::Targets,
    },
    session::{Session, SshCommand},
};

/// An address in the fake range past its reserved `/24`: where the kernel sends it, it sends
/// every name's fake address.
const FAKE_PROBE: Ipv4Addr = Ipv4Addr::new(198, 18, 1, 1);

/// What to route, as the user wrote it.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// CIDRs and domain patterns.
    pub include: Vec<String>,
    /// CIDRs and names carved out of `include` (`-x`).
    pub exclude: Vec<String>,
}

/// Routes `options`' targets through a relay on `destination` until Ctrl-C, SIGTERM or SIGHUP, the
/// session ending, or the root helper dying.
///
/// # Errors
///
/// Fails, before ssh runs, on any target the machine refuses (all reported at once); then when the
/// session, the helper or the device fails, or the session or helper ends. A signal is a clean
/// exit.
pub async fn run(options: &Options, ssh: &SshCommand, destination: &str, relays: &Relays) -> Void {
    // First, so a signal during startup ends in an orderly exit rather than killing the client
    // midway (and leaving the helper's socket dir behind).
    let mut signals = Signals::new()?;
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
    let probes = probes(&targets.routes(), targets.has_names(), &pins.addrs, &connected);
    let status = status_line(&targets, destination);

    let (include, exclude) = targets.args();
    // Uncancellable: sudo handles a Ctrl-C itself, and the helper, which sees it too, tears down
    // right after it answers. A signal meanwhile waits for the select below.
    let mut helper = Helper::start(&Setup { include, exclude, pins: pins.addrs }).await?;
    warned.warn(helper.warnings());

    let router = Arc::new(Router::new(targets, names));
    let mut tasks = JoinSet::new();
    let ended = match start(&mut tasks, &mut helper, session.mux(), &router, &upstreams) {
        Ok(()) => {
            warned.warn(&check_routes(probes).await);
            eprintln!("{status}");
            wait(&mut signals, session, &mut helper, &mut tasks).await
        }
        Err(e) => Err(e),
    };

    // The client's fd on the device closes with its tasks; the helper's goes as it stops, and the
    // device vanishes with the last one, taking its addresses, routes and resolver config along.
    tasks.shutdown().await;
    let saved = router.names().save().context("saving the fake-address map");
    let stopped = helper.stop().await;
    first_failure([ended, saved, stopped])
}

/// Everything that can refuse the run without privileges or ssh: the targets themselves, the
/// machine's connected subnets, and resolved for domain patterns. Returns the targets, the checks'
/// warnings and the connected subnets.
fn preflight(options: &Options) -> Res<(Targets, Vec<String>, Vec<IpNet>)> {
    let targets = Targets::parse(&options.include, &options.exclude)?;
    let snapshot = system::snapshot().context("reading the routing tables")?;
    let warnings = targets.check(&snapshot)?;
    ensure!(
        !targets.has_names() || system::resolved_usable()?,
        "domain patterns need systemd-resolved, and the system resolver doesn't go through it here \
         (/etc/resolv.conf points elsewhere and nss-resolve isn't in /etc/nsswitch.conf, or resolved isn't running); \
         route CIDRs only, or switch the resolver to systemd-resolved"
    );
    Ok((targets, warnings, snapshot.connected))
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

/// Puts the device's packets through the netstack, with the DNS server on it, all in `tasks`.
fn start(tasks: &mut JoinSet<Void>, helper: &mut Helper, mux: &Mux, router: &Arc<Router>, upstreams: &[IpAddr]) -> Void {
    let packets = device::spawn(helper.take_tun()?, tasks)?;
    let upstreams = upstreams.iter().map(|&addr| SocketAddr::new(addr, DNS_PORT)).collect();
    let dns = Arc::new(dns::Server::new(mux.clone(), Arc::clone(router), upstreams));
    tasks.spawn(stack::run(packets, mux.clone(), Arc::clone(router), dns));
    Ok(())
}

/// Runs until a signal (a clean exit), or the session, the helper or a netstack task ends (an
/// error).
async fn wait(signals: &mut Signals, session: Session, helper: &mut Helper, tasks: &mut JoinSet<Void>) -> Void {
    tokio::select! {
        // A Ctrl-C reaches the helper too, which then exits: the signal is the reason.
        biased;
        () = signals.recv() => Ok(()),
        closed = session.closed() => {
            closed?;
            bail!("the ssh session ended")
        }
        () = helper.closed() => bail!("the root helper exited"),
        Some(done) = tasks.join_next() => {
            done.context("a netstack task panicked")??;
            bail!("the netstack stopped")
        }
    }
}

/// An address to look up once the routes are in, and how a warning names it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Probe {
    addr: IpAddr,
    label: String,
}

/// Each route's first address, and with names a fake address. An address that keeps its route by
/// design is skipped: a pin, or one in a connected subnet (the checks already said so).
fn probes(routes: &[IpNet], names: bool, pins: &[IpAddr], connected: &[IpNet]) -> Vec<Probe> {
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
    probes
}

/// Asks the kernel where each probe goes, off the async threads (`ip` is a process).
async fn check_routes(probes: Vec<Probe>) -> Vec<String> {
    tokio::task::spawn_blocking(move || route_warnings(&probes, system::route_get))
        .await
        .unwrap_or_else(|e| vec![format!("checking the routes failed: {e}")])
}

/// A warning for each probe that doesn't land on [`DEVICE`]: another tool's policy routing (a rule
/// ahead of the main table) won it.
fn route_warnings(probes: &[Probe], route_get: impl Fn(IpAddr) -> Res<Via>) -> Vec<String> {
    probes
        .iter()
        .filter_map(|probe| match route_get(probe.addr) {
            Ok(via) if via.dev == DEVICE => None,
            Ok(via) => Some(format!("{} goes through {}, not {DEVICE}: another tool's policy routing outranks the main table", probe.label, via.dev)),
            Err(e) => Some(format!("could not check where {} goes: {e:#}", probe.label)),
        })
        .collect()
}

/// The one status line: what is routed, through where, on which device.
fn status_line(targets: &Targets, destination: &str) -> String {
    let (include, exclude) = targets.args();
    let except = if exclude.is_empty() { String::new() } else { format!(" (except {})", exclude.join(", ")) };
    format!("sshunnel: routing {}{except} through {destination} on {DEVICE}", include.join(", "))
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
    fn each_route_is_probed_at_its_first_address() {
        let routes = [net("10.99.0.0/16"), net("fd99::/64")];

        assert_eq!(probes(&routes, false, &[], &[]), [probe("10.99.0.0", "10.99.0.0/16"), probe("fd99::", "fd99::/64")]);
        assert_eq!(
            probes(&routes[..1], true, &[], &[]),
            [probe("10.99.0.0", "10.99.0.0/16"), probe("198.18.1.1", "the fake range 198.18.0.0/15")]
        );
    }

    #[test]
    fn addresses_that_keep_their_route_are_not_probed() {
        // A pinned peer that is a whole target, and a target whose start is a connected subnet.
        let routes = [net("192.0.2.7/32"), net("10.0.0.0/8"), net("10.99.0.0/16")];

        let probed = probes(&routes, false, &[addr("192.0.2.7")], &[net("10.0.0.0/24")]);

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
        assert!(warnings[0].starts_with("10.98.0.0/16 goes through tailscale0, not sshunnel0"), "{warnings:?}");
        assert!(warnings[1].contains("the fake range 198.18.0.0/15") && warnings[1].contains("unreachable"), "{warnings:?}");
    }

    #[test]
    fn the_first_failure_is_the_runs() {
        assert!(first_failure([Ok(()), Ok(())]).is_ok());

        let error = first_failure([Ok(()), Err(anyhow!("the ssh session ended")), Err(anyhow!("the root helper exited with 1"))]).unwrap_err();

        assert_eq!(error.to_string(), "the ssh session ended");
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
