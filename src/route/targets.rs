//! Route targets: CIDRs and domain patterns, the most-specific-wins matching between them, CIDR
//! set difference for excludes, and the refusals that need no privileges.
//!
//! CIDR rules and name rules never cross: a pattern routes a name by name, whatever address it
//! has on the remote, and a CIDR exclude never touches a name.

use std::{
    collections::BTreeSet,
    fmt::{self, Display},
    net::IpAddr,
    ops::ControlFlow,
    str::FromStr,
};

use anyhow::{anyhow, bail};
use ipnet::IpNet;

use crate::{
    base::{Err, Res},
    route::{FAKE_RANGE, FAKE_RANGE6},
};

/// How specific a name rule is: more labels first, then exact beats wildcard.
type Rank = (usize, bool);

/// The longest hostname, and the longest label in one.
const MAX_NAME: usize = 253;
const MAX_LABEL: usize = 63;

/// The fake ranges, each sshunnel's own whatever the targets: no target is routed into one.
const FAKE_RANGES: [IpNet; 2] = [IpNet::V4(FAKE_RANGE), IpNet::V6(FAKE_RANGE6)];

/// The most routes one setup may add. Each is an `ip` run as root, and excludes inside a wide v6
/// target can carve one into a hundred thousand. The helper counts its pins against it too.
pub const MAX_ROUTES: usize = 4096;

/// A domain pattern: an exact name, or `*.` followed by a domain (the domain and everything under it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    /// Lowercase, no trailing dot; never empty.
    name: String,
    wildcard: bool,
}

impl Pattern {
    /// The domain the pattern is rooted at: `corp.example` for `*.corp.example`.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.name
    }

    /// Whether `name` (case and a trailing dot ignored) is one the pattern covers.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        self.rank(&normalize(name)).is_some()
    }

    /// The pattern's specificity if it covers the already-normalized `name`.
    fn rank(&self, name: &str) -> Option<Rank> {
        let covers = name == self.name || (self.wildcard && name.len() > self.name.len() && name.ends_with(&self.name) && name.as_bytes()[name.len() - self.name.len() - 1] == b'.');
        covers.then(|| (self.name.split('.').count(), !self.wildcard))
    }
}

impl FromStr for Pattern {
    type Err = Err;

    fn from_str(s: &str) -> Res<Self> {
        let name = normalize(s);
        let (wildcard, domain) = match name.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, name.as_str()),
        };

        if name == "*" {
            bail!("a bare '*' would route every name; use a domain such as '*.corp.example'");
        }
        if domain.is_empty() || domain.split('.').any(str::is_empty) {
            bail!("empty label in a domain pattern");
        }
        if domain.contains('*') {
            bail!("'*' is only allowed as the whole leftmost label");
        }
        // resolved would route every name under it here, and the DNS server answers NXDOMAIN for
        // any name that isn't a hostname.
        if !plausible(domain) {
            bail!(
                "no hostname can match it: labels are ASCII letters, digits, '-' and '_', of 1 to {MAX_LABEL} bytes, in at most {MAX_NAME} \
                 (an IDN in its xn-- form)"
            );
        }

        Ok(Self { name: domain.to_owned(), wildcard })
    }
}

impl Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.wildcard {
            write!(f, "*.")?;
        }
        write!(f, "{}", self.name)
    }
}

/// One thing to route (or exclude).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// An address range; host bits are cleared.
    Net(IpNet),
    /// A domain pattern.
    Name(Pattern),
}

impl FromStr for Target {
    type Err = Err;

    fn from_str(s: &str) -> Res<Self> {
        if s.contains('/') || s.parse::<IpAddr>().is_ok() {
            let net = s.parse::<IpNet>().or_else(|_| s.parse::<IpAddr>().map(IpNet::from));
            return net.map(|n| Self::Net(n.trunc())).map_err(|e| anyhow!("not a valid CIDR: {e}"));
        }
        s.parse().map(Self::Name)
    }
}

impl Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Net(net) => write!(f, "{net}"),
            Self::Name(pattern) => write!(f, "{pattern}"),
        }
    }
}

/// A target as the user wrote it, so errors can name it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    target: Target,
    raw: String,
}

/// What the checks need from the routing tables, read once from the machine (or built by a test).
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// The directly connected subnets, from every table a rule consults.
    pub connected: Vec<IpNet>,
    /// Destinations the main table already routes at the metric sshunnel's own routes get.
    pub taken: Vec<Taken>,
    /// Addresses with a host route of their own in the main table, which outranks every route
    /// sshunnel adds but one to that very host.
    pub hosts: Vec<IpAddr>,
}

/// A main-table route that an equal one of sshunnel's would collide with: the kernel takes one
/// route per destination and metric (and, for IPv4, TOS) in a table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Taken {
    pub net: IpNet,
    /// How it routes, for the refusal: `via 192.0.2.1 dev eth0, metric 0`.
    pub route: String,
}

/// Refusals (any one fails the run) and warnings, from [`Targets::findings`].
#[derive(Debug, Clone, Default)]
pub struct Findings {
    pub refusals: Vec<String>,
    pub warnings: Vec<String>,
}

impl Findings {
    /// The warnings, or one error naming every refusal.
    ///
    /// # Errors
    ///
    /// When there is any refusal.
    pub fn into_result(self) -> Res<Vec<String>> {
        if !self.refusals.is_empty() {
            bail!("refused:\n  {}", self.refusals.join("\n  "));
        }
        Ok(self.warnings)
    }
}

/// The parsed includes and excludes of one `route` run.
#[derive(Debug, Clone)]
pub struct Targets {
    include: Vec<Entry>,
    exclude: Vec<Entry>,
}

impl Targets {
    /// Parses the targets and applies the refusals that don't depend on the machine: `/0`s, a
    /// bare `*`, anything equal to or inside a fake range, and more than [`MAX_ROUTES`] routes.
    /// A target that merely contains a fake range is allowed; [`Self::check`] warns and the range
    /// is carved out of the routes.
    ///
    /// # Errors
    ///
    /// Every syntax error and refusal at once, each naming the target as written.
    pub fn parse(include: &[String], exclude: &[String]) -> Res<Self> {
        let mut problems = Vec::new();
        let mut parse_all = |raws: &[String], refuse: bool| -> Vec<Entry> {
            let mut entries = Vec::with_capacity(raws.len());
            for raw in raws {
                match raw.parse::<Target>() {
                    Ok(target) => {
                        if let Some(refusal) = refuse.then(|| refusal_for(&target)).flatten() {
                            problems.push(format!("'{raw}': {refusal}"));
                        }
                        entries.push(Entry { target, raw: raw.clone() });
                    }
                    Err(e) => problems.push(format!("'{raw}': {e}")),
                }
            }
            entries
        };

        let include = parse_all(include, true);
        let exclude = parse_all(exclude, false);
        let targets = Self { include, exclude };

        // Carving stops once the routes pass the cap, so refusing costs the cap's worth of work
        // however large the setup.
        if targets.carve_into(&mut Carving::up_to(MAX_ROUTES)).is_break() {
            problems.push(format!("the targets come to more than the {MAX_ROUTES} routes sshunnel adds"));
        }
        if !problems.is_empty() {
            bail!("invalid targets:\n  {}", problems.join("\n  "));
        }

        Ok(targets)
    }

    /// The CIDR includes minus the CIDR excludes inside them and minus the fake ranges, sorted, each
    /// once. Nothing merges, not even nested or adjacent targets: each target's route must beat an
    /// equal one elsewhere on its own, which a merged, broader route would lose on prefix length.
    #[must_use]
    pub fn routes(&self) -> Vec<IpNet> {
        let mut carving = Carving::up_to(usize::MAX);
        let _ = self.carve_into(&mut carving);
        carving.routes.into_iter().collect()
    }

    /// Carves the routes into `carving`, until they pass its cap. An include given twice is carved
    /// once: its routes would be the same, and each copy would cost the carving again.
    fn carve_into(&self, carving: &mut Carving) -> ControlFlow<()> {
        // The fake ranges belong to sshunnel, so each is always a hole in what a wider include routes.
        let excludes: Vec<IpNet> = nets(&self.exclude).chain(FAKE_RANGES).collect();
        let mut includes: Vec<IpNet> = nets(&self.include).collect();
        includes.sort_unstable();
        includes.dedup();
        for include in includes {
            // Only excludes inside the include carve it; one enclosing it loses to it (more specific).
            let holes: Vec<IpNet> = excludes.iter().filter(|e| include.contains(*e)).copied().collect();
            carving.carve(include, &holes)?;
        }
        ControlFlow::Continue(())
    }

    /// Whether traffic to `addr` goes through the tunnel: the most specific CIDR rule wins, an
    /// exclude on a tie. The fake ranges are never routed by address.
    #[must_use]
    pub fn routes_addr(&self, addr: IpAddr) -> bool {
        if FAKE_RANGES.iter().any(|fake| fake.contains(&addr)) {
            return false;
        }
        let best = |entries: &[Entry]| nets(entries).filter(|n| n.contains(&addr)).map(|n| n.prefix_len()).max();
        wins(best(&self.include), best(&self.exclude))
    }

    /// Whether `name` (case and a trailing dot ignored) goes through the tunnel: the most
    /// specific name rule wins, an exclude on a tie.
    #[must_use]
    pub fn routes_name(&self, name: &str) -> bool {
        let name = normalize(name);
        let best = |entries: &[Entry]| patterns(entries).filter_map(|p| p.rank(&name)).max();
        wins(best(&self.include), best(&self.exclude))
    }

    /// One routing domain per include pattern, for the resolver's link configuration.
    #[must_use]
    pub fn domains(&self) -> Vec<String> {
        patterns(&self.include).map(|p| p.domain().to_owned()).collect()
    }

    /// Whether any include is a domain pattern (so the resolver and DNS server are needed).
    #[must_use]
    pub fn has_names(&self) -> bool {
        patterns(&self.include).next().is_some()
    }

    /// Applies the refusals that need the machine's connected subnets.
    ///
    /// # Errors
    ///
    /// Every refusal at once: a target equal to or inside a connected subnet, a fake range in use
    /// overlapping one, or a route sshunnel would add that the main table already has at the same
    /// metric.
    ///
    /// # Returns
    ///
    /// Warnings: a broader target keeps its connected part local, and a target containing a fake
    /// range leaves that range to sshunnel.
    pub fn check(&self, snapshot: &Snapshot) -> Res<Vec<String>> {
        self.findings(snapshot).into_result()
    }

    /// What [`Self::check`] finds, before it becomes a result, so a caller can add refusals of its
    /// own and still report them all in one error.
    #[must_use]
    pub fn findings(&self, snapshot: &Snapshot) -> Findings {
        let mut found = Findings::default();

        // The device's own addresses sit in the v4 range whatever the targets; the v6 range holds only
        // names' fakes, so without names it may be anyone's.
        let in_use = [Some(IpNet::V4(FAKE_RANGE)), self.has_names().then_some(IpNet::V6(FAKE_RANGE6))];
        for connected in &snapshot.connected {
            for fake in in_use.iter().flatten() {
                if connected.contains(fake) || fake.contains(connected) {
                    found.refusals.push(format!("the fake range {fake} overlaps the connected subnet {connected}"));
                }
            }
        }

        for entry in &self.include {
            let Target::Net(net) = &entry.target else { continue };
            for connected in &snapshot.connected {
                if connected.contains(net) {
                    found.refusals.push(format!("'{}' is inside the connected subnet {connected}", entry.raw));
                } else if net.contains(connected) {
                    found.warnings.push(format!("'{}' contains the connected subnet {connected}, which stays local", entry.raw));
                }
            }
            for fake in FAKE_RANGES.iter().filter(|fake| net.contains(*fake)) {
                found.warnings.push(format!("'{}' contains the fake range {fake}, which stays sshunnel's", entry.raw));
            }
        }

        // The kernel would refuse sshunnel's own route here (EEXIST), and replacing the other one
        // would leave a trace: its teardown would delete it. A route inside a connected subnet is
        // refused above already (the kernel's prefix route for an address is in main, at metric 0).
        for route in self.routes() {
            if snapshot.connected.iter().any(|connected| connected.contains(&route)) {
                continue;
            }
            if let Some(Taken { route: existing, .. }) = snapshot.taken.iter().find(|taken| taken.net == route) {
                found.refusals.push(format!("'{route}' already has a route of its own ({existing}); sshunnel can't add an equal one"));
            }
        }

        found
    }

    /// The includes and excludes back as strings, for the helper to parse again.
    #[must_use]
    pub fn args(&self) -> (Vec<String>, Vec<String>) {
        let strings = |entries: &[Entry]| entries.iter().map(|e| e.target.to_string()).collect();
        (strings(&self.include), strings(&self.exclude))
    }
}

/// Whether `name` (already normalized) could be a hostname: ASCII letters, digits, `-`, `_`,
/// labels of 1 to 63 bytes, and at most 253 bytes in all. One rule for the patterns a run accepts
/// and the names its DNS server looks up.
pub(crate) fn plausible(name: &str) -> bool {
    name.len() <= MAX_NAME
        && name
            .split('.')
            .all(|label| (1..=MAX_LABEL).contains(&label.len()) && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
}

/// Lowercase with no trailing dot, so `WIKI.Corp.Example.` is `wiki.corp.example`.
pub(crate) fn normalize(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

fn nets(entries: &[Entry]) -> impl Iterator<Item = IpNet> + '_ {
    entries.iter().filter_map(|e| match &e.target {
        Target::Net(net) => Some(*net),
        Target::Name(_) => None,
    })
}

fn patterns(entries: &[Entry]) -> impl Iterator<Item = &Pattern> {
    entries.iter().filter_map(|e| match &e.target {
        Target::Name(pattern) => Some(pattern),
        Target::Net(_) => None,
    })
}

/// An include beats an exclude only by being strictly more specific.
fn wins<T: Ord>(include: Option<T>, exclude: Option<T>) -> bool {
    match (include, exclude) {
        (Some(i), Some(e)) => i > e,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

/// Why an include may never be routed, whatever the machine looks like.
fn refusal_for(target: &Target) -> Option<String> {
    let Target::Net(net) = target else { return None };

    if net.prefix_len() == 0 {
        return Some("a full tunnel is not supported".to_owned());
    }
    FAKE_RANGES.iter().find(|fake| fake.contains(net)).map(|fake| format!("is the fake range {fake} or inside it"))
}

/// Routes being carved: the distinct ones so far, how many may be kept before carving stops, and
/// how many nodes carving has visited, its work.
struct Carving {
    routes: BTreeSet<IpNet>,
    cap: usize,
    visited: usize,
}

impl Carving {
    fn up_to(cap: usize) -> Self {
        Self { routes: BTreeSet::new(), cap, visited: 0 }
    }

    /// Keeps `net` minus `holes`, each inside `net`: halves `net` until each half is inside a hole
    /// or holds none, and breaks as soon as the routes kept pass the cap. A hole goes down one half
    /// at each split, so the work grows with the holes times the depth plus the pieces kept, where
    /// carving one hole at a time out of every piece grew with the holes times the pieces.
    fn carve(&mut self, net: IpNet, holes: &[IpNet]) -> ControlFlow<()> {
        self.visited += 1;
        if holes.is_empty() {
            self.routes.insert(net);
            return if self.routes.len() > self.cap { ControlFlow::Break(()) } else { ControlFlow::Continue(()) };
        }
        if holes.iter().any(|hole| hole.contains(&net)) {
            return ControlFlow::Continue(());
        }
        // A hole is strictly inside `net`, so `net` is not a host route and can split.
        let Ok(halves) = net.subnets(net.prefix_len() + 1) else { return ControlFlow::Continue(()) };
        for half in halves {
            let inside: Vec<IpNet> = holes.iter().filter(|hole| half.contains(*hole)).copied().collect();
            self.carve(half, &inside)?;
        }
        ControlFlow::Continue(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

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

    fn snapshot(connected: &[&str]) -> Snapshot {
        Snapshot {
            connected: connected.iter().map(|s| net(s)).collect(),
            ..Snapshot::default()
        }
    }

    #[test]
    fn targets_parse_cidrs_and_patterns() {
        assert_eq!("10.99.0.0/16".parse::<Target>().unwrap(), Target::Net(net("10.99.0.0/16")));
        assert_eq!("fd99::/64".parse::<Target>().unwrap(), Target::Net(net("fd99::/64")));
        assert_eq!("10.99.3.4/16".parse::<Target>().unwrap().to_string(), "10.99.0.0/16");

        let wild: Pattern = "*.corp.example".parse().unwrap();
        assert_eq!(wild.domain(), "corp.example");
        assert!(wild.matches("corp.example") && wild.matches("a.b.corp.example") && !wild.matches("xcorp.example"));

        let exact: Pattern = "host.corp.example".parse().unwrap();
        assert!(exact.matches("host.corp.example") && !exact.matches("a.host.corp.example"));

        assert_eq!("WIKI.Corp.Example.".parse::<Target>().unwrap().to_string(), "wiki.corp.example");
    }

    #[test]
    fn bad_targets_are_rejected_together() {
        let bad = ["*", "*.", "a.*.example", "10.0.0.0/33", "foo..example"];
        let error = Targets::parse(&strings(&bad), &[]).unwrap_err().to_string();

        for target in bad {
            assert!(error.contains(&format!("'{target}'")), "{error} should name {target}");
        }
    }

    // Patterns are typed, so these limits refuse; the DNS wire format already caps a query's labels
    // and names, where they are a backstop.
    #[test]
    fn plausible_names_are_hostnames() {
        assert!(plausible("wiki.corp.example"));
        assert!(plausible("_dmarc.a-b.corp.example"));
        assert!(plausible(&format!("{}.example", "a".repeat(63))));
        assert!(plausible(&vec!["a".repeat(61); 4].join(".")));

        assert!(!plausible(""));
        assert!(!plausible("a..b"));
        assert!(!plausible("bad name"));
        assert!(!plausible("caf\u{e9}.example"));
        assert!(!plausible(&format!("{}.example", "a".repeat(64))));
        assert!(!plausible(&format!("{}.example", vec!["a".repeat(60); 5].join("."))));
    }

    #[test]
    fn refuses_a_pattern_no_hostname_can_match() {
        // resolved would hand sshunnel every name under these, and each would be NXDOMAIN.
        let long_label = format!("*.{}.example", "a".repeat(64));
        let bad = ["caf\u{e9}.corp.example", "*.b\u{fc}ro.example", &long_label, "under_score.ok.example"];
        let error = Targets::parse(&strings(&bad[..3]), &strings(&bad[..1])).unwrap_err().to_string();

        for pattern in &bad[..3] {
            assert!(error.contains(&format!("'{pattern}': no hostname can match it")), "{error} should name {pattern}");
        }
        assert!(Targets::parse(&strings(&bad[3..]), &[]).is_ok(), "an underscore is a hostname's");
    }

    #[test]
    fn the_most_specific_target_wins() {
        let t = targets(&["10.0.0.0/8", "*.corp.example"], &["10.1.0.0/16", "*.dev.corp.example"]);

        assert!(t.routes_addr(addr("10.2.0.1")));
        assert!(!t.routes_addr(addr("10.1.0.1")));
        assert!(!t.routes_addr(addr("192.0.2.1")));
        assert!(t.routes_name("wiki.corp.example"));
        assert!(!t.routes_name("x.dev.corp.example"));
        assert!(!t.routes_name("example.org"));

        let nested = targets(&["10.1.2.0/24"], &["10.1.0.0/16"]);
        assert!(nested.routes_addr(addr("10.1.2.9")) && !nested.routes_addr(addr("10.1.3.9")));
    }

    #[test]
    fn an_exclude_wins_a_tie() {
        let t = targets(&["10.1.0.0/16", "*.corp.example"], &["10.1.0.0/16", "*.corp.example"]);

        assert!(!t.routes_addr(addr("10.1.0.1")));
        assert!(!t.routes_name("wiki.corp.example"));
    }

    #[test]
    fn an_exact_name_outranks_a_wildcard_on_it() {
        let excluded_exact = targets(&["*.host.corp.example"], &["host.corp.example"]);
        assert!(!excluded_exact.routes_name("host.corp.example"));
        assert!(excluded_exact.routes_name("a.host.corp.example"));

        let included_exact = targets(&["host.corp.example"], &["*.host.corp.example"]);
        assert!(included_exact.routes_name("host.corp.example"));
        assert!(!included_exact.routes_name("a.host.corp.example"));
    }

    #[test]
    fn mixed_case_names_match_alike() {
        let t = targets(&["*.Corp.Example"], &["Secret.corp.example."]);

        assert!(t.routes_name("WIKI.Corp.Example."));
        assert!(t.routes_name("wiki.corp.example"));
        assert!(!t.routes_name("SECRET.corp.example"));
    }

    #[test]
    fn an_excluded_range_is_carved_out_of_routes() {
        let t = targets(&["10.0.0.0/8"], &["10.1.0.0/16"]);
        let expected: Vec<IpNet> = [
            "10.0.0.0/16",
            "10.2.0.0/15",
            "10.4.0.0/14",
            "10.8.0.0/13",
            "10.16.0.0/12",
            "10.32.0.0/11",
            "10.64.0.0/10",
            "10.128.0.0/9",
        ]
        .iter()
        .map(|s| net(s))
        .collect();

        assert_eq!(t.routes(), expected);
    }

    #[test]
    fn each_target_keeps_a_route_of_its_own() {
        // Merged into 10.98.0.0/15, an existing 10.99.0.0/16 elsewhere would win on prefix length.
        assert_eq!(targets(&["10.99.0.0/16", "10.98.0.0/16"], &[]).routes(), [net("10.98.0.0/16"), net("10.99.0.0/16")]);
        // A nested target too: its /16 beats an equal /16 elsewhere, which the /8 alone would not.
        assert_eq!(targets(&["10.99.0.0/16", "10.0.0.0/8"], &[]).routes(), [net("10.0.0.0/8"), net("10.99.0.0/16")]);
        // The same route twice is one route.
        assert_eq!(targets(&["10.99.0.0/16", "10.99.7.7/16"], &[]).routes(), [net("10.99.0.0/16")]);
    }

    #[test]
    fn an_include_inside_an_exclude_is_routed() {
        let routes = targets(&["10.0.0.0/8", "10.1.2.0/24"], &["10.1.0.0/16"]).routes();

        assert!(routes.contains(&net("10.1.2.0/24")));
        assert!(!routes.iter().any(|r| r.contains(&addr("10.1.3.1"))));
    }

    #[test]
    fn cidr_excludes_do_not_touch_names() {
        let t = targets(&["*.corp.example", "10.0.0.0/8"], &["10.0.0.0/8"]);

        assert!(t.routes_name("wiki.corp.example"));
        assert_eq!(t.routes(), Vec::<IpNet>::new());
        assert_eq!(targets(&["10.0.0.0/8"], &["*.corp.example"]).routes(), vec![net("10.0.0.0/8")]);
    }

    #[test]
    fn domains_are_one_per_include_pattern() {
        let t = targets(&["*.corp.example", "host.other.example", "10.0.0.0/8"], &["*.dev.corp.example"]);

        assert_eq!(t.domains(), strings(&["corp.example", "host.other.example"]));
        assert!(t.has_names());
        assert!(!targets(&["10.0.0.0/8"], &["*.corp.example"]).has_names());
    }

    #[test]
    fn args_round_trip() {
        let (include, exclude) = targets(&["10.99.0.0/16", "*.Corp.example"], &["host.corp.example."]).args();

        assert_eq!(include, strings(&["10.99.0.0/16", "*.corp.example"]));
        assert_eq!(exclude, strings(&["host.corp.example"]));
    }

    #[test]
    fn refuses_the_default_route() {
        let error = Targets::parse(&strings(&["0.0.0.0/0", "::/0"]), &[]).unwrap_err().to_string();

        assert!(error.contains("'0.0.0.0/0'") && error.contains("'::/0'"), "{error}");
    }

    #[test]
    fn refuses_a_target_inside_a_connected_subnet() {
        let connected = snapshot(&["192.168.1.0/24"]);

        for target in ["192.168.1.0/24", "192.168.1.128/25"] {
            let error = targets(&[target], &[]).check(&connected).unwrap_err().to_string();
            assert!(error.contains(&format!("'{target}'")), "{error}");
        }

        let warnings = targets(&["192.168.0.0/16"], &[]).check(&connected).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("192.168.1.0/24"), "{warnings:?}");
        assert_eq!(targets(&["10.99.0.0/16"], &[]).check(&connected).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn refuses_a_target_overlapping_the_fake_range() {
        for target in ["198.18.5.0/24", "198.18.0.0/15"] {
            let error = Targets::parse(&strings(&[target]), &[]).unwrap_err().to_string();
            assert!(error.contains(&format!("'{target}'")), "{error}");
        }
    }

    #[test]
    fn refuses_a_fake_range_inside_a_connected_subnet() {
        let error = targets(&["10.99.0.0/16"], &[]).check(&snapshot(&["198.18.0.0/16"])).unwrap_err().to_string();

        assert!(error.contains("198.18.0.0/16"), "{error}");
    }

    #[test]
    fn refuses_every_problem_at_once() {
        let error = Targets::parse(&strings(&["0.0.0.0/0", "*"]), &[]).unwrap_err().to_string();

        assert!(error.contains("'0.0.0.0/0'") && error.contains("'*'"), "{error}");
    }

    #[test]
    fn a_target_containing_the_fake_range_is_carved_and_warned() {
        let t = targets(&["128.0.0.0/1"], &[]);

        assert!(t.routes().iter().all(|r| !r.contains(&net("198.18.0.0/15")) && !net("198.18.0.0/15").contains(r)));
        assert!(!t.routes_addr(addr("198.18.1.1")));
        assert!(t.routes_addr(addr("128.0.0.1")));

        let warnings = t.check(&Snapshot::default()).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("'128.0.0.0/1'") && warnings[0].contains("198.18.0.0/15"), "{warnings:?}");
    }

    #[test]
    fn fake_v6_range_targets_are_refused_or_carved() {
        let fake = net("2001:2::/96");
        for inside in ["2001:2::/112", "2001:2::/96", "2001:2::c612:102"] {
            let error = Targets::parse(&strings(&[inside]), &[]).unwrap_err().to_string();
            assert!(error.contains(&format!("is the fake range {fake} or inside it")) && error.contains(&format!("'{inside}'")), "{error}");
        }

        let around = targets(&["2001::/16"], &[]);
        assert!(around.routes().iter().all(|r| !r.contains(&fake) && !fake.contains(r)), "{:?}", around.routes());
        assert!(!around.routes_addr(addr("2001:2::c612:102")));
        assert!(around.routes_addr(addr("2001:3::1")));
        assert_eq!(around.check(&Snapshot::default()).unwrap(), ["'2001::/16' contains the fake range 2001:2::/96, which stays sshunnel's"]);

        // Carving a /96 out of a /3 costs a route per level between them.
        let wide = targets(&["2000::/3"], &[]).routes();
        assert!(wide.len() <= MAX_ROUTES, "{} routes", wide.len());
        assert!(wide.iter().all(|r| !r.contains(&fake) && !fake.contains(r)), "{wide:?}");
    }

    #[test]
    fn fake_v6_connected_overlap_is_refused_with_names() {
        for connected in ["2001:2::/64", "2001:2::/120"] {
            let error = targets(&["*.corp.example"], &[]).check(&snapshot(&[connected])).unwrap_err().to_string();
            assert!(error.contains(&format!("the fake range 2001:2::/96 overlaps the connected subnet {connected}")), "{error}");
        }

        // Without names the range is never used, so it may be anyone's.
        assert_eq!(targets(&["10.99.0.0/16"], &[]).check(&snapshot(&["2001:2::/64"])).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn half_ranges_cover_everything_but_the_default_route() {
        let t = targets(&["0.0.0.0/1", "128.0.0.0/1"], &[]);

        assert!(t.check(&Snapshot::default()).is_ok());
        assert!(t.routes_addr(addr("10.0.0.1")) && t.routes_addr(addr("200.0.0.1")));
    }

    #[test]
    fn refuses_a_route_the_main_table_already_has() {
        let snapshot = Snapshot {
            connected: vec![net("192.168.1.0/24")],
            taken: vec![
                Taken {
                    net: net("10.99.0.0/16"),
                    route: "via 192.0.2.1 dev eth0, metric 0".to_owned(),
                },
                Taken {
                    net: net("10.0.0.0/16"),
                    route: "unreachable, metric 0".to_owned(),
                },
            ],
            ..Snapshot::default()
        };

        // A target, and a piece that carving `10.1.0.0/16` out of `10.0.0.0/8` leaves.
        let error = targets(&["10.99.0.0/16", "10.0.0.0/8", "192.168.1.0/25"], &["10.1.0.0/16"]).check(&snapshot).unwrap_err().to_string();

        assert!(
            error.contains("'10.99.0.0/16' already has a route of its own (via 192.0.2.1 dev eth0, metric 0); sshunnel can't add an equal one"),
            "{error}"
        );
        assert!(error.contains("'10.0.0.0/16' already has a route of its own (unreachable, metric 0)"), "{error}");
        // In the same error as every other refusal.
        assert!(error.contains("'192.168.1.0/25' is inside the connected subnet 192.168.1.0/24"), "{error}");
        // Narrower and broader routes don't collide.
        assert!(targets(&["10.99.0.0/17", "10.98.0.0/15"], &[]).check(&snapshot).is_ok());
    }

    #[test]
    fn refuses_a_connected_subnet_once() {
        // The kernel's prefix route for an address sits in main at metric 0, so it is taken too.
        let snapshot = Snapshot {
            connected: vec![net("172.31.0.0/30")],
            taken: vec![Taken {
                net: net("172.31.0.0/30"),
                route: "dev cl0, metric 0".to_owned(),
            }],
            ..Snapshot::default()
        };

        let error = targets(&["172.31.0.0/30"], &[]).check(&snapshot).unwrap_err().to_string();

        assert_eq!(error.matches("'172.31.0.0/30'").count(), 1, "{error}");
        assert!(error.contains("is inside the connected subnet 172.31.0.0/30"), "{error}");
    }

    #[test]
    fn refuses_every_snapshot_problem_at_once() {
        let connected = snapshot(&["192.168.1.0/24", "198.18.0.0/16"]);
        let error = targets(&["192.168.1.0/25"], &[]).check(&connected).unwrap_err().to_string();

        assert!(error.contains("'192.168.1.0/25'") && error.contains("198.18.0.0/16"), "{error}");
    }

    /// `/128` excludes at `count` points spread evenly over `fd99::/64`, each in a subtree of its
    /// own, so each carves some 50 routes out of it.
    fn spread_excludes(count: u64) -> Vec<String> {
        let base = "fd99::".parse::<std::net::Ipv6Addr>().unwrap().to_bits();
        let step = u64::MAX / count;
        (0..count).map(|i| std::net::Ipv6Addr::from_bits(base | u128::from(i * step + 1)).to_string()).collect()
    }

    /// Targets as written, without `parse`'s refusals, so a test can watch a setup past the cap carve.
    fn unchecked(include: &[String], exclude: &[String]) -> Targets {
        let entries = |raws: &[String]| {
            raws.iter()
                .map(|raw| Entry {
                    target: raw.parse().unwrap(),
                    raw: raw.clone(),
                })
                .collect()
        };
        Targets {
            include: entries(include),
            exclude: entries(exclude),
        }
    }

    #[test]
    fn refuses_more_routes_than_the_cap() {
        // 128 excludes, one at the start of each /72 in the lower /65, come to 7169 routes: refused
        // once the routes pass the cap, before the rest are carved, so no count is named.
        let excludes: Vec<String> = (0..128_u16).map(|i| format!("fd99::{i:x}00:0:0:0")).collect();
        let error = Targets::parse(&strings(&["fd99::/64"]), &excludes).unwrap_err().to_string();
        assert!(error.contains("the targets come to more than the 4096 routes sshunnel adds"), "{error}");

        // The cap itself is allowed: a host target each.
        let hosts = |count: u16| (0..count).map(|i| format!("fd99::{i:x}")).collect::<Vec<_>>();
        assert_eq!(Targets::parse(&hosts(4096), &[]).unwrap().routes().len(), 4096);
        let error = Targets::parse(&hosts(4097), &[]).unwrap_err().to_string();
        assert!(error.contains("the targets come to more than the 4096 routes sshunnel adds"), "{error}");
    }

    #[test]
    fn carving_stops_once_the_routes_pass_the_cap() {
        // Some 55,000 routes in all. The work before the refusal is the cap's, however often the
        // include repeats: a binary tree has fewer nodes than twice its leaves, here the routes kept
        // (the cap's worth and the one past it) and the holes reached on the way.
        let excludes = spread_excludes(1000);
        let work = |copies: usize| {
            let mut carving = Carving::up_to(MAX_ROUTES);
            let carved = unchecked(&vec!["fd99::/64".to_owned(); copies], &excludes).carve_into(&mut carving);
            assert!(carved.is_break(), "{copies} copies stayed under the cap");
            carving.visited
        };

        let once = work(1);
        assert!(once < 2 * (MAX_ROUTES + 1 + excludes.len()), "{once} nodes visited");
        assert_eq!(work(2000), once);
    }

    #[test]
    fn a_repeated_target_is_carved_once() {
        // Under the cap, every copy was carved again: 12 ms and 1.1 MB of root's apiece in release,
        // and the helper's 64 KiB setup holds thousands of copies.
        let excludes = spread_excludes(20);
        let carved = |copies: usize| {
            let mut carving = Carving::up_to(MAX_ROUTES);
            let flow = unchecked(&vec!["fd99::/64".to_owned(); copies], &excludes).carve_into(&mut carving);
            assert!(flow.is_continue(), "{copies} copies passed the cap");
            carving
        };

        let (once, often) = (carved(1), carved(2000));
        assert_eq!(often.routes, once.routes);
        assert_eq!(often.visited, once.visited);
        // A nested target still keeps a route of its own.
        let nested = targets(&["10.0.0.0/22", "10.0.0.0/22", "10.0.2.0/24"], &["10.0.1.0/24"]).routes();
        assert_eq!(nested, [net("10.0.0.0/24"), net("10.0.2.0/23"), net("10.0.2.0/24")]);
    }

    #[test]
    fn nested_repeated_and_adjacent_excludes_carve_exactly() {
        let carved = |include: &str, exclude: &[&str]| targets(&[include], exclude).routes().iter().map(ToString::to_string).collect::<Vec<_>>();

        // Nested: the inner exclude adds nothing to the outer one's hole.
        assert_eq!(carved("10.0.0.0/22", &["10.0.1.0/24", "10.0.1.128/25"]), ["10.0.0.0/24", "10.0.2.0/23"]);
        assert_eq!(carved("fd99::/62", &["fd99:0:0:1::/64", "fd99:0:0:1:8000::/65"]), ["fd99::/64", "fd99:0:0:2::/63"]);
        // Repeated: once is the same as twice.
        assert_eq!(carved("10.0.0.0/22", &["10.0.1.0/24", "10.0.1.0/24"]), ["10.0.0.0/24", "10.0.2.0/23"]);
        assert_eq!(carved("fd99::/62", &["fd99:0:0:1::/64", "fd99:0:0:1::/64"]), ["fd99::/64", "fd99:0:0:2::/63"]);
        // Adjacent across a split: each half carves on its own.
        assert_eq!(carved("10.0.0.0/22", &["10.0.1.0/24", "10.0.2.0/24"]), ["10.0.0.0/24", "10.0.3.0/24"]);
        assert_eq!(carved("fd99::/62", &["fd99:0:0:1::/64", "fd99:0:0:2::/64"]), ["fd99::/64", "fd99:0:0:3::/64"]);
        // Adjacent siblings: together they are their parent's hole.
        assert_eq!(carved("10.0.0.0/22", &["10.0.2.0/24", "10.0.3.0/24"]), ["10.0.0.0/23"]);
        assert_eq!(carved("fd99::/62", &["fd99:0:0:2::/64", "fd99:0:0:3::/64"]), ["fd99::/63"]);
    }

    /// Numbers for generated setups: xorshift, so every run checks the same ones.
    struct Xorshift(u64);

    impl Xorshift {
        fn below(&mut self, bound: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % bound
        }

        /// A CIDR inside `range`, a 256-address one, of any prefix length from `range`'s down.
        fn inside(&mut self, range: IpNet) -> IpNet {
            let spare = range.max_prefix_len() - range.prefix_len();
            let len = range.prefix_len() + u8::try_from(self.below(u64::from(spare) + 1)).unwrap();
            IpNet::new(nth(range, self.below(256)), len).unwrap().trunc()
        }
    }

    /// The `n`th address of `range`.
    fn nth(range: IpNet, n: u64) -> IpAddr {
        match range.network() {
            IpAddr::V4(v4) => std::net::Ipv4Addr::from_bits(v4.to_bits() + u32::try_from(n).unwrap()).into(),
            IpAddr::V6(v6) => std::net::Ipv6Addr::from_bits(v6.to_bits() + u128::from(n)).into(),
        }
    }

    #[test]
    fn carving_covers_exactly_the_includes_minus_their_excludes() {
        let mut numbers = Xorshift(0x9E37_79B9_7F4A_7C15);
        for range in [net("10.99.7.0/24"), net("fd99::/120")] {
            for _ in 0..400 {
                let include = numbers.inside(range);
                let excludes: Vec<IpNet> = (0..numbers.below(8)).map(|_| numbers.inside(range)).collect();
                let names = |nets: &[IpNet]| nets.iter().map(ToString::to_string).collect::<Vec<_>>();
                let routes = Targets::parse(&names(&[include]), &names(&excludes)).unwrap().routes();
                let setup = format!("{include} minus {excludes:?}: {routes:?}");

                // Every address once if the include has it and no exclude inside the include does,
                // else never: the routes are disjoint and cover exactly that.
                for n in 0..256 {
                    let addr = nth(range, n);
                    let kept = include.contains(&addr) && !excludes.iter().any(|exclude| include.contains(exclude) && exclude.contains(&addr));
                    let covering = routes.iter().filter(|route| route.contains(&addr)).count();
                    assert_eq!(covering, usize::from(kept), "{addr} in {setup}");
                }
                // And as few routes as that takes: no two are halves of one block.
                for route in &routes {
                    let sibling = route.supernet().and_then(|parent| parent.subnets(route.prefix_len()).ok()?.find(|half| half != route));
                    assert!(sibling.is_none_or(|sibling| !routes.contains(&sibling)), "{route} and its sibling in {setup}");
                }

                // Several includes: each one's routes, each once.
                let more: Vec<IpNet> = (0..numbers.below(3)).map(|_| numbers.inside(range)).chain([include]).collect();
                let mut each: Vec<IpNet> = more.iter().flat_map(|one| Targets::parse(&names(&[*one]), &names(&excludes)).unwrap().routes()).collect();
                each.sort_unstable();
                each.dedup();
                assert_eq!(Targets::parse(&names(&more), &names(&excludes)).unwrap().routes(), each, "{more:?} minus {excludes:?}");
            }
        }
    }

    #[test]
    fn bare_addresses_are_host_targets() {
        assert_eq!("10.99.0.5".parse::<Target>().unwrap(), Target::Net(net("10.99.0.5/32")));
        assert_eq!("fd99::5".parse::<Target>().unwrap(), Target::Net(net("fd99::5/128")));
    }

    #[test]
    fn an_excluded_v6_range_is_carved_out_of_routes() {
        let t = targets(&["fd99::/64"], &["fd99::/65"]);

        assert_eq!(t.routes(), vec![net("fd99:0:0:0:8000::/65")]);
        assert!(t.routes_addr(addr("fd99::8000:0:0:1")));
        assert!(!t.routes_addr(addr("fd99::1")));
    }
}
