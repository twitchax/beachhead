//! Route targets: CIDRs and domain patterns, the most-specific-wins matching between them, CIDR
//! set difference for excludes, and the refusals that need no privileges.
//!
//! CIDR rules and name rules never cross: a pattern routes a name by name, whatever address it
//! has on the remote, and a CIDR exclude never touches a name.

use std::{
    fmt::{self, Display},
    net::IpAddr,
    str::FromStr,
};

use anyhow::{anyhow, bail};
use ipnet::IpNet;

use crate::{
    base::{Err, Res},
    route::FAKE_RANGE,
};

/// How specific a name rule is: more labels first, then exact beats wildcard.
type Rank = (usize, bool);

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
        if domain.chars().any(|c| c.is_whitespace() || c == '/') {
            bail!("not a valid domain name");
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

/// The directly connected subnets, read once from the machine (or built by a test).
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub connected: Vec<IpNet>,
}

/// The parsed includes and excludes of one `route` run.
#[derive(Debug, Clone)]
pub struct Targets {
    include: Vec<Entry>,
    exclude: Vec<Entry>,
}

impl Targets {
    /// Parses the targets and applies the refusals that don't depend on the machine: `/0`s, a
    /// bare `*`, and anything overlapping the fake range.
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

        if !problems.is_empty() {
            bail!("invalid targets:\n  {}", problems.join("\n  "));
        }

        Ok(Self { include, exclude })
    }

    /// The CIDR includes minus the CIDR excludes inside them, aggregated.
    #[must_use]
    pub fn routes(&self) -> Vec<IpNet> {
        let excludes: Vec<IpNet> = nets(&self.exclude).collect();
        let mut routed = Vec::new();

        for include in nets(&self.include) {
            let mut pieces = vec![include];
            // Only excludes inside the include carve it; one enclosing it loses to it (more specific).
            for exclude in excludes.iter().filter(|e| include.contains(*e)) {
                pieces = pieces.into_iter().flat_map(|p| subtract(p, *exclude)).collect();
            }
            routed.extend(pieces);
        }

        IpNet::aggregate(&routed)
    }

    /// Whether traffic to `addr` goes through the tunnel: the most specific CIDR rule wins, an
    /// exclude on a tie.
    #[must_use]
    pub fn routes_addr(&self, addr: IpAddr) -> bool {
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
    /// Every refusal at once: a target equal to or inside a connected subnet, or the fake range
    /// overlapping one.
    ///
    /// # Returns
    ///
    /// Warnings: a broader target keeps its connected part local.
    pub fn check(&self, snapshot: &Snapshot) -> Res<Vec<String>> {
        let mut refusals = Vec::new();
        let mut warnings = Vec::new();

        for connected in &snapshot.connected {
            if overlaps_fake_range(connected) {
                refusals.push(format!("the fake range {FAKE_RANGE} overlaps the connected subnet {connected}"));
            }
        }

        for entry in &self.include {
            let Target::Net(net) = &entry.target else { continue };
            for connected in &snapshot.connected {
                if connected.contains(net) {
                    refusals.push(format!("'{}' is inside the connected subnet {connected}", entry.raw));
                } else if net.contains(connected) {
                    warnings.push(format!("'{}' contains the connected subnet {connected}, which stays local", entry.raw));
                }
            }
        }

        if !refusals.is_empty() {
            bail!("refused:\n  {}", refusals.join("\n  "));
        }

        Ok(warnings)
    }

    /// The includes and excludes back as strings, for the helper to parse again.
    #[must_use]
    pub fn args(&self) -> (Vec<String>, Vec<String>) {
        let strings = |entries: &[Entry]| entries.iter().map(|e| e.target.to_string()).collect();
        (strings(&self.include), strings(&self.exclude))
    }
}

/// Lowercase with no trailing dot, so `WIKI.Corp.Example.` is `wiki.corp.example`.
fn normalize(name: &str) -> String {
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

fn overlaps_fake_range(net: &IpNet) -> bool {
    let fake = IpNet::V4(FAKE_RANGE);
    net.contains(&fake) || fake.contains(net)
}

/// Why an include may never be routed, whatever the machine looks like.
fn refusal_for(target: &Target) -> Option<String> {
    let Target::Net(net) = target else { return None };

    if net.prefix_len() == 0 {
        return Some("a full tunnel is not supported".to_owned());
    }
    overlaps_fake_range(net).then(|| format!("overlaps the fake range {FAKE_RANGE}"))
}

/// `net` minus `hole`: halves `net` until each half is disjoint from or inside the hole.
fn subtract(net: IpNet, hole: IpNet) -> Vec<IpNet> {
    let mut kept = Vec::new();
    let mut pending = vec![net];

    while let Some(piece) = pending.pop() {
        if hole.contains(&piece) {
            continue;
        }
        if !piece.contains(&hole) {
            kept.push(piece);
            continue;
        }
        // `piece` strictly contains `hole`, so it is not a host route and can split.
        if let Ok(halves) = piece.subnets(piece.prefix_len() + 1) {
            pending.extend(halves);
        }
    }

    kept
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
        for target in ["198.18.5.0/24", "198.0.0.0/8"] {
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
}
