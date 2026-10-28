//! The namespace harness for `route`'s e2e tests. [`netns`] runs a test again as root over fresh
//! user, mount, PID and network namespaces, where it can create a TUN device, routes and bind mounts
//! without touching the machine, and [`RemoteNs`] is a second network namespace, joined to the first
//! by a veth pair, that plays the remote's network. [`Namespaces`] makes the same choice for a
//! command that isn't a test: the route bench's client side.
//!
//! Ubuntu (23.10 on) restricts unprivileged user namespaces through `AppArmor`. There, the test
//! runs again in a privileged Docker container built from the host's own Ubuntu release, so the
//! binaries cargo built here run in it unchanged and nobody changes a sysctl to run `cargo make ci`.

use std::{
    ffi::OsString,
    fmt,
    fs::File,
    io::{self, BufRead as _, BufReader, Write as _},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket},
    os::fd::AsFd as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context as _, anyhow, bail, ensure};
use rustix::thread::{LinkNameSpaceType, move_into_link_name_space};

use sha2::{Digest as _, Sha256};

use crate::{
    base::{Err, Res, Void},
    relays::hex,
};

/// Set for the test run again inside: there, [`netns`] lets the body run.
const INSIDE: &str = "SSHUNNEL_IN_NETNS";
/// `docker` forces the container even where user namespaces work, so CI keeps that path from rotting.
const FORCE: &str = "SSHUNNEL_NETNS";
/// How long a test has, from entering [`netns`], to finish in its container: under nextest's 120 s
/// kill (`.config/nextest.toml`), since a killed `docker run` leaves its container running.
const CONTAINER_TIMEOUT: Duration = Duration::from_secs(110);
/// The groups that may open ping sockets in the network namespace of whoever reads or writes it.
pub(super) const PING_GROUP_RANGE: &str = "/proc/sys/net/ipv4/ping_group_range";
/// The `ping_group_range` that lets root's group ping: the one group the harness's user namespace
/// maps. A new network namespace lets none ("1 0"), and the kernel refuses any bound the writer's
/// user namespace doesn't map, so neither the usual "0 2147483647" nor "1 0" can be written there,
/// and a range once opened stays open.
pub(super) const PING_ROOT: &str = "0 0";

/// Whether to run the test's body here. Outside, runs the test named `test` again as root over fresh
/// namespaces (directly with `unshare`, else in a container), returns `false` once it passed,
/// and prints a skip where neither works. Inside, returns `true`. Each test opens with
/// `if !netns("its_name").unwrap() { return; }`.
///
/// # Errors
///
/// Fails when the test fails in its namespaces, when `test` names no test (the run again would run
/// nothing and pass), and when no namespace is available under `CI`.
pub fn netns(test: &str) -> Res<bool> {
    let entered = Instant::now();
    if std::env::var_os(INSIDE).is_some() {
        return Ok(true);
    }
    let exe = std::env::current_exe().context("locating the test executable")?;
    ensure_listed(&exe, test)?;
    let runner = match Runner::pick()? {
        Ok(runner) => runner,
        Err(why) => {
            ensure!(std::env::var_os("CI").is_none(), "on this CI runner, {}", unavailable(&why));
            eprintln!("skipped: {}", unavailable(&why));
            return Ok(false);
        }
    };
    let status = runner.command(&exe, test, entered)?.status().context("running the test in its namespaces")?;
    ensure!(status.success(), "{test} failed in its namespaces ({status})");
    Ok(false)
}

/// Why no namespace is to be had, with the reason the container can't stand in.
fn unavailable(why: &Err) -> String {
    format!("no network namespaces: `unshare` can't make them here, and the container can't stand in ({why:#})")
}

/// Fails unless `exe` has exactly one test named `test`.
fn ensure_listed(exe: &Path, test: &str) -> Void {
    let listing = Command::new(exe).args(["--list", "--exact", test]).output().context("listing the tests")?;
    let entry = format!("{test}: test");
    let found = String::from_utf8_lossy(&listing.stdout).lines().filter(|line| *line == entry).count();
    ensure!(found == 1, "no test is named `{test}`, so running it again would run nothing and pass");
    Ok(())
}

/// The command that runs `test` alone (ignored or not), with its output passed through, as root in
/// fresh user, mount, PID and network namespaces. The PID namespace takes every process the test
/// leaves behind down with it, even one in a process group of its own. Its PID 1 is a shell that
/// stays in the outer network namespace, as a machine's init does, so the helper's check that
/// patterns run in init's namespace still refuses inside the test's.
fn rerun(exe: &Path, test: &str) -> Vec<OsString> {
    let mut command = namespaced();
    command.push(exe.into());
    command.extend(["--exact", test, "--nocapture", "--include-ignored"].map(OsString::from));
    command
}

/// Whether direct mode works here: the [`rerun`]'s namespaces, running nothing. A host can allow
/// `unshare -rn` and still refuse a fresh `/proc` in a user namespace (under lxcfs, say).
fn probe() -> Vec<OsString> {
    let mut command = namespaced();
    command.push("true".into());
    command
}

/// The [`rerun`]'s namespaces, up to the command to run in them.
fn namespaced() -> Vec<OsString> {
    let outer = ["unshare", "-rmp", "--fork", "--kill-child", "--mount-proc", "sh", "-c", r#"unshare -n "$@"; exit $?"#, "sh"];
    outer.map(OsString::from).into()
}

/// Where the test runs again.
enum Runner {
    /// Here, where the [`probe`] succeeds.
    Direct,
    /// In a container of this Ubuntu release, from `image`.
    Docker { image: String },
}

impl Runner {
    /// The container when [`FORCE`]d; else here, where user namespaces work; else the container,
    /// where it can run, with its image built. The inner `Err` says why the container can't.
    fn pick() -> Res<Result<Self, Err>> {
        match std::env::var(FORCE) {
            Ok(choice) if choice == "docker" => return Ok(Ok(Self::Docker { image: image(&docker_codename()?)? })),
            Ok(choice) => bail!("{FORCE}={choice}: the one choice is `docker`"),
            Err(_) => {}
        }
        let probe = probe();
        if probe.split_first().is_some_and(|(program, args)| succeeds(Command::new(program).args(args))) {
            return Ok(Ok(Self::Direct));
        }
        match docker_codename() {
            Ok(codename) => Ok(Ok(Self::Docker { image: image(&codename)? })),
            Err(why) => Ok(Err(why)),
        }
    }

    /// The [`rerun`] of `test` in `exe`, where this runner runs it. A container gets what is left
    /// of [`CONTAINER_TIMEOUT`] since `entered`, after any image build.
    fn command(&self, exe: &Path, test: &str, entered: Instant) -> Res<Command> {
        let inner = rerun(exe, test);
        match self {
            Self::Direct => direct(&inner),
            Self::Docker { image } => {
                let limit = CONTAINER_TIMEOUT
                    .checked_sub(entered.elapsed())
                    .filter(|left| left.as_secs() > 0)
                    .context("building the image took the test's whole time")?;
                let mounts = [PathBuf::from(env!("CARGO_MANIFEST_DIR")), target_dir(exe)?];
                in_container(image, &inner, &mounts, limit)
            }
        }
    }
}

/// `inner` (a program and its arguments) here, with [`INSIDE`] set.
fn direct(inner: &[OsString]) -> Res<Command> {
    let (program, args) = inner.split_first().context("the command is empty")?;
    let mut command = Command::new(program);
    command.args(args).env(INSIDE, "1");
    Ok(command)
}

/// `inner` in a container from `image`, as [`docker_run`] runs it, from this working directory.
fn in_container(image: &str, inner: &[OsString], mounts: &[PathBuf], limit: Duration) -> Res<Command> {
    let workdir = std::env::current_dir().context("reading the working directory")?;
    let mut command = Command::new("docker");
    command.args(docker_run(image, mounts, &workdir, limit, inner)?);
    Ok(command)
}

/// Where a command that isn't a test runs as root over fresh namespaces: here or in the container,
/// by [`netns`]'s own choice. The route bench's client side runs in them.
pub struct Namespaces(Runner);

impl Namespaces {
    /// [`netns`]'s choice for this host, with the container's image built if it picks that.
    ///
    /// # Errors
    ///
    /// Fails, saying why, where neither works.
    pub fn pick() -> Res<Self> {
        Runner::pick()?.map(Self).map_err(|why| anyhow!(unavailable(&why)))
    }

    /// `program` (a program and its arguments) as root over fresh mount, PID and network
    /// namespaces. Here, that is the user namespace [`netns`] reruns a test in, where this user is
    /// root. In the container, it is the container's own root, with `mounts` read-only at their own
    /// paths and `limit` to live: a user namespace of its own would map only that root, leaving the
    /// files this user owns in the mounts unreadable.
    ///
    /// One difference follows from that: here, as in a test's rerun, PID 1 sits outside `program`'s
    /// network namespace, so `route::system::same_netns_as_init()` reads false; in the container,
    /// PID 1 (Docker's init) shares it, and it reads true. `route`'s helper refuses domain patterns
    /// on that check, so a caller routing patterns would be refused here and not in the container.
    ///
    /// # Errors
    ///
    /// Fails when `program` is empty or a mount can't be passed to Docker.
    pub fn command(&self, program: &[OsString], mounts: &[PathBuf], limit: Duration) -> Res<Command> {
        ensure!(!program.is_empty(), "no command to run in the namespaces");
        match &self.0 {
            Runner::Direct => {
                let mut inner = namespaced();
                inner.extend_from_slice(program);
                direct(&inner)
            }
            Runner::Docker { image } => in_container(image, program, mounts, limit),
        }
    }
}

impl fmt::Display for Namespaces {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Runner::Direct => f.write_str("user namespaces (unshare)"),
            Runner::Docker { image } => write!(f, "a privileged Docker container ({image})"),
        }
    }
}

/// This host's Ubuntu release, when Docker can run its image: only Ubuntu and its derivatives
/// restrict user namespaces, and the release keeps the container's glibc the host's.
fn docker_codename() -> Res<String> {
    let os_release = std::fs::read_to_string("/etc/os-release").context("reading /etc/os-release")?;
    let codename = ubuntu_codename(&os_release).context("/etc/os-release has no UBUNTU_CODENAME, so no image matches this host")?;
    ensure!(succeeds(Command::new("docker").arg("info")), "`docker info` fails: Docker isn't usable");
    Ok(codename.to_owned())
}

/// The `UBUNTU_CODENAME` in an `/etc/os-release`: Ubuntu's, or the release a derivative is built on.
fn ubuntu_codename(os_release: &str) -> Option<&str> {
    let value = os_release.lines().find_map(|line| line.strip_prefix("UBUNTU_CODENAME="))?;
    Some(value.trim().trim_matches('"')).filter(|codename| !codename.is_empty())
}

/// The image's tag, one per Ubuntu release and [`dockerfile`].
fn image_tag(codename: &str) -> String {
    tag_for(codename, &dockerfile(codename))
}

/// A tag naming `dockerfile`'s hash, so a changed image definition is built afresh: [`image`]
/// builds only when the tag is missing.
fn tag_for(codename: &str, dockerfile: &str) -> String {
    let hash = hex(&Sha256::digest(dockerfile));
    format!("sshunnel-netns:{codename}-{}", &hash[..12])
}

/// The image: the host's Ubuntu release, so its glibc is the host's, plus iproute2 for the tests and
/// an ssh client for the route bench's client side.
fn dockerfile(codename: &str) -> String {
    format!(
        "FROM ubuntu:{codename}\n\
         RUN apt-get update && apt-get install -y --no-install-recommends iproute2 openssh-client && rm -rf /var/lib/apt/lists/*\n"
    )
}

/// The image for `codename`, built from [`dockerfile`] the first time. Tests racing to build it all
/// succeed: each later build finds every layer cached and tags the same image.
fn image(codename: &str) -> Res<String> {
    let tag = image_tag(codename);
    if succeeds(Command::new("docker").args(["image", "inspect", &tag])) {
        return Ok(tag);
    }
    let mut builder = Command::new("docker")
        .args(["build", "--quiet", "--tag", &tag, "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("running docker build")?;
    builder
        .stdin
        .take()
        .context("docker build has no stdin")?
        .write_all(dockerfile(codename).as_bytes())
        .context("sending the Dockerfile")?;
    let built = builder.wait_with_output().context("waiting for docker build")?;
    ensure!(built.status.success(), "building {tag} failed: {}", String::from_utf8_lossy(&built.stderr).trim());
    Ok(tag)
}

/// `docker run`'s arguments: `inner` as root in a privileged container with no network, `mounts`
/// read-only at their own paths (so nothing root-owned lands in the tree), and `limit` (whole
/// seconds) to live.
fn docker_run(image: &str, mounts: &[PathBuf], workdir: &Path, limit: Duration, inner: &[OsString]) -> Res<Vec<OsString>> {
    // Root: in a privileged container, any other user hits the same AppArmor restriction.
    let mut args: Vec<OsString> = ["run", "--rm", "--init", "--privileged", "--network", "none"].map(OsString::from).into();
    for mount in mounts {
        let path = mount.to_str().with_context(|| format!("{} is not UTF-8", mount.display()))?;
        ensure!(!path.contains(':'), "{path} has a colon, which `--volume` can't take");
        args.extend(["--volume".into(), format!("{path}:{path}:ro").into()]);
    }
    args.extend(["--workdir".into(), workdir.into()]);
    args.extend(["--env".into(), format!("{INSIDE}=1").into()]);
    args.extend(["--env", "CI", image, "timeout"].map(OsString::from));
    args.push(limit.as_secs().to_string().into());
    args.extend(inner.iter().cloned());
    Ok(args)
}

/// The cargo target dir `exe` was built in: the nearest ancestor cargo tagged as a cache.
fn target_dir(exe: &Path) -> Res<PathBuf> {
    exe.ancestors()
        .find(|dir| dir.join("CACHEDIR.TAG").is_file())
        .map(Path::to_path_buf)
        .with_context(|| format!("no cargo target dir above {}", exe.display()))
}

fn succeeds(command: &mut Command) -> bool {
    command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|status| status.success())
}

/// Runs `command`, failing with its stderr unless it succeeds.
fn run(command: &mut Command) -> Void {
    let output = command.stdin(Stdio::null()).output().with_context(|| format!("running {command:?}"))?;
    ensure!(output.status.success(), "{command:?} failed: {}", String::from_utf8_lossy(&output.stderr).trim());
    Ok(())
}

/// The remote's network: a namespace joined to the test's own by a veth pair, `cl0` here
/// (`172.31.0.1/30`) and `rm0` there (`172.31.0.2/30`), with the targets' hosts and ssh's peer on a
/// dummy link there. Here, `10.98.0.0/16` goes via the veth at metric 100, as a DHCP route would, so
/// a `10.98.0.0/16` target captures the peer and only a pin keeps it; nothing here reaches
/// `10.99.0.0/16` or `fd99::/64` but a route's device. The relay may ping there, as on a systemd
/// distribution, unless the namespace was made [`Self::without_ping`]. A `sleep` holds the namespace
/// and is killed on drop.
pub struct RemoteNs {
    holder: Child,
}

impl RemoteNs {
    /// The remote's end of the veth: the gateway a pin keeps.
    pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(172, 31, 0, 2);
    /// A host inside the v4 target `10.99.0.0/16`, on the remote.
    pub const HOST: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 5);
    /// A host inside the v6 target `fd99::/64`, on the remote.
    pub const HOST6: Ipv6Addr = Ipv6Addr::new(0xfd99, 0, 0, 0, 0, 0, 0, 5);
    /// The test's end of the veth.
    pub const LINK: &str = "cl0";
    /// The address of the test's end of the veth: where a pinned route's traffic comes from.
    pub const LINK_ADDR: Ipv4Addr = Ipv4Addr::new(172, 31, 0, 1);
    /// ssh's peer, inside `10.98.0.0/16` and reached through the veth.
    pub const PEER: Ipv4Addr = Ipv4Addr::new(10, 98, 0, 2);

    /// Makes the namespace, wires both ends, and lets the remote ping.
    ///
    /// # Errors
    ///
    /// As [`Self::without_ping`], and when the sysctl can't be written.
    pub fn new() -> Res<Self> {
        let ns = Self::without_ping()?;
        ns.run(&["sh", "-c", &format!("echo {PING_ROOT} > {PING_GROUP_RANGE}")])?;
        Ok(ns)
    }

    /// Makes the namespace and wires both ends, leaving its `ping_group_range` at a new namespace's
    /// "1 0": a remote whose relay may not ping, as in many containers and on Alpine. Closing the
    /// range of a namespace [`Self::new`] opened is no substitute, since the harness can't write
    /// "1 0" (see `PING_ROOT`).
    ///
    /// # Errors
    ///
    /// Fails outside a network namespace of the test's own (see [`netns`]), or when `ip` fails.
    pub fn without_ping() -> Res<Self> {
        let mut holder = Command::new("unshare")
            .args(["-n", "sh", "-c", "echo ready && exec sleep infinity"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .context("starting the remote's namespace")?;
        let stdout = holder.stdout.take().context("the namespace holder has no stdout")?;
        let ns = Self { holder };
        // Printed once unshare is done, so the holder's namespace is the new one from here on.
        let mut ready = String::new();
        BufReader::new(stdout).read_line(&mut ready).context("waiting for the remote's namespace")?;
        ensure!(ready == "ready\n", "the remote's namespace didn't start");

        let pid = ns.holder.id().to_string();
        let gateway = Self::GATEWAY.to_string();
        let link_addr = format!("{}/30", Self::LINK_ADDR);
        let local: [&[&str]; 5] = [
            &["link", "set", "lo", "up"],
            &["link", "add", Self::LINK, "type", "veth", "peer", "name", "rm0", "netns", &pid],
            &["addr", "add", &link_addr, "dev", Self::LINK],
            &["link", "set", Self::LINK, "up"],
            &["route", "add", "10.98.0.0/16", "via", &gateway, "metric", "100"],
        ];
        for args in local {
            run(Command::new("ip").args(args))?;
        }
        let [rm0, host, host6, peer] = [format!("{gateway}/30"), format!("{}/32", Self::HOST), format!("{}/128", Self::HOST6), format!("{}/32", Self::PEER)];
        let remote: [&[&str]; 8] = [
            &["ip", "link", "set", "lo", "up"],
            &["ip", "addr", "add", &rm0, "dev", "rm0"],
            &["ip", "link", "set", "rm0", "up"],
            &["ip", "link", "add", "dum0", "type", "dummy"],
            &["ip", "addr", "add", &host, "dev", "dum0"],
            &["ip", "addr", "add", &host6, "dev", "dum0"],
            &["ip", "addr", "add", &peer, "dev", "dum0"],
            &["ip", "link", "set", "dum0", "up"],
        ];
        for command in remote {
            ns.run(command)?;
        }
        Ok(ns)
    }

    /// Runs `command` (a program and its arguments) in the remote's namespace.
    ///
    /// # Errors
    ///
    /// Fails when it does, with its stderr.
    pub fn run(&self, command: &[&str]) -> Void {
        run(Command::new("nsenter").arg(self.net()).args(command))
    }

    /// A listener bound to `addr` in the remote's namespace.
    ///
    /// # Errors
    ///
    /// Fails when the namespace can't be entered or `addr` can't be bound there.
    pub fn listen(&self, addr: SocketAddr) -> Res<TcpListener> {
        self.bind(addr, TcpListener::bind)
    }

    /// A UDP socket bound to `addr` in the remote's namespace.
    ///
    /// # Errors
    ///
    /// Fails when the namespace can't be entered or `addr` can't be bound there.
    pub fn udp(&self, addr: SocketAddr) -> Res<UdpSocket> {
        self.bind(addr, UdpSocket::bind)
    }

    /// `bind(addr)` on a thread that enters the remote's namespace first; the socket stays there.
    fn bind<T: Send>(&self, addr: SocketAddr, bind: fn(SocketAddr) -> io::Result<T>) -> Res<T> {
        let ns = File::open(self.net_path()).context("opening the remote's namespace")?;
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    move_into_link_name_space(ns.as_fd(), Some(LinkNameSpaceType::Network)).context("entering the remote's namespace")?;
                    bind(addr).with_context(|| format!("binding {addr} in the remote's namespace"))
                })
                .join()
                .map_err(|_| anyhow!("binding {addr} in the remote's namespace panicked"))?
        })
    }

    /// The command prefix that runs a command in the remote's namespace; `FakeRemote::in_netns` puts
    /// it before the login shell.
    #[must_use]
    pub fn nsenter(&self) -> String {
        format!("nsenter {}", self.net())
    }

    fn net(&self) -> String {
        format!("--net={}", self.net_path())
    }

    fn net_path(&self) -> String {
        format!("/proc/{}/ns/net", self.holder.id())
    }
}

impl Drop for RemoteNs {
    fn drop(&mut self) {
        let _ = self.holder.kill();
        let _ = self.holder.wait();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::ffi::OsStr;

    use pretty_assertions::assert_eq;

    use super::*;

    fn strings(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_rerun_is_one_test_in_fresh_namespaces() {
        assert_eq!(
            rerun(Path::new("/repo/target/debug/deps/route-0123"), "e2e_route_x"),
            strings(&[
                "unshare",
                "-rmp",
                "--fork",
                "--kill-child",
                "--mount-proc",
                "sh",
                "-c",
                r#"unshare -n "$@"; exit $?"#,
                "sh",
                "/repo/target/debug/deps/route-0123",
                "--exact",
                "e2e_route_x",
                "--nocapture",
                "--include-ignored",
            ])
        );
    }

    #[test]
    fn the_probe_needs_every_namespace_the_rerun_does() {
        // A host can allow `unshare -rn` and still refuse a fresh /proc in a user namespace (lxcfs).
        let rerun = rerun(Path::new("/repo/target/debug/deps/route-0123"), "e2e_route_x");
        let probe = probe();
        let (command, setup) = probe.split_last().unwrap();

        assert_eq!(command, "true");
        assert!(rerun.starts_with(setup), "{probe:?} doesn't set up what {rerun:?} needs");
    }

    #[test]
    fn a_skip_says_why_the_container_cant_stand_in() {
        let skip = unavailable(&anyhow!("`docker info` fails: Docker isn't usable"));

        assert!(skip.contains("`unshare` can't") && skip.contains("`docker info` fails"), "{skip}");
    }

    #[test]
    fn the_image_follows_the_hosts_ubuntu_release() {
        let ubuntu = "PRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\nVERSION_CODENAME=noble\nID=ubuntu\nUBUNTU_CODENAME=noble\n";
        // A derivative names its own release first; the image follows the Ubuntu one under it.
        let derivative = "NAME=\"Linux Mint\"\nVERSION_CODENAME=xia\nID=linuxmint\nID_LIKE=\"ubuntu debian\"\nUBUNTU_CODENAME=\"noble\"\n";
        let debian = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nVERSION_CODENAME=trixie\nID=debian\n";

        assert_eq!(ubuntu_codename(ubuntu), Some("noble"));
        assert_eq!(ubuntu_codename(derivative), Some("noble"));
        assert_eq!(ubuntu_codename(debian), None);
        assert_eq!(ubuntu_codename("UBUNTU_CODENAME=\n"), None);

        let dockerfile = dockerfile("noble");
        assert!(dockerfile.starts_with("FROM ubuntu:noble\n") && dockerfile.contains("iproute2"), "{dockerfile}");
        assert!(dockerfile.contains("openssh-client"), "the route bench runs ssh in the container: {dockerfile}");
    }

    #[test]
    fn the_image_tag_follows_the_dockerfile() {
        // `image` builds only on a missing tag, so a changed Dockerfile under the same tag would
        // leave every machine that built the old one running it.
        let tag = image_tag("noble");

        assert_eq!(tag, tag_for("noble", &dockerfile("noble")));
        assert!(tag.starts_with("sshunnel-netns:noble-"), "{tag}");
        assert_ne!(tag_for("noble", "FROM ubuntu:noble\n"), tag_for("noble", "FROM ubuntu:noble\nRUN true\n"));
    }

    #[test]
    fn a_direct_rerun_needs_no_target_dir_or_time_left() {
        // Only the container mounts the target dir and has a limit. A `CARGO_TARGET_DIR` made before
        // cargo ran has no `CACHEDIR.TAG`, and a direct rerun has no image build to run out of time.
        let long_ago = Instant::now().checked_sub(CONTAINER_TIMEOUT).expect("the machine has been up longer than the container's limit");

        let command = Runner::Direct.command(Path::new("/nowhere/route-0123"), "e2e_route_x", long_ago).unwrap();

        assert_eq!(command.get_program(), "unshare");
    }

    #[test]
    fn a_command_runs_here_or_in_the_container() {
        let inner = strings(&["/repo/target/debug/xtask", "bench-client"]);
        let mounts = [PathBuf::from("/repo/target")];

        let here = direct(&inner).unwrap();
        assert_eq!(here.get_program(), "/repo/target/debug/xtask");
        assert_eq!(here.get_args().collect::<Vec<_>>(), ["bench-client"]);
        assert_eq!(here.get_envs().collect::<Vec<_>>(), [(OsStr::new(INSIDE), Some(OsStr::new("1")))]);
        assert!(direct(&[]).is_err(), "nothing to run");

        let image = "sshunnel-netns:noble-0123456789ab";
        let contained = in_container(image, &inner, &mounts, Duration::from_secs(60)).unwrap();
        let workdir = std::env::current_dir().unwrap();
        assert_eq!(contained.get_program(), "docker");
        assert_eq!(contained.get_args().collect::<Vec<_>>(), docker_run(image, &mounts, &workdir, Duration::from_secs(60), &inner).unwrap());
    }

    #[test]
    fn namespaces_run_a_command_here_as_the_rerun_does_and_in_the_container_as_its_root() {
        let program = strings(&["/repo/target/debug/xtask", "bench-client"]);
        let mounts = [PathBuf::from("/repo/target")];
        let argv = |command: &Command| -> Vec<OsString> { std::iter::once(command.get_program()).chain(command.get_args()).map(OsStr::to_owned).collect() };

        // Here: the rerun's own namespaces (the probe checks those), then the program.
        let direct = Namespaces(Runner::Direct);
        let mut expected = namespaced();
        expected.extend(program.clone());
        assert_eq!(argv(&direct.command(&program, &mounts, Duration::from_secs(60)).unwrap()), expected);
        assert!(direct.command(&[], &mounts, Duration::from_secs(60)).is_err(), "nothing to run");
        assert_eq!(direct.to_string(), "user namespaces (unshare)");

        // In the container, the program itself as the container's root: in a user namespace of its
        // own, the files this user owns in the mounts would have an unmapped owner.
        let image = "sshunnel-netns:noble-0123456789ab";
        let docker = Namespaces(Runner::Docker { image: image.to_owned() });
        let workdir = std::env::current_dir().unwrap();
        let mut expected = vec![OsString::from("docker")];
        expected.extend(docker_run(image, &mounts, &workdir, Duration::from_secs(60), &program).unwrap());
        assert_eq!(argv(&docker.command(&program, &mounts, Duration::from_secs(60)).unwrap()), expected);
        assert!(docker.command(&[], &mounts, Duration::from_secs(60)).is_err(), "nothing to run");
        assert_eq!(docker.to_string(), "a privileged Docker container (sshunnel-netns:noble-0123456789ab)");
    }

    #[test]
    fn the_container_runs_the_rerun_as_root_with_the_build_read_only() {
        let inner = rerun(Path::new("/repo/target/debug/deps/route-0123"), "e2e_route_x");
        let mounts = [PathBuf::from("/repo"), PathBuf::from("/repo/target")];

        let args = docker_run("sshunnel-netns:noble", &mounts, Path::new("/repo"), Duration::from_secs(95), &inner).unwrap();

        let mut expected = strings(&[
            "run",
            "--rm",
            "--init",
            "--privileged",
            "--network",
            "none",
            "--volume",
            "/repo:/repo:ro",
            "--volume",
            "/repo/target:/repo/target:ro",
            "--workdir",
            "/repo",
            "--env",
            "SSHUNNEL_IN_NETNS=1",
            "--env",
            "CI",
            "sshunnel-netns:noble",
            "timeout",
            "95",
        ]);
        expected.extend(inner);
        assert_eq!(args, expected);

        // `--volume` splits on colons.
        assert!(docker_run("sshunnel-netns:noble", &[PathBuf::from("/a:b")], Path::new("/repo"), CONTAINER_TIMEOUT, &[]).is_err());
    }

    #[test]
    fn the_container_outlives_no_test() {
        // nextest kills a test after `terminate-after` slow periods; the container must end first.
        let config = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(".config/nextest.toml")).unwrap();
        let slow = config.lines().find_map(|line| line.strip_prefix("slow-timeout = ")).expect("nextest.toml sets a slow-timeout");
        let field = |name: &str| slow.split(name).nth(1).and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).find(|s| !s.is_empty()));
        let period: u64 = field("period").unwrap().parse().unwrap();
        let after: u32 = field("terminate-after").unwrap().parse().unwrap();

        assert!(CONTAINER_TIMEOUT < Duration::from_secs(period) * after, "nextest kills a test at {period} s x {after}");
    }
}
