//! The namespace harness for `route`'s e2e tests. [`netns`] runs a test again as root over fresh
//! user, mount, PID and network namespaces, where it can create a TUN device, routes and bind mounts
//! without touching the machine, and [`RemoteNs`] is a second network namespace, joined to the first
//! by a veth pair, that plays the remote's network.
//!
//! Ubuntu (23.10 on) restricts unprivileged user namespaces through `AppArmor`. There, the test
//! runs again in a privileged Docker container built from the host's own Ubuntu release, so the
//! binaries cargo built here run in it unchanged and nobody changes a sysctl to run `cargo make ci`.

use std::{
    ffi::OsString,
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

use crate::base::{Err, Res, Void};

/// Set for the test run again inside: there, [`netns`] lets the body run.
const INSIDE: &str = "SSHUNNEL_IN_NETNS";
/// `docker` forces the container even where user namespaces work, so CI keeps that path from rotting.
const FORCE: &str = "SSHUNNEL_NETNS";
/// How long a test has, from entering [`netns`], to finish in its container: under nextest's 120 s
/// kill (`.config/nextest.toml`), since a killed `docker run` leaves its container running.
const CONTAINER_TIMEOUT: Duration = Duration::from_secs(110);

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
    format!("no network namespaces: `unshare -rn` fails, and the container can't stand in ({why:#})")
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
    let outer = ["unshare", "-rmp", "--fork", "--kill-child", "--mount-proc", "sh", "-c", r#"unshare -n "$@"; exit $?"#, "sh"];
    let mut command: Vec<OsString> = outer.map(OsString::from).into();
    command.push(exe.into());
    command.extend(["--exact", test, "--nocapture", "--include-ignored"].map(OsString::from));
    command
}

/// Where the test runs again.
enum Runner {
    /// Here, where `unshare -rn` works.
    Direct,
    /// In a container of this Ubuntu release.
    Docker { codename: String },
}

impl Runner {
    /// The container when [`FORCE`]d; else here, where user namespaces work; else the container,
    /// where it can run. The inner `Err` says why the container can't.
    fn pick() -> Res<Result<Self, Err>> {
        match std::env::var(FORCE) {
            Ok(choice) if choice == "docker" => return docker_codename().map(|codename| Ok(Self::Docker { codename })),
            Ok(choice) => bail!("{FORCE}={choice}: the one choice is `docker`"),
            Err(_) => {}
        }
        if succeeds(Command::new("unshare").args(["-rn", "true"])) {
            return Ok(Ok(Self::Direct));
        }
        Ok(docker_codename().map(|codename| Self::Docker { codename }))
    }

    /// The [`rerun`] of `test` in `exe`, where this runner runs it, with [`INSIDE`] set. A container
    /// gets what is left of [`CONTAINER_TIMEOUT`] since `entered`, after any image build.
    fn command(&self, exe: &Path, test: &str, entered: Instant) -> Res<Command> {
        let inner = rerun(exe, test);
        match self {
            Self::Direct => {
                let (program, args) = inner.split_first().context("the command is empty")?;
                let mut command = Command::new(program);
                command.args(args).env(INSIDE, "1");
                Ok(command)
            }
            Self::Docker { codename } => {
                let image = image(codename)?;
                let limit = CONTAINER_TIMEOUT
                    .checked_sub(entered.elapsed())
                    .filter(|left| left.as_secs() > 0)
                    .context("building the image took the test's whole time")?;
                let mounts = [PathBuf::from(env!("CARGO_MANIFEST_DIR")), target_dir(exe)?];
                let workdir = std::env::current_dir().context("reading the working directory")?;
                let mut command = Command::new("docker");
                command.args(docker_run(&image, &mounts, &workdir, limit, &inner)?);
                Ok(command)
            }
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

/// The image's tag, one per Ubuntu release.
fn image_tag(codename: &str) -> String {
    format!("sshunnel-netns:{codename}")
}

/// The image: the host's Ubuntu release plus iproute2, so its glibc is the host's.
fn dockerfile(codename: &str) -> String {
    format!(
        "FROM ubuntu:{codename}\n\
         RUN apt-get update && apt-get install -y --no-install-recommends iproute2 && rm -rf /var/lib/apt/lists/*\n"
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
/// `10.99.0.0/16` or `fd99::/64` but a route's device. A `sleep` holds the namespace and is killed on
/// drop.
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
    /// ssh's peer, inside `10.98.0.0/16` and reached through the veth.
    pub const PEER: Ipv4Addr = Ipv4Addr::new(10, 98, 0, 2);

    /// Makes the namespace and wires both ends.
    ///
    /// # Errors
    ///
    /// Fails outside a network namespace of the test's own (see [`netns`]), or when `ip` fails.
    pub fn new() -> Res<Self> {
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
        let local: [&[&str]; 5] = [
            &["link", "set", "lo", "up"],
            &["link", "add", Self::LINK, "type", "veth", "peer", "name", "rm0", "netns", &pid],
            &["addr", "add", "172.31.0.1/30", "dev", Self::LINK],
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
    fn a_skip_says_why_the_container_cant_stand_in() {
        let skip = unavailable(&anyhow!("`docker info` fails: Docker isn't usable"));

        assert!(skip.contains("unshare -rn") && skip.contains("`docker info` fails"), "{skip}");
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

        assert_eq!(image_tag("noble"), "sshunnel-netns:noble");
        let dockerfile = dockerfile("noble");
        assert!(dockerfile.starts_with("FROM ubuntu:noble\n") && dockerfile.contains("iproute2"), "{dockerfile}");
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
