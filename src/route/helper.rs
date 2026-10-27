//! The root helper, both sides of its socket. `sshunnel route` listens on a unix socket in a
//! private directory and starts `sshunnel helper` through sudo. The helper connects back, takes the
//! targets, sets up [`DEVICE`] as root and hands its fd over the socket (sudo closes inherited fds
//! and may put the helper on a pty, so the socket carries everything). It then holds the device and
//! its pinned routes until the socket closes or a signal arrives, deletes the pins and then the
//! device, and exits. Deleting the device, rather than leaving it to go with the last fd, means it
//! can't outlive the helper whatever the client does with its own fd.
//!
//! The helper is the privilege boundary, not the client. With a `NOPASSWD` sudoers line anything
//! running as the user can start it, so it takes targets, never routes or domains: it parses them
//! again, re-runs every refusal against its own route snapshot, honors only pins inside a route,
//! and works out their gateways itself. Whether matched names get fake v6 addresses is its call too
//! ([`decide_fake_v6`]), reported in [`Reply::Ready`]. What it runs is a closed set ([`plan`]).

use std::{
    ffi::{OsStr, OsString},
    fmt::{self, Display},
    fs::{DirBuilder, File},
    io::{self, ErrorKind, IoSlice, IoSliceMut, Read as _},
    mem::MaybeUninit,
    net::IpAddr,
    os::{
        fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd},
        unix::fs::DirBuilderExt as _,
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context as _, anyhow, bail, ensure};
use ipnet::IpNet;
use rustix::{
    fs::{CWD, FileType, Mode, OFlags, fstat, openat},
    net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, recvmsg, sendmsg, sockopt::socket_peercred},
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader, Interest},
    net::{UnixListener, UnixStream},
    process::{Child, Command},
    signal::unix::{Signal, SignalKind, signal},
    time::timeout,
};

use crate::{
    base::{Res, Void},
    route::{
        DEVICE, DNS_ADDR, FAKE_RANGE, FAKE_RANGE6, MTU, PIN_PROTO, TUN_ADDR, TUN_ADDR6, reverse,
        system::{self, Via},
        targets::{MAX_ROUTES, Targets},
    },
};

/// The longest message either side reads: a setup or a reply, each one JSON line.
const MAX_MESSAGE: usize = 64 * 1024;
/// Attempts at a fresh socket directory; a random name collides only by astronomical luck.
const DIR_ATTEMPTS: u32 = 8;

/// What the client asks for: the targets as the user wrote them, and the addresses the machine
/// depends on (ssh's peers, its DNS servers), which keep their route where a target covers them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Setup {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub pins: Vec<IpAddr>,
}

/// The helper's one answer. `Ready` arrives with the device's fd, and says whether matched names get
/// fake v6 addresses: the helper decides, since only it knows whether the device took its v6 address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    Ready { warnings: Vec<String>, fake_v6: bool },
    Failed { error: String },
}

/// The client's handle on a running helper. Dropping it closes the socket, and the helper tears
/// down and exits.
pub struct Helper {
    tun: Option<OwnedFd>,
    warnings: Vec<String>,
    fake_v6: bool,
    conn: UnixStream,
    /// sudo, or the helper itself when already root.
    child: Child,
}

impl Helper {
    /// Starts the helper (through sudo unless already root), sends it `setup` and waits for the
    /// device. sudo may ask for a password on the terminal meanwhile.
    ///
    /// # Errors
    ///
    /// Fails, leaving nothing behind, when sudo is missing or declines, the helper isn't root, or
    /// the helper refuses the targets or can't set the device up.
    pub async fn start(setup: &Setup) -> Res<Self> {
        let exe = std::env::current_exe().context("locating sshunnel's own executable")?;
        let euid = rustix::process::geteuid().as_raw();
        Self::start_with(setup, &runtime_dir(), |socket| command(&exe, socket, euid)).await
    }

    /// [`Self::start`] with the socket's parent dir and the command line chosen by the caller.
    pub(crate) async fn start_with(setup: &Setup, base: &Path, command_line: impl FnOnce(&Path) -> Vec<OsString>) -> Res<Self> {
        let dir = SocketDir::create(base)?;
        let socket = dir.0.join("helper.sock");
        let listener = UnixListener::bind(&socket).with_context(|| format!("listening on {}", socket.display()))?;

        let line = command_line(&socket);
        let (program, args) = line.split_first().context("the helper command is empty")?;
        let program = Path::new(program);
        let mut child = helper_process(program, args).spawn().with_context(|| format!("starting {}", program.display()))?;

        let handshake = handshake(&listener, &mut child, program, setup).await;
        // The path is done with either way: the helper connected, or now can't.
        drop((listener, dir));
        match handshake {
            Ok((conn, tun, Ready { warnings, fake_v6 })) => Ok(Self {
                tun: Some(tun),
                warnings,
                fake_v6,
                conn,
                child,
            }),
            Err(e) => {
                // A helper that connected undoes its work on EOF and exits, one that didn't fails
                // to connect, and sudo follows it out. sudo isn't killed: under `use_pty` that can
                // leave the terminal raw.
                let _ = child.wait().await;
                Err(e)
            }
        }
    }

    /// The device's fd; the netstack takes it once.
    ///
    /// # Errors
    ///
    /// Fails when it was already taken.
    pub fn take_tun(&mut self) -> Res<OwnedFd> {
        self.tun.take().context("the TUN device was already taken")
    }

    /// The refusal checks' warnings, as the helper found them.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Whether the helper routed [`FAKE_RANGE6`] to the device, so matched names get AAAA answers.
    #[must_use]
    pub fn fake_v6(&self) -> bool {
        self.fake_v6
    }

    /// Resolves when the helper's end of the socket closes: it died, or a signal stopped it.
    pub async fn closed(&mut self) {
        closed(&mut self.conn).await;
    }

    /// Closes the socket and waits for the helper to delete its pins and exit.
    ///
    /// # Errors
    ///
    /// Fails when the helper exits unsuccessfully, which means a pin may be left (the next start
    /// sweeps it).
    pub async fn stop(self) -> Void {
        let Self { tun, conn, mut child, .. } = self;
        drop((tun, conn));
        let status = child.wait().await.context("waiting for the root helper")?;
        ensure!(status.success(), "the root helper exited with {status}");
        Ok(())
    }
}

/// The command line that starts the helper on `socket`: through sudo, unless already root.
#[must_use]
pub fn command(exe: &Path, socket: &Path, euid: u32) -> Vec<OsString> {
    command_with(OsStr::new("sudo"), exe, socket, euid)
}

fn command_with(sudo: &OsStr, exe: &Path, socket: &Path, euid: u32) -> Vec<OsString> {
    let sudo = (euid != 0).then_some([sudo, OsStr::new("--")]);
    sudo.into_iter().flatten().chain(helper_args(exe, socket)).map(OsStr::to_owned).collect()
}

/// `sshunnel helper` on `socket`, as `exe`.
fn helper_args<'a>(exe: &'a Path, socket: &'a Path) -> [&'a OsStr; 4] {
    [exe.as_os_str(), OsStr::new("helper"), OsStr::new("--socket"), socket.as_os_str()]
}

/// What sudo does with the helper when it may not ask for a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sudo {
    /// Already root: `route` starts the helper without sudo.
    AlreadyRoot,
    /// sudo starts the helper without asking.
    NoPrompt,
    /// sudo wouldn't start the helper without asking: for a password, or by refusing.
    Prompts,
}

/// How long the probe waits for sudo to answer, and then for it to exit.
pub(crate) const PROBE_WITHIN: Duration = Duration::from_secs(10);

/// Whether `route` would start the helper without asking, found by asking sudo itself: it starts
/// the helper as `route` does but through `sudo -n -k`, and hangs up as soon as the helper
/// connects, before the helper has changed anything. Listing the rules instead (`sudo -n -l`)
/// succeeds for a password rule beside an unrelated `NOPASSWD` one. `-k` ignores a cached sudo
/// timestamp for this one call (without clearing it): the question is whether sudo asks once that
/// has expired, not whether it happens to be fresh now.
///
/// # Errors
///
/// Fails when sudo can't be started or doesn't answer within 10 s, or when what connects isn't
/// root.
pub async fn probe_sudo() -> Res<Sudo> {
    let exe = std::env::current_exe().context("locating sshunnel's own executable")?;
    probe_sudo_for(&exe).await
}

/// [`probe_sudo`] for the helper as the binary at `exe` would start it.
pub(crate) async fn probe_sudo_for(exe: &Path) -> Res<Sudo> {
    if rustix::process::geteuid().is_root() {
        return Ok(Sudo::AlreadyRoot);
    }
    probe_with(&runtime_dir(), |socket| probe_command(exe, socket), PROBE_WITHIN).await
}

/// [`probe_sudo`] with the socket's parent dir, the command line and the wait chosen by the caller.
pub(crate) async fn probe_with(base: &Path, command_line: impl FnOnce(&Path) -> Vec<OsString>, within: Duration) -> Res<Sudo> {
    let dir = SocketDir::create(base)?;
    let socket = dir.0.join("helper.sock");
    let listener = UnixListener::bind(&socket).with_context(|| format!("listening on {}", socket.display()))?;

    let line = command_line(&socket);
    let (program, args) = line.split_first().context("the probe's command is empty")?;
    let program = Path::new(program);
    // Nothing of sudo's reaches the terminal: a refusal is the answer, not an error to show.
    let mut child = helper_process(program, args).stderr(Stdio::null()).spawn().with_context(|| format!("starting {}", program.display()))?;

    let answer = timeout(within, async {
        tokio::select! {
            biased;
            accepted = listener.accept() => Ok(Some(accepted.context("accepting the helper's connection")?.0)),
            status = child.wait() => status.map(|_| None).with_context(|| format!("waiting for {}", program.display())),
        }
    })
    .await;
    // On a timeout sudo is left to finish, as `start_with` leaves it: the socket dir goes with this
    // return, so a helper that starts late can't connect and exits.
    let Some(conn) = answer.map_err(|_| anyhow!("{} didn't answer within {} s", program.display(), within.as_secs_f64()))?? else {
        return Ok(Sudo::Prompts);
    };

    let root = root_peer(&conn);
    // A helper hung up on before its setup arrives exits having changed nothing, and sudo follows
    // it out. Waited for, so no root helper outlives the probe.
    drop((conn, listener, dir));
    if timeout(within, child.wait()).await.is_err() {
        tracing::warn!("{} is still running {} s after the probe hung up on the root helper", program.display(), within.as_secs_f64());
    }
    root.map(|()| Sudo::NoPrompt)
}

/// The command line that probes sudo with the helper on `socket`: [`command`]'s, through
/// `sudo -n -k`, which fails rather than ask for a password, and ignores a cached sudo timestamp.
pub(crate) fn probe_command(exe: &Path, socket: &Path) -> Vec<OsString> {
    ["sudo", "-n", "-k", "--"].map(OsStr::new).into_iter().chain(helper_args(exe, socket)).map(OsStr::to_owned).collect()
}

/// The process that becomes the helper. It never inherits `SUDO_UID`: sudo sets its own, and a
/// client already root (run as `sudo sshunnel route`) starts the helper directly, which must then
/// serve root rather than the user who ran that sudo.
///
/// Nor does it get the terminal as stdin. sudo (under `use_pty`, and sudo-rs) puts a terminal on
/// the command's stdin into raw mode for as long as the command runs, so a Ctrl-C would reach the
/// helper alone, as a byte, rather than every process in the foreground group. sudo asks for a
/// password on `/dev/tty`, not stdin.
fn helper_process(program: &Path, args: &[OsString]) -> Command {
    let mut process = Command::new(program);
    process.args(args).env_remove("SUDO_UID").stdin(Stdio::null()).stdout(Stdio::null());
    process
}

/// What a `Ready` reply carries besides the fd.
struct Ready {
    warnings: Vec<String>,
    fake_v6: bool,
}

/// Accepts the helper's connection, checks it is root, sends the setup and reads the answer.
async fn handshake(listener: &UnixListener, child: &mut Child, program: &Path, setup: &Setup) -> Res<(UnixStream, OwnedFd, Ready)> {
    let mut conn = tokio::select! {
        biased;
        accepted = listener.accept() => accepted.context("accepting the helper's connection")?.0,
        status = child.wait() => {
            let status = status.with_context(|| format!("waiting for {}", program.display()))?;
            // sudo's own prompt may have gone unanswered: no terminal, or an agent running route.
            let hint = if program.file_name() == Some(OsStr::new("sudo")) {
                "; if it asked for a password nobody could type, `sshunnel sudoers` prints the setup that skips it"
            } else {
                ""
            };
            bail!("{} exited before the root helper started ({status}){hint}", program.display());
        }
    };

    root_peer(&conn)?;

    conn.write_all(&encode(setup)?).await.context("sending the setup to the helper")?;
    match receive(&conn).await? {
        (Reply::Ready { warnings, fake_v6 }, Some(tun)) => Ok((conn, tun, Ready { warnings, fake_v6 })),
        (Reply::Ready { .. }, None) => bail!("the root helper sent no TUN device"),
        (Reply::Failed { error }, _) => bail!("the root helper failed: {error}"),
    }
}

/// Refuses a helper whose end of the socket isn't root: anything the user runs could connect.
fn root_peer(conn: &UnixStream) -> Void {
    let peer = socket_peercred(conn).context("reading the helper's credentials")?.uid;
    ensure!(peer.is_root(), "the helper's end of the socket is not root (uid {})", peer.as_raw());
    Ok(())
}

/// `sshunnel helper --socket <path>`, run as root: connect to the client, set the device up as it
/// asks if its targets pass every check here, and hand over the fd. Then hold the device and its
/// pins until the socket closes or SIGINT, SIGTERM or SIGHUP arrives (a Ctrl-C reaches the helper
/// through sudo too), and delete them.
///
/// # Errors
///
/// Fails when the client can't be reached or isn't the user who ran sudo, when the setup is refused
/// or fails (after telling the client and undoing what was done; marked [`Reported`] once the
/// client has it), or when a pin or the device can't be deleted.
pub async fn serve(socket: &Path) -> Void {
    let uid = served_uid(std::env::var_os("SUDO_UID").as_deref(), rustix::process::getuid().as_raw())?;
    serve_with(socket, uid).await
}

/// [`serve`] for the user `uid`.
async fn serve_with(socket: &Path, uid: u32) -> Void {
    // First, so a signal during setup ends in the teardown below instead of killing the helper midway.
    let mut signals = Signals::new()?;
    let mut conn = connect_client(socket, uid).await?;

    // The handlers replaced the default disposition, so every wait must watch them: a client that
    // connects and stalls must not leave a root helper deaf to Ctrl-C.
    let setup = tokio::select! {
        setup = read_setup(&mut conn) => setup,
        () = signals.recv() => bail!("stopped by a signal before the setup arrived"),
    };
    let (applied, Ready { warnings, fake_v6 }) = match setup.and_then(|setup| apply(&setup)) {
        Ok(applied) => applied,
        // The client prints what it is sent, on the terminal the helper shares through sudo, so
        // the helper reports an error itself only when the client is gone.
        Err(e) => {
            return match send(&mut conn, &Reply::Failed { error: format!("{e:#}") }, None).await {
                Ok(()) => Err(e.context(Reported)),
                Err(_) => Err(e),
            };
        }
    };

    let delivered = send(&mut conn, &Reply::Ready { warnings, fake_v6 }, applied.tun.as_ref().map(|tun| tun.as_fd())).await;
    if delivered.is_ok() {
        tokio::select! {
            () = closed(&mut conn) => {}
            () = signals.recv() => {}
        }
    }
    // Closed before the device goes, so a client still running hears the helper is stopping rather
    // than finding its device gone. It waits for this process to exit all the same.
    drop(conn);
    let torn_down = applied.teardown();
    delivered.and(torn_down)
}

/// Marks the helper's error once the client has it: the client prints it, so `sshunnel helper`
/// exits non-zero without printing it again.
#[derive(Debug)]
pub struct Reported;

impl Display for Reported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("reported to sshunnel route")
    }
}

impl std::error::Error for Reported {}

/// The helper serves only the user it acts for: the one who ran sudo, or without sudo its own user
/// (root, who could do all of this anyway).
fn served_uid(sudo_uid: Option<&OsStr>, own: u32) -> Res<u32> {
    match sudo_uid {
        Some(uid) => uid.to_str().and_then(|uid| uid.parse().ok()).with_context(|| format!("SUDO_UID is not a uid: '{}'", uid.display())),
        None => Ok(own),
    }
}

/// Connects to the client's socket only if it is a socket `uid` owns. The path is the caller's
/// choice, so it is opened without following a final symlink and checked through that fd, and the
/// connect goes through the same fd, so the name can't be swapped in between. A root connect to
/// anything else could start a socket-activated root service, and its errno would tell the caller
/// what root sees, so every refusal reads the same.
async fn connect_client(socket: &Path, uid: u32) -> Res<UnixStream> {
    let refused = || anyhow!("the helper's socket is not a socket of the user it serves");
    let path = openat(CWD, socket, OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(|_| refused())?;
    let stat = fstat(&path).map_err(|_| refused())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Socket || stat.st_uid != uid {
        return Err(refused());
    }

    let conn = UnixStream::connect(format!("/proc/self/fd/{}", path.as_raw_fd())).await.map_err(|_| refused())?;
    // Before a byte crosses: whoever listens there must be that user too.
    let peer = socket_peercred(&conn).map_err(|_| refused())?.uid.as_raw();
    ensure!(peer == uid, "the socket belongs to uid {peer}, not to the user the helper serves (uid {uid})");
    Ok(conn)
}

/// How long [`Signals::arrived`] waits for a signal that was sent before the call: one already
/// delivered to the process only has to reach tokio's driver, so this is short.
const SIGNAL_GRACE: Duration = Duration::from_millis(100);

/// SIGINT, SIGTERM and SIGHUP, the ways a terminal or a service manager asks sshunnel to stop. The
/// helper treats them like its socket closing: a Ctrl-C reaches it through sudo too, and it must
/// still delete its pins. `sshunnel route` tears down on them, except a SIGHUP it started out
/// ignoring.
pub(crate) struct Signals {
    interrupt: Signal,
    terminate: Signal,
    /// `None` while SIGHUP stays ignored.
    hangup: Option<Signal>,
}

impl Signals {
    /// Handles all three from now on, in place of their default (killing the process).
    pub(crate) fn new() -> Res<Self> {
        Self::handling(true)
    }

    /// As [`Self::new`], but a SIGHUP ignored at startup stays ignored: handling it would undo
    /// `nohup`. When that can't be read, SIGHUP is handled.
    pub(crate) fn respecting_nohup() -> Res<Self> {
        Self::respecting(system::sighup_ignored())
    }

    /// [`Self::respecting_nohup`] with what reading SIGHUP's disposition found. Failing to read it
    /// fails safe: handled, a hangup still tears down in order, and the run goes on.
    fn respecting(ignored: Res<bool>) -> Res<Self> {
        let ignored = ignored.unwrap_or_else(|e| {
            tracing::debug!("handling SIGHUP, since whether it was ignored is unknown: {e:#}");
            false
        });
        Self::handling(!ignored)
    }

    fn handling(hangup: bool) -> Res<Self> {
        let handle = |kind: SignalKind, name: &str| signal(kind).with_context(|| format!("handling {name}"));
        Ok(Self {
            interrupt: handle(SignalKind::interrupt(), "SIGINT")?,
            terminate: handle(SignalKind::terminate(), "SIGTERM")?,
            hangup: hangup.then(|| handle(SignalKind::hangup(), "SIGHUP")).transpose()?,
        })
    }

    /// Whether a signal arrives within [`SIGNAL_GRACE`]: a bound for one already delivered to reach
    /// tokio's driver, as when Ctrl-C ended the process that just failed.
    pub(crate) async fn arrived(&mut self) -> bool {
        timeout(SIGNAL_GRACE, self.recv()).await.is_ok()
    }

    /// Resolves at the next signal, or at once for one that arrived since the last call.
    pub(crate) async fn recv(&mut self) {
        let Self { interrupt, terminate, hangup } = self;
        let hangup = async {
            match hangup {
                Some(hangup) => drop(hangup.recv().await),
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
            () = hangup => {}
        }
    }
}

/// What the helper holds while the client runs: the device, and the pins it added, undone by `run`.
/// Dropped without [`Self::teardown`], by an early return or a panic, it still undoes them, and never
/// twice.
struct Applied<R: FnMut(&Step) -> Void = fn(&Step) -> Void> {
    /// `None` once undone.
    tun: Option<OwnedFd>,
    pins: Vec<IpAddr>,
    run: R,
}

impl<R: FnMut(&Step) -> Void> Applied<R> {
    /// [`Self::undo`], reporting what failed.
    fn teardown(mut self) -> Void {
        self.undo()
    }

    /// Deletes the pins, then the device, while this fd still holds it, and lets the fd go with its
    /// persist flag cleared. Deleted, the device can't outlive the helper, even when the client set
    /// that flag through its own fd (no capability needed) after this one closed; its routes and
    /// resolver config go with it. Holding the device until the pins are gone means no new session
    /// can start in between and lose a pin of the same address to this one's delete.
    fn undo(&mut self) -> Void {
        let Some(tun) = self.tun.take() else { return Ok(()) };
        let unpinned = unpin(&self.pins, &mut self.run);
        let deleted = delete_device(&mut self.run);
        let released = system::release_tun(tun);
        unpinned.and(deleted).and(released)
    }
}

impl<R: FnMut(&Step) -> Void> Drop for Applied<R> {
    fn drop(&mut self) {
        if let Err(e) = self.undo() {
            tracing::warn!("{e:#}");
        }
    }
}

/// Checks `setup` again and sets the device up. A failure after the device exists undoes the pins
/// first and drops the fd, which takes the device and everything on it along.
fn apply(setup: &Setup) -> Res<(Applied, Ready)> {
    let targets = Targets::parse(&setup.include, &setup.exclude)?;
    let ipv6 = system::has_ipv6();
    if let Some(refusal) = targets.ipv6_refusal(ipv6) {
        bail!("refused:\n  {refusal}");
    }
    let snapshot = system::snapshot()?;
    let mut warnings = targets.check(&snapshot)?;
    // resolvectl names the link by index, and resolved serves pid 1's namespace: from another one,
    // the config would land on whatever link has the same index there.
    ensure!(
        !targets.has_names() || system::same_netns_as_init(),
        "domain patterns need the host's network namespace, where systemd-resolved runs"
    );
    let routes = targets.routes();
    let pins = honored(&routes, &setup.pins, &snapshot.hosts);
    within_cap(&routes, &pins)?;

    let tun = system::create_tun()?;
    let fake_v6 = decide_fake_v6(&targets, &mut run_step);
    // Holding the device means no other session is running, so any pinned route left is a dead one's.
    let proto = PIN_PROTO.to_string();
    for &family in system::families(ipv6) {
        system::run("ip", &[family, "route", "flush", "proto", &proto])?;
    }
    // Each pin copies the route its address has before the device has any.
    let vias = pins.into_iter().map(|pin| Ok((pin, system::route_get(pin)?))).collect::<Res<Vec<_>>>()?;
    let plan = plan(&targets, &routes, &vias, fake_v6);
    let pins = execute(&plan.steps, &mut run_step)?;
    warnings.extend(plan.warnings);

    Ok((Applied { tun: Some(tun), pins, run: run_step }, Ready { warnings, fake_v6 }))
}

/// The pins a route would capture, each once. A pin outside every route needs nothing, and is never
/// routed: pins can't add host routes of their own. Nor does one with a host route of its own in
/// `hosts` (the main table's), which outranks every route but one to that very host.
fn honored(routes: &[IpNet], pins: &[IpAddr], hosts: &[IpAddr]) -> Vec<IpAddr> {
    let captured = |pin: &IpAddr| {
        let host = IpNet::from(*pin);
        routes.contains(&host) || (!hosts.contains(pin) && routes.iter().any(|route| route.contains(pin)))
    };
    let mut honored: Vec<IpAddr> = pins.iter().copied().filter(captured).collect();
    honored.sort_unstable();
    honored.dedup();
    honored
}

/// Refuses more routes and pins together than [`MAX_ROUTES`]: each pin is root's `ip` as a route
/// is, a lookup, an add and a delete. `Targets::parse` has capped the routes alone; only the helper
/// can count the pins, since the client finds them after ssh starts and the helper decides which
/// it honors.
fn within_cap(routes: &[IpNet], pins: &[IpAddr]) -> Void {
    let total = routes.len() + pins.len();
    ensure!(
        total <= MAX_ROUTES,
        "the targets' {} routes and {} pinned addresses come to {total}, more than the {MAX_ROUTES} sshunnel adds",
        routes.len(),
        pins.len()
    );
    Ok(())
}

/// One command the helper runs as root. A pin is remembered, so a failure or teardown deletes it.
struct Step {
    program: &'static str,
    args: Vec<String>,
    pin: Option<IpAddr>,
}

impl Step {
    fn new<const N: usize>(program: &'static str, args: [&str; N]) -> Self {
        Self {
            program,
            args: args.map(str::to_owned).into(),
            pin: None,
        }
    }
}

impl Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.program)?;
        for arg in &self.args {
            write!(f, " {arg}")?;
        }
        Ok(())
    }
}

/// What the helper will run, and what it decided along the way that the user should hear.
struct Plan {
    steps: Vec<Step>,
    warnings: Vec<String>,
}

/// Everything the helper does to the machine, in order: the device's addresses, MTU and link; the
/// pins, before a route could capture what they keep; the routes, and [`FAKE_RANGE6`]'s with fake v6
/// on; and with names, the resolver's link config (the patterns' domains and the fake ranges' reverse
/// zones), DNS server last, so resolved never takes the link for a default route.
///
/// A pin whose address the machine delivers locally needs nothing (the local table outranks main),
/// and a route that is exactly a pinned host is left out: the pin wins.
fn plan(targets: &Targets, routes: &[IpNet], vias: &[(IpAddr, Via)], fake_v6: bool) -> Plan {
    let pins: Vec<(IpNet, &Via)> = vias.iter().filter(|(_, via)| via.unicast).map(|(pin, via)| (IpNet::from(*pin), via)).collect();
    let mut warnings = Vec::new();
    let mut device_routes = Vec::with_capacity(routes.len());
    for route in routes {
        if pins.iter().any(|(host, _)| host == route) {
            warnings.push(format!("{route} keeps its current route: the machine depends on it (ssh's peer or a DNS server)"));
        } else {
            device_routes.push(route);
        }
    }

    let mut steps = vec![Step::new("ip", ["addr", "add", &format!("{TUN_ADDR}/{}", FAKE_RANGE.prefix_len()), "dev", DEVICE])];
    // Only v6 routes and fake v6 need a v6 source, and adding one where IPv6 is disabled would fail
    // every run. With fake v6 on, `decide_fake_v6` added it already; otherwise v6 routes add it here,
    // and where its trial failed, this fails the run.
    if !fake_v6 && device_routes.iter().any(|route| matches!(route, IpNet::V6(_))) {
        steps.push(addr6());
    }
    steps.push(Step::new("ip", ["link", "set", "dev", DEVICE, "mtu", &MTU.to_string(), "up"]));

    let proto = PIN_PROTO.to_string();
    for (host, via) in &pins {
        let dst = host.to_string();
        let mut step = match via.gateway {
            Some(gateway) => Step::new("ip", ["route", "add", &dst, "via", &gateway.to_string(), "dev", &via.dev, "proto", &proto]),
            None => Step::new("ip", ["route", "add", &dst, "dev", &via.dev, "proto", &proto]),
        };
        step.pin = Some(host.addr());
        steps.push(step);
    }
    steps.extend(device_routes.into_iter().map(device_route));
    if fake_v6 {
        steps.push(device_route(&IpNet::V6(FAKE_RANGE6)));
    }

    if targets.has_names() {
        steps.push(Step::new("resolvectl", ["default-route", DEVICE, "false"]));
        steps.push(Step::new("resolvectl", ["dnssec", DEVICE, "no"]));
        steps.push(Step::new("resolvectl", ["dnsovertls", DEVICE, "no"]));
        let mut domain = Step::new("resolvectl", ["domain", DEVICE]);
        domain.args.extend(targets.domains().into_iter().map(|d| format!("~{d}")));
        // The fake ranges' reverse zones, so a PTR lookup of a fake address reaches the DNS server.
        domain.args.extend(reverse::zones(fake_v6).into_iter().map(|zone| format!("~{zone}")));
        steps.push(domain);
        steps.push(Step::new("resolvectl", ["dns", DEVICE, &DNS_ADDR.to_string()]));
    }
    Plan { steps, warnings }
}

/// `route` on the device, at the metric the refusals checked for: v6 has to name it, since a 0 there
/// means 1024.
fn device_route(route: &IpNet) -> Step {
    let mut step = Step::new("ip", ["route", "add", &route.to_string(), "dev", DEVICE]);
    let metric = system::add_metric(route);
    if metric != 0 {
        step.args.extend(["metric".to_owned(), metric.to_string()]);
    }
    step
}

/// The device's v6 address.
fn addr6() -> Step {
    Step::new("ip", ["addr", "add", &TUN_ADDR6.to_string(), "dev", DEVICE])
}

/// Whether matched names get fake v6 addresses, run right after the device exists: only with names,
/// and only with the device's v6 address up, the source apps reach the fakes from. With names this
/// adds that address, and fake v6 is whether it took: a failure (IPv6 disabled) only turns fake v6
/// off, unless v6 routes need the address too, when the plan's own add fails the run.
fn decide_fake_v6(targets: &Targets, run: &mut impl FnMut(&Step) -> Void) -> bool {
    if !targets.has_names() {
        return false;
    }
    match run(&addr6()) {
        Ok(()) => true,
        Err(e) => {
            tracing::debug!("fake IPv6 is off, since the device can't have its IPv6 address: {e:#}");
            false
        }
    }
}

fn run_step(step: &Step) -> Void {
    system::run(step.program, &step.args)
}

/// Runs `steps` in order. When one fails, deletes the pins already added and returns its error.
fn execute(steps: &[Step], run: &mut impl FnMut(&Step) -> Void) -> Res<Vec<IpAddr>> {
    let mut pins = Vec::new();
    for step in steps {
        if let Err(e) = run(step) {
            return Err(match unpin(&pins, run) {
                Ok(()) => e,
                Err(undo) => anyhow!("{e:#}; and then {undo:#}"),
            });
        }
        pins.extend(step.pin);
    }
    Ok(pins)
}

/// Deletes [`DEVICE`] by name, which is this helper's while its fd holds the device. One already gone
/// (deleted under the fd mid-session) counts as deleted.
fn delete_device(run: &mut impl FnMut(&Step) -> Void) -> Void {
    match run(&Step::new("ip", ["link", "del", "dev", DEVICE])) {
        Err(e) if format!("{e:#}").contains("Cannot find device") => Ok(()),
        deleted => deleted,
    }
}

/// Deletes `pins`, newest first, trying every one.
fn unpin(pins: &[IpAddr], run: &mut impl FnMut(&Step) -> Void) -> Void {
    let proto = PIN_PROTO.to_string();
    let mut failed = Vec::new();
    for pin in pins.iter().rev() {
        if let Err(e) = run(&Step::new("ip", ["route", "del", &IpNet::from(*pin).to_string(), "proto", &proto])) {
            failed.push(format!("{pin}: {e:#}"));
        }
    }
    ensure!(
        failed.is_empty(),
        "deleting pinned routes failed (`ip route flush proto {PIN_PROTO}`, v4 and v6, removes them): {}",
        failed.join("; ")
    );
    Ok(())
}

/// Reads and drops whatever arrives until the other end closes, or the socket fails.
async fn closed(conn: &mut UnixStream) {
    let mut sink = [0; 256];
    while matches!(conn.read(&mut sink).await, Ok(n) if n > 0) {}
}

/// One message as a JSON line.
fn encode(message: &impl Serialize) -> Res<Vec<u8>> {
    let mut line = serde_json::to_vec(message).context("encoding a helper message")?;
    line.push(b'\n');
    Ok(line)
}

/// The client's setup: one line of at most [`MAX_MESSAGE`] bytes.
async fn read_setup(conn: &mut UnixStream) -> Res<Setup> {
    let mut line = Vec::new();
    BufReader::new(conn).take(MAX_MESSAGE as u64).read_until(b'\n', &mut line).await.context("reading the setup")?;
    ensure!(line.ends_with(b"\n"), "the setup was cut short or is longer than {MAX_MESSAGE} bytes");
    serde_json::from_slice(&line).context("parsing the setup")
}

/// Sends `reply`, with `tun` attached to its first byte when given.
async fn send(conn: &mut UnixStream, reply: &Reply, tun: Option<BorrowedFd<'_>>) -> Void {
    let line = encode(reply)?;
    let fds = tun.as_slice();
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() {
        ensure!(control.push(SendAncillaryMessage::ScmRights(fds)), "no room for the TUN fd in the control message");
    }

    let sent = conn
        .async_io(Interest::WRITABLE, || {
            sendmsg(&*conn, &[IoSlice::new(&line)], &mut control, SendFlags::NOSIGNAL).map_err(io::Error::from)
        })
        .await
        .context("sending the reply")?;
    conn.write_all(&line[sent..]).await.context("sending the reply")
}

/// The helper's reply, and the fd that came with it. Received fds are close-on-exec, so nothing
/// the client spawns later keeps the device alive.
async fn receive(conn: &UnixStream) -> Res<(Reply, Option<OwnedFd>)> {
    let mut line = Vec::new();
    let mut tun = None;
    let mut chunk = [0; 4096];
    loop {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let read = conn
            .async_io(Interest::READABLE, || {
                recvmsg(conn, &mut [IoSliceMut::new(&mut chunk)], &mut control, RecvFlags::CMSG_CLOEXEC).map_err(io::Error::from)
            })
            .await
            .context("reading the helper's reply")?
            .bytes;
        for message in control.drain() {
            if let RecvAncillaryMessage::ScmRights(mut fds) = message {
                // Anything past the first fd is closed as the iterator drops.
                tun = tun.or_else(|| fds.next());
            }
        }

        ensure!(read > 0, "the root helper closed the connection before replying");
        line.extend_from_slice(&chunk[..read]);
        if let Some(end) = line.iter().position(|&b| b == b'\n') {
            let reply = serde_json::from_slice(&line[..end]).context("parsing the helper's reply")?;
            return Ok((reply, tun));
        }
        ensure!(line.len() <= MAX_MESSAGE, "the helper's reply is longer than {MAX_MESSAGE} bytes");
    }
}

/// Where the socket's private dir goes: `$XDG_RUNTIME_DIR`, else the temp dir.
fn runtime_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR").filter(|dir| !dir.is_empty()).map_or_else(std::env::temp_dir, PathBuf::from)
}

/// A fresh directory only its owner can enter, removed with the socket in it on drop. `mkdir`
/// fails on an existing path, so the directory is always this process's own, and its name is
/// random, so no one can take it first (in a shared `/tmp`) and block the start.
struct SocketDir(PathBuf);

impl SocketDir {
    fn create(base: &Path) -> Res<Self> {
        let mut urandom = File::open("/dev/urandom").context("opening /dev/urandom")?;
        for _ in 0..DIR_ATTEMPTS {
            let mut nonce = [0; 8];
            urandom.read_exact(&mut nonce).context("reading /dev/urandom")?;
            let path = base.join(format!("sshunnel-{:016x}", u64::from_ne_bytes(nonce)));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e).with_context(|| format!("creating {}", path.display())),
            }
        }
        bail!("no free socket directory in {}", base.display())
    }
}

impl Drop for SocketDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::{os::unix::fs::MetadataExt as _, time::Duration};

    use pretty_assertions::assert_eq;
    use rustix::{
        io::{FdFlags, fcntl_getfd},
        process::{Signal, getpid, getuid, kill_process},
    };
    use tempfile::TempDir;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::tests::shim_dir;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn setup() -> Setup {
        Setup {
            include: strings(&["10.99.0.0/16", "*.corp.example"]),
            exclude: strings(&["10.99.128.0/17"]),
            pins: vec![addr("10.99.0.5"), addr("fd99::5")],
        }
    }

    /// An empty runtime dir in `root`, so a test can see what the client left in it.
    fn runtime_in(root: &TempDir) -> PathBuf {
        let runtime = root.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        runtime
    }

    fn rendered(steps: &[Step]) -> Vec<String> {
        steps.iter().map(ToString::to_string).collect()
    }

    fn via(dev: &str, gateway: Option<&str>) -> Via {
        Via {
            dev: dev.to_owned(),
            gateway: gateway.map(addr),
            unicast: true,
        }
    }

    /// The test plays the client: it owns a socket in `root`, and the helper serves its uid.
    fn serving(root: &TempDir) -> (UnixListener, JoinHandle<Void>) {
        let socket = root.path().join("helper.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let me = getuid().as_raw();
        (listener, tokio::spawn(async move { serve_with(&socket, me).await }))
    }

    /// What the helper answers `setup` with, playing the client against [`serving`].
    async fn reply_to(listener: &UnixListener, setup: &Setup) -> (Reply, Option<OwnedFd>) {
        let (mut client, _) = listener.accept().await.unwrap();
        client.write_all(&encode(setup).unwrap()).await.unwrap();
        receive(&client).await.unwrap()
    }

    /// A runner that records each command and fails the ones in `failing`.
    fn recorder<'a>(log: &'a mut Vec<String>, failing: &'a [&str]) -> impl FnMut(&Step) -> Void + 'a {
        move |step| {
            let command = step.to_string();
            let failed = failing.contains(&command.as_str());
            log.push(command);
            if failed {
                bail!("RTNETLINK answers: File exists");
            }
            Ok(())
        }
    }

    #[test]
    fn setup_round_trips_as_json() {
        let json = serde_json::to_string(&setup()).unwrap();

        assert!(json.contains(r#""pins":["10.99.0.5","fd99::5"]"#), "{json}");
        assert_eq!(serde_json::from_str::<Setup>(&json).unwrap(), setup());
        assert!(serde_json::from_str::<Setup>(r#"{"include":[],"exclude":[],"pins":[],"routes":["0.0.0.0/0"]}"#).is_err());

        let ready = Reply::Ready {
            warnings: strings(&["careful"]),
            fake_v6: true,
        };
        assert_eq!(serde_json::from_slice::<Reply>(&serde_json::to_vec(&ready).unwrap()).unwrap(), ready);
    }

    #[test]
    fn the_helper_runs_through_sudo_unless_root() {
        let exe = Path::new("/usr/local/bin/sshunnel");
        let socket = Path::new("/run/user/1000/sshunnel-7-0/helper.sock");

        assert_eq!(
            command(exe, socket, 1000),
            ["sudo", "--", "/usr/local/bin/sshunnel", "helper", "--socket", "/run/user/1000/sshunnel-7-0/helper.sock"].map(OsString::from)
        );
        assert_eq!(
            command(exe, socket, 0),
            ["/usr/local/bin/sshunnel", "helper", "--socket", "/run/user/1000/sshunnel-7-0/helper.sock"].map(OsString::from)
        );
    }

    /// [`probe_command`]'s line, with `sudo` in place of the real one.
    fn probing(sudo: &Path) -> impl FnOnce(&Path) -> Vec<OsString> + '_ {
        move |socket| {
            let mut line = probe_command(Path::new("sshunnel"), socket);
            line[0] = sudo.into();
            line
        }
    }

    #[test]
    fn sudo_probe_command_is_non_interactive() {
        let exe = Path::new("/usr/local/bin/sshunnel");
        let socket = Path::new("/run/user/1000/sshunnel-7-0/helper.sock");

        assert_eq!(
            probe_command(exe, socket),
            ["sudo", "-n", "-k", "--", "/usr/local/bin/sshunnel", "helper", "--socket", "/run/user/1000/sshunnel-7-0/helper.sock"].map(OsString::from)
        );
    }

    #[tokio::test]
    async fn sudo_probe_reads_a_sudo_that_exits_as_prompts() {
        let root = TempDir::new().unwrap();
        let runtime = runtime_in(&root);
        let sudo = shim_dir(root.path(), &[("sudo", "exit 1")]).unwrap().join("sudo");

        let probed = probe_with(&runtime, probing(&sudo), PROBE_WITHIN).await;

        assert_eq!(probed.unwrap(), Sudo::Prompts);
        assert_eq!(std::fs::read_dir(&runtime).unwrap().count(), 0, "the socket dir is left behind");
    }

    #[tokio::test]
    async fn sudo_probe_fails_on_a_missing_sudo() {
        let root = TempDir::new().unwrap();
        let runtime = runtime_in(&root);

        let error = probe_with(&runtime, probing(&root.path().join("no-such-sudo")), PROBE_WITHIN).await.unwrap_err();

        let error = format!("{error:#}");
        assert!(error.contains("no-such-sudo"), "{error}");
        assert_eq!(std::fs::read_dir(&runtime).unwrap().count(), 0, "the socket dir is left behind");
    }

    #[tokio::test]
    async fn sudo_probe_times_out_on_a_sudo_that_hangs() {
        let root = TempDir::new().unwrap();
        let runtime = runtime_in(&root);
        let sudo = shim_dir(root.path(), &[("sudo", "exec sleep 30")]).unwrap().join("sudo");

        let error = probe_with(&runtime, probing(&sudo), Duration::from_millis(200)).await.unwrap_err();

        let error = format!("{error:#}");
        assert!(error.contains("didn't answer within 0.2 s"), "{error}");
        assert_eq!(std::fs::read_dir(&runtime).unwrap().count(), 0, "the socket dir is left behind");
    }

    #[tokio::test]
    async fn sudo_probe_refuses_a_helper_that_is_not_root() {
        if getuid().is_root() {
            eprintln!("skipping: as root, the test's own connection is a root helper's");
            return;
        }
        let root = TempDir::new().unwrap();
        let runtime = runtime_in(&root);
        // Stands in for a helper still starting: it gives up once the socket is gone.
        let sudo = shim_dir(root.path(), &[("sudo", "for socket do :; done\nwhile [ -e \"$socket\" ]; do sleep 0.05; done")])
            .unwrap()
            .join("sudo");

        // The test answers the socket itself, as the unprivileged user running it.
        let probed = probe_with(
            &runtime,
            |socket| {
                let path = socket.to_owned();
                tokio::spawn(async move { UnixStream::connect(path).await });
                probing(&sudo)(socket)
            },
            PROBE_WITHIN,
        );
        let error = format!("{:#}", probed.await.unwrap_err());

        assert!(error.contains("not root"), "{error}");
        assert_eq!(std::fs::read_dir(&runtime).unwrap().count(), 0, "the socket dir is left behind");
    }

    #[test]
    fn the_helper_never_inherits_sudo_uid() {
        // Run as `sudo sshunnel route`, the client is root with the user's SUDO_UID, starts the
        // helper directly, and the helper would refuse its root peer. Through sudo, sudo sets it.
        let process = helper_process(Path::new("sudo"), &[]);

        assert!(process.as_std().get_envs().any(|(key, value)| key == "SUDO_UID" && value.is_none()));
    }

    #[tokio::test]
    async fn a_declined_sudo_is_a_clean_error() {
        let root = TempDir::new().unwrap();
        let runtime = runtime_in(&root);
        let sudo = shim_dir(root.path(), &[("sudo", "echo 'sudo: a password is required' >&2\nexit 1")]).unwrap().join("sudo");

        let Err(error) = Helper::start_with(&setup(), &runtime, |socket| command_with(sudo.as_os_str(), Path::new("sshunnel"), socket, 1000)).await else {
            panic!("a declined sudo started the helper");
        };

        let error = format!("{error:#}");
        assert!(error.contains("sudo") && error.contains("exit status: 1"), "{error}");
        assert_eq!(std::fs::read_dir(&runtime).unwrap().count(), 0, "the socket dir is left behind");
    }

    #[tokio::test]
    async fn a_declined_sudo_points_at_sudoers() {
        let root = TempDir::new().unwrap();
        let runtime = runtime_in(&root);
        let sudo = shim_dir(root.path(), &[("sudo", "echo 'sudo: a password is required' >&2\nexit 1")]).unwrap().join("sudo");

        let Err(error) = Helper::start_with(&setup(), &runtime, |socket| command_with(sudo.as_os_str(), Path::new("sshunnel"), socket, 1000)).await else {
            panic!("a declined sudo started the helper");
        };

        let error = format!("{error:#}");
        assert!(error.contains("`sshunnel sudoers` prints the setup that skips it"), "{error}");
    }

    #[tokio::test]
    async fn a_helper_started_as_root_never_points_at_sudoers() {
        let root = TempDir::new().unwrap();
        let runtime = runtime_in(&root);
        // Already root, `route` starts the helper itself, and no sudoers line would change a thing.
        let helper = shim_dir(root.path(), &[("sshunnel", "exit 1")]).unwrap().join("sshunnel");

        let Err(error) = Helper::start_with(&setup(), &runtime, |socket| command_with(OsStr::new("sudo"), &helper, socket, 0)).await else {
            panic!("a helper that exits started");
        };

        let error = format!("{error:#}");
        assert!(error.contains("exited before the root helper started"), "{error}");
        assert!(!error.contains("sudoers"), "{error}");
    }

    #[tokio::test]
    async fn sudo_never_gets_the_terminal_as_stdin() {
        let root = TempDir::new().unwrap();
        let runtime = runtime_in(&root);
        let seen = root.path().join("stdin");
        let sudo = shim_dir(root.path(), &[("sudo", &format!("readlink /proc/self/fd/0 > '{}'\nexit 1", seen.display()))])
            .unwrap()
            .join("sudo");
        // Stands in for the terminal `route` runs on: nextest gives a test /dev/null already, which
        // would hide an inherited stdin. nextest runs each test in its own process.
        rustix::stdio::dup2_stdin(File::create(root.path().join("terminal")).unwrap()).unwrap();

        let started = Helper::start_with(&setup(), &runtime, |socket| command_with(sudo.as_os_str(), Path::new("sshunnel"), socket, 1000)).await;

        assert!(started.is_err(), "the shim never starts a helper");
        // With the terminal as stdin, sudo would put it in raw mode for the whole session (under
        // `use_pty`), and a Ctrl-C would reach the helper alone.
        assert_eq!(std::fs::read_to_string(&seen).unwrap(), "/dev/null\n");
    }

    #[tokio::test]
    async fn a_missing_sudo_is_a_clean_error() {
        let root = TempDir::new().unwrap();
        let runtime = runtime_in(&root);
        let sudo = root.path().join("no-such-sudo");

        let Err(error) = Helper::start_with(&setup(), &runtime, |socket| command_with(sudo.as_os_str(), Path::new("sshunnel"), socket, 1000)).await else {
            panic!("a missing sudo started the helper");
        };

        let error = format!("{error:#}");
        assert!(error.contains("no-such-sudo"), "{error}");
        assert_eq!(std::fs::read_dir(&runtime).unwrap().count(), 0, "the socket dir is left behind");
    }

    #[tokio::test]
    async fn a_helper_that_is_not_root_is_refused() {
        let root = TempDir::new().unwrap();
        let runtime = runtime_in(&root);
        // Stands in for a helper still starting: it gives up once the socket is gone.
        let sudo = shim_dir(root.path(), &[("sudo", "for socket do :; done\nwhile [ -e \"$socket\" ]; do sleep 0.05; done")])
            .unwrap()
            .join("sudo");

        // The test answers the socket itself, as the unprivileged user running it.
        let setup = setup();
        let started = Helper::start_with(&setup, &runtime, |socket| {
            let path = socket.to_owned();
            tokio::spawn(async move { UnixStream::connect(path).await });
            command_with(sudo.as_os_str(), Path::new("sshunnel"), socket, 1000)
        });
        let Err(error) = started.await else {
            panic!("an unprivileged peer passed for the helper");
        };

        let error = format!("{error:#}");
        assert!(error.contains("not root"), "{error}");
        assert_eq!(std::fs::read_dir(&runtime).unwrap().count(), 0, "the socket dir is left behind");
    }

    #[test]
    fn the_helper_serves_only_the_user_who_ran_sudo() {
        assert_eq!(served_uid(Some(OsStr::new("1000")), 0).unwrap(), 1000);
        assert_eq!(served_uid(None, 0).unwrap(), 0, "without sudo, root serves root");

        for sudo_uid in ["not-a-uid", "", "-1"] {
            assert!(served_uid(Some(OsStr::new(sudo_uid)), 0).is_err(), "SUDO_UID={sudo_uid} was taken for a uid");
        }
    }

    #[tokio::test]
    async fn the_helper_connects_only_to_a_socket_its_user_owns() {
        let root = TempDir::new().unwrap();
        let me = getuid().as_raw();
        let socket = root.path().join("helper.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let link = root.path().join("link.sock");
        std::os::unix::fs::symlink(&socket, &link).unwrap();
        let file = root.path().join("file");
        std::fs::write(&file, "").unwrap();

        // One message whatever went wrong: no errno, so root's view of the path tells the user nothing.
        let refusals = [
            connect_client(&link, me).await.unwrap_err().to_string(),
            connect_client(&file, me).await.unwrap_err().to_string(),
            connect_client(&root.path().join("missing"), me).await.unwrap_err().to_string(),
            connect_client(&socket, me + 1).await.unwrap_err().to_string(),
        ];
        assert!(refusals.iter().all(|r| *r == refusals[0]), "{refusals:#?}");
        assert!(!refusals[0].contains("os error"), "{}", refusals[0]);

        let _conn = connect_client(&socket, me).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        assert_eq!(socket_peercred(&accepted).unwrap().uid.as_raw(), me);
    }

    #[tokio::test]
    async fn the_helper_refuses_a_default_route_itself() {
        let root = TempDir::new().unwrap();
        let (listener, helper) = serving(&root);

        let full_tunnel = Setup {
            include: strings(&["0.0.0.0/0"]),
            exclude: Vec::new(),
            pins: Vec::new(),
        };
        let (reply, fd) = reply_to(&listener, &full_tunnel).await;

        let Reply::Failed { error } = reply else { panic!("a full tunnel was set up") };
        assert!(error.contains("'0.0.0.0/0'"), "{error}");
        assert!(fd.is_none());
        // The client prints the refusal; the helper's own error says it was delivered.
        assert!(helper.await.unwrap().unwrap_err().is::<Reported>());
    }

    #[tokio::test]
    async fn a_refusal_the_client_never_got_is_the_helpers_to_report() {
        let root = TempDir::new().unwrap();
        let (listener, helper) = serving(&root);
        let full_tunnel = Setup {
            include: strings(&["0.0.0.0/0"]),
            exclude: Vec::new(),
            pins: Vec::new(),
        };

        // The client sends its setup and is gone before the helper (on this thread) can answer.
        let (mut client, _) = listener.accept().await.unwrap();
        client.write_all(&encode(&full_tunnel).unwrap()).await.unwrap();
        drop(client);

        let error = helper.await.unwrap().unwrap_err();
        assert!(!error.is::<Reported>(), "{error:#}");
        assert!(format!("{error:#}").contains("'0.0.0.0/0'"), "{error:#}");
    }

    #[tokio::test]
    async fn the_helper_checks_targets_before_creating_the_device() {
        if getuid().is_root() {
            eprintln!("skipping: as root this would set up {DEVICE}");
            return;
        }
        let root = TempDir::new().unwrap();
        let (listener, helper) = serving(&root);
        let cidrs = Setup {
            include: strings(&["10.99.0.0/16"]),
            exclude: Vec::new(),
            pins: vec![addr("10.99.0.5")],
        };

        let (reply, fd) = reply_to(&listener, &cidrs).await;

        // Past every check, the first thing that needs root fails.
        let Reply::Failed { error } = reply else { panic!("an unprivileged helper set up {DEVICE}") };
        assert!(error.contains(DEVICE) && !error.contains("refused"), "{error}");
        assert!(fd.is_none());
        assert!(helper.await.unwrap().is_err());
    }

    /// `count` distinct addresses inside `10.99.0.0/16`.
    fn pins_in_10_99(count: u32) -> Vec<IpAddr> {
        (0..count).map(|i| IpAddr::V4(std::net::Ipv4Addr::from_bits(0x0a63_0000 + i))).collect()
    }

    #[test]
    fn routes_and_pins_share_the_cap() {
        let routes = [net("10.99.0.0/16")];

        assert!(within_cap(&routes, &pins_in_10_99(4095)).is_ok());
        let error = within_cap(&routes, &pins_in_10_99(4096)).unwrap_err().to_string();
        assert!(error.contains("1 routes and 4096 pinned addresses come to 4097, more than the 4096"), "{error}");
    }

    #[tokio::test]
    async fn the_helper_counts_its_pins_against_the_cap() {
        if getuid().is_root() {
            eprintln!("skipping: as root, a helper past this check would set up {DEVICE}");
            return;
        }
        let root = TempDir::new().unwrap();
        let (listener, helper) = serving(&root);
        // One route, and a pin for every address of 4096 inside it: each pin is root's `ip` too.
        let crowded = Setup {
            include: strings(&["10.99.0.0/16"]),
            exclude: Vec::new(),
            pins: pins_in_10_99(4096),
        };

        let (reply, fd) = reply_to(&listener, &crowded).await;

        // Refused before the device: the first thing that needs root would name it.
        let Reply::Failed { error } = reply else { panic!("4097 routes and pins were set up") };
        assert!(error.contains("more than the 4096") && !error.contains(DEVICE), "{error}");
        assert!(fd.is_none());
        assert!(helper.await.unwrap().unwrap_err().is::<Reported>());
    }

    #[tokio::test]
    async fn the_helper_serves_no_other_user() {
        let root = TempDir::new().unwrap();
        let socket = root.path().join("helper.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();

        assert!(serve_with(&socket, getuid().as_raw() + 1).await.is_err());
        assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock, "the helper connected to another user's socket");
    }

    #[tokio::test]
    async fn sighup_is_handled_unless_it_was_ignored() {
        assert!(Signals::respecting(Ok(true)).unwrap().hangup.is_none(), "handling SIGHUP would undo nohup");
        assert!(Signals::respecting(Ok(false)).unwrap().hangup.is_some());
        // An unreadable or unparseable /proc/self/status must not stop a run: handle it, as before.
        let unknown = Signals::respecting(Err(anyhow!("/proc/self/status has no SigIgn mask")));
        assert!(unknown.unwrap().hangup.is_some());
    }

    #[tokio::test]
    async fn a_signal_stops_a_helper_waiting_for_its_setup() {
        let root = TempDir::new().unwrap();
        let (listener, helper) = serving(&root);
        // Connected means its signal handlers are in place; the setup never comes. nextest runs
        // each test in its own process, so the signal reaches this helper alone.
        let (_client, _) = listener.accept().await.unwrap();

        kill_process(getpid(), Signal::TERM).unwrap();

        let served = tokio::time::timeout(Duration::from_secs(5), helper).await.expect("the helper ignored SIGTERM").unwrap();
        assert!(served.is_err());
    }

    #[test]
    fn a_squatter_cannot_block_the_socket_dir() {
        let root = TempDir::new().unwrap();
        let pid = std::process::id();
        // Every name a pid-and-counter scheme would try, taken by someone else first.
        for n in 0..100 {
            std::fs::create_dir(root.path().join(format!("sshunnel-{pid}-{n}"))).unwrap();
        }

        let dir = SocketDir::create(root.path()).unwrap();
        assert!(dir.0.starts_with(root.path()));
    }

    #[test]
    fn pins_outside_every_route_are_ignored() {
        let routes = [net("10.99.0.0/17"), net("fd99::/64")];
        let pins = ["192.0.2.7", "10.99.0.5", "10.99.200.1", "10.99.0.5", "fd99::5", "198.18.0.9"].map(addr);

        assert_eq!(honored(&routes, &pins, &[]), vec![addr("10.99.0.5"), addr("fd99::5")]);
    }

    #[test]
    fn pins_with_a_host_route_of_their_own_are_left_alone() {
        // That host route outranks every route sshunnel adds, so the address keeps it untouched, and
        // a pin would collide with it (EEXIST at metric 0).
        let routes = [net("10.98.0.0/16"), net("10.99.0.5/32")];
        let pins = ["10.98.0.2", "10.98.0.3", "10.99.0.5"].map(addr);
        let hosts = ["10.98.0.2", "10.99.0.5"].map(addr);

        // Unless a target is that very host: its route would compete, so the pin still goes in.
        assert_eq!(honored(&routes, &pins, &hosts), [addr("10.98.0.3"), addr("10.99.0.5")]);
    }

    #[test]
    fn the_helper_runs_a_closed_set_of_commands() {
        let targets = Targets::parse(&strings(&["10.99.0.0/16", "fd99::/64", "*.corp.example", "host.other.example"]), &strings(&["10.99.128.0/17"])).unwrap();
        let vias = [(addr("10.99.0.5"), via("eth0", Some("192.0.2.1"))), (addr("fd99::5"), via("eth0", None))];

        assert_eq!(
            rendered(&plan(&targets, &targets.routes(), &vias, true).steps),
            [
                // The device's v6 address is fake v6's trial, before the plan.
                "ip addr add 198.18.0.1/15 dev sshunnel0",
                "ip link set dev sshunnel0 mtu 65535 up",
                "ip route add 10.99.0.5/32 via 192.0.2.1 dev eth0 proto 222",
                "ip route add fd99::5/128 dev eth0 proto 222",
                "ip route add 10.99.0.0/17 dev sshunnel0",
                "ip route add fd99::/64 dev sshunnel0 metric 1",
                "ip route add 2001:2::/96 dev sshunnel0 metric 1",
                "resolvectl default-route sshunnel0 false",
                "resolvectl dnssec sshunnel0 no",
                "resolvectl dnsovertls sshunnel0 no",
                "resolvectl domain sshunnel0 ~corp.example ~host.other.example ~18.198.in-addr.arpa ~19.198.in-addr.arpa ~0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.1.0.0.2.ip6.arpa",
                "resolvectl dns sshunnel0 198.18.0.2",
            ]
        );
    }

    #[test]
    fn fake_v6_helper_routes_the_range_when_on() {
        let targets = Targets::parse(&strings(&["10.99.0.0/16", "*.corp.example"]), &[]).unwrap();

        // No v6 routes: the device's v6 address came from the decision's trial, not the plan.
        assert_eq!(
            rendered(&plan(&targets, &targets.routes(), &[], true).steps),
            [
                "ip addr add 198.18.0.1/15 dev sshunnel0",
                "ip link set dev sshunnel0 mtu 65535 up",
                "ip route add 10.99.0.0/16 dev sshunnel0",
                "ip route add 2001:2::/96 dev sshunnel0 metric 1",
                "resolvectl default-route sshunnel0 false",
                "resolvectl dnssec sshunnel0 no",
                "resolvectl dnsovertls sshunnel0 no",
                "resolvectl domain sshunnel0 ~corp.example ~18.198.in-addr.arpa ~19.198.in-addr.arpa ~0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.1.0.0.2.ip6.arpa",
                "resolvectl dns sshunnel0 198.18.0.2",
            ]
        );
        let off = rendered(&plan(&targets, &targets.routes(), &[], false).steps);
        assert!(!off.iter().any(|step| step.contains("2001:2::") || step.contains("fd73:")), "{off:#?}");
    }

    #[test]
    fn ptr_zones_are_routed_on_the_link() {
        let targets = Targets::parse(&strings(&["*.corp.example"]), &[]).unwrap();
        let domain = |fake_v6| {
            let steps = rendered(&plan(&targets, &targets.routes(), &[], fake_v6).steps);
            steps.into_iter().filter(|step| step.starts_with("resolvectl domain")).collect::<Vec<_>>()
        };

        assert_eq!(domain(false), ["resolvectl domain sshunnel0 ~corp.example ~18.198.in-addr.arpa ~19.198.in-addr.arpa"]);
        assert_eq!(
            domain(true),
            ["resolvectl domain sshunnel0 ~corp.example ~18.198.in-addr.arpa ~19.198.in-addr.arpa ~0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.1.0.0.2.ip6.arpa"]
        );
    }

    const ADDR6: &str = "ip addr add fd73:7368::1/64 dev sshunnel0";

    /// What `apply` runs once the device exists, with the commands in `failing` failing: the fake v6
    /// decision, then the plan. Returns the decision, the plan's result and every command run.
    fn set_up(targets: &Targets, vias: &[(IpAddr, Via)], failing: &[&str]) -> (bool, Res<Vec<IpAddr>>, Vec<String>) {
        let mut log = Vec::new();
        let mut run = recorder(&mut log, failing);
        let fake_v6 = decide_fake_v6(targets, &mut run);
        let executed = execute(&plan(targets, &targets.routes(), vias, fake_v6).steps, &mut run);
        drop(run);
        (fake_v6, executed, log)
    }

    fn adds_of_addr6(log: &[String]) -> usize {
        log.iter().filter(|step| *step == ADDR6).count()
    }

    #[test]
    fn fake_v6_helper_turns_off_when_the_address_fails() {
        let names = Targets::parse(&strings(&["10.99.0.0/16", "*.corp.example"]), &[]).unwrap();

        // IPv6 disabled: the address fails, fake v6 is off, and the run goes on without it.
        let (fake_v6, executed, log) = set_up(&names, &[], &[ADDR6]);
        assert!(!fake_v6 && executed.is_ok(), "{executed:?}");
        assert_eq!(log[0], ADDR6);
        assert!(log[1..].iter().all(|step| !step.contains("fd73:") && !step.contains("2001:2::")), "{log:#?}");

        // The address takes: fake v6 is on, and the plan doesn't add it again.
        let (fake_v6, executed, log) = set_up(&names, &[], &[]);
        assert!(fake_v6 && executed.is_ok(), "{executed:?}");
        assert_eq!((log[0].as_str(), adds_of_addr6(&log)), (ADDR6, 1));
        assert!(log.contains(&"ip route add 2001:2::/96 dev sshunnel0 metric 1".to_owned()), "{log:#?}");

        // With v6 routes the trial decides too, and its failure fails the run at the plan's own add.
        let v6 = Targets::parse(&strings(&["fd99::/64", "*.corp.example"]), &[]).unwrap();
        let (fake_v6, executed, log) = set_up(&v6, &[], &[]);
        assert!(fake_v6 && executed.is_ok(), "{executed:?}");
        assert_eq!((log[0].as_str(), adds_of_addr6(&log)), (ADDR6, 1));
        let (fake_v6, executed, log) = set_up(&v6, &[], &[ADDR6]);
        assert!(!fake_v6);
        assert_eq!(format!("{:#}", executed.unwrap_err()), "RTNETLINK answers: File exists");
        assert_eq!(adds_of_addr6(&log), 2, "{log:#?}");

        // Without names, nothing is tried: the plan adds the address for its v6 routes alone.
        let cidrs = Targets::parse(&strings(&["fd99::/64"]), &[]).unwrap();
        let (fake_v6, executed, log) = set_up(&cidrs, &[], &[]);
        assert!(!fake_v6 && executed.is_ok(), "{executed:?}");
        assert_eq!((log[0].as_str(), adds_of_addr6(&log)), ("ip addr add 198.18.0.1/15 dev sshunnel0", 1));
    }

    #[test]
    fn fake_v6_has_its_address_when_every_v6_target_is_a_pin() {
        // fd99::5 keeps its route, so no v6 route goes on the device; fake v6 still needs the address.
        let pinned = Targets::parse(&strings(&["fd99::5", "*.corp.example"]), &[]).unwrap();

        let (fake_v6, executed, log) = set_up(&pinned, &[(addr("fd99::5"), via("eth0", None))], &[]);

        assert!(fake_v6 && executed.is_ok(), "{executed:?}");
        assert_eq!(
            log,
            [
                ADDR6,
                "ip addr add 198.18.0.1/15 dev sshunnel0",
                "ip link set dev sshunnel0 mtu 65535 up",
                "ip route add fd99::5/128 dev eth0 proto 222",
                "ip route add 2001:2::/96 dev sshunnel0 metric 1",
                "resolvectl default-route sshunnel0 false",
                "resolvectl dnssec sshunnel0 no",
                "resolvectl dnsovertls sshunnel0 no",
                "resolvectl domain sshunnel0 ~corp.example ~18.198.in-addr.arpa ~19.198.in-addr.arpa ~0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.1.0.0.2.ip6.arpa",
                "resolvectl dns sshunnel0 198.18.0.2",
            ]
        );
    }

    #[test]
    fn fake_v6_ready_round_trips_as_json() {
        for fake_v6 in [true, false] {
            let ready = Reply::Ready { warnings: Vec::new(), fake_v6 };
            let json = serde_json::to_string(&ready).unwrap();

            assert!(json.contains(&format!(r#""fake_v6":{fake_v6}"#)), "{json}");
            assert_eq!(serde_json::from_str::<Reply>(&json).unwrap(), ready);
        }
    }

    #[test]
    fn a_v4_cidr_setup_skips_ipv6_and_the_resolver() {
        let targets = Targets::parse(&strings(&["10.99.0.0/16"]), &[]).unwrap();

        assert_eq!(
            rendered(&plan(&targets, &targets.routes(), &[], false).steps),
            [
                "ip addr add 198.18.0.1/15 dev sshunnel0",
                "ip link set dev sshunnel0 mtu 65535 up",
                "ip route add 10.99.0.0/16 dev sshunnel0"
            ]
        );
    }

    #[test]
    fn a_pin_on_a_local_route_is_left_alone() {
        // A resolver on 127.0.0.1: the local table outranks any route sshunnel adds to main.
        let targets = Targets::parse(&strings(&["0.0.0.0/1", "128.0.0.0/1"]), &[]).unwrap();
        let local = Via { unicast: false, ..via("lo", None) };

        let plan = plan(&targets, &targets.routes(), &[(addr("127.0.0.1"), local)], false);

        assert!(rendered(&plan.steps).iter().all(|step| !step.contains("proto 222")), "{:#?}", rendered(&plan.steps));
        assert!(rendered(&plan.steps).contains(&"ip route add 0.0.0.0/1 dev sshunnel0".to_owned()));
    }

    #[test]
    fn a_target_that_is_a_pin_keeps_its_route() {
        let targets = Targets::parse(&strings(&["10.99.0.5", "10.98.0.0/16"]), &[]).unwrap();

        let plan = plan(&targets, &targets.routes(), &[(addr("10.99.0.5"), via("eth0", Some("192.0.2.1")))], false);

        assert_eq!(
            rendered(&plan.steps),
            [
                "ip addr add 198.18.0.1/15 dev sshunnel0",
                "ip link set dev sshunnel0 mtu 65535 up",
                "ip route add 10.99.0.5/32 via 192.0.2.1 dev eth0 proto 222",
                "ip route add 10.98.0.0/16 dev sshunnel0",
            ]
        );
        assert_eq!(plan.warnings.len(), 1);
        assert!(plan.warnings[0].contains("10.99.0.5"), "{:?}", plan.warnings);
    }

    #[test]
    fn a_failed_setup_deletes_the_pins_it_added() {
        let targets = Targets::parse(&strings(&["10.99.0.0/16", "fd99::/64"]), &[]).unwrap();
        let vias = [(addr("10.99.0.5"), via("eth0", Some("192.0.2.1"))), (addr("fd99::5"), via("eth0", None))];
        let steps = plan(&targets, &targets.routes(), &vias, false).steps;
        let mut log = Vec::new();

        let error = execute(&steps, &mut recorder(&mut log, &["ip route add fd99::/64 dev sshunnel0 metric 1"])).unwrap_err();

        assert_eq!(format!("{error:#}"), "RTNETLINK answers: File exists");
        assert_eq!(
            &log[log.len() - 3..],
            [
                "ip route add fd99::/64 dev sshunnel0 metric 1",
                "ip route del fd99::5/128 proto 222",
                "ip route del 10.99.0.5/32 proto 222"
            ]
        );
    }

    #[test]
    fn teardown_tries_every_pin() {
        let mut log = Vec::new();

        let error = unpin(&[addr("10.99.0.5"), addr("10.99.0.6")], &mut recorder(&mut log, &["ip route del 10.99.0.6/32 proto 222"])).unwrap_err();

        assert!(format!("{error:#}").contains("10.99.0.6"), "{error:#}");
        assert_eq!(log, ["ip route del 10.99.0.6/32 proto 222", "ip route del 10.99.0.5/32 proto 222"]);
    }

    #[test]
    fn an_applied_setup_is_undone_once_even_when_dropped() {
        let undo = ["ip route del 10.99.0.5/32 proto 222", "ip link del dev sshunnel0"];
        // Stands in for the device's fd: clearing its persist flag fails, which neither path minds.
        let tun = || Some(OwnedFd::from(tempfile::tempfile().unwrap()));

        // An early return or a panic between setup and teardown.
        let mut log = Vec::new();
        drop(Applied {
            tun: tun(),
            pins: vec![addr("10.99.0.5")],
            run: recorder(&mut log, &[]),
        });
        assert_eq!(log, undo);

        // Torn down, then dropped: nothing runs twice.
        let mut log = Vec::new();
        let applied = Applied {
            tun: tun(),
            pins: vec![addr("10.99.0.5")],
            run: recorder(&mut log, &[]),
        };
        let _ = applied.teardown();
        assert_eq!(log, undo);
    }

    #[test]
    fn a_device_already_gone_counts_as_deleted() {
        let mut gone = |_: &Step| -> Void { bail!("`ip link del dev sshunnel0` failed (exit status: 1): Cannot find device \"sshunnel0\"") };
        assert!(delete_device(&mut gone).is_ok());

        let mut refused = |_: &Step| -> Void { bail!("`ip link del dev sshunnel0` failed (exit status: 2): RTNETLINK answers: Operation not permitted") };
        assert!(delete_device(&mut refused).is_err());
    }

    #[tokio::test]
    async fn a_reply_carries_the_tun_fd() {
        let (mut helper, client) = UnixStream::pair().unwrap();
        let device = tempfile::tempfile().unwrap();
        let ready = Reply::Ready {
            warnings: strings(&["'10.0.0.0/8' contains the connected subnet 10.1.0.0/16, which stays local"]),
            fake_v6: false,
        };

        send(&mut helper, &ready, Some(device.as_fd())).await.unwrap();
        let (reply, fd) = receive(&client).await.unwrap();

        assert_eq!(reply, ready);
        let fd = fd.expect("no fd came with the reply");
        assert!(fcntl_getfd(&fd).unwrap().contains(FdFlags::CLOEXEC), "the TUN fd would leak into children");
        assert_eq!(std::fs::File::from(fd).metadata().unwrap().ino(), device.metadata().unwrap().ino());

        let failed = Reply::Failed { error: "refused".to_owned() };
        send(&mut helper, &failed, None).await.unwrap();
        let (reply, fd) = receive(&client).await.unwrap();
        assert_eq!((reply, fd.is_none()), (failed, true));

        drop(helper);
        assert!(receive(&client).await.unwrap_err().to_string().contains("closed"));
    }

    #[tokio::test]
    async fn setups_are_bounded_lines() {
        let (mut client, mut helper) = UnixStream::pair().unwrap();
        client.write_all(&encode(&setup()).unwrap()).await.unwrap();
        assert_eq!(read_setup(&mut helper).await.unwrap(), setup());

        let (mut client, mut helper) = UnixStream::pair().unwrap();
        let writer = tokio::spawn(async move { client.write_all(&vec![b' '; MAX_MESSAGE + 1]).await });
        assert!(read_setup(&mut helper).await.is_err(), "an endless setup was accepted");
        drop(helper);
        let _ = writer.await;

        let (mut client, mut helper) = UnixStream::pair().unwrap();
        client.write_all(br#"{"include":["10.99.0.0/16"],"#).await.unwrap();
        drop(client);
        assert!(read_setup(&mut helper).await.is_err(), "a cut-short setup was accepted");
    }
}
