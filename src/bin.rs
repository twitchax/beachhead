//! The `sshunnel` binary: parse arguments, set up tracing, call the library. Everything worth
//! testing lives in `sshunnel`; this file stays thin.

// `cargo llvm-cov` on nightly sets `coverage_nightly`; elsewhere this is inert, so the source builds
// on stable. Enable the feature only in a crate root that uses `#[coverage(off)]`: an unused
// feature fails the `unused` lint group on current nightlies.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::{io::IsTerminal as _, path::PathBuf, process::ExitCode, sync::Arc};

use anyhow::{Context as _, bail};
use clap::{Args, CommandFactory, Parser, Subcommand};
use tokio::{
    net::{TcpListener, UdpSocket},
    task::JoinSet,
};
use tracing_subscriber::EnvFilter;

#[cfg(target_os = "linux")]
use sshunnel::route;
use sshunnel::{
    base::{Res, Void},
    forward::{self, Forward, Proto, UdpForwards},
    relays::Relays,
    session::{Session, SshCommand, ready_line},
};

/// A userspace VPN over plain SSH: push-exec a static musl relay, cache it by hash, route through it.
#[derive(Debug, Parser)]
#[command(
    version,
    about,
    arg_required_else_help = true,
    after_help = "Run `sshunnel help` for the guide: examples, setup, and running it from a script or an agent.",
    after_long_help = include_str!("help/guide.txt")
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Forward local TCP and UDP ports through a relay on DESTINATION, like `ssh -L`.
    #[command(after_long_help = include_str!("help/forward.txt"))]
    Forward {
        // A `help` string, not a doc comment: clippy wants `bind_address` in backticks there, and
        // clap would print them.
        #[arg(short = 'L', long = "local", value_name = "SPEC", required = true, help = "[bind_address:]port:host:hostport[/udp] (repeatable)")]
        forwards: Vec<Forward>,
        #[command(flatten)]
        ssh: SshArgs,
        #[command(flatten)]
        relays: RelayArgs,
        /// Where to run the relay, as you'd pass it to ssh (config aliases work).
        destination: String,
    },
    /// Route CIDRs and domain patterns through a relay on DESTINATION (Linux).
    #[cfg(target_os = "linux")]
    #[command(after_long_help = include_str!("help/route.txt"))]
    Route {
        /// Carve a CIDR or a name out of the targets (repeatable).
        #[arg(short = 'x', long = "exclude", value_name = "TARGET")]
        exclude: Vec<String>,
        /// Check whether route can start, changing nothing.
        #[arg(long)]
        check: bool,
        #[command(flatten)]
        ssh: SshArgs,
        #[command(flatten)]
        relays: RelayArgs,
        /// Where to run the relay, as you'd pass it to ssh (config aliases work).
        destination: String,
        // A `help` string, as for `-L`: clippy reads `fd99::/64` as a path to put in backticks.
        #[arg(value_name = "TARGET", required = true, help = "CIDRs (10.99.0.0/16, fd99::/64) and domain patterns ('*.corp.example')")]
        targets: Vec<String>,
    },
    /// Print a shell completion script.
    #[command(after_long_help = include_str!("help/completions.txt"))]
    Completions {
        /// The shell to complete for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Print the one-time setup that lets route start without a sudo password (Linux).
    #[cfg(target_os = "linux")]
    #[command(after_long_help = include_str!("help/sudoers.txt"))]
    Sudoers,
    /// The root helper `route` starts through sudo: it sets up sshunnel0 for the client listening on PATH.
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    Helper {
        #[arg(long, value_name = "PATH")]
        socket: PathBuf,
    },
    /// Show the relays this client would push: arch, sha256 and size.
    Relays {
        #[command(flatten)]
        relays: RelayArgs,
    },
}

#[derive(Debug, Args)]
struct SshArgs {
    /// The ssh program and its arguments.
    #[arg(long, env = "SSHUNNEL_SSH", default_value = "ssh", value_name = "COMMAND")]
    ssh_cmd: String,
}

#[derive(Debug, Args)]
struct RelayArgs {
    /// Relays to push instead of the built-in ones.
    #[arg(long, env = "SSHUNNEL_RELAY_DIR", value_name = "DIR")]
    relay_dir: Option<PathBuf>,
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn main() -> ExitCode {
    // Logs go to stderr so stdout stays clean for output; `RUST_LOG` overrides the default level.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")))
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();

    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        // `{:#}` prints the whole context chain on one line.
        Err(e) => {
            // The root helper shares the client's terminal through sudo, and the client prints an
            // error the helper sent it.
            #[cfg(target_os = "linux")]
            if e.is::<sshunnel::route::helper::Reported>() {
                return ExitCode::FAILURE;
            }
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// The command line as a completion script should see it: `clap_complete` lists hidden subcommands
/// too, and `Command` can't drop one, so the visible ones go into a fresh root. The root has no
/// arguments of its own beyond the `--help` and `--version` clap adds.
fn completable() -> clap::Command {
    let cli = Cli::command();
    let visible: Vec<clap::Command> = cli.get_subcommands().filter(|sub| !sub.is_hide_set()).cloned().collect();
    clap::Command::new("sshunnel").version(env!("CARGO_PKG_VERSION")).subcommands(visible)
}

fn run(cli: Cli) -> Void {
    match cli.command {
        Command::Relays { relays } => {
            print_relays(&Relays::load(relays.relay_dir.as_deref())?);
            Ok(())
        }
        Command::Forward { forwards, ssh, relays, destination } => {
            let relays = Relays::load(relays.relay_dir.as_deref())?;
            let ssh = SshCommand::parse(&ssh.ssh_cmd)?;
            runtime()?.block_on(forward(&forwards, &ssh, &destination, &relays))
        }
        #[cfg(target_os = "linux")]
        Command::Route {
            exclude,
            check,
            ssh,
            relays,
            destination,
            targets,
        } => {
            let relays = Relays::load(relays.relay_dir.as_deref())?;
            let ssh = SshCommand::parse(&ssh.ssh_cmd)?;
            let options = route::Options { include: targets, exclude };
            if check {
                return check_route(&options, &ssh, &destination, &relays);
            }
            runtime()?.block_on(route::run(&options, &ssh, &destination, &relays))
        }
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut completable(), "sshunnel", &mut std::io::stdout());
            Ok(())
        }
        #[cfg(target_os = "linux")]
        Command::Sudoers => {
            print!("{}", runtime()?.block_on(route::sudoers::run())?);
            Ok(())
        }
        #[cfg(target_os = "linux")]
        Command::Helper { socket } => {
            // One task waiting on a socket and a few commands: a single thread is plenty for root.
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().context("starting the runtime")?;
            runtime.block_on(route::helper::serve(&socket))
        }
    }
}

/// `route --check`: the findings on stdout, then the verdict, as the last line or as the error.
#[cfg(target_os = "linux")]
fn check_route(options: &route::Options, ssh: &SshCommand, destination: &str, relays: &Relays) -> Void {
    let report = runtime()?.block_on(route::check::run(options, ssh, destination, relays, &mut std::io::stdout()))?;
    match report.problems() {
        0 => {
            println!("sshunnel: route can start");
            Ok(())
        }
        1 => bail!("route would not start: 1 problem"),
        n => bail!("route would not start: {n} problems"),
    }
}

fn runtime() -> Res<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().context("starting the runtime")
}

fn print_relays(relays: &Relays) {
    println!("relays ({}):", relays.source());
    for arch in sshunnel::arch::Arch::ALL {
        match relays.get(arch) {
            Some(relay) => println!("  {:<8} sha256 {}  {} bytes", arch.name(), relay.sha256(), relay.len()),
            None => println!("  {:<8} (none)", arch.name()),
        }
    }
}

/// One spec's local sockets.
enum Listeners {
    Tcp(Vec<TcpListener>),
    Udp(Vec<UdpSocket>),
}

async fn forward(forwards: &[Forward], ssh: &SshCommand, destination: &str, relays: &Relays) -> Void {
    // Bind first, so a port no address can take fails before ssh runs.
    let mut listeners = Vec::with_capacity(forwards.len());
    for spec in forwards {
        listeners.push(match spec.proto {
            Proto::Tcp => Listeners::Tcp(spec.bind().await?),
            Proto::Udp => Listeners::Udp(spec.bind_udp().await?),
        });
    }

    let session = Session::connect(ssh, destination, relays).await?;
    eprintln!("sshunnel: {}", session.describe());

    // One flow table for every UDP listener, so the cap is the session's.
    let udp = UdpForwards::new(session.mux().clone());
    let mut serving = JoinSet::new();
    serving.spawn(udp.clone().sweep());
    for (spec, bound) in forwards.iter().zip(listeners) {
        let host: Arc<str> = Arc::from(spec.host.as_str());
        match bound {
            Listeners::Tcp(bound) => {
                for listener in bound {
                    eprintln!("sshunnel: forwarding {} -> {}:{}", listener.local_addr().context("reading a listener's address")?, spec.host, spec.port);
                    serving.spawn(forward::serve(session.mux().clone(), listener, Arc::clone(&host), spec.port));
                }
            }
            Listeners::Udp(bound) => {
                for socket in bound {
                    eprintln!(
                        "sshunnel: forwarding {} -> {}:{}/udp",
                        socket.local_addr().context("reading a listener's address")?,
                        spec.host,
                        spec.port
                    );
                    serving.spawn(udp.clone().serve(socket, Arc::clone(&host), spec.port));
                }
            }
        }
    }
    let mut stop = StopSignal::new()?;
    eprintln!("{}", ready_line(std::process::id()));
    tokio::select! {
        closed = session.closed() => {
            closed?;
            bail!("the ssh session ended")
        }
        Some(failed) = serving.join_next() => failed.context("a listener task panicked")?,
        () = stop.recv() => Ok(()),
    }
}

/// Ctrl-C and, on unix, SIGTERM. Registered when built, not when first awaited, so building it
/// before the ready line means a signal sent on seeing that line is already caught.
#[cfg(unix)]
struct StopSignal {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl StopSignal {
    fn new() -> Res<Self> {
        use tokio::signal::unix::{SignalKind, signal};

        Ok(Self {
            interrupt: signal(SignalKind::interrupt()).context("registering the SIGINT handler")?,
            terminate: signal(SignalKind::terminate()).context("registering the SIGTERM handler")?,
        })
    }

    async fn recv(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
        }
    }
}

#[cfg(not(unix))]
struct StopSignal;

#[cfg(not(unix))]
impl StopSignal {
    #[expect(clippy::unnecessary_wraps, reason = "the unix constructor registers handlers and can fail")]
    fn new() -> Res<Self> {
        Ok(Self)
    }

    async fn recv(&mut self) {
        let _ = tokio::signal::ctrl_c().await;
    }
}
