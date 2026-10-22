//! The `sshunnel` binary: parse arguments, set up tracing, call the library. Everything worth
//! testing lives in `sshunnel`; this file stays thin.

// `cargo llvm-cov` on nightly sets `coverage_nightly`; elsewhere this is inert, so the source builds
// on stable. Enable the feature only in a crate root that uses `#[coverage(off)]`: an unused
// feature fails the `unused` lint group on current nightlies.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::{io::IsTerminal as _, path::PathBuf, process::ExitCode, sync::Arc};

use anyhow::{Context as _, bail};
use clap::{Args, Parser, Subcommand};
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
    session::{Session, SshCommand},
};

/// A userspace VPN over plain SSH: push-exec a static musl relay, cache it by hash, route through it.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Forward local TCP and UDP ports through a relay on DESTINATION, like `ssh -L`.
    Forward {
        /// `[bind_address:]port:host:hostport[/udp]`. The relay resolves and dials host; the bind
        /// address defaults to localhost (IPv4 and IPv6), and port 0 picks a free local port. With
        /// `/udp`, each local sender gets a flow of its own.
        #[arg(short = 'L', long = "local", value_name = "SPEC", required = true)]
        forwards: Vec<Forward>,
        #[command(flatten)]
        ssh: SshArgs,
        #[command(flatten)]
        relays: RelayArgs,
        /// Where to run the relay, exactly as you'd pass it to ssh (config aliases work).
        destination: String,
    },
    /// Route CIDRs and domain patterns through a relay on DESTINATION, over a TUN device (Linux).
    #[cfg(target_os = "linux")]
    Route {
        /// Carve a CIDR or a name out of the targets (repeatable).
        #[arg(short = 'x', long = "exclude", value_name = "TARGET")]
        exclude: Vec<String>,
        #[command(flatten)]
        ssh: SshArgs,
        #[command(flatten)]
        relays: RelayArgs,
        /// Where to run the relay, exactly as you'd pass it to ssh (config aliases work).
        destination: String,
        /// What to route: CIDRs (`10.99.0.0/16`, `fd99::/64`) and domain patterns (`*.corp.example`, `host.corp.example`).
        #[arg(value_name = "TARGET", required = true)]
        targets: Vec<String>,
    },
    /// The root helper `route` starts through sudo: it sets up sshunnel0 for the client listening on PATH.
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    Helper {
        #[arg(long, value_name = "PATH")]
        socket: PathBuf,
    },
    /// Show the relays this client would push: arch, sha256 and size of exactly what it executes.
    Relays {
        #[command(flatten)]
        relays: RelayArgs,
    },
}

#[derive(Debug, Args)]
struct SshArgs {
    /// The ssh program and its leading arguments, split like a shell would.
    #[arg(long, env = "SSHUNNEL_SSH", default_value = "ssh", value_name = "COMMAND")]
    ssh_cmd: String,
}

#[derive(Debug, Args)]
struct RelayArgs {
    /// Read relays from DIR instead of the ones built in (`cargo xtask relay` writes target/relay).
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
            ssh,
            relays,
            destination,
            targets,
        } => {
            let relays = Relays::load(relays.relay_dir.as_deref())?;
            let ssh = SshCommand::parse(&ssh.ssh_cmd)?;
            let options = route::Options { include: targets, exclude };
            runtime()?.block_on(route::run(&options, &ssh, &destination, &relays))
        }
        #[cfg(target_os = "linux")]
        Command::Helper { socket } => {
            // One task waiting on a socket and a few commands: a single thread is plenty for root.
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().context("starting the runtime")?;
            runtime.block_on(route::helper::serve(&socket))
        }
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
    tokio::select! {
        closed = session.closed() => {
            closed?;
            bail!("the ssh session ended")
        }
        Some(failed) = serving.join_next() => failed.context("a listener task panicked")?,
    }
}
