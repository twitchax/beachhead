//! The `sshunnel` binary: parse arguments, set up tracing, call the library. Everything worth
//! testing lives in `sshunnel`; this file stays thin.

// `cargo llvm-cov` on nightly sets `coverage_nightly`; elsewhere this is inert, so the source builds
// on stable. Enable the feature only in a crate root that uses `#[coverage(off)]`: an unused
// feature fails the `unused` lint group on current nightlies.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::{io::IsTerminal as _, path::PathBuf, process::ExitCode, sync::Arc};

use anyhow::{Context as _, bail};
use clap::{Args, Parser, Subcommand};
use tokio::task::JoinSet;
use tracing_subscriber::EnvFilter;

use sshunnel::{
    base::Void,
    forward::{self, Forward},
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
    /// Forward local TCP ports through a relay on DESTINATION, like `ssh -L`.
    Forward {
        /// `[bind_address:]port:host:hostport`. The relay resolves and dials host; the bind address
        /// defaults to localhost (IPv4 and IPv6), and port 0 picks a free local port.
        #[arg(short = 'L', long = "local", value_name = "SPEC", required = true)]
        forwards: Vec<Forward>,
        /// The ssh program and its leading arguments, split like a shell would.
        #[arg(long, env = "SSHUNNEL_SSH", default_value = "ssh", value_name = "COMMAND")]
        ssh_cmd: String,
        #[command(flatten)]
        relays: RelayArgs,
        /// Where to run the relay, exactly as you'd pass it to ssh (config aliases work).
        destination: String,
    },
    /// Show the relays this client would push: arch, sha256 and size of exactly what it executes.
    Relays {
        #[command(flatten)]
        relays: RelayArgs,
    },
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
        Command::Forward { forwards, ssh_cmd, relays, destination } => {
            let relays = Relays::load(relays.relay_dir.as_deref())?;
            let ssh = SshCommand::parse(&ssh_cmd)?;
            let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().context("starting the runtime")?;
            runtime.block_on(forward(&forwards, &ssh, &destination, &relays))
        }
    }
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

async fn forward(forwards: &[Forward], ssh: &SshCommand, destination: &str, relays: &Relays) -> Void {
    // Bind first, so a port already in use fails before ssh runs.
    let mut listeners = Vec::with_capacity(forwards.len());
    for spec in forwards {
        listeners.push(spec.bind().await?);
    }

    let session = Session::connect(ssh, destination, relays).await?;
    let relay = session.relay();
    eprintln!("sshunnel: relay {} {} {}", relay.arch(), &relay.sha256()[..12], session.bootstrap());

    let mut serving = JoinSet::new();
    for (spec, bound) in forwards.iter().zip(listeners) {
        let host: Arc<str> = Arc::from(spec.host.as_str());
        for listener in bound {
            eprintln!("sshunnel: forwarding {} -> {}:{}", listener.local_addr().context("reading a listener's address")?, spec.host, spec.port);
            serving.spawn(forward::serve(session.mux().clone(), listener, Arc::clone(&host), spec.port));
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
