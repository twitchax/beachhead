//! sshunnel's remote half, pushed over SSH and exec'd by the bootstrap script. Argument handling
//! is by hand: clap would cost more bytes than the relay's whole interface.

use std::process::ExitCode;

const USAGE: &str = "usage: sshunnel-relay --stdio | --probe";

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("--probe") => {
            println!("{}", sshunnel_relay::probe());
            ExitCode::SUCCESS
        }
        Some("--stdio") => match sshunnel_relay::run_stdio() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sshunnel-relay: {e:#}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
