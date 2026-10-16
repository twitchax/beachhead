//! beachhead's remote half: speak the mux over stdio and dial TCP for each stream the client opens.
//!
//! stdout carries frames and nothing else; anything human-readable goes to stderr, which ssh hands
//! back to the client's terminal.

use anyhow::Context as _;
use beachhead_mux::{
    Config, Incoming, OpenRequest, Role,
    base::Void,
    hello::{recv_hello, send_hello},
    pump, start,
};
use bytes::BytesMut;
use tokio::net::TcpStream;

/// What `--probe` prints: proof the binary executes here, which a `noexec` mount would deny.
#[must_use]
pub fn probe() -> String {
    format!("beachhead-relay {} protocol {}", env!("CARGO_PKG_VERSION"), beachhead_mux::frame::VERSION)
}

/// Serves the client over stdin and stdout until the client hangs up.
///
/// # Errors
///
/// Fails when the handshake fails or the pipe breaks mid-connection.
pub fn run_stdio() -> Void {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_io().build().context("starting the runtime")?;
    let result = runtime.block_on(async {
        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        // The relay speaks first: the client stays quiet until this Hello arrives.
        send_hello(&mut stdout).await?;
        let mut buf = BytesMut::new();
        recv_hello(&mut stdin, &mut buf).await?;
        let (_mux, incoming, driver) = start(stdin, buf, stdout, Role::Relay, Config::default());
        tokio::spawn(serve(incoming));
        driver.await
    });
    // A stdin read parked on the blocking pool would make an orderly shutdown wait on it forever.
    runtime.shutdown_background();
    result
}

/// Dials each requested stream and pumps it.
pub async fn serve(mut incoming: Incoming) {
    while let Some(request) = incoming.next().await {
        tokio::spawn(dial(request));
    }
}

async fn dial(request: OpenRequest) {
    match TcpStream::connect((request.host(), request.port())).await {
        Ok(socket) => {
            // Frames already batch; Nagle would only add latency on top.
            let _ = socket.set_nodelay(true);
            // The pump resets the stream itself on failure, which tells the client why.
            let _ = pump(request.accept(), socket).await;
        }
        Err(e) => {
            let reason = format!("dialing {}:{}: {e}", request.host(), request.port());
            request.reject(&reason);
        }
    }
}
