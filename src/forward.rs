//! Local TCP forwards, `ssh -L` style: listen locally, open a stream through the relay for each
//! connection, and pump it.

use std::{str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context as _, anyhow, bail};
use sshunnel_mux::{
    Mux,
    base::{Err, Res, Void},
    pump,
};
use tokio::net::TcpListener;
use tracing::{debug, warn};

/// One `-L [bind_address:]port:host:hostport` spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forward {
    /// Where to listen locally; `127.0.0.1` unless the spec names one.
    pub bind: String,
    /// The local port; 0 picks a free one.
    pub bind_port: u16,
    /// The host the relay dials, resolved on the remote.
    pub host: String,
    /// The port the relay dials.
    pub port: u16,
}

impl FromStr for Forward {
    type Err = Err;

    fn from_str(spec: &str) -> Res<Self> {
        let parts = split_outside_brackets(spec);
        let (bind, bind_port, host, port) = match parts.as_slice() {
            [bind_port, host, port] => ("127.0.0.1", *bind_port, *host, *port),
            [bind, bind_port, host, port] => (*bind, *bind_port, *host, *port),
            _ => bail!("`{spec}` is not [bind_address:]port:host:hostport"),
        };
        let port_of = |s: &str| s.parse::<u16>().map_err(|e| anyhow!("`{s}` in `{spec}` is not a port: {e}"));
        let unbracket = |s: &str| s.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(s).to_owned();
        let (bind, host) = (unbracket(bind), unbracket(host));
        if bind.is_empty() || host.is_empty() {
            bail!("`{spec}` has an empty address");
        }
        Ok(Self {
            bind,
            bind_port: port_of(bind_port)?,
            host,
            port: port_of(port)?,
        })
    }
}

impl std::fmt::Display for Forward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{} -> {}:{}", self.bind, self.bind_port, self.host, self.port)
    }
}

/// Splits on `:` except inside `[...]`, so IPv6 literals survive.
fn split_outside_brackets(spec: &str) -> Vec<&str> {
    let mut parts = Vec::with_capacity(4);
    let (mut depth, mut start) = (0u32, 0);
    for (i, c) in spec.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            ':' if depth == 0 => {
                parts.push(&spec[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&spec[start..]);
    parts
}

impl Forward {
    /// Binds the local listener.
    ///
    /// # Errors
    ///
    /// Fails when the address can't be bound.
    pub async fn bind(&self) -> Res<TcpListener> {
        TcpListener::bind((self.bind.as_str(), self.bind_port))
            .await
            .with_context(|| format!("listening on {}:{}", self.bind, self.bind_port))
    }
}

/// The pause after a failed accept, doubling with each failure in a row up to [`MAX_BACKOFF`].
const MIN_BACKOFF: Duration = Duration::from_millis(5);
const MAX_BACKOFF: Duration = Duration::from_secs(1);

/// Accepts connections on `listener` until dropped, opening a stream to `host:port` for each.
///
/// # Errors
///
/// None: like `ssh -L`, it outlives a failed accept (EMFILE once the process is out of
/// descriptors) by logging it and retrying after a backoff, and a failed connection is logged and
/// dropped.
pub async fn serve(mux: Mux, listener: TcpListener, host: Arc<str>, port: u16) -> Void {
    let mut backoff = MIN_BACKOFF;
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(accepted) => {
                backoff = MIN_BACKOFF;
                accepted
            }
            Err(e) => {
                // Out of descriptors, the connection stays queued and the next accept fails the
                // same way at once: wait for live connections to close rather than spin.
                warn!("accepting a local connection: {e}; retrying in {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };
        let (mux, host) = (mux.clone(), Arc::clone(&host));
        tokio::spawn(async move {
            // Frames already batch; Nagle would only add latency on top.
            let _ = socket.set_nodelay(true);
            match mux.open(&host, port).await {
                Ok(stream) => match pump(stream, socket).await {
                    Ok(traffic) => debug!(%peer, sent = traffic.sent, received = traffic.received, "connection closed"),
                    Err(e) => debug!(%peer, "connection failed: {e:#}"),
                },
                Err(e) => warn!(%peer, "{e:#}"),
            }
        });
    }
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;

    use super::*;

    fn fwd(bind: &str, bind_port: u16, host: &str, port: u16) -> Forward {
        Forward {
            bind: bind.to_owned(),
            bind_port,
            host: host.to_owned(),
            port,
        }
    }

    #[test]
    fn specs_parse_like_ssh_dash_l() {
        assert_eq!("8080:server.lan:80".parse::<Forward>().unwrap(), fwd("127.0.0.1", 8080, "server.lan", 80));
        assert_eq!("0.0.0.0:8080:10.0.0.5:22".parse::<Forward>().unwrap(), fwd("0.0.0.0", 8080, "10.0.0.5", 22));
        assert_eq!("[::1]:8080:[fd00::5]:443".parse::<Forward>().unwrap(), fwd("::1", 8080, "fd00::5", 443));
        assert_eq!("0:localhost:5432".parse::<Forward>().unwrap(), fwd("127.0.0.1", 0, "localhost", 5432));
    }

    #[test]
    fn bad_specs_are_rejected() {
        for spec in ["8080", "8080:host", "a:b:c:d:e", "x:host:80", "8080:host:99999", "8080::80", ":8080:host:80"] {
            assert!(spec.parse::<Forward>().is_err(), "{spec} parsed");
        }
    }
}
