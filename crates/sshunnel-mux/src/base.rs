//! The small vocabulary every sshunnel crate shares: the `anyhow` error aliases. They live in the
//! lowest crate so the client and the relay re-export one definition.

/// The error type for application glue.
pub type Err = anyhow::Error;
/// A result carrying [`Err`].
pub type Res<T> = anyhow::Result<T, Err>;
/// A result with nothing to return.
pub type Void = Res<()>;
