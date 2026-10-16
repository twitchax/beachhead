//! A userspace VPN over plain SSH: push-exec a static musl relay, cache it by hash, route through it.

pub mod base;
pub mod tests;

use anyhow::bail;

use crate::base::Res;

/// Builds the greeting for `name`.
///
/// # Errors
///
/// Fails when `name` is empty or only whitespace.
pub fn greet(name: &str) -> Res<String> {
    let name = name.trim();
    if name.is_empty() {
        bail!("cannot greet an empty name");
    }
    Ok(format!("Hello, {name}!"))
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn greets_a_trimmed_name() {
        assert_eq!(greet("  world ").unwrap(), "Hello, world!");
    }

    #[test]
    fn rejects_an_empty_name() {
        assert!(greet("   ").is_err());
    }
}
