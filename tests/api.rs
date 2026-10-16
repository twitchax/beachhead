//! The public API as an outside caller sees it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use pretty_assertions::assert_eq;

use beachhead::{greet, tests::sample_name};

#[test]
fn greets_the_sample_name() {
    assert_eq!(greet(sample_name()).unwrap(), "Hello, Ferris!");
}
