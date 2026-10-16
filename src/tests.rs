//! Fixtures shared by unit tests, integration tests and benches. Always compiled (not
//! `#[cfg(test)]`), so `tests/` and `benches/` can use it too; keep it free of test-only
//! dependencies.

/// A name every greeting test can rely on.
#[must_use]
pub fn sample_name() -> &'static str {
    "Ferris"
}
