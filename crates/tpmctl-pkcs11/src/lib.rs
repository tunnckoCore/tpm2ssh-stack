//! Minimal scaffold for the PKCS#11 provider crate.
//!
//! PKCS#11 entrypoints are outside Agent 04 scope.

/// Returns the linked core crate version for smoke tests and downstream wiring.
pub fn core_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
