//! Reusable core library for tpmctl.
//!
//! This crate intentionally contains no CLI parser and no PKCS#11 entrypoints.

pub mod crypto;
pub mod tpm;
