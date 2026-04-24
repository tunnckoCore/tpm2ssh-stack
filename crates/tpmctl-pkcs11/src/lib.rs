//! Minimal PKCS#11 crate scaffold.
//!
//! Agent 03 does not own PKCS#11 behavior; this file exists only so the
//! workspace compiles while CLI validation is developed in isolation.

#[unsafe(no_mangle)]
pub extern "C" fn tpmctl_pkcs11_scaffold() -> i32 {
    0
}
