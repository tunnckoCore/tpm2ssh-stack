//! Minimal PKCS#11 provider boundary for `tpmctl`.
//!
//! Full PKCS#11 entrypoints are intentionally left to the PKCS#11 workstream;
//! this crate establishes dependency isolation and the `cdylib` artifact shape.

use pkcs11_sys::{CK_FUNCTION_LIST_PTR_PTR, CK_RV, CKR_ARGUMENTS_BAD, CKR_FUNCTION_NOT_SUPPORTED};

/// PKCS#11 entrypoint required by loaders.
#[unsafe(no_mangle)]
pub extern "C" fn C_GetFunctionList(function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if function_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    CKR_FUNCTION_NOT_SUPPORTED
}

#[allow(dead_code)]
fn core_contract_smoke_test() -> tpmctl_core::Result<()> {
    Err(tpmctl_core::Error::unsupported("pkcs11::C_GetFunctionList"))
}
