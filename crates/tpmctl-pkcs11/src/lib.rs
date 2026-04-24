//! PKCS#11 provider crate boundary for TPMCTL.
//!
//! Entry points are intentionally stubbed for the foundation workstream. The
//! crate owns PKCS#11-only dependencies and builds as a `cdylib`.

#[unsafe(no_mangle)]
pub extern "C" fn C_GetFunctionList(
    pp_function_list: pkcs11_sys::CK_FUNCTION_LIST_PTR_PTR,
) -> pkcs11_sys::CK_RV {
    if pp_function_list.is_null() {
        return pkcs11_sys::CKR_ARGUMENTS_BAD;
    }

    pkcs11_sys::CKR_FUNCTION_NOT_SUPPORTED
}

pub fn provider_name() -> &'static str {
    "tpmctl-pkcs11"
}
