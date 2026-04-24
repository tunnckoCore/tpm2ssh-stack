//! Minimal TPM helper surface shared by frontends in this worktree.
//!
//! Full TPM command modules are intentionally left to the TPM-command workstream;
//! this module only contains small helpers needed by the PKCS#11 provider split.

use std::env;

use tss_esapi::{
    handles::TpmHandle,
    tcti_ldr::{DeviceConfig, TctiNameConf},
};

pub fn tcti_name_conf_from_env() -> Result<TctiNameConf, String> {
    for name in ["TPM2TOOLS_TCTI", "TCTI", "TEST_TCTI"] {
        if let Ok(value) = env::var(name) {
            return value.parse::<TctiNameConf>().map_err(|error| {
                format!("failed to parse {name}={value:?} as a TCTI configuration: {error}")
            });
        }
    }

    Ok(TctiNameConf::Device(DeviceConfig::default()))
}

pub fn parse_tpm_handle_literal(value: &str) -> Result<Option<TpmHandle>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("empty TPM handle".to_string());
    }

    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        Some(u32::from_str_radix(hex, 16).map_err(|error| error.to_string())?)
    } else if trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        Some(trimmed.parse::<u32>().map_err(|error| error.to_string())?)
    } else {
        None
    };

    match parsed {
        Some(raw) => TpmHandle::try_from(raw)
            .map(Some)
            .map_err(|error| format!("unsupported TPM handle {trimmed}: {error}")),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_handle() {
        assert!(parse_tpm_handle_literal("0x81010010").unwrap().is_some());
    }

    #[test]
    fn non_numeric_literal_is_not_a_handle() {
        assert!(parse_tpm_handle_literal("/tmp/key.ctx").unwrap().is_none());
    }
}
