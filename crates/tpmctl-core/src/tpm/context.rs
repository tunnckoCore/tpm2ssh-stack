use std::env;

use tss_esapi::{
    Context,
    handles::TpmHandle,
    tcti_ldr::{DeviceConfig, TctiNameConf},
};

use crate::{CoreError, Result, StoreOptions};

/// Shared execution context passed into core operations.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct CommandContext {
    /// Optional store configuration supplied by the caller.
    pub store: StoreOptions,
    /// Optional TCTI override. Environment fallback is handled by TPM helpers.
    pub tcti: Option<String>,
}

/// Supported TPM-backed object usages.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum KeyUsage {
    Sign,
    Ecdh,
    Hmac,
    Sealed,
}

pub const TCTI_ENV_PRECEDENCE: [&str; 3] = ["TPM2TOOLS_TCTI", "TCTI", "TEST_TCTI"];

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TctiResolution {
    pub source: TctiSource,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TctiSource {
    Env(&'static str),
    DefaultDevice,
}

impl TctiResolution {
    pub fn from_environment() -> Self {
        for name in TCTI_ENV_PRECEDENCE {
            if let Ok(value) = env::var(name) {
                if !value.trim().is_empty() {
                    return Self {
                        source: TctiSource::Env(name),
                        value: Some(value),
                    };
                }
            }
        }

        Self {
            source: TctiSource::DefaultDevice,
            value: None,
        }
    }

    pub fn to_name_conf(&self) -> Result<TctiNameConf> {
        match (&self.source, &self.value) {
            (TctiSource::Env(name), Some(value)) => {
                value.parse::<TctiNameConf>().map_err(|source| {
                    CoreError::Tcti(format!(
                        "failed to parse {name}={value:?} as a TCTI configuration: {source}"
                    ))
                })
            }
            (TctiSource::DefaultDevice, None) => Ok(TctiNameConf::Device(DeviceConfig::default())),
            _ => Err(CoreError::Tcti("inconsistent TCTI resolution state".into())),
        }
    }
}

pub fn resolve_tcti_name_conf() -> Result<TctiNameConf> {
    TctiResolution::from_environment().to_name_conf()
}

pub fn tcti_name_conf_from_env() -> std::result::Result<TctiNameConf, String> {
    resolve_tcti_name_conf().map_err(|error| error.to_string())
}

pub fn parse_tpm_handle_literal(value: &str) -> std::result::Result<Option<TpmHandle>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("empty TPM handle".to_owned());
    }

    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        Some(u32::from_str_radix(hex, 16).map_err(|error| error.to_string())?)
    } else if trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        Some(
            trimmed
                .parse::<u32>()
                .map_err(|error: std::num::ParseIntError| error.to_string())?,
        )
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

pub fn resolve_tcti(override_value: Option<&str>) -> Result<String> {
    if let Some(value) = override_value {
        if value.trim().is_empty() {
            return Err(CoreError::Tcti("TCTI override is empty".into()));
        }
        return Ok(value.to_owned());
    }

    let resolution = TctiResolution::from_environment();
    Ok(resolution
        .value
        .unwrap_or_else(|| "device:/dev/tpmrm0".to_owned()))
}

pub fn create_context() -> Result<Context> {
    let tcti = resolve_tcti_name_conf()?;
    Context::new(tcti).map_err(|source| CoreError::tpm("Context::new", source))
}

pub fn create_context_with_tcti(override_value: Option<&str>) -> Result<Context> {
    let tcti = match override_value {
        Some(value) if value.trim().is_empty() => {
            return Err(CoreError::Tcti("TCTI override is empty".into()));
        }
        Some(value) => value.parse::<TctiNameConf>().map_err(|source| {
            CoreError::Tcti(format!(
                "failed to parse TCTI override {value:?} as a TCTI configuration: {source}"
            ))
        })?,
        None => resolve_tcti_name_conf()?,
    };
    Context::new(tcti).map_err(|source| CoreError::tpm("Context::new", source))
}

pub fn create_context_for(command: &CommandContext) -> Result<Context> {
    create_context_with_tcti(command.tcti.as_deref())
}
