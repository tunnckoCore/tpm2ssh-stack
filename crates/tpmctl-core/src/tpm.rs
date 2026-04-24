#[cfg(feature = "tss-esapi")]
use std::str::FromStr;

use crate::{Result, tcti::TctiConfig};

/// TPM context configuration shared by command-domain operations.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TpmConfig {
    pub tcti: TctiConfig,
}

impl Default for TpmConfig {
    fn default() -> Self {
        Self {
            tcti: TctiConfig::resolve(),
        }
    }
}

/// Lightweight ESAPI context wrapper. The actual TSS object is available when the
/// `tss-esapi` feature is enabled; default builds can still test registry logic.
#[cfg(feature = "tss-esapi")]
pub struct EsapiContext {
    inner: tss_esapi::Context,
}

#[cfg(feature = "tss-esapi")]
impl EsapiContext {
    pub fn connect(config: &TpmConfig) -> Result<Self> {
        let tcti = match &config.tcti.name_conf {
            Some(name_conf) => tss_esapi::tcti_ldr::TctiNameConf::from_str(name_conf)?,
            None => tss_esapi::tcti_ldr::TctiNameConf::Device(Default::default()),
        };
        Ok(Self {
            inner: tss_esapi::Context::new(tcti)?,
        })
    }

    pub fn inner(&self) -> &tss_esapi::Context {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut tss_esapi::Context {
        &mut self.inner
    }
}

/// Stub context for builds that do not enable typed TSS integration yet.
#[cfg(not(feature = "tss-esapi"))]
#[derive(Debug, Clone)]
pub struct EsapiContext;

#[cfg(not(feature = "tss-esapi"))]
impl EsapiContext {
    pub fn connect(_config: &TpmConfig) -> Result<Self> {
        Ok(Self)
    }
}
