use std::str::FromStr;

use tss_esapi::handles::{PersistentTpmHandle, TpmHandle};

use crate::{CoreError, Result};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PersistentHandle {
    raw: u32,
    handle: PersistentTpmHandle,
}

impl PersistentHandle {
    pub fn new(raw: u32) -> Result<Self> {
        let handle = PersistentTpmHandle::new(raw).map_err(|error| {
            invalid_handle(
                &format!("0x{raw:08x}"),
                format!("not a persistent TPM handle: {error}"),
            )
        })?;
        Ok(Self { raw, handle })
    }

    pub fn parse(input: impl AsRef<str>) -> Result<Self> {
        input.as_ref().parse()
    }

    pub fn raw(self) -> u32 {
        self.raw
    }

    pub fn tpm_handle(self) -> TpmHandle {
        TpmHandle::Persistent(self.handle)
    }

    pub fn persistent_tpm_handle(self) -> PersistentTpmHandle {
        self.handle
    }
}

impl std::hash::Hash for PersistentHandle {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl std::fmt::Display for PersistentHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "0x{:08x}", self.raw)
    }
}

impl FromStr for PersistentHandle {
    type Err = CoreError;

    fn from_str(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(invalid_handle(input, "handle is empty"));
        }
        if trimmed != input {
            return Err(invalid_handle(
                input,
                "leading or trailing whitespace is not allowed",
            ));
        }

        let Some(hex) = trimmed.strip_prefix("0x") else {
            return Err(invalid_handle(
                input,
                "persistent handles must be hexadecimal and start with 0x",
            ));
        };
        if hex.is_empty() {
            return Err(invalid_handle(input, "hex digits are missing"));
        }
        if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid_handle(
                input,
                "handle contains non-hexadecimal characters",
            ));
        }

        let raw = u32::from_str_radix(hex, 16)
            .map_err(|error| invalid_handle(input, format!("handle is out of range: {error}")))?;
        let handle = PersistentTpmHandle::new(raw).map_err(|error| {
            invalid_handle(input, format!("not a persistent TPM handle: {error}"))
        })?;

        Ok(Self { raw, handle })
    }
}

fn invalid_handle(input: &str, reason: impl Into<String>) -> CoreError {
    CoreError::InvalidHandle {
        input: input.to_owned(),
        reason: reason.into(),
    }
}
