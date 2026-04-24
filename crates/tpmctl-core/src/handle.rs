use std::{fmt, str::FromStr};

use crate::{Error, Result};

/// TPM persistent handle in the 0x81xx_xxxx persistent handle range.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct PersistentHandle(u32);

impl PersistentHandle {
    pub const MIN: u32 = 0x8100_0000;
    pub const MAX: u32 = 0x81ff_ffff;

    pub fn new(raw: u32) -> Result<Self> {
        if (Self::MIN..=Self::MAX).contains(&raw) {
            Ok(Self(raw))
        } else {
            Err(Error::InvalidPersistentHandle {
                input: format!("0x{raw:08x}"),
                reason: "persistent handles must be in 0x81000000..=0x81ffffff".to_string(),
            })
        }
    }

    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl fmt::Display for PersistentHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

impl FromStr for PersistentHandle {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        let hex = input
            .strip_prefix("0x")
            .or_else(|| input.strip_prefix("0X"))
            .ok_or_else(|| Error::InvalidPersistentHandle {
                input: input.to_string(),
                reason: "expected hex string with 0x prefix, e.g. 0x81010010".to_string(),
            })?;
        if hex.is_empty() || hex.len() > 8 {
            return Err(Error::InvalidPersistentHandle {
                input: input.to_string(),
                reason: "expected 1 to 8 hex digits after 0x".to_string(),
            });
        }
        let raw = u32::from_str_radix(hex, 16).map_err(|_| Error::InvalidPersistentHandle {
            input: input.to_string(),
            reason: "contains non-hex characters".to_string(),
        })?;
        Self::new(raw).map_err(|_| Error::InvalidPersistentHandle {
            input: input.to_string(),
            reason: "persistent handles must be in 0x81000000..=0x81ffffff".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_persistent_handle() {
        let handle: PersistentHandle = "0x81010010".parse().unwrap();
        assert_eq!(handle.raw(), 0x8101_0010);
        assert_eq!(handle.to_string(), "0x81010010");
    }

    #[test]
    fn rejects_non_persistent_or_non_hex_handles() {
        assert!("81010010".parse::<PersistentHandle>().is_err());
        assert!("0x80000000".parse::<PersistentHandle>().is_err());
        assert!("0x82000000".parse::<PersistentHandle>().is_err());
        assert!("0xnope".parse::<PersistentHandle>().is_err());
    }
}
