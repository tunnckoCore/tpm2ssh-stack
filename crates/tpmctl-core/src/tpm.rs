use std::fmt;

/// Shared execution context passed from frontends into core operations.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct CommandContext {
    /// Optional store configuration supplied by a frontend.
    pub store: crate::store::StoreOptions,
    /// Optional TCTI override. Later implementation owns environment fallback.
    pub tcti: Option<String>,
}

/// TPM persistent handle literal.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PersistentHandle(pub u32);

impl PersistentHandle {
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl fmt::Display for PersistentHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{:08x}", self.0)
    }
}

/// Supported TPM-backed object usages.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum KeyUsage {
    Sign,
    Ecdh,
    Hmac,
    Sealed,
}

/// Placeholder for future TPM context construction.
pub fn resolve_tcti(_override_value: Option<&str>) -> crate::Result<String> {
    Err(crate::Error::unsupported("tpm::resolve_tcti"))
}
