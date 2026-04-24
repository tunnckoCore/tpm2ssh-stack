use std::fmt;

/// Result alias used by all public `tpmctl-core` contracts.
pub type Result<T> = std::result::Result<T, Error>;

/// Stable error surface for frontends.
///
/// Domain modules currently return `Unsupported` until the TPM-backed behavior
/// is implemented by the owning workstreams.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
    /// A public contract exists, but its implementation has not landed yet.
    Unsupported { operation: &'static str },
    /// Caller supplied an invalid value for a named field.
    InvalidInput { field: &'static str, reason: String },
}

impl Error {
    pub fn unsupported(operation: &'static str) -> Self {
        Self::Unsupported { operation }
    }

    pub fn invalid_input(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidInput {
            field,
            reason: reason.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { operation } => {
                write!(formatter, "operation is not implemented yet: {operation}")
            }
            Self::InvalidInput { field, reason } => write!(formatter, "invalid {field}: {reason}"),
        }
    }
}

impl std::error::Error for Error {}
