use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    Usage,
    Validation,
    State,
    TpmUnavailable,
    AuthFailure,
    CapabilityMismatch,
    PolicyRefusal,
    Unsupported,
    Internal,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::Validation => "validation",
            Self::State => "state",
            Self::TpmUnavailable => "tpm-unavailable",
            Self::AuthFailure => "auth-failure",
            Self::CapabilityMismatch => "capability-mismatch",
            Self::PolicyRefusal => "policy-refusal",
            Self::Unsupported => "unsupported",
            Self::Internal => "internal",
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("usage error: {0}")]
    Usage(String),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("state error: {0}")]
    State(String),
    #[error("TPM unavailable: {0}")]
    TpmUnavailable(String),
    #[error("authentication failure: {0}")]
    AuthFailure(String),
    #[error("capability mismatch: {0}")]
    CapabilityMismatch(String),
    #[error("policy refusal: {0}")]
    PolicyRefusal(String),
    #[error("unsupported operation: {0}")]
    Unsupported(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl Error {
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Usage(_) => ErrorCode::Usage,
            Self::Validation(_) => ErrorCode::Validation,
            Self::State(_) => ErrorCode::State,
            Self::TpmUnavailable(_) => ErrorCode::TpmUnavailable,
            Self::AuthFailure(_) => ErrorCode::AuthFailure,
            Self::CapabilityMismatch(_) => ErrorCode::CapabilityMismatch,
            Self::PolicyRefusal(_) => ErrorCode::PolicyRefusal,
            Self::Unsupported(_) => ErrorCode::Unsupported,
            Self::Internal(_) | Self::Serialization(_) => ErrorCode::Internal,
        }
    }

    pub const fn exit_code(&self) -> i32 {
        match self.code() {
            ErrorCode::Usage | ErrorCode::Validation => 2,
            ErrorCode::State => 3,
            ErrorCode::TpmUnavailable => 4,
            ErrorCode::AuthFailure => 5,
            ErrorCode::CapabilityMismatch => 6,
            ErrorCode::PolicyRefusal => 7,
            ErrorCode::Unsupported => 8,
            ErrorCode::Internal => 1,
        }
    }
}
