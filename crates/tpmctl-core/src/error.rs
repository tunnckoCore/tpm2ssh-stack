use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, CoreError>;
pub type Error = CoreError;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid {field}: {reason}")]
    InvalidInput { field: &'static str, reason: String },

    #[error("TPM unavailable: {0}")]
    TpmUnavailable(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("invalid registry id {id:?}: {reason}")]
    InvalidRegistryId { id: String, reason: String },

    #[error("invalid persistent TPM handle {input:?}: {reason}")]
    InvalidHandle { input: String, reason: String },

    #[error("failed to resolve TCTI: {0}")]
    Tcti(String),

    #[error("TPM operation {operation} failed: {source}")]
    Tpm {
        operation: &'static str,
        #[source]
        source: tss_esapi::Error,
    },

    #[error("store path {path} is invalid: {reason}")]
    InvalidStorePath { path: PathBuf, reason: String },

    #[error("store entry already exists: {0}")]
    AlreadyExists(PathBuf),

    #[error("store entry was not found: {0}")]
    NotFound(PathBuf),

    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("JSON error at {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

impl CoreError {
    pub fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidInput {
            field,
            reason: reason.into(),
        }
    }

    pub fn invalid_input(field: &'static str, reason: impl Into<String>) -> Self {
        Self::invalid(field, reason)
    }

    pub fn tpm_unavailable(message: impl Into<String>) -> Self {
        Self::TpmUnavailable(message.into())
    }

    pub fn tpm(operation: &'static str, source: tss_esapi::Error) -> Self {
        Self::Tpm { operation, source }
    }

    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    pub fn json(path: impl Into<PathBuf>, source: serde_json::Error) -> Self {
        Self::Json {
            path: path.into(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CoreError;

    #[test]
    fn invalid_input_alias_matches_invalid_constructor() {
        assert!(matches!(
            CoreError::invalid_input("field", "reason"),
            CoreError::InvalidInput { field: "field", ref reason }
                if reason == "reason"
        ));
    }

    #[test]
    fn tpm_unavailable_wraps_message() {
        assert!(matches!(
            CoreError::tpm_unavailable("simulator offline"),
            CoreError::TpmUnavailable(ref message) if message == "simulator offline"
        ));
    }
}
