use std::path::PathBuf;

/// Crate-wide result type.
pub type Result<T> = std::result::Result<T, TpmctlError>;

/// Backwards-compatible alias for modules that refer to the shorter error name.
pub type Error = TpmctlError;

/// Errors produced by TPM context setup, handle parsing, registry storage, and
/// not-yet-implemented command-domain operations.
#[derive(Debug, thiserror::Error)]
pub enum TpmctlError {
    #[error("invalid key id: {0}")]
    InvalidKeyId(String),

    #[error("operation is not implemented yet: {0}")]
    NotImplemented(&'static str),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("invalid persistent handle `{input}`: {reason}")]
    InvalidPersistentHandle { input: String, reason: String },

    #[error("invalid registry id `{input}`: {reason}")]
    InvalidId { input: String, reason: String },

    #[error("could not determine store root: set --store, TPMCTL_STORE, XDG_DATA_HOME, or HOME")]
    StoreRootUnavailable,

    #[error("registry object already exists: {0}")]
    AlreadyExists(PathBuf),

    #[error("registry object not found: {0}")]
    NotFound(PathBuf),

    #[error("refusing to write outside store root: {path} is not below {root}")]
    PathEscapesStore { root: PathBuf, path: PathBuf },

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

    #[cfg(feature = "tss-esapi")]
    #[error("TPM ESAPI error: {0}")]
    Tpm(#[from] tss_esapi::Error),
}

impl TpmctlError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    pub(crate) fn json(path: impl Into<PathBuf>, source: serde_json::Error) -> Self {
        Self::Json {
            path: path.into(),
            source,
        }
    }
}
