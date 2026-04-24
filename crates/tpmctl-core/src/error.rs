pub type Result<T> = std::result::Result<T, TpmctlError>;

#[derive(Debug, thiserror::Error)]
pub enum TpmctlError {
    #[error("invalid key id: {0}")]
    InvalidKeyId(String),
    #[error("operation is not implemented yet: {0}")]
    NotImplemented(&'static str),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}
