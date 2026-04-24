use crate::args::{DeriveFormat, PubkeyFormat, RawHexFormat, SignatureFormat};
use is_terminal::IsTerminal;
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, thiserror::Error)]
pub enum IoError {
    #[error("{0}")]
    RefuseBinaryTty(&'static str),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, IoError>;

pub fn read_input(path: &Path) -> Result<Vec<u8>> {
    if is_dash(path) {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        Ok(fs::read(path)?)
    }
}

#[allow(dead_code)]
pub fn write_output(path: Option<&PathBuf>, bytes: &[u8], binary: bool, force: bool) -> Result<()> {
    match path {
        Some(path) if !is_dash(path) => Ok(fs::write(path, bytes)?),
        _ => {
            guard_binary_stdout(binary, force)?;
            let mut stdout = io::stdout().lock();
            stdout.write_all(bytes)?;
            Ok(stdout.flush()?)
        }
    }
}

pub fn guard_binary_stdout(binary: bool, force: bool) -> Result<()> {
    if binary && !force && io::stdout().is_terminal() {
        return Err(IoError::RefuseBinaryTty(
            "refusing to write binary data to terminal; use --output or --force",
        ));
    }
    Ok(())
}

pub fn is_dash(path: &Path) -> bool {
    path.as_os_str() == "-"
}

pub trait OutputKind {
    fn is_binary(self) -> bool;
}

impl OutputKind for SignatureFormat {
    fn is_binary(self) -> bool {
        matches!(self, Self::Der | Self::Raw)
    }
}
impl OutputKind for PubkeyFormat {
    fn is_binary(self) -> bool {
        matches!(self, Self::Raw | Self::Der)
    }
}
impl OutputKind for RawHexFormat {
    fn is_binary(self) -> bool {
        matches!(self, Self::Raw)
    }
}
impl OutputKind for DeriveFormat {
    fn is_binary(self) -> bool {
        matches!(self, Self::Raw | Self::Der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn dash_models_stdio() {
        assert!(is_dash(Path::new("-")));
        assert!(!is_dash(Path::new("./-")));
    }

    #[test]
    fn writes_file_without_tty_guard() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("out.bin");
        write_output(Some(&path), b"abc", true, false).unwrap();
        assert_eq!(fs::read(path).unwrap(), b"abc");
    }
}
