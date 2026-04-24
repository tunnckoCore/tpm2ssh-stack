use std::{
    fs,
    io::{self, Read as _, Write as _},
    path::Path,
};

use crate::args::CliError;
use tpmctl_core::{
    CoreError, InputSource, MaterialRef, ObjectSelector, OutputTarget, RegistryId, SealDestination,
    SealTarget,
};

const STDIN_PATH: &str = "<stdin>";
const STDOUT_PATH: &str = "<stdout>";

pub fn read_input(source: &InputSource) -> Result<Vec<u8>, CliError> {
    match source {
        InputSource::Stdin => {
            let mut bytes = Vec::new();
            io::stdin()
                .read_to_end(&mut bytes)
                .map_err(|source| CoreError::io(STDIN_PATH, source))?;
            Ok(bytes)
        }
        InputSource::File(path) => {
            fs::read(path).map_err(|source| CoreError::io(path, source).into())
        }
    }
}

pub fn write_output(target: &OutputTarget, bytes: &[u8]) -> Result<(), CliError> {
    match &target.path {
        Some(path) => write_file(path, bytes),
        None => write_stdout(bytes),
    }
}

pub fn write_stdout(bytes: &[u8]) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(bytes)
        .map_err(|source| CoreError::io(STDOUT_PATH, source))?;
    stdout
        .flush()
        .map_err(|source| CoreError::io(STDOUT_PATH, source))?;
    Ok(())
}

pub fn write_stdout_line(line: &str) -> Result<(), CliError> {
    let mut bytes = line.as_bytes().to_vec();
    bytes.push(b'\n');
    write_stdout(&bytes)
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| CoreError::io(parent, source))?;
    }
    fs::write(path, bytes).map_err(|source| CoreError::io(path, source))?;
    Ok(())
}

pub fn selector_from_material(material: &MaterialRef) -> Result<ObjectSelector, CliError> {
    match material {
        MaterialRef::Id(id) => Ok(ObjectSelector::Id(RegistryId::new(id.clone())?)),
        MaterialRef::Handle(handle) => Ok(ObjectSelector::Handle(*handle)),
    }
}

pub fn seal_target_from_destination(destination: &SealDestination) -> Result<SealTarget, CliError> {
    match destination {
        SealDestination::Id(id) => Ok(SealTarget::Id(RegistryId::new(id.clone())?)),
        SealDestination::Handle(handle) => Ok(SealTarget::Handle(*handle)),
    }
}

#[cfg(test)]
pub fn write_output_to_writer<W: std::io::Write>(
    target: &OutputTarget,
    bytes: &[u8],
    stdout: &mut W,
) -> Result<(), CliError> {
    match &target.path {
        Some(path) => write_file(path, bytes),
        None => {
            stdout
                .write_all(bytes)
                .map_err(|source| CoreError::io(STDOUT_PATH, source))?;
            Ok(())
        }
    }
}

#[cfg(test)]
pub fn temp_file_path(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("tpmctl-cli-{name}-{nanos}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_input_reads_file_bytes() {
        let path = temp_file_path("read");
        fs::write(&path, b"abc").unwrap();
        let bytes = read_input(&InputSource::File(path.clone())).unwrap();
        assert_eq!(bytes, b"abc");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn write_output_writes_file_bytes() {
        let path = temp_file_path("write");
        let target = OutputTarget {
            path: Some(path.clone()),
        };
        write_output(&target, b"xyz").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"xyz");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn write_output_to_writer_uses_stdout_for_missing_path() {
        let target = OutputTarget { path: None };
        let mut stdout = Vec::new();
        write_output_to_writer(&target, b"raw", &mut stdout).unwrap();
        assert_eq!(stdout, b"raw");
    }
}
