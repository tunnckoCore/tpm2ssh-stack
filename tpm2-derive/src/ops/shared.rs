use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use secrecy::SecretBox;

use crate::backend::{CommandOutput, CommandRunner};
use crate::crypto::{
    DerivationContext as CryptoDerivationContext, DerivationDomain, DerivationSpec,
    DerivationSpecV1, OutputKind, OutputSpec,
};
use crate::error::{Error, Result};
use crate::model::{
    Algorithm, DerivationOverrides, Format, Identity, InputFormat, InputSource, Mode,
};

use super::prf::{
    PRF_CONTEXT_PATH_METADATA_KEY, PRF_PARENT_CONTEXT_PATH_METADATA_KEY,
    PRF_PRIVATE_PATH_METADATA_KEY, PRF_PUBLIC_PATH_METADATA_KEY, PrfRequest, TpmPrfExecutor,
    TpmPrfKeyHandle, execute_tpm_prf_plan_with_runner, plan_tpm_prf_in,
};

const DEFAULT_DERIVATION_ORG: &str = "tpm2-derive.identity";
const ENCRYPT_KEY_MATERIAL_TAG: &str = "encrypt-key";

pub(crate) const IDENTITY_JSON_BYTES_LIMIT: usize = 256 * 1024;
pub(crate) const BUFFERED_MESSAGE_INPUT_BYTES_LIMIT: usize = 8 * 1024 * 1024;
pub(crate) const VERIFY_SIGNATURE_INPUT_BYTES_LIMIT: usize = 64 * 1024;
pub(crate) const BUFFERED_ENCRYPT_DECRYPT_BYTES_LIMIT: usize = 8 * 1024 * 1024;

pub(crate) type SecretBytes = SecretBox<Vec<u8>>;

pub(crate) fn secret_bytes(bytes: Vec<u8>) -> SecretBytes {
    SecretBox::new(Box::new(bytes))
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct EffectiveDerivationInputs {
    pub org: String,
    pub purpose: String,
    pub context: BTreeMap<String, String>,
}

pub(crate) fn ensure_derivation_overrides_allowed(
    identity: &Identity,
    overrides: &DerivationOverrides,
) -> Result<()> {
    if identity.mode.resolved == Mode::Native && !overrides.is_empty() {
        return Err(Error::Validation(
            "native identities reject derivation overrides; remove command-level --org, --purpose, and --context flags"
                .to_string(),
        ));
    }

    Ok(())
}

pub(crate) fn resolve_effective_derivation_inputs(
    identity: &Identity,
    overrides: &DerivationOverrides,
) -> Result<EffectiveDerivationInputs> {
    ensure_derivation_overrides_allowed(identity, overrides)?;

    if identity.mode.resolved == Mode::Native {
        return Ok(EffectiveDerivationInputs {
            org: DEFAULT_DERIVATION_ORG.to_string(),
            purpose: identity.name.clone(),
            context: BTreeMap::new(),
        });
    }

    let mut context = identity.defaults.context.clone();
    for (key, value) in &overrides.context {
        validate_non_empty("context key", key)?;
        validate_non_empty(&format!("context value for key '{key}'"), value)?;
        context.insert(key.clone(), value.clone());
    }

    let org = overrides
        .org
        .clone()
        .or_else(|| identity.defaults.org.clone())
        .unwrap_or_else(|| DEFAULT_DERIVATION_ORG.to_string());
    let purpose = overrides
        .purpose
        .clone()
        .or_else(|| identity.defaults.purpose.clone())
        .unwrap_or_else(|| identity.name.clone());

    validate_non_empty("org", &org)?;
    validate_non_empty("purpose", &purpose)?;

    Ok(EffectiveDerivationInputs {
        org,
        purpose,
        context,
    })
}

pub(crate) fn encrypt_command_spec(
    effective: &EffectiveDerivationInputs,
) -> Result<DerivationSpec> {
    Ok(DerivationSpec::V1(DerivationSpecV1::new(
        base_context(effective).with_field("material", ENCRYPT_KEY_MATERIAL_TAG),
        OutputSpec::new(OutputKind::SecretBytes, 32)?,
    )?))
}

pub(crate) fn identity_key_spec(
    algorithm: Algorithm,
    effective: &EffectiveDerivationInputs,
) -> Result<DerivationSpec> {
    let output_kind = match algorithm {
        Algorithm::Ed25519 => OutputKind::Ed25519Seed,
        Algorithm::P256 => OutputKind::P256Scalar,
        Algorithm::Secp256k1 => OutputKind::Secp256k1Scalar,
    };

    Ok(DerivationSpec::V1(DerivationSpecV1::new(
        base_context(effective),
        OutputSpec::new(output_kind, 32)?,
    )?))
}

pub(crate) fn execute_prf_derivation_with_runner<R>(
    identity: &Identity,
    spec: DerivationSpec,
    runner: &R,
    workspace_kind: &str,
) -> Result<SecretBytes>
where
    R: CommandRunner,
{
    let executor = resolve_prf_executor(identity)?;
    let request = PrfRequest::new(identity.name.clone(), spec)?;
    let workspace_root = temporary_workspace_root(workspace_kind, &identity.name)?;
    let plan = plan_tpm_prf_in(request, executor, &workspace_root)?;
    let execution = execute_tpm_prf_plan_with_runner(&plan, runner);
    let cleanup = fs::remove_dir_all(&workspace_root).map_err(|error| {
        Error::State(format!(
            "failed to remove {workspace_kind} workspace '{}': {error}",
            workspace_root.display()
        ))
    });

    match (execution, cleanup) {
        (Ok(result), Ok(())) => Ok(secret_bytes(
            result.response.output.expose_secret().to_vec(),
        )),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

pub(crate) fn resolve_prf_executor(identity: &Identity) -> Result<TpmPrfExecutor> {
    let object_dir = identity
        .storage
        .state_layout
        .objects_dir
        .join(&identity.name);

    let metadata_parent = identity
        .metadata
        .get(PRF_PARENT_CONTEXT_PATH_METADATA_KEY)
        .map(|path| resolve_state_path(identity, path));
    let metadata_public = identity
        .metadata
        .get(PRF_PUBLIC_PATH_METADATA_KEY)
        .map(|path| resolve_state_path(identity, path));
    let metadata_private = identity
        .metadata
        .get(PRF_PRIVATE_PATH_METADATA_KEY)
        .map(|path| resolve_state_path(identity, path));

    if let (Some(parent_context_path), Some(public_path), Some(private_path)) =
        (metadata_parent, metadata_public, metadata_private)
    {
        return Ok(TpmPrfExecutor::v1(TpmPrfKeyHandle::LoadableObject {
            parent_context_path,
            public_path,
            private_path,
        }));
    }

    for (parent, public, private) in [
        ("parent.ctx", "prf-root.pub", "prf-root.priv"),
        ("parent.ctx", "root.pub", "root.priv"),
    ] {
        let parent_context_path = object_dir.join(parent);
        let public_path = object_dir.join(public);
        let private_path = object_dir.join(private);
        if parent_context_path.is_file() && public_path.is_file() && private_path.is_file() {
            return Ok(TpmPrfExecutor::v1(TpmPrfKeyHandle::LoadableObject {
                parent_context_path,
                public_path,
                private_path,
            }));
        }
    }

    if let Some(context_path) = identity
        .metadata
        .get(PRF_CONTEXT_PATH_METADATA_KEY)
        .map(|path| resolve_state_path(identity, path))
    {
        return Ok(TpmPrfExecutor::v1(TpmPrfKeyHandle::LoadedContext {
            context_path,
        }));
    }

    for file_name in ["prf-root.ctx", "root.ctx", "key.ctx"] {
        let candidate = object_dir.join(file_name);
        if candidate.is_file() {
            return Ok(TpmPrfExecutor::v1(TpmPrfKeyHandle::LoadedContext {
                context_path: candidate,
            }));
        }
    }

    Err(Error::Unsupported(format!(
        "identity '{}' resolved to PRF mode but no PRF root material was found; expected metadata '{}' or loadable blobs under '{}'",
        identity.name,
        PRF_CONTEXT_PATH_METADATA_KEY,
        object_dir.display()
    )))
}

fn base_context(effective: &EffectiveDerivationInputs) -> CryptoDerivationContext {
    let mut context = CryptoDerivationContext::new(
        effective.org.clone(),
        DerivationDomain::Application,
        effective.purpose.clone(),
    );

    for (key, value) in &effective.context {
        context = context.with_field(key.clone(), value.clone());
    }

    context
}

fn resolve_state_path(identity: &Identity, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        identity.storage.state_layout.root_dir.join(path)
    }
}

fn temporary_workspace_root(kind: &str, _identity: &str) -> Result<PathBuf> {
    let tempdir = tempfile::Builder::new()
        .prefix(&format!("tpm2-derive-{kind}-"))
        .tempdir()
        .map_err(|error| {
            Error::State(format!(
                "failed to allocate secure temporary {kind} workspace: {error}"
            ))
        })?;
    let path = tempdir.keep();
    fs::remove_dir(&path).map_err(|error| {
        Error::State(format!(
            "failed to prepare fresh temporary {kind} workspace '{}': {error}",
            path.display()
        ))
    })?;
    Ok(path)
}

pub(crate) fn ensure_bytes_within_limit(label: &str, len: usize, max_bytes: usize) -> Result<()> {
    if len > max_bytes {
        return Err(Error::Validation(format!(
            "{label} exceeds the {max_bytes}-byte limit"
        )));
    }

    Ok(())
}

pub(crate) fn load_input_bytes_with_limit(
    input: &InputSource,
    label: &str,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    match input {
        InputSource::Stdin => {
            let stdin = std::io::stdin();
            read_reader_bytes_with_limit(stdin.lock(), label, max_bytes)
        }
        InputSource::Path { path } => read_path_bytes_with_limit(path, label, max_bytes),
    }
}

pub(crate) fn read_path_string_with_limit(
    path: &Path,
    label: &str,
    max_bytes: usize,
) -> Result<String> {
    let bytes = read_path_bytes_with_limit(path, label, max_bytes)?;
    String::from_utf8(bytes).map_err(|error| {
        Error::State(format!(
            "failed to decode {label} '{}' as UTF-8: {error}",
            path.display()
        ))
    })
}

pub(crate) fn read_path_bytes_with_limit(
    path: &Path,
    label: &str,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    if let Ok(metadata) = fs::metadata(path) {
        if metadata.is_file() {
            let file_len = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
            ensure_bytes_within_limit(
                &format!("{label} '{}'", path.display()),
                file_len,
                max_bytes,
            )?;
        }
    }

    let file = fs::File::open(path).map_err(|error| {
        Error::State(format!(
            "failed to read {label} '{}': {error}",
            path.display()
        ))
    })?;

    read_reader_bytes_with_limit(file, &format!("{label} '{}'", path.display()), max_bytes)
}

pub(crate) fn read_reader_bytes_with_limit<R>(
    reader: R,
    label: &str,
    max_bytes: usize,
) -> Result<Vec<u8>>
where
    R: Read,
{
    let max_with_sentinel = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX.saturating_sub(1))
        .saturating_add(1);
    let mut limited_reader = reader.take(max_with_sentinel);
    let mut buffer = Vec::new();
    limited_reader
        .read_to_end(&mut buffer)
        .map_err(|error| Error::State(format!("failed to read {label}: {error}")))?;
    ensure_bytes_within_limit(label, buffer.len(), max_bytes)?;
    Ok(buffer)
}

pub(crate) fn encode_textual_output_bytes(format: Format, bytes: &[u8]) -> Result<Vec<u8>> {
    match format {
        Format::Hex => Ok(hex_encode(bytes).into_bytes()),
        Format::Base64 => Ok(base64_encode(bytes).into_bytes()),
        Format::Der => Ok(bytes.to_vec()),
        Format::Pem | Format::Openssh | Format::Eth => Err(Error::Validation(format!(
            "format '{format:?}' is not valid for this output"
        ))),
    }
}

pub(crate) fn decode_input_bytes(
    format: InputFormat,
    bytes: &[u8],
    label: &str,
) -> Result<(Vec<u8>, InputFormat)> {
    match format {
        InputFormat::Raw => Ok((bytes.to_vec(), InputFormat::Raw)),
        InputFormat::Der => Ok((bytes.to_vec(), InputFormat::Der)),
        InputFormat::Hex => Ok((decode_hex_text(bytes, label)?, InputFormat::Hex)),
        InputFormat::Base64 => Ok((decode_base64_text(bytes, label)?, InputFormat::Base64)),
        InputFormat::Auto => {
            if let Ok(decoded) = decode_hex_text(bytes, label) {
                return Ok((decoded, InputFormat::Hex));
            }
            if let Ok(decoded) = decode_base64_text(bytes, label) {
                return Ok((decoded, InputFormat::Base64));
            }
            Ok((bytes.to_vec(), InputFormat::Raw))
        }
        InputFormat::Pem | InputFormat::Openssh | InputFormat::Eth => Err(Error::Validation(
            format!("format '{format:?}' is not valid for {label}"),
        )),
    }
}

pub(crate) fn output_format_extension(format: Format) -> &'static str {
    match format {
        Format::Der => "der",
        Format::Pem => "pem",
        Format::Openssh => "openssh",
        Format::Eth => "eth",
        Format::Hex => "hex",
        Format::Base64 => "base64",
    }
}

pub(crate) fn write_output_file(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| {
        Error::State(format!(
            "failed to create output directory '{}': {error}",
            parent.display()
        ))
    })?;

    if let Ok(metadata) = fs::symlink_metadata(path) {
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(Error::Validation(format!(
                "output '{}' must not be a symlink",
                path.display()
            )));
        }
        if !file_type.is_file() {
            return Err(Error::Validation(format!(
                "output '{}' must be a regular file path",
                path.display()
            )));
        }
    }

    let temp_path = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("output"),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    let mut file = options.open(&temp_path).map_err(|error| {
        Error::State(format!(
            "failed to create temp output file '{}': {error}",
            temp_path.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| {
                let _ = fs::remove_file(&temp_path);
                Error::State(format!(
                    "failed to harden temp output permissions '{}': {error}",
                    temp_path.display()
                ))
            })?;
    }

    use std::io::Write as _;
    if let Err(error) = file.write_all(data) {
        let _ = fs::remove_file(&temp_path);
        return Err(Error::State(format!(
            "failed to write output to '{}': {error}",
            temp_path.display()
        )));
    }
    drop(file);

    fs::rename(&temp_path, path).map_err(|error| {
        let _ = fs::remove_file(&temp_path);
        Error::State(format!(
            "failed to move output into place '{}' -> '{}': {error}",
            temp_path.display(),
            path.display()
        ))
    })
}

pub(crate) fn ensure_dir(path: &Path, label: &str) -> Result<()> {
    fs::create_dir_all(path).map_err(|error| {
        Error::State(format!(
            "failed to create {label} directory '{}': {error}",
            path.display()
        ))
    })
}

pub(crate) fn classify_native_command_failure(program: &str, output: &CommandOutput) -> Error {
    let detail = render_command_failure_detail(output);
    let lower = detail.to_ascii_lowercase();
    let message = format!(
        "native TPM command '{}' failed{}{}",
        program,
        output
            .exit_code
            .map(|code| format!(" with exit status {code}"))
            .unwrap_or_default(),
        if detail.is_empty() {
            String::new()
        } else {
            format!(": {detail}")
        }
    );

    if lower.contains("auth") || lower.contains("authorization") {
        Error::AuthFailure(message)
    } else if output.error.is_some()
        || lower.contains("tcti")
        || lower.contains("/dev/tpm")
        || lower.contains("no standard tcti")
        || lower.contains("connection refused")
    {
        Error::TpmUnavailable(message)
    } else if lower.contains("no such file")
        || lower.contains("could not open")
        || lower.contains("cannot open")
        || lower.contains("context")
        || lower.contains("handle")
    {
        Error::State(message)
    } else {
        Error::CapabilityMismatch(message)
    }
}

fn render_command_failure_detail(output: &CommandOutput) -> String {
    if let Some(error) = output.error.as_deref() {
        return error.to_string();
    }

    let detail = if !output.stderr.trim().is_empty() {
        output.stderr.trim()
    } else {
        output.stdout.trim()
    };

    preview(detail)
}

fn preview(value: &str) -> String {
    let single_line = value.lines().map(str::trim).collect::<Vec<_>>().join(" ");
    let trimmed = single_line.trim();
    const LIMIT: usize = 180;
    if trimmed.len() > LIMIT {
        format!("{}…", &trimmed[..LIMIT])
    } else {
        trimmed.to_string()
    }
}

fn decode_hex_text(bytes: &[u8], label: &str) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::Validation(format!("{label} must be valid UTF-8 hex text")))?
        .trim();
    if text.is_empty() || text.len() % 2 != 0 || !text.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(Error::Validation(format!(
            "{label} must be non-empty hexadecimal text"
        )));
    }

    let mut decoded = Vec::with_capacity(text.len() / 2);
    for index in (0..text.len()).step_by(2) {
        let chunk = &text[index..index + 2];
        let byte = u8::from_str_radix(chunk, 16).map_err(|error| {
            Error::Validation(format!("failed to decode hexadecimal {label}: {error}"))
        })?;
        decoded.push(byte);
    }
    Ok(decoded)
}

fn decode_base64_text(bytes: &[u8], label: &str) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::Validation(format!("{label} must be valid UTF-8 base64 text")))?
        .trim();
    if text.is_empty() {
        return Err(Error::Validation(format!("{label} must not be empty")));
    }

    base64_decode(text)
        .map_err(|error| Error::Validation(format!("failed to decode base64 {label}: {error}")))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let triple = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);

        output.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        output.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(TABLE[(triple & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }

    output
}

fn base64_decode(value: &str) -> Result<Vec<u8>> {
    fn sextet(ch: char) -> Option<u8> {
        match ch {
            'A'..='Z' => Some((ch as u8) - b'A'),
            'a'..='z' => Some((ch as u8) - b'a' + 26),
            '0'..='9' => Some((ch as u8) - b'0' + 52),
            '+' => Some(62),
            '/' => Some(63),
            _ => None,
        }
    }

    let compact = value
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>();
    if compact.len() % 4 != 0 {
        return Err(Error::Validation(
            "base64 text length must be a multiple of 4".to_string(),
        ));
    }

    let mut output = Vec::with_capacity((compact.len() / 4) * 3);
    for chunk in compact.as_bytes().chunks(4) {
        let chars = chunk.iter().map(|byte| *byte as char).collect::<Vec<_>>();
        let mut values = [0u8; 4];
        let mut padding = 0usize;
        for (index, ch) in chars.iter().enumerate() {
            if *ch == '=' {
                values[index] = 0;
                padding += 1;
            } else if let Some(value) = sextet(*ch) {
                values[index] = value;
            } else {
                return Err(Error::Validation(format!(
                    "invalid base64 character '{}'; expected A-Z, a-z, 0-9, '+' or '/'",
                    ch
                )));
            }
        }

        let triple = ((values[0] as u32) << 18)
            | ((values[1] as u32) << 12)
            | ((values[2] as u32) << 6)
            | (values[3] as u32);
        output.push(((triple >> 16) & 0xff) as u8);
        if padding < 2 {
            output.push(((triple >> 8) & 0xff) as u8);
        }
        if padding < 1 {
            output.push((triple & 0xff) as u8);
        }
    }

    Ok(output)
}

fn validate_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::Validation(format!("{field} must not be empty")));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use secrecy::ExposeSecret;

    fn assert_secret_bytes(_: &SecretBytes) {}

    #[test]
    fn secret_bytes_wraps_derived_material_in_secret_storage() {
        let secret = secret_bytes(vec![0x12, 0x34, 0x56]);

        assert_secret_bytes(&secret);
        assert_eq!(secret.expose_secret().as_slice(), &[0x12, 0x34, 0x56]);
    }

    #[test]
    fn read_reader_bytes_with_limit_accepts_exact_limit() {
        let bytes = read_reader_bytes_with_limit(Cursor::new(vec![0xAA; 4]), "stdin input", 4)
            .expect("read exact-size input");

        assert_eq!(bytes, vec![0xAA; 4]);
    }

    #[test]
    fn read_reader_bytes_with_limit_rejects_oversized_input() {
        let error = read_reader_bytes_with_limit(Cursor::new(vec![0xAA; 5]), "stdin input", 4)
            .expect_err("oversized stdin input should fail");

        assert!(
            matches!(error, Error::Validation(message) if message.contains("stdin input") && message.contains("4-byte limit"))
        );
    }
}
