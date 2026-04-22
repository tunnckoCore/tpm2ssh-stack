use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::backend::{CommandOutput, CommandRunner};
use crate::crypto::{
    DerivationContext as CryptoDerivationContext, DerivationDomain, DerivationSpec,
    DerivationSpecV1, OutputKind, OutputSpec,
};
use crate::error::{Error, Result};
use crate::model::{Algorithm, DerivationOverrides, Identity, InputSource, Mode};

use super::prf::{
    PRF_CONTEXT_PATH_METADATA_KEY, PRF_PARENT_CONTEXT_PATH_METADATA_KEY,
    PRF_PRIVATE_PATH_METADATA_KEY, PRF_PUBLIC_PATH_METADATA_KEY, PrfRequest, TpmPrfExecutor,
    TpmPrfKeyHandle, execute_tpm_prf_plan_with_runner, plan_tpm_prf_in,
};

const DEFAULT_DERIVATION_ORG: &str = "tpm2-derive.identity";
const ENCRYPT_KEY_MATERIAL_TAG: &str = "encrypt-key";

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

pub(crate) fn derive_command_spec(
    effective: &EffectiveDerivationInputs,
    length: u16,
) -> Result<DerivationSpec> {
    Ok(DerivationSpec::V1(DerivationSpecV1::new(
        base_context(effective),
        OutputSpec::new(OutputKind::SecretBytes, length)?,
    )?))
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
) -> Result<Vec<u8>>
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
        (Ok(result), Ok(())) => Ok(result.response.output.expose_secret().to_vec()),
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

fn temporary_workspace_root(kind: &str, identity: &str) -> Result<PathBuf> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            Error::State(format!(
                "system clock error while creating {kind} workspace: {error}"
            ))
        })?;
    let sanitized_identity = identity
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>();

    Ok(std::env::temp_dir().join(format!(
        "tpm2-derive-{kind}-{}-{sanitized_identity}-{}",
        std::process::id(),
        now.as_nanos()
    )))
}

pub(crate) fn load_input_bytes(input: &InputSource, label: &str) -> Result<Vec<u8>> {
    match input {
        InputSource::Stdin => {
            let mut buffer = Vec::new();
            std::io::stdin().read_to_end(&mut buffer).map_err(|error| {
                Error::State(format!("failed to read {label} from stdin: {error}"))
            })?;
            Ok(buffer)
        }
        InputSource::Path { path } => fs::read(path).map_err(|error| {
            Error::State(format!(
                "failed to read {label} '{}': {error}",
                path.display()
            ))
        }),
    }
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

fn validate_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::Validation(format!("{field} must not be empty")));
    }

    Ok(())
}
