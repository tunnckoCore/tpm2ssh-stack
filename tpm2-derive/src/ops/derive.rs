use std::path::{Path, PathBuf};

use secrecy::ExposeSecret;

use crate::backend::CommandRunner;
use crate::error::{Error, Result};
use crate::model::{DeriveRequest, DeriveResult, Identity, Mode};

use super::seed::{
    HkdfSha256SeedDeriver, SEED_PRIVATE_BLOB_PATH_METADATA_KEY, SEED_PUBLIC_BLOB_PATH_METADATA_KEY,
    SeedBackend, SeedOpenAuthSource, SeedOpenOutput, SeedOpenRequest, SeedSoftwareDeriver,
    SoftwareSeedDerivationRequest, SubprocessSeedBackend, open_and_derive,
    seed_profile_from_profile,
};
use super::shared::{
    derive_command_spec, encode_textual_output_bytes, execute_prf_derivation_with_runner,
    resolve_effective_derivation_inputs, write_output_file,
};

pub fn execute_with_defaults<R>(
    identity: &Identity,
    request: &DeriveRequest,
    prf_runner: &R,
) -> Result<DeriveResult>
where
    R: CommandRunner,
{
    let seed_backend =
        SubprocessSeedBackend::new(identity.storage.state_layout.objects_dir.clone());
    let seed_deriver = HkdfSha256SeedDeriver;
    execute_with_runner(identity, request, prf_runner, &seed_backend, &seed_deriver)
}

pub fn execute_with_runner<R, B, D>(
    identity: &Identity,
    request: &DeriveRequest,
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
) -> Result<DeriveResult>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    if !identity.uses.contains(&crate::model::UseCase::Derive) {
        return Err(Error::PolicyRefusal(format!(
            "identity '{}' is not configured with use=derive",
            identity.name
        )));
    }

    crate::model::UseCase::validate_for_mode(&identity.uses, identity.mode.resolved)?;

    let effective = resolve_effective_derivation_inputs(identity, &request.derivation)?;
    let spec = derive_command_spec(&effective, request.length)?;

    match identity.mode.resolved {
        Mode::Native => Err(Error::Unsupported(format!(
            "identity '{}' resolved to native mode; derive is currently wired only for PRF and seed identities",
            identity.name
        ))),
        Mode::Prf => execute_prf(identity, request, spec, prf_runner),
        Mode::Seed => execute_seed(identity, request, spec, seed_backend, seed_deriver),
    }
}

fn execute_prf<R>(
    identity: &Identity,
    request: &DeriveRequest,
    spec: crate::crypto::DerivationSpec,
    runner: &R,
) -> Result<DeriveResult>
where
    R: CommandRunner,
{
    let material = execute_prf_derivation_with_runner(identity, spec, runner, "derive")?;
    build_result(
        identity,
        Mode::Prf,
        request.length,
        request.format,
        request.output.as_deref(),
        &material,
    )
}

fn execute_seed<B, D>(
    identity: &Identity,
    request: &DeriveRequest,
    spec: crate::crypto::DerivationSpec,
    backend: &B,
    deriver: &D,
) -> Result<DeriveResult>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let seed_identity = seed_profile_from_profile(identity)?;
    ensure_seed_material_exists(identity)?;

    let seed_request = SeedOpenRequest {
        identity: seed_identity,
        auth_source: SeedOpenAuthSource::None,
        output: SeedOpenOutput::DerivedBytes(SoftwareSeedDerivationRequest {
            spec,
            output_bytes: usize::from(request.length),
        }),
        require_fresh_unseal: true,
        confirm_software_derivation: true,
    };

    let derived = open_and_derive(backend, deriver, &seed_request)?;
    build_result(
        identity,
        Mode::Seed,
        request.length,
        request.format,
        request.output.as_deref(),
        derived.expose_secret(),
    )
}

fn build_result(
    identity: &Identity,
    mode: Mode,
    length: u16,
    format: crate::model::Format,
    output: Option<&Path>,
    material: &[u8],
) -> Result<DeriveResult> {
    if !matches!(
        format,
        crate::model::Format::Hex | crate::model::Format::Base64
    ) {
        return Err(Error::Validation(
            "derive formats are: hex, base64".to_string(),
        ));
    }

    let encoded = encode_textual_output_bytes(format, material)?;

    match output {
        Some(path) => {
            write_output_file(path, &encoded)?;
            Ok(DeriveResult {
                identity: identity.name.clone(),
                mode,
                length,
                format,
                output_path: Some(path.to_path_buf()),
                bytes_written: encoded.len(),
                material: None,
            })
        }
        None => Ok(DeriveResult {
            identity: identity.name.clone(),
            mode,
            length,
            format,
            output_path: None,
            bytes_written: encoded.len(),
            material: Some(String::from_utf8(encoded).map_err(|error| {
                Error::State(format!(
                    "derived output for identity '{}' could not be rendered as text: {error}",
                    identity.name
                ))
            })?),
        }),
    }
}

fn ensure_seed_material_exists(identity: &Identity) -> Result<()> {
    let object_dir = identity
        .storage
        .state_layout
        .objects_dir
        .join(&identity.name);
    let public_blob = metadata_path(identity, SEED_PUBLIC_BLOB_PATH_METADATA_KEY)
        .unwrap_or_else(|| object_dir.join("sealed.pub"));
    let private_blob = metadata_path(identity, SEED_PRIVATE_BLOB_PATH_METADATA_KEY)
        .unwrap_or_else(|| object_dir.join("sealed.priv"));

    if public_blob.is_file() && private_blob.is_file() {
        return Ok(());
    }

    Err(Error::Unsupported(format!(
        "identity '{}' resolved to seed mode but no sealed seed object was found; expected '{}' and '{}'",
        identity.name,
        public_blob.display(),
        private_blob.display()
    )))
}

fn metadata_path(identity: &Identity, key: &str) -> Option<PathBuf> {
    let value = identity.metadata.get(key)?;
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Some(path)
    } else {
        Some(identity.storage.state_layout.root_dir.join(path))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};

    use crate::backend::{CommandInvocation, CommandOutput, CommandRunner};
    use crate::model::{
        Algorithm, DerivationOverrides, Format, Identity, IdentityModeResolution, Mode,
        ModePreference, StateLayout, UseCase,
    };
    use crate::ops::prf::{PRF_CONTEXT_PATH_METADATA_KEY, PrfRequest, RawPrfOutput, finalize};

    use super::*;

    struct RecordingPrfRunner {
        raw_output: Vec<u8>,
        invocations: RefCell<Vec<CommandInvocation>>,
    }

    impl RecordingPrfRunner {
        fn new(raw_output: &[u8]) -> Self {
            Self {
                raw_output: raw_output.to_vec(),
                invocations: RefCell::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for RecordingPrfRunner {
        fn run(&self, invocation: &CommandInvocation) -> CommandOutput {
            self.invocations.borrow_mut().push(invocation.clone());
            let output_path = invocation
                .args
                .windows(2)
                .find(|pair| pair[0] == "-o")
                .map(|pair| PathBuf::from(&pair[1]))
                .expect("prf output path");
            std::fs::write(output_path, &self.raw_output).expect("write prf output");

            CommandOutput {
                exit_code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
                error: None,
            }
        }
    }

    fn prf_identity(root: &Path) -> Identity {
        let mut identity = Identity::new(
            "prf-derive".to_string(),
            Algorithm::Ed25519,
            vec![UseCase::Derive],
            IdentityModeResolution {
                requested: ModePreference::Prf,
                resolved: Mode::Prf,
                reasons: vec!["prf requested".to_string()],
            },
            StateLayout::new(root.to_path_buf()),
        );
        identity.metadata.insert(
            PRF_CONTEXT_PATH_METADATA_KEY.to_string(),
            format!("objects/{}/prf-root.ctx", identity.name),
        );
        identity
    }

    #[test]
    fn prf_derive_returns_single_finalized_output_without_double_expansion() {
        let temp = tempfile::tempdir().expect("tempdir");
        let identity = prf_identity(temp.path());
        let runner = RecordingPrfRunner::new(b"tpm-prf-material");
        let request = DeriveRequest {
            identity: identity.name.clone(),
            derivation: DerivationOverrides::default(),
            length: 32,
            format: Format::Hex,
            output: None,
        };

        let result = execute_with_runner(
            &identity,
            &request,
            &runner,
            &crate::ops::seed::SubprocessSeedBackend::new(
                identity.storage.state_layout.objects_dir.clone(),
            ),
            &crate::ops::seed::HkdfSha256SeedDeriver,
        )
        .expect("derive executes");

        let effective = resolve_effective_derivation_inputs(&identity, &request.derivation)
            .expect("effective derivation inputs");
        let spec = derive_command_spec(&effective, request.length).expect("derive spec");
        let expected = finalize(
            PrfRequest::new(identity.name.clone(), spec).expect("prf request"),
            RawPrfOutput::new(
                crate::ops::prf::PrfProtocolVersion::V1,
                b"tpm-prf-material".to_vec(),
            )
            .expect("raw prf output"),
        )
        .expect("finalize")
        .output
        .expose_secret()
        .to_vec();

        assert_eq!(result.mode, Mode::Prf);
        assert_eq!(result.material, Some(hex_encode(&expected)));
    }
}
