use std::path::PathBuf;

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
    derive_command_spec, execute_prf_derivation_with_runner, resolve_effective_derivation_inputs,
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
        Mode::Prf => execute_prf(identity, request.length, spec, prf_runner),
        Mode::Seed => execute_seed(identity, request.length, spec, seed_backend, seed_deriver),
    }
}

fn execute_prf<R>(
    identity: &Identity,
    length: u16,
    spec: crate::crypto::DerivationSpec,
    runner: &R,
) -> Result<DeriveResult>
where
    R: CommandRunner,
{
    let material = execute_prf_derivation_with_runner(identity, spec, runner, "derive")?;
    Ok(DeriveResult {
        identity: identity.name.clone(),
        mode: Mode::Prf,
        length,
        encoding: "hex".to_string(),
        material: hex_encode(&material),
    })
}

fn execute_seed<B, D>(
    identity: &Identity,
    length: u16,
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

    let request = SeedOpenRequest {
        identity: seed_identity,
        auth_source: SeedOpenAuthSource::None,
        output: SeedOpenOutput::DerivedBytes(SoftwareSeedDerivationRequest {
            spec,
            output_bytes: usize::from(length),
        }),
        require_fresh_unseal: true,
        confirm_software_derivation: true,
    };

    let derived = open_and_derive(backend, deriver, &request)?;
    Ok(DeriveResult {
        identity: identity.name.clone(),
        mode: Mode::Seed,
        length,
        encoding: "hex".to_string(),
        material: hex_encode(derived.expose_secret()),
    })
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
