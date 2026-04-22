use std::fs;

use ed25519_dalek::{Signature as Ed25519Signature, SigningKey as Ed25519SigningKey};
use k256::ecdsa::{Signature as K256Signature, SigningKey as K256SigningKey};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey};
use p256::pkcs8::DecodePublicKey as _;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tempfile::Builder as TempfileBuilder;

use crate::backend::{CommandInvocation, CommandRunner, ProcessCommandRunner};
use crate::error::{Error, Result};
use crate::model::{
    Algorithm, DerivationOverrides, Diagnostic, Identity, InputSource, Mode, UseCase, VerifyRequest,
};
use crate::ops::keygen::{derive_identity_key_material_with_defaults, hex_encode};
use crate::ops::native::{NativeKeyRef, NativePublicKeyEncoding, NativePublicKeyExportRequest};
#[cfg(test)]
use crate::ops::seed::{
    SeedBackend, SeedIdentity, SeedOpenAuthSource, SeedOpenOutput, SeedOpenRequest,
    SeedSoftwareDeriver, SoftwareSeedDerivationRequest, open_and_derive, plan_open,
    seed_profile_from_profile,
};
#[cfg(test)]
use secrecy::ExposeSecret;

use super::shared::{
    classify_native_command_failure, ensure_derivation_overrides_allowed, load_input_bytes,
};
#[cfg(test)]
use super::sign::{
    SEED_SIGNING_KEY_NAMESPACE, SEED_SIGNING_KEY_PATH, seed_signing_key_derivation_spec,
};

#[derive(Debug, Clone, Copy, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum VerifySignatureFormat {
    Der,
    P1363,
    Raw,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyOperationResult {
    pub identity: Identity,
    pub request: VerifyRequest,
    pub mode: Mode,
    pub verified: bool,
    pub digest_algorithm: crate::ops::native::DigestAlgorithm,
    pub digest_hex: String,
    pub input_bytes: usize,
    pub signature_bytes: usize,
    pub signature_format: VerifySignatureFormat,
}

pub fn execute_with_defaults(
    identity: &Identity,
    request: &VerifyRequest,
    derivation: &DerivationOverrides,
) -> Result<(VerifyOperationResult, Vec<Diagnostic>)> {
    let runner = ProcessCommandRunner;
    execute_with_runner(identity, request, derivation, &runner)
}

pub fn execute_with_runner<R>(
    identity: &Identity,
    request: &VerifyRequest,
    derivation: &DerivationOverrides,
    runner: &R,
) -> Result<(VerifyOperationResult, Vec<Diagnostic>)>
where
    R: CommandRunner,
{
    ensure_derivation_overrides_allowed(identity, derivation)?;

    match identity.mode.resolved {
        Mode::Native => verify_native_with_runner(request, identity, runner),
        Mode::Seed | Mode::Prf => verify_derived_identity(request, identity, derivation, runner),
    }
}

fn verify_derived_identity<R>(
    request: &VerifyRequest,
    identity: &Identity,
    derivation: &DerivationOverrides,
    runner: &R,
) -> Result<(VerifyOperationResult, Vec<Diagnostic>)>
where
    R: CommandRunner,
{
    if !identity.uses.contains(&UseCase::Verify) {
        return Err(Error::Unsupported(format!(
            "identity '{}' is not configured with verify use",
            identity.name
        )));
    }

    if matches!(request.input, InputSource::Stdin)
        && matches!(request.signature, InputSource::Stdin)
    {
        return Err(Error::Validation(
            "verify cannot read both --input and --signature from stdin at the same time"
                .to_string(),
        ));
    }

    let input_bytes = load_input_bytes(&request.input, "verify input")?;
    let signature_bytes = load_input_bytes(&request.signature, "verify signature")?;
    if signature_bytes.is_empty() {
        return Err(Error::Validation(
            "verify signature must not be empty".to_string(),
        ));
    }

    let derived = derive_identity_key_material_with_defaults(identity, derivation, runner)?;
    let digest = Sha256::digest(&input_bytes).to_vec();
    let diagnostics = vec![Diagnostic::info(
        "derived-verifier-material",
        format!(
            "derived {} bytes of {:?} verifier material from {:?} backing using the effective derivation inputs",
            derived.len(),
            identity.algorithm,
            identity.mode.resolved,
        ),
    )];

    match identity.algorithm {
        Algorithm::Ed25519 => verify_seed_ed25519(
            request,
            identity,
            &input_bytes,
            &signature_bytes,
            &digest,
            &derived,
            diagnostics,
        ),
        Algorithm::P256 => verify_seed_p256(
            request,
            identity,
            &input_bytes,
            &signature_bytes,
            &digest,
            &derived,
            diagnostics,
        ),
        Algorithm::Secp256k1 => verify_seed_secp256k1(
            request,
            identity,
            &input_bytes,
            &signature_bytes,
            &digest,
            &derived,
            diagnostics,
        ),
    }
}

pub(crate) fn verify_native_with_runner<R>(
    request: &VerifyRequest,
    identity: &Identity,
    runner: &R,
) -> Result<(VerifyOperationResult, Vec<Diagnostic>)>
where
    R: CommandRunner,
{
    if identity.algorithm != Algorithm::P256 {
        return Err(Error::Unsupported(format!(
            "native verify is currently wired only for p256 identities, found {:?}",
            identity.algorithm
        )));
    }

    if !identity.uses.contains(&UseCase::Verify) {
        return Err(Error::Unsupported(format!(
            "identity '{}' is not configured with verify use",
            identity.name
        )));
    }

    if matches!(request.input, InputSource::Stdin)
        && matches!(request.signature, InputSource::Stdin)
    {
        return Err(Error::Validation(
            "verify cannot read both --input and --signature from stdin at the same time"
                .to_string(),
        ));
    }

    let input_bytes = load_input_bytes(&request.input, "verify input")?;
    let signature_bytes = load_input_bytes(&request.signature, "verify signature")?;
    if signature_bytes.is_empty() {
        return Err(Error::Validation(
            "verify signature must not be empty".to_string(),
        ));
    }

    let digest = Sha256::digest(&input_bytes).to_vec();
    let public_key_der = export_native_public_key_der_with_runner(identity, runner)?;
    let verifying_key = load_p256_verifying_key(&public_key_der)?;
    let (signature, signature_format) = parse_p256_verify_signature(&signature_bytes)?;
    let verified = verifying_key.verify(&input_bytes, &signature).is_ok();

    Ok((
        VerifyOperationResult {
            identity: identity.clone(),
            request: request.clone(),
            mode: Mode::Native,
            verified,
            digest_algorithm: crate::ops::native::DigestAlgorithm::Sha256,
            digest_hex: hex_encode(&digest),
            input_bytes: input_bytes.len(),
            signature_bytes: signature_bytes.len(),
            signature_format,
        },
        vec![Diagnostic::info(
            "native-public-key-exported",
            format!(
                "exported {} bytes of SPKI DER public key material from native TPM state for verify",
                public_key_der.len()
            ),
        )],
    ))
}

#[cfg(test)]
pub(crate) fn verify_seed_with_backend<B, D>(
    request: &VerifyRequest,
    identity: &Identity,
    backend: &B,
    deriver: &D,
) -> Result<(VerifyOperationResult, Vec<Diagnostic>)>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    if !identity.uses.contains(&UseCase::Verify) {
        return Err(Error::Unsupported(format!(
            "identity '{}' is not configured with verify use",
            identity.name
        )));
    }

    if matches!(request.input, InputSource::Stdin)
        && matches!(request.signature, InputSource::Stdin)
    {
        return Err(Error::Validation(
            "verify cannot read both --input and --signature from stdin at the same time"
                .to_string(),
        ));
    }

    let input_bytes = load_input_bytes(&request.input, "verify input")?;
    let signature_bytes = load_input_bytes(&request.signature, "verify signature")?;
    if signature_bytes.is_empty() {
        return Err(Error::Validation(
            "verify signature must not be empty".to_string(),
        ));
    }

    let seed_request = seed_verify_open_request(identity)?;
    let seed_plan = plan_open(&seed_request)?;
    let digest = Sha256::digest(&input_bytes).to_vec();
    let derived = open_and_derive(backend, deriver, &seed_request)?;
    let diagnostics =
        seed_verify_diagnostics(identity, &seed_plan.warnings, derived.expose_secret().len());

    match identity.algorithm {
        Algorithm::Ed25519 => verify_seed_ed25519(
            request,
            identity,
            &input_bytes,
            &signature_bytes,
            &digest,
            derived.expose_secret(),
            diagnostics,
        ),
        Algorithm::P256 => verify_seed_p256(
            request,
            identity,
            &input_bytes,
            &signature_bytes,
            &digest,
            derived.expose_secret(),
            diagnostics,
        ),
        Algorithm::Secp256k1 => verify_seed_secp256k1(
            request,
            identity,
            &input_bytes,
            &signature_bytes,
            &digest,
            derived.expose_secret(),
            diagnostics,
        ),
    }
}

fn verify_seed_ed25519(
    request: &VerifyRequest,
    identity: &Identity,
    input_bytes: &[u8],
    signature_bytes: &[u8],
    digest: &[u8],
    derived_seed: &[u8],
    diagnostics: Vec<Diagnostic>,
) -> Result<(VerifyOperationResult, Vec<Diagnostic>)> {
    let seed_bytes: [u8; 32] = derived_seed.try_into().map_err(|_| {
        Error::Internal(
            "seed verify ed25519 derivation produced a non-32-byte seed unexpectedly".to_string(),
        )
    })?;
    let signing_key = Ed25519SigningKey::from_bytes(&seed_bytes);
    let (signature, signature_format) = parse_ed25519_verify_signature(signature_bytes)?;
    let verified = signing_key
        .verifying_key()
        .verify_strict(input_bytes, &signature)
        .is_ok();

    Ok((
        VerifyOperationResult {
            identity: identity.clone(),
            request: request.clone(),
            mode: identity.mode.resolved,
            verified,
            digest_algorithm: crate::ops::native::DigestAlgorithm::Sha256,
            digest_hex: hex_encode(digest),
            input_bytes: input_bytes.len(),
            signature_bytes: signature_bytes.len(),
            signature_format,
        },
        diagnostics,
    ))
}

fn verify_seed_p256(
    request: &VerifyRequest,
    identity: &Identity,
    input_bytes: &[u8],
    signature_bytes: &[u8],
    digest: &[u8],
    derived_seed: &[u8],
    diagnostics: Vec<Diagnostic>,
) -> Result<(VerifyOperationResult, Vec<Diagnostic>)> {
    let scalar_bytes =
        crate::ops::seed_valid_ec_scalar_bytes_standalone(derived_seed, identity.algorithm)?;
    let signing_key = P256SigningKey::from_bytes((&scalar_bytes).into()).map_err(|error| {
        Error::Internal(format!(
            "failed to materialize p256 seed verifying key for identity '{}': {error}",
            identity.name
        ))
    })?;
    let verifying_key = signing_key.verifying_key();
    let (signature, signature_format) = parse_p256_verify_signature(signature_bytes)?;
    let verified = verifying_key.verify(input_bytes, &signature).is_ok();

    Ok((
        VerifyOperationResult {
            identity: identity.clone(),
            request: request.clone(),
            mode: identity.mode.resolved,
            verified,
            digest_algorithm: crate::ops::native::DigestAlgorithm::Sha256,
            digest_hex: hex_encode(digest),
            input_bytes: input_bytes.len(),
            signature_bytes: signature_bytes.len(),
            signature_format,
        },
        diagnostics,
    ))
}

fn verify_seed_secp256k1(
    request: &VerifyRequest,
    identity: &Identity,
    input_bytes: &[u8],
    signature_bytes: &[u8],
    digest: &[u8],
    derived_seed: &[u8],
    diagnostics: Vec<Diagnostic>,
) -> Result<(VerifyOperationResult, Vec<Diagnostic>)> {
    let scalar_bytes =
        crate::ops::seed_valid_ec_scalar_bytes_standalone(derived_seed, identity.algorithm)?;
    let signing_key = K256SigningKey::from_bytes((&scalar_bytes).into()).map_err(|error| {
        Error::Internal(format!(
            "failed to materialize secp256k1 seed verifying key for identity '{}': {error}",
            identity.name
        ))
    })?;
    let verifying_key = signing_key.verifying_key();
    let (signature, signature_format) = parse_k256_verify_signature(signature_bytes)?;
    let verified =
        k256::ecdsa::signature::Verifier::verify(verifying_key, input_bytes, &signature).is_ok();

    Ok((
        VerifyOperationResult {
            identity: identity.clone(),
            request: request.clone(),
            mode: identity.mode.resolved,
            verified,
            digest_algorithm: crate::ops::native::DigestAlgorithm::Sha256,
            digest_hex: hex_encode(digest),
            input_bytes: input_bytes.len(),
            signature_bytes: signature_bytes.len(),
            signature_format,
        },
        diagnostics,
    ))
}

#[cfg(test)]
pub(crate) fn seed_verify_open_request(identity: &Identity) -> Result<SeedOpenRequest> {
    Ok(SeedOpenRequest {
        identity: seed_verify_profile(identity)?,
        auth_source: SeedOpenAuthSource::None,
        output: SeedOpenOutput::DerivedBytes(SoftwareSeedDerivationRequest {
            spec: seed_verify_derivation_spec(identity.algorithm)?,
            output_bytes: 32,
        }),
        require_fresh_unseal: true,
        confirm_software_derivation: true,
    })
}

#[cfg(test)]
fn seed_verify_profile(identity: &Identity) -> Result<SeedIdentity> {
    if identity.mode.resolved != Mode::Seed {
        return Err(Error::Unsupported(format!(
            "identity '{}' did not resolve to seed mode",
            identity.name
        )));
    }

    seed_profile_from_profile(identity)
}

#[cfg(test)]
fn seed_verify_derivation_spec(algorithm: Algorithm) -> Result<crate::crypto::DerivationSpec> {
    seed_signing_key_derivation_spec(algorithm)
}

#[cfg(test)]
fn seed_verify_diagnostics(
    identity: &Identity,
    warnings: &[Diagnostic],
    derived_bytes: usize,
) -> Vec<Diagnostic> {
    let mut diagnostics = warnings.to_vec();
    diagnostics.push(Diagnostic::info(
        "seed-verifier-derived",
        format!(
            "derived {} bytes of {:?} verifier material from sealed seed using {} {}",
            derived_bytes, identity.algorithm, SEED_SIGNING_KEY_NAMESPACE, SEED_SIGNING_KEY_PATH,
        ),
    ));
    diagnostics
}

fn export_native_public_key_der_with_runner<R>(identity: &Identity, runner: &R) -> Result<Vec<u8>>
where
    R: CommandRunner,
{
    if identity.algorithm != Algorithm::P256 {
        return Err(Error::Unsupported(format!(
            "native public-key export is currently wired only for p256 identities, got {:?}",
            identity.algorithm
        )));
    }

    identity.storage.state_layout.ensure_dirs()?;

    let locator = crate::ops::resolve_native_key_locator(identity)?;
    let tempdir = TempfileBuilder::new()
        .prefix("native-verify-public-key-")
        .tempdir_in(&identity.storage.state_layout.exports_dir)
        .map_err(|error| {
            Error::State(format!(
                "failed to create native verify workspace in '{}': {error}",
                identity.storage.state_layout.exports_dir.display()
            ))
        })?;

    let plan = crate::ops::native::subprocess::plan_export_public_key(
        &NativePublicKeyExportRequest {
            key: NativeKeyRef {
                identity: identity.name.clone(),
                key_id: crate::ops::native_key_id(identity),
            },
            encodings: vec![NativePublicKeyEncoding::SpkiDer],
        },
        &crate::ops::native::subprocess::NativePublicKeyExportOptions {
            locator,
            output_dir: tempdir.path().to_path_buf(),
            file_stem: identity.name.clone(),
        },
    )?;

    for command in &plan.commands {
        let output = runner.run(&CommandInvocation::new(
            &command.program,
            command.args.iter().cloned(),
        ));
        if output.error.is_some() || output.exit_code != Some(0) {
            return Err(classify_native_command_failure(&command.program, &output));
        }
    }

    let exported = plan
        .outputs
        .iter()
        .find(|output| output.encoding == NativePublicKeyEncoding::SpkiDer)
        .ok_or_else(|| {
            Error::Internal(
                "native verify export plan did not produce the expected SPKI DER artifact"
                    .to_string(),
            )
        })?;

    fs::read(&exported.path).map_err(|error| {
        Error::State(format!(
            "failed to read native verify public key from '{}': {error}",
            exported.path.display()
        ))
    })
}

fn load_p256_verifying_key(public_key_der: &[u8]) -> Result<VerifyingKey> {
    VerifyingKey::from_public_key_der(public_key_der).map_err(|error| {
        Error::State(format!(
            "native verify exported malformed SPKI DER public key material: {error}"
        ))
    })
}

fn parse_p256_verify_signature(
    signature_bytes: &[u8],
) -> Result<(P256Signature, VerifySignatureFormat)> {
    if let Ok(signature) = P256Signature::from_der(signature_bytes) {
        return Ok((signature, VerifySignatureFormat::Der));
    }

    if let Ok(signature) = P256Signature::from_slice(signature_bytes) {
        return Ok((signature, VerifySignatureFormat::P1363));
    }

    Err(Error::Validation(
        "verify signature must be either ASN.1 DER ECDSA or 64-byte P1363 for p256".to_string(),
    ))
}

fn parse_k256_verify_signature(
    signature_bytes: &[u8],
) -> Result<(K256Signature, VerifySignatureFormat)> {
    if let Ok(signature) = K256Signature::from_der(signature_bytes) {
        return Ok((signature, VerifySignatureFormat::Der));
    }

    if let Ok(signature) = K256Signature::from_slice(signature_bytes) {
        return Ok((signature, VerifySignatureFormat::P1363));
    }

    Err(Error::Validation(
        "verify signature must be either ASN.1 DER ECDSA or 64-byte P1363 for secp256k1"
            .to_string(),
    ))
}

fn parse_ed25519_verify_signature(
    signature_bytes: &[u8],
) -> Result<(Ed25519Signature, VerifySignatureFormat)> {
    let signature_bytes: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        Error::Validation("verify signature for ed25519 must be exactly 64 raw bytes".to_string())
    })?;

    Ok((
        Ed25519Signature::from_bytes(&signature_bytes),
        VerifySignatureFormat::Raw,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    use tempfile::tempdir;

    use crate::model::{IdentityModeResolution, InputSource, ModePreference, StateLayout};

    #[test]
    fn native_verify_rejects_derivation_overrides() {
        let state_root = tempdir().expect("state root");
        let identity = Identity::new(
            "native-verify".to_string(),
            Algorithm::P256,
            vec![UseCase::Sign, UseCase::Verify],
            IdentityModeResolution {
                requested: ModePreference::Native,
                resolved: Mode::Native,
                reasons: vec!["native requested".to_string()],
            },
            StateLayout::new(state_root.path().to_path_buf()),
        );
        let input_path = state_root.path().join("input.bin");
        let sig_path = state_root.path().join("sig.bin");
        fs::write(&input_path, b"hello native verify").expect("input file");
        fs::write(&sig_path, [0u8; 64]).expect("signature file");

        let error = execute_with_defaults(
            &identity,
            &VerifyRequest {
                identity: identity.name.clone(),
                input: InputSource::Path { path: input_path },
                signature: InputSource::Path { path: sig_path },
            },
            &DerivationOverrides {
                org: Some("com.example".to_string()),
                purpose: None,
                context: Default::default(),
            },
        )
        .expect_err("native verify should reject derivation overrides");

        assert!(matches!(error, Error::Validation(message) if message.contains("native identities reject derivation overrides")));
    }
}
