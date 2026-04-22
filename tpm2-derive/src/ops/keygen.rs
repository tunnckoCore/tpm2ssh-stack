//! Shared derived asymmetric-key helpers for PRF/seed-backed identities.
//!
//! These helpers power sign/verify/export/ssh-add and keep them on the same
//! derived key material.

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::pkcs8::EncodePublicKey as _;
use secrecy::ExposeSecret;
use sha2::{Digest as _, Sha256};

use crate::backend::CommandRunner;
use crate::error::{Error, Result};
use crate::model::{Algorithm, DerivationOverrides, Identity, Mode};

use super::seed::{
    HkdfSha256SeedDeriver, SeedBackend, SeedOpenAuthSource, SeedOpenOutput, SeedOpenRequest,
    SeedSoftwareDeriver, SoftwareSeedDerivationRequest, SubprocessSeedBackend, open_and_derive,
    seed_profile_from_profile,
};
use super::shared::{
    execute_prf_derivation_with_runner, identity_key_spec, resolve_effective_derivation_inputs,
};

const KEYGEN_SCALAR_RETRY_DOMAIN: &[u8] = b"tpm2-derive\0keygen-scalar-retry\0v1";
const KEYGEN_SCALAR_RETRY_LIMIT: u32 = 16;

pub(crate) fn derive_identity_key_material_with_defaults<R>(
    identity: &Identity,
    derivation: &DerivationOverrides,
    prf_runner: &R,
) -> Result<Vec<u8>>
where
    R: CommandRunner,
{
    let seed_backend =
        SubprocessSeedBackend::new(identity.storage.state_layout.objects_dir.clone());
    let seed_deriver = HkdfSha256SeedDeriver;
    derive_identity_key_material(
        identity,
        derivation,
        prf_runner,
        &seed_backend,
        &seed_deriver,
    )
}

pub(crate) fn derive_identity_key_material<R, B, D>(
    identity: &Identity,
    derivation: &DerivationOverrides,
    prf_runner: &R,
    seed_backend: &B,
    seed_deriver: &D,
) -> Result<Vec<u8>>
where
    R: CommandRunner,
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let effective = resolve_effective_derivation_inputs(identity, derivation)?;
    let spec = identity_key_spec(identity.algorithm, &effective)?;

    match identity.mode.resolved {
        Mode::Native => Err(Error::Unsupported(
            "native-mode identities keep asymmetric keys inside the TPM; use the native operation paths instead"
                .to_string(),
        )),
        Mode::Prf => execute_prf_derivation_with_runner(identity, spec, prf_runner, "identity-key"),
        Mode::Seed => derive_seed_identity_key_material(identity, spec, seed_backend, seed_deriver),
    }
}

pub(crate) fn normalized_secret_key_bytes(identity: &Identity, derived: &[u8]) -> Result<[u8; 32]> {
    match identity.algorithm {
        Algorithm::Ed25519 => derived.try_into().map_err(|_| {
            Error::Internal(format!(
                "derived ed25519 key material for identity '{}' produced {} bytes instead of 32",
                identity.name,
                derived.len()
            ))
        }),
        Algorithm::P256 => valid_ec_scalar(identity, derived, |candidate| {
            p256::SecretKey::from_slice(candidate).is_ok()
        }),
        Algorithm::Secp256k1 => valid_ec_scalar(identity, derived, |candidate| {
            k256::SecretKey::from_slice(candidate).is_ok()
        }),
    }
}

pub(crate) fn public_key_spki_der_from_material(
    identity: &Identity,
    derived: &[u8],
) -> Result<Vec<u8>> {
    match identity.algorithm {
        Algorithm::Ed25519 => {
            let seed = normalized_secret_key_bytes(identity, derived)?;
            let signing_key = Ed25519SigningKey::from_bytes(&seed);
            signing_key
                .verifying_key()
                .to_public_key_der()
                .map(|document| document.as_bytes().to_vec())
                .map_err(|error| {
                    Error::Internal(format!(
                        "failed to encode ed25519 public key for identity '{}': {error}",
                        identity.name
                    ))
                })
        }
        Algorithm::P256 => {
            let scalar = normalized_secret_key_bytes(identity, derived)?;
            let secret_key = p256::SecretKey::from_slice(&scalar).map_err(|error| {
                Error::Internal(format!(
                    "failed to materialize p256 secret key for identity '{}': {error}",
                    identity.name
                ))
            })?;

            secret_key
                .public_key()
                .to_public_key_der()
                .map(|document| document.as_bytes().to_vec())
                .map_err(|error| {
                    Error::Internal(format!(
                        "failed to encode p256 public key for identity '{}': {error}",
                        identity.name
                    ))
                })
        }
        Algorithm::Secp256k1 => {
            let scalar = normalized_secret_key_bytes(identity, derived)?;
            let secret_key = k256::SecretKey::from_slice(&scalar).map_err(|error| {
                Error::Internal(format!(
                    "failed to materialize secp256k1 secret key for identity '{}': {error}",
                    identity.name
                ))
            })?;

            secret_key
                .public_key()
                .to_public_key_der()
                .map(|document| document.as_bytes().to_vec())
                .map_err(|error| {
                    Error::Internal(format!(
                        "failed to encode secp256k1 public key for identity '{}': {error}",
                        identity.name
                    ))
                })
        }
    }
}

pub(crate) fn keypair_hex_from_material(
    identity: &Identity,
    derived: &[u8],
) -> Result<(String, String)> {
    let secret_key_hex = hex_encode(&normalized_secret_key_bytes(identity, derived)?);
    let public_key_hex = hex_encode(&public_key_spki_der_from_material(identity, derived)?);
    Ok((secret_key_hex, public_key_hex))
}

fn derive_seed_identity_key_material<B, D>(
    identity: &Identity,
    spec: crate::crypto::DerivationSpec,
    backend: &B,
    deriver: &D,
) -> Result<Vec<u8>>
where
    B: SeedBackend,
    D: SeedSoftwareDeriver,
{
    let seed_identity = seed_profile_from_profile(identity)?;
    let output_bytes = usize::from(spec.output().length);
    let request = SeedOpenRequest {
        identity: seed_identity,
        auth_source: SeedOpenAuthSource::None,
        output: SeedOpenOutput::DerivedBytes(SoftwareSeedDerivationRequest { spec, output_bytes }),
        require_fresh_unseal: true,
        confirm_software_derivation: true,
    };

    Ok(open_and_derive(backend, deriver, &request)?
        .expose_secret()
        .to_vec())
}

fn valid_ec_scalar<F>(identity: &Identity, derived: &[u8], is_valid: F) -> Result<[u8; 32]>
where
    F: Fn(&[u8]) -> bool,
{
    let seed: [u8; 32] = derived.try_into().map_err(|_| {
        Error::Internal(format!(
            "derived EC key material for identity '{}' produced {} bytes instead of 32",
            identity.name,
            derived.len()
        ))
    })?;
    if is_valid(&seed) {
        return Ok(seed);
    }

    for counter in 1..=KEYGEN_SCALAR_RETRY_LIMIT {
        let candidate = scalar_retry_bytes(&seed, identity.algorithm, counter);
        if is_valid(&candidate) {
            return Ok(candidate);
        }
    }

    Err(Error::Internal(format!(
        "could not produce a valid {:?} scalar for identity '{}' after {} retries",
        identity.algorithm, identity.name, KEYGEN_SCALAR_RETRY_LIMIT
    )))
}

fn scalar_retry_bytes(seed: &[u8; 32], algorithm: Algorithm, counter: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEYGEN_SCALAR_RETRY_DOMAIN);
    hasher.update(match algorithm {
        Algorithm::Ed25519 => b"ed25519".as_slice(),
        Algorithm::Secp256k1 => b"secp256k1".as_slice(),
        Algorithm::P256 => b"p256".as_slice(),
    });
    hasher.update(counter.to_be_bytes());
    hasher.update(seed);
    hasher.finalize().into()
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
