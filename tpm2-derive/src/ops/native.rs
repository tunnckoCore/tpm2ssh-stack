pub mod subprocess;

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub trait NativeBackend {
    fn setup(&self, request: &NativeIdentityCreateRequest) -> Result<NativeSetupResponse>;
    fn sign(&self, request: &NativeSignRequest) -> Result<NativeSignResponse>;
    fn verify(&self, request: &NativeVerifyRequest) -> Result<NativeVerifyResponse>;
    fn export_public_key(
        &self,
        request: &NativePublicKeyExportRequest,
    ) -> Result<NativePublicKeyExportResponse>;
}

pub trait Validate {
    fn validate(&self) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct ValidatingNativeBackend<B> {
    inner: B,
}

impl<B> ValidatingNativeBackend<B> {
    pub fn new(inner: B) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> B {
        self.inner
    }
}

impl<B: NativeBackend> NativeBackend for ValidatingNativeBackend<B> {
    fn setup(&self, request: &NativeIdentityCreateRequest) -> Result<NativeSetupResponse> {
        request.validate()?;
        self.inner.setup(request)
    }

    fn sign(&self, request: &NativeSignRequest) -> Result<NativeSignResponse> {
        request.validate()?;
        self.inner.sign(request)
    }

    fn verify(&self, request: &NativeVerifyRequest) -> Result<NativeVerifyResponse> {
        request.validate()?;
        self.inner.verify(request)
    }

    fn export_public_key(
        &self,
        request: &NativePublicKeyExportRequest,
    ) -> Result<NativePublicKeyExportResponse> {
        request.validate()?;
        self.inner.export_public_key(request)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum NativeAlgorithm {
    P256,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum NativeCurve {
    NistP256,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum NativeKeyUse {
    Sign,
    Verify,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum NativeHardwareBinding {
    Required,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum NativePrivateKeyPolicy {
    NonExportable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum NativePublicKeyPolicy {
    Exportable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum NativeSignatureScheme {
    Ecdsa,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum NativeSignatureFormat {
    Der,
    P1363,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    pub fn expected_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum NativePublicKeyEncoding {
    Sec1Uncompressed,
    SpkiDer,
    Pem,
    Tpm2bPublic,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativeKeyRef {
    pub identity: String,
    pub key_id: String,
}

impl Validate for NativeKeyRef {
    fn validate(&self) -> Result<()> {
        validate_identifier("identity", &self.identity)?;
        validate_identifier("key_id", &self.key_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativeKeySemantics {
    pub hardware_binding: NativeHardwareBinding,
    pub private_key_policy: NativePrivateKeyPolicy,
    pub public_key_policy: NativePublicKeyPolicy,
}

impl NativeKeySemantics {
    pub const fn hardware_backed_non_exportable() -> Self {
        Self {
            hardware_binding: NativeHardwareBinding::Required,
            private_key_policy: NativePrivateKeyPolicy::NonExportable,
            public_key_policy: NativePublicKeyPolicy::Exportable,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativeIdentityCreateRequest {
    pub identity: String,
    pub key_label: Option<String>,
    pub algorithm: NativeAlgorithm,
    pub curve: NativeCurve,
    pub allowed_uses: Vec<NativeKeyUse>,
    pub hardware_binding: NativeHardwareBinding,
    pub private_key_policy: NativePrivateKeyPolicy,
}

impl Validate for NativeIdentityCreateRequest {
    fn validate(&self) -> Result<()> {
        validate_identifier("identity", &self.identity)?;
        validate_optional_label("key_label", self.key_label.as_deref())?;
        validate_native_key_shape(self.algorithm, self.curve)?;
        validate_non_empty_unique_uses(&self.allowed_uses)?;
        validate_native_semantics(self.hardware_binding, self.private_key_policy)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativeSetupResponse {
    pub key: NativeKeyRef,
    pub algorithm: NativeAlgorithm,
    pub curve: NativeCurve,
    pub allowed_uses: Vec<NativeKeyUse>,
    pub semantics: NativeKeySemantics,
    pub public_key: Option<NativePublicKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativeSignRequest {
    pub key: NativeKeyRef,
    pub scheme: NativeSignatureScheme,
    pub format: NativeSignatureFormat,
    pub digest_algorithm: DigestAlgorithm,
    pub digest: Vec<u8>,
}

impl Validate for NativeSignRequest {
    fn validate(&self) -> Result<()> {
        self.key.validate()?;
        validate_digest(self.digest_algorithm, &self.digest)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativeSignResponse {
    pub key: NativeKeyRef,
    pub scheme: NativeSignatureScheme,
    pub format: NativeSignatureFormat,
    pub digest_algorithm: DigestAlgorithm,
    pub signature: Vec<u8>,
    pub semantics: NativeKeySemantics,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativeVerifyRequest {
    pub target: NativeVerifyTarget,
    pub scheme: NativeSignatureScheme,
    pub format: NativeSignatureFormat,
    pub digest_algorithm: DigestAlgorithm,
    pub digest: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Validate for NativeVerifyRequest {
    fn validate(&self) -> Result<()> {
        self.target.validate()?;
        validate_digest(self.digest_algorithm, &self.digest)?;

        if self.signature.is_empty() {
            return Err(Error::Validation(
                "native verify request requires a non-empty signature".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativeVerifyResponse {
    pub verified: bool,
    pub target: NativeVerifyTargetSummary,
    pub scheme: NativeSignatureScheme,
    pub format: NativeSignatureFormat,
    pub digest_algorithm: DigestAlgorithm,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum NativeVerifyTarget {
    ManagedKey { key: NativeKeyRef },
    ExportedPublicKey { public_key: NativePublicKey },
}

impl Validate for NativeVerifyTarget {
    fn validate(&self) -> Result<()> {
        match self {
            Self::ManagedKey { key } => key.validate(),
            Self::ExportedPublicKey { public_key } => public_key.validate(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum NativeVerifyTargetSummary {
    ManagedKey { key: NativeKeyRef },
    ExportedPublicKey { exported_from: Option<NativeKeyRef> },
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativePublicKeyExportRequest {
    pub key: NativeKeyRef,
    pub encodings: Vec<NativePublicKeyEncoding>,
}

impl Validate for NativePublicKeyExportRequest {
    fn validate(&self) -> Result<()> {
        self.key.validate()?;

        if self.encodings.is_empty() {
            return Err(Error::Validation(
                "native public-key export requires at least one encoding".to_string(),
            ));
        }

        validate_unique_encodings(&self.encodings)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativePublicKeyExportResponse {
    pub key: NativeKeyRef,
    pub public_key: NativePublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativePublicKey {
    pub exported_from: Option<NativeKeyRef>,
    pub algorithm: NativeAlgorithm,
    pub curve: NativeCurve,
    pub point: NativeEcPoint,
    pub semantics: NativeKeySemantics,
    pub encodings: Vec<EncodedNativePublicKey>,
}

impl Validate for NativePublicKey {
    fn validate(&self) -> Result<()> {
        if let Some(exported_from) = &self.exported_from {
            exported_from.validate()?;
        }

        validate_native_key_shape(self.algorithm, self.curve)?;
        self.point.validate()?;
        validate_unique_encoded_public_keys(&self.encodings)?;

        if self.semantics.hardware_binding != NativeHardwareBinding::Required {
            return Err(Error::Validation(
                "native public key must remain explicitly hardware-backed".to_string(),
            ));
        }

        if self.semantics.private_key_policy != NativePrivateKeyPolicy::NonExportable {
            return Err(Error::Validation(
                "native public key export must preserve non-exportable private-key semantics"
                    .to_string(),
            ));
        }

        if self.semantics.public_key_policy != NativePublicKeyPolicy::Exportable {
            return Err(Error::Validation(
                "native public key export must mark the public half as exportable".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NativeEcPoint {
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

impl Validate for NativeEcPoint {
    fn validate(&self) -> Result<()> {
        validate_fixed_len("native public key x-coordinate", &self.x, 32)?;
        validate_fixed_len("native public key y-coordinate", &self.y, 32)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "encoding", rename_all = "kebab-case")]
pub enum EncodedNativePublicKey {
    Sec1Uncompressed { bytes: Vec<u8> },
    SpkiDer { bytes: Vec<u8> },
    Pem { pem: String },
    Tpm2bPublic { bytes: Vec<u8> },
}

impl EncodedNativePublicKey {
    pub fn encoding(&self) -> NativePublicKeyEncoding {
        match self {
            Self::Sec1Uncompressed { .. } => NativePublicKeyEncoding::Sec1Uncompressed,
            Self::SpkiDer { .. } => NativePublicKeyEncoding::SpkiDer,
            Self::Pem { .. } => NativePublicKeyEncoding::Pem,
            Self::Tpm2bPublic { .. } => NativePublicKeyEncoding::Tpm2bPublic,
        }
    }
}

fn validate_identifier(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::Validation(format!("{field} must not be empty")));
    }

    Ok(())
}

fn validate_optional_label(field: &str, value: Option<&str>) -> Result<()> {
    if let Some(value) = value {
        validate_identifier(field, value)?;
    }

    Ok(())
}

fn validate_native_key_shape(algorithm: NativeAlgorithm, curve: NativeCurve) -> Result<()> {
    match (algorithm, curve) {
        (NativeAlgorithm::P256, NativeCurve::NistP256) => Ok(()),
    }
}

fn validate_non_empty_unique_uses(uses: &[NativeKeyUse]) -> Result<()> {
    if uses.is_empty() {
        return Err(Error::Validation(
            "native setup requires at least one allowed use".to_string(),
        ));
    }

    let distinct: BTreeSet<_> = uses.iter().copied().collect();
    if distinct.len() != uses.len() {
        return Err(Error::Validation(
            "native setup allowed_uses must not contain duplicates".to_string(),
        ));
    }

    Ok(())
}

fn validate_native_semantics(
    hardware_binding: NativeHardwareBinding,
    private_key_policy: NativePrivateKeyPolicy,
) -> Result<()> {
    if hardware_binding != NativeHardwareBinding::Required {
        return Err(Error::Validation(
            "native mode requires explicit hardware-backed semantics".to_string(),
        ));
    }

    if private_key_policy != NativePrivateKeyPolicy::NonExportable {
        return Err(Error::Validation(
            "native mode requires explicit non-exportable private-key semantics".to_string(),
        ));
    }

    Ok(())
}

fn validate_digest(algorithm: DigestAlgorithm, digest: &[u8]) -> Result<()> {
    let expected_len = algorithm.expected_len();
    if digest.len() != expected_len {
        return Err(Error::Validation(format!(
            "digest length mismatch: expected {expected_len} bytes for {algorithm:?}, got {}",
            digest.len()
        )));
    }

    Ok(())
}

fn validate_fixed_len(field: &str, bytes: &[u8], expected_len: usize) -> Result<()> {
    if bytes.len() != expected_len {
        return Err(Error::Validation(format!(
            "{field} must be {expected_len} bytes, got {}",
            bytes.len()
        )));
    }

    Ok(())
}

fn validate_unique_encodings(encodings: &[NativePublicKeyEncoding]) -> Result<()> {
    let distinct: BTreeSet<_> = encodings.iter().copied().collect();
    if distinct.len() != encodings.len() {
        return Err(Error::Validation(
            "native public-key export encodings must not contain duplicates".to_string(),
        ));
    }

    Ok(())
}

fn validate_unique_encoded_public_keys(encodings: &[EncodedNativePublicKey]) -> Result<()> {
    let distinct: BTreeSet<_> = encodings
        .iter()
        .map(EncodedNativePublicKey::encoding)
        .collect();
    if distinct.len() != encodings.len() {
        return Err(Error::Validation(
            "native public key contains duplicate encodings".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_ref() -> NativeKeyRef {
        NativeKeyRef {
            identity: "prod-signer".to_string(),
            key_id: "p256-signing-key".to_string(),
        }
    }

    #[test]
    fn native_setup_requires_unique_uses() {
        let request = NativeIdentityCreateRequest {
            identity: "prod-signer".to_string(),
            key_label: Some("api signer".to_string()),
            algorithm: NativeAlgorithm::P256,
            curve: NativeCurve::NistP256,
            allowed_uses: vec![NativeKeyUse::Sign, NativeKeyUse::Sign],
            hardware_binding: NativeHardwareBinding::Required,
            private_key_policy: NativePrivateKeyPolicy::NonExportable,
        };

        let error = request.validate().unwrap_err();
        assert!(matches!(error, Error::Validation(message) if message.contains("duplicates")));
    }

    #[test]
    fn sign_request_rejects_wrong_digest_length() {
        let request = NativeSignRequest {
            key: key_ref(),
            scheme: NativeSignatureScheme::Ecdsa,
            format: NativeSignatureFormat::Der,
            digest_algorithm: DigestAlgorithm::Sha256,
            digest: vec![0u8; 31],
        };

        let error = request.validate().unwrap_err();
        assert!(
            matches!(error, Error::Validation(message) if message.contains("digest length mismatch"))
        );
    }

    #[test]
    fn exported_public_key_preserves_non_exportable_semantics() {
        let public_key = NativePublicKey {
            exported_from: Some(key_ref()),
            algorithm: NativeAlgorithm::P256,
            curve: NativeCurve::NistP256,
            point: NativeEcPoint {
                x: vec![1u8; 32],
                y: vec![2u8; 32],
            },
            semantics: NativeKeySemantics::hardware_backed_non_exportable(),
            encodings: vec![EncodedNativePublicKey::Sec1Uncompressed {
                bytes: vec![4u8; 65],
            }],
        };

        public_key.validate().unwrap();
    }
}
