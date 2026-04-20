use std::collections::BTreeMap;

use hkdf::Hkdf;
use secrecy::SecretSlice;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::{Error, Result};

pub const CANONICAL_SPEC_V1_TAG: &[u8] = b"tpm2-derive\0derivation-spec\0v1";
pub const CANONICAL_CONTEXT_V1_TAG: &[u8] = b"tpm2-derive\0derivation-context\0v1";
pub const PRF_REQUEST_V1_DOMAIN: &[u8] = b"tpm2-derive\0prf-request\0v1";
pub const PRF_OUTPUT_V1_DOMAIN: &[u8] = b"tpm2-derive\0prf-output\0v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum DerivationVersion {
    V1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum DerivationDomain {
    Application,
    PasskeyProvider,
    SoftwareChildKey,
}

impl DerivationDomain {
    fn as_str(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::PasskeyProvider => "passkey-provider",
            Self::SoftwareChildKey => "software-child-key",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum OutputKind {
    SecretBytes,
    Ed25519Seed,
    Secp256k1Scalar,
    P256Scalar,
}

impl OutputKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::SecretBytes => "secret-bytes",
            Self::Ed25519Seed => "ed25519-seed",
            Self::Secp256k1Scalar => "secp256k1-scalar",
            Self::P256Scalar => "p256-scalar",
        }
    }

    fn required_length(self) -> Option<u16> {
        match self {
            Self::SecretBytes => None,
            Self::Ed25519Seed | Self::Secp256k1Scalar | Self::P256Scalar => Some(32),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct OutputSpec {
    pub kind: OutputKind,
    pub length: u16,
}

impl OutputSpec {
    pub fn new(kind: OutputKind, length: u16) -> Result<Self> {
        let spec = Self { kind, length };
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<()> {
        if self.length == 0 {
            return Err(Error::Validation(
                "derivation output length must be greater than zero".to_string(),
            ));
        }

        if let Some(required_length) = self.kind.required_length() {
            if self.length != required_length {
                return Err(Error::Validation(format!(
                    "output kind '{}' requires {} bytes, got {}",
                    self.kind.as_str(),
                    required_length,
                    self.length
                )));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DerivationContext {
    pub namespace: String,
    pub domain: DerivationDomain,
    pub purpose: String,
    pub label: Option<String>,
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
}

impl DerivationContext {
    pub fn new(
        namespace: impl Into<String>,
        domain: DerivationDomain,
        purpose: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            domain,
            purpose: purpose.into(),
            label: None,
            fields: BTreeMap::new(),
        }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    pub fn validate(&self) -> Result<()> {
        validate_non_empty("namespace", &self.namespace)?;
        validate_non_empty("purpose", &self.purpose)?;

        if let Some(label) = &self.label {
            validate_non_empty("label", label)?;
        }

        for (key, value) in &self.fields {
            validate_non_empty("context key", key)?;
            validate_non_empty(&format!("context value for key '{key}'"), value)?;
        }

        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;

        let mut encoded = Vec::new();
        encoded.extend_from_slice(CANONICAL_CONTEXT_V1_TAG);
        write_string(&mut encoded, &self.namespace)?;
        write_string(&mut encoded, self.domain.as_str())?;
        write_string(&mut encoded, &self.purpose)?;
        write_optional_string(&mut encoded, self.label.as_deref())?;
        write_len(&mut encoded, self.fields.len())?;

        for (key, value) in &self.fields {
            write_string(&mut encoded, key)?;
            write_string(&mut encoded, value)?;
        }

        Ok(encoded)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "version", content = "spec", rename_all = "kebab-case")]
pub enum DerivationSpec {
    V1(DerivationSpecV1),
}

impl DerivationSpec {
    pub fn version(&self) -> DerivationVersion {
        match self {
            Self::V1(_) => DerivationVersion::V1,
        }
    }

    pub fn context(&self) -> &DerivationContext {
        match self {
            Self::V1(spec) => &spec.context,
        }
    }

    pub fn output(&self) -> &OutputSpec {
        match self {
            Self::V1(spec) => &spec.output,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::V1(spec) => spec.canonical_bytes(),
        }
    }

    pub fn prf_request_message(&self) -> Result<Vec<u8>> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(PRF_REQUEST_V1_DOMAIN);
        write_blob(&mut encoded, &self.canonical_bytes()?)?;
        Ok(encoded)
    }

    pub fn output_info(&self) -> Result<Vec<u8>> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(PRF_OUTPUT_V1_DOMAIN);
        write_blob(&mut encoded, &self.canonical_bytes()?)?;
        Ok(encoded)
    }

    pub fn derive_output(&self, prf_material: &[u8]) -> Result<SecretSlice<u8>> {
        derive_output(self, prf_material)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DerivationSpecV1 {
    pub context: DerivationContext,
    pub output: OutputSpec,
}

impl DerivationSpecV1 {
    pub fn new(context: DerivationContext, output: OutputSpec) -> Result<Self> {
        let spec = Self { context, output };
        spec.validate()?;
        Ok(spec)
    }

    pub fn application_bytes(
        namespace: impl Into<String>,
        purpose: impl Into<String>,
        length: u16,
    ) -> Result<Self> {
        Self::new(
            DerivationContext::new(namespace, DerivationDomain::Application, purpose),
            OutputSpec::new(OutputKind::SecretBytes, length)?,
        )
    }

    pub fn passkey_provider(
        namespace: impl Into<String>,
        rp_id: impl Into<String>,
        credential_id: impl Into<String>,
        length: u16,
    ) -> Result<Self> {
        let context = DerivationContext::new(
            namespace,
            DerivationDomain::PasskeyProvider,
            "provider-secret",
        )
        .with_field("rp-id", rp_id)
        .with_field("credential-id", credential_id);

        Self::new(context, OutputSpec::new(OutputKind::SecretBytes, length)?)
    }

    pub fn software_child_key(
        namespace: impl Into<String>,
        algorithm: impl Into<String>,
        path: impl Into<String>,
        output_kind: OutputKind,
    ) -> Result<Self> {
        let context =
            DerivationContext::new(namespace, DerivationDomain::SoftwareChildKey, "child-key")
                .with_field("algorithm", algorithm)
                .with_field("path", path);

        let length = output_kind.required_length().unwrap_or(32);
        Self::new(context, OutputSpec::new(output_kind, length)?)
    }

    pub fn validate(&self) -> Result<()> {
        self.context.validate()?;
        self.output.validate()?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;

        let mut encoded = Vec::new();
        encoded.extend_from_slice(CANONICAL_SPEC_V1_TAG);
        write_blob(&mut encoded, &self.context.canonical_bytes()?)?;
        write_string(&mut encoded, self.output.kind.as_str())?;
        write_u16(&mut encoded, self.output.length);
        Ok(encoded)
    }
}

pub fn derive_output(spec: &DerivationSpec, prf_material: &[u8]) -> Result<SecretSlice<u8>> {
    if prf_material.is_empty() {
        return Err(Error::Validation(
            "PRF material must not be empty".to_string(),
        ));
    }

    let mut output = vec![0u8; usize::from(spec.output().length)];
    let hkdf = Hkdf::<Sha256>::new(Some(PRF_OUTPUT_V1_DOMAIN), prf_material);
    hkdf.expand(&spec.output_info()?, &mut output)
        .map_err(|_| Error::Validation("requested output exceeds HKDF limits".to_string()))?;

    Ok(output.into())
}

fn validate_non_empty(field_name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::Validation(format!("{field_name} must not be empty")));
    }

    Ok(())
}

fn write_optional_string(encoded: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        Some(value) => {
            encoded.push(1);
            write_string(encoded, value)
        }
        None => {
            encoded.push(0);
            Ok(())
        }
    }
}

fn write_string(encoded: &mut Vec<u8>, value: &str) -> Result<()> {
    write_blob(encoded, value.as_bytes())
}

fn write_blob(encoded: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    write_len(encoded, value.len())?;
    encoded.extend_from_slice(value);
    Ok(())
}

fn write_len(encoded: &mut Vec<u8>, value: usize) -> Result<()> {
    let value = u32::try_from(value).map_err(|_| {
        Error::Validation("value exceeds canonical encoding size limit".to_string())
    })?;
    encoded.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn write_u16(encoded: &mut Vec<u8>, value: u16) {
    encoded.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::{
        DerivationContext, DerivationDomain, DerivationSpec, DerivationSpecV1, OutputKind,
    };

    #[test]
    fn canonical_context_is_stable_across_field_insertion_order() {
        let left = DerivationContext::new(
            "io.github.example",
            DerivationDomain::Application,
            "session-secret",
        )
        .with_field("tenant", "alpha")
        .with_field("user", "alice")
        .with_label("primary");

        let right = DerivationContext::new(
            "io.github.example",
            DerivationDomain::Application,
            "session-secret",
        )
        .with_field("user", "alice")
        .with_field("tenant", "alpha")
        .with_label("primary");

        assert_eq!(
            left.canonical_bytes().unwrap(),
            right.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn request_and_output_domains_are_distinct() {
        let spec = DerivationSpec::V1(
            DerivationSpecV1::passkey_provider("io.github.example", "example.com", "cred-123", 32)
                .unwrap(),
        );

        let request = spec.prf_request_message().unwrap();
        let output = spec.output_info().unwrap();

        assert_ne!(request, output);
        assert!(request.starts_with(super::PRF_REQUEST_V1_DOMAIN));
        assert!(output.starts_with(super::PRF_OUTPUT_V1_DOMAIN));
    }

    #[test]
    fn same_prf_material_separates_outputs_by_spec() {
        let passkey = DerivationSpec::V1(
            DerivationSpecV1::passkey_provider("io.github.example", "example.com", "cred-123", 32)
                .unwrap(),
        );
        let child_key = DerivationSpec::V1(
            DerivationSpecV1::software_child_key(
                "io.github.example",
                "ed25519",
                "m/ssh/0",
                OutputKind::Ed25519Seed,
            )
            .unwrap(),
        );

        let material = b"test-prf-material";
        let passkey_output = passkey.derive_output(material).unwrap();
        let child_key_output = child_key.derive_output(material).unwrap();

        assert_ne!(
            passkey_output.expose_secret(),
            child_key_output.expose_secret()
        );
    }
}
