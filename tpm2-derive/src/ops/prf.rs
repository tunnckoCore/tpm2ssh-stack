use secrecy::{ExposeSecret, SecretSlice};
use serde::{Deserialize, Serialize};

use crate::crypto::{DerivationSpec, DerivationVersion, OutputKind};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum PrfProtocolVersion {
    V1,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PrfRequest {
    pub profile: String,
    pub derivation: DerivationSpec,
}

impl PrfRequest {
    pub fn new(profile: impl Into<String>, derivation: DerivationSpec) -> Result<Self> {
        let request = Self {
            profile: profile.into(),
            derivation,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        if self.profile.trim().is_empty() {
            return Err(Error::Validation(
                "profile must not be empty for PRF operations".to_string(),
            ));
        }

        let _ = self.derivation.canonical_bytes()?;
        Ok(())
    }

    pub fn protocol_version(&self) -> PrfProtocolVersion {
        match self.derivation.version() {
            DerivationVersion::V1 => PrfProtocolVersion::V1,
        }
    }

    pub fn tpm_input(&self) -> Result<Vec<u8>> {
        self.validate()?;
        self.derivation.prf_request_message()
    }

    pub fn output_len(&self) -> usize {
        usize::from(self.derivation.output().length)
    }
}

#[derive(Debug, Clone)]
pub struct RawPrfOutput {
    pub version: PrfProtocolVersion,
    material: SecretSlice<u8>,
}

impl RawPrfOutput {
    pub fn new(version: PrfProtocolVersion, material: Vec<u8>) -> Result<Self> {
        if material.is_empty() {
            return Err(Error::Validation(
                "raw PRF output must not be empty".to_string(),
            ));
        }

        Ok(Self {
            version,
            material: material.into(),
        })
    }

    pub fn expose_secret(&self) -> &[u8] {
        self.material.expose_secret()
    }
}

#[derive(Debug, Clone)]
pub struct DerivedPrfOutput {
    pub version: PrfProtocolVersion,
    pub kind: OutputKind,
    bytes: SecretSlice<u8>,
}

impl DerivedPrfOutput {
    pub fn expose_secret(&self) -> &[u8] {
        self.bytes.expose_secret()
    }
}

#[derive(Debug, Clone)]
pub struct PrfResponse {
    pub request: PrfRequest,
    pub output: DerivedPrfOutput,
}

pub fn finalize(request: PrfRequest, raw: RawPrfOutput) -> Result<PrfResponse> {
    request.validate()?;
    ensure_matching_versions(request.protocol_version(), raw.version)?;

    let derived = request.derivation.derive_output(raw.expose_secret())?;
    Ok(PrfResponse {
        output: DerivedPrfOutput {
            version: raw.version,
            kind: request.derivation.output().kind,
            bytes: derived,
        },
        request,
    })
}

fn ensure_matching_versions(
    request_version: PrfProtocolVersion,
    response_version: PrfProtocolVersion,
) -> Result<()> {
    if request_version != response_version {
        return Err(Error::Validation(format!(
            "PRF version mismatch: request {:?}, response {:?}",
            request_version, response_version
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PrfProtocolVersion, PrfRequest, RawPrfOutput, finalize};
    use crate::crypto::{DerivationSpec, DerivationSpecV1};

    #[test]
    fn request_tpm_input_is_canonical_and_non_empty() {
        let request = PrfRequest::new(
            "default",
            DerivationSpec::V1(
                DerivationSpecV1::passkey_provider(
                    "io.github.example",
                    "example.com",
                    "cred-123",
                    32,
                )
                .unwrap(),
            ),
        )
        .unwrap();

        let encoded = request.tpm_input().unwrap();
        assert!(!encoded.is_empty());
        assert!(encoded.starts_with(crate::crypto::PRF_REQUEST_V1_DOMAIN));
    }

    #[test]
    fn finalize_derives_output_for_request() {
        let request = PrfRequest::new(
            "default",
            DerivationSpec::V1(
                DerivationSpecV1::software_child_key(
                    "io.github.example",
                    "ed25519",
                    "m/ssh/0",
                    crate::crypto::OutputKind::Ed25519Seed,
                )
                .unwrap(),
            ),
        )
        .unwrap();
        let raw = RawPrfOutput::new(PrfProtocolVersion::V1, b"tpm-prf-material".to_vec()).unwrap();

        let response = finalize(request, raw).unwrap();
        assert_eq!(response.output.expose_secret().len(), 32);
    }
}
