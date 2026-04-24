use p256::pkcs8::DecodePublicKey as _;

use crate::output::{PublicKeyFormat, encode_public_key};
use crate::{
    EccPublicKey, Error, KeyUsage, ObjectDescriptor, ObjectSelector, Result,
    unsupported_without_tpm,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PubkeyRequest {
    pub selector: ObjectSelector,
    pub format: PublicKeyFormat,
}

impl PubkeyRequest {
    pub fn validate_descriptor(&self, descriptor: &ObjectDescriptor) -> Result<()> {
        match descriptor.usage {
            KeyUsage::Sign | KeyUsage::Ecdh => Ok(()),
            KeyUsage::Hmac | KeyUsage::Sealed => Err(Error::invalid(
                "usage",
                format!(
                    "cannot export a public key for {} objects",
                    descriptor.usage
                ),
            )),
        }
    }

    pub fn encode_descriptor_public_key(&self, descriptor: &ObjectDescriptor) -> Result<Vec<u8>> {
        self.validate_descriptor(descriptor)?;
        let public_key = descriptor
            .public_key
            .as_ref()
            .ok_or_else(|| Error::invalid("public_key", "descriptor has no cached public key"))?;
        encode_public_key(
            public_key,
            self.format,
            Some(&descriptor.selector.ssh_comment()),
        )
    }

    pub fn execute(&self) -> Result<Vec<u8>> {
        Err(unsupported_without_tpm("pubkey"))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PublicKeyInput {
    Sec1(Vec<u8>),
    Der(Vec<u8>),
    Pem(String),
}

impl PublicKeyInput {
    pub fn into_p256(self) -> Result<EccPublicKey> {
        match self {
            Self::Sec1(bytes) => EccPublicKey::p256_sec1(bytes),
            Self::Der(bytes) => {
                let key = p256::PublicKey::from_public_key_der(&bytes)
                    .map_err(|error| Error::invalid("public_key", error.to_string()))?;
                let point =
                    p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&key, false);
                EccPublicKey::p256_sec1(point.as_bytes().to_vec())
            }
            Self::Pem(pem) => {
                let key = p256::PublicKey::from_public_key_pem(&pem)
                    .map_err(|error| Error::invalid("public_key", error.to_string()))?;
                let point =
                    p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&key, false);
                EccPublicKey::p256_sec1(point.as_bytes().to_vec())
            }
        }
    }
}

#[cfg(test)]
mod pubkey_tests {
    use super::*;
    use crate::{PersistentHandle, RegistryId, output::PublicKeyFormat};

    fn sec1() -> Vec<u8> {
        hex::decode(concat!(
            "04",
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        ))
        .unwrap()
    }

    fn descriptor(usage: KeyUsage) -> ObjectDescriptor {
        ObjectDescriptor {
            selector: ObjectSelector::Id(RegistryId::new("org/acme/alice/main").unwrap()),
            usage,
            curve: Some(crate::EccCurve::P256),
            hash: None,
            public_key: Some(EccPublicKey::p256_sec1(sec1()).unwrap()),
        }
    }

    #[test]
    fn pubkey_rejects_hmac_and_sealed_objects() {
        let request = PubkeyRequest {
            selector: ObjectSelector::Handle(PersistentHandle::new(0x8101_0010).unwrap()),
            format: PublicKeyFormat::Pem,
        };
        assert!(
            request
                .validate_descriptor(&descriptor(KeyUsage::Hmac))
                .is_err()
        );
        assert!(
            request
                .validate_descriptor(&descriptor(KeyUsage::Sealed))
                .is_err()
        );
    }

    #[test]
    fn pubkey_supports_raw_hex_pem_der_and_ssh_output() {
        for format in [
            PublicKeyFormat::Raw,
            PublicKeyFormat::Hex,
            PublicKeyFormat::Pem,
            PublicKeyFormat::Der,
            PublicKeyFormat::Ssh,
        ] {
            let request = PubkeyRequest {
                selector: ObjectSelector::Id(RegistryId::new("org/acme/alice/main").unwrap()),
                format,
            };
            assert!(
                !request
                    .encode_descriptor_public_key(&descriptor(KeyUsage::Sign))
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn pubkey_ssh_comment_uses_sanitized_id() {
        let request = PubkeyRequest {
            selector: ObjectSelector::Id(RegistryId::new("org/acme/alice/main").unwrap()),
            format: PublicKeyFormat::Ssh,
        };
        let output = String::from_utf8(
            request
                .encode_descriptor_public_key(&descriptor(KeyUsage::Sign))
                .unwrap(),
        )
        .unwrap();
        assert!(output.ends_with(" org_acme_alice_main"));
    }
}
