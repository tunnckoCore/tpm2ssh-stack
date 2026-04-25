use p256::pkcs8::DecodePublicKey as _;

use crate::output::{PublicKeyFormat, encode_public_key};
use crate::{
    CommandContext, EccPublicKey, Error, KeyUsage, ObjectDescriptor, ObjectSelector, Result, Store,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PubkeyRequest {
    pub selector: ObjectSelector,
    pub output_format: PublicKeyFormat,
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
            self.output_format,
            Some(&descriptor.selector.ssh_comment()),
        )
    }

    pub fn execute(&self, store: &Store) -> Result<Vec<u8>> {
        self.execute_with_store_and_context(store, &CommandContext::default())
    }

    pub fn execute_with_context(&self, command: &CommandContext) -> Result<Vec<u8>> {
        let store = Store::resolve(command.store.root.as_deref())?;
        self.execute_with_store_and_context(&store, command)
    }

    pub fn execute_with_store_and_context(
        &self,
        store: &Store,
        command: &CommandContext,
    ) -> Result<Vec<u8>> {
        if let ObjectSelector::Id(id) = &self.selector {
            let entry = store.load_key(id)?;
            let descriptor =
                crate::tpm::descriptor_from_entry(ObjectSelector::Id(id.clone()), &entry)?;
            return self.encode_descriptor_public_key(&descriptor);
        }

        let mut context = crate::tpm::create_context_for(command)?;
        let ObjectSelector::Handle(handle) = self.selector else {
            unreachable!("id selector returned above")
        };
        let loaded = crate::tpm::load_key_by_handle(&mut context, handle)?;
        self.encode_descriptor_public_key(&loaded.descriptor)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PublicKeyInput {
    Sec1(Vec<u8>),
    Der(Vec<u8>),
    Pem(String),
}

impl PublicKeyInput {
    pub fn parse_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.starts_with(b"-----BEGIN") {
            let pem = String::from_utf8(bytes)
                .map_err(|error| Error::invalid("public_key", error.to_string()))?;
            return Ok(Self::Pem(pem));
        }

        if matches!(bytes.first(), Some(0x02..=0x04)) {
            return Ok(Self::Sec1(bytes));
        }

        Ok(Self::Der(bytes))
    }

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
#[path = "mod.test.rs"]
mod pubkey_tests;
