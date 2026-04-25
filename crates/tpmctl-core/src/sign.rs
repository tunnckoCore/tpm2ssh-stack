use std::fmt;

use zeroize::Zeroizing;

use crate::{
    CommandContext, HashAlgorithm, KeyUsage, ObjectDescriptor, ObjectSelector, Result, Store,
};

use crate::output::{SignatureFormat, encode_p256_signature};

#[derive(Clone, Eq, PartialEq)]
pub struct SignRequest {
    pub selector: ObjectSelector,
    pub input: SignInput,
    pub hash: HashAlgorithm,
    pub output_format: SignatureFormat,
}

#[derive(Clone, Eq, PartialEq)]
pub enum SignInput {
    Message(Zeroizing<Vec<u8>>),
    Digest(Zeroizing<Vec<u8>>),
}

impl fmt::Debug for SignRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignRequest")
            .field("selector", &self.selector)
            .field("input", &self.input)
            .field("hash", &self.hash)
            .field("output_format", &self.output_format)
            .finish()
    }
}

impl fmt::Debug for SignInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(_) => formatter
                .debug_tuple("Message")
                .field(&"<redacted>")
                .finish(),
            Self::Digest(_) => formatter
                .debug_tuple("Digest")
                .field(&"<redacted>")
                .finish(),
        }
    }
}

impl SignRequest {
    pub fn digest(&self) -> Result<Zeroizing<Vec<u8>>> {
        match &self.input {
            SignInput::Message(message) => Ok(Zeroizing::new(self.hash.digest(message))),
            SignInput::Digest(digest) => {
                self.hash.validate_digest(digest)?;
                Ok(Zeroizing::new(digest.to_vec()))
            }
        }
    }

    pub fn validate_descriptor(&self, descriptor: &ObjectDescriptor) -> Result<()> {
        descriptor.require_usage(KeyUsage::Sign)
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
        let digest = self.digest()?;
        let mut context = crate::tpm::create_context_for(command)?;
        let loaded = match &self.selector {
            ObjectSelector::Id(id) => crate::tpm::load_key_by_id(&mut context, store, id)?,
            ObjectSelector::Handle(handle) => {
                crate::tpm::load_key_by_handle(&mut context, *handle)?
            }
        };
        self.validate_descriptor(&loaded.descriptor)?;
        let p1363 = crate::tpm::sign_digest(&mut context, loaded.handle, &digest, self.hash)?;
        encode_tpm_p256_signature(&p1363, self.output_format)
    }
}

pub fn encode_tpm_p256_signature(p1363: &[u8], output_format: SignatureFormat) -> Result<Vec<u8>> {
    encode_p256_signature(p1363, output_format)
}

#[cfg(test)]
mod sign_tests {
    use super::*;
    use crate::{PersistentHandle, output::SignatureFormat};

    fn selector() -> ObjectSelector {
        ObjectSelector::Handle(PersistentHandle::new(0x8101_0010).unwrap())
    }

    #[test]
    fn sign_hashes_input_with_requested_hash() {
        let request = SignRequest {
            selector: selector(),
            input: SignInput::Message(Zeroizing::new(b"hello".to_vec())),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Der,
        };
        assert_eq!(request.digest().unwrap().len(), 32);
    }

    #[test]
    fn sign_validates_digest_length_against_hash() {
        let request = SignRequest {
            selector: selector(),
            input: SignInput::Digest(Zeroizing::new(vec![0; 31])),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Der,
        };
        assert!(request.digest().is_err());
    }

    #[test]
    fn sign_supports_der_raw_and_hex_p1363_output() {
        let mut p1363 = vec![0_u8; 64];
        p1363[31] = 1;
        p1363[63] = 2;

        assert_eq!(
            encode_tpm_p256_signature(&p1363, SignatureFormat::Raw).unwrap(),
            p1363
        );
        assert_eq!(
            encode_tpm_p256_signature(&p1363, SignatureFormat::Hex).unwrap(),
            hex::encode(&p1363).into_bytes()
        );
        assert_eq!(
            encode_tpm_p256_signature(&p1363, SignatureFormat::Der).unwrap(),
            vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]
        );
    }

    #[test]
    fn sign_validates_sign_usage() {
        let request = SignRequest {
            selector: selector(),
            input: SignInput::Digest(Zeroizing::new(vec![0; 32])),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Der,
        };
        let descriptor = ObjectDescriptor {
            selector: selector(),
            usage: KeyUsage::Sign,
            curve: Some(crate::EccCurve::P256),
            hash: None,
            public_key: None,
        };
        assert!(request.validate_descriptor(&descriptor).is_ok());
    }
}
