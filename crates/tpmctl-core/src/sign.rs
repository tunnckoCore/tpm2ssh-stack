use std::fmt;

use zeroize::Zeroizing;

use crate::{
    CommandContext, HashAlgorithm, KeyUsage, ObjectDescriptor, ObjectSelector, Result, Store,
};

use crate::output::{SignatureFormat, encode_p256_signature};

/// Request for signing bytes with a TPM-backed P-256 signing key.
///
/// `SignInput::Message` accepts arbitrary bytes and hashes them with `hash` before
/// asking the TPM to sign. `SignInput::Digest` is for callers that already hashed
/// their payload; its length is validated against `hash` before signing.
#[derive(Clone, Eq, PartialEq)]
pub struct SignRequest {
    pub selector: ObjectSelector,
    pub input: SignInput,
    pub hash: HashAlgorithm,
    pub output_format: SignatureFormat,
}

/// Byte payload accepted by [`SignRequest`].
///
/// Use [`SignInput::Message`] for ordinary byte signing. Use
/// [`SignInput::Digest`] only when passing a precomputed digest whose size
/// matches `SignRequest::hash`.
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

    fn request(input: SignInput, hash: HashAlgorithm) -> SignRequest {
        SignRequest {
            selector: selector(),
            input,
            hash,
            output_format: SignatureFormat::Der,
        }
    }

    #[test]
    fn sign_hashes_message_to_exact_requested_digest() {
        let cases = [
            (
                HashAlgorithm::Sha256,
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            ),
            (
                HashAlgorithm::Sha384,
                "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f",
            ),
            (
                HashAlgorithm::Sha512,
                "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
            ),
        ];

        for (hash, expected_hex) in cases {
            let request = request(SignInput::Message(Zeroizing::new(b"hello".to_vec())), hash);
            let digest = request.digest().unwrap();

            assert_eq!(digest.len(), hash.digest_len());
            assert_eq!(hex::encode(&*digest), expected_hex);
        }
    }

    #[test]
    fn sign_uses_direct_digest_without_rehashing_when_length_matches_hash() {
        let digest = vec![0xA5; HashAlgorithm::Sha384.digest_len()];
        let request = request(
            SignInput::Digest(Zeroizing::new(digest.clone())),
            HashAlgorithm::Sha384,
        );

        assert_eq!(&*request.digest().unwrap(), digest.as_slice());
    }

    #[test]
    fn sign_validates_direct_digest_length_against_hash() {
        for (hash, invalid_len) in [
            (
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha256.digest_len() - 1,
            ),
            (HashAlgorithm::Sha384, HashAlgorithm::Sha256.digest_len()),
            (HashAlgorithm::Sha512, HashAlgorithm::Sha384.digest_len()),
        ] {
            let request = request(
                SignInput::Digest(Zeroizing::new(vec![0; invalid_len])),
                hash,
            );
            assert!(request.digest().is_err());
        }
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
