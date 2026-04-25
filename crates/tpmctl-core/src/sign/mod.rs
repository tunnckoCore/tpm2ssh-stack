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
#[path = "mod.test.rs"]
mod sign_tests;
