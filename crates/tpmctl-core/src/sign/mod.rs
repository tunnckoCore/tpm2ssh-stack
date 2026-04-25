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
    /// Signing key selected by registry ID or persistent handle.
    pub selector: ObjectSelector,
    /// Message or digest to sign.
    pub input: SignInput,
    /// Hash algorithm used for message hashing or digest validation.
    pub hash: HashAlgorithm,
    /// Signature encoding to return.
    pub output_format: SignatureFormat,
}

/// Byte payload accepted by [`SignRequest`].
///
/// Use [`SignInput::Message`] for ordinary byte signing. Use
/// [`SignInput::Digest`] only when passing a precomputed digest whose size
/// matches `SignRequest::hash`.
#[derive(Clone, Eq, PartialEq)]
pub enum SignInput {
    /// Arbitrary message bytes that will be hashed before signing.
    Message(Zeroizing<Vec<u8>>),
    /// Precomputed digest bytes whose length must match `SignRequest::hash`.
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
    /// Return the digest that will be submitted to the TPM for signing.
    pub fn digest(&self) -> Result<Zeroizing<Vec<u8>>> {
        match &self.input {
            SignInput::Message(message) => Ok(Zeroizing::new(self.hash.digest(message))),
            SignInput::Digest(digest) => {
                self.hash.validate_digest(digest)?;
                Ok(Zeroizing::new(digest.to_vec()))
            }
        }
    }

    /// Ensure the loaded object descriptor is usable for signing.
    pub fn validate_descriptor(&self, descriptor: &ObjectDescriptor) -> Result<()> {
        descriptor.require_usage(KeyUsage::Sign)
    }

    /// Execute the request using an explicit store and default command context.
    pub fn execute(&self, store: &Store) -> Result<Vec<u8>> {
        self.execute_with_store_and_context(store, &CommandContext::default())
    }

    /// Execute the request using a command context and its resolved store.
    pub fn execute_with_context(&self, command: &CommandContext) -> Result<Vec<u8>> {
        let store = Store::resolve(command.store.root.as_deref())?;
        self.execute_with_store_and_context(&store, command)
    }

    /// Execute the request using both an explicit store and command context.
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

pub(crate) fn encode_tpm_p256_signature(
    p1363: &[u8],
    output_format: SignatureFormat,
) -> Result<Vec<u8>> {
    encode_p256_signature(p1363, output_format)
}

#[cfg(test)]
#[path = "mod.test.rs"]
mod sign_tests;
