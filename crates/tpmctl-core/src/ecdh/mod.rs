use crate::output::{BinaryFormat, encode_secret_binary};
use crate::pubkey::PublicKeyInput;
use crate::{
    CommandContext, EccCurve, EccPublicKey, Error, KeyUsage, ObjectDescriptor, ObjectSelector,
    Result, Store,
};
use zeroize::Zeroizing;

/// Domain request for deriving an ECDH shared secret with a TPM key.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EcdhRequest {
    /// Local TPM ECDH key selected by registry ID or handle.
    pub selector: ObjectSelector,
    /// Peer public key input in SEC1, DER, or PEM form.
    pub peer_public_key: PublicKeyInput,
    /// Output encoding for the shared secret.
    pub output_format: BinaryFormat,
}

impl EcdhRequest {
    /// Ensure the loaded object descriptor is usable for P-256 ECDH.
    pub fn validate_descriptor(&self, descriptor: &ObjectDescriptor) -> Result<()> {
        descriptor.require_usage(KeyUsage::Ecdh)?;
        match descriptor.curve {
            Some(EccCurve::P256) => Ok(()),
            None => Err(Error::invalid(
                "curve",
                "expected P-256 ECDH object descriptor, got missing curve",
            )),
        }
    }

    /// Parse the peer public key into the normalized P-256 representation.
    pub fn parse_peer_public_key(&self) -> Result<EccPublicKey> {
        self.peer_public_key.clone().into_p256()
    }

    /// Execute the request using an explicit store and default command context.
    pub fn execute(&self, store: &Store) -> Result<Zeroizing<Vec<u8>>> {
        self.execute_with_store_and_context(store, &CommandContext::default())
    }

    /// Execute the request using a command context and its resolved store.
    pub fn execute_with_context(&self, command: &CommandContext) -> Result<Zeroizing<Vec<u8>>> {
        let store = Store::resolve(command.store.root.as_deref())?;
        self.execute_with_store_and_context(&store, command)
    }

    /// Execute the request using both an explicit store and command context.
    pub fn execute_with_store_and_context(
        &self,
        store: &Store,
        command: &CommandContext,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let peer_public_key = self.parse_peer_public_key()?;
        let mut context = crate::tpm::create_context_for(command)?;
        let loaded = match &self.selector {
            ObjectSelector::Id(id) => crate::tpm::load_key_by_id(&mut context, store, id)?,
            ObjectSelector::Handle(handle) => {
                crate::tpm::load_key_by_handle(&mut context, *handle)?
            }
        };
        self.validate_descriptor(&loaded.descriptor)?;
        let secret = crate::tpm::ecdh_z_gen(&mut context, loaded.handle, &peer_public_key)?;
        Ok(encode_shared_secret(secret.as_slice(), self.output_format))
    }
}

pub(crate) fn encode_shared_secret(
    secret: &[u8],
    output_format: BinaryFormat,
) -> Zeroizing<Vec<u8>> {
    encode_secret_binary(secret, output_format)
}

#[cfg(test)]
#[path = "mod.test.rs"]
mod ecdh_tests;
