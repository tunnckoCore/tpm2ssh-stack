use crate::output::{BinaryFormat, encode_secret_binary};
use crate::pubkey::PublicKeyInput;
use crate::{
    CommandContext, EccCurve, EccPublicKey, Error, KeyUsage, ObjectDescriptor, ObjectSelector,
    Result, Store,
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EcdhRequest {
    pub selector: ObjectSelector,
    pub peer_public_key: PublicKeyInput,
    pub output_format: BinaryFormat,
}

impl EcdhRequest {
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

    pub fn parse_peer_public_key(&self) -> Result<EccPublicKey> {
        self.peer_public_key.clone().into_p256()
    }

    pub fn execute(&self, store: &Store) -> Result<Zeroizing<Vec<u8>>> {
        self.execute_with_store_and_context(store, &CommandContext::default())
    }

    pub fn execute_with_context(&self, command: &CommandContext) -> Result<Zeroizing<Vec<u8>>> {
        let store = Store::resolve(command.store.root.as_deref())?;
        self.execute_with_store_and_context(&store, command)
    }

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

pub fn encode_shared_secret(secret: &[u8], output_format: BinaryFormat) -> Zeroizing<Vec<u8>> {
    encode_secret_binary(secret, output_format)
}

#[cfg(test)]
#[path = "mod.test.rs"]
mod ecdh_tests;
