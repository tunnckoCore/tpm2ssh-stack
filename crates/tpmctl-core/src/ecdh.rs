use crate::output::{BinaryFormat, encode_binary};
use crate::pubkey::PublicKeyInput;
use crate::{EccPublicKey, KeyUsage, ObjectDescriptor, ObjectSelector, Result, Store};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EcdhRequest {
    pub selector: ObjectSelector,
    pub peer_public_key: PublicKeyInput,
    pub format: BinaryFormat,
}

impl EcdhRequest {
    pub fn validate_descriptor(&self, descriptor: &ObjectDescriptor) -> Result<()> {
        descriptor.require_usage(KeyUsage::Ecdh)
    }

    pub fn parse_peer_public_key(&self) -> Result<EccPublicKey> {
        self.peer_public_key.clone().into_p256()
    }

    pub fn execute(&self, store: &Store) -> Result<Vec<u8>> {
        let peer_public_key = self.parse_peer_public_key()?;
        let mut context = crate::tpm::create_context()?;
        let loaded = match &self.selector {
            ObjectSelector::Id(id) => crate::tpm::load_key_by_id(&mut context, store, id)?,
            ObjectSelector::Handle(handle) => {
                crate::tpm::load_key_by_handle(&mut context, *handle)?
            }
        };
        self.validate_descriptor(&loaded.descriptor)?;
        let secret = crate::tpm::ecdh_z_gen(&mut context, loaded.handle, &peer_public_key)?;
        Ok(encode_shared_secret(&secret, self.format))
    }
}

pub fn encode_shared_secret(secret: &[u8], format: BinaryFormat) -> Vec<u8> {
    encode_binary(secret, format)
}

#[cfg(test)]
mod ecdh_tests {
    use super::*;
    use crate::{KeyUsage, PersistentHandle};

    fn sec1() -> Vec<u8> {
        hex::decode(concat!(
            "04",
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        ))
        .unwrap()
    }

    fn request() -> EcdhRequest {
        EcdhRequest {
            selector: ObjectSelector::Handle(PersistentHandle::new(0x8101_0010).unwrap()),
            peer_public_key: PublicKeyInput::Sec1(sec1()),
            format: BinaryFormat::Raw,
        }
    }

    #[test]
    fn ecdh_validates_expected_key_usage() {
        let descriptor = ObjectDescriptor {
            selector: ObjectSelector::Handle(PersistentHandle::new(0x8101_0010).unwrap()),
            usage: KeyUsage::Ecdh,
            curve: Some(crate::EccCurve::P256),
            hash: None,
            public_key: None,
        };
        assert!(request().validate_descriptor(&descriptor).is_ok());
    }

    #[test]
    fn ecdh_rejects_non_ecdh_usage() {
        let descriptor = ObjectDescriptor {
            selector: ObjectSelector::Handle(PersistentHandle::new(0x8101_0010).unwrap()),
            usage: KeyUsage::Sign,
            curve: Some(crate::EccCurve::P256),
            hash: None,
            public_key: None,
        };
        assert!(request().validate_descriptor(&descriptor).is_err());
    }

    #[test]
    fn ecdh_encodes_raw_and_hex_shared_secret() {
        assert_eq!(encode_shared_secret(&[1, 2], BinaryFormat::Raw), vec![1, 2]);
        assert_eq!(encode_shared_secret(&[1, 2], BinaryFormat::Hex), b"0102");
    }
}
