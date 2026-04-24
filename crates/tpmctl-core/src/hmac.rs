use hmac_crate::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

use crate::output::{BinaryFormat, encode_binary};
use crate::{
    Error, HashAlgorithm, KeyUsage, ObjectDescriptor, ObjectSelector, Result, SealTarget,
    unsupported_without_tpm,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HmacRequest {
    pub selector: ObjectSelector,
    pub input: Vec<u8>,
    pub hash: Option<HashAlgorithm>,
    pub format: BinaryFormat,
    pub seal_target: Option<SealTarget>,
    pub emit_prf_when_sealing: bool,
}

impl HmacRequest {
    pub fn effective_hash(&self, descriptor: Option<&ObjectDescriptor>) -> HashAlgorithm {
        self.hash
            .or_else(|| descriptor.and_then(|descriptor| descriptor.hash))
            .unwrap_or(HashAlgorithm::Sha256)
    }

    pub fn validate_descriptor(&self, descriptor: &ObjectDescriptor) -> Result<()> {
        descriptor.require_usage(KeyUsage::Hmac)
    }

    pub fn should_emit_prf_bytes(&self) -> bool {
        self.seal_target.is_none() || self.emit_prf_when_sealing
    }

    pub fn execute(&self) -> Result<HmacResult> {
        let _hash = self.effective_hash(None);
        Err(unsupported_without_tpm("hmac"))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum HmacResult {
    Output(Vec<u8>),
    Sealed {
        target: SealTarget,
        hash: HashAlgorithm,
    },
    SealedWithOutput {
        target: SealTarget,
        hash: HashAlgorithm,
        output: Vec<u8>,
    },
}

pub fn encode_hmac_output(bytes: &[u8], format: BinaryFormat) -> Vec<u8> {
    encode_binary(bytes, format)
}

pub fn compute_software_hmac_for_tests(
    key: &[u8],
    input: &[u8],
    hash: HashAlgorithm,
) -> Result<Zeroizing<Vec<u8>>> {
    let output = match hash {
        HashAlgorithm::Sha256 => compute::<Hmac<Sha256>>(key, input)?,
        HashAlgorithm::Sha384 => compute::<Hmac<Sha384>>(key, input)?,
        HashAlgorithm::Sha512 => compute::<Hmac<Sha512>>(key, input)?,
    };
    Ok(Zeroizing::new(output))
}

fn compute<M>(key: &[u8], input: &[u8]) -> Result<Vec<u8>>
where
    M: Mac + hmac_crate::digest::KeyInit,
{
    let mut mac = <M as hmac_crate::digest::KeyInit>::new_from_slice(key)
        .map_err(|error| Error::invalid("key", error.to_string()))?;
    mac.update(input);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod hmac_tests {
    use super::*;
    use crate::PersistentHandle;

    fn request() -> HmacRequest {
        HmacRequest {
            selector: ObjectSelector::Handle(PersistentHandle::new(0x8101_0010).unwrap()),
            input: b"ctx".to_vec(),
            hash: None,
            format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
        }
    }

    #[test]
    fn hmac_validates_expected_key_usage() {
        let descriptor = ObjectDescriptor {
            selector: ObjectSelector::Handle(PersistentHandle::new(0x8101_0010).unwrap()),
            usage: KeyUsage::Hmac,
            curve: None,
            hash: Some(HashAlgorithm::Sha512),
            public_key: None,
        };
        assert!(request().validate_descriptor(&descriptor).is_ok());
        assert_eq!(
            request().effective_hash(Some(&descriptor)),
            HashAlgorithm::Sha512
        );
    }

    #[test]
    fn hmac_rejects_non_hmac_usage() {
        let descriptor = ObjectDescriptor {
            selector: ObjectSelector::Handle(PersistentHandle::new(0x8101_0010).unwrap()),
            usage: KeyUsage::Sign,
            curve: None,
            hash: None,
            public_key: None,
        };
        assert!(request().validate_descriptor(&descriptor).is_err());
    }

    #[test]
    fn hmac_encodes_raw_and_hex_output() {
        assert_eq!(encode_hmac_output(&[0xab], BinaryFormat::Raw), vec![0xab]);
        assert_eq!(encode_hmac_output(&[0xab], BinaryFormat::Hex), b"ab");
    }

    #[test]
    fn hmac_one_shot_helper_is_testable() {
        let out = compute_software_hmac_for_tests(b"key", b"input", HashAlgorithm::Sha256).unwrap();
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn hmac_does_not_emit_prf_when_sealing_by_default() {
        let mut request = request();
        request.seal_target = Some(SealTarget::Handle(
            PersistentHandle::new(0x8101_0020).unwrap(),
        ));
        assert!(!request.should_emit_prf_bytes());
        request.emit_prf_when_sealing = true;
        assert!(request.should_emit_prf_bytes());
    }
}
