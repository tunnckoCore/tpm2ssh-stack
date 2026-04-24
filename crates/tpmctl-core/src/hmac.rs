use hmac_crate::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};
use tss_esapi::{handles::ObjectHandle, structures::MaxBuffer};
use zeroize::Zeroizing;

use crate::output::{BinaryFormat, encode_binary};
use crate::{
    CommandContext, Error, HashAlgorithm, KeyUsage, ObjectDescriptor, ObjectSelector, Result,
    SealTarget, seal::seal_bytes, store::Store, tpm,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HmacRequest {
    pub selector: ObjectSelector,
    pub input: Vec<u8>,
    pub hash: Option<HashAlgorithm>,
    pub format: BinaryFormat,
    pub seal_target: Option<SealTarget>,
    pub emit_prf_when_sealing: bool,
    pub force: bool,
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
        self.execute_with_context(&CommandContext::default())
    }

    pub fn execute_with_context(&self, command: &CommandContext) -> Result<HmacResult> {
        let mut context = tpm::create_context_for(command)?;
        let (object_handle, descriptor) = load_hmac_key(&mut context, command, &self.selector)?;
        self.validate_descriptor(&descriptor)?;
        let hash = self.effective_hash(Some(&descriptor));
        let output = compute_tpm_hmac(&mut context, object_handle, &self.input, hash)?;

        match &self.seal_target {
            None => Ok(HmacResult::Output(output)),
            Some(target) => {
                let selector = match target {
                    SealTarget::Id(id) => ObjectSelector::Id(id.clone()),
                    SealTarget::Handle(handle) => ObjectSelector::Handle(*handle),
                };
                seal_bytes(command, selector, output.as_slice(), self.force, Some(hash))?;
                if self.should_emit_prf_bytes() {
                    Ok(HmacResult::SealedWithOutput {
                        target: target.clone(),
                        hash,
                        output,
                    })
                } else {
                    Ok(HmacResult::Sealed {
                        target: target.clone(),
                        hash,
                    })
                }
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum HmacResult {
    Output(Zeroizing<Vec<u8>>),
    Sealed {
        target: SealTarget,
        hash: HashAlgorithm,
    },
    SealedWithOutput {
        target: SealTarget,
        hash: HashAlgorithm,
        output: Zeroizing<Vec<u8>>,
    },
}

pub fn encode_hmac_output(bytes: &[u8], format: BinaryFormat) -> Vec<u8> {
    encode_binary(bytes, format)
}

pub fn compute_tpm_hmac(
    context: &mut tss_esapi::Context,
    object_handle: ObjectHandle,
    input: &[u8],
    hash: HashAlgorithm,
) -> Result<Zeroizing<Vec<u8>>> {
    if input.len() > MaxBuffer::MAX_SIZE {
        // tss-esapi 7.6.0 intentionally has no safe wrappers for TPM2_HMAC_Start,
        // TPM2_SequenceUpdate, or TPM2_SequenceComplete; its
        // src/context/tpm_commands/hash_hmac_event_sequences.rs lists these exact
        // calls as "Missing function". Keep large-input HMAC rejected rather than
        // bypassing the crate's session/handle management with unsafe ESYS calls.
        return Err(Error::invalid(
            "input",
            format!(
                "HMAC input is too large for TPM2_HMAC one-shot ({} > {} bytes); tss-esapi 7.6.0 does not expose safe HMAC sequence APIs (HMAC_Start/SequenceUpdate/SequenceComplete are listed as missing)",
                input.len(),
                MaxBuffer::MAX_SIZE
            ),
        ));
    }

    let buffer = MaxBuffer::try_from(input)
        .map_err(|source| crate::CoreError::tpm("prepare HMAC input", source))?;
    let digest = context
        .execute_with_nullauth_session(|ctx| {
            ctx.hmac(object_handle, buffer, tpm::hashing_algorithm(hash))
        })
        .map_err(|source| crate::CoreError::tpm("HMAC", source))?;
    Ok(Zeroizing::new(digest.value().to_vec()))
}

fn load_hmac_key(
    context: &mut tss_esapi::Context,
    command: &CommandContext,
    selector: &ObjectSelector,
) -> Result<(ObjectHandle, ObjectDescriptor)> {
    match selector {
        ObjectSelector::Handle(handle) => {
            let object = tpm::load_persistent_object(context, *handle)?;
            let (public, _, _) = tpm::read_public(context, object)?;
            let descriptor = tpm::descriptor_from_public(ObjectSelector::Handle(*handle), &public)?;
            Ok((object, descriptor))
        }
        ObjectSelector::Id(id) => {
            let store = Store::resolve(command.store.root.as_deref())?;
            let parent = tpm::create_owner_primary(context)?;
            let (handle, descriptor) =
                tpm::load_key_from_registry_with_descriptor(context, &store, id, parent)?;
            Ok((ObjectHandle::from(handle), descriptor))
        }
    }
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
            force: false,
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

    #[test]
    fn hmac_result_can_carry_zeroizing_output() {
        let result = HmacResult::Output(Zeroizing::new(vec![1, 2, 3]));
        assert!(matches!(result, HmacResult::Output(_)));
    }
}
