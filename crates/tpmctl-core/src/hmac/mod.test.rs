use super::*;
use crate::PersistentHandle;
use hmac_crate::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};

fn request() -> HmacRequest {
    HmacRequest {
        selector: ObjectSelector::Handle(PersistentHandle::new(0x8101_0010).unwrap()),
        input: Zeroizing::new(b"ctx".to_vec()),
        hash: None,
        output_format: BinaryFormat::Raw,
        seal_target: None,
        emit_prf_when_sealing: false,
        force: false,
    }
}

#[test]
fn hmac_effective_hash_matrix_and_usage_validation() {
    let hmac_with_hash = ObjectDescriptor {
        selector: ObjectSelector::Handle(PersistentHandle::new(0x8101_0010).unwrap()),
        usage: KeyUsage::Hmac,
        curve: None,
        hash: Some(HashAlgorithm::Sha512),
        public_key: None,
    };
    let hmac_without_hash = ObjectDescriptor {
        selector: ObjectSelector::Handle(PersistentHandle::new(0x8101_0011).unwrap()),
        usage: KeyUsage::Hmac,
        curve: None,
        hash: None,
        public_key: None,
    };
    let sign_descriptor = ObjectDescriptor {
        selector: ObjectSelector::Handle(PersistentHandle::new(0x8101_0012).unwrap()),
        usage: KeyUsage::Sign,
        curve: None,
        hash: None,
        public_key: None,
    };

    let mut override_request = request();
    override_request.hash = Some(HashAlgorithm::Sha384);
    assert_eq!(
        override_request.effective_hash(Some(&hmac_with_hash)),
        HashAlgorithm::Sha384
    );

    let default_request = request();
    assert!(default_request.validate_descriptor(&hmac_with_hash).is_ok());
    assert_eq!(
        default_request.effective_hash(Some(&hmac_with_hash)),
        HashAlgorithm::Sha512
    );
    assert_eq!(
        default_request.effective_hash(Some(&hmac_without_hash)),
        HashAlgorithm::Sha256
    );
    assert_eq!(default_request.effective_hash(None), HashAlgorithm::Sha256);
    assert!(
        default_request
            .validate_descriptor(&sign_descriptor)
            .is_err()
    );
}

#[test]
fn hmac_encodes_raw_and_hex_output() {
    assert_eq!(
        encode_hmac_output(&[0xab], BinaryFormat::Raw).as_slice(),
        &[0xab]
    );
    assert_eq!(
        encode_hmac_output(&[0xab], BinaryFormat::Hex).as_slice(),
        b"ab"
    );
}

fn reference_hmac<M>(key: &[u8], input: &[u8]) -> Vec<u8>
where
    M: Mac + hmac_crate::digest::KeyInit,
{
    let mut mac = <M as hmac_crate::digest::KeyInit>::new_from_slice(key).unwrap();
    mac.update(input);
    mac.finalize().into_bytes().to_vec()
}

#[test]
fn hmac_software_helper_dispatches_all_supported_hashes() {
    let key = b"key";
    let input = b"input";

    for (hash, expected) in [
        (
            HashAlgorithm::Sha256,
            reference_hmac::<Hmac<Sha256>>(key, input),
        ),
        (
            HashAlgorithm::Sha384,
            reference_hmac::<Hmac<Sha384>>(key, input),
        ),
        (
            HashAlgorithm::Sha512,
            reference_hmac::<Hmac<Sha512>>(key, input),
        ),
    ] {
        let out = compute_software_hmac_for_tests(key, input, hash).unwrap();
        assert_eq!(out.as_slice(), expected.as_slice());
        assert_eq!(out.len(), hash.digest_len());
    }
}

#[test]
fn hmac_should_emit_prf_bytes_matrix() {
    let default_request = request();
    assert!(default_request.should_emit_prf_bytes());

    let mut sealed_request = request();
    sealed_request.seal_target = Some(SealTarget::Handle(
        PersistentHandle::new(0x8101_0020).unwrap(),
    ));
    assert!(!sealed_request.should_emit_prf_bytes());
    sealed_request.emit_prf_when_sealing = true;
    assert!(sealed_request.should_emit_prf_bytes());
}

#[test]
fn hmac_debug_redacts_secret_input_and_output() {
    let mut request = request();
    request.input = Zeroizing::new(b"hmac-input-secret".to_vec());
    let request_debug = format!("{request:?}");
    assert!(request_debug.contains("<redacted>"));
    assert!(!request_debug.contains("hmac-input-secret"));

    let output = HmacResult::SealedWithOutput {
        target: SealTarget::Handle(PersistentHandle::new(0x8101_0020).unwrap()),
        hash: HashAlgorithm::Sha256,
        output: Zeroizing::new(b"hmac-output-secret".to_vec()),
    };
    let output_debug = format!("{output:?}");
    assert!(output_debug.contains("<redacted>"));
    assert!(!output_debug.contains("hmac-output-secret"));
}
