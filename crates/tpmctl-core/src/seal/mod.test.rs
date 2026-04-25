use super::*;
use crate::{PersistentHandle, RegistryId};

fn selector() -> ObjectSelector {
    ObjectSelector::Id(RegistryId::new("org/acme/alice/sealed/foo").unwrap())
}

#[test]
fn seal_requires_non_empty_input() {
    let request = SealRequest {
        selector: selector(),
        input: Zeroizing::new(Vec::new()),
        force: false,
    };
    assert!(request.validate().is_err());
}

#[test]
fn unseal_validates_expected_object_usage() {
    let request = UnsealRequest {
        selector: ObjectSelector::Handle(PersistentHandle::new(0x8101_0020).unwrap()),
        force_binary_stdout: false,
    };
    let descriptor = ObjectDescriptor {
        selector: selector(),
        usage: KeyUsage::Sealed,
        curve: None,
        hash: None,
        public_key: None,
    };
    assert!(request.validate_descriptor(&descriptor).is_ok());
}

#[test]
fn unseal_rejects_non_sealed_usage() {
    let request = UnsealRequest {
        selector: ObjectSelector::Handle(PersistentHandle::new(0x8101_0020).unwrap()),
        force_binary_stdout: false,
    };
    let descriptor = ObjectDescriptor {
        selector: selector(),
        usage: KeyUsage::Hmac,
        curve: None,
        hash: None,
        public_key: None,
    };
    assert!(request.validate_descriptor(&descriptor).is_err());
}

#[test]
fn seal_result_carries_optional_hmac_hash_record() {
    let result = SealResult {
        selector: selector(),
        hash: Some(HashAlgorithm::Sha512),
    };
    assert_eq!(result.hash, Some(HashAlgorithm::Sha512));
}

#[test]
fn seal_request_debug_redacts_input() {
    let request = SealRequest {
        selector: selector(),
        input: Zeroizing::new(b"sealed-input-secret".to_vec()),
        force: false,
    };

    let debug = format!("{request:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("sealed-input-secret"));
}
