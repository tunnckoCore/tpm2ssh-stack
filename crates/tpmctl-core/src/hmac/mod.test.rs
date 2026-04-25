use super::*;
use crate::PersistentHandle;

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
    assert_eq!(
        encode_hmac_output(&[0xab], BinaryFormat::Raw).as_slice(),
        &[0xab]
    );
    assert_eq!(
        encode_hmac_output(&[0xab], BinaryFormat::Hex).as_slice(),
        b"ab"
    );
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
