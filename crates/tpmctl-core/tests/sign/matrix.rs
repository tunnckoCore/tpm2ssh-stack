use super::support::*;

#[test]
fn simulator_native_sign_request_hash_and_format_matrix_verifies_with_exported_public_key() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let command = simulator_command_context(temp_store.path());
    let reloaded_command = simulator_command_context(temp_store.path());
    let handle = PersistentHandle::new(0x8101_0053).unwrap();
    let sign_id = RegistryId::new("sim/native/sign/hash-format-matrix").unwrap();
    let message = Zeroizing::new(b"native sign hash and format matrix".to_vec());

    KeygenRequest {
        usage: KeygenUsage::Sign,
        id: sign_id.clone(),
        persist_at: Some(handle),
        force: initial_persistent_force(),
    }
    .execute_with_context(&command)
    .unwrap();

    let public_by_id = PubkeyRequest {
        selector: ObjectSelector::Id(sign_id.clone()),
        output_format: PublicKeyFormat::Raw,
    }
    .execute_with_context(&command)
    .unwrap();
    let public_by_handle = PubkeyRequest {
        selector: ObjectSelector::Handle(handle),
        output_format: PublicKeyFormat::Raw,
    }
    .execute_with_context(&reloaded_command)
    .unwrap();
    assert_eq!(public_by_id, public_by_handle);

    let verifying_key = VerifyingKey::from_sec1_bytes(&public_by_id).unwrap();
    let hashes = [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ];
    let formats = [
        SignatureFormat::Raw,
        SignatureFormat::Hex,
        SignatureFormat::Der,
    ];

    for (hash_index, hash) in hashes.into_iter().enumerate() {
        let digest = Zeroizing::new(hash.digest(message.as_slice()));

        for (format_index, format) in formats.into_iter().enumerate() {
            let use_id_for_message = (hash_index + format_index) % 2 == 0;
            let (message_selector, message_command, digest_selector, digest_command) =
                if use_id_for_message {
                    (
                        ObjectSelector::Id(sign_id.clone()),
                        &command,
                        ObjectSelector::Handle(handle),
                        &reloaded_command,
                    )
                } else {
                    (
                        ObjectSelector::Handle(handle),
                        &reloaded_command,
                        ObjectSelector::Id(sign_id.clone()),
                        &command,
                    )
                };

            let message_signature = SignRequest {
                selector: message_selector,
                input: SignInput::Message(message.clone()),
                hash,
                output_format: format,
            }
            .execute_with_context(message_command)
            .unwrap();
            match format {
                SignatureFormat::Raw => assert_eq!(message_signature.len(), 64),
                SignatureFormat::Hex => assert_eq!(message_signature.len(), 128),
                SignatureFormat::Der => assert_eq!(message_signature.first(), Some(&0x30)),
            }
            let message_signature = decode_p256_signature(&message_signature, format);
            verifying_key
                .verify_prehash(digest.as_slice(), &message_signature)
                .unwrap();

            let digest_signature = SignRequest {
                selector: digest_selector,
                input: SignInput::Digest(digest.clone()),
                hash,
                output_format: format,
            }
            .execute_with_context(digest_command)
            .unwrap();
            match format {
                SignatureFormat::Raw => assert_eq!(digest_signature.len(), 64),
                SignatureFormat::Hex => assert_eq!(digest_signature.len(), 128),
                SignatureFormat::Der => assert_eq!(digest_signature.first(), Some(&0x30)),
            }
            let digest_signature = decode_p256_signature(&digest_signature, format);
            verifying_key
                .verify_prehash(digest.as_slice(), &digest_signature)
                .unwrap();
        }
    }

    cleanup_persistent_handle(handle);
}
