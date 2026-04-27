use super::support::*;

#[test]
fn simulator_api_facade_keygen_pubkey_sign_hmac_seal_and_ecdh_roundtrip() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };

    let sign_id = RegistryId::new("sim/api/sign").unwrap();
    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Sign,
            id: sign_id.clone(),
            persist_at: None,
            overwrite: false,
        },
    )
    .unwrap();

    let public_sec1 = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(sign_id.clone()),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_sec1).unwrap();

    let message = Zeroizing::new(b"api facade simulator signing".to_vec());
    let signature = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(sign_id),
            payload: SignPayload::Message(message.clone()),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap();
    let signature = P256Signature::from_slice(&signature).unwrap();
    verifying_key
        .verify(message.as_slice(), &signature)
        .unwrap();

    let hmac_id = RegistryId::new("sim/api/hmac").unwrap();
    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: hmac_id.clone(),
            persist_at: None,
            overwrite: false,
        },
    )
    .unwrap();
    let hmac = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(hmac_id),
            input: Zeroizing::new(b"context".to_vec()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::Output(mac) = hmac else {
        panic!("expected HMAC output")
    };
    assert_eq!(mac.len(), HashAlgorithm::Sha256.digest_len());

    let sealed_id = RegistryId::new("sim/api/sealed").unwrap();
    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: Zeroizing::new(b"sealed secret".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();
    let unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(unsealed.as_slice(), b"sealed secret");

    let ecdh_id = RegistryId::new("sim/api/ecdh").unwrap();
    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Ecdh,
            id: ecdh_id.clone(),
            persist_at: None,
            overwrite: false,
        },
    )
    .unwrap();
    let shared_secret = api::ecdh(
        &context,
        EcdhParams {
            material: ObjectSelector::Id(ecdh_id),
            peer_public_key: PublicKeyInput::Sec1(public_sec1),
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap();
    assert_eq!(shared_secret.len(), 32);
}
