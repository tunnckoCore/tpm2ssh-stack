use std::{
    env,
    io::Read,
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use k256::ecdsa::{
    Signature as Secp256k1Signature, SigningKey as Secp256k1SigningKey,
    VerifyingKey as Secp256k1VerifyingKey,
};
use p256::{
    PublicKey, SecretKey,
    ecdh::diffie_hellman,
    ecdsa::{
        Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey,
        signature::{
            Verifier,
            hazmat::{PrehashSigner, PrehashVerifier},
        },
    },
    elliptic_curve::sec1::ToEncodedPoint,
};
use sha2::{Digest, Sha256, Sha384};
use tss_esapi::constants::StartupType;
use zeroize::Zeroizing;

use tpmctl_core::{
    DeriveAlgorithm, DeriveFormat, DeriveUse, HashAlgorithm, ObjectSelector, PersistentHandle,
    RegistryId, SealTarget, Store, StoreOptions,
    api::{
        self, Context as ApiContext, EcdhParams, HmacParams, KeygenParams, PubkeyParams,
        SealParams, SignParams, SignPayload, UnsealParams,
    },
    derive::{self, DeriveParams, SignPayload as DeriveSignPayload},
    hmac::HmacResult,
    keygen::{KeygenRequest, KeygenUsage},
    output::{BinaryFormat, PublicKeyFormat, SignatureFormat},
    pubkey::PublicKeyInput,
    sign::{SignInput, SignRequest},
};

const TCTI_ENV_PRECEDENCE: [&str; 3] = ["TPM2TOOLS_TCTI", "TCTI", "TEST_TCTI"];

fn simulator_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn simulator_or_test_tcti_opens_esapi_context_and_gets_random() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();

    startup_and_get_random();
}

#[test]
fn simulator_non_persistent_keygen_sign_reload_supports_sha512() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let store = Store::new(temp_store.path());
    let id = RegistryId::new("sim/keygen/reload-sign-sha512").unwrap();

    KeygenRequest {
        usage: KeygenUsage::Sign,
        id: id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_store(&store)
    .unwrap();

    let signature = SignRequest {
        selector: ObjectSelector::Id(id),
        input: SignInput::Message(Zeroizing::new(b"parent and hash flexibility".to_vec())),
        hash: HashAlgorithm::Sha512,
        output_format: SignatureFormat::Raw,
    }
    .execute(&store)
    .unwrap();

    assert_eq!(signature.len(), 64);
}

#[test]
fn simulator_persistent_handle_keygen_loads_by_handle_and_enforces_lifecycle() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let store = Store::new(temp_store.path());
    let handle = PersistentHandle::new(0x8101_0040).unwrap();
    let first_id = RegistryId::new("sim/keygen/persistent-first").unwrap();
    let second_id = RegistryId::new("sim/keygen/persistent-second").unwrap();

    let first = KeygenRequest {
        usage: KeygenUsage::Sign,
        id: first_id,
        persist_at: Some(handle),
        force: true,
    }
    .execute_with_store(&store)
    .unwrap();
    assert_eq!(first.persistent_handle, Some(handle));

    let context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let public_sec1 = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_sec1).unwrap();

    let message = Zeroizing::new(b"persistent simulator signing by handle".to_vec());
    let signature = SignRequest {
        selector: ObjectSelector::Handle(handle),
        input: SignInput::Message(message.clone()),
        hash: HashAlgorithm::Sha256,
        output_format: SignatureFormat::Raw,
    }
    .execute(&store)
    .unwrap();
    let signature = P256Signature::from_slice(&signature).unwrap();
    verifying_key
        .verify(message.as_slice(), &signature)
        .unwrap();

    let duplicate = KeygenRequest {
        usage: KeygenUsage::Sign,
        id: second_id.clone(),
        persist_at: Some(handle),
        force: false,
    }
    .execute_with_store(&store);
    assert!(
        duplicate.is_err(),
        "occupied persistent handle should reject duplicate keygen without force"
    );

    let replacement = KeygenRequest {
        usage: KeygenUsage::Sign,
        id: second_id,
        persist_at: Some(handle),
        force: true,
    }
    .execute_with_store(&store)
    .unwrap();
    assert_eq!(replacement.persistent_handle, Some(handle));

    let replacement_signature = SignRequest {
        selector: ObjectSelector::Handle(handle),
        input: SignInput::Message(message.clone()),
        hash: HashAlgorithm::Sha256,
        output_format: SignatureFormat::Raw,
    }
    .execute(&store)
    .unwrap();
    let replacement_signature = P256Signature::from_slice(&replacement_signature).unwrap();
    assert!(
        verifying_key
            .verify(message.as_slice(), &replacement_signature)
            .is_err(),
        "force should evict the old persistent object before persisting replacement"
    );

    let replacement_public_sec1 = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    assert_ne!(
        public_sec1, replacement_public_sec1,
        "replacement must install a distinct object at the persistent handle"
    );

    let mut tpm_context = tpmctl_core::tpm::create_context().unwrap();
    let persistent_object = tpmctl_core::tpm::load_persistent_object(&mut tpm_context, handle)
        .expect("replacement should be present at persistent handle");
    tpmctl_core::tpm::evict_persistent_object(&mut tpm_context, persistent_object, handle)
        .expect("test cleanup should evict replacement persistent object");
    assert!(
        tpmctl_core::tpm::load_persistent_object(&mut tpm_context, handle).is_err(),
        "cleanup eviction should leave the persistent handle vacant"
    );
}

#[test]
fn simulator_seal_rejects_existing_registry_target_without_overwrite_and_preserves_original() {
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
    let sealed_id = RegistryId::new("sim/negative/sealed-duplicate").unwrap();

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: Zeroizing::new(b"first sealed secret".to_vec()),
            overwrite: true,
        },
    )
    .unwrap();

    let store = Store::new(temp_store.path());
    let original_entry = store.load_sealed(&sealed_id).unwrap();

    let duplicate = api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: Zeroizing::new(b"second sealed secret".to_vec()),
            overwrite: false,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(duplicate.contains("already exists"));

    let preserved_entry = store.load_sealed(&sealed_id).unwrap();
    assert_eq!(preserved_entry, original_entry);

    let unsealed = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(unsealed.as_slice(), b"first sealed secret");
}

#[test]
fn simulator_api_rejects_wrong_selector_kinds_and_wrong_usages() {
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

    let sign_id = RegistryId::new("sim/negative/api-misuse/sign").unwrap();
    let hmac_id = RegistryId::new("sim/negative/api-misuse/hmac").unwrap();
    let ecdh_id = RegistryId::new("sim/negative/api-misuse/ecdh").unwrap();
    let sealed_id = RegistryId::new("sim/negative/api-misuse/sealed").unwrap();
    let hmac_handle = PersistentHandle::new(0x8101_0043).unwrap();
    let sign_handle = PersistentHandle::new(0x8101_0045).unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Sign,
            id: sign_id.clone(),
            persist_at: Some(sign_handle),
            overwrite: true,
        },
    )
    .unwrap();
    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: hmac_id.clone(),
            persist_at: Some(hmac_handle),
            overwrite: true,
        },
    )
    .unwrap();
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
    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(sealed_id.clone()),
            input: Zeroizing::new(b"sealed misuse secret".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();
    let sign_with_hmac = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Handle(hmac_handle),
            payload: SignPayload::Message(Zeroizing::new(b"wrong usage sign".to_vec())),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(sign_with_hmac.contains("expected sign object, got hmac"));

    let hmac_with_sign = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(sign_id.clone()),
            input: Zeroizing::new(b"wrong usage hmac".to_vec()),
            hash: None,
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(hmac_with_sign.contains("expected hmac object, got sign"));

    let ecdh_with_sign = api::ecdh(
        &context,
        EcdhParams {
            material: ObjectSelector::Id(sign_id.clone()),
            peer_public_key: PublicKeyInput::Sec1(
                SecretKey::from_slice(&[0x24; 32])
                    .unwrap()
                    .public_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
            ),
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(ecdh_with_sign.contains("expected ecdh object, got sign"));

    let unseal_sign_key = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Handle(sign_handle),
        },
    )
    .unwrap_err()
    .to_string();
    assert!(unseal_sign_key.contains("object is not a keyed-hash HMAC key or sealed data object"));

    let pubkey_from_hmac_handle = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Handle(hmac_handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(pubkey_from_hmac_handle.contains("cannot export a public key for hmac objects"));

    let pubkey_from_sealed_id = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(sealed_id),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap_err();
    assert!(matches!(
        pubkey_from_sealed_id,
        tpmctl_core::Error::NotFound(_)
    ));

    let ecdh_pubkey = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(ecdh_id),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    assert_eq!(ecdh_pubkey.len(), 65);
}

#[test]
fn simulator_sign_and_hmac_reject_wrong_object_usages() {
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

    let store = Store::new(temp_store.path());
    let sign_id = RegistryId::new("sim/negative/sign-key").unwrap();
    let hmac_id = RegistryId::new("sim/negative/hmac-key").unwrap();

    KeygenRequest {
        usage: KeygenUsage::Sign,
        id: sign_id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_store(&store)
    .unwrap();

    KeygenRequest {
        usage: KeygenUsage::Hmac,
        id: hmac_id.clone(),
        persist_at: None,
        force: false,
    }
    .execute_with_store(&store)
    .unwrap();

    let sign_with_hmac = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(hmac_id.clone()),
            payload: SignPayload::Message(Zeroizing::new(b"wrong usage sign".to_vec())),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(sign_with_hmac.contains("expected sign object, got hmac"));

    let hmac_with_sign = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(sign_id.clone()),
            input: Zeroizing::new(b"wrong usage hmac".to_vec()),
            hash: None,
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(hmac_with_sign.contains("expected hmac object, got sign"));
}

#[test]
fn simulator_handle_and_id_resolution_reject_stale_or_mismatched_persistent_metadata() {
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
    let store = Store::new(temp_store.path());
    let handle = PersistentHandle::new(0x8101_0044).unwrap();
    let sign_id = RegistryId::new("sim/negative/handle-id/sign").unwrap();
    let ecdh_id = RegistryId::new("sim/negative/handle-id/ecdh").unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Sign,
            id: sign_id.clone(),
            persist_at: Some(handle),
            overwrite: true,
        },
    )
    .unwrap();
    let original_entry = store.load_key(&sign_id).unwrap();

    let mut tpm_context = tpmctl_core::tpm::create_context().unwrap();
    let persistent_object = tpmctl_core::tpm::load_persistent_object(&mut tpm_context, handle)
        .expect("sign key should be present at persistent handle");
    tpmctl_core::tpm::evict_persistent_object(&mut tpm_context, persistent_object, handle)
        .expect("test should be able to evict persistent object");

    let by_handle_missing = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap_err();
    assert!(matches!(by_handle_missing, tpmctl_core::Error::Tpm { .. }));

    let by_id_missing = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(sign_id.clone()),
            payload: SignPayload::Message(Zeroizing::new(b"missing persistent backing".to_vec())),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap_err();
    assert!(matches!(by_id_missing, tpmctl_core::Error::Tpm { .. }));
    assert_eq!(store.load_key(&sign_id).unwrap(), original_entry);

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Ecdh,
            id: ecdh_id.clone(),
            persist_at: Some(handle),
            overwrite: true,
        },
    )
    .unwrap();

    let replacement_pubkey = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    assert_eq!(replacement_pubkey.len(), 65);

    let stale_by_id = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(sign_id),
            payload: SignPayload::Message(Zeroizing::new(
                b"stale metadata should reject mismatched replacement".to_vec(),
            )),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(stale_by_id.contains("registry says sign but persistent handle contains ecdh object"));

    let ecdh_by_id = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(ecdh_id),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    assert_eq!(replacement_pubkey, ecdh_by_id);
}

#[test]
fn simulator_force_replacement_allows_manual_evict_of_replacement_only() {
    let _guard = simulator_test_lock().lock().unwrap();
    let _tcti = require_simulator_tcti();
    startup_and_get_random();

    let temp_store = tempfile::tempdir().expect("create temp tpmctl store");
    let store = Store::new(temp_store.path());
    let handle = PersistentHandle::new(0x8101_0041).unwrap();
    let first_id = RegistryId::new("sim/keygen/force-evict-first").unwrap();
    let second_id = RegistryId::new("sim/keygen/force-evict-second").unwrap();

    KeygenRequest {
        usage: KeygenUsage::Sign,
        id: first_id,
        persist_at: Some(handle),
        force: true,
    }
    .execute_with_store(&store)
    .unwrap();
    let first_public = api::pubkey(
        &ApiContext {
            store: StoreOptions {
                root: Some(temp_store.path().to_path_buf()),
            },
            tcti: None,
        },
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();

    KeygenRequest {
        usage: KeygenUsage::Sign,
        id: second_id,
        persist_at: Some(handle),
        force: true,
    }
    .execute_with_store(&store)
    .unwrap();
    let mut tpm_context = tpmctl_core::tpm::create_context().unwrap();
    let replacement_object = tpmctl_core::tpm::load_persistent_object(&mut tpm_context, handle)
        .expect("force replacement should leave replacement object persistent");
    let (replacement_public, _, _) =
        tpmctl_core::tpm::read_public(&mut tpm_context, replacement_object).unwrap();
    let replacement_descriptor = tpmctl_core::tpm::descriptor_from_tpm_public(
        ObjectSelector::Handle(handle),
        replacement_public,
    )
    .unwrap();
    assert_ne!(
        first_public,
        replacement_descriptor.public_key.unwrap().sec1(),
        "force replacement should evict old object and expose replacement public key"
    );

    tpmctl_core::tpm::evict_persistent_object(&mut tpm_context, replacement_object, handle)
        .expect("replacement object should be evictable after force replacement");
    assert!(
        tpmctl_core::tpm::load_persistent_object(&mut tpm_context, handle).is_err(),
        "evicting replacement should clean up the persistent handle"
    );
}

#[test]
fn simulator_api_signs_message_and_digest_bytes_with_exported_p256_public_key() {
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
    let sign_id = RegistryId::new("sim/api/sign-message-and-digest").unwrap();

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

    let message = Zeroizing::new(b"api simulator message bytes".to_vec());
    let message_signature = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(sign_id.clone()),
            payload: SignPayload::Message(message.clone()),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap();
    let message_signature = P256Signature::from_slice(&message_signature).unwrap();
    verifying_key
        .verify(message.as_slice(), &message_signature)
        .unwrap();

    let digest = Zeroizing::new(Sha256::digest(b"api simulator digest bytes").to_vec());
    let digest_signature = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(sign_id.clone()),
            payload: SignPayload::Digest(digest.clone()),
            hash: HashAlgorithm::Sha256,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap();
    let digest_signature = P256Signature::from_slice(&digest_signature).unwrap();
    verifying_key
        .verify_prehash(digest.as_slice(), &digest_signature)
        .unwrap();

    let sha384_message = Zeroizing::new(b"api simulator sha384 message bytes".to_vec());
    let sha384_message_digest = Zeroizing::new(Sha384::digest(sha384_message.as_slice()).to_vec());
    let sha384_message_signature = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(sign_id.clone()),
            payload: SignPayload::Message(sha384_message),
            hash: HashAlgorithm::Sha384,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap();
    let sha384_message_signature = P256Signature::from_slice(&sha384_message_signature).unwrap();
    verifying_key
        .verify_prehash(sha384_message_digest.as_slice(), &sha384_message_signature)
        .unwrap();

    let sha384_digest =
        Zeroizing::new(Sha384::digest(b"api simulator sha384 digest bytes").to_vec());
    let sha384_digest_signature = api::sign(
        &context,
        SignParams {
            material: ObjectSelector::Id(sign_id),
            payload: SignPayload::Digest(sha384_digest.clone()),
            hash: HashAlgorithm::Sha384,
            output_format: SignatureFormat::Raw,
        },
    )
    .unwrap();
    let sha384_digest_signature = P256Signature::from_slice(&sha384_digest_signature).unwrap();
    verifying_key
        .verify_prehash(sha384_digest.as_slice(), &sha384_digest_signature)
        .unwrap();
}

#[test]
fn simulator_api_hmac_seal_target_seals_and_emits_prf() {
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
    let hmac_id = RegistryId::new("sim/api/hmac-seal-target/key").unwrap();
    let sealed_id = RegistryId::new("sim/api/hmac-seal-target/prf").unwrap();
    let input = Zeroizing::new(b"seal target integration input".to_vec());

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

    let sealed = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(hmac_id),
            input,
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: Some(SealTarget::Id(sealed_id.clone())),
            emit_prf_when_sealing: true,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::SealedWithOutput {
        target,
        hash,
        output: expected_prf,
    } = sealed
    else {
        panic!("expected sealed HMAC output")
    };
    assert_eq!(target, SealTarget::Id(sealed_id.clone()));
    assert_eq!(hash, HashAlgorithm::Sha256);
    assert_eq!(expected_prf.len(), HashAlgorithm::Sha256.digest_len());

    let unsealed_prf = api::unseal(
        &context,
        UnsealParams {
            material: ObjectSelector::Id(sealed_id),
        },
    )
    .unwrap();
    assert_eq!(unsealed_prf.as_slice(), expected_prf.as_slice());
}

#[test]
fn simulator_api_derive_from_sealed_seed_emits_p256_pubkey_and_signature() {
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
    let seed_id = RegistryId::new("sim/api/derive/sealed-seed").unwrap();
    let label = b"simulator sealed seed p256 derivation".to_vec();

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(seed_id.clone()),
            input: Zeroizing::new(b"sealed derive integration seed material".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();

    let secret = derive::derive(
        &context,
        DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::P256,
            usage: DeriveUse::Secret,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    let repeated_secret = derive::derive(
        &context,
        DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::P256,
            usage: DeriveUse::Secret,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(secret, repeated_secret);
    assert_eq!(secret.len(), 32);
    let software_secret = SecretKey::from_slice(secret.as_slice()).unwrap();

    let public_sec1 = derive::derive(
        &context,
        DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::P256,
            usage: DeriveUse::Pubkey,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(public_sec1.len(), 65);
    assert_eq!(public_sec1[0], 0x04);
    let expected_public_sec1 = software_secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    assert_eq!(public_sec1.as_slice(), expected_public_sec1.as_slice());
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_sec1).unwrap();

    let message = Zeroizing::new(b"api derive simulator signature payload".to_vec());
    let digest = Sha256::digest(message.as_slice());
    let signature = derive::derive(
        &context,
        DeriveParams {
            material: ObjectSelector::Id(seed_id),
            label: Some(label),
            algorithm: DeriveAlgorithm::P256,
            usage: DeriveUse::Sign,
            payload: Some(DeriveSignPayload::Message(message.clone())),
            hash: Some(HashAlgorithm::Sha256),
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(signature.len(), 64);
    let software_signature: P256Signature = P256SigningKey::from(software_secret)
        .sign_prehash(&digest)
        .unwrap();
    let software_signature_bytes = software_signature.to_bytes();
    assert_eq!(signature.as_slice(), &software_signature_bytes[..]);
    let signature = P256Signature::from_slice(&signature).unwrap();
    verifying_key
        .verify(message.as_slice(), &signature)
        .unwrap();
}

#[test]
fn simulator_api_derive_from_sealed_seed_emits_secp256k1_pubkey_address_and_signature() {
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
    let seed_id = RegistryId::new("sim/api/derive/secp256k1-sealed-seed").unwrap();
    let label = b"simulator sealed seed secp256k1 derivation".to_vec();

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(seed_id.clone()),
            input: Zeroizing::new(b"sealed secp256k1 derive integration seed material".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();

    let secret = derive::derive(
        &context,
        DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::Secp256k1,
            usage: DeriveUse::Secret,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(secret.len(), 32);
    let software_secret = k256::SecretKey::from_slice(secret.as_slice()).unwrap();

    let public_sec1 = derive::derive(
        &context,
        DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::Secp256k1,
            usage: DeriveUse::Pubkey,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(public_sec1.len(), 65);
    assert_eq!(public_sec1[0], 0x04);
    let expected_public_sec1 = software_secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    assert_eq!(public_sec1.as_slice(), expected_public_sec1.as_slice());
    let verifying_key = Secp256k1VerifyingKey::from_sec1_bytes(&public_sec1).unwrap();

    let compressed_public = derive::derive(
        &context,
        derive::DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::Secp256k1,
            usage: derive::DeriveUse::Pubkey,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: true,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(compressed_public.len(), 33);
    assert!(matches!(compressed_public[0], 0x02 | 0x03));

    let address = derive::derive(
        &context,
        derive::DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::Secp256k1,
            usage: derive::DeriveUse::Pubkey,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Address,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(address.len(), 42);
    assert!(address.starts_with(b"0x"));

    let message = Zeroizing::new(b"api derive simulator secp256k1 signature payload".to_vec());
    let digest = Zeroizing::new(Sha256::digest(message.as_slice()).to_vec());
    let signature = derive::derive(
        &context,
        DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::Secp256k1,
            usage: DeriveUse::Sign,
            payload: Some(DeriveSignPayload::Message(message.clone())),
            hash: Some(HashAlgorithm::Sha256),
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(signature.len(), 64);
    let software_signature: Secp256k1Signature = Secp256k1SigningKey::from(software_secret.clone())
        .sign_prehash(&digest)
        .unwrap();
    let software_signature_bytes = software_signature.to_bytes();
    assert_eq!(signature.as_slice(), &software_signature_bytes[..]);
    let signature = Secp256k1Signature::from_slice(&signature).unwrap();
    verifying_key
        .verify_prehash(digest.as_slice(), &signature)
        .unwrap();

    let digest_signature = derive::derive(
        &context,
        derive::DeriveParams {
            material: ObjectSelector::Id(seed_id),
            label: Some(label),
            algorithm: DeriveAlgorithm::Secp256k1,
            usage: derive::DeriveUse::Sign,
            payload: Some(derive::SignPayload::Digest(digest.clone())),
            hash: Some(HashAlgorithm::Sha256),
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(digest_signature.len(), 64);
    let digest_signature = Secp256k1Signature::from_slice(&digest_signature).unwrap();
    verifying_key
        .verify_prehash(digest.as_slice(), &digest_signature)
        .unwrap();
}

#[test]
fn simulator_api_derive_from_sealed_seed_emits_ed25519_pubkey_and_signature() {
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
    let seed_id = RegistryId::new("sim/api/derive/ed25519-sealed-seed").unwrap();
    let label = b"simulator sealed seed ed25519 derivation".to_vec();

    api::seal(
        &context,
        SealParams {
            target: ObjectSelector::Id(seed_id.clone()),
            input: Zeroizing::new(b"sealed ed25519 derive integration seed material".to_vec()),
            overwrite: false,
        },
    )
    .unwrap();

    let public_key = derive::derive(
        &context,
        derive::DeriveParams {
            material: ObjectSelector::Id(seed_id.clone()),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::Ed25519,
            usage: derive::DeriveUse::Pubkey,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(public_key.len(), 32);
    let public_key: [u8; 32] = public_key.as_slice().try_into().unwrap();
    let verifying_key = Ed25519VerifyingKey::from_bytes(&public_key).unwrap();

    let message = Zeroizing::new(b"api derive simulator ed25519 signature payload".to_vec());
    let signature = derive::derive(
        &context,
        derive::DeriveParams {
            material: ObjectSelector::Id(seed_id),
            label: Some(label),
            algorithm: DeriveAlgorithm::Ed25519,
            usage: derive::DeriveUse::Sign,
            payload: Some(derive::SignPayload::Message(message.clone())),
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(signature.len(), 64);
    let signature = Ed25519Signature::try_from(signature.as_slice()).unwrap();
    verifying_key
        .verify(message.as_slice(), &signature)
        .unwrap();
}

#[test]
fn simulator_api_derive_uses_hmac_identity_seed_fallback_deterministically() {
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
    let hmac_id = RegistryId::new("sim/api/derive-hmac-seed/key").unwrap();
    let label = b"simulator derive hmac fallback label".to_vec();

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

    let address_params = DeriveParams {
        material: ObjectSelector::Id(hmac_id.clone()),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::Secp256k1,
        usage: DeriveUse::Pubkey,
        payload: None,
        hash: None,
        output_format: DeriveFormat::Address,
        compressed: false,
        entropy: None,
    };
    let first_address = derive::derive(&context, address_params.clone()).unwrap();
    let second_address = derive::derive(&context, address_params).unwrap();
    assert_eq!(first_address, second_address);
    assert_eq!(first_address.len(), 42);
    assert!(first_address.starts_with(b"0x"));

    let pubkey_params = DeriveParams {
        material: ObjectSelector::Id(hmac_id.clone()),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::Secp256k1,
        usage: DeriveUse::Pubkey,
        payload: None,
        hash: None,
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let first_pubkey = derive::derive(&context, pubkey_params.clone()).unwrap();
    let second_pubkey = derive::derive(&context, pubkey_params).unwrap();
    assert_eq!(first_pubkey, second_pubkey);
    assert_eq!(first_pubkey.len(), 65);
    assert_eq!(first_pubkey[0], 0x04);

    let signature_params = DeriveParams {
        material: ObjectSelector::Id(hmac_id),
        label: Some(label),
        algorithm: DeriveAlgorithm::P256,
        usage: DeriveUse::Sign,
        payload: Some(DeriveSignPayload::Message(Zeroizing::new(
            b"derive with hmac identity seed fallback".to_vec(),
        ))),
        hash: Some(HashAlgorithm::Sha256),
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let first_signature = derive::derive(&context, signature_params.clone()).unwrap();
    let second_signature = derive::derive(&context, signature_params).unwrap();
    assert_eq!(first_signature, second_signature);
    assert_eq!(first_signature.len(), 64);
}

#[test]
fn simulator_api_derive_uses_hmac_identity_seed_via_persistent_handle() {
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
    let hmac_id = RegistryId::new("sim/api/derive-hmac-handle/key").unwrap();
    let handle = PersistentHandle::new(0x8101_0042).unwrap();
    let label = b"simulator derive hmac persistent handle label".to_vec();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: hmac_id.clone(),
            persist_at: Some(handle),
            overwrite: true,
        },
    )
    .unwrap();

    let by_handle_secret_params = DeriveParams {
        material: ObjectSelector::Handle(handle),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::P256,
        usage: DeriveUse::Secret,
        payload: None,
        hash: None,
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let handle_secret = derive::derive(&context, by_handle_secret_params.clone()).unwrap();
    let repeated_handle_secret = derive::derive(&context, by_handle_secret_params).unwrap();
    assert_eq!(handle_secret, repeated_handle_secret);
    assert_eq!(handle_secret.len(), 32);
    let software_secret = SecretKey::from_slice(handle_secret.as_slice()).unwrap();

    let by_handle_params = DeriveParams {
        material: ObjectSelector::Handle(handle),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::P256,
        usage: DeriveUse::Pubkey,
        payload: None,
        hash: None,
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let handle_pubkey = derive::derive(&context, by_handle_params.clone()).unwrap();
    let repeated_handle_pubkey = derive::derive(&context, by_handle_params).unwrap();
    assert_eq!(handle_pubkey, repeated_handle_pubkey);
    assert_eq!(handle_pubkey.len(), 65);
    assert_eq!(handle_pubkey[0], 0x04);
    let expected_public = software_secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    assert_eq!(handle_pubkey.as_slice(), expected_public.as_slice());

    let by_id_pubkey = derive::derive(
        &context,
        DeriveParams {
            material: ObjectSelector::Id(hmac_id),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::P256,
            usage: DeriveUse::Pubkey,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(handle_pubkey, by_id_pubkey);

    let message = Zeroizing::new(b"derive with persistent HMAC identity handle".to_vec());
    let digest = Sha256::digest(message.as_slice());
    let public_key = VerifyingKey::from_sec1_bytes(&handle_pubkey).unwrap();
    let signature = derive::derive(
        &context,
        DeriveParams {
            material: ObjectSelector::Handle(handle),
            label: Some(label),
            algorithm: DeriveAlgorithm::P256,
            usage: DeriveUse::Sign,
            payload: Some(DeriveSignPayload::Message(message.clone())),
            hash: Some(HashAlgorithm::Sha256),
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(signature.len(), 64);
    let software_signature: P256Signature = P256SigningKey::from(software_secret)
        .sign_prehash(&digest)
        .unwrap();
    let software_signature_bytes = software_signature.to_bytes();
    assert_eq!(signature.as_slice(), &software_signature_bytes[..]);
    let signature = P256Signature::from_slice(&signature).unwrap();
    public_key.verify(message.as_slice(), &signature).unwrap();

    cleanup_persistent_handle(handle);
}

#[test]
fn simulator_persistent_hmac_handle_survives_reload_and_force_replaces_handle_binding_only() {
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
    let store = Store::new(temp_store.path());
    let handle = PersistentHandle::new(0x8101_0043).unwrap();
    let first_id = RegistryId::new("sim/api/persistent-hmac-handle/first").unwrap();
    let second_id = RegistryId::new("sim/api/persistent-hmac-handle/second").unwrap();
    let input = b"persistent hmac simulator input".to_vec();

    let first = api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: first_id.clone(),
            persist_at: Some(handle),
            overwrite: true,
        },
    )
    .unwrap();
    assert_eq!(first.persistent_handle, Some(handle));

    let stored = store.load_key(&first_id).unwrap();
    assert_eq!(stored.record.handle.as_deref(), Some("0x81010043"));
    assert!(stored.record.persistent);

    let by_id = api::hmac(
        &context,
        HmacParams {
            material: ObjectSelector::Id(first_id.clone()),
            input: Zeroizing::new(input.clone()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::Output(by_id) = by_id else {
        panic!("expected raw HMAC output by id")
    };

    let reloaded_context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let by_handle = api::hmac(
        &reloaded_context,
        HmacParams {
            material: ObjectSelector::Handle(handle),
            input: Zeroizing::new(input.clone()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::Output(by_handle) = by_handle else {
        panic!("expected raw HMAC output by handle")
    };
    assert_eq!(by_id, by_handle);

    api::keygen(
        &reloaded_context,
        KeygenParams {
            usage: KeygenUsage::Hmac,
            id: second_id.clone(),
            persist_at: Some(handle),
            overwrite: true,
        },
    )
    .unwrap();

    let replaced = api::hmac(
        &reloaded_context,
        HmacParams {
            material: ObjectSelector::Handle(handle),
            input: Zeroizing::new(input.clone()),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::Output(replaced) = replaced else {
        panic!("expected replacement HMAC output by handle")
    };
    assert_ne!(replaced, by_handle);

    let original_by_id = api::hmac(
        &reloaded_context,
        HmacParams {
            material: ObjectSelector::Id(first_id),
            input: Zeroizing::new(input),
            hash: Some(HashAlgorithm::Sha256),
            output_format: BinaryFormat::Raw,
            seal_target: None,
            emit_prf_when_sealing: false,
            overwrite: false,
        },
    )
    .unwrap();
    let HmacResult::Output(original_by_id) = original_by_id else {
        panic!("expected original HMAC output by id after handle replacement")
    };
    assert_eq!(original_by_id, by_handle);
    assert_ne!(original_by_id, replaced);

    cleanup_persistent_handle(handle);
}

#[test]
fn simulator_persistent_ecdh_handle_reload_and_force_replacement_changes_shared_secret() {
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
    let handle = PersistentHandle::new(0x8101_0045).unwrap();
    let first_id = RegistryId::new("sim/api/persistent-ecdh-handle/first").unwrap();
    let second_id = RegistryId::new("sim/api/persistent-ecdh-handle/second").unwrap();

    api::keygen(
        &context,
        KeygenParams {
            usage: KeygenUsage::Ecdh,
            id: first_id.clone(),
            persist_at: Some(handle),
            overwrite: true,
        },
    )
    .unwrap();

    let software_secret = SecretKey::from_slice(&[0x24; 32]).unwrap();
    let peer_public_key = PublicKeyInput::Sec1(
        software_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
    );

    let by_id = api::ecdh(
        &context,
        EcdhParams {
            material: ObjectSelector::Id(first_id.clone()),
            peer_public_key: peer_public_key.clone(),
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap();

    let reloaded_context = ApiContext {
        store: StoreOptions {
            root: Some(temp_store.path().to_path_buf()),
        },
        tcti: None,
    };
    let handle_public_sec1 = api::pubkey(
        &reloaded_context,
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let handle_public = PublicKey::from_sec1_bytes(&handle_public_sec1).unwrap();

    let by_handle = api::ecdh(
        &reloaded_context,
        EcdhParams {
            material: ObjectSelector::Handle(handle),
            peer_public_key: peer_public_key.clone(),
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap();
    assert_eq!(by_id, by_handle);

    let expected = diffie_hellman(
        software_secret.to_nonzero_scalar(),
        handle_public.as_affine(),
    );
    let expected_bytes: &[u8; 32] = expected.raw_secret_bytes().as_ref();
    assert_eq!(by_handle.as_slice(), expected_bytes.as_slice());

    api::keygen(
        &reloaded_context,
        KeygenParams {
            usage: KeygenUsage::Ecdh,
            id: second_id,
            persist_at: Some(handle),
            overwrite: true,
        },
    )
    .unwrap();

    let replaced_public_sec1 = api::pubkey(
        &reloaded_context,
        PubkeyParams {
            material: ObjectSelector::Handle(handle),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    assert_ne!(handle_public_sec1, replaced_public_sec1);

    let replaced_by_handle = api::ecdh(
        &reloaded_context,
        EcdhParams {
            material: ObjectSelector::Handle(handle),
            peer_public_key,
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap();
    assert_ne!(by_handle, replaced_by_handle);

    let original_by_id = api::ecdh(
        &reloaded_context,
        EcdhParams {
            material: ObjectSelector::Id(first_id),
            peer_public_key: PublicKeyInput::Sec1(
                software_secret
                    .public_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
            ),
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap();
    assert_eq!(original_by_id, replaced_by_handle);
    assert_ne!(original_by_id, by_handle);

    cleanup_persistent_handle(handle);
}

#[test]
fn simulator_ecdh_shared_secret_matches_software_p256_agreement() {
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
    let ecdh_id = RegistryId::new("sim/api/ecdh-software-p256").unwrap();

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

    let tpm_public_sec1 = api::pubkey(
        &context,
        PubkeyParams {
            material: ObjectSelector::Id(ecdh_id.clone()),
            output_format: PublicKeyFormat::Raw,
        },
    )
    .unwrap();
    let tpm_public = PublicKey::from_sec1_bytes(&tpm_public_sec1).unwrap();

    let software_secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
    let software_public_sec1 = software_secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    let tpm_shared_secret = api::ecdh(
        &context,
        EcdhParams {
            material: ObjectSelector::Id(ecdh_id),
            peer_public_key: PublicKeyInput::Sec1(software_public_sec1),
            output_format: BinaryFormat::Raw,
        },
    )
    .unwrap();

    let software_shared_secret =
        diffie_hellman(software_secret.to_nonzero_scalar(), tpm_public.as_affine());
    let expected_shared_secret: &[u8] = software_shared_secret.raw_secret_bytes().as_ref();
    assert_eq!(tpm_shared_secret.as_slice(), expected_shared_secret);
}

#[test]
fn simulator_ecdh_rejects_invalid_peer_public_key_before_zgen() {
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
    let ecdh_id = RegistryId::new("sim/api/ecdh-invalid-peer").unwrap();

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

    let mut invalid_uncompressed_point = vec![0x04];
    invalid_uncompressed_point.extend_from_slice(&[0xff; 64]);
    let error = api::ecdh(
        &context,
        EcdhParams {
            material: ObjectSelector::Id(ecdh_id),
            peer_public_key: PublicKeyInput::Sec1(invalid_uncompressed_point),
            output_format: BinaryFormat::Raw,
        },
    )
    .expect_err("invalid SEC1 peer public key should be rejected");
    assert!(
        matches!(
            error,
            tpmctl_core::Error::InvalidInput {
                field: "public_key",
                ..
            }
        ),
        "expected invalid public_key error, got {error:?}"
    );
}

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

fn startup_and_get_random() {
    let mut context =
        tpmctl_core::tpm::create_context().expect("configured TCTI should open an ESAPI context");

    let random = match context.get_random(8) {
        Ok(random) => random,
        Err(first_error) => {
            context
                .startup(StartupType::Clear)
                .unwrap_or_else(|startup_error| {
                    panic!(
                        "TPM get_random failed ({first_error}); startup also failed ({startup_error})"
                    )
                });
            context
                .get_random(8)
                .expect("TPM get_random should succeed after startup")
        }
    };

    assert_eq!(random.value().len(), 8);
}

fn cleanup_persistent_handle(handle: PersistentHandle) {
    let mut context =
        tpmctl_core::tpm::create_context().expect("configured TCTI should open an ESAPI context");
    if let Ok(object) = tpmctl_core::tpm::load_persistent_object(&mut context, handle) {
        tpmctl_core::tpm::evict_persistent_object(&mut context, object, handle)
            .expect("cleanup should evict persistent handle");
    }
}

struct SimulatorTcti {
    _child: Option<Child>,
    _state_dir: Option<tempfile::TempDir>,
    previous_tcti_env: Vec<(&'static str, Option<String>)>,
    restore_tcti_env: bool,
}

fn require_simulator_tcti() -> SimulatorTcti {
    SimulatorTcti::activate().unwrap_or_else(|message| panic!("{message}"))
}

impl SimulatorTcti {
    fn activate() -> Result<Self, String> {
        if allow_external_tcti() {
            existing_tcti().ok_or_else(|| {
                "TPMCTL_TEST_EXTERNAL_TCTI=1 requires TEST_TCTI, TCTI, or TPM2TOOLS_TCTI to be set to a non-empty TCTI string".to_string()
            })?;
            return Ok(Self {
                _child: None,
                _state_dir: None,
                previous_tcti_env: Vec::new(),
                restore_tcti_env: false,
            });
        }

        let swtpm = find_on_path("swtpm").ok_or_else(|| {
            let configured = existing_tcti().map(|value| format!(" Found existing TCTI={value:?}, but external mode is disabled; set TPMCTL_TEST_EXTERNAL_TCTI=1 to use it." )).unwrap_or_default();
            format!(
                "simulator tests require swtpm on PATH by default. Install swtpm or set TPMCTL_TEST_EXTERNAL_TCTI=1 with TEST_TCTI, TCTI, or TPM2TOOLS_TCTI configured.{configured}"
            )
        })?;
        let state_dir = tempfile::tempdir().expect("create swtpm state directory");
        let (server_port, ctrl_port) = free_adjacent_local_ports();

        let mut child = Command::new(swtpm)
            .args([
                "socket",
                "--tpm2",
                "--tpmstate",
                &format!("dir={}", state_dir.path().display()),
                "--server",
                &format!("type=tcp,bindaddr=127.0.0.1,port={server_port}"),
                "--ctrl",
                &format!("type=tcp,bindaddr=127.0.0.1,port={ctrl_port}"),
                "--flags",
                "not-need-init",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("failed to start swtpm simulator: {error}"))?;

        wait_for_tcp_port(SocketAddr::from(([127, 0, 0, 1], server_port)), &mut child)
            .map_err(|error| format!("failed to initialize swtpm simulator: {error}"))?;

        let tcti = format!("swtpm:host=127.0.0.1,port={server_port}");
        let previous_tcti_env = capture_tcti_env();
        unsafe {
            for name in TCTI_ENV_PRECEDENCE {
                env::remove_var(name);
            }
            env::set_var("TEST_TCTI", tcti);
        }

        Ok(Self {
            _child: Some(child),
            _state_dir: Some(state_dir),
            previous_tcti_env,
            restore_tcti_env: true,
        })
    }
}

impl Drop for SimulatorTcti {
    fn drop(&mut self) {
        if self.restore_tcti_env {
            unsafe {
                for (name, previous) in &self.previous_tcti_env {
                    if let Some(previous) = previous {
                        env::set_var(name, previous);
                    } else {
                        env::remove_var(name);
                    }
                }
            }
        }

        if let Some(child) = &mut self._child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn allow_external_tcti() -> bool {
    env::var("TPMCTL_TEST_EXTERNAL_TCTI")
        .map(|value| value == "1")
        .unwrap_or(false)
}

fn existing_tcti() -> Option<String> {
    TCTI_ENV_PRECEDENCE
        .iter()
        .find_map(|name| env::var(name).ok().filter(|value| !value.trim().is_empty()))
}

fn capture_tcti_env() -> Vec<(&'static str, Option<String>)> {
    TCTI_ENV_PRECEDENCE
        .iter()
        .map(|name| (*name, env::var(name).ok()))
        .collect()
}

fn find_on_path(binary: &str) -> Option<std::path::PathBuf> {
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|dir| dir.join(binary))
            .find(|candidate| candidate.is_file())
    })
}

fn free_adjacent_local_ports() -> (u16, u16) {
    for _ in 0..100 {
        let first = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral local TCP port");
        let server_port = first.local_addr().expect("read local TCP port").port();
        let Some(ctrl_port) = server_port.checked_add(1) else {
            continue;
        };
        if TcpListener::bind(("127.0.0.1", ctrl_port)).is_ok() {
            drop(first);
            return (server_port, ctrl_port);
        }
    }
    panic!("failed to find adjacent free local TCP ports for swtpm");
}

fn wait_for_tcp_port(addr: SocketAddr, child: &mut Child) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            return Ok(());
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("failed to poll swtpm child process: {error}"))?
        {
            let stderr = read_child_stderr(child);
            return Err(format!(
                "swtpm exited before accepting connections: {status}; stderr:\n{stderr}"
            ));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let stderr = read_child_stderr(child);
            return Err(format!(
                "timed out waiting for swtpm at {addr}; stderr:\n{stderr}"
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn read_child_stderr(child: &mut Child) -> String {
    let Some(mut stderr) = child.stderr.take() else {
        return "<stderr unavailable>".to_string();
    };
    let mut output = String::new();
    match stderr.read_to_string(&mut output) {
        Ok(_) if output.trim().is_empty() => "<empty>".to_string(),
        Ok(_) => output,
        Err(error) => format!("<failed to read stderr: {error}>"),
    }
}
