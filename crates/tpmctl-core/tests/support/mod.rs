#![allow(dead_code, unused_imports)]

pub(crate) use std::{
    env,
    io::Read,
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};

pub(crate) use ed25519_dalek::{
    Signature as Ed25519Signature, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
pub(crate) use k256::ecdsa::{
    Signature as Secp256k1Signature, SigningKey as Secp256k1SigningKey,
    VerifyingKey as Secp256k1VerifyingKey,
};
pub(crate) use p256::{
    PublicKey, SecretKey,
    ecdh::diffie_hellman,
    ecdsa::{
        Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey,
        signature::{
            Signer, Verifier,
            hazmat::{PrehashSigner, PrehashVerifier},
        },
    },
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding},
};
pub(crate) use sha2::{Digest, Sha256, Sha384, Sha512};
pub(crate) use sha3::Keccak256;
pub(crate) use tss_esapi::constants::StartupType;
pub(crate) use zeroize::Zeroizing;

pub(crate) use tpmctl_core::{
    CommandContext, DeriveAlgorithm, DeriveFormat, DeriveUse, HashAlgorithm, ObjectSelector,
    PersistentHandle, RegistryId, SealTarget, Store, StoreOptions,
    api::{
        self, Context as ApiContext, EcdhParams, HmacParams, KeygenParams, PubkeyParams,
        SealParams, SignParams, SignPayload, UnsealParams,
    },
    derive::{self, DeriveParams, SignPayload as DeriveSignPayload},
    ecdh::EcdhRequest,
    hmac::{HmacRequest, HmacResult},
    keygen::{KeygenRequest, KeygenUsage},
    output::{BinaryFormat, PublicKeyFormat, SignatureFormat},
    pubkey::{PubkeyRequest, PublicKeyInput},
    seal::UnsealRequest,
    sign::{SignInput, SignRequest},
};

const TCTI_ENV_PRECEDENCE: [&str; 3] = ["TPM2TOOLS_TCTI", "TCTI", "TEST_TCTI"];

pub(crate) fn simulator_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct P256DeriveSnapshot {
    pub(crate) secret: Vec<u8>,
    pub(crate) public: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct Secp256k1DeriveSnapshot {
    pub(crate) secret: Vec<u8>,
    pub(crate) public: Vec<u8>,
    pub(crate) compressed_public: Vec<u8>,
    pub(crate) address: String,
    pub(crate) signature: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct Ed25519DeriveSnapshot {
    pub(crate) secret: Vec<u8>,
    pub(crate) public: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct DeriveWorkflowSnapshots {
    pub(crate) p256: P256DeriveSnapshot,
    pub(crate) secp256k1: Secp256k1DeriveSnapshot,
    pub(crate) ed25519: Ed25519DeriveSnapshot,
}

pub(crate) fn derive_workflow_snapshots(
    context: &ApiContext,
    material: ObjectSelector,
    scope: &str,
) -> DeriveWorkflowSnapshots {
    let p256_message = format!("{scope}/message/p256").into_bytes();
    let secp256k1_message = format!("{scope}/message/secp256k1").into_bytes();
    let ed25519_message = format!("{scope}/message/ed25519").into_bytes();

    DeriveWorkflowSnapshots {
        p256: derive_p256_snapshot(
            context,
            material.clone(),
            format!("{scope}/label/p256").into_bytes(),
            &p256_message,
        ),
        secp256k1: derive_secp256k1_snapshot(
            context,
            material.clone(),
            format!("{scope}/label/secp256k1").into_bytes(),
            &secp256k1_message,
        ),
        ed25519: derive_ed25519_snapshot(
            context,
            material,
            format!("{scope}/label/ed25519").into_bytes(),
            &ed25519_message,
        ),
    }
}

pub(crate) fn derive_p256_snapshot(
    context: &ApiContext,
    material: ObjectSelector,
    label: Vec<u8>,
    message: &[u8],
) -> P256DeriveSnapshot {
    let secret_params = DeriveParams {
        material: material.clone(),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::P256,
        usage: DeriveUse::Secret,
        payload: None,
        hash: None,
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let secret = derive::derive(context, secret_params.clone()).unwrap();
    let repeated_secret = derive::derive(context, secret_params).unwrap();
    assert_eq!(secret, repeated_secret);
    assert_eq!(secret.len(), 32);

    let software_secret = SecretKey::from_slice(secret.as_slice()).unwrap();
    let expected_public = software_secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    let pubkey_params = DeriveParams {
        material: material.clone(),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::P256,
        usage: DeriveUse::Pubkey,
        payload: None,
        hash: None,
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let public = derive::derive(context, pubkey_params.clone()).unwrap();
    let repeated_public = derive::derive(context, pubkey_params).unwrap();
    assert_eq!(public, repeated_public);
    assert_eq!(public.as_slice(), expected_public.as_slice());

    let digest = Zeroizing::new(Sha256::digest(message).to_vec());
    let sign_message_params = DeriveParams {
        material: material.clone(),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::P256,
        usage: DeriveUse::Sign,
        payload: Some(DeriveSignPayload::Message(Zeroizing::new(message.to_vec()))),
        hash: Some(HashAlgorithm::Sha256),
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let message_signature = derive::derive(context, sign_message_params.clone()).unwrap();
    let repeated_message_signature = derive::derive(context, sign_message_params).unwrap();
    assert_eq!(message_signature, repeated_message_signature);
    assert_eq!(message_signature.len(), 64);

    let digest_signature = derive::derive(
        context,
        DeriveParams {
            material,
            label: Some(label),
            algorithm: DeriveAlgorithm::P256,
            usage: DeriveUse::Sign,
            payload: Some(DeriveSignPayload::Digest(digest.clone())),
            hash: Some(HashAlgorithm::Sha256),
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(message_signature, digest_signature);

    let software_signature: P256Signature = P256SigningKey::from(software_secret)
        .sign_prehash(digest.as_slice())
        .unwrap();
    let software_signature_bytes = software_signature.to_bytes();
    assert_eq!(message_signature.as_slice(), &software_signature_bytes[..]);

    let verifying_key = VerifyingKey::from_sec1_bytes(public.as_slice()).unwrap();
    let signature = P256Signature::from_slice(message_signature.as_slice()).unwrap();
    verifying_key.verify(message, &signature).unwrap();

    P256DeriveSnapshot {
        secret: secret.to_vec(),
        public: public.to_vec(),
        signature: message_signature.to_vec(),
    }
}

pub(crate) fn derive_p256_workflow_and_assert_consistency(
    context: &ApiContext,
    material: ObjectSelector,
    label: Vec<u8>,
    message: &[u8],
) {
    let _ = derive_p256_snapshot(context, material, label, message);
}

pub(crate) fn checksum_address_from_uncompressed_secp256k1(public_key: &[u8]) -> String {
    let digest = Keccak256::digest(&public_key[1..]);
    let lower = hex::encode(&digest[12..]);
    let hash = Keccak256::digest(lower.as_bytes());

    let mut out = String::from("0x");
    for (index, ch) in lower.chars().enumerate() {
        let hash_byte = hash[index / 2];
        let nibble = if index % 2 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0x0f
        };
        if ch.is_ascii_alphabetic() && nibble >= 8 {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push(ch);
        }
    }
    out
}

pub(crate) fn derive_secp256k1_snapshot(
    context: &ApiContext,
    material: ObjectSelector,
    label: Vec<u8>,
    message: &[u8],
) -> Secp256k1DeriveSnapshot {
    let secret_params = DeriveParams {
        material: material.clone(),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::Secp256k1,
        usage: DeriveUse::Secret,
        payload: None,
        hash: None,
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let secret = derive::derive(context, secret_params.clone()).unwrap();
    let repeated_secret = derive::derive(context, secret_params).unwrap();
    assert_eq!(secret, repeated_secret);
    assert_eq!(secret.len(), 32);

    let software_secret = k256::SecretKey::from_slice(secret.as_slice()).unwrap();
    let expected_public = software_secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let expected_compressed_public = software_secret
        .public_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    let pubkey_params = DeriveParams {
        material: material.clone(),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::Secp256k1,
        usage: DeriveUse::Pubkey,
        payload: None,
        hash: None,
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let public = derive::derive(context, pubkey_params.clone()).unwrap();
    let repeated_public = derive::derive(context, pubkey_params).unwrap();
    assert_eq!(public, repeated_public);
    assert_eq!(public.as_slice(), expected_public.as_slice());

    let compressed_public = derive::derive(
        context,
        DeriveParams {
            material: material.clone(),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::Secp256k1,
            usage: DeriveUse::Pubkey,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Raw,
            compressed: true,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(
        compressed_public.as_slice(),
        expected_compressed_public.as_slice()
    );

    let address = derive::derive(
        context,
        DeriveParams {
            material: material.clone(),
            label: Some(label.clone()),
            algorithm: DeriveAlgorithm::Secp256k1,
            usage: DeriveUse::Pubkey,
            payload: None,
            hash: None,
            output_format: DeriveFormat::Address,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    let expected_address = checksum_address_from_uncompressed_secp256k1(expected_public.as_slice());
    assert_eq!(
        std::str::from_utf8(address.as_slice()).unwrap(),
        expected_address
    );

    let digest = Zeroizing::new(Sha256::digest(message).to_vec());
    let sign_message_params = DeriveParams {
        material: material.clone(),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::Secp256k1,
        usage: DeriveUse::Sign,
        payload: Some(DeriveSignPayload::Message(Zeroizing::new(message.to_vec()))),
        hash: Some(HashAlgorithm::Sha256),
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let message_signature = derive::derive(context, sign_message_params.clone()).unwrap();
    let repeated_message_signature = derive::derive(context, sign_message_params).unwrap();
    assert_eq!(message_signature, repeated_message_signature);
    assert_eq!(message_signature.len(), 64);

    let digest_signature = derive::derive(
        context,
        DeriveParams {
            material,
            label: Some(label),
            algorithm: DeriveAlgorithm::Secp256k1,
            usage: DeriveUse::Sign,
            payload: Some(DeriveSignPayload::Digest(digest.clone())),
            hash: Some(HashAlgorithm::Sha256),
            output_format: DeriveFormat::Raw,
            compressed: false,
            entropy: None,
        },
    )
    .unwrap();
    assert_eq!(message_signature, digest_signature);

    let software_signature: Secp256k1Signature = Secp256k1SigningKey::from(software_secret)
        .sign_prehash(digest.as_slice())
        .unwrap();
    let software_signature_bytes = software_signature.to_bytes();
    assert_eq!(message_signature.as_slice(), &software_signature_bytes[..]);

    let verifying_key = Secp256k1VerifyingKey::from_sec1_bytes(public.as_slice()).unwrap();
    let signature = Secp256k1Signature::from_slice(message_signature.as_slice()).unwrap();
    verifying_key
        .verify_prehash(digest.as_slice(), &signature)
        .unwrap();

    Secp256k1DeriveSnapshot {
        secret: secret.to_vec(),
        public: public.to_vec(),
        compressed_public: compressed_public.to_vec(),
        address: std::str::from_utf8(address.as_slice()).unwrap().to_owned(),
        signature: message_signature.to_vec(),
    }
}

pub(crate) fn derive_secp256k1_workflow_and_assert_consistency(
    context: &ApiContext,
    material: ObjectSelector,
    label: Vec<u8>,
    message: &[u8],
) {
    let _ = derive_secp256k1_snapshot(context, material, label, message);
}

pub(crate) fn derive_ed25519_snapshot(
    context: &ApiContext,
    material: ObjectSelector,
    label: Vec<u8>,
    message: &[u8],
) -> Ed25519DeriveSnapshot {
    let secret_params = DeriveParams {
        material: material.clone(),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::Ed25519,
        usage: DeriveUse::Secret,
        payload: None,
        hash: None,
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let secret = derive::derive(context, secret_params.clone()).unwrap();
    let repeated_secret = derive::derive(context, secret_params).unwrap();
    assert_eq!(secret, repeated_secret);
    assert_eq!(secret.len(), 32);

    let secret_bytes: [u8; 32] = secret.as_slice().try_into().unwrap();
    let software_secret = Ed25519SigningKey::from_bytes(&secret_bytes);
    let expected_public = software_secret.verifying_key().to_bytes();

    let pubkey_params = DeriveParams {
        material: material.clone(),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::Ed25519,
        usage: DeriveUse::Pubkey,
        payload: None,
        hash: None,
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let public = derive::derive(context, pubkey_params.clone()).unwrap();
    let repeated_public = derive::derive(context, pubkey_params).unwrap();
    assert_eq!(public, repeated_public);
    assert_eq!(public.as_slice(), &expected_public);

    let sign_message_params = DeriveParams {
        material: material.clone(),
        label: Some(label.clone()),
        algorithm: DeriveAlgorithm::Ed25519,
        usage: DeriveUse::Sign,
        payload: Some(DeriveSignPayload::Message(Zeroizing::new(message.to_vec()))),
        hash: None,
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    };
    let message_signature = derive::derive(context, sign_message_params.clone()).unwrap();
    let repeated_message_signature = derive::derive(context, sign_message_params).unwrap();
    assert_eq!(message_signature, repeated_message_signature);
    assert_eq!(message_signature.len(), 64);

    let software_signature = software_secret.sign(message);
    assert_eq!(
        message_signature.as_slice(),
        &software_signature.to_bytes()[..]
    );

    let verifying_key = Ed25519VerifyingKey::from_bytes(&expected_public).unwrap();
    let signature = Ed25519Signature::try_from(message_signature.as_slice()).unwrap();
    verifying_key.verify(message, &signature).unwrap();

    Ed25519DeriveSnapshot {
        secret: secret.to_vec(),
        public: public.to_vec(),
        signature: message_signature.to_vec(),
    }
}

pub(crate) fn derive_ed25519_workflow_and_assert_consistency(
    context: &ApiContext,
    material: ObjectSelector,
    label: Vec<u8>,
    message: &[u8],
) {
    let _ = derive_ed25519_snapshot(context, material, label, message);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn derive_output(
    context: &ApiContext,
    material: ObjectSelector,
    label: Option<Vec<u8>>,
    algorithm: DeriveAlgorithm,
    usage: DeriveUse,
    payload: Option<DeriveSignPayload>,
    hash: Option<HashAlgorithm>,
    output_format: DeriveFormat,
    compressed: bool,
) -> Zeroizing<Vec<u8>> {
    derive::derive(
        context,
        DeriveParams {
            material,
            label,
            algorithm,
            usage,
            payload,
            hash,
            output_format,
            compressed,
            entropy: None,
        },
    )
    .unwrap()
}

pub(crate) fn decode_derive_p256_signature(bytes: &[u8], format: DeriveFormat) -> P256Signature {
    match format {
        DeriveFormat::Raw => P256Signature::from_slice(bytes).unwrap(),
        DeriveFormat::Hex => {
            let decoded = hex::decode(bytes).unwrap();
            P256Signature::from_slice(&decoded).unwrap()
        }
        DeriveFormat::Der => P256Signature::from_der(bytes).unwrap(),
        DeriveFormat::Address => panic!("address is not a valid p256 signature format"),
    }
}

pub(crate) fn decode_derive_secp256k1_signature(
    bytes: &[u8],
    format: DeriveFormat,
) -> Secp256k1Signature {
    match format {
        DeriveFormat::Raw => Secp256k1Signature::from_slice(bytes).unwrap(),
        DeriveFormat::Hex => {
            let decoded = hex::decode(bytes).unwrap();
            Secp256k1Signature::from_slice(&decoded).unwrap()
        }
        DeriveFormat::Der => Secp256k1Signature::from_der(bytes).unwrap(),
        DeriveFormat::Address => panic!("address is not a valid secp256k1 signature format"),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn assert_p256_derive_sign_case(
    context: &ApiContext,
    material: ObjectSelector,
    label: &[u8],
    software_secret: &SecretKey,
    verifying_key: &VerifyingKey,
    message: &[u8],
    hash: Option<HashAlgorithm>,
    output_format: DeriveFormat,
) {
    let message_signature = derive_output(
        context,
        material.clone(),
        Some(label.to_vec()),
        DeriveAlgorithm::P256,
        DeriveUse::Sign,
        Some(DeriveSignPayload::Message(Zeroizing::new(message.to_vec()))),
        hash,
        output_format,
        false,
    );
    let effective_hash = hash.unwrap_or(HashAlgorithm::Sha256);
    let digest = Zeroizing::new(effective_hash.digest(message));
    let digest_signature = derive_output(
        context,
        material,
        Some(label.to_vec()),
        DeriveAlgorithm::P256,
        DeriveUse::Sign,
        Some(DeriveSignPayload::Digest(digest.clone())),
        hash,
        DeriveFormat::Raw,
        false,
    );

    let message_signature =
        decode_derive_p256_signature(message_signature.as_slice(), output_format);
    let digest_signature = P256Signature::from_slice(digest_signature.as_slice()).unwrap();
    assert_eq!(message_signature, digest_signature);

    let software_signature: P256Signature = P256SigningKey::from(software_secret.clone())
        .sign_prehash(digest.as_slice())
        .unwrap();
    assert_eq!(message_signature, software_signature);
    verifying_key
        .verify_prehash(digest.as_slice(), &message_signature)
        .unwrap();
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn assert_secp256k1_derive_sign_case(
    context: &ApiContext,
    material: ObjectSelector,
    label: &[u8],
    software_secret: &k256::SecretKey,
    verifying_key: &Secp256k1VerifyingKey,
    message: &[u8],
    hash: Option<HashAlgorithm>,
    output_format: DeriveFormat,
) {
    let message_signature = derive_output(
        context,
        material.clone(),
        Some(label.to_vec()),
        DeriveAlgorithm::Secp256k1,
        DeriveUse::Sign,
        Some(DeriveSignPayload::Message(Zeroizing::new(message.to_vec()))),
        hash,
        output_format,
        false,
    );
    let effective_hash = hash.unwrap_or(HashAlgorithm::Sha256);
    let digest = Zeroizing::new(effective_hash.digest(message));
    let digest_signature = derive_output(
        context,
        material,
        Some(label.to_vec()),
        DeriveAlgorithm::Secp256k1,
        DeriveUse::Sign,
        Some(DeriveSignPayload::Digest(digest.clone())),
        hash,
        DeriveFormat::Raw,
        false,
    );

    let message_signature =
        decode_derive_secp256k1_signature(message_signature.as_slice(), output_format);
    let digest_signature = Secp256k1Signature::from_slice(digest_signature.as_slice()).unwrap();
    assert_eq!(message_signature, digest_signature);

    let software_signature: Secp256k1Signature = Secp256k1SigningKey::from(software_secret.clone())
        .sign_prehash(digest.as_slice())
        .unwrap();
    assert_eq!(message_signature, software_signature);
    verifying_key
        .verify_prehash(digest.as_slice(), &message_signature)
        .unwrap();
}

pub(crate) fn simulator_command_context(root: &Path) -> CommandContext {
    CommandContext {
        store: StoreOptions {
            root: Some(root.to_path_buf()),
        },
        tcti: None,
    }
}

pub(crate) fn decode_p256_signature(bytes: &[u8], format: SignatureFormat) -> P256Signature {
    match format {
        SignatureFormat::Raw => P256Signature::from_slice(bytes).unwrap(),
        SignatureFormat::Hex => {
            let decoded = hex::decode(bytes).unwrap();
            P256Signature::from_slice(&decoded).unwrap()
        }
        SignatureFormat::Der => P256Signature::from_der(bytes).unwrap(),
    }
}

pub(crate) fn expect_hmac_output(result: HmacResult) -> Zeroizing<Vec<u8>> {
    match result {
        HmacResult::Output(output) => output,
        other => panic!("expected raw or hex HMAC output, got {other:?}"),
    }
}

pub(crate) fn startup_and_get_random() {
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

fn startup_fresh_simulator() -> Result<(), String> {
    let mut context = tpmctl_core::tpm::create_context()
        .map_err(|error| format!("configured TCTI should open an ESAPI context: {error}"))?;
    context
        .startup(StartupType::Clear)
        .map_err(|error| format!("failed to start fresh swtpm simulator: {error}"))?;
    Ok(())
}

pub(crate) fn cleanup_persistent_handle(handle: PersistentHandle) {
    if !allow_external_tcti() {
        return;
    }

    let mut context =
        tpmctl_core::tpm::create_context().expect("configured TCTI should open an ESAPI context");
    if let Ok(object) = tpmctl_core::tpm::load_persistent_object(&mut context, handle) {
        tpmctl_core::tpm::evict_persistent_object(&mut context, object, handle)
            .expect("cleanup should evict persistent handle");
    }
}

pub(crate) fn initial_persistent_overwrite() -> bool {
    allow_external_tcti()
}

pub(crate) fn initial_persistent_force() -> bool {
    allow_external_tcti()
}

pub(crate) struct SimulatorTcti {
    _child: Option<Child>,
    _state_dir: Option<tempfile::TempDir>,
    previous_tcti_env: Vec<(&'static str, Option<String>)>,
    previous_tss2_log: Option<String>,
    restore_tcti_env: bool,
}

pub(crate) fn require_simulator_tcti() -> SimulatorTcti {
    SimulatorTcti::activate().unwrap_or_else(|message| panic!("{message}"))
}

impl SimulatorTcti {
    fn activate() -> Result<Self, String> {
        if allow_external_tcti() {
            existing_tcti().ok_or_else(|| {
                "TPMCTL_TEST_EXTERNAL_TCTI=1 requires TEST_TCTI, TCTI, or TPM2TOOLS_TCTI to be set to a non-empty TCTI string".to_string()
            })?;
            let previous_tss2_log = env::var("TSS2_LOG").ok();
            unsafe {
                env::set_var("TSS2_LOG", "all+NONE");
            }
            return Ok(Self {
                _child: None,
                _state_dir: None,
                previous_tcti_env: Vec::new(),
                previous_tss2_log,
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
        let previous_tss2_log = env::var("TSS2_LOG").ok();
        unsafe {
            for name in TCTI_ENV_PRECEDENCE {
                env::remove_var(name);
            }
            env::set_var("TEST_TCTI", tcti);
            env::set_var("TSS2_LOG", "all+NONE");
        }

        startup_fresh_simulator()?;

        Ok(Self {
            _child: Some(child),
            _state_dir: Some(state_dir),
            previous_tcti_env,
            previous_tss2_log,
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

        unsafe {
            if let Some(previous) = &self.previous_tss2_log {
                env::set_var("TSS2_LOG", previous);
            } else {
                env::remove_var("TSS2_LOG");
            }
        }

        if let Some(child) = &mut self._child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub(crate) fn allow_external_tcti() -> bool {
    env::var("TPMCTL_TEST_EXTERNAL_TCTI")
        .map(|value| value == "1")
        .unwrap_or(false)
}

pub(crate) fn existing_tcti() -> Option<String> {
    TCTI_ENV_PRECEDENCE
        .iter()
        .find_map(|name| env::var(name).ok().filter(|value| !value.trim().is_empty()))
}

pub(crate) fn capture_tcti_env() -> Vec<(&'static str, Option<String>)> {
    TCTI_ENV_PRECEDENCE
        .iter()
        .map(|name| (*name, env::var(name).ok()))
        .collect()
}

pub(crate) fn find_on_path(binary: &str) -> Option<std::path::PathBuf> {
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|dir| dir.join(binary))
            .find(|candidate| candidate.is_file())
    })
}

pub(crate) fn free_adjacent_local_ports() -> (u16, u16) {
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

pub(crate) fn wait_for_tcp_port(addr: SocketAddr, child: &mut Child) -> Result<(), String> {
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

pub(crate) fn read_child_stderr(child: &mut Child) -> String {
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
