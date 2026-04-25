use std::fmt;

use zeroize::Zeroizing;

use crate::{
    CommandContext, HashAlgorithm, ObjectSelector, RegistryId, Result, SealTarget, Store,
    StoreOptions,
    ecdh::EcdhRequest,
    hmac::{HmacRequest, HmacResult},
    keygen::{self, KeygenResult, KeygenUsage},
    output::{BinaryFormat, PublicKeyFormat, SignatureFormat},
    pubkey::{self as pubkey_api, PublicKeyInput},
    seal::{SealRequest, SealResult, UnsealRequest},
    sign::{SignInput, SignRequest},
    tpm,
};

pub mod derive {
    use std::fmt;

    use zeroize::Zeroizing;

    use crate::{HashAlgorithm, ObjectSelector, Result, crypto::derive::DerivedAlgorithm};

    use super::Context;

    pub use crate::DeriveFormat;
    pub use crate::crypto::derive::{DeriveUse, HashSelection};

    #[derive(Clone, Eq, PartialEq)]
    pub enum SignPayload {
        Message(Zeroizing<Vec<u8>>),
        Digest(Zeroizing<Vec<u8>>),
    }

    impl fmt::Debug for SignPayload {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Message(_) => formatter
                    .debug_tuple("Message")
                    .field(&"<redacted>")
                    .finish(),
                Self::Digest(_) => formatter
                    .debug_tuple("Digest")
                    .field(&"<redacted>")
                    .finish(),
            }
        }
    }

    #[derive(Clone, Eq, PartialEq)]
    pub struct DeriveParams {
        pub material: ObjectSelector,
        pub label: Option<Vec<u8>>,
        pub algorithm: DerivedAlgorithm,
        pub usage: DeriveUse,
        pub payload: Option<SignPayload>,
        pub hash: Option<HashAlgorithm>,
        pub output_format: DeriveFormat,
        pub compressed: bool,
        pub entropy: Option<Zeroizing<Vec<u8>>>,
    }

    impl fmt::Debug for DeriveParams {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("DeriveParams")
                .field("material", &self.material)
                .field("label", &self.label.as_ref().map(|_| "<redacted>"))
                .field("algorithm", &self.algorithm)
                .field("usage", &self.usage)
                .field("payload", &self.payload)
                .field("hash", &self.hash)
                .field("output_format", &self.output_format)
                .field("compressed", &self.compressed)
                .field("entropy", &self.entropy.as_ref().map(|_| "<redacted>"))
                .finish()
        }
    }

    pub fn derive(context: &Context, params: DeriveParams) -> Result<Zeroizing<Vec<u8>>> {
        crate::derive_domain::derive(&context.command(), params)
    }

    impl DeriveParams {
        pub fn validate(&self) -> Result<()> {
            crate::derive_domain::validate_params(self)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::RegistryId;

        fn params(
            algorithm: DerivedAlgorithm,
            usage: DeriveUse,
            output_format: DeriveFormat,
        ) -> DeriveParams {
            DeriveParams {
                material: ObjectSelector::Id(RegistryId::new("material").unwrap()),
                label: Some(b"label".to_vec()),
                algorithm,
                usage,
                payload: None,
                hash: None,
                output_format,
                compressed: false,
                entropy: None,
            }
        }

        #[test]
        fn validate_rejects_ed25519_digest_payload() {
            let mut params = params(
                DerivedAlgorithm::Ed25519,
                DeriveUse::Sign,
                DeriveFormat::Raw,
            );
            params.payload = Some(SignPayload::Digest(Zeroizing::new(vec![0_u8; 32])));
            assert!(params.validate().is_err());
        }

        #[test]
        fn validate_rejects_entropy_when_label_present() {
            let mut params = params(DerivedAlgorithm::P256, DeriveUse::Secret, DeriveFormat::Raw);
            params.entropy = Some(Zeroizing::new(vec![1_u8; 32]));
            assert!(params.validate().is_err());
        }

        #[test]
        fn validate_rejects_pubkey_formats_matching_root_rules() {
            let mut p256 = params(DerivedAlgorithm::P256, DeriveUse::Pubkey, DeriveFormat::Der);
            assert!(p256.validate().is_err());
            p256.algorithm = DerivedAlgorithm::Ed25519;
            assert!(p256.validate().is_err());
            let secp_der = params(
                DerivedAlgorithm::Secp256k1,
                DeriveUse::Pubkey,
                DeriveFormat::Der,
            );
            assert!(secp_der.validate().is_err());
        }

        #[test]
        fn validate_rejects_sign_formats_matching_root_rules() {
            let mut ed = params(
                DerivedAlgorithm::Ed25519,
                DeriveUse::Sign,
                DeriveFormat::Der,
            );
            ed.payload = Some(SignPayload::Message(Zeroizing::new(b"message".to_vec())));
            assert!(ed.validate().is_err());
            let mut p256 = params(
                DerivedAlgorithm::P256,
                DeriveUse::Sign,
                DeriveFormat::Address,
            );
            p256.payload = Some(SignPayload::Message(Zeroizing::new(b"message".to_vec())));
            assert!(p256.validate().is_err());
        }
    }
}
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct Context {
    pub store: StoreOptions,
    pub tcti: Option<String>,
}

impl Context {
    pub fn command(&self) -> CommandContext {
        CommandContext {
            store: self.store.clone(),
            tcti: self.tcti.clone(),
        }
    }

    pub fn store(&self) -> Result<Store> {
        Store::resolve(self.store.root.as_deref())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeygenParams {
    pub usage: KeygenUsage,
    pub id: RegistryId,
    pub persist_at: Option<tpm::PersistentHandle>,
    pub overwrite: bool,
}

impl KeygenParams {
    pub fn validate(&self) -> Result<()> {
        if self.id.as_str().starts_with("0x") {
            return Err(crate::Error::invalid(
                "id",
                "registry ids beginning with 0x are reserved for TPM handle literals",
            ));
        }
        Ok(())
    }
}

pub fn keygen(context: &Context, params: KeygenParams) -> Result<KeygenResult> {
    params.validate()?;
    keygen::KeygenRequest {
        usage: params.usage,
        id: params.id,
        persist_at: params.persist_at,
        force: params.overwrite,
    }
    .execute_with_context(&context.command())
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PubkeyParams {
    pub material: ObjectSelector,
    pub output_format: PublicKeyFormat,
}

pub fn pubkey(context: &Context, params: PubkeyParams) -> Result<Vec<u8>> {
    pubkey_api::PubkeyRequest {
        selector: params.material,
        output_format: params.output_format,
    }
    .execute_with_context(&context.command())
}

#[derive(Clone, Eq, PartialEq)]
pub struct EcdhParams {
    pub material: ObjectSelector,
    pub peer_public_key: PublicKeyInput,
    pub output_format: BinaryFormat,
}

impl fmt::Debug for EcdhParams {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EcdhParams")
            .field("material", &self.material)
            .field("peer_public_key", &"<redacted>")
            .field("output_format", &self.output_format)
            .finish()
    }
}

pub fn ecdh(context: &Context, params: EcdhParams) -> Result<Zeroizing<Vec<u8>>> {
    EcdhRequest {
        selector: params.material,
        peer_public_key: params.peer_public_key,
        output_format: params.output_format,
    }
    .execute_with_context(&context.command())
}

/// Byte payload for [`sign`].
///
/// `Message` signs arbitrary bytes after hashing them with `SignParams::hash`.
/// `Digest` signs a caller-supplied prehash and validates its length against
/// `SignParams::hash`.
#[derive(Clone, Eq, PartialEq)]
pub enum SignPayload {
    Message(Zeroizing<Vec<u8>>),
    Digest(Zeroizing<Vec<u8>>),
}

/// Parameters for [`sign`], the ergonomic public API around TPM P-256 signing.
#[derive(Clone, Eq, PartialEq)]
pub struct SignParams {
    pub material: ObjectSelector,
    pub payload: SignPayload,
    pub hash: HashAlgorithm,
    pub output_format: SignatureFormat,
}

impl fmt::Debug for SignPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(_) => formatter
                .debug_tuple("Message")
                .field(&"<redacted>")
                .finish(),
            Self::Digest(_) => formatter
                .debug_tuple("Digest")
                .field(&"<redacted>")
                .finish(),
        }
    }
}

impl fmt::Debug for SignParams {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignParams")
            .field("material", &self.material)
            .field("payload", &self.payload)
            .field("hash", &self.hash)
            .field("output_format", &self.output_format)
            .finish()
    }
}

pub fn sign(context: &Context, params: SignParams) -> Result<Vec<u8>> {
    let input = match params.payload {
        SignPayload::Message(message) => SignInput::Message(message),
        SignPayload::Digest(digest) => SignInput::Digest(digest),
    };
    SignRequest {
        selector: params.material,
        input,
        hash: params.hash,
        output_format: params.output_format,
    }
    .execute_with_context(&context.command())
}

#[derive(Clone, Eq, PartialEq)]
pub struct HmacParams {
    pub material: ObjectSelector,
    pub input: Zeroizing<Vec<u8>>,
    pub hash: Option<HashAlgorithm>,
    pub output_format: BinaryFormat,
    pub seal_target: Option<SealTarget>,
    pub emit_prf_when_sealing: bool,
    pub overwrite: bool,
}

impl fmt::Debug for HmacParams {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HmacParams")
            .field("material", &self.material)
            .field("input", &"<redacted>")
            .field("hash", &self.hash)
            .field("output_format", &self.output_format)
            .field("seal_target", &self.seal_target)
            .field("emit_prf_when_sealing", &self.emit_prf_when_sealing)
            .field("overwrite", &self.overwrite)
            .finish()
    }
}

pub fn hmac(context: &Context, params: HmacParams) -> Result<HmacResult> {
    HmacRequest {
        selector: params.material,
        input: params.input,
        hash: params.hash,
        output_format: params.output_format,
        seal_target: params.seal_target,
        emit_prf_when_sealing: params.emit_prf_when_sealing,
        force: params.overwrite,
    }
    .execute_with_context(&context.command())
}

#[derive(Clone, Eq, PartialEq)]
pub struct SealParams {
    pub target: ObjectSelector,
    pub input: Zeroizing<Vec<u8>>,
    pub overwrite: bool,
}

impl fmt::Debug for SealParams {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealParams")
            .field("target", &self.target)
            .field("input", &"<redacted>")
            .field("overwrite", &self.overwrite)
            .finish()
    }
}

pub fn seal(context: &Context, params: SealParams) -> Result<SealResult> {
    SealRequest {
        selector: params.target,
        input: params.input,
        force: params.overwrite,
    }
    .execute_with_context(&context.command())
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnsealParams {
    pub material: ObjectSelector,
}

pub fn unseal(context: &Context, params: UnsealParams) -> Result<Zeroizing<Vec<u8>>> {
    UnsealRequest {
        selector: params.material,
        force_binary_stdout: true,
    }
    .execute_with_context(&context.command())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyUsage;

    #[test]
    fn keygen_params_reserve_handle_literal_namespace() {
        let params = KeygenParams {
            usage: KeygenUsage::Sign,
            id: RegistryId::new("0x81010010").unwrap(),
            persist_at: None,
            overwrite: false,
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn sign_payload_keeps_digest_in_zeroizing_storage() {
        let payload = SignPayload::Digest(Zeroizing::new(vec![0_u8; 32]));
        let SignPayload::Digest(digest) = payload else {
            panic!("expected digest payload");
        };
        assert_eq!(digest.len(), HashAlgorithm::Sha256.digest_len());
    }

    #[test]
    fn sign_params_debug_redacts_message_and_digest_bytes() {
        for payload in [
            SignPayload::Message(Zeroizing::new(b"super secret message".to_vec())),
            SignPayload::Digest(Zeroizing::new(vec![0x7a; 32])),
        ] {
            let params = SignParams {
                material: ObjectSelector::Id(RegistryId::new("sign-key").unwrap()),
                payload,
                hash: HashAlgorithm::Sha256,
                output_format: SignatureFormat::Der,
            };
            let debug = format!("{params:?}");
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains("super secret"));
            assert!(!debug.contains("122"));
        }
    }

    #[test]
    fn ecdh_params_debug_redacts_peer_public_key() {
        let params = EcdhParams {
            material: ObjectSelector::Id(RegistryId::new("ecdh-key").unwrap()),
            peer_public_key: PublicKeyInput::Sec1(vec![0x04, 0xaa, 0xbb]),
            output_format: BinaryFormat::Hex,
        };
        let debug = format!("{params:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("170"));
        assert!(!debug.contains("187"));
    }

    #[test]
    fn context_builds_command_and_store_without_tcti_side_effects() {
        let dir = tempfile::tempdir().unwrap();
        let context = Context {
            store: StoreOptions {
                root: Some(dir.path().to_path_buf()),
            },
            tcti: Some("swtpm:host=127.0.0.1,port=2321".to_string()),
        };
        let command = context.command();
        assert_eq!(command.store.root.as_deref(), Some(dir.path()));
        assert_eq!(
            command.tcti.as_deref(),
            Some("swtpm:host=127.0.0.1,port=2321")
        );
        let store = context.store().unwrap();
        assert_eq!(store.root(), dir.path());
    }

    #[test]
    fn object_selector_usage_stays_explicit() {
        let descriptor = crate::ObjectDescriptor {
            selector: ObjectSelector::Id(RegistryId::new("id").unwrap()),
            usage: KeyUsage::Sign,
            curve: None,
            hash: None,
            public_key: None,
        };
        descriptor.require_usage(KeyUsage::Sign).unwrap();
        assert!(descriptor.require_usage(KeyUsage::Hmac).is_err());
    }
}
