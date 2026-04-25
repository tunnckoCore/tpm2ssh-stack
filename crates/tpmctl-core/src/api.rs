use std::fmt;

use zeroize::Zeroizing;

use crate::{
    CommandContext, HashAlgorithm, ObjectSelector, RegistryId, Result, SealTarget, Store,
    StoreOptions, ecdh as ecdh_api,
    hmac::{self, HmacResult},
    keygen::{self, KeygenResult, KeygenUsage},
    output::{BinaryFormat, PublicKeyFormat, SignatureFormat},
    pubkey::{self as pubkey_api, PublicKeyInput},
    seal::{self, SealResult},
    sign as sign_api, tpm,
};

pub mod derive {
    use std::fmt;

    use zeroize::{Zeroize as _, Zeroizing};

    use crate::{
        CommandContext, Error, HashAlgorithm, ObjectSelector, Result,
        crypto::{self, derive::DerivedAlgorithm},
        hmac as hmac_domain,
        output::{self, BinaryFormat, SignatureFormat},
        seal,
    };

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
        params.validate()?;
        let command = context.command();
        let mode = derive_mode(&params)?;
        let seed_bytes = prf_seed(&command, &params.material, &params)?;
        let seed = crypto::derive::SecretSeed::new(seed_bytes.as_slice()).map_err(derive_error)?;
        output(&params, &seed, &mode)
    }

    impl DeriveParams {
        pub fn validate(&self) -> Result<()> {
            if self.usage == DeriveUse::Sign && self.payload.is_none() {
                return Err(Error::invalid("derive", "derive sign requires a payload"));
            }
            if self.usage != DeriveUse::Sign && self.payload.is_some() {
                return Err(Error::invalid(
                    "derive",
                    "payload is valid only for derive sign",
                ));
            }
            if self.label.is_some() && self.entropy.is_some() {
                return Err(Error::invalid(
                    "entropy",
                    "entropy is valid only when label is omitted",
                ));
            }
            if self.algorithm == DerivedAlgorithm::Ed25519 && self.usage == DeriveUse::Sign {
                if self.hash.is_some() {
                    return Err(Error::invalid(
                        "derive",
                        "ed25519 derive sign does not support hash selection",
                    ));
                }
                if matches!(self.payload.as_ref(), Some(SignPayload::Digest(_))) {
                    return Err(Error::invalid(
                        "derive",
                        "ed25519 derive sign supports only message payloads",
                    ));
                }
            }
            if self.usage == DeriveUse::Secret
                && !matches!(self.output_format, DeriveFormat::Raw | DeriveFormat::Hex)
            {
                return Err(Error::invalid(
                    "derive",
                    "secret output supports only raw or hex",
                ));
            }
            if self.usage == DeriveUse::Pubkey {
                match self.algorithm {
                    DerivedAlgorithm::P256 | DerivedAlgorithm::Ed25519 => {
                        if !matches!(self.output_format, DeriveFormat::Raw | DeriveFormat::Hex) {
                            return Err(Error::invalid(
                                "derive",
                                "pubkey output for p256 or ed25519 supports only raw or hex",
                            ));
                        }
                    }
                    DerivedAlgorithm::Secp256k1 => {
                        if !matches!(
                            self.output_format,
                            DeriveFormat::Raw | DeriveFormat::Hex | DeriveFormat::Address
                        ) {
                            return Err(Error::invalid(
                                "derive",
                                "secp256k1 pubkey output supports only raw, hex, or address",
                            ));
                        }
                    }
                }
            }
            if self.usage == DeriveUse::Sign {
                match self.algorithm {
                    DerivedAlgorithm::Ed25519 => {
                        if !matches!(self.output_format, DeriveFormat::Raw | DeriveFormat::Hex) {
                            return Err(Error::invalid(
                                "derive",
                                "ed25519 sign output supports only raw or hex",
                            ));
                        }
                    }
                    DerivedAlgorithm::P256 | DerivedAlgorithm::Secp256k1 => {
                        if !matches!(
                            self.output_format,
                            DeriveFormat::Der | DeriveFormat::Raw | DeriveFormat::Hex
                        ) {
                            return Err(Error::invalid(
                                "derive",
                                "p256 or secp256k1 sign output supports only der, raw, or hex",
                            ));
                        }
                    }
                }
            }
            if self.output_format == DeriveFormat::Address
                && !(self.algorithm == DerivedAlgorithm::Secp256k1
                    && self.usage == DeriveUse::Pubkey)
            {
                return Err(Error::invalid(
                    "output_format",
                    "address output is valid only for secp256k1 pubkey derivation",
                ));
            }
            if self.compressed
                && !(self.algorithm == DerivedAlgorithm::Secp256k1
                    && self.usage == DeriveUse::Pubkey
                    && matches!(self.output_format, DeriveFormat::Raw | DeriveFormat::Hex))
            {
                return Err(Error::invalid(
                    "compressed",
                    "compressed output is valid only for secp256k1 pubkey raw/hex derivation",
                ));
            }
            crypto::derive::DeriveRequest::new(
                self.algorithm,
                self.usage,
                self.hash.map(hash_selection),
            )
            .map_err(derive_error)?;
            Ok(())
        }
    }

    fn prf_seed(
        command: &CommandContext,
        selector: &ObjectSelector,
        params: &DeriveParams,
    ) -> Result<Zeroizing<Vec<u8>>> {
        match (seal::UnsealRequest {
            selector: selector.clone(),
            force_binary_stdout: true,
        })
        .execute_with_context(command)
        {
            Ok(seed) => Ok(seed),
            Err(Error::NotFound(_)) if matches!(selector, ObjectSelector::Id(_)) => {
                hmac_prf_seed(command, selector, params)
            }
            Err(Error::InvalidInput { .. }) | Err(Error::Tpm { .. })
                if matches!(selector, ObjectSelector::Handle(_)) =>
            {
                hmac_prf_seed(command, selector, params)
            }
            Err(error) => Err(error),
        }
    }

    fn hmac_prf_seed(
        command: &CommandContext,
        selector: &ObjectSelector,
        params: &DeriveParams,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut input = Vec::new();
        input.extend_from_slice(b"tpmctl derive prf v1\0");
        input.extend_from_slice(params.algorithm.domain());
        input.push(0);
        if let Some(label) = &params.label {
            input.extend_from_slice(label);
        }
        let seed = hmac_domain::prf_seed_from_hmac_identity(command, selector, &input, None)?;
        input.zeroize();
        Ok(seed)
    }

    fn derive_mode(params: &DeriveParams) -> Result<crypto::derive::DeriveMode> {
        if let Some(label) = &params.label {
            Ok(crypto::derive::DeriveMode::deterministic(label.clone()))
        } else {
            let entropy = params.entropy.as_ref().ok_or_else(|| {
                Error::invalid("entropy", "entropy is required when label is omitted")
            })?;
            Ok(crypto::derive::DeriveMode::ephemeral(
                Vec::new(),
                entropy.as_slice().to_vec(),
            ))
        }
    }

    fn output(
        params: &DeriveParams,
        seed: &crypto::derive::SecretSeed,
        mode: &crypto::derive::DeriveMode,
    ) -> Result<Zeroizing<Vec<u8>>> {
        match params.usage {
            DeriveUse::Secret => secret(params, seed, mode),
            DeriveUse::Pubkey => pubkey(params, seed, mode),
            DeriveUse::Sign => signature(params, seed, mode),
        }
    }

    fn secret(
        params: &DeriveParams,
        seed: &crypto::derive::SecretSeed,
        mode: &crypto::derive::DeriveMode,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut raw = match params.algorithm {
            DerivedAlgorithm::P256 => crypto::p256::derive_secret_key(seed, mode)
                .map_err(derive_error)?
                .to_bytes()
                .to_vec(),
            DerivedAlgorithm::Ed25519 => crypto::ed25519::derive_signing_key(seed, mode)
                .map_err(derive_error)?
                .to_bytes()
                .to_vec(),
            DerivedAlgorithm::Secp256k1 => crypto::secp256k1::derive_secret_key(seed, mode)
                .map_err(derive_error)?
                .to_bytes()
                .to_vec(),
        };
        let encoded = encode_raw_or_hex(&raw, params.output_format)?;
        raw.zeroize();
        Ok(Zeroizing::new(encoded))
    }

    fn pubkey(
        params: &DeriveParams,
        seed: &crypto::derive::SecretSeed,
        mode: &crypto::derive::DeriveMode,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let bytes = match params.algorithm {
            DerivedAlgorithm::P256 => encode_raw_or_hex(
                &crypto::p256::derive_public_key_sec1(seed, mode, false).map_err(derive_error)?,
                params.output_format,
            )?,
            DerivedAlgorithm::Ed25519 => encode_raw_or_hex(
                &crypto::ed25519::derive_public_key_bytes(seed, mode).map_err(derive_error)?,
                params.output_format,
            )?,
            DerivedAlgorithm::Secp256k1 if params.output_format == DeriveFormat::Address => {
                crypto::secp256k1::derive_ethereum_address(seed, mode)
                    .map_err(derive_error)?
                    .into_bytes()
            }
            DerivedAlgorithm::Secp256k1 => encode_raw_or_hex(
                &crypto::secp256k1::derive_public_key_sec1(seed, mode, params.compressed)
                    .map_err(derive_error)?,
                params.output_format,
            )?,
        };
        Ok(Zeroizing::new(bytes))
    }

    fn signature(
        params: &DeriveParams,
        seed: &crypto::derive::SecretSeed,
        mode: &crypto::derive::DeriveMode,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let message = sign_message_bytes(params)?;
        let bytes = match params.algorithm {
            DerivedAlgorithm::P256 => output::encode_p256_signature(
                &crypto::p256::sign_prehash(seed, mode, &message).map_err(derive_error)?,
                signature_format(params.output_format)?,
            )?,
            DerivedAlgorithm::Ed25519 => encode_raw_or_hex(
                &crypto::ed25519::sign_message(seed, mode, &message).map_err(derive_error)?,
                params.output_format,
            )?,
            DerivedAlgorithm::Secp256k1 => output::encode_secp256k1_signature(
                &crypto::secp256k1::sign_prehash(seed, mode, &message).map_err(derive_error)?,
                signature_format(params.output_format)?,
            )?,
        };
        Ok(Zeroizing::new(bytes))
    }

    fn sign_message_bytes(params: &DeriveParams) -> Result<Zeroizing<Vec<u8>>> {
        let payload = params
            .payload
            .as_ref()
            .ok_or_else(|| Error::invalid("derive", "derive sign requires a payload"))?;
        match payload {
            SignPayload::Message(message) if params.algorithm == DerivedAlgorithm::Ed25519 => {
                Ok(message.clone())
            }
            SignPayload::Message(message) => {
                let hash = derive_hash(params)
                    .ok_or_else(|| Error::invalid("derive", "derive sign requires a hash"))?;
                Ok(Zeroizing::new(hash.digest(message)))
            }
            SignPayload::Digest(digest) => {
                let hash = derive_hash(params)
                    .ok_or_else(|| Error::invalid("derive", "derive sign requires a hash"))?;
                hash.validate_digest(digest)?;
                Ok(digest.clone())
            }
        }
    }

    fn encode_raw_or_hex(raw: &[u8], format: DeriveFormat) -> Result<Vec<u8>> {
        match format {
            DeriveFormat::Raw => Ok(output::encode_binary(raw, BinaryFormat::Raw)),
            DeriveFormat::Hex => Ok(output::encode_binary(raw, BinaryFormat::Hex)),
            DeriveFormat::Der | DeriveFormat::Address => Err(Error::invalid(
                "output_format",
                "derive output format is not valid for this operation",
            )),
        }
    }

    fn signature_format(format: DeriveFormat) -> Result<SignatureFormat> {
        match format {
            DeriveFormat::Der => Ok(SignatureFormat::Der),
            DeriveFormat::Raw => Ok(SignatureFormat::Raw),
            DeriveFormat::Hex => Ok(SignatureFormat::Hex),
            DeriveFormat::Address => Err(Error::invalid(
                "output_format",
                "derive sign does not support address output",
            )),
        }
    }

    fn derive_hash(params: &DeriveParams) -> Option<HashAlgorithm> {
        if params.usage == DeriveUse::Sign
            && matches!(
                params.algorithm,
                DerivedAlgorithm::P256 | DerivedAlgorithm::Secp256k1
            )
        {
            Some(params.hash.unwrap_or(HashAlgorithm::Sha256))
        } else {
            params.hash
        }
    }

    fn hash_selection(hash: HashAlgorithm) -> HashSelection {
        match hash {
            HashAlgorithm::Sha256 => HashSelection::Sha256,
            HashAlgorithm::Sha384 => HashSelection::Sha384,
            HashAlgorithm::Sha512 => HashSelection::Sha512,
        }
    }

    fn derive_error(error: impl std::fmt::Display) -> Error {
        Error::invalid("derive", error.to_string())
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

        #[test]
        fn sign_message_bytes_returns_error_without_payload_instead_of_panicking() {
            let params = params(DerivedAlgorithm::P256, DeriveUse::Sign, DeriveFormat::Raw);

            assert!(sign_message_bytes(&params).is_err());
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
    ecdh_api::EcdhRequest {
        selector: params.material,
        peer_public_key: params.peer_public_key,
        output_format: params.output_format,
    }
    .execute_with_context(&context.command())
}

#[derive(Clone, Eq, PartialEq)]
pub enum SignPayload {
    Message(Zeroizing<Vec<u8>>),
    Digest(Zeroizing<Vec<u8>>),
}

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
        SignPayload::Message(message) => sign_api::SignInput::Message(message),
        SignPayload::Digest(digest) => sign_api::SignInput::Digest(digest),
    };
    sign_api::SignRequest {
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
    hmac::HmacRequest {
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
    seal::SealRequest {
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
    seal::UnsealRequest {
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
