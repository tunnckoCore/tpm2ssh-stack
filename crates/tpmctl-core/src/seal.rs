use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    handles::ObjectHandle,
    interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm},
    structures::{
        Digest, KeyedHashScheme, PublicBuilder, PublicKeyedHashParameters, SensitiveData,
    },
};
use zeroize::Zeroizing;

use crate::{
    CommandContext, Error, HashAlgorithm, KeyUsage, ObjectDescriptor, ObjectSelector, Result,
    store::{
        ObjectUsage, ParentMetadata, RegistryMetadata, Store, StoredObjectEntry, StoredObjectKind,
    },
    tpm,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SealRequest {
    pub selector: ObjectSelector,
    pub input: Zeroizing<Vec<u8>>,
    pub force: bool,
}

impl SealRequest {
    pub fn validate(&self) -> Result<()> {
        validate_seal_input(&self.input)
    }

    pub fn execute(&self) -> Result<SealResult> {
        self.execute_with_context(&CommandContext::default())
    }

    pub fn execute_with_context(&self, command: &CommandContext) -> Result<SealResult> {
        seal_bytes(
            command,
            self.selector.clone(),
            &self.input,
            self.force,
            None,
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SealResult {
    pub selector: ObjectSelector,
    pub hash: Option<HashAlgorithm>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnsealRequest {
    pub selector: ObjectSelector,
    pub force_binary_stdout: bool,
}

impl UnsealRequest {
    pub fn validate_descriptor(&self, descriptor: &ObjectDescriptor) -> Result<()> {
        descriptor.require_usage(KeyUsage::Sealed)
    }

    pub fn execute(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.execute_with_context(&CommandContext::default())
    }

    pub fn execute_with_context(&self, command: &CommandContext) -> Result<Zeroizing<Vec<u8>>> {
        unseal_bytes(command, &self.selector)
    }
}

pub fn seal_bytes(
    command: &CommandContext,
    selector: ObjectSelector,
    input: &[u8],
    force: bool,
    hash: Option<HashAlgorithm>,
) -> Result<SealResult> {
    validate_seal_input(input)?;

    let mut context = tpm::create_context_for(command)?;
    let parent = tpm::create_owner_primary(&mut context)?;
    let public = sealed_data_public()?;
    let sensitive = SensitiveData::try_from(input)
        .map_err(|source| crate::CoreError::tpm("prepare sealed sensitive data", source))?;

    let create_result = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create(parent, public, None, Some(sensitive), None, None)
        })
        .map_err(|source| crate::CoreError::tpm("Create sealed object", source))?;

    match &selector {
        ObjectSelector::Handle(handle) => {
            clear_persistent_if_needed(&mut context, *handle, force)?;
            let loaded = context
                .load(parent, create_result.out_private, create_result.out_public)
                .map_err(|source| crate::CoreError::tpm("Load sealed object", source))?;
            tpm::persist_object(&mut context, ObjectHandle::from(loaded), *handle)?;
        }
        ObjectSelector::Id(id) => {
            let store = Store::resolve(command.store.root.as_deref())?;
            let mut metadata =
                RegistryMetadata::new(id, StoredObjectKind::Sealed, ObjectUsage::Sealed);
            metadata.hash = hash.map(|hash| hash.to_string());
            metadata.parent = Some(ParentMetadata {
                hierarchy: "owner".to_string(),
                template: "rsa2048-restricted-decrypt-aes128cfb-sha256".to_string(),
            });
            metadata.template = Some("keyedhash-sealed-null-sha256".to_string());

            let entry = StoredObjectEntry {
                metadata,
                public_blob: tpm::marshal_public(&create_result.out_public)?,
                private_blob: tpm::marshal_private(&create_result.out_private)?,
                public_pem: None,
            };
            store.save_sealed(&entry, force)?;
        }
    }

    Ok(SealResult { selector, hash })
}

pub fn unseal_bytes(
    command: &CommandContext,
    selector: &ObjectSelector,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut context = tpm::create_context_for(command)?;

    let (object_handle, descriptor) = match selector {
        ObjectSelector::Handle(handle) => {
            let object = tpm::load_persistent_object(&mut context, *handle)?;
            let (public, _, _) = tpm::read_public(&mut context, object)?;
            (
                object,
                tpm::descriptor_from_public(ObjectSelector::Handle(*handle), &public)?,
            )
        }
        ObjectSelector::Id(id) => {
            let store = Store::resolve(command.store.root.as_deref())?;
            let parent = tpm::create_owner_primary(&mut context)?;
            let (key_handle, descriptor) =
                tpm::load_sealed_from_registry_with_descriptor(&mut context, &store, id, parent)?;
            (ObjectHandle::from(key_handle), descriptor)
        }
    };

    descriptor.require_usage(KeyUsage::Sealed)?;
    let unsealed = context
        .execute_with_nullauth_session(|ctx| ctx.unseal(object_handle))
        .map_err(|source| crate::CoreError::tpm("Unseal", source))?;
    Ok(Zeroizing::new(unsealed.value().to_vec()))
}

fn validate_seal_input(input: &[u8]) -> Result<()> {
    if input.is_empty() {
        return Err(Error::invalid("input", "sealed input cannot be empty"));
    }
    if input.len() > SensitiveData::MAX_SIZE {
        return Err(Error::invalid(
            "input",
            format!(
                "sealed input is too large for a TPM sensitive-data object: {} > {} bytes",
                input.len(),
                SensitiveData::MAX_SIZE
            ),
        ));
    }
    Ok(())
}

fn sealed_data_public() -> Result<tss_esapi::structures::Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_no_da(true)
        .with_user_with_auth(true)
        .build()
        .map_err(|source| crate::CoreError::tpm("build sealed object attributes", source))?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_auth_policy(Digest::default())
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .map_err(|source| crate::CoreError::tpm("build sealed object template", source))
}

fn clear_persistent_if_needed(
    context: &mut tss_esapi::Context,
    handle: crate::PersistentHandle,
    force: bool,
) -> Result<()> {
    let existing = match tpm::load_persistent_object(context, handle) {
        Ok(existing) => existing,
        Err(_) => return Ok(()),
    };

    if !force {
        return Err(Error::invalid(
            "handle",
            format!("persistent handle {handle} already exists; use --force to replace it"),
        ));
    }

    context
        .execute_with_session(
            Some(tss_esapi::interface_types::session_handles::AuthSession::Password),
            |ctx| {
                ctx.evict_control(
                    tss_esapi::interface_types::resource_handles::Provision::Owner,
                    existing,
                    tss_esapi::interface_types::dynamic_handles::Persistent::from(
                        handle.persistent_tpm_handle(),
                    ),
                )
            },
        )
        .map(|_| ())
        .map_err(|source| crate::CoreError::tpm("EvictControl existing persistent object", source))
}

#[cfg(test)]
mod seal_tests {
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
    fn seal_result_carries_optional_hmac_hash_metadata() {
        let result = SealResult {
            selector: selector(),
            hash: Some(HashAlgorithm::Sha512),
        };
        assert_eq!(result.hash, Some(HashAlgorithm::Sha512));
    }
}
