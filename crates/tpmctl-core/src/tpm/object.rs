use std::fmt;

use crate::{
    CoreError, HashAlgorithm, ObjectDescriptor, ObjectSelector, Result,
    store::{RegistryCollection, RegistryId, Store, StoredObjectEntry},
};
use zeroize::Zeroizing;

use tss_esapi::{
    Context,
    attributes::ObjectAttributesBuilder,
    handles::{KeyHandle, ObjectHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        dynamic_handles::Persistent,
        key_bits::RsaKeyBits,
        resource_handles::{Hierarchy, Provision},
        session_handles::AuthSession,
    },
    structures::{
        Auth, Name, Private, Public, PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder,
        RsaExponent, SymmetricDefinitionObject,
    },
    traits::{Marshall, UnMarshall},
};

use super::registry::{
    descriptor_from_entry, descriptor_from_registry_entry, registry_entry_handle,
};
use super::{PersistentHandle, descriptor_from_tpm_public};

/// Template name for the owner-hierarchy restricted decrypt parent used by stored children.
pub const OWNER_STORAGE_PARENT_TEMPLATE: &str = "owner-rsa2048-aes128cfb-restricted-decrypt";

/// TPM create output for a child object before it is loaded or stored.
#[derive(Clone)]
pub struct CreatedChildKey {
    /// Public area returned by TPM2_Create.
    pub public: Public,
    /// Private area returned by TPM2_Create.
    pub private: Private,
}

impl fmt::Debug for CreatedChildKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedChildKey")
            .field("public", &self.public)
            .field("private", &"<redacted>")
            .finish()
    }
}

pub(crate) fn hashing_algorithm(hash: HashAlgorithm) -> HashingAlgorithm {
    match hash {
        HashAlgorithm::Sha256 => HashingAlgorithm::Sha256,
        HashAlgorithm::Sha384 => HashingAlgorithm::Sha384,
        HashAlgorithm::Sha512 => HashingAlgorithm::Sha512,
    }
}

pub(crate) fn owner_storage_parent_template() -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_restricted(true)
        .build()
        .map_err(|source| CoreError::tpm("build owner storage parent attributes", source))?;

    let parameters = PublicRsaParametersBuilder::new_restricted_decryption_key(
        SymmetricDefinitionObject::AES_128_CFB,
        RsaKeyBits::Rsa2048,
        RsaExponent::default(),
    )
    .build()
    .map_err(|source| CoreError::tpm("build owner storage parent parameters", source))?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(parameters)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .map_err(|source| CoreError::tpm("build owner storage parent template", source))
}

/// Create a transient owner-hierarchy storage parent.
pub fn create_owner_storage_parent(context: &mut Context) -> Result<KeyHandle> {
    let public = owner_storage_parent_template()?;
    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create_primary(
                Hierarchy::Owner,
                public,
                Some(Auth::default()),
                None,
                None,
                None,
            )
        })
        .map(|result| result.key_handle)
        .map_err(|source| CoreError::tpm("CreatePrimary owner storage parent", source))
}

/// Create the default owner primary object used to load children.
pub fn create_owner_primary(context: &mut Context) -> Result<KeyHandle> {
    create_owner_storage_parent(context)
}

/// Create a child key under an existing parent using a supplied public template.
pub fn create_child_key(
    context: &mut Context,
    parent_handle: KeyHandle,
    public: Public,
) -> Result<CreatedChildKey> {
    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create(
                parent_handle,
                public,
                Some(Auth::default()),
                None,
                None,
                None,
            )
        })
        .map(|result| CreatedChildKey {
            public: result.out_public,
            private: result.out_private,
        })
        .map_err(|source| CoreError::tpm("Create child object", source))
}

/// Load a child object previously returned by TPM2_Create.
pub fn load_created_child_key(
    context: &mut Context,
    parent_handle: KeyHandle,
    child: &CreatedChildKey,
) -> Result<KeyHandle> {
    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.load(parent_handle, child.private.clone(), child.public.clone())
        })
        .map_err(|source| CoreError::tpm("Load child object", source))
}

/// Marshaled TPM public/private object blobs.
#[derive(Clone, Eq, PartialEq)]
pub struct ObjectBlobs {
    /// Marshaled TPM public area.
    pub public: Vec<u8>,
    /// Marshaled TPM private area; zeroized when dropped.
    pub private: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for ObjectBlobs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectBlobs")
            .field("public", &self.public)
            .field("private", &"<redacted>")
            .finish()
    }
}

impl ObjectBlobs {
    /// Copy marshaled blobs out of a registry entry.
    pub fn from_entry(entry: &StoredObjectEntry) -> Self {
        Self {
            public: entry.public_blob.clone(),
            private: entry.private_blob.clone(),
        }
    }
}

/// Marshal a TPM public area into bytes for registry storage.
pub fn marshal_public(public: &Public) -> Result<Vec<u8>> {
    public
        .marshall()
        .map_err(|source| CoreError::tpm("marshal public object", source))
}

/// Marshal a TPM private area into zeroizing bytes for registry storage.
pub fn marshal_private(private: &Private) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(private.value().to_vec()))
}

/// Unmarshal registry bytes into a TPM public area.
pub fn unmarshal_public(bytes: &[u8]) -> Result<Public> {
    Public::unmarshall(bytes).map_err(|source| CoreError::tpm("unmarshal public object", source))
}

/// Unmarshal registry bytes into a TPM private area.
pub fn unmarshal_private(bytes: &[u8]) -> Result<Private> {
    Private::try_from(bytes).map_err(|source| CoreError::tpm("unmarshal private object", source))
}

fn load_object_from_entry(
    context: &mut Context,
    parent_handle: KeyHandle,
    entry: &StoredObjectEntry,
) -> Result<KeyHandle> {
    load_object_from_blob_slices(
        context,
        parent_handle,
        &entry.public_blob,
        &entry.private_blob,
    )
}

fn load_object_from_blob_slices(
    context: &mut Context,
    parent_handle: KeyHandle,
    public_blob: &[u8],
    private_blob: &[u8],
) -> Result<KeyHandle> {
    let private = unmarshal_private(private_blob)?;
    let public = unmarshal_public(public_blob)?;
    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.load(parent_handle, private, public)
        })
        .map_err(|source| CoreError::tpm("Load", source))
}

/// Load a transient TPM object from a registry entry.
pub fn load_object_from_registry(
    context: &mut Context,
    store: &Store,
    collection: RegistryCollection,
    id: &RegistryId,
    parent_handle: KeyHandle,
) -> Result<KeyHandle> {
    let entry = store.load_entry(collection, id)?;
    load_object_from_entry(context, parent_handle, &entry)
}

/// Load a registered key object under the default parent.
pub fn load_key_from_registry(
    context: &mut Context,
    store: &Store,
    id: &RegistryId,
    parent_handle: KeyHandle,
) -> Result<KeyHandle> {
    load_object_from_registry(context, store, RegistryCollection::Keys, id, parent_handle)
}

pub(crate) fn load_key_from_registry_with_descriptor(
    context: &mut Context,
    store: &Store,
    id: &RegistryId,
    parent_handle: KeyHandle,
) -> Result<(KeyHandle, ObjectDescriptor)> {
    let entry = store.load_entry(RegistryCollection::Keys, id)?;
    let descriptor = descriptor_from_registry_entry(RegistryCollection::Keys, id, &entry)?;
    let handle = load_object_from_entry(context, parent_handle, &entry)?;
    Ok((handle, descriptor))
}

/// Load a registered sealed-data object under the default parent.
pub fn load_sealed_from_registry(
    context: &mut Context,
    store: &Store,
    id: &RegistryId,
    parent_handle: KeyHandle,
) -> Result<KeyHandle> {
    load_object_from_registry(
        context,
        store,
        RegistryCollection::Sealed,
        id,
        parent_handle,
    )
}

pub(crate) fn load_sealed_from_registry_with_descriptor(
    context: &mut Context,
    store: &Store,
    id: &RegistryId,
    parent_handle: KeyHandle,
) -> Result<(KeyHandle, ObjectDescriptor)> {
    let entry = store.load_entry(RegistryCollection::Sealed, id)?;
    let descriptor = descriptor_from_registry_entry(RegistryCollection::Sealed, id, &entry)?;
    let handle = load_object_from_entry(context, parent_handle, &entry)?;
    Ok((handle, descriptor))
}

/// Load an object already resident at a persistent TPM handle.
pub fn load_persistent_object(
    context: &mut Context,
    handle: PersistentHandle,
) -> Result<ObjectHandle> {
    context
        .tr_from_tpm_public(handle.tpm_handle())
        .map_err(|source| CoreError::tpm("TR_FromTPMPublic", source))
}

/// Read the public area, name, and qualified name for a TPM object.
pub fn read_public(
    context: &mut Context,
    object_handle: ObjectHandle,
) -> Result<(Public, Name, Name)> {
    context
        .read_public(KeyHandle::from(object_handle))
        .map_err(|source| CoreError::tpm("ReadPublic", source))
}

/// Persist a transient object at a TPM persistent handle.
pub fn persist_object(
    context: &mut Context,
    object_handle: ObjectHandle,
    destination: PersistentHandle,
) -> Result<ObjectHandle> {
    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(
                Provision::Owner,
                object_handle,
                Persistent::from(destination.persistent_tpm_handle()),
            )
        })
        .map_err(|source| CoreError::tpm("EvictControl persist object", source))
}

/// Evict an object from a TPM persistent handle.
pub fn evict_persistent_object(
    context: &mut Context,
    object_handle: ObjectHandle,
    destination: PersistentHandle,
) -> Result<ObjectHandle> {
    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(
                Provision::Owner,
                object_handle,
                Persistent::from(destination.persistent_tpm_handle()),
            )
        })
        .map_err(|source| CoreError::tpm("EvictControl evict persistent object", source))
}

fn create_default_parent(context: &mut Context) -> Result<KeyHandle> {
    create_owner_storage_parent(context)
}

pub(crate) fn load_key_by_id(
    context: &mut Context,
    store: &Store,
    id: &RegistryId,
) -> Result<LoadedKey> {
    let entry = store.load_key(id)?;
    let descriptor = descriptor_from_entry(ObjectSelector::Id(id.clone()), &entry)?;

    if let Some(handle) = registry_entry_handle(&entry)? {
        let object_handle = load_persistent_object(context, handle)?;
        let (public, _, _) = read_public(context, object_handle)?;
        let descriptor = descriptor.with_public_from_tpm(public)?;
        return Ok(LoadedKey {
            handle: KeyHandle::from(object_handle),
            descriptor,
        });
    }

    let parent_handle = create_default_parent(context)?;
    let handle = load_object_from_entry(context, parent_handle, &entry)?;
    Ok(LoadedKey { handle, descriptor })
}

pub(crate) fn load_key_by_handle(
    context: &mut Context,
    handle: PersistentHandle,
) -> Result<LoadedKey> {
    let object_handle = load_persistent_object(context, handle)?;
    let (public, _, _) = read_public(context, object_handle)?;
    Ok(LoadedKey {
        handle: KeyHandle::from(object_handle),
        descriptor: descriptor_from_tpm_public(ObjectSelector::Handle(handle), public)?,
    })
}

/// Loaded TPM key handle paired with object metadata.
#[derive(Debug)]
pub struct LoadedKey {
    /// Transient TPM key handle.
    pub handle: KeyHandle,
    /// Descriptor inferred from registry metadata or TPM public area.
    pub descriptor: ObjectDescriptor,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{ObjectKind, ObjectUsage, RegistryRecord};

    #[test]
    fn created_child_key_debug_redacts_private_blob() {
        let child = CreatedChildKey {
            public: owner_storage_parent_template().unwrap(),
            private: Private::try_from(vec![0xde, 0xad, 0xbe, 0xef]).unwrap(),
        };

        let debug = format!("{child:?}");
        assert!(debug.contains("public"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("deadbeef"));
    }

    #[test]
    fn hashing_algorithm_maps_all_supported_hashes() {
        assert_eq!(
            hashing_algorithm(HashAlgorithm::Sha256),
            HashingAlgorithm::Sha256
        );
        assert_eq!(
            hashing_algorithm(HashAlgorithm::Sha384),
            HashingAlgorithm::Sha384
        );
        assert_eq!(
            hashing_algorithm(HashAlgorithm::Sha512),
            HashingAlgorithm::Sha512
        );
    }

    #[test]
    fn owner_storage_parent_template_round_trips_through_marshal_and_unmarshal() {
        let public = owner_storage_parent_template().unwrap();
        let marshaled = marshal_public(&public).unwrap();
        let unmarshaled = unmarshal_public(&marshaled).unwrap();

        assert_eq!(marshaled, marshal_public(&unmarshaled).unwrap());
    }

    #[test]
    fn private_blob_round_trips_through_marshal_and_unmarshal() {
        let private = Private::try_from(vec![0xaa, 0xbb, 0xcc, 0xdd]).unwrap();
        let marshaled = marshal_private(&private).unwrap();
        let unmarshaled = unmarshal_private(&marshaled).unwrap();

        assert_eq!(unmarshaled.value(), private.value());
    }

    #[test]
    fn object_blobs_from_entry_clones_public_and_private_blobs() {
        let entry = StoredObjectEntry {
            record: RegistryRecord::new(
                &RegistryId::new("org/acme/alice/main").unwrap(),
                ObjectKind::Key,
                ObjectUsage::Sign,
            ),
            public_blob: b"public-blob".to_vec(),
            private_blob: Zeroizing::new(b"private-blob-secret".to_vec()),
            public_pem: Some(b"pem".to_vec()),
        };

        let blobs = ObjectBlobs::from_entry(&entry);
        assert_eq!(blobs.public, entry.public_blob);
        assert_eq!(blobs.private.as_slice(), entry.private_blob.as_slice());
    }

    #[test]
    fn object_blobs_debug_redacts_private_blob() {
        let blobs = ObjectBlobs {
            public: b"public-blob".to_vec(),
            private: Zeroizing::new(b"private-blob-secret".to_vec()),
        };

        let debug = format!("{blobs:?}");
        assert!(debug.contains("public"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("private-blob-secret"));
    }
}
