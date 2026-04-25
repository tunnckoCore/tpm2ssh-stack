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

use super::{
    PersistentHandle, descriptor_from_entry, descriptor_from_registry_entry,
    descriptor_from_tpm_public, registry_entry_handle,
};

pub const OWNER_STORAGE_PARENT_TEMPLATE: &str = "owner-rsa2048-aes128cfb-restricted-decrypt";

#[derive(Clone)]
pub struct CreatedChildKey {
    pub public: Public,
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

pub fn hashing_algorithm(hash: HashAlgorithm) -> HashingAlgorithm {
    match hash {
        HashAlgorithm::Sha256 => HashingAlgorithm::Sha256,
        HashAlgorithm::Sha384 => HashingAlgorithm::Sha384,
        HashAlgorithm::Sha512 => HashingAlgorithm::Sha512,
    }
}

pub fn owner_storage_parent_template() -> Result<Public> {
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

pub fn create_owner_primary(context: &mut Context) -> Result<KeyHandle> {
    create_owner_storage_parent(context)
}

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

#[derive(Clone, Eq, PartialEq)]
pub struct ObjectBlobs {
    pub public: Vec<u8>,
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
    pub fn from_entry(entry: &StoredObjectEntry) -> Self {
        Self {
            public: entry.public_blob.clone(),
            private: entry.private_blob.clone(),
        }
    }
}

pub fn marshal_public(public: &Public) -> Result<Vec<u8>> {
    public
        .marshall()
        .map_err(|source| CoreError::tpm("marshal public object", source))
}

pub fn marshal_private(private: &Private) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(private.value().to_vec()))
}

pub fn unmarshal_public(bytes: &[u8]) -> Result<Public> {
    Public::unmarshall(bytes).map_err(|source| CoreError::tpm("unmarshal public object", source))
}

pub fn unmarshal_private(bytes: &[u8]) -> Result<Private> {
    Private::try_from(bytes).map_err(|source| CoreError::tpm("unmarshal private object", source))
}

pub fn load_object_from_blobs(
    context: &mut Context,
    parent_handle: KeyHandle,
    blobs: &ObjectBlobs,
) -> Result<KeyHandle> {
    let private = unmarshal_private(&blobs.private)?;
    let public = unmarshal_public(&blobs.public)?;
    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.load(parent_handle, private, public)
        })
        .map_err(|source| CoreError::tpm("Load", source))
}

pub fn load_object_from_registry(
    context: &mut Context,
    store: &Store,
    collection: RegistryCollection,
    id: &RegistryId,
    parent_handle: KeyHandle,
) -> Result<KeyHandle> {
    let entry = store.load_entry(collection, id)?;
    load_object_from_blobs(context, parent_handle, &ObjectBlobs::from_entry(&entry))
}

pub fn load_key_from_registry(
    context: &mut Context,
    store: &Store,
    id: &RegistryId,
    parent_handle: KeyHandle,
) -> Result<KeyHandle> {
    load_object_from_registry(context, store, RegistryCollection::Keys, id, parent_handle)
}

pub fn load_key_from_registry_with_descriptor(
    context: &mut Context,
    store: &Store,
    id: &RegistryId,
    parent_handle: KeyHandle,
) -> Result<(KeyHandle, ObjectDescriptor)> {
    let entry = store.load_entry(RegistryCollection::Keys, id)?;
    let descriptor = descriptor_from_registry_entry(RegistryCollection::Keys, id, &entry)?;
    let handle = load_object_from_blobs(context, parent_handle, &ObjectBlobs::from_entry(&entry))?;
    Ok((handle, descriptor))
}

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

pub fn load_sealed_from_registry_with_descriptor(
    context: &mut Context,
    store: &Store,
    id: &RegistryId,
    parent_handle: KeyHandle,
) -> Result<(KeyHandle, ObjectDescriptor)> {
    let entry = store.load_entry(RegistryCollection::Sealed, id)?;
    let descriptor = descriptor_from_registry_entry(RegistryCollection::Sealed, id, &entry)?;
    let handle = load_object_from_blobs(context, parent_handle, &ObjectBlobs::from_entry(&entry))?;
    Ok((handle, descriptor))
}

pub fn load_persistent_object(
    context: &mut Context,
    handle: PersistentHandle,
) -> Result<ObjectHandle> {
    context
        .tr_from_tpm_public(handle.tpm_handle())
        .map_err(|source| CoreError::tpm("TR_FromTPMPublic", source))
}

pub fn read_public(
    context: &mut Context,
    object_handle: ObjectHandle,
) -> Result<(Public, Name, Name)> {
    context
        .read_public(KeyHandle::from(object_handle))
        .map_err(|source| CoreError::tpm("ReadPublic", source))
}

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

pub fn create_default_parent(context: &mut Context) -> Result<KeyHandle> {
    create_owner_storage_parent(context)
}

pub fn load_key_by_id(context: &mut Context, store: &Store, id: &RegistryId) -> Result<LoadedKey> {
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
    let handle = load_object_from_blobs(context, parent_handle, &ObjectBlobs::from_entry(&entry))?;
    Ok(LoadedKey { handle, descriptor })
}

pub fn load_key_by_handle(context: &mut Context, handle: PersistentHandle) -> Result<LoadedKey> {
    let object_handle = load_persistent_object(context, handle)?;
    let (public, _, _) = read_public(context, object_handle)?;
    Ok(LoadedKey {
        handle: KeyHandle::from(object_handle),
        descriptor: descriptor_from_tpm_public(ObjectSelector::Handle(handle), public)?,
    })
}

#[derive(Debug)]
pub struct LoadedKey {
    pub handle: KeyHandle,
    pub descriptor: ObjectDescriptor,
}
