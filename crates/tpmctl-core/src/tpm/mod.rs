mod context;
mod crypto_ops;
mod handle;
mod object;
mod registry;

pub use context::{
    CommandContext, KeyUsage, TCTI_ENV_PRECEDENCE, TctiResolution, TctiSource, create_context,
    create_context_for, parse_tpm_handle_literal, resolve_tcti, tcti_name_conf_from_env,
};
pub use crypto_ops::{ecdh_z_gen, sign_digest};
pub use handle::PersistentHandle;
pub use object::{
    CreatedChildKey, OWNER_STORAGE_PARENT_TEMPLATE, ObjectBlobs, create_child_key,
    create_owner_primary, create_owner_storage_parent, evict_persistent_object,
    load_created_child_key, load_key_from_registry, load_object_from_registry,
    load_persistent_object, load_sealed_from_registry, marshal_private, marshal_public,
    persist_object, read_public, unmarshal_private, unmarshal_public,
};
pub use registry::{descriptor_from_public, descriptor_from_tpm_public};

pub(crate) use object::{
    hashing_algorithm, load_key_by_handle, load_key_by_id, load_key_from_registry_with_descriptor,
    load_sealed_from_registry_with_descriptor,
};
pub(crate) use registry::descriptor_from_entry;

#[cfg(test)]
#[path = "mod.test.rs"]
mod tests;
