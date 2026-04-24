use std::{env, str::FromStr};

use tss_esapi::{
    Context,
    handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, TpmHandle},
    interface_types::{
        dynamic_handles::Persistent, resource_handles::Provision, session_handles::AuthSession,
    },
    structures::{Name, Private, Public},
    tcti_ldr::{DeviceConfig, TctiNameConf},
    traits::{Marshall, UnMarshall},
};

use crate::{
    CoreError, Result,
    store::{RegistryCollection, RegistryId, Store, StoredObjectEntry},
};

pub const TCTI_ENV_PRECEDENCE: [&str; 3] = ["TPM2TOOLS_TCTI", "TCTI", "TEST_TCTI"];

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TctiResolution {
    pub source: TctiSource,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TctiSource {
    Env(&'static str),
    DefaultDevice,
}

impl TctiResolution {
    pub fn from_environment() -> Self {
        for name in TCTI_ENV_PRECEDENCE {
            if let Ok(value) = env::var(name) {
                if !value.trim().is_empty() {
                    return Self {
                        source: TctiSource::Env(name),
                        value: Some(value),
                    };
                }
            }
        }

        Self {
            source: TctiSource::DefaultDevice,
            value: None,
        }
    }

    pub fn to_name_conf(&self) -> Result<TctiNameConf> {
        match (&self.source, &self.value) {
            (TctiSource::Env(name), Some(value)) => {
                value.parse::<TctiNameConf>().map_err(|source| {
                    CoreError::Tcti(format!(
                        "failed to parse {name}={value:?} as a TCTI configuration: {source}"
                    ))
                })
            }
            (TctiSource::DefaultDevice, None) => Ok(TctiNameConf::Device(DeviceConfig::default())),
            _ => Err(CoreError::Tcti("inconsistent TCTI resolution state".into())),
        }
    }
}

pub fn resolve_tcti_name_conf() -> Result<TctiNameConf> {
    TctiResolution::from_environment().to_name_conf()
}

pub fn create_context() -> Result<Context> {
    let tcti = resolve_tcti_name_conf()?;
    Context::new(tcti).map_err(|source| CoreError::tpm("Context::new", source))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PersistentHandle {
    raw: u32,
    handle: PersistentTpmHandle,
}

impl PersistentHandle {
    pub fn parse(input: impl AsRef<str>) -> Result<Self> {
        input.as_ref().parse()
    }

    pub fn raw(self) -> u32 {
        self.raw
    }

    pub fn tpm_handle(self) -> TpmHandle {
        TpmHandle::Persistent(self.handle)
    }

    pub fn persistent_tpm_handle(self) -> PersistentTpmHandle {
        self.handle
    }
}

impl std::fmt::Display for PersistentHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "0x{:08x}", self.raw)
    }
}

impl FromStr for PersistentHandle {
    type Err = CoreError;

    fn from_str(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(invalid_handle(input, "handle is empty"));
        }
        if trimmed != input {
            return Err(invalid_handle(
                input,
                "leading or trailing whitespace is not allowed",
            ));
        }

        let Some(hex) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        else {
            return Err(invalid_handle(
                input,
                "persistent handles must be hexadecimal and start with 0x",
            ));
        };
        if hex.is_empty() {
            return Err(invalid_handle(input, "hex digits are missing"));
        }
        if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid_handle(
                input,
                "handle contains non-hexadecimal characters",
            ));
        }

        let raw = u32::from_str_radix(hex, 16)
            .map_err(|error| invalid_handle(input, format!("handle is out of range: {error}")))?;
        let handle = PersistentTpmHandle::new(raw).map_err(|error| {
            invalid_handle(input, format!("not a persistent TPM handle: {error}"))
        })?;

        Ok(Self { raw, handle })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ObjectBlobs {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
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

pub fn marshal_private(private: &Private) -> Result<Vec<u8>> {
    Ok(private.value().to_vec())
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
        .load(parent_handle, private, public)
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
        .map_err(|source| CoreError::tpm("EvictControl", source))
}

fn invalid_handle(input: &str, reason: impl Into<String>) -> CoreError {
    CoreError::InvalidHandle {
        input: input.to_owned(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn handle_parses_persistent_hex() {
        let handle = PersistentHandle::parse("0x81010010").unwrap();
        assert_eq!(handle.raw(), 0x8101_0010);
        assert_eq!(handle.to_string(), "0x81010010");

        let upper = PersistentHandle::parse("0X81010010").unwrap();
        assert_eq!(upper, handle);
    }

    #[test]
    fn handle_rejects_non_persistent_or_non_hex_forms() {
        for input in [
            "",
            "81010010",
            "2164326416",
            "0x",
            "0xzzzzzzzz",
            "0x80000000",
            " 0x81010010",
            "0x81010010 ",
        ] {
            assert!(
                PersistentHandle::parse(input).is_err(),
                "{input} should be rejected"
            );
        }
    }

    #[test]
    fn tcti_uses_documented_env_precedence() {
        let _guard = env_lock();
        unsafe {
            env::set_var("TPM2TOOLS_TCTI", "device:/dev/tpmrm0");
            env::set_var("TCTI", "swtpm:port=2321");
            env::set_var("TEST_TCTI", "mssim:host=localhost,port=2321");
        }

        let resolution = TctiResolution::from_environment();
        assert_eq!(resolution.source, TctiSource::Env("TPM2TOOLS_TCTI"));
        assert_eq!(resolution.value.as_deref(), Some("device:/dev/tpmrm0"));

        unsafe {
            env::remove_var("TPM2TOOLS_TCTI");
            env::remove_var("TCTI");
            env::remove_var("TEST_TCTI");
        }
    }

    #[test]
    fn tcti_falls_back_to_device() {
        let _guard = env_lock();
        unsafe {
            env::remove_var("TPM2TOOLS_TCTI");
            env::remove_var("TCTI");
            env::remove_var("TEST_TCTI");
        }

        let resolution = TctiResolution::from_environment();
        assert_eq!(resolution.source, TctiSource::DefaultDevice);
        assert_eq!(resolution.value, None);
    }
}
