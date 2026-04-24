use crate::{
    KeyUsage, ObjectSelector, PersistentHandle, RegistryId, Result, unsupported_without_tpm,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeygenRequest {
    pub usage: KeygenUsage,
    pub id: RegistryId,
    pub persist_at: Option<PersistentHandle>,
    pub force: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KeygenUsage {
    Sign,
    Ecdh,
    Hmac,
}

impl KeygenUsage {
    pub fn object_usage(self) -> KeyUsage {
        match self {
            Self::Sign => KeyUsage::Sign,
            Self::Ecdh => KeyUsage::Ecdh,
            Self::Hmac => KeyUsage::Hmac,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeygenPlan {
    pub usage: KeygenUsage,
    pub selector: ObjectSelector,
    pub persistent_handle: Option<PersistentHandle>,
    pub force: bool,
    pub template: KeyTemplate,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KeyTemplate {
    EccP256Sign,
    EccP256Ecdh,
    KeyedHashHmac,
}

impl KeygenRequest {
    pub fn plan(&self) -> Result<KeygenPlan> {
        Ok(KeygenPlan {
            usage: self.usage,
            selector: ObjectSelector::Id(self.id.clone()),
            persistent_handle: self.persist_at,
            force: self.force,
            template: template_for_usage(self.usage),
        })
    }

    pub fn execute(&self) -> Result<KeygenResult> {
        self.plan()?;
        Err(unsupported_without_tpm("keygen"))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeygenResult {
    pub id: RegistryId,
    pub usage: KeygenUsage,
    pub persistent_handle: Option<PersistentHandle>,
}

pub fn template_for_usage(usage: KeygenUsage) -> KeyTemplate {
    match usage {
        KeygenUsage::Sign => KeyTemplate::EccP256Sign,
        KeygenUsage::Ecdh => KeyTemplate::EccP256Ecdh,
        KeygenUsage::Hmac => KeyTemplate::KeyedHashHmac,
    }
}

#[cfg(test)]
mod keygen_tests {
    use super::*;

    #[test]
    fn keygen_supports_sign_ecdh_and_hmac_usages() {
        assert_eq!(
            template_for_usage(KeygenUsage::Sign),
            KeyTemplate::EccP256Sign
        );
        assert_eq!(
            template_for_usage(KeygenUsage::Ecdh),
            KeyTemplate::EccP256Ecdh
        );
        assert_eq!(
            template_for_usage(KeygenUsage::Hmac),
            KeyTemplate::KeyedHashHmac
        );
    }

    #[test]
    fn keygen_execute_reports_tpm_unavailable_without_foundation() {
        let request = KeygenRequest {
            usage: KeygenUsage::Sign,
            id: RegistryId::new("org/acme/alice/main").unwrap(),
            persist_at: None,
            force: false,
        };
        let error = request.execute().unwrap_err();
        assert!(error.to_string().contains("TPM unavailable"));
    }
}
