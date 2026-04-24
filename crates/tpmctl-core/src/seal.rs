use zeroize::Zeroizing;

use crate::{Error, KeyUsage, ObjectDescriptor, ObjectSelector, Result, unsupported_without_tpm};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SealRequest {
    pub selector: ObjectSelector,
    pub input: Vec<u8>,
    pub force: bool,
}

impl SealRequest {
    pub fn validate(&self) -> Result<()> {
        if self.input.is_empty() {
            return Err(Error::invalid("input", "sealed input cannot be empty"));
        }
        Ok(())
    }

    pub fn execute(&self) -> Result<SealResult> {
        self.validate()?;
        Err(unsupported_without_tpm("seal"))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SealResult {
    pub selector: ObjectSelector,
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
        Err(unsupported_without_tpm("unseal"))
    }
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
            input: Vec::new(),
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
}
