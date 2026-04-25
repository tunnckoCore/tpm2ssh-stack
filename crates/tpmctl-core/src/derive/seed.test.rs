use super::*;
use crate::{DeriveFormat, Error, ObjectSelector, RegistryId};
use zeroize::Zeroizing;

fn params() -> DeriveParams {
    DeriveParams {
        material: ObjectSelector::Id(RegistryId::new("material").unwrap()),
        label: Some(b"label".to_vec()),
        algorithm: crate::DeriveAlgorithm::P256,
        usage: crate::DeriveUse::Secret,
        payload: None,
        hash: None,
        output_format: DeriveFormat::Raw,
        compressed: false,
        entropy: None,
    }
}

#[test]
fn resolve_mode_requires_entropy_when_label_is_omitted() {
    let mut params = params();
    params.label = None;

    let error = resolve_mode(&params).unwrap_err();
    assert!(matches!(
        error,
        Error::InvalidInput { field: "entropy", ref reason }
        if reason == "entropy is required when label is omitted"
    ));
}

#[test]
fn resolve_mode_uses_ephemeral_entropy_when_label_is_omitted() {
    let mut params = params();
    params.label = None;
    params.entropy = Some(Zeroizing::new(b"entropy".to_vec()));

    assert_eq!(
        resolve_mode(&params).unwrap(),
        DeriveMode::ephemeral(Vec::new(), b"entropy".to_vec())
    );
}
