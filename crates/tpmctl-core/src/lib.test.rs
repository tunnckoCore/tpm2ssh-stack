use super::*;

#[test]
fn material_ref_from_id_or_handle_preserves_registry_id() {
    assert_eq!(
        MaterialRef::from_id_or_handle("org/acme/alice/main").unwrap(),
        MaterialRef::Id("org/acme/alice/main".to_owned())
    );
}

#[test]
fn material_ref_from_id_or_handle_parses_persistent_handle() {
    assert_eq!(
        MaterialRef::from_id_or_handle("0x81010010").unwrap(),
        MaterialRef::Handle(PersistentHandle::new(0x8101_0010).unwrap())
    );
}

#[test]
fn material_ref_from_id_or_handle_rejects_invalid_handle_prefixed_values() {
    let error = MaterialRef::from_id_or_handle("0xnot-a-handle").unwrap_err();
    assert!(matches!(error, Error::InvalidHandle { .. }));
}

#[test]
fn material_ref_selector_converts_id_to_object_selector_id() {
    let selector = MaterialRef::Id("org/acme/alice/main".to_owned())
        .selector()
        .unwrap();

    assert_eq!(
        selector,
        ObjectSelector::Id(RegistryId::new("org/acme/alice/main").unwrap())
    );
}

#[test]
fn material_ref_selector_converts_handle_to_object_selector_handle() {
    let handle = PersistentHandle::new(0x8101_0010).unwrap();
    let selector = MaterialRef::Handle(handle).selector().unwrap();

    assert_eq!(selector, ObjectSelector::Handle(handle));
}

#[test]
fn material_ref_selector_validates_registry_id() {
    let error = MaterialRef::Id("../escape".to_owned())
        .selector()
        .unwrap_err();
    assert!(matches!(error, Error::InvalidRegistryId { .. }));
}
