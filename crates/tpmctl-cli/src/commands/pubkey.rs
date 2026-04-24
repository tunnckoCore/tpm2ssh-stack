use crate::{
    args::{CliError, PubkeyArgs},
    commands::io::{selector_from_material, write_output_with_force},
};
use tpmctl_core::{
    EccPublicKey, KeyUsage, MaterialRef, ObjectDescriptor, ObjectSelector, RegistryId, Store,
    pubkey as core_pubkey, store::ObjectUsage,
};

pub fn run(runtime: tpmctl_core::RuntimeOptions, args: &PubkeyArgs) -> Result<(), CliError> {
    let material = args.material.material();
    let request = core_pubkey::PubkeyRequest {
        selector: selector_from_material(&material)?,
        format: args.format.into(),
    };
    let bytes = match &material {
        MaterialRef::Id(id) => cached_public_key(&runtime, id, &request)?,
        MaterialRef::Handle(_) => {
            let store = Store::new(runtime.store.root.clone());
            request.execute(&store)?
        }
    };
    let output: tpmctl_core::OutputTarget = (&args.output).into();
    write_output_with_force(&output, &bytes, args.force)?;
    Ok(())
}

fn cached_public_key(
    runtime: &tpmctl_core::RuntimeOptions,
    id: &str,
    request: &core_pubkey::PubkeyRequest,
) -> Result<Vec<u8>, CliError> {
    let id = RegistryId::new(id.to_owned())?;
    let store = Store::new(runtime.store.root.clone());
    let entry = store.load_key(&id)?;
    let public_key = cached_p256_public_key(&entry)?;
    let descriptor = ObjectDescriptor {
        selector: ObjectSelector::Id(id),
        usage: key_usage(entry.metadata.usage),
        curve: Some(tpmctl_core::EccCurve::P256),
        hash: None,
        public_key: Some(public_key),
    };
    Ok(request.encode_descriptor_public_key(&descriptor)?)
}

fn cached_p256_public_key(
    entry: &tpmctl_core::store::StoredObjectEntry,
) -> Result<EccPublicKey, CliError> {
    if let Some(sec1_hex) = &entry.metadata.public_key {
        let sec1 = hex::decode(sec1_hex).map_err(|error| {
            tpmctl_core::CoreError::invalid(
                "public_key",
                format!("invalid cached public key hex: {error}"),
            )
        })?;
        return Ok(EccPublicKey::p256_sec1(sec1)?);
    }

    if let Some(public_pem) = &entry.public_pem {
        let pem = String::from_utf8(public_pem.clone()).map_err(|error| {
            tpmctl_core::CoreError::invalid(
                "public_key",
                format!("cached public PEM is not UTF-8: {error}"),
            )
        })?;
        return Ok(core_pubkey::PublicKeyInput::Pem(pem).into_p256()?);
    }

    Err(tpmctl_core::CoreError::invalid(
        "public_key",
        "registry entry has no cached public key material",
    )
    .into())
}

fn key_usage(usage: ObjectUsage) -> KeyUsage {
    match usage {
        ObjectUsage::Sign => KeyUsage::Sign,
        ObjectUsage::Ecdh => KeyUsage::Ecdh,
        ObjectUsage::Hmac => KeyUsage::Hmac,
        ObjectUsage::Sealed => KeyUsage::Sealed,
    }
}
