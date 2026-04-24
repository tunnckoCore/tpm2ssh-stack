use crate::{
    args::{CliError, KeyUsageArg, KeygenArgs},
    commands::io::{write_stdout, write_stdout_line},
};
use tpmctl_core::{RegistryId, keygen as core_keygen};

pub fn run(runtime: tpmctl_core::RuntimeOptions, args: &KeygenArgs) -> Result<(), CliError> {
    let request = core_keygen::KeygenRequest {
        usage: keygen_usage(args.usage),
        id: RegistryId::new(args.id.clone())?,
        persist_at: args.handle,
        force: args.force,
    };
    let result = request.execute()?;

    if runtime.json {
        let payload = serde_json::json!({
            "id": result.id.to_string(),
            "usage": result.usage.object_usage().to_string(),
            "handle": result.persistent_handle.map(|handle| handle.to_string()),
        });
        write_stdout(&serde_json::to_vec_pretty(&payload).expect("keygen JSON is serializable"))?;
        write_stdout(b"\n")?;
    } else {
        let mut message = format!(
            "created {} identity {}",
            result.usage.object_usage(),
            result.id
        );
        if let Some(handle) = result.persistent_handle {
            message.push_str(&format!(" at {handle}"));
        }
        write_stdout_line(&message)?;
    }

    Ok(())
}

fn keygen_usage(value: KeyUsageArg) -> core_keygen::KeygenUsage {
    match value {
        KeyUsageArg::Sign => core_keygen::KeygenUsage::Sign,
        KeyUsageArg::Ecdh => core_keygen::KeygenUsage::Ecdh,
        KeyUsageArg::Hmac => core_keygen::KeygenUsage::Hmac,
    }
}
