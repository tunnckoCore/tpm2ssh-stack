use crate::{
    args::{CliError, SealArgs},
    commands::io::{read_input, seal_target_from_destination, write_stdout, write_stdout_line},
};
use tpmctl_core::{CommandContext, SealTarget, StoreOptions, seal as core_seal};
use zeroize::Zeroizing;

pub fn run(runtime: tpmctl_core::RuntimeOptions, args: &SealArgs) -> Result<(), CliError> {
    let destination = args.destination();
    let target = seal_target_from_destination(&destination)?;
    let selector = match target {
        SealTarget::Id(id) => tpmctl_core::ObjectSelector::Id(id),
        SealTarget::Handle(handle) => tpmctl_core::ObjectSelector::Handle(handle),
    };
    let request = core_seal::SealRequest {
        selector,
        input: Zeroizing::new(read_input(&args.input)?),
        force: args.force,
    };
    let command = CommandContext {
        store: StoreOptions {
            root: Some(runtime.store.root.clone()),
        },
        tcti: None,
    };
    let result = request.execute_with_context(&command)?;
    write_seal_result(runtime.json, &result.selector)?;
    Ok(())
}

fn write_seal_result(json: bool, selector: &tpmctl_core::ObjectSelector) -> Result<(), CliError> {
    if json {
        let payload = match selector {
            tpmctl_core::ObjectSelector::Id(id) => {
                serde_json::json!({ "sealed_id": id.to_string() })
            }
            tpmctl_core::ObjectSelector::Handle(handle) => {
                serde_json::json!({ "sealed_at": handle.to_string() })
            }
        };
        write_stdout(&serde_json::to_vec_pretty(&payload).expect("seal JSON is serializable"))?;
        write_stdout(b"\n")?;
    } else {
        match selector {
            tpmctl_core::ObjectSelector::Id(id) => {
                write_stdout_line(&format!("sealed data as {id}"))?
            }
            tpmctl_core::ObjectSelector::Handle(handle) => {
                write_stdout_line(&format!("sealed data at {handle}"))?
            }
        }
    }
    Ok(())
}
