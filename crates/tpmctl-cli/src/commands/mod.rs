use crate::args::Cli;

pub fn dispatch(_cli: &Cli) -> tpmctl_core::Result<serde_json::Value> {
    Err(tpmctl_core::TpmctlError::NotImplemented(
        "cli command dispatch",
    ))
}
