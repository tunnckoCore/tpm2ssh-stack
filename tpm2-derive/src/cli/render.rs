use serde::Serialize;
use serde_json::{Value, json};

use crate::error::Result;
use crate::model::{CommandPath, Diagnostic, ErrorEnvelope, OutputEnvelope};

pub fn success<T: Serialize>(json: bool, command: CommandPath, result: T) -> Result<String> {
    success_with_diagnostics(json, command, result, Vec::new())
}

pub fn success_with_diagnostics<T: Serialize>(
    json: bool,
    command: CommandPath,
    result: T,
    diagnostics: Vec<Diagnostic>,
) -> Result<String> {
    render(json, OutputEnvelope::ok(command, result, diagnostics), false)
}

pub fn failure(
    json: bool,
    command: CommandPath,
    error: ErrorEnvelope,
    diagnostics: Vec<crate::model::Diagnostic>,
) -> Result<String> {
    render(json, OutputEnvelope::<Value>::err(command, diagnostics, error), true)
}

fn render<T: Serialize>(json: bool, envelope: OutputEnvelope<T>, force_full: bool) -> Result<String> {
    if json || force_full {
        return Ok(serde_json::to_string_pretty(&envelope)?);
    }

    let value = if let Some(result) = envelope.result {
        serde_json::to_value(result)?
    } else if let Some(error) = envelope.error {
        json!({
            "ok": false,
            "command": envelope.command.display(),
            "error": error,
        })
    } else {
        json!({ "ok": true, "command": envelope.command.display() })
    };

    Ok(serde_json::to_string_pretty(&value)?)
}
