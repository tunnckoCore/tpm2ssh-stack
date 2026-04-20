use serde::{Deserialize, Serialize};

use crate::model::Diagnostic;

pub const OUTPUT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct CommandPath {
    pub segments: Vec<String>,
}

impl CommandPath {
    pub fn from_segments(segments: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            segments: segments.into_iter().map(Into::into).collect(),
        }
    }

    pub fn display(&self) -> String {
        self.segments.join(" ")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ErrorEnvelope {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct OutputEnvelope<T> {
    pub schema_version: u32,
    pub ok: bool,
    pub command: CommandPath,
    pub result: Option<T>,
    pub diagnostics: Vec<Diagnostic>,
    pub error: Option<ErrorEnvelope>,
}

impl<T> OutputEnvelope<T> {
    pub fn ok(command: CommandPath, result: T, diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            schema_version: OUTPUT_SCHEMA_VERSION,
            ok: true,
            command,
            result: Some(result),
            diagnostics,
            error: None,
        }
    }

    pub fn err(command: CommandPath, diagnostics: Vec<Diagnostic>, error: ErrorEnvelope) -> Self {
        Self {
            schema_version: OUTPUT_SCHEMA_VERSION,
            ok: false,
            command,
            result: None,
            diagnostics,
            error: Some(error),
        }
    }
}
