use std::env;

/// Source used to resolve TPM TCTI configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TctiSource {
    Tpm2ToolsTcti,
    Tcti,
    TestTcti,
    DefaultDevice,
}

/// Resolved TCTI configuration. `name_conf == None` means use device TCTI.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TctiConfig {
    pub source: TctiSource,
    pub name_conf: Option<String>,
}

impl TctiConfig {
    /// Resolve TCTI using plan precedence: `TPM2TOOLS_TCTI`, `TCTI`, `TEST_TCTI`, device.
    pub fn resolve() -> Self {
        for (name, source) in [
            ("TPM2TOOLS_TCTI", TctiSource::Tpm2ToolsTcti),
            ("TCTI", TctiSource::Tcti),
            ("TEST_TCTI", TctiSource::TestTcti),
        ] {
            if let Ok(value) = env::var(name) {
                if !value.trim().is_empty() {
                    return Self {
                        source,
                        name_conf: Some(value),
                    };
                }
            }
        }
        Self {
            source: TctiSource::DefaultDevice,
            name_conf: None,
        }
    }
}
