use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Native,
    Prf,
    Seed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ModePreference {
    #[default]
    Auto,
    Native,
    Prf,
    Seed,
}

impl ModePreference {
    pub const fn explicit(self) -> Option<Mode> {
        match self {
            Self::Auto => None,
            Self::Native => Some(Mode::Native),
            Self::Prf => Some(Mode::Prf),
            Self::Seed => Some(Mode::Seed),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum Algorithm {
    P256,
    Ed25519,
    Secp256k1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum UseCase {
    Sign,
    Verify,
    Derive,
    Ssh,
    SshAgent,
    Ethereum,
    Encrypt,
    Decrypt,
}
