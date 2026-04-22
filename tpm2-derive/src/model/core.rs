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
    All,
    Sign,
    Verify,
    SshAgent,
    Derive,
    Encrypt,
    Decrypt,
}

impl UseCase {
    pub const fn is_all(self) -> bool {
        matches!(self, Self::All)
    }

    /// Returns the set of currently-wired use-cases allowed for the given mode.
    pub fn allowed_for_mode(mode: Mode) -> &'static [UseCase] {
        match mode {
            Mode::Prf => &[UseCase::Derive, UseCase::Encrypt, UseCase::Decrypt],
            Mode::Native => &[UseCase::Sign, UseCase::Verify],
            Mode::Seed => &[
                UseCase::Sign,
                UseCase::Verify,
                UseCase::SshAgent,
                UseCase::Derive,
                UseCase::Encrypt,
                UseCase::Decrypt,
            ],
        }
    }

    /// Check whether all given use-cases are compatible with the given mode.
    /// Returns `Ok(())` or an error describing the incompatibility.
    pub fn validate_for_mode(uses: &[UseCase], mode: Mode) -> crate::error::Result<()> {
        let allowed = Self::allowed_for_mode(mode);
        for use_case in uses {
            if use_case.is_all() {
                return Err(crate::error::Error::PolicyRefusal(format!(
                    "use '{use_case:?}' must be expanded before validating {mode:?} mode compatibility"
                )));
            }

            if !allowed.contains(use_case) {
                return Err(crate::error::Error::PolicyRefusal(format!(
                    "use '{use_case:?}' is not allowed in {mode:?} mode; allowed uses: {allowed:?}"
                )));
            }
        }
        Ok(())
    }
}
