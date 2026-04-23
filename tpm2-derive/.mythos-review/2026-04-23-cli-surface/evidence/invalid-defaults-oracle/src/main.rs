use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use secrecy::SecretBox;
use tpm2_derive::backend::{CommandInvocation, CommandOutput, CommandRunner, HeuristicProbe};
use tpm2_derive::model::{
    Algorithm, DerivationOverrides, Identity, IdentityCreateRequest, IdentityDerivationDefaults,
    IdentityModeResolution, Mode, ModePreference, StateLayout, UseCase,
};
use tpm2_derive::ops;
use tpm2_derive::ops::encrypt;
use tpm2_derive::ops::seed::{
    HkdfSha256SeedDeriver, SeedBackend, SeedCreateRequest, SeedIdentity, SeedMaterial,
    SeedOpenAuthSource,
};
use tpm2_derive::{Error, Result};

struct NoopRunner;
impl CommandRunner for NoopRunner {
    fn run(&self, _invocation: &CommandInvocation) -> CommandOutput {
        panic!("CommandRunner should not be used for these seed-mode oracles")
    }
}

struct FixedSeedBackend;
impl SeedBackend for FixedSeedBackend {
    fn seal_seed(&self, _request: &SeedCreateRequest) -> Result<()> {
        Ok(())
    }

    fn unseal_seed(
        &self,
        _identity: &SeedIdentity,
        _auth_source: &SeedOpenAuthSource,
    ) -> Result<SeedMaterial> {
        Ok(SecretBox::new(Box::new(vec![0x41; 32])))
    }
}

fn temp_state_root(label: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tpm2-derive-oracle-{label}-{}-{now}",
        std::process::id()
    ))
}

fn must_fail_later(identity: &Identity, case: &str) -> String {
    let err = encrypt::encrypt(
        identity,
        b"oracle plaintext",
        &DerivationOverrides::default(),
        &NoopRunner,
        &FixedSeedBackend,
        &HkdfSha256SeedDeriver,
    )
    .expect_err("invalid defaults should fail when the identity is actually used");

    match err {
        Error::Validation(message) => format!("{case}: later encrypt rejected identity with validation error: {message}"),
        other => panic!("{case}: expected validation error, got {other:?}"),
    }
}

fn main() {
    let mut lines = Vec::new();

    let whitespace_purpose_root = temp_state_root("whitespace-purpose");
    let whitespace_purpose = ops::resolve_identity(
        &HeuristicProbe,
        &IdentityCreateRequest {
            identity: "whitespace-purpose".to_string(),
            algorithm: Algorithm::Ed25519,
            uses: vec![UseCase::Encrypt],
            requested_mode: ModePreference::Seed,
            defaults: DerivationOverrides {
                org: Some("com.example".to_string()),
                purpose: Some("   ".to_string()),
                context: BTreeMap::new(),
            },
            state_dir: Some(whitespace_purpose_root.clone()),
            dry_run: true,
        },
    )
    .expect("identity creation unexpectedly rejected whitespace purpose at setup time");
    lines.push(format!(
        "create_whitespace_purpose: accepted identity defaults {:?}",
        whitespace_purpose.identity.defaults
    ));
    lines.push(must_fail_later(&whitespace_purpose.identity, "create_whitespace_purpose"));

    let empty_context_root = temp_state_root("empty-context");
    let empty_context = ops::resolve_identity(
        &HeuristicProbe,
        &IdentityCreateRequest {
            identity: "empty-context".to_string(),
            algorithm: Algorithm::Ed25519,
            uses: vec![UseCase::Encrypt],
            requested_mode: ModePreference::Seed,
            defaults: DerivationOverrides {
                org: Some("com.example".to_string()),
                purpose: Some("app".to_string()),
                context: BTreeMap::from([("tenant".to_string(), "".to_string())]),
            },
            state_dir: Some(empty_context_root.clone()),
            dry_run: true,
        },
    )
    .expect("identity creation unexpectedly rejected empty context value at setup time");
    lines.push(format!(
        "create_empty_context_value: accepted identity defaults {:?}",
        empty_context.identity.defaults
    ));
    lines.push(must_fail_later(&empty_context.identity, "create_empty_context_value"));

    let load_root = temp_state_root("load-invalid");
    let layout = StateLayout::new(load_root.clone());
    let invalid_persisted = Identity::with_defaults(
        "loaded-invalid".to_string(),
        Algorithm::Ed25519,
        vec![UseCase::Encrypt],
        IdentityModeResolution {
            requested: ModePreference::Seed,
            resolved: Mode::Seed,
            reasons: vec!["oracle".to_string()],
        },
        IdentityDerivationDefaults {
            org: Some("com.example".to_string()),
            purpose: Some("app".to_string()),
            context: BTreeMap::from([("tenant".to_string(), "".to_string())]),
        },
        layout.clone(),
    );
    invalid_persisted.persist().expect("persist invalid identity");
    let loaded = Identity::load_named("loaded-invalid", Some(load_root.clone()))
        .expect("load_named unexpectedly rejected invalid persisted defaults");
    lines.push(format!(
        "load_invalid_defaults: load_named accepted persisted defaults {:?}",
        loaded.defaults
    ));
    lines.push(must_fail_later(&loaded, "load_invalid_defaults"));

    println!("{}", lines.join("\n"));

    let _ = fs::remove_dir_all(whitespace_purpose_root);
    let _ = fs::remove_dir_all(empty_context_root);
    let _ = fs::remove_dir_all(load_root);
}
