use std::process::Command;

fn tpmctl() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tpmctl"))
}

#[test]
fn help_and_version_exit_successfully() {
    let help = tpmctl().arg("--help").output().expect("run tpmctl --help");
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("TPM-backed identities"));

    let version = tpmctl()
        .arg("--version")
        .output()
        .expect("run tpmctl --version");
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains("tpmctl"));
}

#[test]
fn parser_rejects_legacy_handle_flag() {
    let output = tpmctl()
        .args(["pubkey", "--handle", "0x81010010"])
        .output()
        .expect("run tpmctl parser validation");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument '--handle'"));
}
