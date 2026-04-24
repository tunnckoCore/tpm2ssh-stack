use crate::{
    args::{CliError, EcdhArgs},
    commands::io::{read_input, selector_from_material, write_output},
};
use tpmctl_core::{ecdh as core_ecdh, pubkey::PublicKeyInput};

pub fn run(_runtime: tpmctl_core::RuntimeOptions, args: &EcdhArgs) -> Result<(), CliError> {
    let peer_public_key = parse_peer_public_key(read_input(&args.peer_pub)?);
    let request = core_ecdh::EcdhRequest {
        selector: selector_from_material(&args.material.material())?,
        peer_public_key,
        format: args.format.into(),
    };
    let bytes = request.execute()?;
    let output: tpmctl_core::OutputTarget = (&args.output).into();
    write_output(&output, &bytes)?;
    Ok(())
}

fn parse_peer_public_key(bytes: Vec<u8>) -> PublicKeyInput {
    if bytes.starts_with(b"-----BEGIN") {
        PublicKeyInput::Pem(String::from_utf8_lossy(&bytes).into_owned())
    } else if matches!(bytes.first(), Some(0x02 | 0x03 | 0x04)) {
        PublicKeyInput::Sec1(bytes)
    } else {
        PublicKeyInput::Der(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_public_key_dash_input_parser_detects_common_encodings() {
        assert!(matches!(
            parse_peer_public_key(b"-----BEGIN PUBLIC KEY-----".to_vec()),
            PublicKeyInput::Pem(_)
        ));
        assert!(matches!(
            parse_peer_public_key(vec![0x04, 1, 2]),
            PublicKeyInput::Sec1(_)
        ));
        assert!(matches!(
            parse_peer_public_key(vec![0x30, 1, 2]),
            PublicKeyInput::Der(_)
        ));
    }
}
