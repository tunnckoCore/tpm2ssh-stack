
use super::*;

fn parse_address(value: &str) -> [u8; 20] {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value)).unwrap();
    let mut out = [0_u8; 20];
    out.copy_from_slice(&bytes);
    out
}

#[test]
fn eip55_known_vectors() {
    let vectors = [
        "0x52908400098527886E0F7030069857D2E4169EE7",
        "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
        "0xde709f2102306220921060314715629080e2fb77",
        "0x27b1fdb04752bbc536007a920d24acb045561c26",
        "0x5AEDA56215b167893e80B4fE645BA6d5Bab767DE",
    ];

    for vector in vectors {
        let address = parse_address(vector);
        assert_eq!(to_checksum_address(&address), vector);
    }
}

#[test]
fn rejects_wrong_public_key_length() {
    assert_eq!(
        ethereum_address_bytes(&[0_u8; 33]),
        Err(EthereumError::InvalidPublicKeyLength),
    );
}
