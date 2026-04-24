use sha3::{Digest, Keccak256};
use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EthereumError {
    #[error("Ethereum public key must be 64 raw bytes or 65 uncompressed SEC1 bytes")]
    InvalidPublicKeyLength,
}

/// Returns the 20-byte Ethereum address for a secp256k1 public key.
///
/// Accepts either raw `x || y` (64 bytes) or uncompressed SEC1 (`0x04 || x || y`).
pub fn ethereum_address_bytes(public_key: &[u8]) -> Result<[u8; 20], EthereumError> {
    let raw = match public_key.len() {
        64 => public_key,
        65 if public_key[0] == 0x04 => &public_key[1..],
        _ => return Err(EthereumError::InvalidPublicKeyLength),
    };

    let digest = Keccak256::digest(raw);
    let mut address = [0_u8; 20];
    address.copy_from_slice(&digest[12..]);
    Ok(address)
}

/// Formats a 20-byte address with EIP-55 checksum casing.
pub fn to_checksum_address(address: &[u8; 20]) -> String {
    let lower = hex::encode(address);
    let hash = Keccak256::digest(lower.as_bytes());

    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (index, ch) in lower.chars().enumerate() {
        let hash_byte = hash[index / 2];
        let nibble = if index % 2 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0x0f
        };
        if ch.is_ascii_hexdigit() && ch.is_ascii_alphabetic() && nibble >= 8 {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Derives and formats an EIP-55 address from a secp256k1 public key.
pub fn checksum_address_from_public_key(public_key: &[u8]) -> Result<String, EthereumError> {
    Ok(to_checksum_address(&ethereum_address_bytes(public_key)?))
}

#[cfg(test)]
mod tests {
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
}
