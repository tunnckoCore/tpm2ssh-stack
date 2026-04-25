use sha3::{Digest, Keccak256};
use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum EthereumError {
    #[error("Ethereum public key must be 64 raw bytes or 65 uncompressed SEC1 bytes")]
    InvalidPublicKeyLength,
}

/// Returns the 20-byte Ethereum address for a secp256k1 public key.
///
/// Accepts either raw `x || y` (64 bytes) or uncompressed SEC1 (`0x04 || x || y`).
pub(crate) fn ethereum_address_bytes(public_key: &[u8]) -> Result<[u8; 20], EthereumError> {
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
pub(crate) fn to_checksum_address(address: &[u8; 20]) -> String {
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
pub(crate) fn checksum_address_from_public_key(public_key: &[u8]) -> Result<String, EthereumError> {
    Ok(to_checksum_address(&ethereum_address_bytes(public_key)?))
}

#[cfg(test)]
#[path = "ethereum.test.rs"]
mod tests;
