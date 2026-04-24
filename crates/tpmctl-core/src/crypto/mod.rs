pub mod derive;
pub mod ed25519;
pub mod ethereum;
pub mod p256;
pub mod secp256k1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum DerivedKeyCurve {
    P256,
    Ed25519,
    Secp256k1,
}
