use crate::{CoreError, EccPublicKey, HashAlgorithm, Result};
use zeroize::Zeroizing;

use tss_esapi::{
    Context,
    constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK},
    handles::KeyHandle,
    interface_types::{algorithm::HashingAlgorithm, session_handles::AuthSession},
    structures::{Digest, HashScheme, HashcheckTicket, Signature, SignatureScheme},
    tss2_esys::TPMT_TK_HASHCHECK,
};

use super::{ecc_point_from_public_key, left_pad_copy};

/// Ask the TPM to produce a P-256 ECDSA signature over a digest.
pub fn sign_digest(
    context: &mut Context,
    key_handle: KeyHandle,
    digest: &[u8],
    hash: HashAlgorithm,
) -> Result<Vec<u8>> {
    let digest = Digest::try_from(digest.to_vec())
        .map_err(|source| CoreError::tpm("build Sign digest", source))?;
    let scheme = SignatureScheme::EcDsa {
        hash_scheme: HashScheme::new(hash.to_tpm_hash()),
    };
    let validation = null_hashcheck_ticket()?;
    let signature = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.sign(key_handle, digest, scheme, validation)
        })
        .map_err(|source| CoreError::tpm("Sign", source))?;
    p1363_from_tpm_signature(signature)
}

/// Ask the TPM to derive an ECDH shared secret with a peer public key.
pub fn ecdh_z_gen(
    context: &mut Context,
    key_handle: KeyHandle,
    peer_public_key: &EccPublicKey,
) -> Result<Zeroizing<Vec<u8>>> {
    let point = ecc_point_from_public_key(peer_public_key)?;
    let z = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.ecdh_z_gen(key_handle, point)
        })
        .map_err(|source| CoreError::tpm("ECDH_ZGen", source))?;
    let mut x = Zeroizing::new(vec![0_u8; 32]);
    left_pad_copy(z.x().value(), x.as_mut_slice(), "ECDH_ZGen x coordinate")?;
    Ok(x)
}

fn p1363_from_tpm_signature(signature: Signature) -> Result<Vec<u8>> {
    let Signature::EcDsa(signature) = signature else {
        return Err(CoreError::invalid(
            "signature",
            format!(
                "expected TPM ECDSA signature, got {:?}",
                signature.algorithm()
            ),
        ));
    };
    let mut p1363 = vec![0_u8; 64];
    left_pad_copy(
        signature.signature_r().value(),
        &mut p1363[..32],
        "signature r",
    )?;
    left_pad_copy(
        signature.signature_s().value(),
        &mut p1363[32..],
        "signature s",
    )?;
    Ok(p1363)
}

fn null_hashcheck_ticket() -> Result<HashcheckTicket> {
    let validation = TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: Default::default(),
    };
    validation
        .try_into()
        .map_err(|source| CoreError::tpm("build hashcheck ticket", source))
}

impl HashAlgorithm {
    pub(crate) fn to_tpm_hash(self) -> HashingAlgorithm {
        match self {
            Self::Sha256 => HashingAlgorithm::Sha256,
            Self::Sha384 => HashingAlgorithm::Sha384,
            Self::Sha512 => HashingAlgorithm::Sha512,
        }
    }
}
