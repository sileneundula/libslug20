use libslug::slugcrypt::internals::signature;
use serde::{Serialize,Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};
use crate::constants::*;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, PartialOrd, Hash, Zeroize, ZeroizeOnDrop)]
pub enum SlugPublicKey {
    /// ShulginSigning: A hybrid signature scheme combining classical and post-quantum algorithms.
    ShulginSigning(signature::shulginsigning::ShulginKeypair),
    /// EsphandSigning: A signature scheme based on the Esphand algorithm, designed for high security and efficiency.
    EsphandSigning(signature::esphand_signature::EsphandKeypair),
    /// AbsolveSigning: A signature scheme that provides strong security guarantees while maintaining performance.
    AbsolveSigning(signature::absolvesigning::AbsolveKeypair),
    
    //=====CLASSICAL======//
    ED25519(signature::ed25519::ED25519PublicKey),
    ED448(signature::ed448::Ed448PublicKey),
    ECDSA(signature::ecdsa::ECDSAPublicKey),
    BLS12_381(signature::bls::BLSPublicKey),
    SchnorrOverRistretto(signature::schnorr::SchnorrPublicKey),

    //=====PQ=====//
    SPHINCS(signature::sphincs_plus::SPHINCSPublicKey),
    FALCON1024(signature::falcon::Falcon1024PublicKey),
    MLDSA3(signature::ml_dsa::MLDSA3PublicKey),
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, PartialOrd, Hash, Zeroize, ZeroizeOnDrop)]
pub enum SlugSecretKey {
    /// ShulginSigning: A hybrid signature scheme combining classical and post-quantum algorithms.
    ShulginSigning(signature::shulginsigning::ShulginKeypair),
    /// EsphandSigning: A signature scheme based on the Esphand algorithm, designed for high security and efficiency.
    EsphandSigning(signature::esphand_signature::EsphandKeypair),
    /// AbsolveSigning: A signature scheme that provides strong security guarantees while maintaining performance.
    AbsolveSigning(signature::absolvesigning::AbsolveKeypair),

    //=====CLASSICAL=====//
    ED25519(signature::ed25519::ED25519SecretKey),
    ED448(signature::ed448::Ed448SecretKey),
    ECDSA(signature::ecdsa::ECDSASecretKey),
    BLS12_381(signature::bls::BLSSecretKey),
    SchnorrOverRistretto(signature::schnorr::SchnorrSecretKey),

    //=====PQ=====//
    SPHINCS((signature::sphincs_plus::SPHINCSSecretKey, signature::sphincs_plus::SPHINCSPublicKey)),
    FALCON1024((signature::falcon::Falcon1024SecretKey, signature::falcon::Falcon1024PublicKey)),
    MLDSA3((signature::ml_dsa::MLDSA3SecretKey, signature::ml_dsa::MLDSA3PublicKey)),
}

impl SlugSecretKey {
    pub fn as_alg(&self) -> Algorithms {
        match self {
            Self::ShulginSigning(_) => return Algorithms::ShulginSigning,
            Self::EsphandSigning(_) => return Algorithms::EsphandSigning,
            Self::AbsolveSigning(_) => return Algorithms::AbsolveSigning,
            Self::ED25519(_) => return Algorithms::ED25519,
            Self::ED448(_) => return Algorithms::ED448,
            Self::ECDSA(_) => return Algorithms::ECDSA,
            Self::BLS12_381(_) => return Algorithms::BLS12_381,
            Self::SchnorrOverRistretto(_) => return Algorithms::Schnorr,
            Self::SPHINCS(_) => return Algorithms::Sphincs,
            Self::FALCON1024(_) => return Algorithms::Falcon1024,
            Self::MLDSA3(_) => return Algorithms::MLDSA3,
        }
    }

}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, PartialOrd, Hash, Zeroize, ZeroizeOnDrop)]
pub enum SlugSignature {
    /// ShulginSigning: A hybrid signature scheme combining classical and post-quantum algorithms.
    ShulginSigning(signature::shulginsigning::ShulginSignature),
    /// EsphandSigning: A signature scheme based on the Esphand algorithm, designed for high security and efficiency.
    EsphandSigning(signature::esphand_signature::EsphandSignature),
    /// AbsolveSigning: A signature scheme that provides strong security guarantees while maintaining performance.
    AbsolveSigning(signature::absolvesigning::AbsolveSignature),

    //=====CLASSICAL=====//
    ED25519(signature::ed25519::ED25519Signature),
    ED448(signature::ed448::Ed448Signature),
    ECDSA(signature::ecdsa::ECDSASignature,signature::ecdsa::ECDSASignatureRecoveryID),
    BLS12_381(signature::bls::BLSSignature),
    SchnorrOverRistretto(signature::schnorr::SchnorrSignature),

    //=====PQ=====//
    SPHINCS(signature::sphincs_plus::SPHINCSSignature),
    FALCON1024(signature::falcon::Falcon1024Signature),
    MLDSA3(signature::ml_dsa::MLDSA3Signature),
}

impl SlugPublicKey {
    pub fn as_alg(&self) -> Algorithms {
        match self {
            Self::ShulginSigning(_) => return Algorithms::ShulginSigning,
            Self::EsphandSigning(_) => return Algorithms::EsphandSigning,
            Self::AbsolveSigning(_) => return Algorithms::AbsolveSigning,
            Self::ED25519(_) => return Algorithms::ED25519,
            Self::ED448(_) => return Algorithms::ED448,
            Self::ECDSA(_) => return Algorithms::ECDSA,
            Self::BLS12_381(_) => return Algorithms::BLS12_381,
            Self::SchnorrOverRistretto(_) => return Algorithms::Schnorr,
            Self::SPHINCS(_) => return Algorithms::Sphincs,
            Self::FALCON1024(_) => return Algorithms::Falcon1024,
            Self::MLDSA3(_) => return Algorithms::MLDSA3,
        }
    }
}

impl SlugSignature {
    pub fn as_alg(&self) -> Algorithms {
        match self {
            Self::ShulginSigning(_) => return Algorithms::ShulginSigning,
            Self::EsphandSigning(_) => return Algorithms::EsphandSigning,
            Self::AbsolveSigning(_) => return Algorithms::AbsolveSigning,
            Self::ED25519(_) => return Algorithms::ED25519,
            Self::ED448(_) => return Algorithms::ED448,
            Self::ECDSA(_, _) => return Algorithms::ECDSA,
            Self::BLS12_381(_) => return Algorithms::BLS12_381,
            Self::SchnorrOverRistretto(_) => return Algorithms::Schnorr,
            Self::SPHINCS(_) => return Algorithms::Sphincs,
            Self::FALCON1024(_) => return Algorithms::Falcon1024,
            Self::MLDSA3(_) => return Algorithms::MLDSA3,
        }
    }
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, PartialOrd, Hash, Zeroize, ZeroizeOnDrop)]
pub enum Algorithms {
    ShulginSigning,
    EsphandSigning,
    AbsolveSigning,
    ED25519,
    ED448,
    ECDSA,
    Schnorr,
    BLS12_381,
    Falcon1024,
    Sphincs,
    MLDSA3,
}

impl Algorithms {
    /// # Cipher Suite Output
    /// 
    /// Outputs the cipher suite identifier for the given algorithm using:
    /// 
    /// - [X] slug20/ShulginSigning
    /// - [X] slug20/EsphandSigning
    /// - [X] slug20/AbsolveSigning
    /// - [X] slug20/ed25519
    /// - [X] slug20/ed448
    /// - [X] slug20/ecdsa
    /// - [X] slug20/bls12-381
    /// - [X] slug20/schnorr
    /// - [X] slug20/Falcon1024
    /// - [X] slug20/sphincs_plus
    /// - [X] slug20/ml-dsa3
    /// 
    pub fn cipher_suite(&self) -> &str {
        match self {
            Self::ShulginSigning => return SLUG20_SHULGINSIGNING_ID,
            Self::EsphandSigning => return SLUG20_ESPHANDSIGNING_ID,
            Self::AbsolveSigning => return SLUG20_ABSOLVESIGNING_ID,
            Self::ED25519 => return SLUG20_ED25519_ID,
            Self::ED448 => return SLUG20_ED448_ID,
            Self::ECDSA => return SLUG20_ECDSA_SECP256k1_ID,
            Self::Schnorr => return SLUG20_SCHNORR_ID,
            Self::BLS12_381 => return SLUG20_BLS_12_381_ID,
            Self::Falcon1024 => return SLUG20_FALCON1024_ID,
            Self::Sphincs => return SLUG20_SPHINCS_PLUS_ID,
            Self::MLDSA3 => return SLUG20_MLDSA3_ID,
        }
    }
}