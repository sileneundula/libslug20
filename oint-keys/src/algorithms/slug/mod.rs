use libslug::slugcrypt::internals::signature;
use serde::{Serialize,Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};

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
    ECDSA(signature::ecdsa::ECDSASignature),
    BLS12_381(signature::bls::BLSSignature),
    SchnorrOverRistretto(signature::schnorr::SchnorrSignature),

    //=====PQ=====//
    SPHINCS(signature::sphincs_plus::SPHINCSSignature),
    FALCON1024(signature::falcon::Falcon1024Signature),
    MLDSA3(signature::ml_dsa::MLDSA3Signature),
}

impl SlugSignature {
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