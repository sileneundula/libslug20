use libslug::slugcrypt::internals::signature;
use serde::{Serialize,Deserialize};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, PartialOrd, Hash)]
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

pub enum SlugSecretKey {
    /// ShulginSigning: A hybrid signature scheme combining classical and post-quantum algorithms.
    ShulginSigning(signature::ShulginKeypair),
    /// EsphandSigning: A signature scheme based on the Esphand algorithm, designed for high security and efficiency.
    EsphandSigning(signature::EsphandKeypair),
    /// AbsolveSigning: A signature scheme that provides strong security guarantees while maintaining performance.
    AbsolveSigning,
}