use serde::{Serialize, Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};


use libslug::slugcrypt::internals::signature::{
    shulginsigning::{ShulginKeypair,ShulginSignature},
    absolvesigning::{AbsolveKeypair,AbsolveSignature},
    esphand_signature::{EsphandKeypair,EsphandSignature},
    ed25519::{ED25519PublicKey,ED25519SecretKey,ED25519Signature},
    ed448::{Ed448PublicKey,Ed448SecretKey,Ed448Signature},
    ecdsa::{ECDSAPublicKey, ECDSASecretKey, ECDSASignature},
    falcon::{Falcon1024PublicKey,Falcon1024SecretKey,Falcon1024Signature},
    ml_dsa::{MLDSA3PublicKey, MLDSA3SecretKey, MLDSA3Signature},
    schnorr::{SchnorrPublicKey, SchnorrSecretKey, SchnorrSignature},
    sphincs_plus::{SPHINCSPublicKey, SPHINCSSecretKey, SPHINCSSignature},
    bls::{BLSPublicKey, BLSSecretKey, BLSSignature}
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash, Zeroize, ZeroizeOnDrop)]
pub enum Slug20PublicKey {
    ShulginSigning(ShulginKeypair),
    AbsolveSigning(AbsolveKeypair),
    EsphandSigning(EsphandKeypair),
    Ed25519(ED25519PublicKey),
    Ed448(Ed448PublicKey),
    ECDSA(ECDSAPublicKey),
    Falcon(Falcon1024PublicKey),
    MLDSA(MLDSA3PublicKey),
    Schnorr(SchnorrPublicKey),
    SPHINCSPlus(SPHINCSPublicKey),
    BLS(BLSPublicKey),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash, Zeroize, ZeroizeOnDrop)]
pub enum Slug20SecretKey {
    ShulginSigning(ShulginKeypair),
    AbsolveSigning(AbsolveKeypair),
    EsphandSigning(EsphandKeypair),
    Ed25519(ED25519SecretKey), // derive public key
    Ed448(Ed448SecretKey), 
    ECDSA(ECDSASecretKey),
    Falcon(Falcon1024SecretKey),
    MLDSA(MLDSA3SecretKey),
    Schnorr(SchnorrSecretKey),
    SPHINCSPlus(SPHINCSSecretKey),
    BLS(BLSSecretKey),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash, Zeroize, ZeroizeOnDrop)]
pub enum Slug20Signature {
    ShulginSigning(ShulginSignature),
    AbsolveSigning(AbsolveSignature),
    EsphandSigning(EsphandSignature),
    Ed25519(ED25519Signature),
    Ed448(Ed448Signature),
    ECDSA(ECDSASignature),
    Falcon(Falcon1024Signature),
    MLDSA(MLDSA3Signature),
    Schnorr(SchnorrSignature),
    SPHINCSPlus(SPHINCSSignature),
    BLS(BLSSignature),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash, Zeroize, ZeroizeOnDrop)]
pub enum Slug20Algorithm {
    ShulginSigning,
    AbsolveSigning,
    EsphandSigning,
    Ed25519,
    Ed448,
    ECDSA,
    Falcon,
    MLDSA,
    Schnorr,
    SPHINCSPlus,
    BLS,
}