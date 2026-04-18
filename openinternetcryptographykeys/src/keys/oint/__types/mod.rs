use serde::{Serialize, Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};

use libslug::slugcrypt::traits::{IntoStandardPem,FromStandardPem,FromBincode,IntoBincode};


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

impl Slug20SecretKey {
    pub fn as_pem_label_secret(&self) -> String {
        match self {
            Slug20SecretKey::ShulginSigning(_) => ShulginKeypair::label_for_standard_pem_secret(),
            Slug20SecretKey::AbsolveSigning(_) => AbsolveKeypair::label_for_standard_pem_secret(),
            Slug20SecretKey::EsphandSigning(_) => EsphandKeypair::label_for_standard_pem_secret(),
            Slug20SecretKey::Ed25519(_) => ED25519SecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::Ed448(_) => Ed448SecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::ECDSA(_) => ECDSASecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::Falcon(_) => Falcon1024SecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::MLDSA(_) => MLDSA3SecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::Schnorr(_) => SchnorrSecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::SPHINCSPlus(_) => SPHINCSSecretKey::label_for_standard_pem_secret(),
            Slug20SecretKey::BLS(_) => BLSSecretKey::label_for_standard_pem_secret(),
        }
    }
    pub fn get_pem_label_secret(alg: Slug20Algorithm) -> String {
        match alg {
            Slug20Algorithm::ShulginSigning => ShulginKeypair::label_for_standard_pem_secret(),
            Slug20Algorithm::AbsolveSigning => AbsolveKeypair::label_for_standard_pem_secret(),
            Slug20Algorithm::EsphandSigning => EsphandKeypair::label_for_standard_pem_secret(),
            Slug20Algorithm::Ed25519 => ED25519SecretKey::label_for_standard_pem_secret(),
            Slug20Algorithm::Ed448 => Ed448SecretKey::label_for_standard_pem_secret(),
            Slug20Algorithm::ECDSA => ECDSASecretKey::label_for_standard_pem_secret(),
            Slug20Algorithm::Falcon => Falcon1024SecretKey::label_for_standard_pem_secret(),
            Slug20Algorithm::MLDSA => MLDSA3SecretKey::label_for_standard_pem_secret(),
            Slug20Algorithm::Schnorr => SchnorrSecretKey::label_for_standard_pem_secret(),
            Slug20Algorithm::SPHINCSPlus => SPHINCSSecretKey::label_for_standard_pem_secret(),
            Slug20Algorithm::BLS => BLSSecretKey::label_for_standard_pem_secret(),
        }
    }
}
impl Slug20PublicKey {
    pub fn as_pem_label_public(&self) -> String {
        match self {
            Slug20PublicKey::ShulginSigning(_) => ShulginKeypair::label_for_standard_pem(),
            Slug20PublicKey::AbsolveSigning(_) => AbsolveKeypair::label_for_standard_pem(),
            Slug20PublicKey::EsphandSigning(_) => EsphandKeypair::label_for_standard_pem(),
            Slug20PublicKey::Ed25519(_) => ED25519PublicKey::label_for_standard_pem(),
            Slug20PublicKey::Ed448(_) => Ed448PublicKey::label_for_standard_pem(),
            Slug20PublicKey::ECDSA(_) => ECDSAPublicKey::label_for_standard_pem(),
            Slug20PublicKey::Falcon(_) => Falcon1024PublicKey::label_for_standard_pem(),
            Slug20PublicKey::MLDSA(_) => MLDSA3PublicKey::label_for_standard_pem(),
            Slug20PublicKey::Schnorr(_) => SchnorrPublicKey::label_for_standard_pem(),
            Slug20PublicKey::SPHINCSPlus(_) => SPHINCSPublicKey::label_for_standard_pem(),
            Slug20PublicKey::BLS(_) => BLSPublicKey::label_for_standard_pem(),
        }
    }
    pub fn get_pem_label_public(alg: Slug20Algorithm) -> String {
        match alg {
            Slug20Algorithm::ShulginSigning => ShulginKeypair::label_for_standard_pem(),
            Slug20Algorithm::AbsolveSigning => AbsolveKeypair::label_for_standard_pem(),
            Slug20Algorithm::EsphandSigning => EsphandKeypair::label_for_standard_pem(),
            Slug20Algorithm::Ed25519 => ED25519PublicKey::label_for_standard_pem(),
            Slug20Algorithm::Ed448 => Ed448PublicKey::label_for_standard_pem(),
            Slug20Algorithm::ECDSA => ECDSAPublicKey::label_for_standard_pem(),
            Slug20Algorithm::Falcon => Falcon1024PublicKey::label_for_standard_pem(),
            Slug20Algorithm::MLDSA => MLDSA3PublicKey::label_for_standard_pem(),
            Slug20Algorithm::Schnorr => SchnorrPublicKey::label_for_standard_pem(),
            Slug20Algorithm::SPHINCSPlus => SPHINCSPublicKey::label_for_standard_pem(),
            Slug20Algorithm::BLS => BLSPublicKey::label_for_standard_pem(),
        }
    }
}

impl Slug20Signature {
    pub fn as_pem_label_signature(&self) -> String {
        match self {
            Slug20Signature::ShulginSigning(sig) => ShulginSignature::label_for_standard_pem(),
            Slug20Signature::AbsolveSigning(sig) => AbsolveSignature::label_for_standard_pem(),
            Slug20Signature::EsphandSigning(sig) => EsphandSignature::label_for_standard_pem(),
            Slug20Signature::BLS(sig) => BLSSignature::label_for_standard_pem(),
            Slug20Signature::ECDSA(sig) => ECDSASignature::label_for_standard_pem(),
            Slug20Signature::Ed25519(sig) => ED25519Signature::label_for_standard_pem(),
            Slug20Signature::Ed448(sig) => Ed448Signature::label_for_standard_pem(),
            Slug20Signature::Falcon(sig) => Falcon1024Signature::label_for_standard_pem(),
            Slug20Signature::MLDSA(sig) => MLDSA3Signature::label_for_standard_pem(),
            Slug20Signature::Schnorr(sig) => SchnorrSignature::label_for_standard_pem(),
            Slug20Signature::SPHINCSPlus(sig) => SPHINCSSignature::label_for_standard_pem(),
        }
    }
    pub fn get_pem_label_signature(alg: Slug20Algorithm) -> String {
        match alg {
            Slug20Algorithm::ShulginSigning => ShulginSignature::label_for_standard_pem(),
            Slug20Algorithm::AbsolveSigning => AbsolveSignature::label_for_standard_pem(),
            Slug20Algorithm::EsphandSigning => EsphandSignature::label_for_standard_pem(),
            Slug20Algorithm::BLS => BLSSignature::label_for_standard_pem(),
            Slug20Algorithm::ECDSA => ECDSASignature::label_for_standard_pem(),
            Slug20Algorithm::Ed25519 => ED25519Signature::label_for_standard_pem(),
            Slug20Algorithm::Ed448 => Ed448Signature::label_for_standard_pem(),
            Slug20Algorithm::Falcon => Falcon1024Signature::label_for_standard_pem(),
            Slug20Algorithm::MLDSA => MLDSA3Signature::label_for_standard_pem(),
            Slug20Algorithm::Schnorr => SchnorrSignature::label_for_standard_pem(),
            Slug20Algorithm::SPHINCSPlus => SPHINCSSignature::label_for_standard_pem(),
        }
    }
}