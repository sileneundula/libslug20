use libslug::slugcrypt::internals::signature::absolvesigning::AbsolveKeypair;

use libslug::slugcrypt::internals::signature::ed25519::{ED25519PublicKey,ED25519SecretKey,ED25519Signature};
use libslug::slugcrypt::internals::signature::ed448::{Ed448PublicKey,Ed448SecretKey,Ed448Signature};
use libslug::slugcrypt::internals::signature::ecdsa::{ECDSAPublicKey, ECDSASecretKey, ECDSASignature};
use libslug::slugcrypt::internals::signature::esphand_signature::EsphandKeypair;
use libslug::slugcrypt::internals::signature::shulginsigning::ShulginKeypair;

pub enum SlugPublicKey {
    ED25519PublicKey(ED25519PublicKey),
    ED448PublicKey(Ed448PublicKey),
    ECDSAPublicKey(ECDSAPublicKey),

    BLS12381PublicKey(libslug::slugcrypt::internals::signature::bls::BLSPublicKey),
    SchnorrOverRistrettoPublicKey(libslug::slugcrypt::internals::signature::schnorr::SchnorrPublicKey),

    SPHINCSPublicKey(libslug::slugcrypt::internals::signature::sphincs_plus::SPHINCSPublicKey),
    FALCON1024PublicKey(libslug::slugcrypt::internals::signature::falcon::Falcon1024PublicKey),
    MLDSA3PublicKey(libslug::slugcrypt::internals::signature::ml_dsa::MLDSA3PublicKey),
}

pub enum SlugSecretKey {
    ED25519SecretKey(ED25519SecretKey),
    ED448SecretKey(Ed448SecretKey),
    ECDSASecretKey(ECDSASecretKey),
    SchnorrOverRistrettoSecretKey(libslug::slugcrypt::internals::signature::schnorr::SchnorrSecretKey),
    BLS12381SecretKey(libslug::slugcrypt::internals::signature::bls::BLSSecretKey),
    SPHINCSSecretKey(libslug::slugcrypt::internals::signature::sphincs_plus::SPHINCSSecretKey),
    FALCON1024SecretKey(libslug::slugcrypt::internals::signature::falcon::Falcon1024SecretKey),
    MLDSA3SecretKey(libslug::slugcrypt::internals::signature::ml_dsa::MLDSA3SecretKey),
}

pub enum SlugSignature {
    ED25519Signature(ED25519Signature),
    ED448Signature(Ed448Signature),
    ECDSASignature(ECDSASignature),
    SchnorrOverRistrettoSignature(libslug::slugcrypt::internals::signature::schnorr::SchnorrSignature),
    BLS12381Signature(libslug::slugcrypt::internals::signature::bls::BLSSignature),
    SPHINCSSignature(libslug::slugcrypt::internals::signature::sphincs_plus::SPHINCSSignature),
    FALCON1024Signature(libslug::slugcrypt::internals::signature::falcon::Falcon1024Signature),
    MLDSA3Signature(libslug::slugcrypt::internals::signature::ml_dsa::MLDSA3Signature),
}