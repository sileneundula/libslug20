//! # OintKeys
//! 
//! ## Cipher Suite
//! 
//! Modular Approach To Adding Keys
//! 
//! 

use fixedstr::str64;

use libslug::slugcrypt::internals::signature::bls::BLSPublicKey;
use libslug::slugcrypt::internals::signature::bls::BLSSecretKey;
use libslug::slugcrypt::internals::signature::ecdsa::ECDSAPublicKey;
use libslug::slugcrypt::internals::signature::ecdsa::ECDSASecretKey;
use libslug::slugcrypt::internals::signature::ed25519::ED25519PublicKey;
use libslug::slugcrypt::internals::signature::ed25519::ED25519SecretKey;
use libslug::slugcrypt::internals::signature::esphand_signature::EsphandKeypair;
use libslug::slugcrypt::internals::signature::falcon::Falcon1024SecretKey;
use libslug::slugcrypt::internals::signature::ml_dsa::MLDSA3PublicKey;
use libslug::slugcrypt::internals::signature::ml_dsa::MLDSA3SecretKey;
use libslug::slugcrypt::internals::signature::schnorr::SchnorrPublicKey;
use libslug::slugcrypt::internals::signature::schnorr::SchnorrSecretKey;
use libslug::slugcrypt::internals::signature::shulginsigning::ShulginKeypair;
use libslug::slugcrypt::internals::signature::sphincs_plus::SPHINCSPublicKey;
use libslug::slugcrypt::internals::signature::sphincs_plus::SPHINCSSecretKey;
use oint_keys_traits::GenerateKeypair;

// HYBRID
use libslug::slugcrypt::internals::signature::shulginsigning;
use libslug::slugcrypt::internals::signature::esphand_signature;

// Classical
use libslug::slugcrypt::internals::signature::ed25519;
use libslug::slugcrypt::internals::signature::ecdsa;
use libslug::slugcrypt::internals::signature::bls;
use libslug::slugcrypt::internals::signature::schnorr;
// Post-Quantum
use libslug::slugcrypt::internals::signature::sphincs_plus;
use libslug::slugcrypt::internals::signature::falcon;
use libslug::slugcrypt::internals::signature::ml_dsa;

pub struct OintKeypair<'a> {
    pub pkh: OintPublicKey<'a>,
    pub skh: OintSecretKey<'a>,
    pub alg: str64,
}

pub struct OintPublicKey<'a> {
    pub public_key: &'a str,
    pub alg: str64,
}

pub struct OintSecretKey<'a> {
    pub secret_key: &'a str,
    pub alg: str64,
}

pub struct OintSignature<'a> {
    pub signature: &'a str,
    pub alg: str64,
}

impl GenerateKeypair for OintKeypair<'a> {
    fn generate<T: AsRef<str>>(algorithm: T) -> Self {
        let x = match algorithm.as_ref() {
            "slug20/shulginsigning" => Keypairs::ShulginSigning(ShulginKeypair::generate()),
            "slug20/esphandsigning" => Keypairs::EsphandSigning(EsphandKeypair::generate()),
            "slug20/ed25519" => {
                let x = ed25519::ED25519SecretKey::generate();
                let pkh = x.public_key().unwrap();
                Keypairs::ED25519(x, pkh)
            }
            "slug20/ecdsa" => {
                let x = ecdsa::ECDSASecretKey::generate();
                let pkh = x.public_key().unwrap();
                Keypairs::ECDSA(x, pkh)
            },
            "slug20/bls" => {
                let (pkh,sk) = bls::SlugBLS::generate();
                Keypairs::BLS(sk, pkh)
            }
            "slug20/schnorr" => {
                let skh = schnorr::SchnorrSecretKey::generate();
                let pk = skh.public_key().unwrap();
                Keypairs::Schnorr(skh, pk)
            }
            _ => panic!("Invalid Value")
        }
        
        let x = ShulginKeypair::generate();
    }
}

pub enum Keypairs {
    // Hybrid
    ShulginSigning(ShulginKeypair),
    EsphandSigning(EsphandKeypair),
    // Classical
    ED25519(ED25519SecretKey,ED25519PublicKey),
    ECDSA(ECDSASecretKey,ECDSAPublicKey),
    BLS(BLSSecretKey,BLSPublicKey),
    Schnorr(SchnorrSecretKey,SchnorrPublicKey),
    // PQ
    Falcon1024(Falcon1024SecretKey,Falcon1024SecretKey),
    SPHINCS(SPHINCSSecretKey,SPHINCSPublicKey),
    MLDSA(MLDSA3SecretKey,MLDSA3PublicKey)
}