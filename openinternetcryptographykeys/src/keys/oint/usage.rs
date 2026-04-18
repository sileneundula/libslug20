use fixedstr::str192;
use libslug::errors::SlugErrors;
use libslug::slugcrypt::traits::IntoStandardPem;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::prelude::essentials::{OpenInternetGeneration,OpenInternetSigner,OpenInternetVerifier,OpenInternetPublicKeyDerive};
use crate::prelude::essentials::Slug20Algorithm;
use crate::prelude::essentials::{Slug20PublicKey,Slug20SecretKey, Slug20Signature};
use crate::prelude::essentials::{OpenInternetFromStandardPEM,OpenInternetIntoStandardPEM}; //OpenInternetIntoStandardPEM

use libslug::slugcrypt::traits::{IntoBincode,FromBincode};
use libslug::slugcrypt::traits::FromStandardPem;


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

use libslug::slugcrypt::internals::signature::falcon::SlugFalcon1024;
use libslug::slugcrypt::internals::signature::ml_dsa::SlugMLDSA3;

pub const OpenInternetCryptographyStandardContext: &[u8] = b"OpenInternetCryptographyStandardContext";

//=====OPENINTERNETCRYPTOGRAPHYKEYS OINT TYPES=====

/// # Open Internet Cryptography Keys (OICK) - OINT Types
/// 
/// This module defines the core types for the Open Internet Cryptography Keys (OICK) library, specifically for the OINT (Open Internet Cryptography Key) cipher suite. It includes standardized key and signature types, as well as a structure for representing cipher suites and their variants.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash,Zeroize, ZeroizeOnDrop)]
pub struct OpenInternetCryptographyPublicKey {
    pub key: Slug20PublicKey,
}

/// # Open Internet Cryptography Keys (OICK) - OINT Types
/// 
/// This module defines the core types for the Open Internet Cryptography Keys (OICK) library, specifically for the OINT (Open Internet Cryptography Key) cipher suite. It includes standardized key and signature types, as well as a structure for representing cipher suites and their variants.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash,Zeroize, ZeroizeOnDrop)]
pub struct OpenInternetCryptographySecretKey {
    pub key: Slug20SecretKey,
}

/// # Open Internet Cryptography Keys (OICK) - OINT Types
/// 
/// This module defines the core types for the Open Internet Cryptography Keys (OICK) library, specifically for the OINT (Open Internet Cryptography Key) cipher suite. It includes standardized key and signature types, as well as a structure for representing cipher suites and their variants.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash,Zeroize, ZeroizeOnDrop)]
pub struct OpenInternetCryptographySignature {
    pub signature: Slug20Signature,
}

/// # Open Internet Cryptography Keypair
/// 
/// This struct represents a keypair consisting of a public key and a secret key for the Open Internet Cryptography Keys (OICK) library, specifically for the OINT (Open Internet Cryptography Key) cipher suite.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash,Zeroize, ZeroizeOnDrop)]
pub struct OpenInternetCryptographyKeypair {
    pub public_key: OpenInternetCryptographyPublicKey,
    pub secret_key: OpenInternetCryptographySecretKey,
}

//=====OPENINTERNETCRYPTOGRAPHYKEYS OINT CIPHER SUITE=====

#[derive(Serialize, Copy, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash)]
pub struct OpenInternetCryptographyCipherSuite {
    pub cipher_suite: str192,
    pub variant: Option<str192>,
}

//=====OPENINTERNETCRYPTOGRAPHYKEYS OINT USAGE=====

//=====IMPLEMENTATION MANUAL=====//
impl OpenInternetCryptographyPublicKey {
    pub fn from_slug20_public_key(key: Slug20PublicKey) -> Self {
        OpenInternetCryptographyPublicKey { key }
    }
}

impl OpenInternetCryptographySecretKey {
    pub fn from_slug20_secret_key(key: Slug20SecretKey) -> Self {
        OpenInternetCryptographySecretKey { key }
    }
}

impl OpenInternetCryptographySignature {
    pub fn from_slug20_signature(signature: Slug20Signature) -> Self {
        OpenInternetCryptographySignature { signature }
    }
}

//=====IMPLEMENTATION OF OINT USAGE TYPES=====

impl OpenInternetGeneration for OpenInternetCryptographySecretKey {
    fn generate_with_algorithm(alg: Slug20Algorithm) -> Result<Self, libslug::prelude::core::SlugErrors> {
        match alg {
            Slug20Algorithm::ShulginSigning => {
                let keypair: ShulginKeypair = ShulginKeypair::generate();
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::ShulginSigning(keypair) })
            },
            Slug20Algorithm::AbsolveSigning => {
                let keypair: AbsolveKeypair = AbsolveKeypair::generate();
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::AbsolveSigning(keypair) })
            },
            Slug20Algorithm::EsphandSigning => {
                let keypair: EsphandKeypair = EsphandKeypair::generate();
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::EsphandSigning(keypair) })
            },
            Slug20Algorithm::Ed25519 => {
                let secret_key: ED25519SecretKey = ED25519SecretKey::generate();
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::Ed25519(secret_key) })
            },
            Slug20Algorithm::Ed448 => {
                let secret_key: Ed448SecretKey = Ed448SecretKey::generate();
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::Ed448(secret_key) })
            },
            Slug20Algorithm::ECDSA => {
                let secret_key: ECDSASecretKey = ECDSASecretKey::generate();
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::ECDSA(secret_key) })
            },
            Slug20Algorithm::Falcon => {
                let (pk,sk): (Falcon1024PublicKey, Falcon1024SecretKey) = SlugFalcon1024::generate();
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::Falcon(sk) })
            },
            Slug20Algorithm::MLDSA => {
                let secret_key: libslug::slugcrypt::internals::signature::ml_dsa::MLDSA3Keypair = SlugMLDSA3::generate();
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::MLDSA(MLDSA3SecretKey::from(secret_key.secret_key.clone())) })
            },
            Slug20Algorithm::Schnorr => {
                let secret_key: SchnorrSecretKey = SchnorrSecretKey::generate();
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::Schnorr(secret_key) })
            },
            Slug20Algorithm::SPHINCSPlus => {
                let secret_key: (SPHINCSPublicKey, SPHINCSSecretKey) = SPHINCSSecretKey::generate();
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::SPHINCSPlus(SPHINCSSecretKey::from(secret_key.1)) })
            },
            Slug20Algorithm::BLS => {
                let secret_key = BLSSecretKey::generate();
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::BLS(secret_key) })
            },
        }
    }
}

impl OpenInternetSigner for OpenInternetCryptographySecretKey {
    fn sign_with_context<T: AsRef<[u8]>>(&self, message: T, context: T) -> Result<OpenInternetCryptographySignature, SlugErrors> {
        match &self.key {
            Slug20SecretKey::ShulginSigning(keypair) => {
                let signature: ShulginSignature = keypair.sign(message)?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::ShulginSigning(signature)))
            },
            // TODO: Context Parsing; Should support keeping context in struct
            Slug20SecretKey::AbsolveSigning(keypair) => {
                let signature: AbsolveSignature = keypair.sign_with_context(message, context)?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::AbsolveSigning(signature)))
            },
            Slug20SecretKey::EsphandSigning(keypair) => {
                let signature: EsphandSignature = keypair.sign(message)?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::EsphandSigning(signature)))
            },
            Slug20SecretKey::BLS(key) => {
                let signature: BLSSignature = key.sign(message)?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::BLS(signature)))
             },
            Slug20SecretKey::ECDSA(key) => {
                let signature: (ECDSASignature, libslug::slugcrypt::internals::signature::ecdsa::ECDSASignatureRecoveryID) = key.sign(message)?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::ECDSA(signature.0)))
             },
            Slug20SecretKey::Ed25519(key) => {
                let signature: ED25519Signature = key.sign(message)?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::Ed25519(signature)))
            },
            Slug20SecretKey::Ed448(key) => {
                let signature: Ed448Signature = key.sign(message)?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::Ed448(signature)))
            }
            Slug20SecretKey::Falcon(key) => {
                let signature = key.sign(message);

                if signature.is_err() {
                    return Err(libslug::prelude::core::SlugErrors::Other(String::from("Signing with Falcon failed")));
                }
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::Falcon(signature.unwrap())))
            },
            Slug20SecretKey::MLDSA(key) => {
                let signature: MLDSA3Signature = key.sign(message, context)?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::MLDSA(signature)))
            },
            Slug20SecretKey::Schnorr(key) => {
                let signature = key.sign_with_context(message, context);

                if signature.is_err() {
                    return Err(libslug::prelude::core::SlugErrors::Other(String::from("Signing with Schnorr failed")));
                }
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::Schnorr(signature.unwrap())))
            },
            Slug20SecretKey::SPHINCSPlus(key) => {
                let signature: SPHINCSSignature = key.sign(message)?;
                Ok(OpenInternetCryptographySignature::from_slug20_signature(Slug20Signature::SPHINCSPlus(signature)))
            },
            _ => Err(libslug::prelude::core::SlugErrors::Other(String::from("Unsupported algorithm for signing with context")))
        }
    }
    fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<OpenInternetCryptographySignature, SlugErrors> {
        self.sign_with_context(message.as_ref(), OpenInternetCryptographyStandardContext)
    }
}

impl OpenInternetVerifier for OpenInternetCryptographyPublicKey {
    fn verify_with_context<T: AsRef<[u8]>>(&self, message: T, context: T, signature: &OpenInternetCryptographySignature) -> Result<bool, SlugErrors> {
        match &self.key {
            Slug20PublicKey::ShulginSigning(keypair) => {
                if let Slug20Signature::ShulginSigning(sig) = &signature.signature {
                    keypair.verify(message.as_ref(), sig)
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for ShulginSigning")))
                }
            },
            Slug20PublicKey::AbsolveSigning(keypair) => {
                if let Slug20Signature::AbsolveSigning(sig) = &signature.signature {
                    keypair.verify(message.as_ref(), sig.to_owned())
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for AbsolveSigning")))
                }
            },
            Slug20PublicKey::EsphandSigning(keypair) => {
                if let Slug20Signature::EsphandSigning(sig) = &signature.signature {
                    keypair.verify(message, sig)
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for EsphandSigning")))
                }
            },
            Slug20PublicKey::BLS(key) => {
                if let Slug20Signature::BLS(sig) = &signature.signature {
                    key.verify(message, sig)
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for BLS")))
                }
             },
            Slug20PublicKey::ECDSA(key) => {
                if let Slug20Signature::ECDSA(sig) = &signature.signature {
                    key.verify(message, sig.clone())
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for ECDSA")))
                }
             },
            Slug20PublicKey::Ed25519(key) => {
                if let Slug20Signature::Ed25519(sig) = &signature.signature {
                    let x = key.verify(sig.to_owned(), message.as_ref())?;
                    return Ok(x)
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for Ed25519")))
                }
            },
            Slug20PublicKey::Ed448(key) => {
                if let Slug20Signature::Ed448(sig) = &signature.signature {
                    key.verify(message, sig.clone())
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for Ed448")))
                }
            }
            Slug20PublicKey::Falcon(key) => {
                if let Slug20Signature::Falcon(sig) = &signature.signature {
                    let x = key.verify(message, sig);

                    if x.is_err() {
                        return Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for Falcon")));
                    }
                    return Ok(x.unwrap())
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for Falcon")))
                }
            },
            Slug20PublicKey::MLDSA(key) => {
                if let Slug20Signature::MLDSA(sig) = &signature.signature {
                    let x = key.verify(message.as_ref(), context.as_ref(), sig);
                    if x.is_err() {
                        return Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for MLDSA")));
                    }
                    return Ok(x.unwrap())
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for MLDSA")))
                }
            },
            Slug20PublicKey::Schnorr(key) => {
                if let Slug20Signature::Schnorr(sig) = &signature.signature {
                    let x = key.verify_with_context(message, context, sig.clone());
                    if x.is_err() {
                        return Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for Schnorr")));
                    }
                    else {
                        return Ok(true)
                    }
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for Schnorr")))
                }
            },
            Slug20PublicKey::SPHINCSPlus(key) => {
                if let Slug20Signature::SPHINCSPlus(sig) = &signature.signature {
                    let x = key.verify(message, sig.clone());

                    if x.is_err() {
                        return Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for SPHINCSPlus")));
                    }
                    else {
                        return Ok(true)
                    }
                } else {
                    Err(libslug::prelude::core::SlugErrors::Other(String::from("Signature type mismatch for SPHINCSPlus")))
                }
            },
            _ => Err(libslug::prelude::core::SlugErrors::Other(String::from("Unsupported algorithm for verification with context")))
        }
    }
    fn verify<T: AsRef<[u8]>>(&self, message: T, signature: &OpenInternetCryptographySignature) -> Result<bool, SlugErrors> {
        self.verify_with_context(message.as_ref(), OpenInternetCryptographyStandardContext, signature)
    }
}

// TODO: Keypairs
impl OpenInternetIntoStandardPEM for OpenInternetCryptographySecretKey {
    fn into_standard_pem(&self) -> Result<String, SlugErrors> {
        match &self.key {
            Slug20SecretKey::ShulginSigning(keypair) => keypair.into_standard_pem(),
            Slug20SecretKey::AbsolveSigning(keypair) => keypair.into_standard_pem(),
            Slug20SecretKey::EsphandSigning(keypair) => keypair.into_standard_pem(),
            Slug20SecretKey::BLS(key) => key.into_standard_pem(),
            Slug20SecretKey::ECDSA(key) => key.into_standard_pem(),
            Slug20SecretKey::Ed25519(key) => key.into_standard_pem(),
            Slug20SecretKey::Ed448(key) => key.into_standard_pem(),
            Slug20SecretKey::Falcon(key) => key.into_standard_pem(),
            Slug20SecretKey::MLDSA(key) => key.into_standard_pem(),
            Slug20SecretKey::Schnorr(key) => key.into_standard_pem(),
            Slug20SecretKey::SPHINCSPlus(key) => key.into_standard_pem(),
        }
    }
}

impl OpenInternetIntoStandardPEM for OpenInternetCryptographyPublicKey {
    fn into_standard_pem(&self) -> Result<String, SlugErrors> {
        match &self.key {
            Slug20PublicKey::ShulginSigning(keypair) => keypair.into_standard_pem(),
            Slug20PublicKey::AbsolveSigning(keypair) => keypair.into_standard_pem(),
            Slug20PublicKey::EsphandSigning(keypair) => keypair.into_standard_pem(),
            Slug20PublicKey::BLS(key) => key.into_standard_pem(),
            Slug20PublicKey::ECDSA(key) => key.into_standard_pem(),
            Slug20PublicKey::Ed25519(key) => key.into_standard_pem(),
            Slug20PublicKey::Ed448(key) => key.into_standard_pem(),
            Slug20PublicKey::Falcon(key) => key.into_standard_pem(),
            Slug20PublicKey::MLDSA(key) => key.into_standard_pem(),
            Slug20PublicKey::Schnorr(key) => key.into_standard_pem(),
            Slug20PublicKey::SPHINCSPlus(key) => key.into_standard_pem(),
        }
    }
}

impl OpenInternetIntoStandardPEM for OpenInternetCryptographySignature {
    fn into_standard_pem(&self) -> Result<String, SlugErrors> {
        match &self.signature {
            Slug20Signature::ShulginSigning(sig) => sig.into_standard_pem(),
            Slug20Signature::AbsolveSigning(sig) => sig.into_standard_pem(),
            Slug20Signature::EsphandSigning(sig) => sig.into_standard_pem(),
            Slug20Signature::BLS(sig) => sig.into_standard_pem(),
            Slug20Signature::ECDSA(sig) => sig.into_standard_pem(),
            Slug20Signature::Ed25519(sig) => sig.into_standard_pem(),
            Slug20Signature::Ed448(sig) => sig.into_standard_pem(),
            Slug20Signature::Falcon(sig) => sig.into_standard_pem(),
            Slug20Signature::MLDSA(sig) => sig.into_standard_pem(),
            Slug20Signature::Schnorr(sig) => sig.into_standard_pem(),
            Slug20Signature::SPHINCSPlus(sig) => sig.into_standard_pem(),
        }
    }
}

impl OpenInternetFromStandardPEM for OpenInternetCryptographySecretKey {
    fn from_standard_pem_with_algorithm<T: AsRef<str>>(pem: T, alg: Slug20Algorithm) -> Result<Self, SlugErrors> {
        match alg {
            Slug20Algorithm::ShulginSigning => {
                let keypair: ShulginKeypair = ShulginKeypair::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::ShulginSigning(keypair) })
            },
            Slug20Algorithm::AbsolveSigning => {
                let keypair: AbsolveKeypair = AbsolveKeypair::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::AbsolveSigning(keypair) })
            },
            Slug20Algorithm::EsphandSigning => {
                let keypair: EsphandKeypair = EsphandKeypair::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::EsphandSigning(keypair) })
            },
            Slug20Algorithm::Ed25519 => {
                let secret_key: ED25519SecretKey = ED25519SecretKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::Ed25519(secret_key) })
            },
            Slug20Algorithm::Ed448 => {
                let secret_key: Ed448SecretKey = Ed448SecretKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::Ed448(secret_key) })
            },
            Slug20Algorithm::ECDSA => {
                let secret_key: ECDSASecretKey = ECDSASecretKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::ECDSA(secret_key) })
            },
            Slug20Algorithm::Falcon => {
                let secret_key: Falcon1024SecretKey = Falcon1024SecretKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::Falcon(secret_key) })
            },
            Slug20Algorithm::MLDSA => {
                let secret_key: MLDSA3SecretKey = MLDSA3SecretKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::MLDSA(secret_key) })
            },
            Slug20Algorithm::Schnorr => {
                let secret_key: SchnorrSecretKey = SchnorrSecretKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::Schnorr(secret_key) })
            },
            Slug20Algorithm::SPHINCSPlus => {
                let secret_key: SPHINCSSecretKey = SPHINCSSecretKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::SPHINCSPlus(secret_key) })
            },
            Slug20Algorithm::BLS => {
                let secret_key: BLSSecretKey = BLSSecretKey::from_standard_pem(pem.as_ref())?;
                Ok(OpenInternetCryptographySecretKey { key: Slug20SecretKey::BLS(secret_key) })
            },
        }
    }
    fn from_standard_pem<T: AsRef<str>>(pem: T) -> Result<Self, SlugErrors> {
        for x in Slug20SecretKey {
            
        }
        if pem.as_ref().contains()
        
        OpenInternetCryptographySecretKey::from_standard_pem_with_algorithm(pem, alg)
    }
}