use libslug::errors::SlugErrors;
use libslug::slugcrypt::internals::signature;
// Keys
use libslug::slugcrypt::internals::signature::shulginsigning::ShulginKeypair;
use libslug::slugcrypt::internals::signature::absolvesigning::AbsolveKeypair;
use libslug::slugcrypt::internals::signature::esphand_signature::EsphandKeypair;
// Signatures
use libslug::slugcrypt::internals::signature::shulginsigning::ShulginSignature;
use libslug::slugcrypt::internals::signature::absolvesigning::AbsolveSignature;
use libslug::slugcrypt::internals::signature::esphand_signature::EsphandSignature;

use libslug::slugcrypt::traits::{FromBincode,IntoBincode,FromStandardPem,IntoStandardPem};
use libslug::slugfmt::key;

use crate::core::__types::algorithms::Algorithms;

/// # Standardized Key and Signature Types
/// 
/// This module defines standardized key and signature types for the Open Internet Cryptography Keys (OICK) library, allowing for consistent handling of different cryptographic key types and their associated signatures.
pub enum StandardPublicKey {
    ShulginSigning(ShulginKeypair),
    AbsolveSigning(AbsolveKeypair),
    EsphandSigning(EsphandKeypair),
}

/// # Standardized Private Key Types
/// 
/// This enum defines standardized private key types for the Open Internet Cryptography Keys (OICK) library, enabling consistent management of different cryptographic key types.
pub enum StandardPrivateKey {
    ShulginSigning(ShulginKeypair),
    AbsolveSigning(AbsolveKeypair),
    EsphandSigning(EsphandKeypair),
}

/// # Standardized Signature Types
/// 
/// This enum defines standardized signature types for the Open Internet Cryptography Keys (OICK) library, enabling consistent handling of different cryptographic signature types.
pub enum StandardSignature {
    ShulginSigning(ShulginSignature),
    AbsolveSigning(AbsolveSignature),
    EsphandSigning(EsphandSignature),
}

impl StandardPublicKey {
    pub fn from_shulgin(keypair: ShulginKeypair) -> Self {
        StandardPublicKey::ShulginSigning(keypair)
    }
    pub fn from_absolve(keypair: AbsolveKeypair) -> Self {
        StandardPublicKey::AbsolveSigning(keypair)
    }
    pub fn from_esphand(keypair: EsphandKeypair) -> Self {
        StandardPublicKey::EsphandSigning(keypair)
    }
}

impl StandardPrivateKey {
    pub fn from_shulgin(keypair: ShulginKeypair) -> Self {
        StandardPrivateKey::ShulginSigning(keypair)
    }
    pub fn from_absolve(keypair: AbsolveKeypair) -> Self {
        StandardPrivateKey::AbsolveSigning(keypair)
    }
    pub fn from_esphand(keypair: EsphandKeypair) -> Self {
        StandardPrivateKey::EsphandSigning(keypair)
    }
    pub fn into_public_key(&self) -> StandardPublicKey {
        match self {
            StandardPrivateKey::ShulginSigning(keypair) => StandardPublicKey::ShulginSigning(keypair.into_public_key()),
            StandardPrivateKey::AbsolveSigning(keypair) => StandardPublicKey::AbsolveSigning(keypair.into_public_key()),
            StandardPrivateKey::EsphandSigning(keypair) => StandardPublicKey::EsphandSigning(keypair.into_public_key()),
        }
    }
}

impl StandardSignature {
    pub fn from_shulgin(signature: ShulginSignature) -> Self {
        StandardSignature::ShulginSigning(signature)
    }
    pub fn from_absolve(signature: AbsolveSignature) -> Self {
        StandardSignature::AbsolveSigning(signature)
    }
    pub fn from_esphand(signature: EsphandSignature) -> Self {
        StandardSignature::EsphandSigning(signature)
    }
}

impl StandardPrivateKey {
    pub fn generate(alg: Algorithms) -> Self {
        match alg {
            Algorithms::ShulginSigning => {
                let keypair = ShulginKeypair::generate();
                StandardPrivateKey::ShulginSigning(keypair)
            }
            Algorithms::AbsolveSigning => {
                let keypair = AbsolveKeypair::generate();
                StandardPrivateKey::AbsolveSigning(keypair)
            }
            Algorithms::EsphandSigning => {
                let keypair = EsphandKeypair::generate();
                StandardPrivateKey::EsphandSigning(keypair)
            }
        }
    }
    pub fn from_pem<T: AsRef<str>>(pem: T, alg: Algorithms) -> Result<Self, SlugErrors> {
        match alg {
            Algorithms::ShulginSigning => {
                let keypair = ShulginKeypair::from_standard_pem(pem.as_ref())?;
                Ok(StandardPrivateKey::ShulginSigning(keypair))
            }
            Algorithms::AbsolveSigning => {
                let keypair = AbsolveKeypair::from_standard_pem(pem.as_ref())?;
                Ok(StandardPrivateKey::AbsolveSigning(keypair))
            }
            Algorithms::EsphandSigning => {
                let keypair = EsphandKeypair::from_standard_pem(pem.as_ref())?;
                Ok(StandardPrivateKey::EsphandSigning(keypair))
            }
        }
    }
    pub fn into_pem(&self) -> Result<String, SlugErrors> {
        match self {
            StandardPrivateKey::ShulginSigning(keypair) => keypair.into_standard_pem(),
            StandardPrivateKey::AbsolveSigning(keypair) => keypair.into_standard_pem(),
            StandardPrivateKey::EsphandSigning(keypair) => keypair.into_standard_pem(),
        }
    }
}

impl StandardPublicKey {
    /// # Verify
    /// 
    /// Verifies a signature against a message using the public key. Returns `Ok(true)` if the signature is valid, `Ok(false)` if it is invalid, and `Err(SlugErrors)` if an error occurs during verification.
    /// 
    /// # Arguments
    /// - `message`: The message to verify, which can be any type that can be referenced as a byte slice.
    /// - `signature`: The signature to verify, which must be of the same type as the public key.
    /// # Returns
    /// - `Ok(true)` if the signature is valid.
    /// - `Ok(false)` if the signature is invalid.
    /// - `Err(SlugErrors)` if an error occurs during verification.
    /// # Example
    /// 
    /// ```rust
    /// use openinternetcryptographykeys::core::__types::standard::{StandardPublicKey, StandardSignature};
    /// 
    /// fn main() {
    ///     
    /// }
    /// ```
    pub fn verify<T: AsRef<[u8]>>(&self, message: T, signature: &StandardSignature) -> Result<bool,SlugErrors> {
        match (self, signature) {
            (StandardPublicKey::ShulginSigning(keypair), StandardSignature::ShulginSigning(sig)) => {
                keypair.verify(message, sig)
            }
            (StandardPublicKey::AbsolveSigning(keypair), StandardSignature::AbsolveSigning(sig)) => {
                keypair.verify(message, sig.clone())
            }
            (StandardPublicKey::EsphandSigning(keypair), StandardSignature::EsphandSigning(sig)) => {
                keypair.verify(message, sig)
            }
            _ => Ok(false), // Mismatched key and signature types
        }
    }
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Self {
        // Placeholder implementation for key generation from bytes
        unimplemented!()
    }
    pub fn from_pem<T: AsRef<str>>(pem: T, alg: Algorithms) -> Result<Self,SlugErrors> {
        match alg {
            Algorithms::ShulginSigning => {
                let keypair = ShulginKeypair::from_standard_pem(pem.as_ref())?;
                assert_eq!(keypair.ed25519sk.is_none(), true);
                assert_eq!(keypair.sphincssk.is_none(), true);
                Ok(StandardPublicKey::ShulginSigning(keypair))
            }
            Algorithms::AbsolveSigning => {
                let keypair = AbsolveKeypair::from_standard_pem(pem.as_ref())?;
                assert_eq!(keypair.ed25519sk.is_none(), true);
                assert_eq!(keypair.mldsa3sk.is_none(), true);
                Ok(StandardPublicKey::AbsolveSigning(keypair))
            }
            Algorithms::EsphandSigning => {
                let keypair = EsphandKeypair::from_standard_pem(pem.as_ref())?;
                assert_eq!(keypair.clsk.is_none(), true);
                assert_eq!(keypair.pqsk.is_none(), true);
                Ok(StandardPublicKey::EsphandSigning(keypair))
            }
        }
    }
    pub fn into_public_pem(&self) -> Result<String, SlugErrors> {
        match self {
            StandardPublicKey::ShulginSigning(keypair) => {

                if keypair.ed25519sk.is_none() && keypair.sphincssk.is_none() {
                    let x = keypair.into_standard_pem()?;
                    Ok(x)
                } else {
                    Err(SlugErrors::InvalidPemLabel)
                }
            },
            StandardPublicKey::AbsolveSigning(keypair) => {
                if keypair.ed25519sk.is_none() && keypair.mldsa3sk.is_none() {
                    let x = keypair.into_standard_pem()?;
                    Ok(x)
                } else {
                    Err(SlugErrors::InvalidPemLabel)
                }
            },
            StandardPublicKey::EsphandSigning(keypair) => {
                if keypair.clsk.is_none() && keypair.pqsk.is_none() {
                    let x = keypair.into_standard_pem()?;
                    Ok(x)
                } else {
                    Err(SlugErrors::InvalidPemLabel)
                }
            }
        }
    }
}

pub mod standard;
pub mod algorithms;
pub mod suite;