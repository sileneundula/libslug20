//! # OpenInternetCryptography Standardized Types
//! 
//! This module defines standardized key and signature types for the Open Internet Cryptography Keys (OICK) library, allowing for consistent handling of different cryptographic key types and their associated signatures. It includes enums for standardized public keys, private keys, and signatures, as well as a struct for the main Open Internet Cryptography API.
//! 
//! The standardized types defined in this module enable consistent management and usage of different cryptographic key types and their associated signatures across various algorithms supported by the OICK library.
//! 
//! The `OpenInternetCryptographyAPI` struct provides methods for key generation, signing, and verification using the standardized key and signature types defined in this module.

use libslug::{errors::SlugErrors, slugcrypt::{internals::signature::{absolvesigning::{AbsolveKeypair, AbsolveSignature}, esphand_signature::{EsphandKeypair, EsphandSignature}, shulginsigning::{ShulginKeypair, ShulginSignature}}, traits::{FromStandardPem, IntoStandardPem}}};

use crate::core::__types::{StandardPrivateKey, StandardPublicKey, StandardSignature, algorithms::Algorithms};


/// # Open Internet Cryptography API
/// 
/// This struct represents the main API for the Open Internet Cryptography Keys (OICK) library, providing methods for key generation, signing, and verification using standardized key and signature types.
/// 
/// ## Standardized Types
/// 
/// OpenInternetCryptographySuites provides a standardized interface for handling different cryptographic key types and their associated signatures, allowing for consistent management and usage across various algorithms.
pub struct OpenInternetCryptographyAPI;

pub struct OintKeyPair {
    pub public_key: Option<OintPublicKey>,
    pub secret_key: Option<OintSecretKey>,
}

pub struct OintPublicKey {
    pub key: StandardPublicKey,
}

pub struct OintSecretKey {
    pub key: StandardPrivateKey,
}

pub struct OintSignature {
    pub signature: StandardSignature,
}

impl OintPublicKey {
    pub fn from_standard(public_key: StandardPublicKey) -> Self {
        OintPublicKey { key: public_key }
    }
    pub fn from_pem<T: AsRef<str>>(pem: T, alg: Algorithms) -> Result<OintPublicKey, SlugErrors> {
        match alg {
            Algorithms::ShulginSigning => {
                let keypair: ShulginKeypair = ShulginKeypair::from_standard_pem(pem.as_ref())?;
                let x: StandardPublicKey = StandardPublicKey::ShulginSigning(keypair);
                Ok(OintPublicKey { key: x })
            }
            Algorithms::AbsolveSigning => {
                let keypair: AbsolveKeypair = AbsolveKeypair::from_standard_pem(pem.as_ref())?;
                let x: StandardPublicKey = StandardPublicKey::AbsolveSigning(keypair);
                Ok(OintPublicKey { key: x })
            }
            Algorithms::EsphandSigning => {
                let keypair: EsphandKeypair = EsphandKeypair::from_standard_pem(pem.as_ref())?;
                let x: StandardPublicKey = StandardPublicKey::EsphandSigning(keypair);
                Ok(OintPublicKey { key: x })
            }
        }
    }
    pub fn into_pem_public(&self) -> Result<String, SlugErrors> {
        match &self.key {
            StandardPublicKey::ShulginSigning(keypair) => {
                if keypair.ed25519sk.is_none() && keypair.sphincssk.is_none() {
                    keypair.into_standard_pem()
                } else {
                    Err(SlugErrors::InvalidPemLabel)
                }
            }
            StandardPublicKey::AbsolveSigning(keypair) => {
                if keypair.ed25519sk.is_none() && keypair.mldsa3sk.is_none() {
                    keypair.into_standard_pem()
                } else {
                    Err(SlugErrors::InvalidPemLabel)
                }
            },
            StandardPublicKey::EsphandSigning(keypair) => {
                if keypair.clsk.is_none() && keypair.pqsk.is_none() {
                    keypair.into_standard_pem()
                } else {
                    Err(SlugErrors::InvalidPemLabel)
                }
            }
        }
    }
    pub fn verify<T: AsRef<[u8]>>(&self, message: T, signature: &OintSignature) -> Result<bool,SlugErrors> {
        match (&self.key, &signature.signature) {
            (StandardPublicKey::ShulginSigning(keypair), StandardSignature::ShulginSigning(sig)) => keypair.verify(message.as_ref(), sig),
            (StandardPublicKey::AbsolveSigning(keypair), StandardSignature::AbsolveSigning(sig)) => keypair.verify(message.as_ref(), sig.to_owned()),
            (StandardPublicKey::EsphandSigning(keypair), StandardSignature::EsphandSigning(sig)) => keypair.verify(message.as_ref(), sig),
            _ => Err(SlugErrors::Other(String::from("Mismatched key and signature types"))), // Mismatched key and signature types
        }
    }
}

impl OintSecretKey {
    pub fn from_standard(secret_key: StandardPrivateKey) -> Self {
        OintSecretKey { key: secret_key }
    }
    pub fn from_pem_with_algorithm<T: AsRef<str>>(pem: T, alg: Algorithms) -> Result<OintSecretKey, SlugErrors> {
        match alg {
            Algorithms::ShulginSigning => {
                let keypair = ShulginKeypair::from_standard_pem(pem.as_ref())?;
                Ok(OintSecretKey { key: StandardPrivateKey::ShulginSigning(keypair) })
            }
            Algorithms::AbsolveSigning => {
                let keypair = AbsolveKeypair::from_standard_pem(pem.as_ref())?;
                Ok(OintSecretKey { key: StandardPrivateKey::AbsolveSigning(keypair) })
            }
            Algorithms::EsphandSigning => {
                let keypair = EsphandKeypair::from_standard_pem(pem.as_ref())?;
                Ok(OintSecretKey { key: StandardPrivateKey::EsphandSigning(keypair) })
            }
        }
    }
    pub fn from_pem<T: AsRef<str>>(pem: T) -> Result<OintSecretKey, SlugErrors> {
        let pem_str = pem.as_ref();
        if pem_str.contains(&ShulginKeypair::label_for_standard_pem()) {
            Self::from_pem_with_algorithm(pem, Algorithms::ShulginSigning)
        } else if pem_str.contains(&AbsolveKeypair::label_for_standard_pem()) {
            Self::from_pem_with_algorithm(pem, Algorithms::AbsolveSigning)
        } else if pem_str.contains(&EsphandKeypair::label_for_standard_pem()) {
            Self::from_pem_with_algorithm(pem, Algorithms::EsphandSigning)
        } else {
            Err(SlugErrors::Other(String::from("Unable to determine algorithm from PEM string")))
        }
    }
    pub fn into_pem_secret(&self) -> Result<String, SlugErrors> {
        match &self.key {
            StandardPrivateKey::ShulginSigning(keypair) => keypair.into_standard_pem(),
            StandardPrivateKey::AbsolveSigning(keypair) => keypair.into_standard_pem(),
            StandardPrivateKey::EsphandSigning(keypair) => keypair.into_standard_pem(),
        }
    }
    pub fn into_public_key(&self) -> OintPublicKey {
        let x = match &self.key {
            StandardPrivateKey::ShulginSigning(keypair) => StandardPublicKey::ShulginSigning(keypair.into_public_key()),
            StandardPrivateKey::AbsolveSigning(keypair) => StandardPublicKey::AbsolveSigning(keypair.into_public_key()),
            StandardPrivateKey::EsphandSigning(keypair) => StandardPublicKey::EsphandSigning(keypair.into_public_key()),
        };
        OintPublicKey { key: x }
    }
    pub fn sign_with_context<T: AsRef<[u8]>>(&self, message: T, context: Option<T>) -> Result<OintSignature,SlugErrors> {
            match &self.key {
                StandardPrivateKey::ShulginSigning(keypair) => {
                    let sig = keypair.sign(message.as_ref())?;
                    let output: StandardSignature = StandardSignature::ShulginSigning(sig);
                    return Ok(OintSignature { signature: output });
                }
                StandardPrivateKey::AbsolveSigning(keypair) => {
                    let sig = keypair.sign(message.as_ref())?;
                    let output: StandardSignature = StandardSignature::AbsolveSigning(sig);
                    return Ok(OintSignature { signature: output });
                }
                StandardPrivateKey::EsphandSigning(keypair) => {
                    let sig = keypair.sign(message.as_ref())?;
                    let output: StandardSignature = StandardSignature::EsphandSigning(sig);
                    return Ok(OintSignature { signature: output });
                }
            }
    }
    pub fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<OintSignature, SlugErrors> {
        self.sign_with_context(message, None)
    }
}

impl OintSignature {
    pub fn from_standard(signature: StandardSignature) -> Self {
        OintSignature { signature }
    }
    pub fn into_pem(&self) -> Result<String, SlugErrors> {
        match &self.signature {
            StandardSignature::ShulginSigning(signature) => signature.into_standard_pem(),
            StandardSignature::AbsolveSigning(signature) => signature.into_standard_pem(),
            StandardSignature::EsphandSigning(signature) => signature.into_standard_pem(),
        }
    }
    pub fn from_pem<T: AsRef<str>>(pem: T, alg: Algorithms) -> Result<OintSignature, SlugErrors> {
        match alg {
            Algorithms::ShulginSigning => {
                let signature = ShulginSignature::from_standard_pem(pem.as_ref())?;
                Ok(OintSignature { signature: StandardSignature::ShulginSigning(signature) })
            }
            Algorithms::AbsolveSigning => {
                let signature = AbsolveSignature::from_standard_pem(pem.as_ref())?;
                Ok(OintSignature { signature: StandardSignature::AbsolveSigning(signature) })
            }
            Algorithms::EsphandSigning => {
                let signature = EsphandSignature::from_standard_pem(pem.as_ref())?;
                Ok(OintSignature { signature: StandardSignature::EsphandSigning(signature) })
            }
        }
    }
}

impl OpenInternetCryptographyAPI {
    pub fn generate(alg: Algorithms) -> (OintPublicKey, OintSecretKey) {
        match alg {
            Algorithms::ShulginSigning => {
                let keypair = ShulginKeypair::generate();
                let public_key = OintPublicKey { key: StandardPublicKey::ShulginSigning(keypair.into_public_key()) };
                let secret_key = OintSecretKey { key: StandardPrivateKey::ShulginSigning(keypair) };
                (public_key, secret_key)
            }
            Algorithms::AbsolveSigning => {
                let keypair = AbsolveKeypair::generate();
                let public_key = OintPublicKey { key: StandardPublicKey::AbsolveSigning(keypair.into_public_key()) };
                let secret_key = OintSecretKey { key: StandardPrivateKey::AbsolveSigning(keypair) };
                (public_key, secret_key)
            },
            Algorithms::EsphandSigning => {
                let keypair = EsphandKeypair::generate();
                let public_key = OintPublicKey { key: StandardPublicKey::EsphandSigning(keypair.into_public_key()) };
                let secret_key = OintSecretKey { key: StandardPrivateKey::EsphandSigning(keypair) };
                (public_key, secret_key)
            }
        }
    }
    pub fn generate_with_str<T: AsRef<str>>(s: T) -> (OintPublicKey, OintSecretKey) {
        let alg = s.as_ref().to_lowercase();

        let alg_enum = match alg.as_str() {
            "shulgin" => Algorithms::ShulginSigning,
            "absolve" => Algorithms::AbsolveSigning,
            "esphand" => Algorithms::EsphandSigning,
            _ => panic!("Unsupported algorithm string: {}", s.as_ref()),
        };
        Self::generate(alg_enum)
    }

    pub fn sign<T: AsRef<[u8]>>(&self, secret_key: &OintSecretKey, message: T) -> Result<OintSignature,SlugErrors> {
        secret_key.sign(message)
    }

    pub fn verify(&self, public_key: &OintPublicKey, message: &[u8], signature: &OintSignature) -> bool {
        public_key.verify(message, signature).unwrap_or(false)
    }
}