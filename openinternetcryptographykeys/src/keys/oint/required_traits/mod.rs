//! # Required Traits for Open Internet Cryptography Keys (OICK)
//! 
//! ## Description
//! 
//! This module contains the required traits to be implemented for OpenInternetCryptographyKeys (OICK) key types, ensuring that they adhere to the necessary functionality for signing, verifying, key derivation, and generation as defined by the OICK specification.
//! 
//! ## Traits
//! 
//! - [X] `OpenInternetSigner`: Trait for signing messages with a context to produce a signature.
//! - [X] `OpenInternetVerifier`: Trait for verifying signatures against messages and contexts.
//! - [X] `OpenInternetPublicKeyDerive`: Trait for deriving a public key from a secret key.
//! - [X] `OpenInternetGeneration`: Trait for generating keys based on a provided string input.

use fixedstr::str192;
use libslug::errors::SlugErrors;

use crate::keys::oint::{__types::Slug20Algorithm, usage::{OpenInternetCryptographyPublicKey, OpenInternetCryptographySignature}};

//=====OPENINTERNETCRYPTOGRAPHYKEYS OINT REQUIRED TRAITS=====

/// # OpenInternetSigner Trait
/// 
/// This trait implements signing functionality for the Open Internet Cryptography Keys (OICK) library, allowing for signing messages with a context to produce a signature.
pub trait OpenInternetSigner: Sized {
    fn sign_with_context<T: AsRef<[u8]>>(&self, message: T, context: T) -> Result<OpenInternetCryptographySignature, SlugErrors>;
    fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<OpenInternetCryptographySignature, SlugErrors> {
        self.sign_with_context(message.as_ref(), "OpenInternetCryptographyStandardContext".as_bytes())
    }
}

/// # OpenInternetVerifier Trait
/// 
/// This trait implements verification functionality for the Open Internet Cryptography Keys (OICK) library, allowing for verifying signatures against messages and contexts.
pub trait OpenInternetVerifier: Sized {
    fn verify_with_context<T: AsRef<[u8]>>(&self, message: T, context: T, signature: &OpenInternetCryptographySignature) -> Result<bool, SlugErrors>;
    fn verify<T: AsRef<[u8]>>(&self, message: T, signature: &OpenInternetCryptographySignature) -> Result<bool, SlugErrors> {
        self.verify_with_context(message.as_ref(), "OpenInternetCryptographyStandardContext".as_bytes(), signature)
    }
}

/// # OpenInternetPublicKeyDerive Trait
/// 
/// This trait implements key derivation functionality for the Open Internet Cryptography Keys (OICK) library, allowing for deriving a public key from a secret key.
pub trait OpenInternetPublicKeyDerive: Sized {
    fn derive_public_key(&self) -> Result<OpenInternetCryptographyPublicKey, SlugErrors>;
}

/// # OpenInternetGeneration Trait
/// 
/// This trait implements key generation functionality for the Open Internet Cryptography Keys (OICK) library, allowing for generating keys based on a provided string input.
pub trait OpenInternetGeneration: Sized {
    fn generate_with_algorithm(alg: Slug20Algorithm) -> Result<Self, SlugErrors>;
}

//=====OPENINTERNETCRYPTOGRAPHYKEYS OINT REQUIRED TRAITS END=====

pub trait OpenInternetIntoStandardPEM {
    fn into_standard_pem(&self) -> Result<String, SlugErrors>;
    fn as_standard_pem_label(&self) -> String;
}

pub trait OpenInternetFromStandardPEM: Sized {
    /// # From Standard PEM (With Algorithm)
    /// 
    /// Converts a standard PEM format into the type implementing this trait using bincode as the underlying deserialization format.
    fn from_standard_pem_with_algorithm<T: AsRef<str>>(pem: T, alg: Slug20Algorithm) -> Result<Self, SlugErrors>;
    /// # From Standard PEM
    /// 
    /// Converts a standard PEM format into the type implementing this trait using bincode as the underlying deserialization format.
    //fn from_standard_pem<T: AsRef<str>>(pem: T) -> Result<Self, SlugErrors>;
    
    // PEM Label
    fn get_standard_pem_label(&self) -> String;
    fn get_standard_pem_label_with_algorithm(alg: Slug20Algorithm) -> String;
    fn enumerate_standard_pem_labels() -> Vec<String>;
}