//! # Oint-Keys Traits
//! 
//! ## Signing and Verifying
//! 
//! - [ ] OintGeneration
//! - [ ] OintSigning
//! - [ ] OintVerifying
//! 
//! ### Encodings
//! 
//! #### Encodings
//! 
//! #### OpenInternetExport
//! 
//! - [ ] OpenInternetExport
//! 
//! #### X59 Format
//! - [ ] IntoX59
//! - [ ] FromX59
//! 
//! #### PEM
//! - [ ] IntoPEM
//! - [ ] FromPEM

use fixedstr::str256;
use libslug::errors::SlugErrors;
use crate::key::oint_keys::{OpenInternetKeypair,OpenInternetPublicKey,OpenInternetSecretKey,OpenInternetSignature};
use crate::algorithms::slug::Algorithms;


pub trait IntoPem {
    fn into_pem(&self) -> Result<String, SlugErrors>;
}

pub trait OpenInternetExport {
    fn export(&self) -> Result<String, SlugErrors>;
}

pub trait OintSecretKey {
    fn into_public_key(&self) -> Result<OpenInternetPublicKey,SlugErrors>;
}

pub trait IntoEncodingKeypair {
    fn hex(&self) -> Result<String,SlugErrors>;
    fn base32(&self) -> Result<String,SlugErrors>;
    fn base32up(&self) -> Result<String,SlugErrors>;
    fn base58(&self) -> Result<String,SlugErrors>;
    fn base64(&self) -> Result<String,SlugErrors>;
    fn base64url(&self) -> Result<String,SlugErrors>;
}

/// # IntoX59
/// 
/// Into X59 Format
pub trait IntoX59 {
    fn into_x59_fmt(&self) -> Result<String,SlugErrors>;
    fn add_prefix(&self, alg: Algorithms) -> String;
}

/// # FromX59
/// 
/// From X59 Format
pub trait FromX59: Sized {
    fn from_x59_fmt<T: AsRef<str>>(s: T, alg: Algorithms) -> Result<Self,SlugErrors>;
}

/// # IntoEncodingSecretKey
/// 
/// This trait provides methods to encode a secret key into various formats.
pub trait IntoEncodingSecretKey {
    fn into_hex(&self) -> Result<String,SlugErrors>;
    fn into_base32(&self) -> Result<String,SlugErrors>;
    fn into_base32up(&self) -> Result<String,SlugErrors>;
    fn into_base58(&self) -> Result<String,SlugErrors>;
    fn into_base64(&self) -> Result<String,SlugErrors>;
    fn into_base64url(&self) -> Result<String,SlugErrors>;
}

/// # Into Encoding Public Key
/// 
/// This trait provides methods to encode the public key into various formats.
pub trait IntoEncodingPublicKey {
    fn into_hex(&self) -> Result<String,SlugErrors>;
    fn into_base32(&self) -> Result<String,SlugErrors>;
    fn into_base32up(&self) -> Result<String,SlugErrors>;
    fn into_base58(&self) -> Result<String,SlugErrors>;
    fn into_base64(&self) -> Result<String,SlugErrors>;
    fn into_base64url(&self) -> Result<String,SlugErrors>;
}

pub trait IntoEncodingSignature {
    fn into_hex(&self) -> Result<String,SlugErrors>;
    fn into_base32(&self) -> Result<String,SlugErrors>;
    fn into_base32up(&self) -> Result<String,SlugErrors>;
    fn into_base58(&self) -> Result<String,SlugErrors>;
    fn into_base64(&self) -> Result<String,SlugErrors>;
    fn into_base64url(&self) -> Result<String,SlugErrors>;
}

pub trait OintKeypairTrait: Sized {
    /// # Generate Keypair
    /// 
    /// This trait generates the required keypairs.
    /// 
    /// ## Algorithms
    /// 
    /// ### Hybrid Algorithms
    /// 
    /// - [X] ShulginSigning
    /// - [X] EsphandSigning
    /// - [X] AbsolveSigning
    /// 
    /// ### Classical
    /// 
    /// - [X] EdDSA
    ///     - [X] ED25519
    ///     - [X] ED448
    /// - [X] ECDSA
    ///     - [X] Secp256k1
    /// - [X] Schnorr Over Ristretto
    /// - [X] BLS12-381
    /// 
    /// ### Post-Quantum
    /// 
    /// - [X] FALCON1024
    /// - [X] SPHINCS+ (SHAKE256) (Level 5)
    /// - [X] ML-DSA3 (Dilithium65)
    fn generate(alg: Algorithms) -> Result<Self,SlugErrors>;
    
    fn public_key(&self) -> &OpenInternetPublicKey;
    fn secret_key(&self) -> &OpenInternetSecretKey;
    
    fn algorithm(&self) -> Algorithms;
    
    fn cipher_suite(&self) -> String;
    fn cipher_suite_as_str256(&self) -> str256;
}

pub trait OintSigning: Sized {
    /// # Signing
    /// 
    /// Signs a message as a byte slice generic and with an optional context.
    /// 
    /// ## TODO:
    /// 
    /// - Check Context options
    fn sign_with_context<T: AsRef<[u8]>>(&self, msg: T, context: Option<T>) -> Result<Box<OpenInternetSignature>,SlugErrors>;
    fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Result<Box<OpenInternetSignature>,SlugErrors>;
}

pub trait OintVerification {
    fn verify_with_context<T: AsRef<[u8]>>(&self, msg: T, context: Option<T>, signature: &OpenInternetSignature) -> Result<bool,SlugErrors>;
    fn verify<T: AsRef<[u8]>>(&self, msg: T, signature: &OpenInternetSignature) -> Result<bool,SlugErrors>;
}