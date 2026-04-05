use fixedstr::str256;
use libslug::errors::SlugErrors;
use crate::key::Liberato::{LiberatoKeypair,LiberatoPublicKey,LiberatoSecretKey,LiberatoSignature};
use crate::algorithms::slug::Algorithms;

pub trait OintSecretKey {
    fn into_public_key(&self) -> Result<LiberatoPublicKey,SlugErrors>;
}

pub trait IntoEncodingKeypair {
    fn hex(&self) -> Result<String,SlugErrors>;
    fn base32(&self) -> Result<String,SlugErrors>;
    fn base32up(&self) -> Result<String,SlugErrors>;
    fn base58(&self) -> Result<String,SlugErrors>;
    fn base64(&self) -> Result<String,SlugErrors>;
    fn base64url(&self) -> Result<String,SlugErrors>;
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

pub trait LiberatoKeypairTrait: Sized {
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
    
    fn public_key(&self) -> &LiberatoPublicKey;
    fn secret_key(&self) -> &LiberatoSecretKey;
    
    fn algorithm(&self) -> Algorithms;
    
    fn cipher_suite(&self) -> String;
    fn cipher_suite_as_str256(&self) -> str256;
}

pub trait LiberatoSigning: Sized {
    /// # Signing
    /// 
    /// Signs a message as a byte slice generic and with an optional context.
    /// 
    /// ## TODO:
    /// 
    /// - Check Context options
    fn sign_with_context<T: AsRef<[u8]>>(&self, msg: T, context: Option<T>) -> Result<Box<LiberatoSignature>,SlugErrors>;
    fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Result<Box<LiberatoSignature>,SlugErrors>;
}

pub trait LiberatoVerification {
    fn verify<T: AsRef<[u8]>>(&self, msg: T, context: Option<T>, signature: &LiberatoSignature) -> Result<bool,SlugErrors>;
}