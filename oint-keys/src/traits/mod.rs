use libslug::errors::SlugErrors;

use crate::key::{OintKeypair, OintPublicKey, OintSecretKey, OintSignature};

pub trait OintGenerateKeypair<'a> {
    fn generate<T: AsRef<str>>(cipher_suite: T) -> Result<OintKeypair<'a>,SlugErrors>;
}

pub trait OintSign<'a> {
    fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Result<OintSignature,SlugErrors>;
}

pub trait OintVerify<'a> {
    fn verify<T: AsRef<[u8]>>(&self, msg: T, signature: OintSignature) -> Result<bool,SlugErrors>;
}

pub trait FromEncoding: Sized {
    fn from_bytes<T: AsRef<str>>(bytes: &[u8], algorithm: T) -> Result<Self,SlugErrors>;
    fn from_hex<T: AsRef<str>>(hex: T, algorithm: T) -> Result<Self,SlugErrors>;
    fn from_base58<T: AsRef<str>>(base58: T, algorithm: T) -> Result<Self,SlugErrors>;
    fn from_base32<T: AsRef<str>>(base32: T, algorithm: T) -> Result<Self,SlugErrors>;
    fn from_base32_unpadded<T: AsRef<str>>(base32_unpadded: T, algorithm: T) -> Result<Self,SlugErrors>;
    fn from_base64<T: AsRef<str>>(base64: T, algorithm: T) -> Result<Self,SlugErrors>;
    fn from_base64_url_safe<T: AsRef<str>>(base64_url_safe: T, algorithm: T) -> Result<Self,SlugErrors>;
}

pub trait OintKeysFromX59: Sized {
    fn from_x59<T: AsRef<str>>(x59_fmt: T, algorithm: T) -> Result<Self, SlugErrors>;
}

pub mod liberato_traits {
    use libslug::errors::SlugErrors;
    use crate::key::Liberato::{LiberatoKeypair,LiberatoPublicKey,LiberatoSecretKey,LiberatoSignature};
    use crate::algorithms::slug::Algorithms;

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
    }

    pub trait LiberatoSecretKeyTrait: Sized {
        fn generate() -> Result<Self,SlugErrors>;
        fn public_key(&self) -> Result<LiberatoPublicKey,SlugErrors>;
        fn sign<T: AsRef<[u8]>>(&self, msg: T, context: Option<T>) -> Result<LiberatoSignature,SlugErrors>;
    }

    pub trait LiberatoSigning: Sized {
        /// # Signing
        /// 
        /// Signs a message as a byte slice generic and with an optional context.
        /// 
        /// ## TODO:
        /// 
        /// - Check Context options
        fn sign<T: AsRef<[u8]>>(&self, msg: T, context: Option<T>) -> Result<Box<LiberatoSignature>,SlugErrors>;
    }

    pub trait LiberatoVerification: Sized {
        fn verify<T: AsRef<[u8]>>(&self, msg: T, context: Option<T>, signature: &LiberatoSignature) -> Result<bool,SlugErrors>;
    }

    pub trait LiberatoPublicKeyTrait: Sized {
        fn verify<T: AsRef<[u8]>>(&self, msg: T, context: Option<T>, signature: LiberatoSignature) -> Result<bool,SlugErrors>;
    }

    pub trait LiberatoX59Encoding: Sized {
        fn into_encoding(&self) -> Result<String,SlugErrors>;
        fn from_encoding<T: AsRef<str>>(encoding: T) -> Result<Self,SlugErrors>;
    }
}