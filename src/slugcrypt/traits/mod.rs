//! # Slug20 Traits
//! 
//! This is a collection of common-traits used by the libslug library.
//! 
//! ## Verified Traits
//! 
//! ## Encoding
//! 
//! - [X] IntoEncoding
//! - [X] FromEncoding
//! 
//! ## PEM
//! 
//! - [ ] IntoPemPublic
//! - [ ] IntoPemSecret
//! - [ ] IntoPemSignature
//! 
//! ## Traits
//! 
//! - [X] IntoPEM
//!     - [X] IntoPemPublic
//!     - [X] IntoPemSecret
//!     - [X] IntoPemSignature
//! - [X] IntoX59
//!     - [X] IntoX59Public
//!     - [X] IntoX59Secret
//!     - [X] IntoX59Signature
//!     - [ ] IntoX59Encryption
//! - [ ] Signature Digest (BLAKE3)
//!     - [ ] BLAKE3
//!     - [ ] SHA256
//!     - [ ] SHA512
//!     - [ ] BLAKE2B (Variable)
//! - [ ] GenerateWithBIP39
//!     - [ ] Implemented
//!         - [ ] X
//! - [ ] SignWithHedgedSignature
//! - [ ] DeriveOintDigest (uses BLAKE2B to derive an address from the input)
//! 
//! ## Implemented Traits
//! 
//! - [X] IntoPEM
//!     - [X] EsphandSignature
//!     - [X] ShulginSigning

//use crate::slugfmt::certificate::cert::X59Certificate;

use bip39::Language;
use slugencode::errors::SlugEncodingError;

use crate::slugcrypt::internals::signature::esphand_signature::EsphandKeypair;

use crate::errors::SlugErrors;

//=====VERIFIED=====//

/// # Into Encoding
/// 
/// Contains Constant-Time Encodings For Various Types
pub trait IntoEncoding {
    fn to_hex(&self) -> Result<String,SlugEncodingError>;
    fn to_base32(&self) -> Result<String,SlugEncodingError>;
    fn to_base32_unpadded(&self) -> Result<String,SlugEncodingError>;
    fn to_base58(&self) -> Result<String,SlugEncodingError>;
    fn to_base64(&self) -> Result<String,SlugEncodingError>;
    fn to_base64_url_safe(&self) -> Result<String,SlugEncodingError>;
}

pub trait FromEncoding: Sized {
    fn from_hex<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors>;
    fn from_base32<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors>;
    fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors>;
    fn from_base58<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors>;
    fn from_base64<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors>;
    fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors>;
}

pub trait StandardExport {
    fn export(&self) -> Result<String,SlugErrors>;
}

//=====END OF VERIFIED=====//

/// # Recoverable Public Key
/// 
/// This type can recover its public key from its secret key.
pub trait RecoverablePublicKey {

}

/// # HybridCryptographyRevert
/// 
/// Verifies one of the signatures.
pub trait HybridCryptographyRevert: Sized {
    fn verify_classical(&self) -> bool;
    fn verify_pq(&self) -> bool;
}

/// # IntoPemX59
/// 
/// Converts Into PEM format using X59FMT Standard as input.
pub trait IntoPemX59: Sized {
    fn into_pem_x59_standard(&self) -> Result<String,SlugErrors>;
    fn from_pem_x59_standard<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors>;
    fn info_pem_x59_standard_label() -> String;
}

pub trait IntoPemX59PublicKey: Sized {
    fn into_pem_x59_standard_pk(&self) -> Result<String,SlugErrors>;
    fn from_pem_x59_standard_pk<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors>;
    fn info_pem_x59_standard_label() -> String;
}


/// # IntoPem Trait
/// 
/// The IntoPem trait handles all serialiazing of data structures using the PEM format.
pub trait IntoPem: Sized {
    fn into_pem_public(&self) -> String;
    fn into_pem_private(&self) -> String;
    fn from_pem_public<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors>;
    fn from_pem_private<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors>;
    fn get_pem_label_for_public() -> String;
    fn get_pem_label_for_secret() -> String;
}

pub trait IntoPemPublic: Sized {
    fn into_pem(&self) -> Result<String,SlugErrors>;
    fn from_pem<T: AsRef<str>>(public_key_in_pem: T) -> Result<Self,SlugErrors>;
    fn get_pem_label() -> String;
}

pub trait IntoPemSecret: Sized {
    fn into_pem_secret(&self) -> Result<String,SlugErrors>;
    fn from_pem_secret<T: AsRef<str>>(secret_key_in_pem: T) -> Result<Self,SlugErrors>;
    fn get_pem_label_secret() -> String;
}

pub trait IntoPemSignature: Sized {
    fn into_pem(&self) -> Result<String,SlugErrors>;
    fn from_pem<T: AsRef<str>>(signature_in_pem: T) -> Result<Self,SlugErrors>;
    fn get_pem_label_signature() -> String;
}

pub trait GenerateWithBIP39: Sized {
    fn generate_bip39<T: AsRef<str>>(num_of_words: usize, language: Language, password: T) -> Result<Self,SlugErrors>;
}

/// # Into X59 Trait (Public Key)
/// 
/// Into X59 Format for Public Key
pub trait IntoX59PublicKey: Sized {
    fn into_x59_pk(&self) -> Result<String,SlugErrors>;
    fn from_x59_pk<T: AsRef<str>>(x59_encoded: T) -> Result<Self,SlugErrors>;
    fn x59_metadata_pk() -> String;
}

pub trait IntoX59SecretKey: Sized {
    fn into_x59(&self) -> Result<String,SlugErrors>;
    fn from_x59<T: AsRef<str>>(x59_encoded_secret_key: T) -> Result<Self,SlugErrors>;
    fn x59_metadata() -> String;
}

pub trait IntoX59Signature: Sized {
    fn into_x59(&self) -> Result<String,SlugErrors>;
    fn from_x59<T: AsRef<str>>(x59_encoded_signature: T) -> Result<Self,SlugErrors>;
    fn x59_metadata() -> String;
}

pub trait IsMessage {
    fn as_str(&self) -> &str;
    fn to_str(&self) -> String;
    fn as_bytes(&self) -> &[u8];
}




pub trait SignatureDigest {
    fn as_digest(&self) -> String;
}