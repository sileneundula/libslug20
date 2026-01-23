//use crate::slugfmt::certificate::cert::X59Certificate;

use slugencode::errors::SlugEncodingError;

use crate::slugcrypt::internals::signature::hybridfalconsigning::HybridFalconKeypair;

use crate::errors::SlugErrors;

/// # Recoverable Public Key
/// 
/// This type can recover its public key from its secret key.
pub trait RecoverablePublicKey {

}

/// # X59 Format
/// 
/// A Standard-Format For Encoding Cryptography.
pub trait IntoX59Encoding {
    fn to_x59(&self) -> String;
    
    fn from_x59<T: AsRef<str>>(encoded_str: T) -> Self;
    fn from_x59_hex<T: AsRef<str>>(encoded_str: T) -> Self;
    fn from_x59_base58<T: AsRef<str>>(encoded_str: T) -> Self;
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

/// # Into X59 Trait (Public Key)
/// 
/// Into X59 Format for Public Key
pub trait IntoX59PublicKey: Sized {
    fn into_x59_pk(&self) -> Result<String,SlugErrors>;
    fn from_x59_pk<T: AsRef<str>>(x59_encoded: T) -> Result<Self,SlugErrors>;
    fn x59_metadata() -> String;
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
    fn from_hex<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError>;
    fn from_base32<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError>;
    fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError>;
    fn from_base58<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError>;
    fn from_base64<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError>;
    fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError>;
}











pub trait Signature {

}

pub trait AsymmetricEncryption {

}

pub trait SymmetricEncryption {
    
}

pub trait Hashing {

}

pub trait Rand {

}

pub trait X59Signature {

}

pub trait X59Encryption {

}

pub trait X59SymmetricEncryption {
    
}