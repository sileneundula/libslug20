//use crate::slugfmt::certificate::cert::X59Certificate;

use slugencode::errors::SlugEncodingError;

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

/*
pub trait FromEncoding {
    fn from_hex<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError>;
    fn from_base32<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError>;
    fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError>;
    fn from_base58<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError>;
    fn from_base64<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError>;
    fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError>;
}
     */











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