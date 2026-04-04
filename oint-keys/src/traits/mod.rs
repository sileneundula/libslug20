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

    pub trait LiberatoKeypairTrait: Sized {
        fn generate(alg: Algorithms) -> Result<Self,SlugErrors>;
    }

    pub trait LiberatoSecretKeyTrait: Sized {
        fn generate() -> Result<Self,SlugErrors>;
        fn public_key(&self) -> Result<LiberatoPublicKey,SlugErrors>;
        fn sign<T: AsRef<[u8]>>(&self, msg: T, context: Option<T>) -> Result<LiberatoSignature,SlugErrors>;
    }

    pub trait LiberatoSigning: Sized {
        fn sign<T: AsRef<[u8]>>(&self, msg: T, context: Option<T>) -> Result<LiberatoSignature,SlugErrors>;
    }

    pub trait LiberatoVerification: Sized {
        fn verify<T: AsRef<[u8]>>(&self, msg: T, context: Option<T>, signature: LiberatoSignature) -> Result<bool,SlugErrors>;
    }

    pub trait LiberatoPublicKeyTrait: Sized {
        fn verify<T: AsRef<[u8]>>(&self, msg: T, context: Option<T>, signature: LiberatoSignature) -> Result<bool,SlugErrors>;
    }

    pub trait LiberatoX59Encoding: Sized {
        fn into_encoding(&self) -> Result<String,SlugErrors>;
        fn from_encoding<T: AsRef<str>>(encoding: T) -> Result<Self,SlugErrors>;
    }
}