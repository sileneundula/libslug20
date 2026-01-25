//! # EsphandCertificate
//! 
//! An EsphandCertificate is a decentralized, secure, certificate scheme that uses the decentralized web to establish trust.

pub trait EsphandCertificate {

}

pub trait EsphandCertificateDigest {

}

pub trait CertificatePublicKey {
    fn public_key(&self) -> String;
    fn public_key_as_bytes(&self) -> Vec<u8>;
}