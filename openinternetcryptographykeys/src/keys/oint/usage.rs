use crate::keys::oint::__types::{Slug20PublicKey, Slug20SecretKey, Slug20Signature};
use fixedstr::str192;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

//=====OPENINTERNETCRYPTOGRAPHYKEYS OINT TYPES=====

/// # Open Internet Cryptography Keys (OICK) - OINT Types
/// 
/// This module defines the core types for the Open Internet Cryptography Keys (OICK) library, specifically for the OINT (Open Internet Cryptography Key) cipher suite. It includes standardized key and signature types, as well as a structure for representing cipher suites and their variants.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash,Zeroize, ZeroizeOnDrop)]
pub struct OpenInternetCryptographyPublicKey {
    pub key: Slug20PublicKey,
}

/// # Open Internet Cryptography Keys (OICK) - OINT Types
/// 
/// This module defines the core types for the Open Internet Cryptography Keys (OICK) library, specifically for the OINT (Open Internet Cryptography Key) cipher suite. It includes standardized key and signature types, as well as a structure for representing cipher suites and their variants.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash,Zeroize, ZeroizeOnDrop)]
pub struct OpenInternetCryptographySecretKey {
    pub key: Slug20SecretKey,
}

/// # Open Internet Cryptography Keys (OICK) - OINT Types
/// 
/// This module defines the core types for the Open Internet Cryptography Keys (OICK) library, specifically for the OINT (Open Internet Cryptography Key) cipher suite. It includes standardized key and signature types, as well as a structure for representing cipher suites and their variants.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash,Zeroize, ZeroizeOnDrop)]
pub struct OpenInternetCryptographySignature {
    pub signature: Slug20Signature,
}

/// # Open Internet Cryptography Keypair
/// 
/// This struct represents a keypair consisting of a public key and a secret key for the Open Internet Cryptography Keys (OICK) library, specifically for the OINT (Open Internet Cryptography Key) cipher suite.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash,Zeroize, ZeroizeOnDrop)]
pub struct OpenInternetCryptographyKeypair {
    pub public_key: OpenInternetCryptographyPublicKey,
    pub secret_key: OpenInternetCryptographySecretKey,
}

//=====OPENINTERNETCRYPTOGRAPHYKEYS OINT CIPHER SUITE=====

#[derive(Serialize, Copy, Deserialize, Debug, Clone, PartialEq, PartialOrd, Hash)]
pub struct OpenInternetCryptographyCipherSuite {
    pub cipher_suite: str192,
    pub variant: Option<str192>,
}

//=====OPENINTERNETCRYPTOGRAPHYKEYS OINT USAGE=====

