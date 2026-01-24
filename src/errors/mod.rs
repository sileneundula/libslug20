//! # Errors
//! 
//! This module contains all the error-handling. It uses `thiserror` for error handling.
//! 
//! The error type is known as `SlugErrors` and implements the crate `thiserror` for easy error handling.
//! 
//! Most types will return `SlugErrors`.
//! 
//! ## Features
//! 
//! - [X] Error Handeling
//! - [ ] Error Codes

use std::fmt::Display;

use slugencode::errors::SlugEncodingError;
use thiserror::Error;
use std::convert::From;


/// # SlugErrors
/// 
/// Default Erroring In libslug
/// 
/// ## Errors
/// 
/// - [X] EncodingError
/// - [X] DecodingError
/// - [X] SigningError
/// - [X] VerifyingError
/// - [X] EncryptionError
/// - [X] DecryptionError
/// - [X] InvalidLengthFromBytes
/// - [X] Other
#[derive(Debug, Error)]
pub enum SlugErrors {
    ///=====ENCODING/DECODING=====///
    #[error("Encoding Error Encountered In {alg:?} With Encoding {encoding:?}. Other Info: {other:?}")]
    EncodingError {
        alg: SlugErrorAlgorithms,
        encoding: EncodingError,
        other: Option<String>,
    },
    #[error("Decoding Error Encountered In {alg:?} With Encoding {encoding:?}. Other Info: {other:?}")]
    DecodingError {
        alg: SlugErrorAlgorithms,
        encoding: EncodingError,
        other: Option<String>,
    },
    #[error("Invalid Number of Bytes")]
    InvalidLengthFromBytes,
    #[error("Signing Failure For {0:?}")]
    SigningFailure(SlugErrorAlgorithms),
    #[error("Verifying Failure For {0:?}")]
    VerifyingError(SlugErrorAlgorithms),
    #[error("Decryption Error For {alg:?}")]
    DecryptionError {
        alg: SlugErrorAlgorithms,
    },
    #[error("Encryption Error For {alg:?}")]
    EncryptionError {
        alg: SlugErrorAlgorithms,
    },
    #[error("[Error] Other: {0:?}")]
    Other(String),
    #[error("[Error] SlugEncodingError: {0:?}")]
    SlugEncodingErrors(SlugEncodingError),
}

impl From<SlugEncodingError> for SlugErrors {
    fn from(value: SlugEncodingError) -> Self {
        match value {
            SlugEncodingError => return SlugErrors::SlugEncodingErrors(value)
        }
        
    }
}

#[derive(Debug)]
pub enum SlugErrorAlgorithms {
    SIG_ED25519,
    SIG_ED448,
    SIG_SCHNORR,
    SIG_SPHINCS_PLUS,
    SIG_FALCON,
    SIG_MLDSA,
    SIG_SHULGINSIGNING,
    SIG_BLS,
    SIG_SECP256k1,
    ENC_ECIES_ED25519,
    ENC_RSA,
    ENC_KYBER,
    SYMENC_AES,
    SYMENC_XCHACHA20,
}

/* 
impl Display for SlugErrorAlgorithms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let x = match self::SlugErrorAlgorithms {
            SlugErrorAlgorithms::ENC_ECIES_ED25519 => String::from("ECIES-ED25519-SHA3"),
            SlugErrorAlgorithms::ENC_KYBER => String::from("Kyber1024"),
            SlugErrorAlgorithms::ENC_RSA => String::from("RSA"),
            SlugErrorAlgorithms::SIG_BLS => String::from("BLS12-381"),
            SlugErrorAlgorithms::SIG_ED25519 => String::from("ED25519"),
            SlugErrorAlgorithms::SIG_ED448 => String::from("ED448"),
            SlugErrorAlgorithms::SIG_FALCON => String::from("FALCON1024"),
            SlugErrorAlgorithms::SIG_MLDSA => String::from("MLDSA"),
            SlugErrorAlgorithms::SIG_SCHNORR => String::from("Schnorr"),
            SlugErrorAlgorithms::SIG_SHULGINSIGNING => String::from("ShulginSigning"),
            SlugErrorAlgorithms::SIG_SPHINCS_PLUS => String::from("SPHINCS+ (SHAKE256)"),
            SlugErrorAlgorithms::SYMENC_AES => String::from("AES-256"),
            SlugErrorAlgorithms::SYMENC_XCHACHA20 => String::from("XCHACHA20-POLY1305"),
            _ => panic!("None")
        }
        f.fmt(x);
        Ok(())
    }
}
*/    

#[derive(Debug)]
pub enum EncodingError {
    Bytes,
    Hexadecimal,
    Base32,
    Base32unpadded,
    Base58,
    Base64,
    Base64urlsafe,
    
    X59_fmt,
    PEM,
}