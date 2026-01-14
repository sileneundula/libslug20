//! # Errors
//! 
//! This module contains all the error-handling. It uses `thiserror` for error handling.

use thiserror::Error;

/// # SlugErrors
/// 
/// Default Erroring In libslug
#[derive(Debug)]
pub enum SlugErrors {
    InvalidLengthFromBytes,
    SigningFailure,
    VerifyingError(SlugErrorAlgorithms),
    Other(String),
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
    ENC_ECIES_ED25519,
    ENC_RSA,
    ENC_KYBER,
    SYMENC_AES,
    SYMENC_XCHACHA20,
}