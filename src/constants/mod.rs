//! # Constants
//! 
//! This module contains all the needed constants.
//! 
//! ## List of Constants
//! 
//! ### ECIES-ED25519-Silene
//! 
//! - ECIES-ED25519-PK-SIZE: 32 bytes
//! - ECIES-ED25519-SK-SIZE: 32 bytes
//! 
//! 


// ECIES

/// ECIES Public Key (ED25519-silene): 32 bytes
pub const ECIESED25519_PK_SIZE: usize = 32;

/// ECIES Secret Key (ED25519-silene): 32 bytes
pub const ECIESED25519_SK_SIZE: usize = 32;

/// Cipher Suites
pub mod cipher_suites;