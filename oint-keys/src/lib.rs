//! # OpenInternet Keys
//! 
//! An abstraction for cryptographic primitives for the open internet or Web 3.20.
//! 
//! ## Features
//! 
//! - [ ] Hybrid Signatures: ShulginSigning, EsphandSigning, AbsolveSigning

use oint_keys_traits::{IsOintPublicKey,IsOintSecretKey,IsOintSignature};

/// Official Oint-Keys Key Types
pub mod key;
/// Official Oint-Keys Traits
pub mod traits;

/// Constants for Oint-Keys
pub mod constants;

/// Official Oint-Keys Encodings
pub mod encodings;

/// Official Oint-Keys Algorithms
pub mod algorithms;