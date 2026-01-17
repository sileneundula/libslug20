//! # X59 Public Key Format
//! 
//! A standardized, modular format for cryptography.
//! 
//! 
//! [libslug/ed25519]
//! [custom::ed25519][(!id)]
//! 
//! One with no attribute is the algorithm used. Use custom/ for others.
//! 
//! ## Encodings
//! 
//! Encodings should be in:
//! 
//! - Hexadecimal (prefered)
//! - Base32
//! - Base58
//! - Base64

/// # Attribute
/// 
/// Attribute defines the value inside the braces and the properties it has.
/// 
/// ## Format
/// 
/// `[(!<value>)]` where <value> is the attribute
pub struct Attribute {
    _type: String,
}

/// Parsing For X59 Certificate Type
pub mod parser;

pub mod constants;

pub mod label;

pub mod errors;

pub mod prelude;

pub mod derive;