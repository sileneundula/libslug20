//! # LibSlug: Digital Signatures
//! 
//! This module contains all the provided digital signature schemes. A digital signature is a cryptographic signature generated using a secret key, producing a signature that can be verified by the public key of the signer's.
//! 
//! The following are provided:
//! 
//! - [X] ED25519
//! 
//! - [X] Schnorr over Ristreto
//! 
//! - [ ] ECDSA
//! 
//! - [ ] ED448
//! 
//! - [X] FALCON1024
//! 
//! - [X] ML-DSA (Dilithium65)
//! 
//! - [X] SPHINCS+ (SHAKE256) (Level 5)
//! 
//! - [ ] Lamport Signatures
//! 
//! - [ ] Winternitz One-Time Signatures (WOTS)

#[cfg(feature = "sphincs_plus")]
/// SPHINCS+ (SHAKE256) (255bit security) (smaller signature version)
pub mod sphincs_plus;

#[cfg(feature = "ed25519")]
/// ED25519 Signature
pub mod ed25519;

#[cfg(feature = "schnorr")]
/// Schnorr Digital Signature
pub mod schnorr;

#[cfg(feature = "ecdsa")]
/// ECDSA
pub mod ecdsa;

#[cfg(feature = "falcon")]
/// FALCON1024
pub mod falcon;

#[cfg(feature = "ml-dsa")]
/// MLDSA65
pub mod ml_dsa;

#[cfg(feature = "ed448")]

/// ED448
pub mod ed448;

/// ShulginSigning
pub mod shulginsigning;

/// FALCON1024
pub mod esphand_signature;

/// Dilithium (ML-DSA3) + ED25519
pub mod absolvesigning;

pub mod utils;

pub mod bls;


/// One-Time Signatures (Lamport Signatures, Winternitz-OTS)
#[cfg(feature = "experimental")]
pub mod onetimesigs;