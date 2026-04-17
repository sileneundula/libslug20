use libslug::slugcrypt::internals::signature;
// Keys
use libslug::slugcrypt::internals::signature::shulginsigning::ShulginKeypair;
use libslug::slugcrypt::internals::signature::absolvesigning::AbsolveKeypair;
use libslug::slugcrypt::internals::signature::esphand_signature::EsphandKeypair;
// Signatures
use libslug::slugcrypt::internals::signature::shulginsigning::ShulginSignature;
use libslug::slugcrypt::internals::signature::absolvesigning::AbsolveSignature;
use libslug::slugcrypt::internals::signature::esphand_signature::EsphandSignature;

/// # Standardized Key and Signature Types
/// 
/// This module defines standardized key and signature types for the Open Internet Cryptography Keys (OICK) library, allowing for consistent handling of different cryptographic key types and their associated signatures.
pub enum StandardPublicKey {
    ShulginSigning(ShulginKeypair),
    AbsolveSigning(AbsolveKeypair),
    EsphandSigning(EsphandKeypair),
}

/// # Standardized Private Key Types
/// 
/// This enum defines standardized private key types for the Open Internet Cryptography Keys (OICK) library, enabling consistent management of different cryptographic key types.
pub enum StandardPrivateKey {
    ShulginSigning(ShulginKeypair),
    AbsolveSigning(AbsolveKeypair),
    EsphandSigning(EsphandKeypair),
}

/// # Standardized Signature Types
/// 
/// This enum defines standardized signature types for the Open Internet Cryptography Keys (OICK) library, enabling consistent handling of different cryptographic signature types.
pub enum StandardSignature {
    ShulginSigning(ShulginSignature),
    AbsolveSigning(AbsolveSignature),
    EsphandSigning(EsphandSignature),
}

pub mod standard;
pub mod algorithms;
pub mod suite;