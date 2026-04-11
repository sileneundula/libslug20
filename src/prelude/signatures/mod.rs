/// Prelude For Signature Scheme ED25519
pub mod ed25519 {
    pub use crate::slugcrypt::internals::signature::ed25519::{ED25519PublicKey,ED25519SecretKey,ED25519Signature};
}

/// Prelude For Signature Scheme Ed448
pub mod ed448 {
    pub use crate::slugcrypt::internals::signature::ed448::{Ed448Keypair,Ed448PublicKey,Ed448SecretKey,Ed448Signature};
    pub use crate::slugcrypt::internals::signature::ed448::ED448_CONTEXT;
    pub use crate::slugcrypt::internals::signature::ed448::protocol_info as ed448_info;
}

/// Prelude for Signature Scheme Schnorr over Ristresto
pub mod schnorr {
    pub use crate::slugcrypt::internals::signature::schnorr::{SchnorrPublicKey,SchnorrSecretKey,SchnorrSignature,SchnorrPreout,SchnorrIO,SLUGCRYPT_CONTEXT};
}