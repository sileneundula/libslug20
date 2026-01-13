//! # LibSlug: A Rust Cryptography Library
//! 
//! This cryptography library is comprehensive and incorporates a large number of cryptological interfaces for use. It uses an easy to understand interface.
//! 
//! It also includes a module prelude that contains all necessary components.
//! 
//! It has several components, including:
//! 
//! - [X] Symmetric Encryption
//!     - [X] AES256-GCM
//!     - [X] XCHACHA20-POLY1305 (Extended Nonce)
//!     - [ ] MORUS
//! - [X] Asymmetric Encryption (Public Key Encryption)
//!     - [X] ECIES-ED25519-silene
//!     - [ ] Kyber768
//!     - [X] Kyber1024
//! - [X] Digital Signatures
//!     - [ ] RSA2048
//!     - [ ] RSA4096
//!     - [X] ED25519
//!     - [ ] ED448
//!     - [X] Schnorr
//!     - [ ] ECDSA
//!     - [X] SPHINCS+ (SHAKE256)
//!     - [ ] FALCON512
//!     - [X] FALCON1024
//!     - [X] Dilithium65 (ML-DSA)
//!     - [X] One-Time Signatures
//!         - [X] Lamport Signatures
//!         - [X] Winternitz One Time Signatures (WOTS)
//! - [X] Hash Functions
//!     - [X] SHA2 (224,256,384,512)
//!     - [X] SHA3 (224,256,384,512)
//!     - [X] BLAKE2 (s + b)
//!     - [X] BLAKE3
//! - [X] Cryptographically Secure PseudoRandom Number Generators
//!     - [X] OS-CSPRNG
//!     - [X] EphermalPass
//!     - [X] Determinstic Password
//!     - [X] Derive From Seed (ChaCha20 RNG)
//!     - [X] Verifiable Random Functions (Schnorr-VRF)
//!     - [X] BIP39 (Mnemonic)
//! 
//! ## TODO
//! 
//! - [ ] Slugencoding for all algs
//! - [ ] HybridFalcon
//! - [ ] ShulginSigning
//! - [ ] Hedged Signatures (0x20CB-style)
//! - [ ] Add ed448
//! - [ ] Add P256, P521 others
//! - [ ] Oint-Wallet
//! - [ ] BIP32

/// SlugCrypt Library
pub mod slugcrypt;

/// Slugfmt (YAML)
pub mod slugfmt;

/// x59Cert (YAML)
pub mod x59;

/// Constants
pub mod constants;

/// Errors
pub mod errors;

/// Prelude
pub mod prelude;

