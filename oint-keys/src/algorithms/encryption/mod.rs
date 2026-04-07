//! # Oint-Keys Public Key Encryption:
//! 
//! This module contains the type for a public key used for encrypting/decrypting data.
//! 
//! ## Implemented
//! 
//! - [ ] RSA
//! - [X] ECIES_ED25519_SHA3
//! - [X] Kyber1024 (ML-KEM-5) (Post-Quantum)

use libslug::slugcrypt::internals::encryption::ecies::{ECPublicKey,ECSecretKey,ECIESDecrypt,ECIESEncrypt};
use libslug::slugcrypt::internals::encryption::ml_kem::{MLKEMPublicKey,MLKEMSecretKey,MLKEMSharedSecret,MLKEMCipherText};
use libslug::slugcrypt::internals::ciphertext::CipherText as EciesCipherText;

pub enum EncryptionAlgorithms {
    ECIES_ED25519_SHA3,
    MLKEM,
}

pub enum EncryptionPublicKey {
    ECIES_ED25519_SHA3(ECPublicKey),
    MLKEM_5(MLKEMPublicKey)
}
    
pub enum EncryptionSecretKey {
    ECIES_ED25519_SHA3(ECSecretKey),
    MLKEM_5(MLKEMSecretKey)
}

pub enum SharedSecret {
    MLKEM_5(MLKEMSharedSecret)
}

pub enum EncryptionCipherText {
    ECIES_ED25519_SHA3(EciesCipherText),
    MLKEM_5(MLKEMCipherText),
}