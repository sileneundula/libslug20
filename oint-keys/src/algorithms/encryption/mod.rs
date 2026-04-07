use libslug::slugcrypt::internals::encryption::ecies::{ECPublicKey,ECSecretKey,ECIESDecrypt,ECIESEncrypt};
use libslug::slugcrypt::internals::encryption::ml_kem::{MLKEMPublicKey,MLKEMSecretKey,MLKEMSharedSecret,MLKEMCipherText};

pub enum SlugEncryptionAlgorithms {
    ECIES_ED25519_SHA3,
    MLKEM,
}

pub enum EncryptionPublicKey {
    ECIES_ED25519_SHA3(ECPublicKey),
    MLKEM_5(MLKEMPublicKey)
}