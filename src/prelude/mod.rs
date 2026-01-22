pub use crate::slugcrypt::api::*;

/// # Core Usage
/// 
/// This is where all the internal stuff occurs. It is lower-level and useful to use. It can be found in the slugcrypt module.
pub mod core {
    pub use crate::errors::{SlugErrors,SlugErrorAlgorithms};
    pub use crate::slugcrypt::internals;
    pub use crate::slugcrypt::traits;
}

/// # Symmetric Encryption
/// 
/// ## Description
/// 
/// **Symmetric Encryption** is the encryption of data using an encryption algorithm that allows decryption through the encryption key.
/// 
/// ## Algorithms
/// 
/// - [X] AES256-GCM
/// - [X] XCHACHA20-POLY1305 (Extended Nonce)
/// 
/// ## TODO
/// - [ ] Add More Algorithms
pub mod SymmetricEncryption {
    pub use crate::slugcrypt::api::SlugCrypt;
}

/// # Public Key Encryption
/// 
/// ## Description
/// 
/// **Public-Key Encryption** is using the secret key to encode data to the respected public key.
/// 
/// ## Algorithms
/// 
/// - [X] ECIES-ED25519-SHA3
/// - [ ] Kyber768
/// - [X] Kyber1024
pub mod PublicKeyEncryption {
    pub use crate::slugcrypt::api::SlugAsyCrypt;
}

/// # Digital Signatures
/// 
/// ## Algorithms
/// 
/// - [X] ED25519
pub mod signatures {
    pub use crate::slugcrypt::api::SlugED25519Signatures;
}

/// # Digests
/// 
/// ## Algorithms
/// - [X] SHA2
/// - [X] SHA3
/// - [X] BLAKE2
/// - [X] BLAKE3
pub mod digests {
    pub use crate::slugcrypt::api::SlugDigest;
    pub use crate::slugcrypt::internals::digest::digest::SlugDigest as SlugDigestBytes;
}

/// # Cryptographic Random Number Generator
/// 
/// - [X] OS CSPRNG
/// - [X] Argon2
/// - [X] 
pub mod random {
    pub use crate::slugcrypt::internals::csprng::SlugCSPRNG;
}