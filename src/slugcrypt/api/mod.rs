//! # SlugCrypt
//! 
//! This is the standard interface for using libslug (slugcrypt) and provides various helper functions and functionalities to abstract away from internals.
//! 
//! It contains the following structs:
//! 
//! 1. SlugCrypt (Symmetric Encryption using AES256-GCM or XCHACHA20-POLY1305)
//! 2. SlugAsyCrypt (Asymmetric Encryption using ECIES-ED25519-silene (SHA3) or Kyber768)
//! 3. SlugSignatures (Digital Signatures using a variety of different signature schemes)
//! 4. SlugDigest (Hash Functions like Blake2, SHA2, SHA3, BLAKE3)
//! 5. SlugCSPRNG (Random Number Generation)
//! 
//! For Signatures, it contains the following:
//! 
//! 1. SlugED25519Signatures
//! 2. SlugSchnorrSignatures
//! 3.

/// # SlugCrypt
/// 
/// SlugCrypt is the main usage struct for encryption using:
/// 
/// - AES-256-GCM
/// - XCHACHA20-POLY1305 (extended nonce)
pub struct SlugCrypt;

/// # SlugAsyCrypt
/// 
/// SlugAsyCrypt is the Asymetric encryption that is performed using:
/// 
/// - ECIES-ED25519-silene (SHA3)
/// - \[PQ] Kyber768 (not implemented)
pub struct SlugAsyCrypt;

/// # SlugSignatures
/// 
/// SlugSignatures is the main interface for signing/verifying and doing all the above for signatures. It contains:
/// 
/// ## Signatures
/// 
/// - ED25519
/// - Schnorr
/// - \[PQ] Dilithium (ML-DSA)
/// - \[PQ] FALCON1024
/// - \[PQ] SPHINCS+ (SHAKE256) (ML-SLH) (Level 5)
/// 
/// ## One-Time Signatures
/// 
/// - \[PQ] Lamport Signatures
/// - \[PQ] Winternitz-OTS Signatures
pub struct SlugSignatures;

/// # ED25519
pub struct SlugED25519Signatures;

/// # Schnorr Signatures
pub struct SlugSchnorrSignatures;

/// # SPHINCS (PLUS) (SHAKE256)
pub struct SlugSphincsPlus;

pub struct SlugFalcon1024;

pub struct SlugMLDSA;

/// # Digests
/// 
/// Digests API (BLAKE2, SHA2, SHA3, BLAKE3)
pub struct SlugDigest;

pub struct VerifiableRandomFunction;

/// # SlugCSPRNG
/// 
/// The cryptographic random number generator
/// 
/// ## Styles
/// 
/// - SecureRand (password as entropy as well as OS salt)
/// 
/// - from_os()
/// 
/// - mnemonic()
pub struct SlugCSPRNGAPI;

use bip39::{ErrorKind, Language};
use ed25519_dalek::SignatureError;

use crate::slugcrypt::internals::encrypt::chacha20::*;
use crate::slugcrypt::internals::encrypt::aes256::{EncryptAES256, DecryptAES256};
use crate::slugcrypt::internals::encrypt::aes256;
use crate::slugcrypt::internals::encryption::ecies::*;

use crate::slugcrypt::internals::digest::blake2;
use crate::slugcrypt::internals::digest::sha2;
use crate::slugcrypt::internals::digest::sha3;
use crate::slugcrypt::internals::digest::blake3;
use crate::slugcrypt::internals::digest::digest;

use crate::slugcrypt::internals::csprng::SlugCSPRNG;

use crate::slugcrypt::internals::bip39::SlugMnemonic;
use crate::slugcrypt::internals::signature::ed25519::{ED25519PublicKey, ED25519SecretKey, ED25519Signature};
use crate::slugcrypt::internals::signature::schnorr::{SchnorrIO, SchnorrPreout, SchnorrPublicKey, SchnorrSecretKey, SchnorrSignature, SchnorrVRFProof};

use super::internals::ciphertext::CipherText;

impl SlugCrypt {
    /// Encrypt Using XChaCha20Poly1305
    pub fn encrypt<T: AsRef<[u8]>>(key: EncryptionKey, data: T) -> Result<(EncryptionCipherText,EncryptionNonce),chacha20poly1305::aead::Error> {
        let x = XChaCha20Encrypt::encrypt(key, data.as_ref())?;
        return Ok(x)
    }
    /// Decrypt Using XChaCha20Poly1305
    pub fn decrypt(key: EncryptionKey, nonce: EncryptionNonce, data: EncryptionCipherText) -> Result<Vec<u8>,chacha20poly1305::aead::Error> {
        let x = XChaCha20Encrypt::decrypt(key, nonce, data)?;
        return Ok(x)
    }
    /// Encrypt Using AES256-GCM
    pub fn encrypt_aes256<T: AsRef<[u8]>>(key: aes256::EncryptionKey, data: T) -> Result<(aes256::AESCipherText,aes256::EncryptionNonce),aes_gcm::Error> {
        let x: (aes256::AESCipherText, aes256::EncryptionNonce) = EncryptAES256::encrypt(key, data.as_ref())?;
        return Ok(x)
    }
    /// Decrypt Using AES256-GCM
    pub fn decrypt_aes256(key: aes256::EncryptionKey, nonce: aes256::EncryptionNonce, data: aes256::AESCipherText) -> Result<Vec<u8>,aes_gcm::Error> {
        let x = DecryptAES256::decrypt(key, nonce, data)?;
        return Ok(x)
    }
}

impl SlugDigest {
    /// BLAKE2B with variable digest size from 1-64 bytes (8-512 bits)
    /// 
    /// Defaults to 48 bytes if invalid value added
    pub fn blake2b(size: usize, data: &[u8]) -> digest::SlugDigest {
        let hasher = blake2::SlugBlake2bHasher::new(size);
        let result = hasher.update(data);
        return digest::SlugDigest::from_bytes(&result).unwrap()
    }
    /// Blake2s with variable digest size from 1-32 bytes (8-256 bits)
    /// 
    /// Defaults to 32 bytes if invalid value added
    pub fn blake2s(size: usize, data: &[u8]) -> digest::SlugDigest {
        let hasher = blake2::SlugBlake2sHasher::new(size);
        let result = hasher.update(data);
        return digest::SlugDigest::from_bytes(&result).unwrap()
    }
    /// SHA2 with SHA2-224, SHA256, SHA384, SHA512 (defaults to 512 if invalid value added)
    pub fn sha2(size: usize, data: &[u8]) -> digest::SlugDigest {
        let hasher = sha2::Sha2Hasher::new(size);
        let result = hasher.update(data);
        return digest::SlugDigest::from_bytes(&result).unwrap()
    }
    /// SHA3 with SHA3-224, SHA3-256, SHA3-384, SHA3-512
    pub fn sha3(size: usize, data: &[u8]) -> digest::SlugDigest {
        let hasher = sha3::Sha3Hasher::new(size);
        let result = hasher.update(data);
        return digest::SlugDigest::from_bytes(&result).unwrap()
    }
    /// The efficient BLAKE3 hash function with byte size of 32 bytes
    pub fn blake3(data: &[u8]) -> digest::SlugDigest {
        let mut hasher = blake3::Blake3Hasher::new();
        let result = hasher.update(data);
        return digest::SlugDigest::from_bytes(&result).unwrap()
    }
}

impl SlugAsyCrypt {
    // Encrypt using ECIES-ED25519-Silene
    pub fn encrypt<T: AsRef<[u8]>>(pk: ECPublicKey, data: T) -> Result<super::internals::ciphertext::CipherText, ecies_ed25519::Error> {
        let ct: Result<super::internals::ciphertext::CipherText, ecies_ed25519::Error> = ECIESEncrypt::encrypt(&pk, data.as_ref());
        return ct
    }
    // Decrypt Using ECIES-ED25519-Silene
    pub fn decrypt(sk: ECSecretKey, ct: CipherText) -> Result<super::internals::messages::Message, ecies_ed25519::Error> {
        let x: Result<super::internals::messages::Message, ecies_ed25519::Error> = ECIESDecrypt::decrypt(&sk, &ct);
        return x
    }
}

impl SlugCSPRNGAPI {
    /// SecureRand Algorithm For Secure Random Number Generation Using Ephermal Passwords and OS RNG With the CHACHA20RNG
    pub fn new(pass: &str) -> [u8;32] {
        SlugCSPRNG::new(pass)
    }
    /// Retrieve Randomness From The Operating System
    pub fn from_os() -> [u8;32] {
        SlugCSPRNG::os_rand()
    }
    pub fn from_seed_64(bytes: [u8;32]) -> [u8;64] {
        SlugCSPRNG::from_seed_64(bytes)
    }
    pub fn from_seed(bytes: [u8;32]) -> [u8;32] {
        SlugCSPRNG::from_seed(bytes)
    }
    /// Generate a new Mnemonic
    pub fn mnemonic(mnemonic: SlugMnemonic, pass: &str) -> Result<[u8;32],ErrorKind> {
        let seed = mnemonic.to_seed(pass)?;
        let mut output: [u8;32] = [0u8;32];

        output.copy_from_slice(&seed);

        Ok(output)
    }
}

impl VerifiableRandomFunction {
    pub fn generate() -> SchnorrSecretKey {
        return SchnorrSecretKey::generate();
    }
    pub fn create_schnorr_vrf<T: AsRef<[u8]>>(sk: SchnorrSecretKey, msg: T, context: T) -> (SchnorrIO,SchnorrVRFProof,SchnorrPreout)  {
        return sk.vrf(msg.as_ref(), context.as_ref())
    }
    pub fn verify_schnorr_vrf<T: AsRef<[u8]>>(pk: SchnorrPublicKey, vrf_io: SchnorrIO, vrf_proof: SchnorrVRFProof, vrf_preout: SchnorrPreout, msg: T, context: T) -> Result<(schnorrkel::vrf::VRFInOut, schnorrkel::vrf::VRFProofBatchable),schnorrkel::SignatureError> {
        let x = pk.verify_vrf(vrf_preout, vrf_io, vrf_proof, context.as_ref(), msg.as_ref())?;
        return Ok(x)
    }
}

impl SlugED25519Signatures {
    /// Generate ED25519 using OS Randomness
    pub fn generate() -> ED25519SecretKey {
        ED25519SecretKey::generate()
    }
    /// Generate ED25519 Using SecureRand with CHACHA20RNG and Ephermal Password
    pub fn generate_securerand(pass: &str) -> ED25519SecretKey {
        ED25519SecretKey::generate_securerand(pass)
    }
    /// Get ED25519 Public Key From Secret Key
    pub fn public_key(sk: ED25519SecretKey) -> Result<ED25519PublicKey, SignatureError>{
        let pk = sk.public_key()?;
        Ok(pk)
    }
    /// Sign using ED25519 Key
    pub fn sign<T: AsRef<[u8]>>(sk: ED25519SecretKey, data: T) -> Result<ED25519Signature,SignatureError> {
        let signature = sk.sign(data.as_ref())?;
        Ok(signature)
    }
    /// Verifies an ED25519 Signature
    pub fn verify<T: AsRef<[u8]>>(pk: ED25519PublicKey, signature: ED25519Signature, data: T) -> Result<bool, SignatureError> {
        let is_valid = pk.verify(signature, data)?;
        Ok(is_valid)
    }
}

impl SlugSchnorrSignatures {
    pub fn generate() -> SchnorrSecretKey {
        let x = SchnorrSecretKey::generate();
        return x
    }
    pub fn sign<T: AsRef<[u8]>>(sk: SchnorrSecretKey, message: T, context: T) -> Result<SchnorrSignature, schnorrkel::SignatureError> {
        let sig: SchnorrSignature = sk.sign_with_context(message.as_ref(), context.as_ref())?;
        return Ok(sig)
    }
}