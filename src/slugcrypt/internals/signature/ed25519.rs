//! # ED25519 Digital Signature
//! 
//! This contains the ED25519 Digital Signature scheme using dalek's audited crate. It implements zeroize, serialization, and other common utilties and makes it easy to sign, as well as store keys.
//! 
//! ## Features
//! 
//! ### Generation
//! 
//! - [X] Operating System Randomness
//! - [X] SecureRand
//! - [X] SecureRand with determinstic generation
//! - [X] BIP39
//! 
//! ### Signing
//! 
//! - [X] Sign
//! - [ ] Sign with Hedged Signatures
//! 
//! ### Verification
//! 
//! - [X] Verify
//! 
//! ### Encodings
//! 
//! Supports multiple encodings, including hexadecimal, base32, and base58.
//! 
//! ## TODO
//! 
//! - PKCS #7
//! - More encodings
//! - Certificate Encoding

use bip39::Language;
use ed25519_dalek::{Signer,Verifier};
use ed25519_dalek::ed25519::SignatureEncoding;
use ed25519_dalek::SignatureError;
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use ed25519_dalek::Signature;
use ed25519_dalek::SecretKey;
use rand::rngs::OsRng;
use zeroize::{Zeroize,ZeroizeOnDrop};
use serde::{Serialize,Deserialize};
use crate::slugcrypt::internals::bip39::SlugMnemonic;
use crate::slugcrypt::internals::csprng::SlugCSPRNG;
use crate::errors::SlugErrors;
use subtle_encoding::hex;
use subtle_encoding::Error;

use bip39::ErrorKind;

use base32;
use base58::{FromBase58,ToBase58,FromBase58Error};
use serde_big_array::BigArray;


/// # ED25519: Public Key (Verifying Key)
/// 
/// ## Description
/// 
/// 32-byte Key in ED25519. It implements zeroize and serialization.
/// 
/// It is used to verify signatures.
#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize, Clone, Debug)]
pub struct ED25519PublicKey([u8;32]);

/// # ED25519: Secret Key (Signing Key)
/// 
/// ## Description
/// 
/// 32-byte Key in ED25519. It implements zeroize and serialization.
/// 
/// It is used to sign data/messages.
/// 
/// The public key can be derived from the secret key.
/// 
/// ## Generation
/// 
/// - From Operating System Randomness (OS)
/// - SecureRand (Ephermal Password + Argon2id + ChaCha20RNG + OSCSPRNG Salt)
/// - BIP39
/// 
/// ## Signing
/// 
/// - Sign message or data
#[derive(Zeroize,ZeroizeOnDrop,Serialize,Deserialize, Clone, Debug)]
pub struct ED25519SecretKey([u8;32]);

/// # ED25519: Signature
/// 
/// ## Description
/// 
/// 64-byte signature in ED25519. It implements zeroize and serialization.
/// 
/// It is used to verify digital signatures.
#[derive(Zeroize,ZeroizeOnDrop,Debug,Serialize,Deserialize, Clone)]
pub struct ED25519Signature(#[serde(with = "BigArray")][u8;64]);


pub mod protocol_info {
    pub const PROTOCOL_NAME: &str = "libslug20/ed25519";
    pub const PK_SIZE: usize = 32;
    pub const SK_SIZE: usize = 32;
    pub const SIG_SIZE: usize = 64;
    pub const DERIVES_PUBLIC_KEY_FROM_SECRET: bool = true;
    pub const RANDOMNESS: [&str;4] = ["Operating-System CSPRNG","SecureRand","Deterministic With Password","BIP39"];
}

impl ED25519SecretKey {
    /// Generates from OS-Generated Random Seed
    /// 
    /// ```rust
    /// fn main() {
    ///     use libslug::slugcrypt::internals::signature::ed25519;
    /// 
    ///     // Generate Secret Key From Operating System Randomness
    ///     let sk = ed25519::ED25519SecretKey::generate();
    /// }
    /// ```
    pub fn generate() -> ED25519SecretKey {
        let csprng = SlugCSPRNG::os_rand();
        let signing_key = SigningKey::from_bytes(&csprng);

        return ED25519SecretKey(signing_key.to_bytes())
    }
    /// Generates ED25519 Secret Key From Password With OS-Generated Salt using Argon2id and pushes into ChaCha20RNG to generate seed.
    pub fn generate_securerand(pass: &str) -> ED25519SecretKey {
        let csprng = SlugCSPRNG::new(pass);
        let signing_key = SigningKey::from_bytes(&csprng);

        return ED25519SecretKey(signing_key.to_bytes())
    }
    /// \[Determinstic] Generates Determinstically (warning: some security caution as this is deterministic with password and salt)
    pub fn generate_deterministic(pass: &str, salt: &str) -> ED25519SecretKey {
        let csprng = SlugCSPRNG::derive_from_password_with_salt(pass, salt);
        let signing_key = SigningKey::from_bytes(&csprng);

        return ED25519SecretKey(signing_key.to_bytes());
    }
    /// From BIP39 (Generation or From)
    pub fn from_bip39(mnemonic: SlugMnemonic, language: bip39::Language, password: &str) -> Result<Self,ErrorKind> {
        let seed = mnemonic.to_seed(password, language)?;
        Ok(Self::from_bytes(&seed).unwrap())
    }
    /// to byte array of 32 bytes
    pub fn to_bytes(&self) -> [u8;32] {
        self.0
    }
    /// as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    /// [Encoding] UPPER-HEXADECIMAL
    pub fn to_hex_string(&self) -> String {
        String::from_utf8(hex::encode_upper(self.0)).unwrap()
    }
    /// [Encoding] Decode From UPPER-HEXADECIMAL
    pub fn from_hex_string<T: AsRef<str>>(hex_str: T) -> Result<Vec<u8>,Error> {
        let bytes = hex::decode_upper(hex_str.as_ref().as_bytes())?;
        Ok(bytes)
    }
    /// from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<ED25519SecretKey, SlugErrors> {
        let mut secret_key_array: [u8;32] = [0u8;32];
        
        if bytes.len() == 32 {
            secret_key_array.copy_from_slice(bytes);
            return Ok(ED25519SecretKey(secret_key_array))
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    /// to usable type
    pub fn to_usable_type(&self) -> SigningKey {
        SigningKey::from_bytes(&self.0)
    }
    /// into public key
    pub fn public_key(&self) -> Result<ED25519PublicKey,SignatureError> {
        let vk = self.to_usable_type().verifying_key();
        Ok(ED25519PublicKey(vk.to_bytes()))
    }
    /// # Signing
    /// 
    /// Signs a message or data.
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Result<ED25519Signature,SignatureError> {
        let signature = self.to_usable_type().try_sign(msg.as_ref())?;


        return Ok(ED25519Signature(signature.to_bytes()))
    }
}

impl ED25519PublicKey {
    /// as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// to byte array (32 bytes)
    pub fn to_bytes(&self) -> [u8;32] {
        self.0
    }
    /// from bytes (byte array of 32 bytes)
    pub fn from_bytes(bytes: [u8;32]) -> Self {
        Self(bytes)
    }
    pub fn from_slice(bytes: &[u8]) -> Result<Self,SlugErrors> {
        let mut x: [u8;32] = [0u8;32];

        if bytes.len() == 32 {
            x.copy_from_slice(bytes);
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
        Ok(Self::from_bytes(x))
    }
    /// to usable type
    fn to_usable_type(&self) -> Result<VerifyingKey,SignatureError> {
        VerifyingKey::from_bytes(&self.0)
    }
    /// # Verify (ED25519)
    /// 
    /// Verify a signature and message
    pub fn verify<T: AsRef<[u8]>>(&self, signature: ED25519Signature, msg: T) -> Result<bool,SignatureError> {
        let x = self.to_usable_type().unwrap().verify_strict(msg.as_ref(), &signature.to_usable_type())?;
        return Ok(true)
    }
    /// \[Encoding] Encode From UPPER-HEXADECIMAL
    pub fn to_hex_string(&self) -> String {
        String::from_utf8(hex::encode_upper(self.0)).unwrap()
    }
    /// \[Encoding] Decode From UPPER-HEXADECIMAL
    pub fn from_hex_string<T: AsRef<str>>(hex_str: T) -> Result<Vec<u8>,Error> {
        let bytes = hex::decode_upper(hex_str.as_ref().as_bytes())?;
        Ok(bytes)
    }
    /// \[Encoding] To Base32 string
    pub fn to_base32_string(&self) -> String {
        base32::encode(base32::Alphabet::Crockford, &self.0)
    }
    /// \[Encoding] From Base32 String
    pub fn from_base32_string<T: AsRef<str>>(bs32_str: T) -> Vec<u8> {
        let bytes = base32::decode(base32::Alphabet::Crockford, bs32_str.as_ref()).unwrap();
        return bytes
    }
}

impl ED25519Signature {
    /// as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// to 64-byte array
    pub fn to_bytes(&self) -> [u8;64] {
        self.0
    }
    /// from byte slice (must be 64 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self,SlugErrors> {
        let mut signature_array: [u8;64] = [0u8;64];
        
        if bytes.len() == 64 {
            signature_array.copy_from_slice(bytes);
            return Ok(Self(signature_array))
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    /// to usable type
    pub fn to_usable_type(&self) -> Signature {
        Signature::from_bytes(&self.0)
    }
    /// to base58 string
    pub fn to_base58_string(&self) -> String {
        self.0.to_base58()
    }
    /// from base58 string (must convert into bytes)
    pub fn from_base58_string<T: AsRef<str>>(base58_str: T) -> Result<Vec<u8>,FromBase58Error> {
        let bytes = base58_str.as_ref().from_base58()?;
        Ok(bytes)
    }
    /// [Encoding] Encode From UPPER-HEXADECIMAL
    pub fn to_hex_string(&self) -> String {
        String::from_utf8(hex::encode_upper(self.0)).unwrap()
    }
    /// [Encoding] Decode From UPPER-HEXADECIMAL (must convert from bytes)
    pub fn from_hex_string<T: AsRef<str>>(hex_str: T) -> Result<Vec<u8>,Error> {
        let bytes = hex::decode_upper(hex_str.as_ref().as_bytes())?;
        Ok(bytes)
    }
}


#[test]
fn run() {
    let sk = ED25519SecretKey::generate();
    println!("Secret Key: {:?}", sk);
}

#[test]
fn ed25519() {
    let sk = ED25519SecretKey::generate();
    let cert = sk.public_key().unwrap();
}