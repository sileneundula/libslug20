//! # SPHINCS+ (SHAKE256) (Smaller Signatures) (Level 5, 254 bit security)
//! 
//! SPHINCS+ is a stateless hash based digital signature algorithm that relies on the hardness of finding collisions in hash functions.  It has the following properties:
//! 
//! ## Key Size:
//! 
//! - Public Key: 64 bytes
//! 
//! - Secret Key: 128 bytes
//! 
//! - Signature: 29792 bytes
//! 
//! ## Security
//! 
//! This implementation uses pqcrypto sphincs+
//! 
//! ## TODO
//! 
//! - Remove Message Struct

use std::primitive;

use pqcrypto_sphincsplus::sphincsshake256ssimple::{PublicKey as PublicKeySphincs, SecretKey as SecretKeySphincs, DetachedSignature as DetachedSignatureSphincs};
use pqcrypto_sphincsplus::sphincsshake256ssimple::*;
use pqcrypto_traits::sign::VerificationError;
use pqcrypto_traits::{Error,Result,sign::{PublicKey,SecretKey,DetachedSignature,SignedMessage}};
use crate::errors::SlugErrors;
use crate::slugcrypt::internals::messages::Message;
use zeroize::{Zeroize,ZeroizeOnDrop};
use serde::{Serialize,Deserialize};
use serde_big_array::BigArray;

use subtle_encoding::hex;
use base58::{FromBase58, FromBase58Error, ToBase58};
use slugencode::prelude::*;

/// # SPHINCS: Public Key
/// 
/// Size of 64 bytes
#[derive(Debug,Zeroize,ZeroizeOnDrop,Serialize,Deserialize, Clone)]
pub struct SPHINCSPublicKey {
    #[serde(with = "BigArray")]
    pk: [u8;64]
}

/// # SPHINCS: Secret Key
/// 
/// Size of 128 bytes
#[derive(Debug,Zeroize,ZeroizeOnDrop,Serialize,Deserialize, Clone)]
pub struct SPHINCSSecretKey {
    #[serde(with = "BigArray")]
    sk: [u8;128]
}

/// # SPHINCS Signature
/// 
/// Size of 29_792 bytes
#[derive(Debug,Zeroize,ZeroizeOnDrop,Serialize,Deserialize,Clone)]
pub struct SPHINCSSignature {
    #[serde(with = "BigArray")]
    signature: [u8;29_792],
}

impl SPHINCSSecretKey {
    /// Generate keypair using operating system randomness
    pub fn generate() -> (SPHINCSPublicKey,SPHINCSSecretKey) {
        let keypair = keypair();

        let mut pk_array: [u8;64] = [0u8;64];
        let mut sk_array: [u8;128] = [0u8;128];

        pk_array.copy_from_slice(keypair.0.as_bytes());
        sk_array.copy_from_slice(keypair.1.as_bytes());

        return (SPHINCSPublicKey{pk: pk_array},SPHINCSSecretKey{sk: sk_array})
    }
}

impl SPHINCSPublicKey {
    /// From Bytes (64-bytes)
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<SPHINCSPublicKey,SlugErrors> {
        let mut pk_array: [u8;64] = [0u8;64];


        if bytes.len() == 64 {
            pk_array.copy_from_slice(bytes);
            return Ok(SPHINCSPublicKey {
                pk: pk_array
            })
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
        

    }
    /// as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.pk
    }
    /// to usable type
    pub fn to_usable_type(&self) -> std::result::Result<PublicKeySphincs,SlugErrors> {
        let pk = PublicKeySphincs::from_bytes(self.as_bytes());

        if pk.is_err() {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
        else {
            return Ok(pk.unwrap())
        }
    }
    /// # Verify
    /// 
    /// Verifies msg and SPHINCSSignature
    pub fn verify<T: AsRef<[u8]>>(&self, msg: T, sig: SPHINCSSignature) -> std::result::Result<bool,VerificationError> {
        let verification = verify_detached_signature(&sig.to_usable_type().unwrap(), msg.as_ref(), &self.to_usable_type().unwrap())?;

        return Ok(true)

    }
    /// To Hex String  
    pub fn to_hex_string(&self) -> std::result::Result<String, std::string::FromUtf8Error> {
        let bytes = hex::encode_upper(self.pk);
        Ok(String::from_utf8(bytes)?)
    }
    /// From Hex String
    pub fn from_hex_string<T: AsRef<str>>(hex_str: T) -> std::result::Result<Vec<u8>,subtle_encoding::Error> {
        Ok(hex::decode_upper(hex_str.as_ref().as_bytes())?)
    }
    pub fn from_hex_string_final<T: AsRef<str>>(hex_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = Self::from_hex_string(hex_str.as_ref());

        if x.is_err() {
            return Err(SlugErrors::Other(String::from("From Hexadecimal Error")))
        }
        else {
            return Ok(Self::from_bytes(&x.unwrap())?)
        }
    }
    /// To Base58 String
    pub fn to_base58_string(&self) -> String {
        self.pk.to_base58()
    }
    /// From Base58 String
    pub fn from_base58_string<T: AsRef<str>>(bs58_str: T) -> std::result::Result<Vec<u8>, FromBase58Error> {
        let bytes = bs58_str.as_ref().from_base58()?;
        Ok(bytes)
    }
    pub fn to_base32(&self) -> std::result::Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.encode(&self.as_bytes())?;
        return Ok(output)
    }
    pub fn to_base32_unpadded(&self) -> std::result::Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.encode(&self.as_bytes())?;
        return Ok(output)
    }
    pub fn to_base64(&self) -> std::result::Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.encode(&self.as_bytes())?;
        return Ok(output)
    }
    pub fn to_base64_url_safe(&self) -> std::result::Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.encode(&self.as_bytes())?;
        return Ok(output)
    }
    pub fn from_base32<T: AsRef<str>>(b32_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let bytes = x.decode(b32_str.as_ref());
        if bytes.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Public Key Base32 Decoding Error")))
        }

        let output = bytes.unwrap();
        let pk: SPHINCSPublicKey = SPHINCSPublicKey::from_bytes(&output)?;

        return Ok(pk)
    }
    pub fn from_base32_unpadded<T: AsRef<str>>(b32_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let bytes = x.decode(b32_str.as_ref());
        if bytes.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Public Key Base32 Unpadded Decoding Error")))
        }

        let output = bytes.unwrap();
        let pk: SPHINCSPublicKey = SPHINCSPublicKey::from_bytes(&output)?;

        return Ok(pk)
    }
    pub fn from_base64<T: AsRef<str>>(b64_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let bytes = x.decode(b64_str.as_ref());
        if bytes.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Public Key Base64 Decoding Error")))
        }

        let output = bytes.unwrap();
        let pk: SPHINCSPublicKey = SPHINCSPublicKey::from_bytes(&output)?;

        return Ok(pk)
    }
    pub fn from_base64_url_safe<T: AsRef<str>>(b64_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let bytes = x.decode(b64_str.as_ref());
        if bytes.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Public Key Base64 URL Safe Decoding Error")))
        }

        let output = bytes.unwrap();
        let pk: SPHINCSPublicKey = SPHINCSPublicKey::from_bytes(&output)?;

        return Ok(pk)
    }
    pub fn from_base58<T: AsRef<str>>(bs58_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let bytes = x.decode(bs58_str.as_ref());
        if bytes.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Public Key Base58 Decoding Error")))
        }

        let output = bytes.unwrap();
        let pk: SPHINCSPublicKey = SPHINCSPublicKey::from_bytes(&output)?;

        return Ok(pk)
    }
    pub fn to_base58(&self) -> std::result::Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.encode(&self.as_bytes())?;
        return Ok(output)
    }
    pub fn to_hex(&self) -> std::result::Result<String, SlugEncodingError> {
        let x: SlugEncodingUsage = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output: String = x.encode(&self.as_bytes())?;
        return Ok(output)
    }
    pub fn from_hex<T: AsRef<str>>(hex_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let bytes = x.decode(hex_str.as_ref());
        if bytes.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Public Key Hex Decoding Error")))
        }

        let output = bytes.unwrap();
        let pk: SPHINCSPublicKey = SPHINCSPublicKey::from_bytes(&output)?;

        return Ok(pk)
    }
}

impl SPHINCSSecretKey {
    /// From Bytes (128-bytes)
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<SPHINCSSecretKey, SlugErrors> {
        let mut sk_array: [u8;128] = [0u8;128];

        if bytes.len() == 128 {
            sk_array.copy_from_slice(bytes);
            
            return Ok(SPHINCSSecretKey {
                sk: sk_array
            })
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    /// as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.sk
    }
    pub fn to_hex(&self) -> std::result::Result<String, SlugEncodingError> {
        let x: SlugEncodingUsage = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output: String = x.encode(&self.as_bytes())?;
        return Ok(output)
    }
    pub fn from_hex<T: AsRef<str>>(hex_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let bytes = x.decode(hex_str.as_ref());
        if bytes.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Secret Key Hex Decoding Error")))
        }

        let output = bytes.unwrap();
        let sk: SPHINCSSecretKey = SPHINCSSecretKey::from_bytes(&output)?;

        return Ok(sk)
    }
    pub fn to_base32(&self) -> std::result::Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.encode(&self.as_bytes())?;
        return Ok(output)
    }
    pub fn to_base32_unpadded(&self) -> std::result::Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.encode(&self.as_bytes())?;
        return Ok(output)
    }
    pub fn from_base32<T: AsRef<str>>(b32_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let bytes = x.decode(b32_str.as_ref());
        if bytes.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Secret Key Base32 Decoding Error")))
        }

        let output = bytes.unwrap();
        let sk: SPHINCSSecretKey = SPHINCSSecretKey::from_bytes(&output)?;

        return Ok(sk)
    }
    pub fn from_base32_unpadded<T: AsRef<str>>(b32_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let bytes = x.decode(b32_str.as_ref());
        if bytes.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Secret Key Base32 Unpadded Decoding Error")))
        }

        let output = bytes.unwrap();
        let sk: SPHINCSSecretKey = SPHINCSSecretKey::from_bytes(&output)?;

        return Ok(sk)
    }
    pub fn to_base58(&self) -> std::result::Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.encode(&self.as_bytes())?;
        return Ok(output)
    }
    pub fn to_base64(&self) -> std::result::Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.encode(&self.as_bytes())?;
        return Ok(output)
    }
    pub fn to_base64_url_safe(&self) -> std::result::Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.encode(&self.as_bytes())?;
        return Ok(output)
    }
    pub fn from_base58<T: AsRef<str>>(bs58_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let bytes = x.decode(bs58_str.as_ref());
        if bytes.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Secret Key Base58 Decoding Error")))
        }

        let output = bytes.unwrap();
        let sk: SPHINCSSecretKey = SPHINCSSecretKey::from_bytes(&output)?;

        return Ok(sk)
    }
    pub fn from_base64<T: AsRef<str>>(b64_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let bytes = x.decode(b64_str.as_ref());
        if bytes.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Secret Key Base64 Decoding Error")))
        }

        let output = bytes.unwrap();
        let sk: SPHINCSSecretKey = SPHINCSSecretKey::from_bytes(&output)?;

        return Ok(sk)
    }
    pub fn from_base64_url_safe<T: AsRef<str>>(b64_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let bytes = x.decode(b64_str.as_ref());
        if bytes.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Secret Key Base64 URL Safe Decoding Error")))
        }

        let output = bytes.unwrap();
        let sk: SPHINCSSecretKey = SPHINCSSecretKey::from_bytes(&output)?;

        return Ok(sk)
    }
    /// # Sign
    /// 
    /// Signs a message
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) -> std::result::Result<SPHINCSSignature,SlugErrors> {
        let bytes = detached_sign(msg.as_ref(), &self.to_usable_type().unwrap());

        let signature = SPHINCSSignature::from_bytes(bytes.as_bytes())?;

        return Ok(signature)
    }
    fn to_usable_type(&self) -> std::result::Result<SecretKeySphincs,SlugErrors> {
        let sk = SecretKeySphincs::from_bytes(self.as_bytes());

        if sk.is_err() {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
        else {
            return Ok(sk.unwrap())
        }
    }
    /// To Hex String (Upper)
    pub fn to_hex_string(&self) -> std::result::Result<String, std::string::FromUtf8Error> {
        let bytes = hex::encode_upper(self.sk);
        Ok(String::from_utf8(bytes)?)
    }
    /// From Hex String (Upper)
    pub fn from_hex_string<T: AsRef<str>>(hex_str: T) -> std::result::Result<Vec<u8>,subtle_encoding::Error> {
        Ok(hex::decode_upper(hex_str.as_ref().as_bytes())?)
    }
}

impl SPHINCSSignature {
    /// To Bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.signature.to_vec()
    }
    /// As Bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.as_bytes()
    }
    pub fn to_hex(&self) -> std::result::Result<String, SlugEncodingError> {
        let x: SlugEncodingUsage = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output: String = x.encode(&self.as_bytes())?;
        return Ok(output)
    }
    pub fn from_hex<T: AsRef<str>>(hex_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let bytes = x.decode(hex_str.as_ref());
        if bytes.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Signature Hex Decoding Error")))
        }

        let output = bytes.unwrap();
        let sk: SPHINCSSignature = SPHINCSSignature::from_bytes(&output)?;

        return Ok(sk)
    }
    pub fn to_base32(&self) -> std::result::Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.encode(&self.as_bytes())?;
        return Ok(output)
    }
    pub fn to_base32_unpadded(&self) -> std::result::Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.encode(&self.as_bytes())?;
        return Ok(output)
    }
    pub fn to_base58(&self) -> std::result::Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.encode(&self.as_bytes())?;
        return Ok(output)
    }
    pub fn to_base64(&self) -> std::result::Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.encode(&self.as_bytes())?;
        return Ok(output)
    }
    pub fn to_base64_url_safe(&self) -> std::result::Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.encode(&self.as_bytes())?;
        return Ok(output)
    }
    pub fn from_base32<T: AsRef<str>>(b32_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let bytes = x.decode(b32_str.as_ref());
        if bytes.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Signature Base32 Decoding Error")))
        }

        let output = bytes.unwrap();
        let sk: SPHINCSSignature = SPHINCSSignature::from_bytes(&output)?;

        return Ok(sk)
    }
    pub fn from_base32_unpadded<T: AsRef<str>>(b32_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let bytes = x.decode(b32_str.as_ref());
        if bytes.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Signature Base32 Unpadded Decoding Error")))
        }

        let output = bytes.unwrap();
        let sk: SPHINCSSignature = SPHINCSSignature::from_bytes(&output)?;

        return Ok(sk)
    }
    pub fn from_base58<T: AsRef<str>>(bs58_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let bytes = x.decode(bs58_str.as_ref());
        if bytes.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Signature Base58 Decoding Error")))
        }

        let output = bytes.unwrap();
        let sk: SPHINCSSignature = SPHINCSSignature::from_bytes(&output)?;

        return Ok(sk)
    }
    pub fn from_base64<T: AsRef<str>>(b64_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let bytes = x.decode(b64_str.as_ref());
        if bytes.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Signature Base64 Decoding Error")))
        }

        let output = bytes.unwrap();
        let sk: SPHINCSSignature = SPHINCSSignature::from_bytes(&output)?;

        return Ok(sk)
    }
    pub fn from_base64_url_safe<T: AsRef<str>>(b64_str: T) -> std::result::Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let bytes = x.decode(b64_str.as_ref());
        if bytes.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Signature Base64 URL Safe Decoding Error")))
        }

        let output = bytes.unwrap();
        let sk: SPHINCSSignature = SPHINCSSignature::from_bytes(&output)?;

        return Ok(sk)
    }
    /// From Bytes (29972 bytes)
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<SPHINCSSignature,SlugErrors> {
        let mut signature_array: [u8;29_792] = [0u8;29_792];

        if bytes.len() == 29_792 {
            signature_array.copy_from_slice(bytes);

            return Ok(SPHINCSSignature { signature: signature_array })
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    /// to usable type
    fn to_usable_type(&self) -> std::result::Result<DetachedSignatureSphincs,Error> {
        let signature = DetachedSignatureSphincs::from_bytes(&self.to_bytes())?;

        return Ok(signature)
    }
    /// to hex string (upper)
    pub fn to_hex_string(&self) -> std::result::Result<String, std::string::FromUtf8Error> {
        let bytes = hex::encode_upper(self.signature);
        Ok(String::from_utf8(bytes)?)
    }
    /// from hex string (upper)
    pub fn from_hex_string<T: AsRef<str>>(hex_str: T) -> std::result::Result<Vec<u8>,subtle_encoding::Error> {
        Ok(hex::decode_upper(hex_str.as_ref().as_bytes())?)
    }
    pub fn from_hex_string_final<T: AsRef<str>>(hex_str: T) -> std::result::Result<Self, SlugErrors> {
        let x = Self::from_hex_string(hex_str.as_ref());

        if x.is_err() {
            return Err(SlugErrors::Other(String::from("SPHINCS+ Signature Error")))
        }
        else {
            return Ok(Self::from_bytes(&x.unwrap())?)
        }
    }
    /// to base58 string
    pub fn to_base58_string(&self) -> String {
        self.signature.to_base58()
    }
    /// from base58 string
    pub fn from_base58_string<T: AsRef<str>>(bs58_str: T) -> std::result::Result<Vec<u8>, FromBase58Error> {
        let bytes = bs58_str.as_ref().from_base58()?;
        Ok(bytes)
    }
}

#[test]
fn keypair_ls() {
    let keypair = SPHINCSSecretKey::generate();

    let message: Message = Message::new("This is a signed message");

    println!("Public Key Length: {}",keypair.0.as_bytes().len());
    println!("Secret Key Length: {}",keypair.1.as_bytes().len());

    let signature = keypair.1.sign("Hello World. This is using SPHINCS+.").unwrap();

    let length: usize = signature.to_bytes().len();

    println!("SPHINCS+ Signature Length: {}", length);
}