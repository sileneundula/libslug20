//! # \[libslug/signatures/ecdsa:k256] Secp256k1 ECDSA Signatures
//! 
//! ## Description
//! 
//! ECDSA signatures using Secp256k1
//! 
//! ## Features
//! 
//! - [X] Generation
//!     - [X] OSCSPRNG
//! - [X] Signing
//!     - [X] Sign
//!     - [X] Sign (prehashed)
//! - [X] Verifying
//!     - [X] Verify
//! - [X] Encodings
//!     - [X] Hex
//!     - [X] Base32
//!     - [X] Base58
//!     - [X] Base64
//! - [X] Serialization
//! - [X] Zeroize
//! - [X] Other
//!     - [X] Derive Public Key From Secret

//use ecdsa::signature::Keypair;
use ecdsa::PrimeCurve;
use ecdsa::signature::Signer;
use ecdsa::signature::RandomizedSigner;
use ecdsa::signature::Keypair;
use k256::ecdsa::{SigningKey, Signature, VerifyingKey};
use k256::Secp256k1;
use k256::ecdsa::signature::Verifier;
use rand::rngs::OsRng;

use serde::{Serialize,Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};
use serde_big_array::BigArray;

// SLUG ENCODE :TEMPNAME
use slugencode::SlugEncodingUsage;
use slugencode::SlugEncodings;
use slugencode::errors::SlugEncodingError;

use crate::slugcrypt::traits::RecoverablePublicKey;

use crate::errors::SlugErrors;

/// # ECDSA Public Key (Secp256k1)
/// 
/// `Key-Size:` 32 bytes
/// 
/// ### Encodings
/// 
/// - [X] Hexadecimal
/// - [X] Base58
/// - [X] Base32
/// - [X] Base32_unpadded
/// - [X] Base64
/// - [X] Base64_url_safe
/// 
/// ## Description
/// 
/// ECDSA Public Key as 32 bytes
#[derive(Clone,PartialEq,PartialOrd,Hash,Debug,Serialize,Deserialize,Zeroize,ZeroizeOnDrop)]
pub struct ECDSAPublicKey(pub [u8;32]);
/// # ECDSA Secret Key (Secp256k1)
/// 
/// `Key-Size:` 32 bytes
/// 
/// ### Encodings
/// 
/// - [X] Hexadecimal
/// - [X] Base58
/// - [X] Base32
/// - [X] Base32_unpadded
/// - [X] Base64
/// - [X] Base64_url_safe
/// 
/// ## Description
/// 
/// ECDSA Secret Key as 32 bytes
#[derive(Clone,PartialEq,PartialOrd,Hash,Debug,Serialize,Deserialize,Zeroize,ZeroizeOnDrop)]
pub struct ECDSASecretKey(pub [u8;32]);

/// # ECDSA Signature (Secp256k1)
/// 
/// `Key-Size:` 64 bytes
/// 
/// ### Encodings
/// 
/// - [X] Hexadecimal
/// - [X] Base58
/// - [X] Base32
/// - [X] Base32_unpadded
/// - [X] Base64
/// - [X] Base64_url_safe
/// 
/// ## Description
/// 
/// ECDSA Signature as 64 bytes
#[derive(Clone,PartialEq,PartialOrd,Hash,Debug,Serialize,Deserialize,Zeroize,ZeroizeOnDrop)]
pub struct ECDSASignature(
    #[serde(with = "BigArray")]
    pub [u8;64]
);

#[derive(Clone,PartialEq,PartialOrd,Hash,Debug,Serialize,Deserialize,Zeroize,ZeroizeOnDrop)]
pub struct ECDSASignatureRecoveryID(pub u8);


// DO NOT IMPLEMENT FOR ECDSASIGNATURE

impl RecoverablePublicKey for ECDSAPublicKey {

}

impl RecoverablePublicKey for ECDSASecretKey {

}

impl ECDSASignature {
    pub fn verify<T: AsRef<[u8]>>(&self, bytes: T, pk: ECDSAPublicKey) -> Result<bool,SlugErrors> {
        return pk.verify(bytes.as_ref(), self.clone())
    }
    pub fn as_bytes(&self) -> &[u8] {
        return self.0.as_slice()
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        return self.0.to_vec()
    }
    pub fn from_bytes(bytes: [u8;64]) -> Self {
        return Self(bytes)
    }
    pub fn from_slice(bytes: &[u8]) -> Result<Self,SlugErrors> {
        let mut output: [u8;64] = [0u8;64];
        
        if bytes.len() == 64 {
            output.copy_from_slice(bytes);
            Ok(Self(output))
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    pub fn into_usable_type(&self) -> Result<Signature,SlugErrors> {
        let x = Signature::from_slice(&self.0);

        match x {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    /// # \[slugcrypt/signatures/ecdsa-secp256k1/signature] From Base58
    /// 
    /// From Base58 format as a string
    pub fn from_base58<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.decode(s.as_ref())?;
        let output = Self::from_slice(&output);

        match output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_hex<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
                let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.decode(s.as_ref())?;
        let output = Self::from_slice(&output);

        match output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base32<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.decode(s.as_ref())?;
        let output = Self::from_slice(&output);

        match output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.decode(s.as_ref())?;
        let output = Self::from_slice(&output);

        match output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base64<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.decode(s.as_ref())?;
        let output = Self::from_slice(&output);

        match output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.decode(s.as_ref())?;
        let output = Self::from_slice(&output);

        match output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn to_hex(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.encode(&self.0);
        
        match output {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugEncodingError::EncodingError)
        }
    }
    pub fn to_base32(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.encode(&self.0);
        
        match output {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugEncodingError::EncodingError)
        }
    }
    pub fn to_base32_unpadded(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.encode(&self.0);
        
        match output {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugEncodingError::EncodingError)
        }
    }
    pub fn to_base58(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.encode(&self.0);
        
        match output {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugEncodingError::EncodingError)
        }
    }
    pub fn to_base64(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.encode(&self.0);
        
        match output {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugEncodingError::EncodingError)
        }
    }
    pub fn to_base64_url_safe(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.encode(&self.0);
        
        match output {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugEncodingError::EncodingError)
        }
    }
}

impl ECDSASecretKey {
    /// # Generate k256
    /// 
    /// ## Description
    /// 
    /// Generates an ECDSA signing key for secp256k1 with 32 bytes of operating system randomness.
    pub fn generate() -> Self {
        let mut bytes: [u8;32] = [0u8;32];

        let mut os_rng = OsRng;
        let key = k256::ecdsa::SigningKey::random(&mut os_rng);
        let output_bytes = key.to_bytes().as_slice().to_vec();

        bytes.copy_from_slice(&output_bytes);

        ECDSASecretKey(bytes)
    }
    /// # Sign (Recoverable)
    /// 
    /// Sign using ECDSA.
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Result<(ECDSASignature, ECDSASignatureRecoveryID), SlugErrors> {
        let signature = self.to_usable_type();
        
        let signingkey = match signature {
            Ok(v) => v,
            Err(_) => return Err(SlugErrors::SigningFailure(crate::errors::SlugErrorAlgorithms::SIG_SECP256k1)),
        };

        let x: Result<(ecdsa::Signature<Secp256k1>, ecdsa::RecoveryId), ecdsa::Error> = signingkey.sign_recoverable(msg.as_ref());

        let output = match x {
            Ok(v) => v,
            Err(_) => return Err(SlugErrors::SigningFailure(crate::errors::SlugErrorAlgorithms::SIG_SECP256k1))
        };

        let output_bytes = output.0.to_bytes();

        let recovery_id = output.1.to_byte();

        let sig = ECDSASignature::from_slice(output_bytes.as_slice());

        match sig {
            Ok(v) => return Ok((v, ECDSASignatureRecoveryID(recovery_id))),
            Err(_) => return Err(SlugErrors::SigningFailure(crate::errors::SlugErrorAlgorithms::SIG_SECP256k1)),
        }
    }
    pub fn sign_prehash<T: AsRef<[u8]>>(&self, msg: T) -> Result<(ECDSASignature, ECDSASignatureRecoveryID), SlugErrors> {
        let pk = self.to_usable_type();

        let x: ecdsa::SigningKey<Secp256k1> = match pk {
            Ok(v) => v,
            Err(_) => return Err(SlugErrors::SigningFailure(crate::errors::SlugErrorAlgorithms::SIG_SECP256k1))
        };

        let signature = x.sign_prehash_recoverable(msg.as_ref());
        
        let output = match signature {
            Ok(v) => v,
            Err(_) => return Err(SlugErrors::SigningFailure(crate::errors::SlugErrorAlgorithms::SIG_SECP256k1))
        };

        let signature_output = ECDSASignature::from_slice(&output.0.to_bytes())?;
        let recovery_id = ECDSASignatureRecoveryID(output.1.to_byte());

        return Ok((signature_output,recovery_id))
    }
    /// # To SigningKey
    /// 
    /// Converts To Signing Key
    pub fn to_usable_type(&self) -> Result<SigningKey,ecdsa::Error> {
        let key: ecdsa::SigningKey<Secp256k1> = SigningKey::from_slice(&self.0)?;
        return Ok(key)
    }
    /// # To VerifyingKey
    /// 
    /// Converts To Verifying Key From Secret Key
    pub fn to_usable_type_pk(&self) -> Result<VerifyingKey,ecdsa::Error> {
        let x = self.to_usable_type();

        let key = match x {
            Ok(v) => v,
            Err(_) => return Err(ecdsa::Error::default()),
        };

        return Ok(key.verifying_key().to_owned())
    }
    /// # Public Key
    /// 
    /// Gets Public Key From Secret Key
    pub fn public_key(&self) -> Result<ECDSAPublicKey,ecdsa::Error> {
        let mut output_bytes: [u8;32] = [0u8;32];
        let bytes = self.to_usable_type_pk();

        let pk = match bytes {
            Ok(v) => v,
            Err(_) => return Err(ecdsa::Error::default())
        };
        let bytes = pk.to_sec1_bytes();
        let final_bytes = bytes.to_vec();

        if final_bytes.len() == 32 {
            output_bytes.copy_from_slice(&final_bytes);
        }
        Ok(ECDSAPublicKey(output_bytes))
    }
    pub fn from_slice(bytes: &[u8]) -> Result<Self,SlugErrors> {
        let mut output: [u8;32] = [0u8;32];
        
        if bytes.len() == 32 {
            output.copy_from_slice(bytes);
            Ok(Self(output))
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    pub fn from_base58<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.decode(s.as_ref())?;
        let output = Self::from_slice(&output);

        match output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_hex<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
                let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.decode(s.as_ref())?;
        let output = Self::from_slice(&output);

        match output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base32<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.decode(s.as_ref())?;
        let output = Self::from_slice(&output);

        match output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.decode(s.as_ref())?;
        let output = Self::from_slice(&output);

        match output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base64<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.decode(s.as_ref())?;
        let output = Self::from_slice(&output);

        match output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.decode(s.as_ref())?;
        let output = Self::from_slice(&output);

        match output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn to_hex(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.encode(&self.0);
        
        match output {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugEncodingError::EncodingError)
        }
    }
    pub fn to_base32(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.encode(&self.0);
        
        match output {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugEncodingError::EncodingError)
        }
    }
    pub fn to_base32_unpadded(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.encode(&self.0);
        
        match output {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugEncodingError::EncodingError)
        }
    }
    pub fn to_base58(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.encode(&self.0);
        
        match output {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugEncodingError::EncodingError)
        }
    }
    pub fn to_base64(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.encode(&self.0);
        
        match output {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugEncodingError::EncodingError)
        }
    }
    pub fn to_base64_url_safe(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.encode(&self.0);
        
        match output {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugEncodingError::EncodingError)
        }
    }
}

impl ECDSAPublicKey {
    pub fn verify<T: AsRef<[u8]>>(&self, bytes: T, signature: ECDSASignature) -> Result<bool,SlugErrors> {
        let x: Result<ecdsa::VerifyingKey<Secp256k1>, ecdsa::Error> = self.to_usable_type();

        let pk: ecdsa::VerifyingKey<Secp256k1> = match x {
            Ok(v) => v,
            Err(_) => return Err(SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_SCHNORR))
        };

        let sig: Result<ecdsa::Signature<Secp256k1>, SlugErrors> = signature.into_usable_type();

        let signature_output = match sig {
            Ok(v) => v,
            Err(_) => return Err(SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::ENC_ECIES_ED25519))
        };
        
        let is_valid = pk.verify(bytes.as_ref(), &signature_output);

        if is_valid.is_ok() {
            return Ok(true)
        }
        else {
            return Ok(false)
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        return &self.0
    }
    pub fn to_bytes(&self) -> [u8;32] {
        return self.0
    }
    pub fn from_bytes(bytes: [u8;32]) -> Self {
        Self(bytes)
    }
    pub fn from_slice(bytes: &[u8]) -> Result<Self,SlugErrors> {
        let mut output: [u8;32] = [0u8;32];
        
        if bytes.len() == 32 {
            output.copy_from_slice(bytes);
            return Ok(Self(output))
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
    pub fn to_usable_type(&self) -> Result<VerifyingKey,ecdsa::Error> {
        let key: ecdsa::VerifyingKey<Secp256k1> = VerifyingKey::from_sec1_bytes(&self.0)?;
        return Ok(key)
    }
    pub fn from_base58<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.decode(s.as_ref())?;
        let output = Self::from_slice(&output);

        match output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_hex<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
                let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.decode(s.as_ref())?;
        let output = Self::from_slice(&output);

        match output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base32<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.decode(s.as_ref())?;
        let output = Self::from_slice(&output);

        match output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.decode(s.as_ref())?;
        let output = Self::from_slice(&output);

        match output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base64<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.decode(s.as_ref())?;
        let output = Self::from_slice(&output);

        match output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.decode(s.as_ref())?;
        let output = Self::from_slice(&output);

        match output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn to_hex(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.encode(&self.0);
        
        match output {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugEncodingError::EncodingError)
        }
    }
    pub fn to_base32(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.encode(&self.0);
        
        match output {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugEncodingError::EncodingError)
        }
    }
    pub fn to_base32_unpadded(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.encode(&self.0);
        
        match output {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugEncodingError::EncodingError)
        }
    }
    pub fn to_base58(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.encode(&self.0);
        
        match output {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugEncodingError::EncodingError)
        }
    }
    pub fn to_base64(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.encode(&self.0);
        
        match output {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugEncodingError::EncodingError)
        }
    }
    pub fn to_base64_url_safe(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.encode(&self.0);
        
        match output {
            Ok(v) => Ok(v),
            Err(_) => return Err(SlugEncodingError::EncodingError)
        }
    }
}



#[test]
fn ECDSA() {
    let key = ECDSASecretKey::generate();
    let pk = key.public_key().unwrap();
    let signature = key.sign("Hello World!").unwrap();

    let is_valid = pk.verify("Hello World!", signature.0);

    println!("{}",is_valid.unwrap())

}