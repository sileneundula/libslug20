//! # FALCON1024
//! 
//! ## Description
//! 
//! FALCON1024 is a post-quantum algorithm for digital signatures.
//! 
//! This implementation includes zeroize, serialization, and more.
//! 
//! ### Key-Size:
//! 
//! **Public-Key Size (in bytes):** 1793
//! **Secret-Key Size (in bytes):** 2305
//! **Signature Size (in bytes):** 1280
//! 
//! ## Features
//! - Generation
//! - Signing
//! - Verification
//! 
//! ## Warning
//! 
//! The Public Key and Secret Key must be kept together. The Public Key *cannot* be derived from the secret key in this implementation.

use pqcrypto_falcon::falconpadded1024;

use pqcrypto_traits::sign::{PublicKey,SecretKey,DetachedSignature};

use subtle_encoding::hex::Hex;
use subtle_encoding::Encoding;

use serde::{Serialize,Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};
use serde_big_array::BigArray;

use slugencode::{SlugEncodingUsage,SlugEncodings,errors::SlugEncodingError};

use crate::slugcrypt::traits::{FromEncoding, IntoEncoding};
use crate::errors::SlugErrors;
/// # Falcon1024: Public Key
/// 
/// ## Description
/// 
/// Falcon1024 is a post-quantum signature scheme based on the Falcon algorithm. The public key is 1793-bytes in size.
/// 
/// It implements Zeroize and Serialization.
/// 
/// ## Sizes
/// 
/// Public Key Size: 1793 bytes
/// Secret Key Size: 2305 bytes
/// Signature Size: 1280 bytes
/// 
/// ## Features
/// 
/// - Verification
#[derive(Debug,Zeroize,ZeroizeOnDrop,Serialize,Deserialize,Clone,PartialEq,PartialOrd,Hash)]
pub struct Falcon1024PublicKey {
    #[serde(with = "BigArray")]
    pk: [u8; 1_793],
}

/// # Falcon1024: Secret Key
/// 
/// ## Description
/// 
/// Falcon1024 is a post-quantum signature scheme based on the Falcon algorithm. The secret key is 2305-bytes in size.
/// 
/// It implements Zeroize and Serialization.
/// 
/// ## Sizes
/// 
/// Public Key Size: 1793 bytes
/// Secret Key Size: 2305 bytes
/// Signature Size: 1280 bytes
/// 
/// ## Features
/// 
/// - Signing
#[derive(Debug,Zeroize,ZeroizeOnDrop,Serialize,Deserialize,Clone,PartialEq,PartialOrd,Hash)]
pub struct Falcon1024SecretKey {
    #[serde(with = "BigArray")]
    sk: [u8; 2_305],
}

/// # Falcon1024: Signature
/// 
/// ## Description
/// 
/// Falcon1024 is a post-quantum signature scheme based on the Falcon algorithm. The signature key is 1280-bytes in size.
/// 
/// It implements Zeroize and Serialization.
/// 
/// ## Sizes
/// 
/// Public Key Size: 1793 bytes
/// Secret Key Size: 2305 bytes
/// Signature Size: 1280 bytes
/// 
/// ## Features
/// 
/// - Verification
#[derive(Debug,Zeroize,ZeroizeOnDrop,Serialize,Deserialize,Clone,PartialEq,PartialOrd,Hash)]
pub struct Falcon1024Signature {
    #[serde(with = "BigArray")]
    signature: [u8; 1_280],
}

/// Protocol Info for `FALCON1024`
pub mod protocol_info {
    pub const FALCON1024_PROTOCOL_NAME: &str = "libslug/FALCON1024";
    pub const FALCON1024_PK_SIZE: usize = 1_793;
    pub const FALCON1024_SK_SIZE: usize = 2_305;
    pub const FALCON1024_SIG_SIZE: usize = 1_280;
    pub const FALCON1024_CAN_DERIVE_PUBLIC_KEY_FROM_SECRET_KEY: bool = false;
    pub const FALCON1024_SOURCE_LIBRARY: &str = "pqcrypto";
    pub const FALCON1024_RANDOMNESS: &str = "OSCSPRNG";
}

/// # SlugFalcon1024
/// 
/// This is used to generate the keypairs. Both keypairs are required.
pub struct SlugFalcon1024;

impl SlugFalcon1024 {
    /// Generation using OSCSPRNG of Falcon1024 keypairs
    pub fn generate() -> (Falcon1024PublicKey, Falcon1024SecretKey) {
        let keypair = falconpadded1024::keypair();
        let pk = keypair.0.as_bytes();
        let sk = keypair.1.as_bytes();

        let mut pk_output = [0u8; 1793];
        let mut sk_output = [0u8; 2305];
        pk_output.copy_from_slice(pk);
        sk_output.copy_from_slice(sk);

        let public_key = Falcon1024PublicKey { pk: pk_output };
        let secret_key = Falcon1024SecretKey { sk: sk_output };
        return (public_key, secret_key)
    }
}

impl Falcon1024PublicKey {
    /// From Bytes (1793 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut pk_array = [0u8; 1793];
        if bytes.len() == 1793 {
            pk_array.copy_from_slice(bytes);
            Ok(Self { pk: pk_array })
        } else {
            Err("Invalid length for Falcon1024 public key".to_string())
        }
    }
    /// as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.pk
    }
    /// To Hex Upper
    pub fn to_hex_upper(&self) -> Result<String, subtle_encoding::Error> {
        let hex = Hex::upper_case();
        return hex.encode_to_string(&self.pk)
    }
    /// To Hex Lower
    pub fn to_hex_lower(&self) -> Result<String, subtle_encoding::Error> {
        let hex = Hex::lower_case();
        return hex.encode_to_string(&self.pk)
    }
    /// From Hex Lower
    pub fn from_hex_lower(&self, s_hex: &str) -> Result<Self, String> {
        let hex = Hex::lower_case();
        let decoded = hex.decode_from_str(s_hex);
        return Self::from_bytes(&decoded.unwrap());
    }
    /// From Hex Upper
    pub fn from_hex_upper(&self, s_hex: &str) -> Result<Self, String> {
        let hex = Hex::upper_case();
        let decoded = hex.decode_from_str(s_hex);
        return Self::from_bytes(&decoded.unwrap());
    }
    /// To Usable Type
    pub fn to_usable_type(&self) -> falconpadded1024::PublicKey {
        falconpadded1024::PublicKey::from_bytes(&self.pk).unwrap()
    }
    /// # Verify
    /// 
    /// Verifies a message against the Falcon1024 signature.
    /// 
    /// Accepts as input message (as ref \[u8]) and the signature.
    pub fn verify<T: AsRef<[u8]>>(&self, message: T, signature: &Falcon1024Signature) -> Result<bool, String> {
        let pkh = self.to_usable_type();
        let sigh = falconpadded1024::DetachedSignature::from_bytes(&signature.as_bytes()).unwrap();
        let result = falconpadded1024::verify_detached_signature(&sigh, message.as_ref(), &pkh);

        return match result {
            Ok(()) => Ok(true),
            Err(e) => Err(format!("Verification failed: {}", e)),
        }
    }
    pub fn from_hex<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base32<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base58<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base64<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn to_hex(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base32(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base32_unpadded(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base58(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base64(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base64_url_safe(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
}

impl Falcon1024SecretKey {
    /// From Bytes (2305 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut sk_array = [0u8; 2305];
        if bytes.len() == 2305 {
            sk_array.copy_from_slice(bytes);
            Ok(Self { sk: sk_array })
        } else {
            Err("Invalid length for Falcon1024 secret key".to_string())
        }
    }
    /// As Bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.sk
    }
    /// To Usable Type
    pub fn to_usable_type(&self) -> falconpadded1024::SecretKey {
        falconpadded1024::SecretKey::from_bytes(&self.sk).unwrap()
    }
    /// # Falcon1024 Sign
    /// 
    /// Signs a message using Falcon1024 secret key and returns signature. Detatched Signature.
    pub fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<Falcon1024Signature, String> {
        let skh = self.to_usable_type();
        let signature = falconpadded1024::detached_sign(message.as_ref(), &skh);
        let mut sig_array = [0u8; 1280]; 
        sig_array.copy_from_slice(signature.as_bytes());
        Ok(Falcon1024Signature { signature: sig_array })
    }
    /// To Hex Upper
    pub fn to_hex_upper(&self) -> Result<String, subtle_encoding::Error> {
        let hex = Hex::upper_case();
        return hex.encode_to_string(&self.sk)
    }
    /// To Hex Lower
    pub fn to_hex_lower(&self) -> Result<String, subtle_encoding::Error> {
        let hex = Hex::lower_case();
        return hex.encode_to_string(&self.sk)
    }
    /// From Hex Lower
    pub fn from_hex_lower(&self, s_hex: &str) -> Result<Self, String> {
        let hex = Hex::lower_case();
        let decoded = hex.decode_from_str(s_hex);
        return Self::from_bytes(&decoded.unwrap());
    }
    /// From Hex Upper
    pub fn from_hex_upper(&self, s_hex: &str) -> Result<Self, String> {
        let hex = Hex::upper_case();
        let decoded = hex.decode_from_str(s_hex);
        return Self::from_bytes(&decoded.unwrap());
    }
    pub fn from_hex<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base32<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base58<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base64<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn to_hex(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base32(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base32_unpadded(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base58(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base64(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base64_url_safe(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
}

impl Falcon1024Signature {
    /// From Bytes (1280 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut sig_array = [0u8; 1280];
        if bytes.len() == 1280 {
            sig_array.copy_from_slice(bytes);
            Ok(Self { signature: sig_array })
        } else {
            Err("Invalid length for Falcon1024 signature".to_string())
        }
    }
    /// as bytes (1280 bytes)
    pub fn as_bytes(&self) -> &[u8] {
        &self.signature
    }
    /// to usable type
    pub fn to_usable_type(&self) -> falconpadded1024::DetachedSignature {
        falconpadded1024::DetachedSignature::from_bytes(&self.signature).unwrap()
    }
    /// To Hex Upper (Constant-Time)
    pub fn to_hex_upper(&self) -> Result<String, subtle_encoding::Error> {
        let hex = Hex::upper_case();
        return hex.encode_to_string(&self.signature)
    }
    /// To Hex Lower (Constant-Time)
    pub fn to_hex_lower(&self) -> Result<String, subtle_encoding::Error> {
        let hex = Hex::lower_case();
        return hex.encode_to_string(&self.signature)
    }
    /// From Hex Lower (Constant-Time)
    pub fn from_hex_lower(&self, s_hex: &str) -> Result<Self, String> {
        let hex = Hex::lower_case();
        let decoded = hex.decode_from_str(s_hex);
        return Self::from_bytes(&decoded.unwrap());
    }
    /// From Hex Upper (Constant Time)
    pub fn from_hex_upper(&self, s_hex: &str) -> Result<Self, String> {
        let hex = Hex::upper_case();
        let decoded = hex.decode_from_str(s_hex);
        return Self::from_bytes(&decoded.unwrap());
    }
    pub fn from_hex<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base32<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base58<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base64<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugEncodingError::DecodingError)
        }
    }
    pub fn to_hex(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base32(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base32_unpadded(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base58(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base64(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    pub fn to_base64_url_safe(&self) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
}


impl IntoEncoding for Falcon1024PublicKey {
    fn to_hex(&self) -> Result<String, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    fn to_base32(&self) -> Result<String, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    fn to_base32_unpadded(&self) -> Result<String, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    fn to_base58(&self) -> Result<String, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    fn to_base64(&self) -> Result<String, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    fn to_base64_url_safe(&self) -> Result<String, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
}
impl IntoEncoding for Falcon1024SecretKey {
    fn to_hex(&self) -> Result<String, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    fn to_base32(&self) -> Result<String, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    fn to_base32_unpadded(&self) -> Result<String, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    fn to_base58(&self) -> Result<String, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    fn to_base64(&self) -> Result<String, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    fn to_base64_url_safe(&self) -> Result<String, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
}
impl IntoEncoding for Falcon1024Signature {
    fn to_hex(&self) -> Result<String, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    fn to_base32(&self) -> Result<String, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    fn to_base32_unpadded(&self) -> Result<String, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    fn to_base58(&self) -> Result<String, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    fn to_base64(&self) -> Result<String, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
    fn to_base64_url_safe(&self) -> Result<String, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.encode(self.as_bytes())?;
        Ok(output)
    }
}

impl FromEncoding for Falcon1024PublicKey {
    fn from_hex<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let x: SlugEncodingUsage = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::DecodingError { alg: crate::errors::SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::Hexadecimal, other: None })
        }
    }
    fn from_base32<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let x: SlugEncodingUsage = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::DecodingError { alg: crate::errors::SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::Base32, other: None })
        }
    }
    fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::DecodingError { alg: crate::errors::SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::Base32unpadded, other: None })
        }
    }
    fn from_base58<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::DecodingError { alg: crate::errors::SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::Base58, other: None })
        }
    }
    fn from_base64<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::DecodingError { alg: crate::errors::SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::Base64, other: None })
        }
    }
    fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::DecodingError { alg: crate::errors::SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::Base64urlsafe, other: None })
        }
    }
}
impl FromEncoding for Falcon1024SecretKey {
    fn from_hex<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let x: SlugEncodingUsage = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::DecodingError { alg: crate::errors::SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::Hexadecimal, other: None })
        }
    }
    fn from_base32<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let x: SlugEncodingUsage = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::DecodingError { alg: crate::errors::SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::Base32, other: None })
        }
    }
    fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::DecodingError { alg: crate::errors::SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::Base32unpadded, other: None })
        }
    }
    fn from_base58<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::DecodingError { alg: crate::errors::SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::Base58, other: None })
        }
    }
    fn from_base64<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::DecodingError { alg: crate::errors::SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::Base64, other: None })
        }
    }
    fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::DecodingError { alg: crate::errors::SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::Base64urlsafe, other: None })
        }
    }
}
impl FromEncoding for Falcon1024Signature {
    fn from_hex<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let x: SlugEncodingUsage = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::DecodingError { alg: crate::errors::SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::Hexadecimal, other: None })
        }
    }
    fn from_base32<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let x: SlugEncodingUsage = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::DecodingError { alg: crate::errors::SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::Base32, other: None })
        }
    }
    fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::DecodingError { alg: crate::errors::SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::Base32unpadded, other: None })
        }
    }
    fn from_base58<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::DecodingError { alg: crate::errors::SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::Base58, other: None })
        }
    }
    fn from_base64<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::DecodingError { alg: crate::errors::SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::Base64, other: None })
        }
    }
    fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.decode(s.as_ref())?;
        let final_output = Self::from_bytes(&output);

        match final_output {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SlugErrors::DecodingError { alg: crate::errors::SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::Base64urlsafe, other: None })
        }
    }
}

#[test]
fn test_falcon_generate() {
    let (pk,sk) = SlugFalcon1024::generate();
    let sig = sk.sign(b"Message").unwrap();
    let is_valid = pk.verify(b"Message", &sig).unwrap();
    assert_eq!(is_valid, true);
}