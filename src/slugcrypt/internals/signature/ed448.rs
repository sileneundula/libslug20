//! # Ed448
//! 
//! Secret Key Size: 57 Bytes
//! 
//! ## TODO:
//! 
//! - [ ] Encoding
//!     - [X] IntoEncoding
//!     - [ ] IntoX59
//!     - [ ] IntoPem
//!     - [ ] FromPem
//!     - [ ] FromX59
//!     - [X] FromEncoding
//! 
//! - [ ] Signature Verifying

use ed448_goldilocks_plus::{EdwardsPoint, CompressedEdwardsY, Scalar, elliptic_curve::hash2curve::ExpandMsgXof, sha3::Shake256};
use ed448_goldilocks_plus::{SigningKey, VerifyingKey};
use ed448_goldilocks_plus::SecretKey;
use rand::rngs::OsRng;
use serde_big_array::BigArray;
use zeroize::ZeroizeOnDrop;
use zeroize::Zeroize;
use serde::{Serialize,Deserialize};
use ed448_goldilocks_plus::SigningError;
use ed448_goldilocks_plus::Signature;

// Encodings
use crate::slugcrypt::traits::IntoEncoding;
use crate::slugcrypt::traits::FromEncoding;

use crate::errors::SlugErrors;
use slugencode::SlugEncodingUsage;
use slugencode::SlugEncodings;

pub const ED448_CONTEXT: &str = "libslug20";

pub mod protocol_info {
    // Key Sizes
    pub const ed448_secret_key_size: usize = 57;
    pub const ed448_public_key_size: usize = 57;
    pub const ed448_signature_size: usize = 114;

    /// # Context
    /// 
    /// **Default Context:** "libslug20"
    pub const ed448_default_context: &str = "libslug20";
    /// # Protocol Name
    /// 
    /// **Name:** `libslug20/ed448`
    pub const PROTOCOL_NAME: &str = "libslug20/ed448";

    /// # Traits Implemented
    pub const TRAITS_IMPLEMENTED: [&str;2] = ["IntoEncoding","FromEncoding"];

}

#[derive(Clone, PartialEq, PartialOrd, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Ed448PublicKey {
    #[serde(with = "BigArray")]
    pub pk: [u8;57]
}

#[derive(Clone, PartialEq, PartialOrd, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Ed448SecretKey {
    #[serde(with = "BigArray")]
    pub sk: [u8;57],
}

#[derive(Clone, PartialEq, PartialOrd, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Ed448Signature {
    #[serde(with = "BigArray")]
    pub sig: [u8;114],
    pub context: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, PartialOrd, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Ed448Keypair {
    pk: Ed448PublicKey,
    sk: Ed448SecretKey,
}

impl IntoEncoding for Ed448PublicKey {
    fn to_base32(&self) -> Result<String,slugencode::prelude::SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.encode(&self.pk)?;

        return Ok(output)

        
    }
    fn to_base32_unpadded(&self) -> Result<String,slugencode::prelude::SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.encode(&self.pk)?;

        return Ok(output)
    }
    fn to_base58(&self) -> Result<String,slugencode::prelude::SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.encode(&self.pk)?;

        return Ok(output)
    }
    fn to_base64(&self) -> Result<String,slugencode::prelude::SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.encode(&self.pk)?;

        return Ok(output)
    }
    fn to_base64_url_safe(&self) -> Result<String,slugencode::prelude::SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.encode(&self.pk)?;

        return Ok(output)
    }
    fn to_hex(&self) -> Result<String,slugencode::prelude::SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.encode(&self.pk)?;

        return Ok(output)
    }
}

impl IntoEncoding for Ed448SecretKey {
    fn to_base32(&self) -> Result<String,slugencode::prelude::SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.encode(&self.sk)?;

        return Ok(output)

        
    }
    fn to_base32_unpadded(&self) -> Result<String,slugencode::prelude::SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.encode(&self.sk)?;

        return Ok(output)
    }
    fn to_base58(&self) -> Result<String,slugencode::prelude::SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.encode(&self.sk)?;

        return Ok(output)
    }
    fn to_base64(&self) -> Result<String,slugencode::prelude::SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.encode(&self.sk)?;

        return Ok(output)
    }
    fn to_base64_url_safe(&self) -> Result<String,slugencode::prelude::SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.encode(&self.sk)?;

        return Ok(output)
    }
    fn to_hex(&self) -> Result<String,slugencode::prelude::SlugEncodingError> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.encode(&self.sk)?;

        return Ok(output)
    }
}

impl IntoEncoding for Ed448Signature {
    fn to_base32(&self) -> Result<String,slugencode::prelude::SlugEncodingError> {
        let mut output_final = String::new();
        
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.encode(&self.sig)?;
        
        if self.context.is_some() {
            let y = SlugEncodingUsage::new(SlugEncodings::Hex);
            let context = y.encode(&self.context.as_ref().unwrap())?;

            output_final.push_str(&output);
            output_final.push_str(":");
            output_final.push_str(&context);
            return Ok(output_final)
        }
        else {
            return Ok(output)
        }
    }
    fn to_base32_unpadded(&self) -> Result<String,slugencode::prelude::SlugEncodingError> {
        let mut output_final = String::new();
        
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.encode(&self.sig)?;
        
        if self.context.is_some() {
            let y = SlugEncodingUsage::new(SlugEncodings::Hex);
            let context = y.encode(&self.context.as_ref().unwrap())?;

            output_final.push_str(&output);
            output_final.push_str(":");
            output_final.push_str(&context);
            return Ok(output_final)
        }
        else {
            return Ok(output)
        }
    }
    fn to_base58(&self) -> Result<String,slugencode::prelude::SlugEncodingError> {
        let mut output_final = String::new();
        
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.encode(&self.sig)?;
        
        if self.context.is_some() {
            let y = SlugEncodingUsage::new(SlugEncodings::Hex);
            let context = y.encode(&self.context.as_ref().unwrap())?;

            output_final.push_str(&output);
            output_final.push_str(":");
            output_final.push_str(&context);
            return Ok(output_final)
        }
        else {
            return Ok(output)
        }
    }
    fn to_base64(&self) -> Result<String,slugencode::prelude::SlugEncodingError> {
        let mut output_final = String::new();
        
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.encode(&self.sig)?;
        
        if self.context.is_some() {
            let y = SlugEncodingUsage::new(SlugEncodings::Hex);
            let context = y.encode(&self.context.as_ref().unwrap())?;

            output_final.push_str(&output);
            output_final.push_str(":");
            output_final.push_str(&context);
            return Ok(output_final)
        }
        else {
            return Ok(output)
        }
    }
    fn to_base64_url_safe(&self) -> Result<String,slugencode::prelude::SlugEncodingError> {
        let mut output_final = String::new();
        
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.encode(&self.sig)?;
        
        if self.context.is_some() {
            let y = SlugEncodingUsage::new(SlugEncodings::Hex);
            let context = y.encode(&self.context.as_ref().unwrap())?;

            output_final.push_str(&output);
            output_final.push_str(":");
            output_final.push_str(&context);
            return Ok(output_final)
        }
        else {
            return Ok(output)
        }
    }
    fn to_hex(&self) -> Result<String,slugencode::prelude::SlugEncodingError> {
        let mut output_final = String::new();
        
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.encode(&self.sig)?;
        
        if self.context.is_some() {
            let y = SlugEncodingUsage::new(SlugEncodings::Hex);
            let context = y.encode(&self.context.as_ref().unwrap())?;

            output_final.push_str(&output);
            output_final.push_str(":");
            output_final.push_str(&context);
            return Ok(output_final)
        }
        else {
            return Ok(output)
        }
    }
}

impl FromEncoding for Ed448PublicKey {
    fn from_base32<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.decode(s.as_ref())?;
        let output_2 = Self::from_slice(&output)?;
        return Ok(output_2)
    }
    fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.decode(s.as_ref())?;
        let output_2 = Self::from_slice(&output)?;
        return Ok(output_2)
    }
    fn from_base58<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.decode(s.as_ref())?;
        let output_2 = Self::from_slice(&output)?;
        return Ok(output_2)
    }
    fn from_base64<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.decode(s.as_ref())?;
        let output_2 = Self::from_slice(&output)?;
        return Ok(output_2)
    }
    fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.decode(s.as_ref())?;
        let output_2 = Self::from_slice(&output)?;
        return Ok(output_2)
    }
    fn from_hex<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.decode(s.as_ref())?;
        let output_2 = Self::from_slice(&output)?;
        return Ok(output_2)
    }
}

impl FromEncoding for Ed448SecretKey {
    fn from_base32<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32);
        let output = x.decode(s.as_ref())?;
        let output_2 = Self::from_slice(&output)?;
        return Ok(output_2)  
    }
    fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let output = x.decode(s.as_ref())?;
        let output_2 = Self::from_slice(&output)?;
        return Ok(output_2)
    }
    fn from_base58<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base58);
        let output = x.decode(s.as_ref())?;
        let output_2 = Self::from_slice(&output)?;
        return Ok(output_2)
    }
    fn from_base64<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64);
        let output = x.decode(s.as_ref())?;
        let output_2 = Self::from_slice(&output)?;
        return Ok(output_2)
    }
    fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let output = x.decode(s.as_ref())?;
        let output_2 = Self::from_slice(&output)?;
        return Ok(output_2)
    }
    fn from_hex<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let x = SlugEncodingUsage::new(SlugEncodings::Hex);
        let output = x.decode(s.as_ref())?;
        let output_2 = Self::from_slice(&output)?;
        return Ok(output_2)
    }
}

impl FromEncoding for Ed448Signature {
    fn from_base32<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        if s.as_ref().contains(":") {
            let (sig, context_hex) = s.as_ref().split_once(":").unwrap();

            let context_decoder = SlugEncodingUsage::new(SlugEncodings::Hex);
            let sig_decoder = SlugEncodingUsage::new(SlugEncodings::Base32);

            let output = sig_decoder.decode(sig)?;
            let context = context_decoder.decode(context_hex)?;

            let x = Self::from_slice(&output, Some(&context))?;
            return Ok(x)
        }
        else {
            let sig_decoder = SlugEncodingUsage::new(SlugEncodings::Base32);
            let y = sig_decoder.decode(s.as_ref())?;

            let output = Ed448Signature::from_slice(&y, None)?;

            return Ok(output)
        }
    }
    fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        if s.as_ref().contains(":") {
            let (sig, context_hex) = s.as_ref().split_once(":").unwrap();

            let context_decoder = SlugEncodingUsage::new(SlugEncodings::Hex);
            let sig_decoder = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);

            let output = sig_decoder.decode(sig)?;
            let context = context_decoder.decode(context_hex)?;

            let x = Self::from_slice(&output, Some(&context))?;
            return Ok(x)
        }
        else {
            let sig_decoder = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
            let y = sig_decoder.decode(s.as_ref())?;

            let output = Ed448Signature::from_slice(&y, None)?;

            return Ok(output)
        }
    }
    fn from_base58<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        if s.as_ref().contains(":") {
            let (sig, context_hex) = s.as_ref().split_once(":").unwrap();

            let context_decoder = SlugEncodingUsage::new(SlugEncodings::Hex);
            let sig_decoder = SlugEncodingUsage::new(SlugEncodings::Base58);

            let output = sig_decoder.decode(sig)?;
            let context = context_decoder.decode(context_hex)?;

            let x = Self::from_slice(&output, Some(&context))?;
            return Ok(x)
        }
        else {
            let sig_decoder = SlugEncodingUsage::new(SlugEncodings::Base58);
            let y = sig_decoder.decode(s.as_ref())?;

            let output = Ed448Signature::from_slice(&y, None)?;

            return Ok(output)
        }
    }
    fn from_base64<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        if s.as_ref().contains(":") {
            let (sig, context_hex) = s.as_ref().split_once(":").unwrap();

            let context_decoder = SlugEncodingUsage::new(SlugEncodings::Hex);
            let sig_decoder = SlugEncodingUsage::new(SlugEncodings::Base64);

            let output = sig_decoder.decode(sig)?;
            let context = context_decoder.decode(context_hex)?;

            let x = Self::from_slice(&output, Some(&context))?;
            return Ok(x)
        }
        else {
            let sig_decoder = SlugEncodingUsage::new(SlugEncodings::Base64);
            let y = sig_decoder.decode(s.as_ref())?;

            let output = Ed448Signature::from_slice(&y, None)?;

            return Ok(output)
        }
    }
    fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        if s.as_ref().contains(":") {
            let (sig, context_hex) = s.as_ref().split_once(":").unwrap();

            let context_decoder = SlugEncodingUsage::new(SlugEncodings::Hex);
            let sig_decoder = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);

            let output = sig_decoder.decode(sig)?;
            let context = context_decoder.decode(context_hex)?;

            let x = Self::from_slice(&output, Some(&context))?;
            return Ok(x)
        }
        else {
            let sig_decoder = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
            let y = sig_decoder.decode(s.as_ref())?;

            let output = Ed448Signature::from_slice(&y, None)?;

            return Ok(output)
        }
    }
    fn from_hex<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        if s.as_ref().contains(":") {
            let (sig, context_hex) = s.as_ref().split_once(":").unwrap();

            let context_decoder = SlugEncodingUsage::new(SlugEncodings::Hex);
            let sig_decoder = SlugEncodingUsage::new(SlugEncodings::Hex);

            let output = sig_decoder.decode(sig)?;
            let context = context_decoder.decode(context_hex)?;

            let x = Self::from_slice(&output, Some(&context))?;
            return Ok(x)
        }
        else {
            let sig_decoder = SlugEncodingUsage::new(SlugEncodings::Hex);
            let y = sig_decoder.decode(s.as_ref())?;

            let output = Ed448Signature::from_slice(&y, None)?;

            return Ok(output)
        }
    }
}
impl Ed448SecretKey {
    pub fn as_bytes(&self) -> &[u8] {
        return &self.sk
    }
    pub fn to_bytes(&self) -> [u8;57] {
        return self.sk
    }
    pub fn to_bytes_vec(&self) -> Vec<u8> {
        return self.sk.to_vec()
    }
    pub fn generate() -> Self {
        let mut output_key: [u8;57] = [0u8;57];


        let key: SigningKey = SigningKey::generate(&mut OsRng);
        let key_bytes = key.as_bytes().as_slice();
        assert_eq!(key_bytes.len(),57usize);

        output_key.copy_from_slice(key_bytes);
        
        return Self {
            sk: output_key
        }
    }
    pub fn into_usable_type(&self) -> SigningKey {
        let sk = SecretKey::from_slice(&self.sk);
        let skk = SigningKey::from(sk);
        return skk
    }
    pub fn into_public_key_type(&self) -> VerifyingKey {
        return self.into_usable_type().verifying_key().clone()
    }
    pub fn into_public_key(&self) -> Ed448PublicKey {
        let x = self.into_usable_type().verifying_key().to_bytes();

        return Ed448PublicKey { pk: x }
    }
    pub fn sign_with_context<T: AsRef<[u8]>>(&self, msg: T, context: T) -> Result<Ed448Signature,SlugErrors> {
        let x: Result<ed448_goldilocks_plus::Signature, _> = self.into_usable_type().sign_ctx(context.as_ref(), msg.as_ref());

        if x.is_err() {
            return Err(SlugErrors::SigningFailure(crate::errors::SlugErrorAlgorithms::SIG_ED448))
        }
        else {
            let mut signature_output: [u8;114] = [0u8;114];
            signature_output.copy_from_slice(&x.unwrap().to_bytes());

            let signature = Ed448Signature {
                sig: signature_output,
                context: Some(context.as_ref().to_vec()),
            };
            return Ok(signature)
        }

        

        
    }
    pub fn sign_without_context_attached<T: AsRef<[u8]>>(&self, msg: T, context: T) -> Result<Ed448Signature,SlugErrors> {
        let x: Result<ed448_goldilocks_plus::Signature, _> = self.into_usable_type().sign_ctx(context.as_ref(), msg.as_ref());

        if x.is_err() {
            return Err(SlugErrors::SigningFailure(crate::errors::SlugErrorAlgorithms::SIG_ED448))
        }
        else {
            let mut signature_output: [u8;114] = [0u8;114];
            signature_output.copy_from_slice(&x.unwrap().to_bytes());

            let signature = Ed448Signature {
                sig: signature_output,
                context: None,
            };

            return Ok(signature)
        }
    }
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Result<Ed448Signature, SlugErrors>  {
        self.sign_with_context(msg.as_ref(), ED448_CONTEXT.as_bytes())
    }
    pub fn from_slice(x: &[u8]) -> Result<Ed448SecretKey, SlugErrors> {
        let mut output: [u8;57] = [0u8;57];
        
        if x.len() == 57 {
            output.copy_from_slice(x);
            return Ok(Self {
                sk: output
            })
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
}

impl Ed448PublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        return &self.pk
    }
    pub fn to_bytes(&self) -> [u8;57] {
        return self.pk
    }
    pub fn to_bytes_vec(&self) -> Vec<u8> {
        return self.pk.to_vec()
    }
    pub fn into_usable_type(&self) -> Result<VerifyingKey,SlugErrors> {
        let x: Result<VerifyingKey, _> = VerifyingKey::from_bytes(&self.pk);

        if x.is_err() {
            return Err(SlugErrors::Other(String::from("Failed To Convert Into VerifyingKey Type")))
        }
        else {
            return Ok(x.unwrap())
        }
    }
    pub fn verify<T: AsRef<[u8]>>(&self, msg: T, sig: Ed448Signature) -> Result<bool, SlugErrors> {
        let x = self.into_usable_type()?;
        let signature = sig.into_usable_type()?;

        // FIX LATER
        if sig.context.is_some() {
            let output = x.verify_ctx(&signature, &sig.context.clone().unwrap(), msg.as_ref());

            if output.is_ok() {
                return Ok(true)
            }
            else {
                return Ok(false)
            }
        }
        else {
            let output = x.verify_ctx(&signature, &ED448_CONTEXT.as_bytes(), msg.as_ref());

            if output.is_ok() {
                return Ok(true)
            }
            else {
                return Ok(false)
            }
        }
        
    }
    pub fn verify_with_context<T: AsRef<[u8]>>(&self, msg: T, context: T, sig: Ed448Signature) {

    }
    pub fn from_slice(x: &[u8]) -> Result<Ed448PublicKey, SlugErrors> {
        let mut output: [u8;57] = [0u8;57];
        
        if x.len() == 57 {
            output.copy_from_slice(x);
            return Ok(Self {
                pk: output
            })
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
}

impl Ed448Signature {
    pub fn as_bytes(&self) -> &[u8] {
        return &self.sig
    }
    pub fn to_bytes(&self) -> [u8;114] {
        return self.sig
    }
    pub fn to_bytes_vec(&self) -> Vec<u8> {
        return self.sig.to_vec()
    }
    pub fn into_usable_type(&self) -> Result<Signature, SlugErrors> {
        let sig: Result<Signature, SigningError> = Signature::from_bytes(&self.sig);

        if sig.is_err() {
            return Err(SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_ED448))
        }
        else {
            return Ok(sig.unwrap())
        }    
    }
    pub fn from_slice(x: &[u8], context: Option<&[u8]>) -> Result<Ed448Signature, SlugErrors> {
        let mut output: [u8;114] = [0u8;114];
        
        if x.len() == 114 && context.is_some() {
            output.copy_from_slice(x);
            return Ok(Self {
                sig: output,
                context: Some(context.unwrap().to_vec())
            })
        }
        else if x.len() == 114 && context.is_none() {
            output.copy_from_slice(x);
            return Ok(Self {
                sig: output,
                context: None,
            })
        }
        else {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
    }
}


#[test]
fn create() {
    let key = Ed448SecretKey::generate();
    let msg = "This is a message being signed by ed448-goldilocks-plus";
    let sig = key.sign_with_context(msg.as_bytes(), ED448_CONTEXT.as_bytes()).expect("Failed to receive");

    let result = key.into_public_key().verify(msg.as_bytes(), sig);
    assert_eq!(result.unwrap(),true);
}