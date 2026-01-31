//! # Esphand Signing
//! 
//! ## Description
//! 
//! Esphand signing is signing using ED25519 for the classical key and FALCON1024 for the post-quantum key.
//! 
//! ## Encoding
//! 
//! Encoding type is **Hexadecimal** with a colon seperating the keys, with the ed25519 being first and falcon1024 being second.
//! 
//! ## Implemented Traits
//! - [X] IntoX59
//!     - [X] IntoX59PublicKey
//!     - [X] IntoX59SecretKey
//!     - [X] IntoX59Signature
//! - [X] IntoPEM
//!     - [X] IntoPemPublicKey
//!     - [X] IntoPemSecretKey
//!     - [X] IntoPemSignature
//! - [ ] IntoOintAddress (propiertary)
//!     - [ ]
//! 
//! ## TODO
//! 
//! - [ ] Serialization
//! - [ ] Examples
//! - [ ] Tests
//! - [ ] Encodings
//! - [ ] Add Randominzed Signing

use crate::slugcrypt::internals::messages::Message;
use crate::slugcrypt::internals::signature::ed25519::{ED25519SecretKey,ED25519PublicKey,ED25519Signature};
use crate::slugcrypt::internals::signature::falcon::*;
use crate::errors::SlugErrors;
use crate::errors::SlugErrorAlgorithms;
use crate::slugcrypt::internals::signature::esphand_signature::protocol_values::{PROTOCOL_NAME_FOR_PEM, PROTOCOL_NAME_FOR_PEM_PUBLIC, PROTOCOL_NAME_FOR_PEM_SECRET, PROTOCOL_NAME_FOR_PEM_SIGNATURE};

use serde::{Serialize,Deserialize};
use zeroize::{ZeroizeOnDrop,Zeroize};
use pem::Pem;
use std::f32::consts::E;
use std::str::FromStr;
use std::string::ToString;
use log::debug;
use log::warn;
use log::info;

// Trait
use crate::slugcrypt::traits::{IntoPemPublic,IntoPemSecret, IntoPemSignature};
use crate::slugcrypt::traits::IntoPem;
use crate::slugcrypt::traits::{IntoX59PublicKey,IntoX59SecretKey,IntoX59Signature};

use slugencode::prelude::*;

pub mod protocol_info {
    pub const PROTOCOL_NAME: &str = "libslug20/EsphandSignature";
    pub const NAME: &str = "Esphand";
    pub const NAME_FULL: &str = "slug20_EsphandSignature_ED25519_with_FALCON1024";


    pub const CLASSICALALGORITHM: &str = "ed25519";
    pub const POSTQUANTUMALGORITHM: &str = "Falcon1024";
    pub const FALCON1024_PK_SIZE: usize = 1_793;
    pub const FALCON1024_SK_SIZE: usize = 2_305;
    pub const FALCON1024_SIG_SIZE: usize = 1_280;
    pub const ED25519_PK_SIZE: usize = 32;
    pub const ED25519_SK_SIZE: usize = 32;
    pub const ED25519_SIG_SIZE: usize = 64;
    pub const X59_SIZE_SECRET: usize = 4229;
}

pub mod protocol_values {
    /// Adonis
    pub const PROTOCOL_NAME_FOR_PEM: &str = "libslug20/Esphand";
    pub const PROTOCOL_NAME_FOR_PEM_2: &str = "libslug20/EsphandSignature";
    pub const PROTOCOL_NAME_FOR_PEM_SECRET: &str = "EsphandSignature-SecretKey";
    pub const NAME_FULL: &str = "slug20_EsphandSignature_ED25519_with_FALCON1024";
    pub const PROTOCOL_NAME_FOR_PEM_PUBLIC: &str = "EsphandSignature-PublicKey";
    pub const PROTOCOL_NAME_FOR_PEM_SIGNATURE: &str = "EsphandSignature-Signature";
}

#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop)]
pub struct EsphandKeypair {
    pub clpk: ED25519PublicKey,
    pub pqpk: Falcon1024PublicKey,
    
    pub clsk: Option<ED25519SecretKey>,
    pub pqsk: Option<Falcon1024SecretKey>,
}

impl IntoX59PublicKey for EsphandKeypair {
    fn into_x59_pk(&self) -> Result<String,SlugErrors> {
        let mut output: String = String::new();
        
        let clpk = self.clpk.to_hexadecimal();
        let pqpk = self.pqpk.to_hex();

        let output_cl = match clpk {
            Ok(v) => v,
            Err(_) => return Err(SlugErrors::Other(String::from("Failed To Convert ED25519")))
        };
        
        let output_pq = match pqpk {
            Ok(v) => v,
            Err(_) => return Err(SlugErrors::Other(String::from("Failed To Convert ED25519")))
        };

        output.push_str(&output_cl);
        output.push_str(":");
        output.push_str(&output_pq);

        return Ok(output)



    }
    fn from_x59_pk<T: AsRef<str>>(x59_encoded: T) -> Result<Self,SlugErrors> {
        let x = x59_encoded.as_ref();
        let pk: Vec<&str> = x.split(":").collect();
        let ed25519_pk: Result<ED25519PublicKey, SlugEncodingError> = ED25519PublicKey::from_hex(pk[0]);
        let falcon_pk = Falcon1024PublicKey::from_hex(pk[1]);

        let output_ed25519 = match ed25519_pk {
            Ok(v) => v,
            Err(_) => return Err(SlugErrors::InvalidLengthFromBytes)
        };
        let output_falcon1024 = match falcon_pk {
            Ok(v) => v,
            Err(_) => return Err(SlugErrors::InvalidLengthFromBytes)
        };

        return Ok(Self {
            clpk: output_ed25519,
            pqpk: output_falcon1024,
            pqsk: None,
            clsk: None,
        })
    }
    fn x59_metadata_pk() -> String {
        return protocol_values::NAME_FULL.to_string()
    }
}

impl IntoX59SecretKey for EsphandKeypair {
    /// # Into X59 Format
    /// 
    /// This converts the EsphandKeypair into X59 Format.
    /// 
    /// ## Definition
    /// 
    /// `ED25519_PK:ED25519_SK/FALCON1024PK:FALCON1024SK`
    fn into_x59(&self) -> Result<String,SlugErrors> {
        if self.clsk.is_none() || self.pqsk.is_none() {
            return Err(SlugErrors::EncodingError { 
                alg: SlugErrorAlgorithms::SIG_FALCON, 
                encoding: crate::errors::EncodingError::X59_fmt, 
                other: Some(String::from("No Secret Key Found For ED25519 or FALCON1024")) })
        }
        let mut output = String::new();

        let x = self.clpk.to_hexadecimal()?;
        let x_2 = self.clsk.clone().unwrap().to_hexadecimal()?;
        let y = self.pqpk.to_hex()?;
        let y_2 = self.pqsk.clone().unwrap().to_hex()?;

        output.push_str(&x);
        output.push_str(":");
        output.push_str(&x_2);
        output.push_str("/");
        output.push_str(&y);
        output.push_str(":");
        output.push_str(&y_2); 

        return Ok(output)
        
    }
    fn from_x59<T: AsRef<str>>(x59_encoded_secret_key: T) -> Result<Self,SlugErrors> {
        let x = x59_encoded_secret_key.as_ref();

        if x.len() == 4229 && x.contains("/") == true && x.contains(":") == true {
            let x = 0;
        }
        else {
            return Err(SlugErrors::DecodingError { alg: SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::X59_fmt, other: None })
        }
        let pkandsk: Vec<&str> = x.split("/").collect();
        assert_eq!(pkandsk.len(),2);
        let ed25519 = pkandsk[0];
        let falcon = pkandsk[1];

        let keypair_ed25519_hex: Vec<&str> = ed25519.split(":").collect();
        let keypair_falcon_hex: Vec<&str> = falcon.split(":").collect();

        let output_ed25519 = ED25519PublicKey::from_hex(keypair_ed25519_hex[0])?;
        let output_ed25519_sk = ED25519SecretKey::from_hex(keypair_ed25519_hex[1])?;

        let output_falcon1024 = Falcon1024PublicKey::from_hex(keypair_falcon_hex[0])?;
        let output_falcon1024_sk = Falcon1024SecretKey::from_hex(keypair_falcon_hex[0])?;

        return Ok(
            Self {
                clpk: output_ed25519,
                pqpk: output_falcon1024,
                clsk: Some(output_ed25519_sk),
                pqsk: Some(output_falcon1024_sk)
            }
        )
    }
    fn x59_metadata() -> String {
        return protocol_values::NAME_FULL.to_string()
    }
}

impl IntoX59Signature for EsphandSignature {
    fn into_x59(&self) -> Result<String,SlugErrors> {
        let mut output: String = String::new();
        
        let ed25519_sig = self.clsig.to_hexadecimal()?;
        let falcon1024_sig = self.pqsig.to_hex()?;

        output.push_str(&ed25519_sig);
        output.push_str(":");
        output.push_str(&falcon1024_sig);

        return Ok(output)
    }
    fn from_x59<T: AsRef<str>>(x59_encoded_signature: T) -> Result<Self,SlugErrors> {
        let x = x59_encoded_signature.as_ref();
        let signatures: Vec<&str> = x.split(":").collect();

        let ed25519_sig = ED25519Signature::from_hex(signatures[0])?;
        let falcon_sig = Falcon1024Signature::from_hex(signatures[1])?;

        return Ok(
            Self {
                clsig: ed25519_sig,
                pqsig: falcon_sig,
            }
        )
    }
    fn x59_metadata() -> String {
        return protocol_values::NAME_FULL.to_string()
    }
}

impl IntoPemPublic for EsphandKeypair {
    fn into_pem(&self) -> Result<String,SlugErrors> {
        let x = self.into_x59_pk()?;
        let output = Pem::new(protocol_values::PROTOCOL_NAME_FOR_PEM_PUBLIC, x).to_string();
        Ok(output)
    }
    fn from_pem<T: AsRef<str>>(public_key_in_pem: T) -> Result<Self,SlugErrors> {
        let x = pem::parse(public_key_in_pem.as_ref());

        let data = match x {
            Ok(v) => {
                v
            }
            Err(_) => return Err(SlugErrors::DecodingError { alg: SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::PEM, other: None })
        };

        let n = String::from_utf8(data.into_contents());

        let x59 = match n {
            Ok(v) => v,
            Err(_) => return Err(SlugErrors::DecodingError { alg: SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::PEM, other: None })
        };
        let output = Self::from_x59_pk(x59)?;
        Ok(output)
    }
    fn get_pem_label() -> String {
        return protocol_values::PROTOCOL_NAME_FOR_PEM_PUBLIC.to_string()
    }
}

impl IntoPemSecret for EsphandKeypair {
    fn into_pem_secret(&self) -> Result<String,SlugErrors> {
        let x = self.into_x59()?;
        let output = Pem::new(PROTOCOL_NAME_FOR_PEM_SECRET,x.as_bytes()).to_string();
        return Ok(output)
    }
    fn from_pem_secret<T: AsRef<str>>(secret_key_in_pem: T) -> Result<Self,SlugErrors> {
        let x = secret_key_in_pem.as_ref();

        let x = pem::parse(x);

        let output = match x {
            Ok(v) => v,
            Err(_) => return Err(SlugErrors::DecodingError { alg: SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::PEM, other: None, })
        };
        let x59_encoded = String::from_utf8(output.contents().to_vec());

        let x59_encoded_data = match x59_encoded {
            Ok(v) => v,
            Err(_) => return Err(SlugErrors::DecodingError { alg: SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::PEM, other: None })
        };
        let y = Self::from_x59(x59_encoded_data)?;
        return Ok(y)
    }
    fn get_pem_label_secret() -> String {
        return PROTOCOL_NAME_FOR_PEM_SECRET.to_string()
    }
}

impl IntoPemSignature for EsphandSignature {
    fn into_pem(&self) -> Result<String,SlugErrors> {
        let x = self.into_x59()?;
        let output = Pem::new(PROTOCOL_NAME_FOR_PEM_SIGNATURE, x.as_bytes()).to_string();
        return Ok(output)
    }
    fn from_pem<T: AsRef<str>>(signature_in_pem: T) -> Result<Self,SlugErrors> {
        let x = signature_in_pem.as_ref();
        let pem_decoded = pem::parse(x);

        let pem_output = match pem_decoded {
            Ok(v) => v,
            Err(_) => return Err(SlugErrors::DecodingError { alg: SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::PEM, other: Some(String::from("Signature PEM Decoding Failure")) })
        };

        let output = String::from_utf8(pem_output.into_contents());

        let x59 = match output {
            Ok(v) => v,
            Err(_) => return Err(SlugErrors::DecodingError { alg: SlugErrorAlgorithms::SIG_FALCON, encoding: crate::errors::EncodingError::PEM, other: Some(String::from("Signature PEM Decoding Failure")) })
        };

        let keypair = Self::from_x59(x59)?;

        return Ok(keypair)
    }
    fn get_pem_label_signature() -> String {
        return PROTOCOL_NAME_FOR_PEM_SIGNATURE.to_string()
    }
}


#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop)]
pub struct EsphandSignature {
    pub clsig: ED25519Signature,
    pub pqsig: Falcon1024Signature,
}

impl EsphandKeypair {
    /// # From Keys
    /// 
    /// Imports Public Key From Keys
    pub fn from_keys(ed: &ED25519PublicKey, falcon: &Falcon1024PublicKey) -> Self {
        Self {
            clpk: ed.to_owned(),
            pqpk: falcon.to_owned(),
            clsk: None,
            pqsk: None,
        }
    }
    /// # From Secret Keys
    pub fn from_keys_secret(ed_pk: &ED25519PublicKey, ed_sk: &ED25519SecretKey, falcon_pk: &Falcon1024PublicKey, falcon_sk: &Falcon1024SecretKey) -> Self {
        Self {
            clpk: ed_pk.to_owned(),
            clsk: Some(ed_sk.to_owned()),
            pqpk: falcon_pk.to_owned(),
            pqsk: Some(falcon_sk.to_owned()),
        }
    }
    /// # Generate a EsphandSignature Scheme
    /// 
    /// Generates an ED25519 + FALCON1024 digital signature scheme using OSCSPRNG.
    pub fn generate() -> Self {
        let cl = ED25519SecretKey::generate();
        let clpk = cl.public_key().unwrap();
        let (pq_pk,pq_sk) = SlugFalcon1024::generate();

        return Self {
            clpk: clpk,
            pqpk: pq_pk,

            clsk: Some(cl),
            pqsk: Some(pq_sk)
        }
    }
    pub fn sign<T: AsRef<[u8]>>(&self, data: T) -> Result<EsphandSignature,SlugErrors> {
        if self.pqsk.is_some() && self.pqsk.is_some() {
            let cl_sig = self.clsk.clone().unwrap().sign(data.as_ref());
            let pq_sig = self.pqsk.clone().unwrap().sign(data.as_ref());

            if cl_sig.is_err() || pq_sig.is_err() {
                return Err(SlugErrors::SigningFailure(SlugErrorAlgorithms::SIG_FALCON))
            }
            else {
                Ok(
                    EsphandSignature {
                    clsig: cl_sig.unwrap(),
                    pqsig: pq_sig.unwrap(),
                    }
                )
            }



        }
        else {
            return Err(SlugErrors::SigningFailure(SlugErrorAlgorithms::SIG_FALCON))
        }
    }
    pub fn verify<T: AsRef<[u8]>>(&self, data: T, signature: &EsphandSignature) -> Result<bool,SlugErrors> {
        let cl_is_valid = self.clpk.verify(signature.clsig.clone(),data.as_ref());
        let pq_is_valid = self.pqpk.verify(data.as_ref(), &signature.pqsig);

        if cl_is_valid.is_err() {
            return Err(SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_ED25519))
        }
        else if pq_is_valid.is_err() {
            return Err(SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_SPHINCS_PLUS))
        }
        else {
            if cl_is_valid.unwrap() == true && pq_is_valid.unwrap() == true {
                return Ok(true)
            }
            else {
                return Ok(false)
            }
        }
    }
    /// # X59 Public Key
    /// 
    /// `X59 Public Key` is a hex-encoded, constant-time encoder, that is in the following format:
    /// 
    /// **Format:** `CL_PK` + `:` + `FALCON1024_PK`
    pub fn to_x59_public_key(&self) -> Result<String, SlugEncodingError> {
        let encoder = SlugEncodingUsage::new(SlugEncodings::Hex);

        let mut s: String = String::new();

        let classical_key = encoder.encode(self.clpk.as_bytes())?;
        let post_quantum = encoder.encode(self.pqpk.as_bytes())?;

        s.push_str(&classical_key);
        s.push_str(":");
        s.push_str(&post_quantum);

        return Ok(s)
    }
    /// # From X59 Public Key
    /// 
    /// **Format:** `cl_pk` + `:` + `pq_pk`
    pub fn from_x59_public_key<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let encoder = SlugEncodingUsage::new(SlugEncodings::Hex);

        let x: Vec<&str> = s.as_ref().split(":").collect();
        
        let output_cl = encoder.decode(x[0])?;
        let output_pq = encoder.decode(x[1])?;

        Ok(Self {
            clpk: ED25519PublicKey::from_slice(&output_cl).unwrap(),
            pqpk: Falcon1024PublicKey::from_bytes(&output_pq).unwrap(),

            pqsk: None,
            clsk: None,
        })
    }
    /// # X59 To Secret Key
    /// 
    /// Converts To Secret Key Format
    pub fn to_x59_secret_key(&self) -> Result<String,SlugEncodingError> {
        let encoder = SlugEncodingUsage::new(SlugEncodings::Hex);

        let mut s: String = String::new();

        let clpk = encoder.encode(self.clpk.as_bytes())?;
        let pqpk = encoder.encode(self.pqpk.as_bytes())?;
        let pqsk = encoder.encode(self.pqsk.clone().unwrap().as_bytes())?;
        let clsk = encoder.encode(self.clsk.clone().unwrap().as_bytes())?;

        s.push_str(&clsk);
        s.push_str(":");
        s.push_str(&clpk);
        s.push_str(":");
        s.push_str(&pqsk);
        s.push_str(":");
        s.push_str(&pqpk);

        Ok(s)


    }
    /// # From X59 Secret Key
    /// 
    /// `ED25519SK`:`ED25519PK`:`FALCON1024SK`:`FALCON1024PK`
    pub fn from_x59_secret_key<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let encoder = SlugEncodingUsage::new(SlugEncodings::Hex);

        let x: Vec<&str> = s.as_ref().split(":").collect();

        let clpk = encoder.decode(x[0])?;
        let clsk = encoder.decode(x[1])?;
        let pqsk = encoder.decode(x[2])?;
        let pqpk = encoder.decode(x[3])?;

        Ok(Self {
            clpk: ED25519PublicKey::from_slice(&clpk).unwrap(),
            pqpk: Falcon1024PublicKey::from_bytes(&pqsk).unwrap(),
            pqsk: Some(Falcon1024SecretKey::from_bytes(&pqsk).unwrap()),
            clsk: Some(ED25519SecretKey::from_bytes(&clsk).unwrap())
        })

    }
}

impl IntoPem for EsphandKeypair {
    /// # Into PEM (Secret Key)
    /// 
    /// Converts to X59 Secret Key And Encodes As Pem
    fn into_pem_private(&self) -> String {
        let x = self.to_x59_secret_key().unwrap();
        let output = Pem::new(PROTOCOL_NAME_FOR_PEM_SECRET, x).to_string();
        return output
    }
    fn into_pem_public(&self) -> String {
        let x = self.to_x59_public_key().unwrap();
        let output = Pem::new(PROTOCOL_NAME_FOR_PEM_PUBLIC, x).to_string();
        return output
    }
    fn from_pem_private<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let parsed_adonis: Result<Pem, pem::PemError> = pem::parse(s.as_ref());

        match parsed_adonis {
            Ok(v) => {
                if v.tag().to_string() == PROTOCOL_NAME_FOR_PEM_SECRET {
                    log::info!("[Libslug] Adonis PEM matches for Secret Key");
                    let y: Result<EsphandKeypair, SlugEncodingError> = EsphandKeypair::from_x59_secret_key(String::from_utf8(v.contents().to_vec()).expect("Failed to convert to string"));
                    
                    if y.is_ok() {
                        return Ok(y.unwrap())
                    }
                    else {
                        return Err(SlugErrors::Other(String::from("Could not parse PEM for Adonis")))
                    }

                }
                else {
                    log::warn!("[Libslug] Adonis PEM does not match the tag for Secret Key");

                    let output: Result<EsphandKeypair, SlugEncodingError> = EsphandKeypair::from_x59_secret_key(String::from_utf8(v.contents().to_vec()).expect("Failed to convert X59 Private Key"));
                    
                    if output.is_ok() {
                        return Ok(output.unwrap())
                    }
                    else {
                        return Err(SlugErrors::Other(String::from("Failure in Signing For Adonis Signature")))
                    }
                }
            }
            Err(_) => {
                return Err(SlugErrors::Other(String::from("Could Not Parse PEM For Adonis.")))
            }
        }
    }
    fn from_pem_public<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let parsed_adonis: Result<Pem, pem::PemError> = pem::parse(s.as_ref());

        match parsed_adonis {
            Ok(v) => {
                if v.tag().to_string() == PROTOCOL_NAME_FOR_PEM_PUBLIC {
                    log::info!("[Libslug] Adonis PEM matches for Public Key");
                    let y: Result<EsphandKeypair, SlugEncodingError> = EsphandKeypair::from_x59_secret_key(String::from_utf8(v.contents().to_vec()).expect("Failed to convert to string"));
                    
                    if y.is_ok() {
                        return Ok(y.unwrap())
                    }
                    else {
                        return Err(SlugErrors::Other(String::from("Could not parse PEM for Adonis")))
                    }

                }
                else {
                    log::warn!("[Libslug] Adonis PEM does not match the tag for Public Key");

                    let output = EsphandKeypair::from_x59_secret_key(String::from_utf8(v.contents().to_vec()).unwrap());
                    
                    if output.is_ok() {
                        return Ok(output.unwrap())
                    }
                    else {
                        return Err(SlugErrors::Other(String::from("Failure in Signing For Adonis Signature")))
                    }
                }
            }
            Err(_) => {
                return Err(SlugErrors::Other(String::from("Could Not Parse PEM For Adonis.")))
            }
        }
    }
    fn get_pem_label_for_public() -> String {
        return PROTOCOL_NAME_FOR_PEM_PUBLIC.to_string()
    }
    fn get_pem_label_for_secret() -> String {
        return PROTOCOL_NAME_FOR_PEM_SECRET.to_string()
    }
}

impl EsphandSignature {
    /// # To Bytes
    /// 
    /// 1. ED25519
    /// 2. FALCON1024
    pub fn to_bytes(&self) -> (Vec<u8>,Vec<u8>) {
        return (self.clsig.as_bytes().to_vec(),self.pqsig.as_bytes().to_vec())
    }
    /// # To X59 Signature (Esphand)
    /// 
    /// **Encoding:** Hexadecimal
    pub fn to_x59_signature(&self) -> Result<String,SlugEncodingError> {
        let mut output = String::new();

        output.push_str(&self.clsig.to_hexadecimal()?);
        output.push_str(":");
        output.push_str(&self.pqsig.to_hex()?);

        return Ok(output)
    }
    /// # From X59 Signature (Esphand)
    /// 
    /// **Encoding:** Hexadecimal
    pub fn from_x59_signature<T: AsRef<str>>(s: T) -> Result<Self,SlugEncodingError> {
        let x = s.as_ref();
        let output: Vec<&str> = x.split(":").collect();

        let clsig = ED25519Signature::from_hex(output[0])?;
        let pqsig = Falcon1024Signature::from_hex(output[1])?;

        return Ok(Self {
            clsig: clsig,
            pqsig: pqsig,
        })
    }
    
}