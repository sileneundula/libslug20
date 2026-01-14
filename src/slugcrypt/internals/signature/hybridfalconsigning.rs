//! # HybridFalcon Signing
//! 
//! HybridFalcon signing is signing using ED25519 for the classical key and FALCON1024 for the post-quantum key.
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

use serde::{Serialize,Deserialize};
use zeroize::{ZeroizeOnDrop,Zeroize};

use slugencode::prelude::*;

#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop)]
pub struct HybridFalconKeypair {
    pub clpk: ED25519PublicKey,
    pub pqpk: Falcon1024PublicKey,
    
    pub clsk: Option<ED25519SecretKey>,
    pub pqsk: Option<Falcon1024SecretKey>,
}

#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop)]
pub struct HybridFalconSignature {
    pub clsig: ED25519Signature,
    pub pqsig: Falcon1024Signature,
}

impl HybridFalconKeypair {
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
    pub fn sign<T: AsRef<[u8]>>(&self, data: T) -> Result<HybridFalconSignature,SlugErrors> {
        if self.pqsk.is_some() && self.pqsk.is_some() {
            let cl_sig = self.clsk.clone().unwrap().sign(data.as_ref());
            let pq_sig = self.pqsk.clone().unwrap().sign(data.as_ref());

            if cl_sig.is_err() || pq_sig.is_err() {
                return Err(SlugErrors::SigningFailure)
            }
            else {
                Ok(
                    HybridFalconSignature {
                    clsig: cl_sig.unwrap(),
                    pqsig: pq_sig.unwrap(),
                    }
                )
            }



        }
        else {
            return Err(SlugErrors::SigningFailure)
        }
    }
    pub fn verify<T: AsRef<[u8]>>(&self, data: T, signature: HybridFalconSignature) -> Result<bool,SlugErrors> {
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
}