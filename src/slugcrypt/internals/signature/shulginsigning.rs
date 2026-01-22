//! # ShulginSigning
//! 
//! ShulginSigning is a hybrid digital signature scheme using ED25519 and SPHINCS+ (SHAKE256).
//! 
//! ## Encoding
//! 
//! ### Public Key
//! 
//! ED25519 (Upper-Hex) | : | SPHINCS+ PK (Upper-Hex)
//! 
//! ### Signature
//! 
//! ED25519 (Upper-Hex) | : | SPHINCS+ Signature (Base58)
//! 
//! It is created by Joseph P. Tortorelli (silene/0x20CB)
//! 
//! ## TODO:
//! 
//! - [ ] REFACTOR
//! - [ ] ENCODINGS
//! - [ ] PUBLIC KEY
//! - [ ] PRIVATE KEY
//! - [ ] ADD PEM ENCODING

use std::f32::consts::E;
use std::string::FromUtf8Error;

use crate::slugcrypt::internals::messages::Message;
use crate::slugcrypt::internals::signature::ed25519::{ED25519SecretKey,ED25519PublicKey,ED25519Signature};
use crate::slugcrypt::internals::signature::sphincs_plus::{SPHINCSPublicKey,SPHINCSSecretKey,SPHINCSSignature};
use crate::errors::SlugErrors;
use crate::errors::SlugErrorAlgorithms;

use fixedstr::str128;

use k256::pkcs8;
use slugencode::prelude::*;
use pem::Pem;

use serde::{Serialize,Deserialize};
use zeroize::{ZeroizeOnDrop,Zeroize};

/// # ShulginKeypair
/// 
/// Contains an ED25519 Keypair and a SPHINCS+ Keypair
#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop)]
pub struct ShulginKeypair {
    //=====Public-Keys=====//
    pub ed25519pk: ED25519PublicKey,
    pub sphincspk: SPHINCSPublicKey, // Post-Quantum
    
    //=====Secret-Keys=====//
    pub ed25519sk: Option<ED25519SecretKey>,
    pub sphincssk: Option<SPHINCSSecretKey>,
}

#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop)]
pub struct ShulginSigningPublicKey {
    pub clpk: ED25519PublicKey,
    pub pqpk: SPHINCSPublicKey,
}

#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop)]
pub struct ShulginSigningSecretKey {
    pub clsk: ED25519SecretKey,
    pub pqpk: SPHINCSPublicKey,
    pub pqsk: SPHINCSSecretKey,
}

/// # ShulginSigning Compact
#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop)]
pub struct ShulginKeypairCompact {
    pub public_key: String,
    pub secret_key: Option<String>,
}

impl ShulginKeypairCompact {
    pub fn from_pk(keypair: &ShulginKeypair) -> Result<Self,SlugErrors> {
        let pk = key_to_compact(&keypair);

        if pk.is_err() {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
        else {
            return Ok(Self { public_key: pk.unwrap(), secret_key: None })
        }
    }
    pub fn from_sk(keypair: &ShulginKeypair) -> Result<Self, SlugErrors> {
        let pk = key_to_compact(keypair);
        let sk = secret_key_to_compact(keypair);

        if pk.is_err() || sk.is_err() {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
        else {
            return Ok(Self {
                public_key: pk.unwrap(),
                secret_key: Some(sk.unwrap())
            })
        }
    }
    pub fn as_str_pk(&self) -> &str {
        return &self.public_key
    }
    pub fn to_str_pk(&self) -> String {
        return self.public_key.clone()
    }
    pub fn to_str_sk(&self) -> String {
        return self.secret_key.clone().unwrap()
    }
    pub fn contains_secret(&self) -> bool {
        if self.secret_key.is_some() {
            return true
        }
        else {
            return false
        }
    }
    pub fn into_shulginkeypair(&self) -> Result<ShulginKeypair, SlugErrors> {
        if self.contains_secret() == false {
            return ShulginKeypair::from_compact_pk(&self.public_key)
        }
        else {
            return ShulginKeypair::from_compact_keypair(&self.public_key, &self.secret_key.clone().unwrap())
        }
    }
}

#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop)]
pub struct ShulginSignature {
    pub clsig: ED25519Signature,
    pub pqsig: SPHINCSSignature,
}
/*
/// # Compact Signature
/// 
/// SPHINCS+ is compact due to using hash to find signature.
pub struct ShulginSignatureCompact {
    pub clsig: ED25519Signature,
    pub pqsig_location: str128,
}
    */

#[derive(Debug,Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop)]
pub struct ShulginSignatureCompact {
    pub signature: String,
}

impl ShulginSignatureCompact {
    pub fn new(ed25519: ED25519Signature, sphincs: SPHINCSSignature) -> Self {
        let mut output: String = String::new();
        
        let delimiter = ":";

        let upper_ed25519_sig = ed25519.to_hex_string();
        let sphincs_sig_bs58 = sphincs.to_base58_string();

        output.push_str(&upper_ed25519_sig);
        output.push_str(delimiter);
        output.push_str(&sphincs_sig_bs58);

        return Self {
            signature: output
        }
    }
    pub fn as_string(&self) -> &str {
        &self.signature
    }
    pub fn to_string(&self) -> String {
        self.signature.clone()
    }
    pub fn from_str<T: AsRef<str>>(compact: T) -> Self {
        return Self {
            signature: compact.as_ref().to_string()
        }
    }
    pub fn into_shulginsignature(&self) -> Result<ShulginSignature, SlugErrors> {
        let manipulated_string = self.to_string();

        let keys: Vec<&str> = manipulated_string.split(":").collect();

        if keys.len() != 2 {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }

        let output_ed = ED25519Signature::from_hex_string(keys[0]);
        let output_sphincs = SPHINCSSignature::from_base58_string(keys[1]);

        if output_ed.is_err() {
            return Err(SlugErrors::VerifyingError(SlugErrorAlgorithms::SIG_ED25519))
        } 
        else if output_sphincs.is_err() {
            return Err(SlugErrors::VerifyingError(SlugErrorAlgorithms::SIG_SPHINCS_PLUS))
        }
        else {
            let output_sig_cl: ED25519Signature = ED25519Signature::from_bytes(&output_ed.unwrap())?;
            let output_sig_pq: SPHINCSSignature = SPHINCSSignature::from_bytes(&output_sphincs.unwrap())?;

            return Ok(ShulginSignature {
                clsig: output_sig_cl,
                pqsig: output_sig_pq,
        })
        }

    }
}

impl ShulginKeypair {
    pub fn add_secret(&mut self, ed25519secret: ED25519SecretKey, sphincssecret: SPHINCSSecretKey) {
        self.ed25519sk = Some(ed25519secret);
        self.sphincssk = Some(sphincssecret);
    }
    pub fn from_public_key(ed25519pk: ED25519PublicKey, sphincspk: SPHINCSPublicKey) -> Self {
        return Self {
            ed25519pk: ed25519pk,
            sphincspk: sphincspk,

            ed25519sk: None,
            sphincssk: None,
        }
    }
    pub fn generate() -> Self {
        let cl = ED25519SecretKey::generate();
        let clpk = cl.public_key().unwrap();
        let (pq_pk,pq_sk) = SPHINCSSecretKey::generate();

        return Self {
            ed25519pk: clpk,
            sphincspk: pq_pk,

            ed25519sk: Some(cl),
            sphincssk: Some(pq_sk)
        }
    }
    pub fn sign<T: AsRef<[u8]>>(&self, data: T) -> Result<ShulginSignature,SlugErrors> {
        if self.ed25519sk.is_some() && self.sphincssk.is_some() {
            let cl_sig = self.ed25519sk.clone().unwrap().sign(data.as_ref());
            let pq_sig = self.sphincssk.clone().unwrap().sign(data.as_ref());

            if cl_sig.is_err() || pq_sig.is_err() {
                return Err(SlugErrors::SigningFailure)
            }
            else {
                Ok(
                    ShulginSignature {
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
    pub fn verify<T: AsRef<[u8]>>(&self, data: T, signature: ShulginSignature) -> Result<bool,SlugErrors> {
        let cl_is_valid = self.ed25519pk.verify(signature.clsig.clone(),data.as_ref());
        let pq_is_valid = self.sphincspk.verify(data.as_ref(), signature.pqsig.clone());

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
    pub fn from_compact_pk<T: AsRef<str>>(pk: T) -> Result<ShulginKeypair, SlugErrors> {
        return from_public_key_compact(pk.as_ref())
    }
    pub fn from_compact_keypair<T: AsRef<str>>(pk: T, sk: T) -> Result<ShulginKeypair, SlugErrors> {
        let mut x = from_public_key_compact(pk.as_ref())?;
        let z = from_secret_key_compact(sk.as_ref())?;
        x.add_secret(z.0,z.1);

        return Ok(x)
    }
    pub fn into_compact(&self) -> Result<ShulginKeypairCompact,FromUtf8Error> {
        if self.ed25519sk.is_some() && self.sphincssk.is_some() {
            let pk = key_to_compact(&self)?;
            let sk = secret_key_to_compact(&self)?;

            return Ok(ShulginKeypairCompact {
                public_key: pk,
                secret_key: Some(sk)
            })
        }
        else {
            let pk = key_to_compact(&self)?;
            return Ok(ShulginKeypairCompact {
                public_key: pk,
                secret_key: None,
            })
        }
    }
    pub fn into_secret_pem(&self) -> Result<String,FromUtf8Error> {
        let x = Pem::new("SHULGINSIGNING-SECRET-KEY",self.into_compact()?.to_str_sk()).to_string();
        return Ok(x)
    }
    pub fn into_pem(&self) -> Result<String,FromUtf8Error> {
        let x = Pem::new("SHULGINSIGNING-PUBLIC-KEY", self.into_compact()?.to_str_pk()).to_string();
        return Ok(x)
    }
}

impl ShulginSignature {
    pub fn new(ed25519: ED25519Signature, sphincs: SPHINCSSignature) -> Self {
        return Self {
            clsig: ed25519,
            pqsig: sphincs,
        }
    }
    pub fn import(signature_compact: ShulginSignatureCompact) {
        return 
    }
    pub fn into_ss_format(&self) -> String {
        let mut output: String = String::new();
        
        let delimiter = ":";

        let upper_ed25519_sig = self.clsig.to_hex_string();
        let sphincs_sig_bs58 = self.pqsig.to_base58_string();

        output.push_str(&upper_ed25519_sig);
        output.push_str(delimiter);
        output.push_str(&sphincs_sig_bs58);

        return output
    }
    pub fn from_ss_format<T: AsRef<str>>(ss_format: T) -> Result<Self,SlugErrors> {
        let manipulated_string = ss_format.as_ref().to_string();

        let keys: Vec<&str> = manipulated_string.split(":").collect();

        if keys.len() != 2 {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }

        let output_ed = ED25519Signature::from_hex_string(keys[0]);
        let output_sphincs = SPHINCSSignature::from_base58_string(keys[1]);

        if output_ed.is_err() {
            return Err(SlugErrors::VerifyingError(SlugErrorAlgorithms::SIG_ED25519))
        } 
        else if output_sphincs.is_err() {
            return Err(SlugErrors::VerifyingError(SlugErrorAlgorithms::SIG_SPHINCS_PLUS))
        }
        else {
            let output_sig_cl: ED25519Signature = ED25519Signature::from_bytes(&output_ed.unwrap())?;
            let output_sig_pq: SPHINCSSignature = SPHINCSSignature::from_bytes(&output_sphincs.unwrap())?;

            return Ok(Self {
                clsig: output_sig_cl,
                pqsig: output_sig_pq,
        })
        }




    }
}

/// Naive Version Of ShulginSigning Compact Signature Verification
fn verify_signature_compact<T: AsRef<str>>(s: T) -> Result<bool,SlugErrors> {
    let manipulated_string = s.as_ref().to_string();

    let colon_count = manipulated_string.chars().filter(|c| *c == ':').count();

    if manipulated_string.contains(":") == true && colon_count == 1 {
        {
            let x: Vec<&str> = manipulated_string.split(":").collect();
            if x[0].len() != 128 {
                return Err(SlugErrors::Other(String::from("ED25519 Hexadecimal not equal to 128 chars.")))
            }
            else {
                return Ok(true)
            }
        }
    }
    else {
        return Err(SlugErrors::Other(String::from("Does Not Contain Colon Or Contains Too Many Colons")))
    }
}

fn key_to_compact(keypair: &ShulginKeypair) -> Result<String, FromUtf8Error> {
    let mut output: String = String::new();
    
    let delimiter = ":";
    
    let ed25519_pk = &keypair.ed25519pk;
    let sphincs_pk = &keypair.sphincspk;

    output.push_str(&ed25519_pk.to_hex_string());
    output.push_str(delimiter);
    output.push_str(&sphincs_pk.to_hex_string()?);

    return Ok(output)
}

fn from_public_key_compact<T: AsRef<str>>(ss_pk: T) -> Result<ShulginKeypair,SlugErrors> {
    let x = ss_pk.as_ref().to_string();

    let keys: Vec<&str> = x.split(":").collect();

    let hex_str = ED25519PublicKey::from_hex_string(keys[0]).unwrap();

    let mut byte_array: [u8;32] = [0u8;32];

    if hex_str.len() == 32 {
        byte_array.copy_from_slice(&hex_str)
    }

    if keys.len() == 2 {
        if keys[0].len() == 64 && keys[1].len() == 128 {
            return Ok(ShulginKeypair {
                ed25519pk: ED25519PublicKey::from_bytes(byte_array),
                sphincspk: SPHINCSPublicKey::from_hex_string_final(keys[1])?,

                sphincssk: None,
                ed25519sk: None,
            })
        }
        else {
            return Err(SlugErrors::Other(String::from("Error when compacting key for shulgin signing.")))
        }
    }
    else {
        return Err(SlugErrors::Other(String::from("Key Length Too High")))
    }

}

fn from_secret_key_compact<T: AsRef<str>>(ss_sk: T) -> Result<(ED25519SecretKey,SPHINCSSecretKey), SlugErrors> {
    let x = ss_sk.as_ref().to_string();

    let keys: Vec<&str> = x.split(":").collect();

    let hex_str = ED25519SecretKey::from_hex_string(keys[0]).unwrap();

    let mut byte_array: [u8;32] = [0u8;32];

    if hex_str.len() == 32 {
        byte_array.copy_from_slice(&hex_str)
    }

    if keys.len() == 2 {
        if keys[0].len() == 64 && keys[1].len() == 256 {
            return Ok((ED25519SecretKey::from_bytes(&byte_array).unwrap(),SPHINCSSecretKey::from_bytes(&SPHINCSSecretKey::from_hex_string(keys[1]).unwrap()).unwrap()))
        }
        else {
            return Err(SlugErrors::Other(String::from("Failed To Convert")))
        }
    }
    else {
        return Err(SlugErrors::Other(String::from("Failed To Convert")))
    }
}

fn secret_key_to_compact(keypair: &ShulginKeypair) -> Result<String, FromUtf8Error> {
    let mut output: String = String::new();
    
    let delimiter = ":";
    
    let ed25519_sk = keypair.ed25519sk.clone().unwrap();
    let sphincs_sk = keypair.sphincssk.clone().unwrap();

    output.push_str(&ed25519_sk.to_hex_string());
    output.push_str(delimiter);
    output.push_str(&sphincs_sk.to_hex_string()?);

    return Ok(output)
}

#[test]
fn run() {
    let keypair = ShulginKeypair::generate();
    let signature = keypair.sign("This message is being signed.").unwrap();


    let sig = signature.into_ss_format();

    let compact = ShulginKeypairCompact::from_pk(&keypair).unwrap();
    
    println!("{}",compact.as_str_pk())
}

#[test]
fn shulginsigning() {
    let keypair = ShulginKeypair::generate();
    let signature = keypair.sign("Data").unwrap();
    let compact = keypair.into_compact().unwrap();
    let pk_str = compact.as_str_pk();
    let sk_str = compact.to_str_sk();

    let pem = keypair.into_pem().unwrap();

    println!("PEM: {}", pem);

    println!("Public Key: {}",pk_str);
    println!("Secret Key: {}",sk_str.clone());

    let keypair2 = ShulginKeypair::from_compact_keypair(pk_str, &sk_str).unwrap();

    let is_valid = keypair2.verify("Data", signature).unwrap();

    println!("Is Valid: {}", is_valid);
}