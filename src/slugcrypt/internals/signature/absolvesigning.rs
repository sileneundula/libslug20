//! # Absolve Keypair
//! 
//! MLDSA3 + ED25519
//! 
//! ## X59
//! 
//! Format should be `public key` + `:` + `public key` + `/` + `sk` + `:` + `sk_pq`
//! 
//! **Absolve Context:** `libslug20`
//! 
//! ## Features
//! 
//! - [ ] Encoding
//!     - [X] X59 Format
//!         - [X] Public Key
//!             - [X] To X59 Format
//!             - [X] From X59 Format
//!             - [X] X59 Metadata
//!         - [ ] Secret Key
//!         - [ ] Signature

use crate::errors::SlugErrors;
use crate::slugcrypt::internals::signature::ed25519::{ED25519PublicKey,ED25519SecretKey,ED25519Signature};
use crate::slugcrypt::internals::signature::ml_dsa::{SlugMLDSA3,MLDSA3Keypair,MLDSA3PublicKey,MLDSA3SecretKey,MLDSA3Signature};
use serde::{Serialize,Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};

pub const ABSOLVE_CONTEXT: &str = "libslug20";

use crate::slugcrypt::traits::{IntoPemPublic,IntoPemSecret, IntoPemSignature};
use crate::slugcrypt::traits::IntoPem;
use crate::slugcrypt::traits::{IntoX59PublicKey,IntoX59SecretKey,IntoX59Signature};
use crate::slugcrypt::traits::{FromEncoding,IntoEncoding};
use crate::errors::{SlugErrorAlgorithms,EncodingError};


/// # AbsolveKeypair
/// 
/// ML-DSA3 + ED25519
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Zeroize, ZeroizeOnDrop)]
pub struct AbsolveKeypair {
    pub ed25519pk: ED25519PublicKey,
    pub mldsa3pk: MLDSA3PublicKey,

    pub ed25519sk: Option<ED25519SecretKey>,
    pub mldsa3sk: Option<MLDSA3SecretKey>, 
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Zeroize, ZeroizeOnDrop)]
pub struct AbsolveSignature {
    pub ed25519sig: ED25519Signature,
    pub mldsa3sig: MLDSA3Signature,
    pub context: Vec<u8>,
}

impl AbsolveKeypair {
    /// # Generate Absolve Keypair
    /// 
    /// MLDSA3 + ED25519
    pub fn generate() -> Self {
        let ed25519_sk = ED25519SecretKey::generate();
        let ed25519_pk = ed25519_sk.public_key().unwrap();

        let mldsa_keypair = SlugMLDSA3::generate();
        let mldsa_pk = mldsa_keypair.public_key();
        let mldsa_sk = mldsa_keypair.secret_key();

        
        Self {
            ed25519pk: ed25519_pk,
            mldsa3pk: mldsa_pk.to_owned(),
            ed25519sk: Some(ed25519_sk),
            mldsa3sk: Some(mldsa_sk.to_owned())
        }
    }
    pub fn sign_with_context<T: AsRef<[u8]>>(&self, msg: T, context: T) -> Result<AbsolveSignature,SlugErrors> {
        if self.ed25519sk.is_some() == true && self.mldsa3sk.is_some() == true {
            let sig = self.ed25519sk.clone().unwrap().sign(msg.as_ref())?;
            let sig_mldsa = self.mldsa3sk.clone().unwrap().sign(msg.as_ref(),context.as_ref())?;

            return Ok(AbsolveSignature { ed25519sig: sig.to_owned(), mldsa3sig: sig_mldsa.to_owned(), context: context.as_ref().to_vec() })
        }
        else {
            return Err(SlugErrors::SigningFailure(crate::errors::SlugErrorAlgorithms::SIG_ABSOLVESIGNING))
        }
    }
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Result<AbsolveSignature,SlugErrors> {
        return self.sign_with_context(msg.as_ref(), ABSOLVE_CONTEXT.as_bytes())
    }
    pub fn verify<T: AsRef<[u8]>>(&self, msg: T, signature: AbsolveSignature) -> Result<bool,SlugErrors> {
        let is_valid = self.ed25519pk.verify(signature.ed25519sig.clone(), msg.as_ref())?;
        let is_valid_pq = self.mldsa3pk.verify(msg.as_ref(), signature.context.as_slice(), &signature.mldsa3sig)?;

        if is_valid == true && is_valid_pq == true {
            return Ok(true)
        }
        else if is_valid == true && is_valid_pq == false {
            return Ok(false)
        }
        else if is_valid == false && is_valid_pq == true {
            return Ok(false)
        }
        else if is_valid == false && is_valid_pq == false {
            return Ok(false)
        }
        else {
            return Err(SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_ABSOLVESIGNING))
        }
    }
}

impl IntoX59PublicKey for AbsolveKeypair {
    fn into_x59_pk(&self) -> Result<String,SlugErrors> {
        let classical_ed25519 = self.ed25519pk.to_hexadecimal()?;
        let pq_mldsa = self.mldsa3pk.to_hex()?;

        let mut output: String = String::new();
        output.push_str(&classical_ed25519);
        output.push_str(":");
        output.push_str(&pq_mldsa);

        return Ok(output)
    }
    /// # From X59 Public Key (AbsolveSigning: MLDSA3 + ED25519)
    /// 
    /// Format: `ED25519PK (hex)` + `:` + `ML-DSA3 (hex)`
    fn from_x59_pk<T: AsRef<str>>(x59_encoded: T) -> Result<Self,SlugErrors> {
        let input = x59_encoded.as_ref();
        let keys = input.split_once(":");

        if keys.is_some() {
            let ed25519 = keys.unwrap().0;
            let mldsa = keys.unwrap().1;

            let output_1 = ED25519PublicKey::from_hex(ed25519)?;
            let output_2= MLDSA3PublicKey::from_hex(mldsa)?;

            return Ok(Self {
                ed25519pk: output_1,
                mldsa3pk: output_2,

                ed25519sk: None,
                mldsa3sk: None,
            })
        }
        else {
            return Err(SlugErrors::DecodingError { alg: SlugErrorAlgorithms::SIG_MLDSA, encoding: EncodingError::X59_fmt, other: None })
        }
    }
    /// # Return X59 Metadata
    /// 
    /// X59 metadata: `libslug20/AbsolveSigning`
    fn x59_metadata_pk() -> String {
        String::from("libslug20/AbsolveSigning")
    }
}

impl IntoX59SecretKey for AbsolveKeypair {
    fn into_x59(&self) -> Result<String,SlugErrors> {
        let classical_key_pk = self.ed25519pk.to_hexadecimal()?;
        let mldsa_pk = self.mldsa3pk.to_hex()?;


        if self.ed25519sk.is_some() && self.mldsa3sk.is_some() {
            let classical_key_sk = self.ed25519sk.unwrap().to_hexadecimal()?;
            let mldsa_sk = self.mldsa3sk.unwrap().to_hex()?;

            let mut output = String::new();
            output.push_str(&classical_key_pk);
            output.push_str(":");
            output.push_str(&mldsa_pk);
            output.push_str("/");
            output.push_str(&classical_key_sk);
            output.push_str(":");
            output.push_str(&mldsa_sk);

            return Ok(output)
        }
        else {
            return Err(SlugErrors::Other(String::from("No Secret Key For AbsolveSigning (ML-DSA3 + ED25519)")))
        }

    }
    fn from_x59<T: AsRef<str>>(x59_encoded_secret_key: T) -> Result<Self,SlugErrors> {
        let x = x59_encoded_secret_key.as_ref();
        let output = x.split_once("/");

        if output.is_some() {
            let (pk, sk) = output.unwrap();
            let pk_output = pk.split_once(":");
            let sk_output = sk.split_once(":");

            if pk_output.is_some() && sk_output.is_some() {
                let (ed25519pk, mldsa3pk) = pk_output.unwrap();
                let (ed25519sk, mldsa3sk) = pk_output.unwrap();

                let output_ed25519_pk = ED25519PublicKey::from_hex(ed25519pk)?;
                let output_mldsa3_pk = MLDSA3PublicKey::from_hex(mldsa3pk)?;

                let output_ed25519_sk = ED25519SecretKey::from_hex(ed25519sk)?;
                let output_mldsa3_sk = MLDSA3SecretKey::from_hex(mldsa3sk)?;

                return Ok(Self {
                    ed25519pk: output_ed25519_pk,
                    mldsa3pk: output_mldsa3_pk,
                    ed25519sk: Some(output_ed25519_sk),
                    mldsa3sk: Some(output_mldsa3_sk),
                })
            }
            else {
                return Err(SlugErrors::DecodingError { alg: SlugErrorAlgorithms::SIG_ABSOLVESIGNING, encoding: EncodingError::X59_fmt, other: None })
            }
        }
        else {
            return Err(SlugErrors::DecodingError { alg: SlugErrorAlgorithms::SIG_ABSOLVESIGNING, encoding: EncodingError::X59_fmt, other: None })
        }


    }
    fn x59_metadata() -> String {
        String::from("libslug20/AbsolveSigning")
    }
}

impl IntoX59Signature for AbsolveSignature {
    fn into_x59(&self) -> Result<String,SlugErrors> {
        let ed25519sig = self.ed25519sig.to_hexadecimal()?;
        let mldsa3sig = self.mldsa3sig.to_hex()?;

        let context_encoder = slugencode::SlugEncodingUsage::new(slugencode::SlugEncodings::Hex);

        let context_as_hex = context_encoder.encode(&self.context)?;

        let mut output = String::new();

        output.push_str(&ed25519sig);
        output.push_str(":");
        output.push_str(&mldsa3sig);
        output.push_str("/");
        output.push_str(&context_as_hex);

        return Ok(output)
        

    }
    fn from_x59<T: AsRef<str>>(x59_encoded_signature: T) -> Result<Self,SlugErrors> {
        let x = x59_encoded_signature.as_ref();

        let y = x.split_once(":");
        if y.is_some() {
            let sig = y.unwrap();
            let ed25519_sig = sig.0;

            let output = sig.1;
            let mldsa3 = output.split_once("/");

            if mldsa3.is_some() {
                let (mldsa3sig, context) = mldsa3.unwrap();

                let output_mldsa3_sig = MLDSA3Signature::from_hex(mldsa3sig)?;
                let output_ed25519_sig = ED25519Signature::from_hex(output)?;
                let encoder = slugencode::SlugEncodingUsage::new(slugencode::SlugEncodings::Hex);
                let output_context_sig = encoder.decode(context)?;

                return Ok(Self {
                    mldsa3sig: output_mldsa3_sig,
                    ed25519sig: output_ed25519_sig,
                    context: output_context_sig,
                })
            }
            else {
                return Err(SlugErrors::DecodingError { alg: SlugErrorAlgorithms::SIG_ABSOLVESIGNING, encoding: EncodingError::X59_fmt, other: None })
            }
        }
        else {
            return Err(SlugErrors::DecodingError { alg: SlugErrorAlgorithms::SIG_ABSOLVESIGNING, encoding: EncodingError::X59_fmt, other: None })
        }
        
    }
    fn x59_metadata() -> String {
        String::from("libslug20/AbsolveSigning")
    }
}