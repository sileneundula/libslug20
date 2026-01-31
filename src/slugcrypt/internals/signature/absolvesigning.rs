//! # Absolve Keypair
//! 
//! MLDSA3 + ED25519

use crate::errors::SlugErrors;
use crate::slugcrypt::internals::signature::ed25519::{ED25519PublicKey,ED25519SecretKey,ED25519Signature};
use crate::slugcrypt::internals::signature::ml_dsa::{SlugMLDSA3,MLDSA3Keypair,MLDSA3PublicKey,MLDSA3SecretKey,MLDSA3Signature};
use serde::{Serialize,Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};

pub const ABSOLVE_CONTEXT: &str = "libslug20";


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