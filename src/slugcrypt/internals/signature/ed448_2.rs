//! # Ed448
//! 
//! Secret Key Size: 57 Bytes

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

use crate::errors::SlugErrors;

pub const ED448_CONTEXT: &str = "libslug20";

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

impl Ed448SecretKey {
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
            unimplemented!()
        }

        let mut signature_output: [u8;114] = [0u8;114];
        signature_output.copy_from_slice(&x.unwrap().to_bytes());

        let signature = Ed448Signature {
            sig: signature_output,
            context: Some(context.as_ref().to_vec()),
        };

        return Ok(signature)
    }
    pub fn sign_without_context_attached<T: AsRef<[u8]>>(&self, msg: T, context: T) -> Result<Ed448Signature,SlugErrors> {
        let x: Result<ed448_goldilocks_plus::Signature, _> = self.into_usable_type().sign_ctx(context.as_ref(), msg.as_ref());

        if x.is_err() {
            return Err(SlugErrors::SigningFailure(crate::errors::SlugErrorAlgorithms::SIG_ED448))
        }
        else {
            unimplemented!()
        }

        let mut signature_output: [u8;114] = [0u8;114];
        signature_output.copy_from_slice(&x.unwrap().to_bytes());

        let signature = Ed448Signature {
            sig: signature_output,
            context: None,
        };

        return Ok(signature)
    }
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Result<Ed448Signature, SlugErrors>  {
        self.sign_with_context(msg.as_ref(), ED448_CONTEXT.as_bytes())
    }
}

impl Ed448PublicKey {
    pub fn into_usable_type(&self) -> Result<VerifyingKey,SlugErrors> {
        let x: Result<VerifyingKey, _> = VerifyingKey::from_bytes(&self.pk);

        if x.is_err() {
            return Err(SlugErrors::Other(String::from("Failed To Convert Into VerifyingKey Type")))
        }
        else {
            unimplemented!()
        }

        return Ok(x.unwrap())
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
}

impl Ed448Signature {
    pub fn into_usable_type(&self) -> Result<Signature, SlugErrors> {
        let sig: Result<Signature, SigningError> = Signature::from_bytes(&self.sig);

        if sig.is_err() {
            return Err(SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_ED448))
        }
        else {
            unimplemented!()
        }

        return Ok(sig.unwrap())
    }
}


#[test]
fn create() {
    let key = Ed448SecretKey::generate();
    let msg = "This is a message warning of the future... heed my warnings and serve allah...repent....repent...repent...icu...copper...mineshafts...like...outlast";
    let sig = key.sign_with_context(msg.as_bytes(), ED448_CONTEXT.as_bytes()).expect("Failed to receive");

    let result = key.into_public_key().verify(msg.as_bytes(), sig);
    assert_eq!(result.unwrap(),true);
}