use serde::{Serialize,Deserialize};
use serde_big_array::BigArray;
use rsa::{RsaPublicKey, RsaPrivateKey};
use crate::errors::SlugErrors;
use crate::slugcrypt::traits::{FromBincode, IntoBincode};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop, PartialEq, PartialOrd, Hash)]
pub struct RSASecretKey2048 {
    #[serde(with = "BigArray")]
    pub key: [u8; 256],
}

#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop, PartialEq, PartialOrd, Hash)]
pub struct RSAPublicKey2048 {
    #[serde(with = "BigArray")]
    pub key: [u8; 256], 
}

#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop, PartialEq, PartialOrd, Hash)]
pub struct RSASignature {
    pub signature: Vec<u8>,
}

impl FromBincode for RSASecretKey2048 {
    fn from_bincode<T: AsRef<[u8]>>(bincode: T) -> Result<Self, SlugErrors> {
        let x = bincode::deserialize(bincode.as_ref())?;
        Ok(x)
    }
}

impl FromBincode for RSAPublicKey2048 {
    fn from_bincode<T: AsRef<[u8]>>(bincode: T) -> Result<Self, SlugErrors> {
        let x = bincode::deserialize(bincode.as_ref())?;
        Ok(x)
    }
}

impl FromBincode for RSASignature {
    fn from_bincode<T: AsRef<[u8]>>(bincode: T) -> Result<Self, SlugErrors> {
        let x = bincode::deserialize(bincode.as_ref())?;
        Ok(x)
    }
}