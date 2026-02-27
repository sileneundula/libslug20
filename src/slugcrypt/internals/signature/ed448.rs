use digest::Update;
use ed448_goldilocks_plus::{EdwardsPoint, CompressedEdwardsY, Scalar, elliptic_curve::hash2curve::ExpandMsgXof, sha3::Shake256};
use k256::elliptic_curve::PrimeField;
use rand::rngs::OsRng;
use tiny_keccak::Shake;

use serde::{Serialize,Deserialize};
use serde_big_array::BigArray;

#[derive(Clone, Debug, PartialEq, PartialOrd, Serialize, Deserialize, Hash)]
pub struct ED448PublicKey(#[serde(with = "BigArray")]pub [u8;57]);

#[derive(Clone, Debug, PartialEq, PartialOrd, Serialize, Deserialize, Hash)]

pub struct ED448SecretKey(#[serde(with = "BigArray")]pub  [u8;56]);
#[derive(Clone, Debug, PartialEq, PartialOrd, Serialize, Deserialize, Hash)]

pub struct ED448Signature(#[serde(with = "BigArray")]pub [u8;114]);

impl ED448SecretKey {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let secret_key = Scalar::random(&mut rng);
        return Self(secret_key.to_bytes())
    }
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Scalar {
        let mut hasher = Shake256::default();
        hasher.update(&self.0);
        
        let mut signer = self.to_usable_type();

        let r_scalar = Scalar::hash(msg, dst)

        signer.multiply(Scalar::MULTIPLICATIVE_GENERATOR);

        let hashed_scalar = Scalar::hash::<ExpandMsgXof<Shake256>>(msg.as_ref(), b"edwards448_XOF:SHAKE256_ELL2_RO_");

        let hashed_point = EdwardsPoint::hash::<ExpandMsgXof<Shake256>>(b"test", b"edwards448_XOF:SHAKE256_ELL2_RO_");

        return hashed_scalar
    }
    pub fn as_bytes(&self) -> &[u8] {
        return &self.0
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        return self.0.to_vec()
    }
    pub fn to_byte_array(&self) -> [u8;56] {
        return self.0
    }
    pub fn public_key(&self) -> ED448PublicKey {
        let pk = EdwardsPoint::GENERATOR * &self.to_usable_type();
        let pk_compressed = pk.compress();
        let pk_bytes = pk_compressed.as_bytes();
        return ED448PublicKey(pk_bytes.to_owned())
    }
    pub fn to_usable_type(&self) -> Scalar {
        return Scalar::from_bytes(&self.0)
    }
}

impl ED448PublicKey {
    pub fn to_usable_type(&self) -> CompressedEdwardsY {
        CompressedEdwardsY(self.0)
    }
    pub fn decompress(&self) -> subtle::CtOption<EdwardsPoint> {
        let output: subtle::CtOption<EdwardsPoint> = self.to_usable_type().decompress();
        return output
    }
}