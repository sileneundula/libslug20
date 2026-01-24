//! # BLS Signatures
//!
//! BLS signatures wrapper for libslug using the `bls-signatures` crate.
//! Provides generation, signing, verification, zeroize and common encodings.
//!
//! Note: This file follows the style used for ED25519 and Falcon implementations.
//! 
//! Made with chatgpt and human review.
//! 
//! ## TODO:
//! 
//! - [ ] Tests
//! - [ ] Refactor
//! - [ ] Examples
//! - [ ] Verify it works correctly with other BLS implementations.
use bls_signatures::Serialize as BLSSerialize;
use pem::Pem;
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde_big_array::BigArray;
use slugencode::{SlugEncodingUsage, SlugEncodings, errors::SlugEncodingError};
use crate::errors::SlugErrors;
use rand::rngs::OsRng;




pub mod protocol_info {
    pub const PROTOCOL_NAME: &str = "libslug20/bls12-381";
    // Common BLS12-381 sizes (compressed forms):
    pub const BLS_PK_SIZE: usize = 48;
    pub const BLS_SK_SIZE: usize = 32;
    pub const BLS_SIG_SIZE: usize = 96;
    pub const SOURCE_LIBRARY: &str = "bls-signatures";
    pub const ENCODINGS: [&str;6] = ["Hexadecimal (Upper)","Base32 (Crockford)","Base58","PEM","Base64","Base64 URL Safe"];
    pub const SIGNATURE_ALGORITHM: &str = "BLS12-381";
    pub const RANDOMNESS: [&str;1] = ["Operating-System CSPRNG"];
    pub const CSUITE: &str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    pub const FEATURES: [&str;3] = ["Aggregate Signatures","Fast Verification","Deterministic Signing"];
}

impl BLSSignature {
    /// Aggregate multiple BLS signatures into a single signature.
    pub fn aggregate(signatures: &[BLSSignature]) -> Result<BLSSignature, SlugErrors> {
        let mut sigs = Vec::with_capacity(signatures.len());
        for s in signatures {
            let s0 = bls_signatures::Signature::from_bytes(&s.signature)
                .map_err(|_| SlugErrors::SigningFailure(crate::errors::SlugErrorAlgorithms::SIG_BLS))?;
            sigs.push(s0);
        }
        let agg = bls_signatures::aggregate(&sigs)
            .map_err(|_| SlugErrors::SigningFailure(crate::errors::SlugErrorAlgorithms::SIG_BLS))?;
        let bytes = agg.as_bytes();
        if bytes.len() != protocol_info::BLS_SIG_SIZE {
            return Err(SlugErrors::SigningFailure(crate::errors::SlugErrorAlgorithms::SIG_BLS));
        }
        let mut out = [0u8; protocol_info::BLS_SIG_SIZE];
        out.copy_from_slice(&bytes);
        Ok(BLSSignature { signature: out })
    }
}

/*
impl BLSPublicKey {
    /*
    pub fn aggregate(pubkeys: &[BLSPublicKey]) -> Result<BLSPublicKey, SlugErrors> {
        let mut pks = Vec::with_capacity(pubkeys.len());
        for pk in pubkeys {
            let pk0 = bls_signatures::PublicKey::from_bytes(&pk.pk)
                .map_err(|_| SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_BLS))?;
            pks.push(pk0);
        }
        let agg = bls_signatures::aggregate(&pks)
            .map_err(|_| SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_BLS))?;
        let bytes = agg.as_bytes();
        if bytes.len() != protocol_info::BLS_PK_SIZE {
            return Err(SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_BLS));
        }
        let mut out = [0u8; protocol_info::BLS_PK_SIZE];
        out.copy_from_slice(bytes);
        Ok(BLSPublicKey { pk: out })
    }
    */
/*
    /// Verify an aggregated signature created for the same message by aggregating signatures from multiple signers.
    pub fn verify_aggregated_same_message<T: AsRef<[u8]>>(
        pubkeys: &[BLSPublicKey],
        message: T,
        aggregate_signature: &BLSSignature,
    ) -> Result<bool, SlugErrors> {
        // Aggregate public keys then verify the aggregate signature against the single message.
        let pk = bls_signatures::PublicKey::from_bytes(&agg_pk.pk)
            .map_err(|_| SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_BLS))?;
        let sig = bls_signatures::Signature::from_bytes(&aggregate_signature.signature)
            .map_err(|_| SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_BLS))?;
        Ok(pk.verify(sig, message.as_ref()))
    }

    /// Verify an aggregated signature over multiple distinct messages (one per public key).
    ///
    /// messages must have the same length and ordering as pubkeys.
    pub fn verify_aggregated_multiple_messages<T: AsRef<[u8]>>(
        pubkeys: &[BLSPublicKey],
        messages: &[T],
        aggregate_signature: &BLSSignature,
    ) -> Result<bool, SlugErrors> {
        if pubkeys.len() != messages.len() || pubkeys.is_empty() {
            return Err(SlugErrors::InvalidLengthFromBytes);
        }

        let mut pks = Vec::with_capacity(pubkeys.len());
        for pk in pubkeys {
            let pk0 = bls_signatures::PublicKey::from_bytes(&pk.pk)
                .map_err(|_| SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_BLS))?;
            pks.push(pk0);
        }

        // Convert messages to slice-of-slices
        let msg_slices: Vec<&[u8]> = messages.iter().map(|m| m.as_ref()).collect();

        let sig = bls_signatures::Signature::from_bytes(&aggregate_signature.signature)
            .map_err(|_| SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_BLS))?;

        // Use the bls-signatures crate helper for multi-message aggregate verification.
        // Expected signature: bls_signatures::verify_messages(&[&[u8]], &[PublicKey], &Signature) -> bool
        // Map any false/true into Result accordingly.
        let ok = bls_signatures::verify_messages(&msg_slices, &pks, &sig);
        Ok(ok)
    }
    */
}
*/
#[derive(Debug, Zeroize, ZeroizeOnDrop, Serialize, Deserialize, Clone, PartialEq, Hash)]
pub struct BLSSecretKey {
    #[serde(with = "BigArray")]
    sk: [u8; protocol_info::BLS_SK_SIZE],
}

#[derive(Debug, Zeroize, ZeroizeOnDrop, Serialize, Deserialize, Clone, PartialEq, Hash)]
pub struct BLSPublicKey {
    #[serde(with = "BigArray")]
    pk: [u8; protocol_info::BLS_PK_SIZE],
}

#[derive(Debug, Zeroize, ZeroizeOnDrop, Serialize, Deserialize, Clone, PartialEq, Hash)]
pub struct BLSSignature {
    #[serde(with = "BigArray")]
    signature: [u8; protocol_info::BLS_SIG_SIZE],
}

pub struct SlugBLS;

impl SlugBLS {
    /// Generate a new keypair using OS randomness.
    pub fn generate() -> (BLSPublicKey, BLSSecretKey) {
        // Using `bls-signatures` crate API expectations:
        // PrivateKey::generate(&mut OsRng) -> PrivateKey
        // private_key.as_bytes()/to_bytes() and public_key.as_bytes()/to_bytes()
        // signature.as_bytes()
        //
        // The exact crate API may differ; this wrapper follows a typical pattern.
        let mut rng = OsRng {};
        let sk = bls_signatures::PrivateKey::generate(&mut rng);
        let pk = sk.public_key();

        let sk_bytes = sk.as_bytes();
        let pk_bytes = pk.as_bytes();

        let mut sk_array = [0u8; protocol_info::BLS_SK_SIZE];
        let mut pk_array = [0u8; protocol_info::BLS_PK_SIZE];

        sk_array.copy_from_slice(&sk_bytes[..protocol_info::BLS_SK_SIZE]);
        pk_array.copy_from_slice(&pk_bytes[..protocol_info::BLS_PK_SIZE]);

        (BLSPublicKey { pk: pk_array }, BLSSecretKey { sk: sk_array })
    }
}

impl BLSSecretKey {
    pub fn generate() -> Self {
        let mut rng = OsRng {};
        let sk = bls_signatures::PrivateKey::generate(&mut rng);
        let sk_bytes = sk.as_bytes();

        let mut sk_array = [0u8; protocol_info::BLS_SK_SIZE];
        sk_array.copy_from_slice(&sk_bytes[..protocol_info::BLS_SK_SIZE]);

        Self { sk: sk_array }
    }
    /// Sign a message (detached) and return BLSSignature.
    pub fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<BLSSignature, SlugErrors> {
        let sk = bls_signatures::PrivateKey::from_bytes(&self.sk)
            .map_err(|_| SlugErrors::SigningFailure(crate::errors::SlugErrorAlgorithms::SIG_BLS))?;
        let sig = sk.sign(message.as_ref());

        let sig_bytes = sig.as_bytes();
        let mut sig_array = [0u8; protocol_info::BLS_SIG_SIZE];
        if sig_bytes.len() != protocol_info::BLS_SIG_SIZE {
            return Err(SlugErrors::SigningFailure(crate::errors::SlugErrorAlgorithms::SIG_BLS));
        }
        sig_array.copy_from_slice(&sig_bytes);

        Ok(BLSSignature { signature: sig_array })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.sk
    }
    pub fn to_bytes(&self) -> [u8; protocol_info::BLS_SK_SIZE] {
        self.sk
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.sk.to_vec()
    }
    pub fn to_hex(&self) -> Result<String, SlugEncodingError> {
        SlugEncodingUsage::new(SlugEncodings::Hex).encode(&self.sk)
    }
    pub fn to_base32(&self) -> Result<String, SlugEncodingError> {
        SlugEncodingUsage::new(SlugEncodings::Base32).encode(&self.sk)
    }
    pub fn to_base32_unpadded(&self) -> Result<String, SlugEncodingError> {
        SlugEncodingUsage::new(SlugEncodings::Base32unpadded).encode(&self.sk)
    }
    pub fn to_base58(&self) -> Result<String, SlugEncodingError> {
        SlugEncodingUsage::new(SlugEncodings::Base58).encode(&self.sk)
    }
    pub fn to_base64(&self) -> Result<String, SlugEncodingError> {
        SlugEncodingUsage::new(SlugEncodings::Base64).encode(&self.sk)
    }
    pub fn to_base64_url_safe(&self) -> Result<String, SlugEncodingError> {
        SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).encode(&self.sk)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlugErrors> {
        if bytes.len() != protocol_info::BLS_SK_SIZE {
            return Err(SlugErrors::InvalidLengthFromBytes);
        }
        let mut sk_array = [0u8; protocol_info::BLS_SK_SIZE];
        sk_array.copy_from_slice(bytes);
        Ok(Self { sk: sk_array })
    }
    pub fn from_hex<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let decoder = SlugEncodingUsage::new(SlugEncodings::Hex);
        let bytes = decoder.decode(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        Self::from_bytes(&bytes)
    }
    pub fn from_base32<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let decoder = SlugEncodingUsage::new(SlugEncodings::Base32);
        let bytes = decoder.decode(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        Self::from_bytes(&bytes)
    }
    pub fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let decoder = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let bytes = decoder.decode(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        Self::from_bytes(&bytes)
    }
    pub fn from_base58<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let decoder = SlugEncodingUsage::new(SlugEncodings::Base58);
        let bytes = decoder.decode(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        Self::from_bytes(&bytes)
    }
    pub fn from_base64<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let decoder = SlugEncodingUsage::new(SlugEncodings::Base64);
        let bytes = decoder.decode(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        Self::from_bytes(&bytes)
    }
    pub fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let decoder = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let bytes = decoder.decode(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        Self::from_bytes(&bytes)
    }
    pub fn to_pem(&self) -> String {
        let pem = Pem::new("BLS PRIVATE KEY", self.as_bytes());
        return pem.to_string()
    }
    pub fn from_pem<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let pem = pem::parse(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        if pem.tag() != "BLS PRIVATE KEY" {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
        Ok(Self::from_bytes(&pem.contents())?)
    }
}

impl BLSPublicKey {
    pub fn verify<T: AsRef<[u8]>>(&self, message: T, signature: &BLSSignature) -> Result<bool, SlugErrors> {
        let pk = Self::to_usable_types(&self)?;

        let sig = bls_signatures::Signature::from_bytes(&signature.signature).map_err(|_| SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_BLS))?;
        let ok = pk.verify(sig, message.as_ref());
        Ok(ok)
    }
    pub fn to_usable_types(&self) -> Result<bls_signatures::PublicKey, SlugErrors> {
        let pk = bls_signatures::PublicKey::from_bytes(&self.pk)
            .map_err(|_| SlugErrors::VerifyingError(crate::errors::SlugErrorAlgorithms::SIG_BLS))?;
        Ok(pk)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.pk
    }
    pub fn to_hex(&self) -> Result<String, SlugEncodingError> {
        SlugEncodingUsage::new(SlugEncodings::Hex).encode(&self.pk)
    }
    pub fn to_base32(&self) -> Result<String, SlugEncodingError> {
        SlugEncodingUsage::new(SlugEncodings::Base32).encode(&self.pk)
    }
    pub fn to_base32_unpadded(&self) -> Result<String, SlugEncodingError> {
        SlugEncodingUsage::new(SlugEncodings::Base32unpadded).encode(&self.pk)
    }
    pub fn to_base58(&self) -> Result<String, SlugEncodingError> {
        SlugEncodingUsage::new(SlugEncodings::Base58).encode(&self.pk)
    }
    pub fn to_base64(&self) -> Result<String, SlugEncodingError> {
        SlugEncodingUsage::new(SlugEncodings::Base64).encode(&self.pk)
    }
    pub fn to_base64_url_safe(&self) -> Result<String, SlugEncodingError> {
        SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).encode(&self.pk)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlugErrors> {
        if bytes.len() != protocol_info::BLS_PK_SIZE {
            return Err(SlugErrors::InvalidLengthFromBytes);
        }
        let mut pk_array = [0u8; protocol_info::BLS_PK_SIZE];
        pk_array.copy_from_slice(bytes);
        Ok(Self { pk: pk_array })
    }
    pub fn to_pem(&self) -> String {
        let pem = Pem::new("BLS PUBLIC KEY", self.as_bytes());
        return pem.to_string()
    }
    pub fn from_pem<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let pem = pem::parse(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        if pem.tag() != "BLS PUBLIC KEY" {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
        Ok(Self::from_bytes(&pem.contents())?)
    }
        pub fn from_hex<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let decoder = SlugEncodingUsage::new(SlugEncodings::Hex);
        let bytes = decoder.decode(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        Self::from_bytes(&bytes)
    }
    pub fn from_base32<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let decoder = SlugEncodingUsage::new(SlugEncodings::Base32);
        let bytes = decoder.decode(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        Self::from_bytes(&bytes)
    }
    pub fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let decoder = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let bytes = decoder.decode(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        Self::from_bytes(&bytes)
    }
    pub fn from_base58<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let decoder = SlugEncodingUsage::new(SlugEncodings::Base58);
        let bytes = decoder.decode(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        Self::from_bytes(&bytes)
    }
    pub fn from_base64<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let decoder = SlugEncodingUsage::new(SlugEncodings::Base64);
        let bytes = decoder.decode(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        Self::from_bytes(&bytes)
    }
    pub fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let decoder = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let bytes = decoder.decode(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        Self::from_bytes(&bytes)
    }
}

impl BLSSignature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.signature
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlugErrors> {
        if bytes.len() != protocol_info::BLS_SIG_SIZE {
            return Err(SlugErrors::InvalidLengthFromBytes);
        }
        let mut sig_array = [0u8; protocol_info::BLS_SIG_SIZE];
        sig_array.copy_from_slice(bytes);
        Ok(Self { signature: sig_array })
    }
    pub fn from_hex<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let decoder = SlugEncodingUsage::new(SlugEncodings::Hex);
        let bytes = decoder.decode(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        Self::from_bytes(&bytes)
    }
    pub fn from_base32<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let decoder = SlugEncodingUsage::new(SlugEncodings::Base32);
        let bytes = decoder.decode(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        Self::from_bytes(&bytes)
    }
    pub fn from_base32_unpadded<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let decoder = SlugEncodingUsage::new(SlugEncodings::Base32unpadded);
        let bytes = decoder.decode(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        Self::from_bytes(&bytes)
    }
    pub fn from_base58<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let decoder = SlugEncodingUsage::new(SlugEncodings::Base58);
        let bytes = decoder.decode(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        Self::from_bytes(&bytes)
    }
    pub fn from_base64<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let decoder = SlugEncodingUsage::new(SlugEncodings::Base64);
        let bytes = decoder.decode(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        Self::from_bytes(&bytes)
    }
    pub fn from_base64_url_safe<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let decoder = SlugEncodingUsage::new(SlugEncodings::Base64urlsafe);
        let bytes = decoder.decode(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        Self::from_bytes(&bytes)
    }
    pub fn to_hex(&self) -> Result<String, SlugEncodingError> {
        SlugEncodingUsage::new(SlugEncodings::Hex).encode(&self.signature)
    }
    pub fn to_base32(&self) -> Result<String, SlugEncodingError> {
        SlugEncodingUsage::new(SlugEncodings::Base32).encode(&self.signature)
    }
    pub fn to_base32_unpadded(&self) -> Result<String, SlugEncodingError> {
        SlugEncodingUsage::new(SlugEncodings::Base32unpadded).encode(&self.signature)
    }
    pub fn to_base58(&self) -> Result<String, SlugEncodingError> {
        SlugEncodingUsage::new(SlugEncodings::Base58).encode(&self.signature)
    }
    pub fn to_base64(&self) -> Result<String, SlugEncodingError> {
        SlugEncodingUsage::new(SlugEncodings::Base64).encode(&self.signature)
    }
    pub fn to_base64_url_safe(&self) -> Result<String, SlugEncodingError> {
        SlugEncodingUsage::new(SlugEncodings::Base64urlsafe).encode(&self.signature)
    }
}


impl BLSSignature {
    pub fn to_pem(&self) -> String {
        let pem = Pem::new("BLS SIGNATURE", self.as_bytes());
        return pem.to_string()
    }
    pub fn from_pem<T: AsRef<str>>(s: T) -> Result<Self, SlugErrors> {
        let pem = pem::parse(s.as_ref()).map_err(|_| SlugErrors::InvalidLengthFromBytes)?;
        if pem.tag() != "BLS SIGNATURE" {
            return Err(SlugErrors::InvalidLengthFromBytes)
        }
        Ok(Self::from_bytes(&pem.contents())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bls_roundtrip_sign_verify() {
        let (pk, sk) = SlugBLS::generate();
        let msg = b"test message";
        let sig = sk.sign(msg).expect("sign");
        let ok = pk.verify(msg, &sig).expect("verify");
        assert!(ok);
    }
}