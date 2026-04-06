//! # oint-keys: A Standardized Library For Cryptographic Utility
//! 
//! ## Cipher Suite
//! 
//! - [ ] slug20
//!     - [ ] Hybrid
//!         - [ ] `slug20_shulginsignature`
//!         - [ ] `slug20_esphandsignature`
//!         - [ ] `slug20_absolvesignature`
//!     - [ ] Classical
//!         - [ ] `slug20_ed25519`
//!         - [ ] `slug20_ed448`
//!         - [ ] `slug20_ecdsa_secp256k1`
//!         - [ ] `slug20_bls12-381
//!     - [ ] Post-Quantum
//!         - [ ] `slug20_falcon1024`
//!         - [ ] `slug20_sphincs_plus`
//!         - [ ] `slug20_mldsa`
//! 
//! ## TODO:
//! 
//! - [ ] Implement Key Encodings
//! - [ ] Implement Key Decodings
//! 

pub mod Liberato {
    //! # Liberato Keypair: A Unified Interface for Cryptographic Key Management
    //! 
    //! ## Algorithms Supported
    //! 
    //! ### Hybrid Algorithms
    //! 
    //! - [X] ShulginSigning
    //! - [X] EsphandSigning
    //! - [X] AbsolveSigning
    //! 
    //! ### Classical
    //! 
    //! - [X] EdDSA
    //!    - [X] ED25519
    //!    - [X] ED448
    //! - [X] ECDSA
    //!   - [X] Secp256k1
    //! - [X] Schnorr Over Ristretto
    //! - [X] BLS12-381
    //! 
    //! ## Post-Quantum
    //! 
    //! - [X] Falcon1024
    //! - [X] SPHINCS+
    //! - [X] MLDSA3
    use std::str::FromStr;

    use fixedstr::str256;
    use libslug::errors::SlugErrors;
    use libslug::slugcrypt::internals::signature::absolvesigning::AbsolveKeypair;
    use libslug::slugcrypt::internals::signature::bls::{BLSPublicKey, BLSSecretKey, SlugBLS};
    use libslug::slugcrypt::internals::signature::ecdsa::{ECDSAPublicKey, ECDSASecretKey};
    use libslug::slugcrypt::internals::signature::ed448::{Ed448PublicKey, Ed448SecretKey};
    use libslug::slugcrypt::internals::signature::ed25519::{ED25519PublicKey, ED25519SecretKey};
    use libslug::slugcrypt::internals::signature::esphand_signature::EsphandKeypair;
    use libslug::slugcrypt::internals::signature::falcon::{Falcon1024PublicKey, SlugFalcon1024};
    use libslug::slugcrypt::internals::signature::ml_dsa::{MLDSA3Keypair, MLDSA3PublicKey, SlugMLDSA3};
    use libslug::slugcrypt::internals::signature::schnorr::{SchnorrPublicKey, SchnorrSecretKey};
    use libslug::slugcrypt::internals::signature::shulginsigning::ShulginKeypair;
    use libslug::slugcrypt::internals::signature::sphincs_plus::{SPHINCSPublicKey, SPHINCSSecretKey};
    use libslug::slugcrypt::traits::{FromEncoding, IntoEncoding, IntoX59PublicKey};
    use zeroize::{Zeroize,ZeroizeOnDrop};
    use serde::{Serialize,Deserialize};
    use crate::algorithms::slug::{SlugPublicKey,SlugSecretKey,SlugSignature};
    use crate::algorithms::slug::Algorithms;
    
    
    use crate::traits::liberato_key_traits::{FromX59, IntoX59, LiberatoKeypairTrait};
    use crate::traits::liberato_key_traits::{LiberatoSigning,LiberatoVerification};

    use crate::traits::liberato_key_traits::{IntoEncodingPublicKey,IntoEncodingKeypair,IntoEncodingSecretKey,IntoEncodingSignature};

    use crate::constants::*;

    pub const LIBERATO_KEYPAIR_CONTEXT: &str = "OintKeys-LiberatoKeypair-Context";

    #[derive(Clone, Debug, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
    pub struct LiberatoKeypair {
        pub pk: LiberatoPublicKey,
        pub sk: LiberatoSecretKey,
    }

    impl LiberatoKeypairTrait for LiberatoKeypair {
        /// # [Oint-Keys]Generate Keypair
        /// 
        /// This function generates a keypair based on the provided algorithm. It supports a wide range of algorithms, including both classical and post-quantum schemes. The generated keypair is returned as a `LiberatoKeypair` struct, which contains both the public and secret keys.
        fn generate(alg: crate::algorithms::slug::Algorithms) -> Result<Self,libslug::prelude::core::SlugErrors> {
            match alg {
                Algorithms::AbsolveSigning => {
                    let secret_key: AbsolveKeypair = AbsolveKeypair::generate();
                    
                    let pk: AbsolveKeypair = secret_key.into_public_key();

                    return Ok(Self {
                        pk: LiberatoPublicKey { pk: SlugPublicKey::AbsolveSigning(pk) },
                        sk: LiberatoSecretKey { sk: SlugSecretKey::AbsolveSigning(secret_key) }
                    })
                    
                }
                Algorithms::BLS12_381 => {
                    let (pk, sk) = SlugBLS::generate();

                    let pk_output: LiberatoPublicKey = LiberatoPublicKey::from_public_key(SlugPublicKey::BLS12_381(pk));
                    let sk_output: LiberatoSecretKey = LiberatoSecretKey::from_secret_key(SlugSecretKey::BLS12_381(sk));

                    return Ok(Self {
                        pk: pk_output,
                        sk: sk_output,
                    })
                }
                Algorithms::ECDSA => {
                    let sk: ECDSASecretKey = ECDSASecretKey::generate();
                    let pk: libslug::slugcrypt::internals::signature::ecdsa::ECDSAPublicKey = sk.public_key()?;

                    let pk_output: LiberatoPublicKey = LiberatoPublicKey::from_public_key(SlugPublicKey::ECDSA(pk));
                    let sk_output: LiberatoSecretKey = LiberatoSecretKey::from_secret_key(SlugSecretKey::ECDSA(sk));

                    return Ok(Self {
                        pk: pk_output,
                        sk: sk_output,
                    })
                }
                Algorithms::ED25519 => {
                    let sk: ED25519SecretKey = ED25519SecretKey::generate();
                    let pk: libslug::slugcrypt::internals::signature::ed25519::ED25519PublicKey = sk.public_key()?;

                    let pk_output: LiberatoPublicKey = LiberatoPublicKey::from_public_key(SlugPublicKey::ED25519(pk));
                    let sk_output: LiberatoSecretKey = LiberatoSecretKey::from_secret_key(SlugSecretKey::ED25519(sk));

                    return Ok(Self {
                        pk: pk_output,
                        sk: sk_output,
                    })
                }
                Algorithms::ED448 => {
                    let sk: Ed448SecretKey = Ed448SecretKey::generate();
                    let pk: libslug::slugcrypt::internals::signature::ed448::Ed448PublicKey = sk.into_public_key();

                    let pk_output: LiberatoPublicKey = LiberatoPublicKey::from_public_key(SlugPublicKey::ED448(pk));
                    let sk_output: LiberatoSecretKey = LiberatoSecretKey::from_secret_key(SlugSecretKey::ED448(sk));

                    return Ok(Self {
                        pk: pk_output,
                        sk: sk_output,
                    })
                }
                Algorithms::EsphandSigning => {
                    let secret_key = EsphandKeypair::generate();
                    let pk = secret_key.into_public_key();

                    return Ok(Self {
                        pk: LiberatoPublicKey { pk: SlugPublicKey::EsphandSigning(pk) },
                        sk: LiberatoSecretKey { sk: SlugSecretKey::EsphandSigning(secret_key) }
                    })
                }
                Algorithms::Falcon1024 => {
                    let (pk,sk) = SlugFalcon1024::generate();

                    let pk_output = LiberatoPublicKey::from_public_key(SlugPublicKey::FALCON1024(pk.clone()));
                    let sk_output = LiberatoSecretKey::from_secret_key(SlugSecretKey::FALCON1024((sk,pk.clone())));

                    return Ok(Self {
                        pk: pk_output,
                        sk: sk_output,
                    })
                }
                Algorithms::MLDSA3 => {
                    let mldsa3: MLDSA3Keypair = SlugMLDSA3::generate();
                    let mldsa3_pk: libslug::slugcrypt::internals::signature::ml_dsa::MLDSA3PublicKey = mldsa3.public_key().clone();
                    let mldsa3_sk: libslug::slugcrypt::internals::signature::ml_dsa::MLDSA3SecretKey  = mldsa3.secret_key().clone();

                    let pk_output: LiberatoPublicKey = LiberatoPublicKey::from_public_key(SlugPublicKey::MLDSA3(mldsa3_pk.clone()));
                    let sk_output: LiberatoSecretKey = LiberatoSecretKey::from_secret_key(SlugSecretKey::MLDSA3((mldsa3_sk, mldsa3_pk.clone())));

                    return Ok(Self {
                        pk: pk_output,
                        sk: sk_output,
                    })
                }
                Algorithms::Schnorr => {
                    let sk: SchnorrSecretKey = SchnorrSecretKey::generate();
                    let pk: libslug::slugcrypt::internals::signature::schnorr::SchnorrPublicKey = sk.public_key().expect("Failed During Generation of Schnorr Public Key");

                    let pk_output: LiberatoPublicKey = LiberatoPublicKey::from_public_key(SlugPublicKey::SchnorrOverRistretto(pk));
                    let sk_output: LiberatoSecretKey = LiberatoSecretKey::from_secret_key(SlugSecretKey::SchnorrOverRistretto(sk));

                    return Ok(Self {
                        pk: pk_output,
                        sk: sk_output,
                    })
                }
                Algorithms::ShulginSigning => {
                    let secret_key = ShulginKeypair::generate();
                    let pk = secret_key.into_public_key();

                    return Ok(Self {
                        pk: LiberatoPublicKey { pk: SlugPublicKey::ShulginSigning(pk) },
                        sk: LiberatoSecretKey { sk: SlugSecretKey::ShulginSigning(secret_key) }
                    })
                }
                Algorithms::Sphincs => {
                    let (pk,sk) = SPHINCSSecretKey::generate();
                    let pk_output: LiberatoPublicKey = LiberatoPublicKey::from_public_key(SlugPublicKey::SPHINCS(pk.clone()));
                    let sk_output: LiberatoSecretKey = LiberatoSecretKey::from_secret_key(SlugSecretKey::SPHINCS((sk,pk.clone())));

                    return Ok(Self {
                        pk: pk_output,
                        sk: sk_output,
                    })

                }
            }
        }
        /// # Get Public Key
        /// 
        /// Returns Public Key as `LiberatoPublicKey` struct.
        fn public_key(&self) -> &LiberatoPublicKey {
            return &self.pk;
        }
        /// # Get Secret Key
        /// 
        /// Returns Secret Key as `LiberatoSecretKey` struct.
        fn secret_key(&self) -> &LiberatoSecretKey {
            return &self.sk;
        }
        /// # Get Algorithm
        /// 
        /// Returns the algorithm used for the keypair as an `Algorithms` enum variant.
        fn algorithm(&self) -> Algorithms {
            return self.pk.pk.as_alg()
        }
        /// # Get Cipher Suite
        /// 
        /// Returns the cipher suite associated with the keypair's algorithm as a `String`.
        fn cipher_suite(&self) -> String {
            let x = self.algorithm().clone();
            let output = x.cipher_suite().to_string();
            return output
        }
        /// # Get Cipher Suite As Str256
        /// 
        /// Returns the cipher suite associated with the keypair's algorithm as a `str256` for optimized performance in contexts where fixed-size strings are beneficial.
        fn cipher_suite_as_str256(&self) -> str256 {
            let x = fixedstr::str256::from_str(self.algorithm().cipher_suite()).unwrap();
            return x;
        }
    }

    impl LiberatoSigning for LiberatoKeypair {
        fn sign_with_context<T: AsRef<[u8]>>(&self, msg: T, context: Option<T>) -> Result<Box<LiberatoSignature>,libslug::prelude::core::SlugErrors> {
            match &self.sk.sk {
                // TODO: Sk signs using "libslug20" but this library forces it to use Liberato_Keypair_Context
                // Contains Context Option
                SlugSecretKey::AbsolveSigning(sk) => {

                    if context.is_none() {
                        let x = sk.sign_with_context(msg.as_ref(),LIBERATO_KEYPAIR_CONTEXT.as_bytes())?;
                        return Ok(LiberatoSignature::from_signature(SlugSignature::AbsolveSigning(x)))
                    }
                    let signature: libslug::slugcrypt::internals::signature::absolvesigning::AbsolveSignature = sk.sign_with_context(msg.as_ref(), context.unwrap().as_ref())?;

                    return Ok(LiberatoSignature::from_signature(SlugSignature::AbsolveSigning(signature)))
                }
                // [X] Done
                SlugSecretKey::BLS12_381(sk) => {
                    let sig = sk.sign(msg.as_ref())?;

                    return Ok(LiberatoSignature::from_signature(SlugSignature::BLS12_381(sig)))
                }
                // [X] Done
                SlugSecretKey::ECDSA(sk) => {
                    let signature: (libslug::slugcrypt::internals::signature::ecdsa::ECDSASignature, libslug::slugcrypt::internals::signature::ecdsa::ECDSASignatureRecoveryID) = sk.sign(msg.as_ref())?;

                    return Ok(LiberatoSignature::from_signature(SlugSignature::ECDSA(signature.0,signature.1)))
                }
                // [X] Done
                SlugSecretKey::ED25519(sk) => {
                    let signature: libslug::slugcrypt::internals::signature::ed25519::ED25519Signature = sk.sign(msg.as_ref())?;

                    return Ok(LiberatoSignature::from_signature(SlugSignature::ED25519(signature)))
                }
                // [X] Done
                SlugSecretKey::ED448(sk) => {
                    let signature: libslug::slugcrypt::internals::signature::ed448::Ed448Signature = sk.sign(msg.as_ref())?;

                    return Ok(LiberatoSignature::from_signature(SlugSignature::ED448(signature)))
                }
                // [X] Done
                SlugSecretKey::EsphandSigning(sk) => {
                    let signature = sk.sign(msg.as_ref())?;

                    return Ok(LiberatoSignature::from_signature(SlugSignature::EsphandSigning(signature)))
                }
                // [X] Done
                SlugSecretKey::FALCON1024((sk, _)) => {
                    let signature = sk.sign(msg.as_ref());

                    if signature.is_err() {
                        return Err(libslug::errors::SlugErrors::SigningFailure(libslug::errors::SlugErrorAlgorithms::SIG_FALCON))
                    }
                    else {
                        let signature = signature.unwrap();
                        return Ok(LiberatoSignature::from_signature(SlugSignature::FALCON1024(signature)))
                    }
                }
                // [X] Done
                SlugSecretKey::MLDSA3((sk, _)) => {
                    if context.is_none() {
                        let signature: libslug::slugcrypt::internals::signature::ml_dsa::MLDSA3Signature = sk.sign(msg.as_ref(), LIBERATO_KEYPAIR_CONTEXT.as_bytes())?;

                        return Ok(LiberatoSignature::from_signature(SlugSignature::MLDSA3(signature)))
                    }
                    else {
                        let signature: libslug::slugcrypt::internals::signature::ml_dsa::MLDSA3Signature = sk.sign(msg.as_ref(), context.unwrap().as_ref())?;
                        
                        return Ok(LiberatoSignature::from_signature(SlugSignature::MLDSA3(signature)))
                    }

                }
                // [X] Done
                SlugSecretKey::SchnorrOverRistretto(sk) => {
                    if context.is_some() {
                        let signature = sk.sign_with_context(msg.as_ref(), context.unwrap().as_ref());

                        if signature.is_err() {
                            return Err(libslug::errors::SlugErrors::SigningFailure(libslug::errors::SlugErrorAlgorithms::SIG_SCHNORR))
                        }
                        else {
                            let signature = signature.unwrap();
                            return Ok(LiberatoSignature::from_signature(SlugSignature::SchnorrOverRistretto(signature)))
                        }
                    }
                    else {
                        let signature = sk.sign_with_context(msg.as_ref(),LIBERATO_KEYPAIR_CONTEXT.as_bytes());

                        if signature.is_err() {
                            return Err(libslug::errors::SlugErrors::SigningFailure(libslug::errors::SlugErrorAlgorithms::SIG_SCHNORR))
                        }
                        else {
                            let signature = signature.unwrap();
                            return Ok(LiberatoSignature::from_signature(SlugSignature::SchnorrOverRistretto(signature)))
                        }
                    }
                }
                // [X] Done
                SlugSecretKey::ShulginSigning(sk) => {
                    let signature: libslug::slugcrypt::internals::signature::shulginsigning::ShulginSignature = sk.sign(msg.as_ref())?;

                    return Ok(LiberatoSignature::from_signature(SlugSignature::ShulginSigning(signature)))
                }
                // [X] Done
                SlugSecretKey::SPHINCS(sk) => {
                    let signature: libslug::slugcrypt::internals::signature::sphincs_plus::SPHINCSSignature = sk.0.sign(msg.as_ref())?;
                    
                    return Ok(LiberatoSignature::from_signature(SlugSignature::SPHINCS(signature)))
                }
        }

    }
        fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Result<Box<LiberatoSignature>,libslug::prelude::core::SlugErrors> {
            return self.sign_with_context(msg, None)
        }
}
    impl LiberatoVerification for LiberatoPublicKey {
        fn verify_with_context<T: AsRef<[u8]>>(&self, msg: T, context: Option<T>, sig: &LiberatoSignature) -> Result<bool,libslug::prelude::core::SlugErrors> {
            let signature: SlugSignature = sig.as_slug_signature();
            
            match &self.pk {
                SlugPublicKey::AbsolveSigning(pk) => {
                    if let SlugSignature::AbsolveSigning(signature) = &sig.signature {
                        if context.is_none() {
                            let verify = pk.verify(msg.as_ref(), signature.clone())?;

                            return Ok(verify)
                        }
                        else {
                            let verify = pk.verify(msg.as_ref(), signature.clone())?;

                            return Ok(verify)
                        }
                    }
                    else {
                        return Err(libslug::errors::SlugErrors::VerifyingError(libslug::errors::SlugErrorAlgorithms::SIG_ABSOLVESIGNING))
                    }
                }
                SlugPublicKey::BLS12_381(pk) => {
                    if let SlugSignature::BLS12_381(signature) = &sig.signature {
                        let verify = pk.verify(msg.as_ref(), &signature)?;

                        return Ok(verify)
                    }
                    else {
                        return Err(libslug::errors::SlugErrors::VerifyingError(libslug::errors::SlugErrorAlgorithms::SIG_BLS))
                    }
                }
                SlugPublicKey::ECDSA(pk) => {
                    if let SlugSignature::ECDSA(signature, _) = &sig.signature {
                        let verify = pk.verify(msg.as_ref(), signature.clone())?;

                        return Ok(verify)
                    }
                    else {
                        return Err(libslug::errors::SlugErrors::VerifyingError(libslug::errors::SlugErrorAlgorithms::SIG_SECP256k1))
                    }
                }
                SlugPublicKey::ED25519(pk) => {
                    if let SlugSignature::ED25519(signature) = &sig.signature {
                        let verify = pk.verify(signature.clone(),msg.as_ref())?;

                        return Ok(verify)
                    }
                    else {
                        return Err(libslug::errors::SlugErrors::VerifyingError(libslug::errors::SlugErrorAlgorithms::SIG_ED25519))
                    }
                }
                SlugPublicKey::ED448(pk) => {
                    if let SlugSignature::ED448(signature) = &sig.signature {
                        let verify = pk.verify(msg.as_ref(),signature.clone())?;

                        return Ok(verify)
                    }
                    else {
                        return Err(libslug::errors::SlugErrors::VerifyingError(libslug::errors::SlugErrorAlgorithms::SIG_ED448))
                    }
                }
                SlugPublicKey::EsphandSigning(pk) => {
                    if let SlugSignature::EsphandSigning(signature) = &sig.signature {
                        let verify = pk.verify(msg.as_ref(), &signature)?;

                        return Ok(verify)
                    }
                    else {
                        //TODO: Add Correct Error as EsphandSigning
                        return Err(libslug::errors::SlugErrors::VerifyingError(libslug::errors::SlugErrorAlgorithms::SIG_FALCON))
                    }
                }
                SlugPublicKey::FALCON1024(pk) => {
                    if let SlugSignature::FALCON1024(signature) = &sig.signature {
                        let verify = pk.verify(msg.as_ref(), &signature);

                        if verify.is_ok() {
                            return Ok(verify.unwrap())
                        }
                        else {
                            return Err(libslug::errors::SlugErrors::VerifyingError(libslug::errors::SlugErrorAlgorithms::SIG_FALCON))
                        }
                    }
                    else {
                        return Err(libslug::errors::SlugErrors::VerifyingError(libslug::errors::SlugErrorAlgorithms::SIG_FALCON))
                    }
                }
                SlugPublicKey::MLDSA3(pk) => {
                    if context.is_none() {
                        if let SlugSignature::MLDSA3(signature) = &sig.signature {
                            let verify = pk.verify(msg.as_ref(), LIBERATO_KEYPAIR_CONTEXT.as_bytes(), &signature)?;

                            return Ok(verify)
                        }
                        else {
                            return Err(libslug::errors::SlugErrors::VerifyingError(libslug::errors::SlugErrorAlgorithms::SIG_MLDSA))
                        }
                    }
                    else {
                        if let SlugSignature::MLDSA3(signature) = &sig.signature {
                            let verify = pk.verify(msg.as_ref(), context.unwrap().as_ref(), &signature)?;

                            return Ok(verify)
                        }
                        else {
                            return Err(libslug::errors::SlugErrors::VerifyingError(libslug::errors::SlugErrorAlgorithms::SIG_MLDSA))
                        }
                    }

                }
                SlugPublicKey::SchnorrOverRistretto(pk) => {
                    if context.is_none() {
                        if let SlugSignature::SchnorrOverRistretto(signature) = &sig.signature {
                            let verify = pk.verify_with_context(msg.as_ref(), LIBERATO_KEYPAIR_CONTEXT.as_bytes(), signature.clone());

                            if verify.is_ok() {
                                return Ok(true)
                            }
                            else {
                                return Err(libslug::errors::SlugErrors::VerifyingError(libslug::errors::SlugErrorAlgorithms::SIG_SCHNORR))
                            }
                        }
                        else {
                            return Err(libslug::errors::SlugErrors::VerifyingError(libslug::errors::SlugErrorAlgorithms::SIG_SCHNORR))
                        }
                    }
                    else {
                        if let SlugSignature::SchnorrOverRistretto(signature) = &sig.signature {
                            let verify = pk.verify_with_context(msg.as_ref(), context.unwrap().as_ref(), signature.clone());

                            if verify.is_ok() {
                                return Ok(true)
                            }
                            else {
                                return Err(libslug::errors::SlugErrors::VerifyingError(libslug::errors::SlugErrorAlgorithms::SIG_SCHNORR))
                            }
                        }
                        else {
                            return Err(libslug::errors::SlugErrors::VerifyingError(libslug::errors::SlugErrorAlgorithms::SIG_SCHNORR))
                        }
                    }
                }
                SlugPublicKey::ShulginSigning(pk) => {
                    if let SlugSignature::ShulginSigning(signature) = &sig.signature {
                        let verify = pk.verify(msg.as_ref(), &signature)?;

                        return Ok(verify)
                    }
                    else {
                        return Err(libslug::errors::SlugErrors::VerifyingError(libslug::errors::SlugErrorAlgorithms::SIG_SHULGINSIGNING))
                    }
                }
                SlugPublicKey::SPHINCS(pk) => {
                    if let SlugSignature::SPHINCS(signature) = &sig.signature {
                        let verify = pk.verify(msg.as_ref(), signature.clone());

                        if verify.is_ok() {
                            return Ok(verify.unwrap())
                        }
                        else {
                            return Err(libslug::errors::SlugErrors::VerifyingError(libslug::errors::SlugErrorAlgorithms::SIG_SPHINCS_PLUS));
                        }
                    }
                    else {
                        return Err(libslug::errors::SlugErrors::VerifyingError(libslug::errors::SlugErrorAlgorithms::SIG_SPHINCS_PLUS))
                    }
            }
        }
    }
    fn verify<T: AsRef<[u8]>>(&self, msg: T, signature: &LiberatoSignature) -> Result<bool,libslug::prelude::core::SlugErrors> {
        return self.verify_with_context(msg, None, signature)
    }
    }
    #[derive(Clone, Debug, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
    pub struct LiberatoPublicKey {
        pub pk: SlugPublicKey,
    }

    impl LiberatoPublicKey {
        pub fn from_public_key(alg: SlugPublicKey) -> Self {
            return Self {
                pk: alg,
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
    pub struct LiberatoSecretKey {
        pub sk: SlugSecretKey
    }

    impl LiberatoSecretKey {
        pub fn from_secret_key(alg: SlugSecretKey) -> Self {
            return Self {
                sk: alg,
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
    pub struct LiberatoSignature {
        pub signature: SlugSignature,
    }

    impl LiberatoSignature {
        pub fn from_signature(alg: SlugSignature) -> Box<Self> {
            return Box::new(Self {
                signature: alg,
            })
        }
        pub fn as_slug_signature(&self) -> SlugSignature {
            return self.signature.clone();
        }
    }

    //===== Implementations of Encoding Traits for Liberato Keys =====

    impl IntoEncodingPublicKey for LiberatoPublicKey {
        fn into_base32(&self) -> Result<String,libslug::prelude::core::SlugErrors> {
            match &self.pk {
                SlugPublicKey::AbsolveSigning(pk) => {
                    unimplemented!()
                }
                SlugPublicKey::BLS12_381(pk) => {
                    let x = pk.to_base32()?;

                    return Ok(x)
                }
                SlugPublicKey::ECDSA(pk) => {
                    let x = pk.to_base32()?;

                    return Ok(x)
                }
                SlugPublicKey::ED25519(pk) => {
                    let x = pk.to_base32()?;

                    return Ok(x)
                }
                SlugPublicKey::ED448(pk) => {
                    let x = pk.to_base32()?;

                    return Ok(x)
                }
                SlugPublicKey::EsphandSigning(pk) => {
                    unimplemented!();
                }
                SlugPublicKey::FALCON1024(pk) => {
                    let x = pk.to_base32()?;

                    return Ok(x)
                }
                SlugPublicKey::MLDSA3(pk) => {
                    let x = pk.to_base32()?;

                    return Ok(x)
                }
                SlugPublicKey::SchnorrOverRistretto(pk) => {
                    unimplemented!();
                }
                SlugPublicKey::ShulginSigning(pk) => {
                    unimplemented!();
                }
                SlugPublicKey::SPHINCS(pk) => {
                    let x = pk.to_base32()?;

                    return Ok(x)
                }
            }
        }
        fn into_base32up(&self) -> Result<String,libslug::prelude::core::SlugErrors> {
            match &self.pk {
                SlugPublicKey::AbsolveSigning(pk) => {
                    unimplemented!()
                }
                SlugPublicKey::BLS12_381(pk) => {
                    let x = pk.to_base32_unpadded()?;

                    return Ok(x)
                }
                SlugPublicKey::ECDSA(pk) => {
                    let x = pk.to_base32_unpadded()?;

                    return Ok(x)
                }
                SlugPublicKey::ED25519(pk) => {
                    let x = pk.to_base32_unpadded()?;

                    return Ok(x)
                }
                SlugPublicKey::ED448(pk) => {
                    let x = pk.to_base32_unpadded()?;

                    return Ok(x)
                }
                SlugPublicKey::EsphandSigning(pk) => {
                    unimplemented!();
                }
                SlugPublicKey::FALCON1024(pk) => {
                    let x = pk.to_base32_unpadded()?;

                    return Ok(x)
                }
                SlugPublicKey::MLDSA3(pk) => {
                    let x = pk.to_base32_unpadded()?;

                    return Ok(x)
                }
                SlugPublicKey::SchnorrOverRistretto(pk) => {
                    unimplemented!();
                }
                SlugPublicKey::ShulginSigning(pk) => {
                    unimplemented!();
                }
                SlugPublicKey::SPHINCS(pk) => {
                    let x = pk.to_base32_unpadded()?;

                    return Ok(x)
                }
        }
    }
        fn into_base58(&self) -> Result<String,libslug::prelude::core::SlugErrors> {
            match &self.pk {
                SlugPublicKey::AbsolveSigning(pk) => {
                    unimplemented!()
                }
                SlugPublicKey::BLS12_381(pk) => {
                    let x = pk.to_base58()?;

                    return Ok(x)
                }
                SlugPublicKey::ECDSA(pk) => {
                    let x = pk.to_base58()?;

                    return Ok(x)
                }
                SlugPublicKey::ED25519(pk) => {
                    let x = pk.to_base58()?;

                    return Ok(x)
                }
                SlugPublicKey::ED448(pk) => {
                    let x = pk.to_base58()?;

                    return Ok(x)
                }
                SlugPublicKey::EsphandSigning(pk) => {
                    unimplemented!();
                }
                SlugPublicKey::FALCON1024(pk) => {
                    let x = pk.to_base58()?;

                    return Ok(x)
                }
                SlugPublicKey::MLDSA3(pk) => {
                    let x = pk.to_base58()?;

                    return Ok(x)
                }
                SlugPublicKey::SchnorrOverRistretto(pk) => {
                    unimplemented!();
                }
                SlugPublicKey::ShulginSigning(pk) => {
                    unimplemented!();
                }
                SlugPublicKey::SPHINCS(pk) => {
                    let x = pk.to_base58()?;

                    return Ok(x)
                }
            }
        }
        fn into_base64(&self) -> Result<String,libslug::prelude::core::SlugErrors> {
            match &self.pk {
                SlugPublicKey::AbsolveSigning(pk) => {
                    unimplemented!()
                }
                SlugPublicKey::BLS12_381(pk) => {
                    let x = pk.to_base64()?;

                    return Ok(x)
                }
                SlugPublicKey::ECDSA(pk) => {
                    let x = pk.to_base64()?;

                    return Ok(x)
                }
                SlugPublicKey::ED25519(pk) => {
                    let x = pk.to_base64()?;

                    return Ok(x)
                }
                SlugPublicKey::ED448(pk) => {
                    let x = pk.to_base64()?;

                    return Ok(x)
                }
                SlugPublicKey::EsphandSigning(pk) => {
                    unimplemented!();
                }
                SlugPublicKey::FALCON1024(pk) => {
                    let x = pk.to_base64()?;

                    return Ok(x)
                }
                SlugPublicKey::MLDSA3(pk) => {
                    let x = pk.to_base64()?;

                    return Ok(x)
                }
                SlugPublicKey::SchnorrOverRistretto(pk) => {
                    unimplemented!();
                }
                SlugPublicKey::ShulginSigning(pk) => {
                    unimplemented!();
                }
                SlugPublicKey::SPHINCS(pk) => {
                    let x = pk.to_base64()?;

                    return Ok(x)
                }
            }
    }
        fn into_base64url(&self) -> Result<String,libslug::prelude::core::SlugErrors> {
            match &self.pk {
                SlugPublicKey::AbsolveSigning(pk) => {
                    unimplemented!()
                }
                SlugPublicKey::BLS12_381(pk) => {
                    let x = pk.to_base64_url_safe()?;

                    return Ok(x)
                }
                SlugPublicKey::ECDSA(pk) => {
                    let x = pk.to_base64_url_safe()?;

                    return Ok(x)
                }
                SlugPublicKey::ED25519(pk) => {
                    let x = pk.to_base64_url_safe()?;

                    return Ok(x)
                }
                SlugPublicKey::ED448(pk) => {
                    let x = pk.to_base64_url_safe()?;

                    return Ok(x)
                }
                SlugPublicKey::EsphandSigning(pk) => {
                    unimplemented!();
                }
                SlugPublicKey::FALCON1024(pk) => {
                    let x = pk.to_base64_url_safe()?;

                    return Ok(x)
                }
                SlugPublicKey::MLDSA3(pk) => {
                    let x = pk.to_base64_url_safe()?;

                    return Ok(x)
                }
                SlugPublicKey::SchnorrOverRistretto(pk) => {
                    unimplemented!();
                }
                SlugPublicKey::ShulginSigning(pk) => {
                    unimplemented!();
                }
                SlugPublicKey::SPHINCS(pk) => {
                    let x = pk.to_base64_url_safe()?;

                    return Ok(x)
                }
            }
        }
        fn into_hex(&self) -> Result<String,libslug::prelude::core::SlugErrors> {
            match &self.pk {
                SlugPublicKey::AbsolveSigning(pk) => {
                    unimplemented!()
                }
                SlugPublicKey::BLS12_381(pk) => {
                    let x = pk.to_hex()?;

                    return Ok(x)
                }
                SlugPublicKey::ECDSA(pk) => {
                    let x = pk.to_hex()?;

                    return Ok(x)
                }
                SlugPublicKey::ED25519(pk) => {
                    let x = pk.to_hexadecimal()?;

                    return Ok(x)
                }
                SlugPublicKey::ED448(pk) => {
                    let x = pk.to_hex()?;

                    return Ok(x)
                }
                SlugPublicKey::EsphandSigning(pk) => {
                    unimplemented!();
                }
                SlugPublicKey::FALCON1024(pk) => {
                    let x = pk.to_hex()?;

                    return Ok(x)
                }
                SlugPublicKey::MLDSA3(pk) => {
                    let x = pk.to_hex()?;

                    return Ok(x)
                }
                SlugPublicKey::SchnorrOverRistretto(pk) => {
                    unimplemented!();
                }
                SlugPublicKey::ShulginSigning(pk) => {
                    unimplemented!();
                }
                SlugPublicKey::SPHINCS(pk) => {
                    let x = pk.to_hex()?;

                    return Ok(x)
                }
            }
        }
    }

    impl IntoEncodingSecretKey for LiberatoSecretKey {
        fn into_base32(&self) -> Result<String,libslug::prelude::core::SlugErrors> {
            match &self.sk {
                SlugSecretKey::AbsolveSigning(sk) => {
                    unimplemented!()
                }
                SlugSecretKey::BLS12_381(sk) => {
                    let x = sk.to_base32()?;

                    return Ok(x)
                }
                SlugSecretKey::ECDSA(sk) => {
                    let x = sk.to_base32()?;

                    return Ok(x)
                }
                SlugSecretKey::ED25519(sk) => {
                    let x = sk.to_base32()?;

                    return Ok(x)
                }
                SlugSecretKey::ED448(sk) => {
                    let x = sk.to_base32()?;

                    return Ok(x)
                }
                SlugSecretKey::EsphandSigning(sk) => {
                    unimplemented!();
                }
                SlugSecretKey::FALCON1024((sk, _)) => {
                    let x = sk.to_base32()?;

                    return Ok(x)
                }
                SlugSecretKey::MLDSA3((sk, _)) => {
                    let x = sk.to_base32()?;

                    return Ok(x)
                }
                SlugSecretKey::SchnorrOverRistretto(sk) => {
                    unimplemented!();
                }
                SlugSecretKey::ShulginSigning(sk) => {
                    unimplemented!();
                }
                SlugSecretKey::SPHINCS((sk, _)) => {
                    let x = sk.to_base32()?;

                    return Ok(x)
                }
            }
        }
        fn into_base32up(&self) -> Result<String,libslug::prelude::core::SlugErrors> {
            match &self.sk {
                SlugSecretKey::AbsolveSigning(sk) => {
                    unimplemented!()
                }
                SlugSecretKey::BLS12_381(sk) => {
                    let x = sk.to_base32_unpadded()?;

                    return Ok(x)
                }
                SlugSecretKey::ECDSA(sk) => {
                    let x = sk.to_base32_unpadded()?;

                    return Ok(x)
                }
                SlugSecretKey::ED25519(sk) => {
                    let x = sk.to_base32_unpadded()?;

                    return Ok(x)
                }
                SlugSecretKey::ED448(sk) => {
                    let x = sk.to_base32_unpadded()?;

                    return Ok(x)
                }
                SlugSecretKey::EsphandSigning(sk) => {
                    unimplemented!();
                }
                SlugSecretKey::FALCON1024((sk, _)) => {
                    let x = sk.to_base32_unpadded()?;

                    return Ok(x)
                }
                SlugSecretKey::MLDSA3((sk, _)) => {
                    let x = sk.to_base32_unpadded()?;

                    return Ok(x)
                }
                SlugSecretKey::SchnorrOverRistretto(sk) => {
                    unimplemented!();
                }
                SlugSecretKey::ShulginSigning(sk) => {
                    unimplemented!();
                }
                SlugSecretKey::SPHINCS((sk, _)) => {
                    let x = sk.to_base32_unpadded()?;

                    return Ok(x)
                }
            }
        }
        fn into_base58(&self) -> Result<String,libslug::prelude::core::SlugErrors> {
            match &self.sk {
                SlugSecretKey::AbsolveSigning(sk) => {
                    unimplemented!()
                }
                SlugSecretKey::BLS12_381(sk) => {
                    let x = sk.to_base58()?;

                    return Ok(x)
                }
                SlugSecretKey::ECDSA(sk) => {
                    let x = sk.to_base58()?;

                    return Ok(x)
                }
                SlugSecretKey::ED25519(sk) => {
                    let x = sk.to_base58()?;

                    return Ok(x)
                }
                SlugSecretKey::ED448(sk) => {
                    let x = sk.to_base58()?;

                    return Ok(x)
                }
                SlugSecretKey::EsphandSigning(sk) => {
                    unimplemented!();
                }
                SlugSecretKey::FALCON1024((sk, _)) => {
                    let x = sk.to_base58()?;

                    return Ok(x)
                }
                SlugSecretKey::MLDSA3((sk, _)) => {
                    let x = sk.to_base58()?;

                    return Ok(x)
                }
                SlugSecretKey::SchnorrOverRistretto(sk) => {
                    unimplemented!();
                }
                SlugSecretKey::ShulginSigning(sk) => {
                    unimplemented!();
                }
                SlugSecretKey::SPHINCS((sk, _)) => {
                    let x = sk.to_base58()?;

                    return Ok(x)
                }
            }
        }
        fn into_base64(&self) -> Result<String,libslug::prelude::core::SlugErrors> {
            match &self.sk {
                SlugSecretKey::AbsolveSigning(sk) => {
                    unimplemented!()
                }
                SlugSecretKey::BLS12_381(sk) => {
                    let x = sk.to_base64()?;

                    return Ok(x)
                }
                SlugSecretKey::ECDSA(sk) => {
                    let x = sk.to_base64()?;

                    return Ok(x)
                }
                SlugSecretKey::ED25519(sk) => {
                    let x = sk.to_base64()?;

                    return Ok(x)
                }
                SlugSecretKey::ED448(sk) => {
                    let x = sk.to_base64()?;

                    return Ok(x)
                }
                SlugSecretKey::EsphandSigning(sk) => {
                    unimplemented!();
                }
                SlugSecretKey::FALCON1024((sk, _)) => {
                    let x = sk.to_base64()?;

                    return Ok(x)
                }
                SlugSecretKey::MLDSA3((sk, _)) => {
                    let x = sk.to_base64()?;

                    return Ok(x)
                }
                SlugSecretKey::SchnorrOverRistretto(sk) => {
                    unimplemented!();
                }
                SlugSecretKey::ShulginSigning(sk) => {
                    unimplemented!();
                }
                SlugSecretKey::SPHINCS((sk, _)) => {
                    let x = sk.to_base64()?;

                    return Ok(x)
                }
            }
        }
        fn into_base64url(&self) -> Result<String,libslug::prelude::core::SlugErrors> {
            match &self.sk {
                SlugSecretKey::AbsolveSigning(sk) => {
                    unimplemented!()
                }
                SlugSecretKey::BLS12_381(sk) => {
                    let x = sk.to_base64_url_safe()?;

                    return Ok(x)
                }
                SlugSecretKey::ECDSA(sk) => {
                    let x = sk.to_base64_url_safe()?;

                    return Ok(x)
                }
                SlugSecretKey::ED25519(sk) => {
                    let x = sk.to_base64_url_safe()?;

                    return Ok(x)
                }
                SlugSecretKey::ED448(sk) => {
                    let x = sk.to_base64_url_safe()?;

                    return Ok(x)
                }
                SlugSecretKey::EsphandSigning(sk) => {
                    unimplemented!();
                }
                SlugSecretKey::FALCON1024((sk, _)) => {
                    let x = sk.to_base64_url_safe()?;

                    return Ok(x)
                }
                SlugSecretKey::MLDSA3((sk, _)) => {
                    let x = sk.to_base64_url_safe()?;

                    return Ok(x)
                }
                SlugSecretKey::SchnorrOverRistretto(sk) => {
                    unimplemented!();
                }
                SlugSecretKey::ShulginSigning(sk) => {
                    unimplemented!();
                }
                SlugSecretKey::SPHINCS((sk, _)) => {
                    let x = sk.to_base64_url_safe()?;

                    return Ok(x)
                }
            }
        }
        fn into_hex(&self) -> Result<String,libslug::prelude::core::SlugErrors> {
            match &self.sk {
                SlugSecretKey::AbsolveSigning(sk) => {
                    unimplemented!()
                }
                SlugSecretKey::BLS12_381(sk) => {
                    let x = sk.to_hex()?;

                    return Ok(x)
                }
                SlugSecretKey::ECDSA(sk) => {
                    let x = sk.to_hex()?;

                    return Ok(x)
                }
                SlugSecretKey::ED25519(sk) => {
                    let x = sk.to_hexadecimal()?;

                    return Ok(x)
                }
                SlugSecretKey::ED448(sk) => {
                    let x = sk.to_hex()?;

                    return Ok(x)
                }
                SlugSecretKey::EsphandSigning(sk) => {
                    unimplemented!();
                }
                SlugSecretKey::FALCON1024((sk, _)) => {
                    let x = sk.to_hex()?;

                    return Ok(x)
                }
                SlugSecretKey::MLDSA3((sk, _)) => {
                    let x = sk.to_hex()?;

                    return Ok(x)
                }
                SlugSecretKey::SchnorrOverRistretto(sk) => {
                    unimplemented!();
                }
                SlugSecretKey::ShulginSigning(sk) => {
                    unimplemented!();
                }
                SlugSecretKey::SPHINCS((sk, _)) => {
                    let x = sk.to_hex()?;

                    return Ok(x)
                }
            }
        }
    }


    impl IntoX59 for LiberatoPublicKey {
        fn into_x59_fmt(&self) -> Result<String,libslug::prelude::core::SlugErrors> {
            match &self.pk {
                SlugPublicKey::AbsolveSigning(x) => {
                    let pk = x.into_x59_pk()?;
                    return Ok(pk)
                }
                SlugPublicKey::BLS12_381(x) => {
                    let pk = x.to_hex()?;

                    return Ok(pk)
                }
                SlugPublicKey::ECDSA(x) => {
                    let pk = x.to_hex()?;

                    return Ok(pk)
                }
                SlugPublicKey::ED25519(x) => {
                    let pk = x.to_hexadecimal()?;

                    return Ok(pk)
                }
                SlugPublicKey::ED448(x) => {
                    let pk = x.to_hex()?;

                    return Ok(pk)
                }
                SlugPublicKey::EsphandSigning(x) => {
                    let pk = x.into_x59_pk()?;

                    return Ok(pk)
                }
                SlugPublicKey::FALCON1024(x) => {
                    let pk = x.to_hex()?;

                    return Ok(pk)
                }
                SlugPublicKey::MLDSA3(x) => {
                    let pk = x.to_hex()?;

                    return Ok(pk)
                }
                SlugPublicKey::SPHINCS(x) => {
                    let pk = x.to_hex()?;

                    return Ok(pk)
                }
                SlugPublicKey::SchnorrOverRistretto(x) => {
                    let pk = x.to_hex_string()?;

                    return Ok(pk)
                }
                SlugPublicKey::ShulginSigning(x) => {
                    let pk = x.into_x59_pk()?;

                    return Ok(pk)
                }
            }
        }
        fn add_prefix(&self, alg: Algorithms) -> String {
            match self.pk {
                SlugPublicKey::AbsolveSigning(_) => SLUG20_ABSOLVESIGNING_ID.to_string(),
                SlugPublicKey::BLS12_381(_) => SLUG20_BLS_12_381_ID.to_string(),
                SlugPublicKey::ECDSA(_) => SLUG20_ECDSA_SECP256k1_ID.to_string(),
                SlugPublicKey::ED25519(_) => SLUG20_ED25519_ID.to_string(),
                SlugPublicKey::ED448(_) => SLUG20_ED448_ID.to_string(),
                SlugPublicKey::EsphandSigning(_) => SLUG20_ESPHANDSIGNING_ID.to_string(),
                SlugPublicKey::FALCON1024(_) => SLUG20_FALCON1024_ID.to_string(),
                SlugPublicKey::MLDSA3(_) => SLUG20_MLDSA3_ID.to_string(),
                SlugPublicKey::SPHINCS(_) => SLUG20_SPHINCS_PLUS_ID.to_string(),
                SlugPublicKey::SchnorrOverRistretto(_) => SLUG20_SCHNORR_ID.to_string(),
                SlugPublicKey::ShulginSigning(_) => SLUG20_SHULGINSIGNING_ID.to_string(),
            }
       }
    }

    impl FromX59 for LiberatoPublicKey {
        fn from_x59_fmt<T: AsRef<str>>(s: T, alg: Algorithms) -> Result<Self,libslug::prelude::core::SlugErrors> {
            match alg {
                Algorithms::AbsolveSigning => {
                    let keypair: AbsolveKeypair = AbsolveKeypair::from_x59_pk(s.as_ref())?;

                    return Ok(Self {
                        pk: SlugPublicKey::AbsolveSigning(keypair)
                    })
                }
                Algorithms::BLS12_381 => {
                    let keypair: BLSPublicKey = BLSPublicKey::from_hex(s.as_ref())?;

                    return Ok(Self {
                        pk: SlugPublicKey::BLS12_381(keypair)
                    })
                }
                Algorithms::ECDSA => {
                    let keypair: ECDSAPublicKey = ECDSAPublicKey::from_hex(s.as_ref())?;

                    return Ok(Self {
                        pk: SlugPublicKey::ECDSA(keypair)
                    })
                }
                Algorithms::ED25519 => {
                    let keypair: ED25519PublicKey = ED25519PublicKey::from_hex(s.as_ref())?;

                    return Ok(Self {
                        pk: SlugPublicKey::ED25519(keypair),
                    })
                }
                Algorithms::ED448 => {
                    let keypair: Ed448PublicKey = Ed448PublicKey::from_hex(s.as_ref())?;

                    return Ok(Self {
                        pk: SlugPublicKey::ED448(keypair)
                    })
                }
                Algorithms::EsphandSigning => {
                    let keypair: EsphandKeypair = EsphandKeypair::from_x59_public_key(s.as_ref())?;

                    return Ok(Self {
                        pk: SlugPublicKey::EsphandSigning(keypair)
                    })
                }
                Algorithms::Falcon1024 => {
                    let pk: Falcon1024PublicKey = Falcon1024PublicKey::from_hex(s.as_ref())?;

                    return Ok(Self {
                        pk: SlugPublicKey::FALCON1024(pk),
                    })
                }
                Algorithms::MLDSA3 => {
                    let pk: MLDSA3PublicKey = MLDSA3PublicKey::from_hex(s.as_ref())?;

                    return Ok( Self {
                        pk: SlugPublicKey::MLDSA3(pk)
                    })
                }
                Algorithms::Schnorr => {
                    let pk = SchnorrPublicKey::from_hex_string(s.as_ref());
                    let pk_output: SchnorrPublicKey = SchnorrPublicKey::from_bytes(&pk.clone().unwrap())?;

                    if pk.clone().is_ok() {
                        return Ok(Self {
                            pk: SlugPublicKey::SchnorrOverRistretto(pk_output)
                    })
                    }
                    else {
                        return Err(SlugErrors::DecodingError { alg: libslug::errors::SlugErrorAlgorithms::SIG_SCHNORR, encoding: libslug::errors::EncodingError::Hexadecimal, other: None })
                    }
                }
                Algorithms::ShulginSigning => {
                    let pk: ShulginKeypair = ShulginKeypair::from_x59_pk(s.as_ref())?;

                    return Ok(Self {
                        pk: SlugPublicKey::ShulginSigning(pk)  
                    })
                }
                Algorithms::Sphincs => {
                    let x: SPHINCSPublicKey = SPHINCSPublicKey::from_hex_string_final(s.as_ref())?;

                    return Ok(Self {
                        pk: SlugPublicKey::SPHINCS(x)
                    })
                }
            }
        }
    }
}