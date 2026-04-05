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

use std::str::FromStr;

use fixedstr::str64;

use libslug::errors::SlugErrors;
use libslug::slugcrypt::internals::signature::absolvesigning::AbsolveKeypair;
use libslug::slugcrypt::internals::signature::bls::BLSPublicKey;
use libslug::slugcrypt::internals::signature::bls::BLSSecretKey;
use libslug::slugcrypt::internals::signature::ecdsa::ECDSAPublicKey;
use libslug::slugcrypt::internals::signature::ecdsa::ECDSASecretKey;
use libslug::slugcrypt::internals::signature::ed448::Ed448PublicKey;
use libslug::slugcrypt::internals::signature::ed448::Ed448SecretKey;
use libslug::slugcrypt::internals::signature::ed25519::ED25519PublicKey;
use libslug::slugcrypt::internals::signature::ed25519::ED25519SecretKey;
use libslug::slugcrypt::internals::signature::esphand_signature::EsphandKeypair;
use libslug::slugcrypt::internals::signature::falcon::SlugFalcon1024;
use libslug::slugcrypt::internals::signature::falcon::{Falcon1024SecretKey,Falcon1024PublicKey};
use libslug::slugcrypt::internals::signature::ml_dsa::MLDSA3Keypair;
use libslug::slugcrypt::internals::signature::ml_dsa::MLDSA3PublicKey;
use libslug::slugcrypt::internals::signature::ml_dsa::MLDSA3SecretKey;
use libslug::slugcrypt::internals::signature::ml_dsa::SlugMLDSA3;
use libslug::slugcrypt::internals::signature::schnorr::SchnorrPublicKey;
use libslug::slugcrypt::internals::signature::schnorr::SchnorrSecretKey;
use libslug::slugcrypt::internals::signature::shulginsigning::ShulginKeypair;
use libslug::slugcrypt::internals::signature::sphincs_plus::SPHINCSPublicKey;
use libslug::slugcrypt::internals::signature::sphincs_plus::SPHINCSSecretKey;
use oint_keys_traits::GenerateKeypair;

// HYBRID
use libslug::slugcrypt::internals::signature::shulginsigning;
use libslug::slugcrypt::internals::signature::esphand_signature;

// Classical
use libslug::slugcrypt::internals::signature::ed25519;
use libslug::slugcrypt::internals::signature::ecdsa;
use libslug::slugcrypt::internals::signature::bls;
use libslug::slugcrypt::internals::signature::schnorr;
// Post-Quantum
use libslug::slugcrypt::internals::signature::sphincs_plus;
use libslug::slugcrypt::internals::signature::falcon;
use libslug::slugcrypt::internals::signature::ml_dsa;

use libslug::slugcrypt::traits::{IntoEncoding,FromEncoding};
use libslug::slugcrypt::traits::{IntoX59PublicKey,IntoX59SecretKey,IntoX59Signature};

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
    use libslug::slugcrypt::internals::signature::absolvesigning::AbsolveKeypair;
    use libslug::slugcrypt::internals::signature::bls::{BLSSecretKey, SlugBLS};
    use libslug::slugcrypt::internals::signature::ecdsa::ECDSASecretKey;
    use libslug::slugcrypt::internals::signature::ed448::Ed448SecretKey;
    use libslug::slugcrypt::internals::signature::ed25519::ED25519SecretKey;
    use libslug::slugcrypt::internals::signature::esphand_signature::EsphandKeypair;
    use libslug::slugcrypt::internals::signature::falcon::SlugFalcon1024;
    use libslug::slugcrypt::internals::signature::ml_dsa::{MLDSA3Keypair, SlugMLDSA3};
    use libslug::slugcrypt::internals::signature::schnorr::SchnorrSecretKey;
    use libslug::slugcrypt::internals::signature::shulginsigning::ShulginKeypair;
    use libslug::slugcrypt::internals::signature::sphincs_plus::SPHINCSSecretKey;
    use libslug::slugcrypt::traits::IntoEncoding;
    use zeroize::{Zeroize,ZeroizeOnDrop};
    use serde::{Serialize,Deserialize};
    use crate::algorithms::slug::{SlugPublicKey,SlugSecretKey,SlugSignature};
    use crate::algorithms::slug::Algorithms;
    
    
    use crate::traits::liberato_key_traits::{LiberatoKeypairTrait, LiberatoVerification};
    use crate::traits::liberato_key_traits::LiberatoSigning;

    use crate::traits::liberato_key_traits::{IntoEncodingPublicKey,IntoEncodingKeypair,IntoEncodingSecretKey,IntoEncodingSignature};


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
        fn verify<T: AsRef<[u8]>>(&self, msg: T, context: Option<T>, sig: &LiberatoSignature) -> Result<bool,libslug::prelude::core::SlugErrors> {
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

}

/* 
pub struct OintKeypair<'a> {
    pub pkh: OintPublicKey<'a>,
    pub skh: OintSecretKey<'a>,
    
    // Metadata
    pub encoding: str64,
    pub alg: str64,
}
/*
impl<'a> OintGenerateKeypair<'a> for OintKeypair<'a> {
    fn generate<T: AsRef<str>>(cipher_suite: T) -> Result<OintKeypair<'a>,SlugErrors> {
        let x = cipher_suite.as_ref().to_ascii_uppercase();

        if x == SLUG20_ABSOLVESIGNING_ID.to_ascii_uppercase() {
            let encoding = OintEncoding::new(OintKeyEncodings::X59FMT);
            
            let absolve_keypair: AbsolveKeypair = AbsolveKeypair::generate();
            let pk: String = absolve_keypair.into_x59_pk()?;
            let sk: String = absolve_keypair.into_x59()?;

            let pk_output: OintPublicKey<'_> = OintPublicKey {
                public_key: &pk,
                alg: str64::from_str(SLUG20_ABSOLVESIGNING_ID).unwrap(),
                encoding: encoding.as_label_str64()
            };
            let sk_output: OintSecretKey<'_> = OintSecretKey {
                secret_key: &sk,
                alg: str64::from_str(SLUG20_ABSOLVESIGNING_ID).unwrap(),
                encoding: encoding.as_label_str64(),
            };

            let output: OintKeypair<'a> = OintKeypair { 
                pkh: pk_output, 
                skh: sk_output,
                encoding: encoding.as_label_str64(),
                alg: str64::from_str(SLUG20_ABSOLVESIGNING_ID).unwrap(),
            };

            return Ok(output)
        }
        else if x == SLUG20_BLS_12_381_ID.to_ascii_uppercase() {
            let bls: BLSSecretKey = BLSSecretKey::generate();
            unimplemented!();
        }
        else if x == SLUG20_ECDSA_SECP256k1_ID.to_ascii_uppercase() {
            let encoding = OintEncoding::new(OintKeyEncodings::Hex);
            
            let ecdsa: ECDSASecretKey = ECDSASecretKey::generate();
            let ecdsa_pk: ECDSAPublicKey = ecdsa.public_key()?;

            let sk_hex = ecdsa.to_hex()?;
            let pk_hex = ecdsa_pk.to_hex()?;

            let sk_output: OintSecretKey<'_> = OintSecretKey {
                secret_key: &sk_hex,
                alg: str64::from_str(&SLUG20_ECDSA_SECP256k1_ID.to_ascii_uppercase()).unwrap(),
                encoding: encoding.as_label_str64()
            };
            let pk_output: OintPublicKey<'_> = OintPublicKey {
                public_key: &pk_hex,
                alg: str64::from_str(&SLUG20_ECDSA_SECP256k1_ID.to_ascii_uppercase()).unwrap(),
                encoding: encoding.as_label_str64()
            };

            let output: OintKeypair<'_> = OintKeypair {
                pkh: pk_output,
                skh: sk_output,
                encoding: encoding.as_label_str64(),
                alg: str64::from_str(&SLUG20_ECDSA_SECP256k1_ID.to_ascii_uppercase()).unwrap()
            };

            return Ok(output)
        }
        else if x == SLUG20_ED25519_ID.to_ascii_uppercase() {
            let ed25519: ED25519SecretKey = ED25519SecretKey::generate();
            let ed25519_pk: ED25519PublicKey = ed25519.public_key()?;

            let ed25519_hex = ed25519.to_hexadecimal()?;
            let ed25519_pk_hex = ed25519_pk.to_hexadecimal()?;

            let pk: OintPublicKey<'_> = OintPublicKey {
                public_key: &ed25519_pk_hex,
                alg: str64::from_str(&SLUG20_ED25519_ID.to_ascii_uppercase()).unwrap(),
                encoding: str64::from_str("hex").unwrap()
            };
            let sk: OintSecretKey<'_> = OintSecretKey {
                secret_key: &ed25519_hex,
                alg: str64::from_str(&SLUG20_ED25519_ID.to_ascii_uppercase()).unwrap(),
                encoding: str64::from_str("hex").unwrap()
            };

            return Ok(
                OintKeypair { 
                    pkh: pk, 
                    skh: sk, 
                    encoding: str64::from_str("hex").unwrap(), 
                    alg: str64::from_str(&SLUG20_ED25519_ID.to_ascii_uppercase()).unwrap() 
                }
            )
        }
        else if x == SLUG20_ED448_ID.to_ascii_uppercase() {
            let ed448: Ed448SecretKey = Ed448SecretKey::generate();
            let ed448_pk: Ed448PublicKey = ed448.into_public_key();

            let ed448_hex = ed448.to_hex()?;
            let ed448_pk_hex = ed448_pk.to_hex()?;

            let pk: OintPublicKey<'_> = OintPublicKey {
                public_key: &ed448_pk_hex,
                alg: str64::from_str(&SLUG20_ED448_ID.to_ascii_uppercase()).unwrap(),
                encoding: str64::from_str("hex").unwrap()
            };
            let sk: OintSecretKey<'_> = OintSecretKey {
                secret_key: &ed448_hex,
                alg: str64::from_str(&SLUG20_ED448_ID.to_ascii_uppercase()).unwrap(),
                encoding: str64::from_str("hex").unwrap()
            };

            return Ok(
                OintKeypair { 
                    pkh: pk, 
                    skh: sk, 
                    encoding: str64::from_str("hex").unwrap(), 
                    alg: str64::from_str(&SLUG20_ED448_ID.to_ascii_uppercase()).unwrap() 
                }
            )

        }
        else if x == SLUG20_ESPHANDSIGNING_ID.to_ascii_uppercase() {
            let encoding: OintEncoding = OintEncoding::new(OintKeyEncodings::X59FMT);
            
            let esphandsigning: EsphandKeypair = EsphandKeypair::generate();
            
            let esphand_sk = esphandsigning.into_x59()?;
            let esphand_pk = esphandsigning.into_x59_pk()?;

            let pk: OintPublicKey<'_> = OintPublicKey {
                public_key: &esphand_pk,
                alg: str64::from_str(&x.to_ascii_uppercase()).unwrap(),
                encoding: encoding.as_label_str64()
            };

            let sk: OintSecretKey<'_> = OintSecretKey {
                secret_key: &esphand_sk,
                alg: str64::from_str(&x.to_ascii_uppercase()).unwrap(),
                encoding: encoding.as_label_str64(),
            }

            return Ok(
                OintKeypair { 
                    pkh: pk, 
                    skh: sk, 
                    encoding: encoding.as_label_str64(), 
                    alg: str64::from_str(&x.to_ascii_uppercase()).unwrap() 
                }
            )
        }
        else if x == SLUG20_FALCON1024_ID.to_ascii_uppercase() {
            let encoding = OintEncoding::new(OintKeyEncodings::Hex);
            
            let falcon: (Falcon1024PublicKey, Falcon1024SecretKey) = SlugFalcon1024::generate();

            let falcon_pk_hex = falcon.0.to_hex()?;
            let falcon_sk_hex = falcon.1.to_hex()?;

            let pk: OintPublicKey<'_> = OintPublicKey {
                public_key: &falcon_pk_hex,
                alg: str64::from_str(&x.to_ascii_uppercase()).unwrap(),
                encoding: encoding.as_label_str64()
            };
            let sk: OintSecretKey<'_> = OintSecretKey {
                secret_key: &falcon_sk_hex,
                alg: str64::from_str(&x.to_ascii_uppercase()).unwrap(),
                encoding: encoding.as_label_str64()
            };

            return Ok(
                OintKeypair { 
                    pkh: pk, 
                    skh: sk, 
                    encoding: encoding.as_label_str64(), 
                    alg: str64::from_str(&x.to_ascii_uppercase()).unwrap() 
                }
            )
        }
        else if x == SLUG20_MLDSA3_ID.to_ascii_uppercase() {
            let mldsa3: MLDSA3Keypair = SlugMLDSA3::generate();
            let mldsa3_pk = mldsa3.public_key();
            let mldsa3_sk = mldsa3.secret_key();

            let mldsa3_pk_hex = mldsa3_pk.to_hex()?;
            let mldsa3_sk_hex = mldsa3_sk.to_hex()?;

            let pk: OintPublicKey<'_> = OintPublicKey {
                public_key: &mldsa3_pk_hex,
                alg: str64::from_str(&x.to_ascii_uppercase()).unwrap(),
                encoding: str64::from_str("hex").unwrap()
            };
            let sk: OintSecretKey<'_> = OintSecretKey {
                secret_key: &mldsa3_sk_hex,
                alg: str64::from_str(&x.to_ascii_uppercase()).unwrap(),
                encoding: str64::from_str("hex").unwrap()
            };

            return Ok(
                OintKeypair { 
                    pkh: pk, 
                    skh: sk, 
                    encoding: str64::from_str("hex").unwrap(), 
                    alg: str64::from_str(&x.to_ascii_uppercase()).unwrap() 
                }
            )
        }
        else if x == SLUG20_SCHNORR_ID.to_ascii_uppercase() {
            let schnorr: SchnorrSecretKey = SchnorrSecretKey::generate();
            let schnorr_pk: SchnorrPublicKey = schnorr.public_key().expect("Failed To Generate Public Key For Schnorr");

            let schnorr_pk_hex: String = schnorr_pk.to_hex_string()?;
            let schnorr_sk_hex: String = schnorr.to_hex_string()?;

            let pk: OintPublicKey<'_> = OintPublicKey {
                public_key: &schnorr_pk_hex,
                alg: str64::from_str(&x.to_ascii_uppercase()).unwrap(),
                encoding: str64::from_str("hex").unwrap()
            };
            let sk: OintSecretKey<'_> = OintSecretKey {
                secret_key: &schnorr_sk_hex,
                alg: str64::from_str(&x.to_ascii_uppercase()).unwrap(),
                encoding: str64::from_str("hex").unwrap()
            };

            return Ok(
                OintKeypair { 
                    pkh: pk, 
                    skh: sk, 
                    encoding: str64::from_str("hex").unwrap(), 
                    alg: str64::from_str(&x.to_ascii_uppercase()).unwrap() 
                }
            )
        }
        else if x == SLUG20_SHULGINSIGNING_ID.to_ascii_uppercase() {
            let shulginsigning: ShulginKeypair = ShulginKeypair::generate();

            let shulginsigning_pk = shulginsigning.into_x59_pk()?;
            let shulginsigning_sk = shulginsigning.to_x59_format_full()?;

            let pk: OintPublicKey<'_> = OintPublicKey {
                public_key: &shulginsigning_pk,
                alg: str64::from_str(&x.to_ascii_uppercase()).unwrap(),
                encoding: str64::from_str("x59-fmt").unwrap()
            };
            let sk: OintSecretKey<'_> = OintSecretKey {
                secret_key: &shulginsigning_sk,
                alg: str64::from_str(&x.to_ascii_uppercase()).unwrap(),
                encoding: str64::from_str("x59-fmt").unwrap()
            };

            return Ok(
                OintKeypair { 
                    pkh: pk, 
                    skh: sk, 
                    encoding: str64::from_str("x59-fmt").unwrap(), 
                    alg: str64::from_str(&x.to_ascii_uppercase()).unwrap() 
                }
            )

        }
        else if x == SLUG20_SPHINCS_PLUS_ID.to_ascii_uppercase() {
            let encoding = OintEncoding::new(OintKeyEncodings::Hex);
            
            let sphincs: (SPHINCSPublicKey, SPHINCSSecretKey) = SPHINCSSecretKey::generate();
            let sphincs_pk_hex = sphincs.0.to_hex()?;
            let sphincs_sk_hex = sphincs.1.to_hex()?;

            let pk: OintPublicKey<'_> = OintPublicKey {
                public_key: &sphincs_pk_hex,
                alg: str64::from_str(&x.to_ascii_uppercase()).unwrap(),
                encoding: str64::from_str("hex").unwrap()
            };
            let sk: OintSecretKey<'_> = OintSecretKey {
                secret_key: &sphincs_sk_hex,
                alg: str64::from_str(&x.to_ascii_uppercase()).unwrap(),
                encoding: str64::from_str("hex").unwrap()
            };

            return Ok(
                 OintKeypair { 
                    pkh: pk, 
                    skh: sk, 
                    encoding: str64::from_str("hex").unwrap(), 
                    alg: str64::from_str(&x.to_ascii_uppercase()).unwrap() 
                }
            )
        }
        else {
            return Err(SlugErrors::Other(String::from("No Valid Algorithm To Generate")))
        }
    }
}
    */

pub struct OintPublicKey<'a> {
    pub public_key: &'a str,
    

    pub alg: str64,
    pub encoding: str64,
}

pub struct OintSecretKey<'a> {
    pub secret_key: &'a str,
    
    pub alg: str64,
    pub encoding: str64,
}

pub struct OintSignature<'a> {
    pub signature: &'a str,
    
    pub alg: str64,
    pub encoding: str64,
}

pub struct OintEncoding(pub OintKeyEncodings);

impl OintEncoding {
    pub fn new(encoding: OintKeyEncodings) -> Self {
        return Self(encoding)
    }
    pub fn as_label(&self) -> &str {
        return self.0.as_label()
    }
    pub fn as_label_str64(&self) -> str64 {
        return str64::from_str(&self.as_label()).unwrap()
    }
}

/* 
impl GenerateKeypair for OintKeypair<'a> {
    fn generate<T: AsRef<str>>(algorithm: T) -> Self {
        let x = match algorithm.as_ref() {
            "slug20/shulginsigning" => Keypairs::ShulginSigning(ShulginKeypair::generate()),
            "slug20/esphandsigning" => Keypairs::EsphandSigning(EsphandKeypair::generate()),
            "slug20/ed25519" => {
                let x = ed25519::ED25519SecretKey::generate();
                let pkh = x.public_key().unwrap();
                Keypairs::ED25519(x, pkh)
            }
            "slug20/ecdsa" => {
                let x = ecdsa::ECDSASecretKey::generate();
                let pkh = x.public_key().unwrap();
                Keypairs::ECDSA(x, pkh)
            },
            "slug20/bls" => {
                let (pkh,sk) = bls::SlugBLS::generate();
                Keypairs::BLS(sk, pkh)
            }
            "slug20/schnorr" => {
                let skh = schnorr::SchnorrSecretKey::generate();
                let pk = skh.public_key().unwrap();
                Keypairs::Schnorr(skh, pk)
            }
            _ => panic!("Invalid Value")
        }
        
        let x = ShulginKeypair::generate();
    }
}
    */

/// # Keypairs: List of Available Keypairs
pub enum Keypairs {
    //=====Hybrid=====//
    ShulginSigning(ShulginKeypair),
    EsphandSigning(EsphandKeypair),
    AbsolveSigning(AbsolveKeypair),
    
    //=====CLASSICAL=====//
    ED25519(ED25519PublicKey,ED25519SecretKey),
    ED448(Ed448PublicKey,Ed448SecretKey),
    ECDSA(ECDSAPublicKey,ECDSASecretKey),
    BLS12381(BLSPublicKey,BLSSecretKey),
    Schnorr(SchnorrPublicKey,SchnorrSecretKey),

    //=====POST-QUANTUM=====//
    FALCON1024(Falcon1024PublicKey,Falcon1024SecretKey),
    SPHINCS_PLUS(SPHINCSPublicKey,SPHINCSSecretKey),
    MLDSA(MLDSA3PublicKey,MLDSA3SecretKey),
}
*/