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

use crate::traits::{OintGenerateKeypair,OintVerify,OintSign};
use crate::constants::*;
use crate::encodings::OintKeyEncodings;

use serde::{Serialize,Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};


type PublicKey = fixedstr::tstr<16_000>;
type SecretKey = fixedstr::tstr<16_000>;

pub mod Liberato {

    use libslug::slugcrypt::internals::signature::absolvesigning::AbsolveKeypair;
    use zeroize::{Zeroize,ZeroizeOnDrop};
    use serde::{Serialize,Deserialize};
    use crate::algorithms::slug::{SlugPublicKey,SlugSecretKey,SlugSignature};
    use crate::algorithms::slug::Algorithms;
    use crate::traits::liberato_traits::{LiberatoKeypairTrait,LiberatoPublicKeyTrait,LiberatoSecretKeyTrait,LiberatoX59Encoding};


    #[derive(Clone, Debug, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
    pub struct LiberatoKeypair {
        pub pk: LiberatoPublicKey,
        pub sk: LiberatoSecretKey,
    }

    impl LiberatoKeypairTrait for LiberatoKeypair {
        fn generate(alg: crate::algorithms::slug::Algorithms) -> Result<Self,libslug::prelude::core::SlugErrors> {
            match alg {
                Algorithms::AbsolveSigning => {
                    let x: AbsolveKeypair = AbsolveKeypair::generate();
                    
                }
                Algorithms::BLS12_381 => {

                }
                Algorithms::ECDSA => {

                }
                Algorithms::ED25519 => {

                }
                Algorithms::ED448 => {

                }
                Algorithms::EsphandSigning => {

                }
                Algorithms::Falcon1024 => {

                }
                Algorithms::MLDSA3 => {

                }
                Algorithms::Schnorr => {

                }
                Algorithms::ShulginSigning => {

                }
                Algorithms::Sphincs => {

                }
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
    pub struct LiberatoPublicKey {
        pub pk: SlugPublicKey,
    }

    #[derive(Clone, Debug, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
    pub struct LiberatoSecretKey {
        pub sk: SlugSecretKey
    }

    #[derive(Clone, Debug, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
    pub struct LiberatoSignature {
        pub signature: SlugSignature,
    }

}

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