use libslug::slugfmt::key;
use openinternetcryptographykeys::prelude::essentials::{OpenInternetAPIGeneration, OpenInternetCryptographyKeypair, OpenInternetCryptographySecretKey, OpenInternetFromPemAny, Slug20Algorithm};
use openinternetcryptographykeys::prelude::essentials::{OpenInternetFromStandardPEM,OpenInternetGeneration,OpenInternetIntoStandardPEM,OpenInternetSigner,OpenInternetVerifier};
use openinternetcryptographykeys::prelude::essentials::OpenInternetCryptographyPublicKey;
use openinternetcryptographykeys::prelude::essentials::OpenInternetCryptographySignature;
use openinternetcryptographykeys::prelude::essentials::FromPemAny;
use openinternetcryptographykeys::prelude::essentials::OpenInternetCryptographyAPI;

#[test]
fn into_pem() {

    let key1_absolve: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::AbsolveSigning).unwrap();
    let key2_bls: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::BLS).unwrap();
    let key3_ecdsa: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::ECDSA).unwrap();
    let key4_ed25519: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::Ed25519).unwrap();
    let key5_ed448: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::Ed448).unwrap();
    let key6_esphandsigning: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::EsphandSigning).unwrap();
    let key7_falcon: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::Falcon).unwrap();
    let key8_mldsa: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::MLDSA).unwrap();
    let key9_sphincsplus: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::SPHINCSPlus).unwrap();
    let key10_schnorr: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::Schnorr).unwrap();
    let key11_shulginsigning: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::ShulginSigning).unwrap();
    //let key12 = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::ECDSA);

    let key1_absolve_pem: String = key1_absolve.as_secret_key().into_standard_pem().unwrap();
    let key2_bls_pem: String = key2_bls.as_secret_key().into_standard_pem().unwrap();
    let key3_ecdsa_pem: String = key3_ecdsa.as_secret_key().into_standard_pem().unwrap();
    let key4_ed25519_pem: String = key4_ed25519.as_secret_key().into_standard_pem().unwrap();
    let key5_ed448_pem: String = key5_ed448.as_secret_key().into_standard_pem().unwrap();
    let key6_esphandsigning_pem: String = key6_esphandsigning.as_secret_key().into_standard_pem().unwrap();
    let key7_falcon_pem: String = key7_falcon.as_secret_key().into_standard_pem().unwrap();
    let key8_mldsa_pem: String = key8_mldsa.as_secret_key().into_standard_pem().unwrap();
    let key9_sphincsplus_pem: String = key9_sphincsplus.as_secret_key().into_standard_pem().unwrap();
    let key10_schnorr_pem: String = key10_schnorr.as_secret_key().into_standard_pem().unwrap();
    let key11_shulginsigning_pem: String = key11_shulginsigning.as_secret_key().into_standard_pem().unwrap();

    let key1_absolve_pem_pk: String = key1_absolve.as_public_key().into_standard_pem().unwrap();
    let key2_bls_pem_pk: String = key2_bls.as_public_key().into_standard_pem().unwrap();
    let key3_ecdsa_pem_pk: String = key3_ecdsa.as_public_key().into_standard_pem().unwrap();
    let key4_ed25519_pem_pk: String = key4_ed25519.as_public_key().into_standard_pem().unwrap();
    let key5_ed448_pem_pk: String = key5_ed448.as_public_key().into_standard_pem().unwrap();
    let key6_esphandsigning_pem_pk: String = key6_esphandsigning.as_public_key().into_standard_pem().unwrap();
    let key7_falcon_pem_pk: String = key7_falcon.as_public_key().into_standard_pem().unwrap();
    let key8_mldsa_pem_pk: String = key8_mldsa.as_public_key().into_standard_pem().unwrap();
    let key9_sphincsplus_pem_pk: String = key9_sphincsplus.as_public_key().into_standard_pem().unwrap();
    let key10_schnorr_pem_pk: String = key10_schnorr.as_public_key().into_standard_pem().unwrap();
    let key11_shulginsigning_pem_pk: String = key11_shulginsigning.as_public_key().into_standard_pem().unwrap();
}


#[test]
fn from_pem_any() {

    let key1_absolve: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::AbsolveSigning).unwrap();
    let key2_bls: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::BLS).unwrap();
    let key3_ecdsa: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::ECDSA).unwrap();
    let key4_ed25519: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::Ed25519).unwrap();
    let key5_ed448: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::Ed448).unwrap();
    let key6_esphandsigning: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::EsphandSigning).unwrap();
    let key7_falcon: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::Falcon).unwrap();
    let key8_mldsa: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::MLDSA).unwrap();
    let key9_sphincsplus: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::SPHINCSPlus).unwrap();
    let key10_schnorr: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::Schnorr).unwrap();
    let key11_shulginsigning: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::ShulginSigning).unwrap();
    //let key12 = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::ECDSA);

    let key1_absolve_pem: String = key1_absolve.as_secret_key().into_standard_pem().unwrap();
    let key2_bls_pem: String = key2_bls.as_secret_key().into_standard_pem().unwrap();
    let key3_ecdsa_pem: String = key3_ecdsa.as_secret_key().into_standard_pem().unwrap();
    let key4_ed25519_pem: String = key4_ed25519.as_secret_key().into_standard_pem().unwrap();
    let key5_ed448_pem: String = key5_ed448.as_secret_key().into_standard_pem().unwrap();
    let key6_esphandsigning_pem: String = key6_esphandsigning.as_secret_key().into_standard_pem().unwrap();
    let key7_falcon_pem: String = key7_falcon.as_secret_key().into_standard_pem().unwrap();
    let key8_mldsa_pem: String = key8_mldsa.as_secret_key().into_standard_pem().unwrap();
    let key9_sphincsplus_pem: String = key9_sphincsplus.as_secret_key().into_standard_pem().unwrap();
    let key10_schnorr_pem: String = key10_schnorr.as_secret_key().into_standard_pem().unwrap();
    let key11_shulginsigning_pem: String = key11_shulginsigning.as_secret_key().into_standard_pem().unwrap();

    let key1_absolve_pem_pk: String = key1_absolve.as_public_key().into_standard_pem().unwrap();
    let key2_bls_pem_pk: String = key2_bls.as_public_key().into_standard_pem().unwrap();
    let key3_ecdsa_pem_pk: String = key3_ecdsa.as_public_key().into_standard_pem().unwrap();
    let key4_ed25519_pem_pk: String = key4_ed25519.as_public_key().into_standard_pem().unwrap();
    let key5_ed448_pem_pk: String = key5_ed448.as_public_key().into_standard_pem().unwrap();
    let key6_esphandsigning_pem_pk: String = key6_esphandsigning.as_public_key().into_standard_pem().unwrap();
    let key7_falcon_pem_pk: String = key7_falcon.as_public_key().into_standard_pem().unwrap();
    let key8_mldsa_pem_pk: String = key8_mldsa.as_public_key().into_standard_pem().unwrap();
    let key9_sphincsplus_pem_pk: String = key9_sphincsplus.as_public_key().into_standard_pem().unwrap();
    let key10_schnorr_pem_pk: String = key10_schnorr.as_public_key().into_standard_pem().unwrap();
    let key11_shulginsigning_pem_pk: String = key11_shulginsigning.as_public_key().into_standard_pem().unwrap();

    let msg = "hello world";

    let signature1_absolve: OpenInternetCryptographySignature = key1_absolve.as_secret_key().sign(msg).unwrap();
    let signature2_bls: OpenInternetCryptographySignature = key2_bls.as_secret_key().sign(msg).unwrap();
    let signature3_ecdsa: OpenInternetCryptographySignature = key3_ecdsa.as_secret_key().sign(msg).unwrap();
    let signature4_ed25519: OpenInternetCryptographySignature = key4_ed25519.as_secret_key().sign(msg).unwrap();
    let signature5_ed448: OpenInternetCryptographySignature = key5_ed448.as_secret_key().sign(msg).unwrap();
    let signature6_esphandsigning: OpenInternetCryptographySignature = key6_esphandsigning.as_secret_key().sign(msg).unwrap();
    let signature7_falcon: OpenInternetCryptographySignature = key7_falcon.as_secret_key().sign(msg).unwrap();
    let signature8_mldsa: OpenInternetCryptographySignature = key8_mldsa.as_secret_key().sign(msg).unwrap();
    let signature9_sphincs: OpenInternetCryptographySignature = key9_sphincsplus.as_secret_key().sign(msg).unwrap();
    let signature10_schnorr: OpenInternetCryptographySignature = key10_schnorr.as_secret_key().sign(msg).unwrap();
    let signature11_shulginsigning: OpenInternetCryptographySignature = key11_shulginsigning.as_secret_key().sign(msg).unwrap();

    let signature1_absolve_pem: String = signature1_absolve.into_standard_pem().unwrap();
    let signature2_bls_pem: String = signature2_bls.into_standard_pem().unwrap();
    let signature3_ecdsa_pem: String = signature3_ecdsa.into_standard_pem().unwrap();
    let signature4_ed25519_pem: String = signature4_ed25519.into_standard_pem().unwrap();
    let signature5_ed448_pem: String = signature5_ed448.into_standard_pem().unwrap();
    let signature6_esphandsigning_pem: String = signature6_esphandsigning.into_standard_pem().unwrap();
    let signature7_falcon_pem: String = signature7_falcon.into_standard_pem().unwrap();
    let signature8_mldsa_pem: String = signature8_mldsa.into_standard_pem().unwrap();
    let signature9_sphincs_pem: String = signature9_sphincs.into_standard_pem().unwrap();
    let signature10_schnorr_pem: String = signature10_schnorr.into_standard_pem().unwrap();
    let signature11_shulginsigning_pem: String = signature11_shulginsigning.into_standard_pem().unwrap();

    let mut x: Vec<String> = vec![];

    x.push(key1_absolve_pem);
    x.push(key2_bls_pem);
    x.push(key3_ecdsa_pem);
    x.push(key4_ed25519_pem);
    x.push(key5_ed448_pem);
    x.push(key6_esphandsigning_pem);
    x.push(key7_falcon_pem);
    x.push(key8_mldsa_pem);
    x.push(key9_sphincsplus_pem);
    x.push(key10_schnorr_pem);
    x.push(key11_shulginsigning_pem);

    x.push(key1_absolve_pem_pk);
    x.push(key2_bls_pem_pk);
    x.push(key3_ecdsa_pem_pk);
    x.push(key4_ed25519_pem_pk);
    x.push(key5_ed448_pem_pk);
    x.push(key6_esphandsigning_pem_pk);
    x.push(key7_falcon_pem_pk);
    x.push(key8_mldsa_pem_pk);
    x.push(key9_sphincsplus_pem_pk);
    x.push(key10_schnorr_pem_pk);
    x.push(key11_shulginsigning_pem_pk);

    x.push(signature1_absolve_pem);
    x.push(signature2_bls_pem);
    x.push(signature3_ecdsa_pem);
    x.push(signature4_ed25519_pem);
    x.push(signature5_ed448_pem);
    x.push(signature6_esphandsigning_pem);
    x.push(signature7_falcon_pem);
    x.push(signature8_mldsa_pem);
    x.push(signature9_sphincs_pem);
    x.push(signature10_schnorr_pem);
    x.push(signature11_shulginsigning_pem);

    for z in x {
        let y: Result<FromPemAny, libslug::prelude::core::SlugErrors> = OpenInternetCryptographyAPI::from_pem(&z);
        if y.is_err() {
            println!("Error: {}", z.clone());
        }
    }
}