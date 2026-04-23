use openinternetcryptographykeys::prelude::essentials::*;
use openinternetcryptographykeys::prelude::essentials::{OpenInternetFromStandardPEM,OpenInternetGeneration,OpenInternetFromPemAny,OpenInternetIntoStandardPEM,OpenInternetSigner,OpenInternetVerifier};

#[test]
fn _0x00_generate_ECDSA_keypair() {
    let keypair: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::ECDSA).unwrap();
}

#[test]
fn _0x01_generate_ECDSA_and_sign_keypair() {
    let keypair: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::ECDSA).unwrap();
    let msg = "Example Message";
    let sig = keypair.as_secret_key().sign(msg).unwrap();
}

#[test]
fn _0x02_generate_ECDSA_and_sign_and_verify_keypair() {
    let keypair: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::ECDSA).unwrap();
    let msg: &str = "Example Message";
    let sig: OpenInternetCryptographySignature = keypair.as_secret_key().sign(msg).unwrap();
    let is_valid: bool = keypair.as_public_key().verify(msg, &sig).unwrap();
    assert_eq!(is_valid,true)
}

#[test]
fn _0x03_generate_ECDSA_and_sign_and_verify_with_invalid_message() {
    let keypair: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::ECDSA).unwrap();
    let msg: &str = "Example Message";
    let invalid_msg: &str = "Invalid Message";
    let sig: OpenInternetCryptographySignature = keypair.as_secret_key().sign(msg).unwrap();
    let is_valid = keypair.as_public_key().verify(invalid_msg, &sig).unwrap_or(false);
    assert_eq!(is_valid,false)
}

#[test]
fn _0x04_from_and_into_standard_pem_ECDSA() {
    let keypair: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::ECDSA).unwrap();
    let keypair_pem: String = keypair.as_public_key().into_standard_pem().unwrap();
    let keypair_from_pem: OpenInternetCryptographyPublicKey = OpenInternetCryptographyPublicKey::from_standard_pem_with_algorithm(keypair_pem.as_str(),Slug20Algorithm::ECDSA).unwrap();

    assert_eq!(keypair.as_public_key().to_owned(),keypair_from_pem);
}

#[test]
fn _0x05_from_and_into_standard_pem_ECDSA_secret() {
    let keypair: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::ECDSA).unwrap();
    let keypair_pem: String = keypair.as_secret_key().into_standard_pem().unwrap();
    let keypair_from_pem: OpenInternetCryptographySecretKey = OpenInternetCryptographySecretKey::from_standard_pem_with_algorithm(keypair_pem.as_str(),Slug20Algorithm::ECDSA).unwrap();

    assert_eq!(keypair.as_secret_key().to_owned(),keypair_from_pem);
}

#[test]
fn _0x06_from_and_into_standard_pem_ECDSA_signature() {
    let keypair: OpenInternetCryptographyKeypair = OpenInternetCryptographyKeypair::generate_with_algorithm(Slug20Algorithm::ECDSA).unwrap();
    let msg: &str = "Example Message";
    let sig: OpenInternetCryptographySignature = keypair.as_secret_key().sign(msg).unwrap();
    let pem_sig = sig.into_standard_pem().unwrap();

    let x = OpenInternetCryptographySignature::from_standard_pem_with_algorithm(pem_sig, Slug20Algorithm::ECDSA).unwrap();

    let is_valid: bool = keypair.as_public_key().verify(msg, &x).unwrap();
    assert_eq!(is_valid,true)
}