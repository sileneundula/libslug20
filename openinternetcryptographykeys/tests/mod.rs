use openinternetcryptographykeys::prelude::*;



#[test]
fn generate_absolve_signing_key() {
    let absolve_signing = OpenInternetCryptographyAPI::generate(Algorithms::AbsolveSigning);
}

#[test]
fn generate_shulgin_signing_key() {
    let shulgin_signing = OpenInternetCryptographyAPI::generate(Algorithms::ShulginSigning);
}

#[test]
fn generate_esphand_signing_key() {
    let esphand_signing = OpenInternetCryptographyAPI::generate(Algorithms::EsphandSigning);
}

#[test]
fn generate_and_export_absolve_signing_key() {
    let absolve_signing: (OintPublicKey, OintSecretKey) = OpenInternetCryptographyAPI::generate(Algorithms::AbsolveSigning);
    let pem: Result<String, libslug::prelude::core::SlugErrors> = absolve_signing.0.into_pem_public();
    let pem_secret: Result<String, libslug::prelude::core::SlugErrors> = absolve_signing.1.into_pem_secret();
    println!("Absolve PEM:\n{}", pem.unwrap());
    println!("Absolve Secret PEM:\n{}", pem_secret.unwrap());
}

#[test]
fn generate_and_export_shulgin_signing_key() {
    let shulgin_signing: (OintPublicKey, OintSecretKey) = OpenInternetCryptographyAPI::generate(Algorithms::ShulginSigning);
    let pem: Result<String, libslug::prelude::core::SlugErrors> = shulgin_signing.0.into_pem_public();
    let pem_secret: Result<String, libslug::prelude::core::SlugErrors> = shulgin_signing.1.into_pem_secret();
    println!("Shulgin PEM:\n{}", pem.unwrap());
    println!("Shulgin Secret PEM:\n{}", pem_secret.unwrap());
}

#[test]
fn generate_and_export_esphand_signing_key() {
    let esphand_signing: (OintPublicKey, OintSecretKey) = OpenInternetCryptographyAPI::generate(Algorithms::EsphandSigning);
    let pem: Result<String, libslug::prelude::core::SlugErrors> = esphand_signing.0.into_pem_public();
    let pem_secret: Result<String, libslug::prelude::core::SlugErrors> = esphand_signing.1.into_pem_secret();
    println!("Esphand PEM:\n{}", pem.unwrap());
    println!("Esphand Secret PEM:\n{}", pem_secret.unwrap());
}

#[test]
fn testing_from_pem_shulgin_signing() {
    let shulgin_signing: (OintPublicKey, OintSecretKey) = OpenInternetCryptographyAPI::generate(Algorithms::ShulginSigning);
    let pem: Result<String, libslug::prelude::core::SlugErrors> = shulgin_signing.0.into_pem_public();
    let pem_secret: Result<String, libslug::prelude::core::SlugErrors> = shulgin_signing.1.into_pem_secret();
    let msg: &str = "Example Message For Signing With OpenInternetCryptographyAPI";

    let sig: OintSignature = shulgin_signing.1.sign(msg).unwrap();
    let is_valid = shulgin_signing.0.verify(msg, &sig).unwrap();

    assert_eq!(is_valid, true);

    let key1: OintPublicKey = OintPublicKey::from_pem(pem.unwrap(), Algorithms::ShulginSigning).unwrap();
    let key2: OintSecretKey = OintSecretKey::from_pem_with_algorithm(pem_secret.unwrap(), Algorithms::ShulginSigning).unwrap();

    key1.verify(msg, &sig).unwrap();
}