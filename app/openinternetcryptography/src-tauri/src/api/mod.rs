use libslug::errors::SlugErrors;
use libslug::slugfmt::key;
use openinternetcryptographykeys::prelude::*;
use openinternetcryptographykeys::prelude::essentials::{
    FromPemAny, OpenInternetCryptographyPublicKey, OpenInternetCryptographySecretKey, OpenInternetCryptographySignature, OpenInternetFromPemAny, OpenInternetFromStandardPEM, OpenInternetGeneration, OpenInternetIntoStandardPEM, OpenInternetSigner, OpenInternetVerifier, Slug20Algorithm
};
use openinternetcryptographykeys::prelude::essentials::OpenInternetCryptographyAPI;
use tauri::ipc::InvokeError;

pub struct OpenInternetCryptographyProjectAPI;

impl OpenInternetCryptographyProjectAPI {
    pub fn generate(alg: Slug20Algorithm) -> Result<OpenInternetCryptographySecretKey, SlugErrors> {
        let x = OpenInternetCryptographySecretKey::generate_with_algorithm(alg)?;
        Ok(x)
    }
    pub fn sign<T: AsRef<[u8]>>(
        key: OpenInternetCryptographySecretKey,
        message: T,
    ) -> Result<OpenInternetCryptographySignature, SlugErrors> {
        let x = key.sign(message)?;
        Ok(x)
    }
    pub fn verify<T: AsRef<[u8]>>(
        pk: &OpenInternetCryptographyPublicKey,
        message: T,
        signature: OpenInternetCryptographySignature,
    ) -> Result<bool, SlugErrors> {
        let x = pk.verify(message.as_ref(), &signature)?;
        Ok(x)
    }
    pub fn from_pem<T: AsRef<str>>(pem: T) -> Result<FromPemAny, SlugErrors> {
        let x: FromPemAny = OpenInternetCryptographyAPI::from_pem(pem.as_ref())?;
        Ok(x)
    }
}

/// # Generate Key
///
/// Tauri Generation of Keys Using Slug20Algorithm
#[tauri::command]
pub fn generate_with_algorithm(alg: Slug20Algorithm) -> Result<OpenInternetCryptographySecretKey, InvokeError> {
    let x = OpenInternetCryptographySecretKey::generate_with_algorithm(alg);

    if x.is_err() == true {
        return Err(InvokeError::from_error(x.unwrap_err()));
    } else {
        return Ok(x.unwrap());
    }
}