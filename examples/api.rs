use libslug::slugcrypt::api::{SlugCrypt,SlugDigest};

use libslug::slugcrypt::internals::encrypt::chacha20::{EncryptionKey,EncryptionNonce,EncryptionCipherText};
use libslug::slugcrypt::internals::encrypt::aes256;
use libslug::slugcrypt::api::SlugAsyCrypt;


fn main() {
    let key = EncryptionKey::generate();
    let key_hex = key.to_hex().unwrap();
    let data = "encrypted by xchacha20-poly1305";

    let crypt = SlugCrypt::encrypt(key, data).unwrap();

    let decrypted = SlugCrypt::decrypt(EncryptionKey::from_hex(&key_hex).unwrap(), crypt.1, crypt.0).unwrap();
    println!("Decrypted: {}", String::from_utf8(decrypted).unwrap());
}