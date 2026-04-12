use libslug::slugcrypt::internals::encrypt::chacha20::*;

fn main() {
    println!("Generating XChaCha20 Key:");
    
    // Generate Encryption Key Using 32-bytes of OSCSPRNG
    let key = EncryptionKey::generate();

    // Get The Key As A Hex Using Constant-Time Encoding
    let key_hex = key.to_hex().unwrap();

    println!("Key Hex (Using Constant-Time(ish)): {}", &key_hex);

    // Encrypt Message Using XChaCha20-Poly1305
    let (eciphertext, nonce) = XChaCha20Encrypt::encrypt(key, "This message is to be encrypted using XCHACHA20-POLY1305").unwrap();

    // Get the Message As Bytes
    let message = XChaCha20Encrypt::decrypt(EncryptionKey::from_hex(&key_hex).unwrap(), nonce, eciphertext).unwrap();

    // Get Message as UTF-8
    let decoded_msg = String::from_utf8(message).unwrap();

    println!("Decoded Message: {}", decoded_msg);
}