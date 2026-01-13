use libslug::slugcrypt::internals::encryption::ecies::{ECIESDecrypt,ECIESEncrypt,ECPublicKey,ECSecretKey};
use libslug::slugcrypt::internals::messages::Message;
use libslug::slugcrypt::internals::ciphertext::CipherText;

#[test]
fn encrypt_ecies() {
    // Alice
    let sk_1 = ECSecretKey::generate();
    let message = "This message is for Bob from Alice";

    // Bob
    let sk_2 = ECSecretKey::generate();
    let pk_2 = sk_2.public_key();


    // Ciphertext to be decoded by Bob encrypted by Alice (not using secret key)
    let ciphertext = ECIESEncrypt::encrypt(&pk_2, message).unwrap();

    let decoded_message = ECIESDecrypt::decrypt(&sk_2, &ciphertext).unwrap();

    assert_eq!(decoded_message.message().unwrap(),message);
}

#[should_panic]
#[test]
fn encrypt_ecies_wrong_message() {
        // Alice
        let sk_1 = ECSecretKey::generate();
        let message = "This message is for Bob from Alice";
        let wrong_message = "This message is wrong";
    
        // Bob
        let sk_2 = ECSecretKey::generate();
        let pk_2 = sk_2.public_key();
    
    
        // Ciphertext to be decoded by Bob encrypted by Alice (not using secret key)
        let ciphertext = ECIESEncrypt::encrypt(&pk_2, message).unwrap();
    
        let decoded_message = ECIESDecrypt::decrypt(&sk_2, &ciphertext).unwrap();
    
        assert_eq!(decoded_message.message().unwrap(),wrong_message);
}

#[should_panic]
#[test]
fn encrypt_wrong_sk() {
        // Alice
        let sk_1 = ECSecretKey::generate();
        let message = "This message is for Bob from Alice";
    
        // Bob
        let sk_2 = ECSecretKey::generate();
        let pk_2 = sk_2.public_key();
    
    
        // Ciphertext to be decoded by Bob encrypted by Alice (not using secret key)
        let ciphertext = ECIESEncrypt::encrypt(&pk_2, message).unwrap();
    
        let decoded_message = ECIESDecrypt::decrypt(&sk_1, &ciphertext).unwrap();
    
        assert_eq!(decoded_message.message().unwrap(),message);
}