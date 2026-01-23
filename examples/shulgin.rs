use libslug::slugcrypt::internals::signature::shulginsigning::{ShulginKeypair,ShulginSignature};

fn main() {
    let message = "This message is being signed by ShulginSigning. This is a combination of ED25519 and SPHINCS+ (SHAKE256).";

    let keypair = ShulginKeypair::generate();
    let signature = keypair.sign(message).unwrap();
    let is_valid = keypair.verify(message, &signature).unwrap();

    assert_eq!(is_valid, true)
}