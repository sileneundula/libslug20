use oint_keys::prelude::algorithms::*;
use oint_keys::prelude::traits::*;
use oint_keys::prelude::errors::*;
use oint_keys::prelude::base::{OpenInternetKeypair,OpenInternetSecretKey,OpenInternetSignature,OpenInternetPublicKey};

fn main() {
    // Generate Keypair
    let keypair: OpenInternetKeypair = OpenInternetKeypair::generate(Algorithms::ED25519).unwrap();
    
    // Message To Sign
    let msg: &str = "Example Message";
    let context: &str = "RandomContext";
    
    // Sign
    let sig: Box<OpenInternetSignature> = keypair.sign_with_context(msg, Some(context)).unwrap();
    let result = keypair.pk.verify_with_context(msg, Some(context), sig.as_ref()).unwrap();

    println!("ED25519: {:?}", result);
}