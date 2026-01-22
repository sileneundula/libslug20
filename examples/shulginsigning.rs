use libslug::slugcrypt::internals::signature::shulginsigning::{ShulginKeypair,ShulginKeypairCompact,ShulginSignature,ShulginSignatureCompact};


fn main() {
    let keypair = ShulginKeypair::generate();

    let msg: &str = "This message is being signed by ShulginSigning without the attached rng";
    
    let signature = keypair.sign(msg).unwrap();

    let is_valid = keypair.verify(msg, signature.clone()).unwrap();

    let compact = signature.clone().into_x59_format();
    let compact_pk = ShulginKeypairCompact::from_pk(&keypair).unwrap();
}