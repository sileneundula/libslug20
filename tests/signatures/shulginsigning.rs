use libslug::slugcrypt::internals::signature::shulginsigning::*;

#[test]
fn generate() {
    let keypair = ShulginKeypair::generate();
}

#[test]
fn generate_and_sign() {
    let keypair = ShulginKeypair::generate();
    let msg: &str = "This is a random message being signed by ShulginSigning.";
    let signature: Result<ShulginSignature, libslug::errors::SlugErrors> = keypair.sign(msg); 
}

#[test]
fn generate_and_sign_with_verify() {
    let keypair = ShulginKeypair::generate();
    let msg: &str = "This is a random message being signed by ShulginSigning.";
    let signature: Result<ShulginSignature, libslug::errors::SlugErrors> = keypair.sign(msg);
    let is_valid = keypair.verify(msg, &signature.unwrap()).unwrap();
    assert_eq!(is_valid,true);
}

#[test]
fn generate_and_sign_with_exported() {
    let keypair: ShulginKeypair = ShulginKeypair::generate();
    let msg: &str = "This message is being signed.";
    let signature = keypair.sign(msg).expect("Should not fail");

    let keypair_compact: ShulginKeypairCompact = keypair.into_compact().expect("Shouldnt have errors");
    let keypair_pk: String = keypair_compact.to_str_pk();
    let keypair_sk: String = keypair_compact.to_str_sk();

    let output_keypair = ShulginKeypair::from_compact_pk(keypair_pk).expect("Should not fail");
    let is_valid = output_keypair.verify(msg, &signature).expect("Should not fail");
}

#[test]
fn generate_and_sign_with_exported_sk() {
    let keypair: ShulginKeypair = ShulginKeypair::generate();
    let msg: &str = "This message is being signed.";
    let signature = keypair.sign(msg).expect("Should not fail");

    let keypair_compact: ShulginKeypairCompact = keypair.into_compact().expect("Shouldnt have errors");
    let keypair_pk: String = keypair_compact.to_str_pk();
    let keypair_sk: String = keypair_compact.to_str_sk();

    let new_keypair = ShulginKeypair::from_compact_keypair(keypair_pk, keypair_sk).expect("Failed To Get From Secret Key + Public Key");

    let msg2: &str = "This is a second message.";

    let signature2 = new_keypair.sign(msg2).expect("Should not fail");

    // Verify and check if they have been altered.
    let is_valid_1 = new_keypair.verify(msg, &signature.clone());
    let is_valid_2 = new_keypair.verify(msg2,&signature2.clone());
    let is_valid_3 = keypair.verify(msg,&signature.clone());
    let is_valid_4 = keypair.verify(msg2,&signature2.clone());

    //
    assert_eq!(is_valid_1.unwrap(),true);
    assert_eq!(is_valid_2.unwrap(),true);
    assert_eq!(is_valid_3.unwrap(),true);
    assert_eq!(is_valid_4.unwrap(),true);
}
