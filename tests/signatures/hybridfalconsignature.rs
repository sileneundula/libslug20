use libslug::slugcrypt::internals::signature::esphand_signature::EsphandKeypair;
use libslug::slugcrypt::internals::signature::esphand_signature::EsphandSignature;

#[test]
fn generate() {
    let keypair = EsphandKeypair::generate();
}

#[test]
fn signing() {
    let keypair = EsphandKeypair::generate();
    let msg: &str = "This is a default message for hybridfalcon keypair (needs name)";
    let output = keypair.sign(msg).expect("Failed To Sign");
}

#[test]
fn verifying() {
    let keypair = EsphandKeypair::generate();
    let msg: &str = "This is a default message for hybridfalcon keypair (needs name)";
    let output = keypair.sign(msg).expect("Failed To Sign");
    let is_valid = keypair.verify(msg, &output).expect("Failed to Verify Signature");
}

#[test]
fn verifying_and_exporting() {
    let keypair = EsphandKeypair::generate();
    let msg: &str = "This is a default message for hybridfalcon keypair (needs name)";
    let output = keypair.sign(msg).expect("Failed To Sign");
    let keypair_x59 = keypair.to_x59_public_key().expect("Failed to export");

    let new_keypair = EsphandKeypair::from_x59_public_key(keypair_x59).expect("Failed to convert to new keypair");
    let is_valid_new = new_keypair.verify(msg, &output).expect("Failed to get value");
    let is_valid = keypair.verify(msg, &output).expect("Failed to Verify Signature");

    assert_eq!(is_valid,true);
    assert_eq!(is_valid_new,true);
}