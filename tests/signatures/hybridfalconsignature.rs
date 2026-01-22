use libslug::slugcrypt::internals::signature::hybridfalconsigning::HybridFalconKeypair;
use libslug::slugcrypt::internals::signature::hybridfalconsigning::HybridFalconSignature;

#[test]
fn generate() {
    let keypair = HybridFalconKeypair::generate();
}

#[test]
fn signing() {
    let keypair = HybridFalconKeypair::generate();
    let msg: &str = "This is a default message for hybridfalcon keypair (needs name)";
    let output = keypair.sign(msg).expect("Failed To Sign");
}

#[test]
fn verifying() {
    let keypair = HybridFalconKeypair::generate();
    let msg: &str = "This is a default message for hybridfalcon keypair (needs name)";
    let output = keypair.sign(msg).expect("Failed To Sign");
    let is_valid = keypair.verify(msg, &output).expect("Failed to Verify Signature");
}

#[test]
fn verifying_and_exporting() {
    let keypair = HybridFalconKeypair::generate();
    let msg: &str = "This is a default message for hybridfalcon keypair (needs name)";
    let output = keypair.sign(msg).expect("Failed To Sign");
    let keypair_x59 = keypair.to_x59_public_key().expect("Failed to export");

    let new_keypair = HybridFalconKeypair::from_x59_public_key(keypair_x59).expect("Failed to convert to new keypair");
    let is_valid_new = new_keypair.verify(msg, &output).expect("Failed to get value");
    let is_valid = keypair.verify(msg, &output).expect("Failed to Verify Signature");

    assert_eq!(is_valid,true);
    assert_eq!(is_valid_new,true);
}