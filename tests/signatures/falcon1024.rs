use libslug::slugcrypt::internals::signature::falcon::*;

#[test]
fn generate() {
    let (_pk, _sk) = SlugFalcon1024::generate();
}

#[test]
fn signing() {
    let (_pk, sk) = SlugFalcon1024::generate();
    let msg = "This is a falcon signed message";
    let _signature = sk.sign(msg).expect("No Errors In FalconSigning");
}

#[test]
fn signing_and_verifying() {
    let (pk, sk) = SlugFalcon1024::generate();
    let msg = "This is a falcon signed message";
    let signature = sk.sign(msg).expect("No Errors In FalconSigning");
    let is_valid = pk.verify(msg, &signature).expect("Shouldnt throw an error");

    assert_eq!(is_valid,true)
}