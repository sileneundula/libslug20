use oint_keys::{algorithms::slug::Algorithms, prelude::{traits::{OintKeypairTrait, OintSigning, OintVerification}, *}};
use oint_keys::key::oint_keys::OpenInternetKeypair;

#[test]
fn _0x00_ed448_generation() {
    let keypair = OpenInternetKeypair::generate(Algorithms::ED448).unwrap();
}

#[test]
fn _0x02_Ed448_generation_and_signing_no_context() {
    let keypair = OpenInternetKeypair::generate(Algorithms::ED448).unwrap();

    let sig = keypair.sign_with_context("Hello World.", None).unwrap();
}

#[test]
fn _0x01_Ed448_generation_and_signing_with_context() {
    let keypair = OpenInternetKeypair::generate(Algorithms::ED448).unwrap();

    let sig = keypair.sign_with_context("Hello World.", Some("RandomContext")).unwrap();
}

#[test]
fn _0x04_Ed448_generation_and_signing_no_context_verifying() {
    let keypair = OpenInternetKeypair::generate(Algorithms::ED448).unwrap();

    let msg = "Example Message";

    let sig = keypair.sign_with_context(msg, None).unwrap();

    let is_valid = keypair.pk.verify_with_context(msg, None, sig.as_ref()).unwrap();

    assert_eq!(is_valid,true);
}

#[test]
fn _0x03_Ed448_generation_and_signing_with_context_verifying() {
    let keypair = OpenInternetKeypair::generate(Algorithms::ED448).unwrap();

    let msg = "Example Message";
    let context = "Example Context";

    let sig = keypair.sign_with_context(msg, Some(context)).unwrap();

    let is_valid = keypair.pk.verify_with_context(msg, Some(context), sig.as_ref()).unwrap();

    assert_eq!(is_valid,true);
}


#[test]
fn _0x08_Ed448_wrong_context() {
    let keypair = OpenInternetKeypair::generate(Algorithms::ED448).unwrap();

    let msg = "Example Message";
    let context = "Example Context";
    let context_2: &str = "Not The Same Context";

    let sig = keypair.sign_with_context(msg, Some(context)).unwrap();

    let is_valid = keypair.pk.verify_with_context(msg, Some(context_2), sig.as_ref()).unwrap();

    assert_eq!(is_valid,true);
}

#[test]
#[should_panic]
fn _0x06_Ed448_wrong_message_with_context() {
    let keypair = OpenInternetKeypair::generate(Algorithms::ED448).unwrap();

    let msg = "Example Message";
    let msg_wrong = "Other Message";
    let context = "Example Context";

    let sig = keypair.sign_with_context(msg, Some(context)).unwrap();

    let is_valid = keypair.pk.verify_with_context(msg_wrong, Some(context), sig.as_ref()).unwrap();

    assert_eq!(is_valid,true);
}

#[test]
#[should_panic]
fn _0x07_Ed448_wrong_message_with_wrong_context() {
    let keypair = OpenInternetKeypair::generate(Algorithms::ED448).unwrap();

    let msg = "Example Message";
    let msg_wrong = "Other Message";
    let context = "Example Context";
    let context_wrong = "Other Context";

    let sig = keypair.sign_with_context(msg, Some(context)).unwrap();

    let is_valid = keypair.pk.verify_with_context(msg_wrong, Some(context_wrong), sig.as_ref()).unwrap();

    assert_eq!(is_valid,true);
}

#[test]
#[should_panic]
fn _0x05_Ed448_wrong_message_with_no_context() {
    let keypair = OpenInternetKeypair::generate(Algorithms::ED448).unwrap();

    let msg = "Example Message";
    let msg_wrong = "Other Message";
    let context = "Example Context";
    let context_wrong = "Other Context";

    let sig = keypair.sign_with_context(msg, Some(context)).unwrap();

    let is_valid = keypair.pk.verify_with_context(msg_wrong, None, sig.as_ref()).unwrap();

    assert_eq!(is_valid,true);
}

#[test]
#[should_panic]
fn _0x09_Ed448_right_message_with_no_context_after_signing_with_context() {
    let keypair = OpenInternetKeypair::generate(Algorithms::ED448).unwrap();

    let msg = "Example Message";
    let msg_wrong = "Other Message";
    let context = "Example Context";
    let context_wrong = "Other Context";

    let sig = keypair.sign_with_context(msg, Some(context)).unwrap();

    let is_valid = keypair.pk.verify_with_context(msg, None, sig.as_ref()).unwrap();

    assert_eq!(is_valid,true);
}

#[test]
#[should_panic]
fn _0x0A_Ed448_right_message_with_no_context_after_signing_with_no_context_and_providing_context() {
    let keypair = OpenInternetKeypair::generate(Algorithms::ED448).unwrap();

    let msg = "Example Message";
    let msg_wrong = "Other Message";
    let context = "Example Context";
    let context_wrong = "Other Context";

    let sig = keypair.sign_with_context(msg, None).unwrap();

    let is_valid = keypair.pk.verify_with_context(msg, Some(context), sig.as_ref()).unwrap();

    assert_eq!(is_valid,true);
}

#[test]
#[should_panic]
fn _0x0B_Ed448_wrong_signature() {
    let keypair = OpenInternetKeypair::generate(Algorithms::ED448).unwrap();

    let msg = "Example Message";
    let msg_wrong = "Other Message";
    let context = "Example Context";
    let context_wrong = "Other Context";

    let sig = keypair.sign_with_context(msg, None).unwrap();
    let sig2 = keypair.sign_with_context(msg_wrong, None).unwrap();

    let is_valid = keypair.pk.verify_with_context(msg, None, sig2.as_ref()).unwrap();

    assert_eq!(is_valid,true);
}