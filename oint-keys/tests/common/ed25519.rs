//! # Testing
//! 
//! ## Tests
//! 
//! - [X] Generation (0x00)
//! - [X] Signing
//!     - [X] Signing With Context (0x01)
//!     - [X] Signing Without Context (0x02)
//! - [X] Generation, Signing, and Verifying
//!     - [X] Verifying With Context (pass) (0x03)
//!     - [X] Verifying Without Context (pass) (0x04)
//!     - [X] Verifying With Wrong Message And Without Context (panic) (0x05)
//!     - [X] Verifying With Wrong Message and With Context (panic) (0x06)
//!     - [X] Verifying With Wrong Message and Wrong Context (panic) (0x07)
//!     - [X] Verifying With Right Message and Wrong Context (panic/pass) (0x08)
//!     - [X] Verifying With Right Message and No Context After Context Has Been Provided (0x09)
//!     - [X] Verifying With Right Message And Signing No Context But Providing Context (0x0A)

use oint_keys::{algorithms::slug::Algorithms, prelude::{traits::{LiberatoKeypairTrait, LiberatoSigning, LiberatoVerification}, *}};

#[test]
fn _0x00_ed25519_generation() {
    let keypair = LiberatoKeypair::generate(Algorithms::ED25519).unwrap();
}

#[test]
fn _0x02_ed25519_generation_and_signing_no_context() {
    let keypair = LiberatoKeypair::generate(Algorithms::ED25519).unwrap();

    let sig = keypair.sign("Hello World.", None).unwrap();
}

#[test]
fn _0x01_ed25519_generation_and_signing_with_context() {
    let keypair = LiberatoKeypair::generate(Algorithms::ED25519).unwrap();

    let sig = keypair.sign("Hello World.", Some("RandomContext")).unwrap();
}

#[test]
fn _0x04_ed25519_generation_and_signing_no_context_verifying() {
    let keypair = LiberatoKeypair::generate(Algorithms::ED25519).unwrap();

    let msg = "Example Message";

    let sig = keypair.sign(msg, None).unwrap();

    let is_valid = keypair.pk.verify(msg, None, sig.as_ref()).unwrap();

    assert_eq!(is_valid,true);
}

#[test]
fn _0x03_ed25519_generation_and_signing_with_context_verifying() {
    let keypair = LiberatoKeypair::generate(Algorithms::ED25519).unwrap();

    let msg = "Example Message";
    let context = "Example Context";

    let sig = keypair.sign(msg, Some(context)).unwrap();

    let is_valid = keypair.pk.verify(msg, Some(context), sig.as_ref()).unwrap();

    assert_eq!(is_valid,true);
}


#[test]
fn _0x08_ed25519_wrong_context() {
    let keypair = LiberatoKeypair::generate(Algorithms::ED25519).unwrap();

    let msg = "Example Message";
    let context = "Example Context";
    let context_2: &str = "Not The Same Context";

    let sig = keypair.sign(msg, Some(context)).unwrap();

    let is_valid = keypair.pk.verify(msg, Some(context_2), sig.as_ref()).unwrap();

    assert_eq!(is_valid,true);
}

#[test]
#[should_panic]
fn _0x06_ed25519_wrong_message_with_context() {
    let keypair = LiberatoKeypair::generate(Algorithms::ED25519).unwrap();

    let msg = "Example Message";
    let msg_wrong = "Other Message";
    let context = "Example Context";

    let sig = keypair.sign(msg, Some(context)).unwrap();

    let is_valid = keypair.pk.verify(msg_wrong, Some(context), sig.as_ref()).unwrap();

    assert_eq!(is_valid,true);
}

#[test]
#[should_panic]
fn _0x07_ed25519_wrong_message_with_wrong_context() {
    let keypair = LiberatoKeypair::generate(Algorithms::ED25519).unwrap();

    let msg = "Example Message";
    let msg_wrong = "Other Message";
    let context = "Example Context";
    let context_wrong = "Other Context";

    let sig = keypair.sign(msg, Some(context)).unwrap();

    let is_valid = keypair.pk.verify(msg_wrong, Some(context_wrong), sig.as_ref()).unwrap();

    assert_eq!(is_valid,true);
}

#[test]
#[should_panic]
fn _0x05_ed25519_wrong_message_with_no_context() {
    let keypair = LiberatoKeypair::generate(Algorithms::ED25519).unwrap();

    let msg = "Example Message";
    let msg_wrong = "Other Message";
    let context = "Example Context";
    let context_wrong = "Other Context";

    let sig = keypair.sign(msg, Some(context)).unwrap();

    let is_valid = keypair.pk.verify(msg_wrong, None, sig.as_ref()).unwrap();

    assert_eq!(is_valid,true);
}

#[test]
#[should_panic]
fn _0x09_ed25519_right_message_with_no_context_after_signing_with_context() {
    let keypair = LiberatoKeypair::generate(Algorithms::ED25519).unwrap();

    let msg = "Example Message";
    let msg_wrong = "Other Message";
    let context = "Example Context";
    let context_wrong = "Other Context";

    let sig = keypair.sign(msg, Some(context)).unwrap();

    let is_valid = keypair.pk.verify(msg, None, sig.as_ref()).unwrap();

    assert_eq!(is_valid,true);
}

#[test]
#[should_panic]
fn _0x0A_ed25519_right_message_with_no_context_after_signing_with_no_context_and_providing_context() {
    let keypair = LiberatoKeypair::generate(Algorithms::ED25519).unwrap();

    let msg = "Example Message";
    let msg_wrong = "Other Message";
    let context = "Example Context";
    let context_wrong = "Other Context";

    let sig = keypair.sign(msg, None).unwrap();

    let is_valid = keypair.pk.verify(msg, Some(context), sig.as_ref()).unwrap();

    assert_eq!(is_valid,true);
}