use oint_keys::prelude::base::OpenInternetKeypair;
use oint_keys::prelude::*;
use oint_keys::prelude::traits::{OintKeypairTrait,OintSigning,OintVerification};
use oint_keys::prelude::errors::SlugErrors;
use oint_keys::prelude::algorithms::Algorithms;

fn main() {
    let keypair = OpenInternetKeypair::generate(Algorithms::ShulginSigning).unwrap();

    let msg: &str = "This is an example of signing using the oint-keys abstraction that support a variety of algorithms.";

    let sig = keypair.sign(msg).unwrap();

    let is_valid = keypair.pk.verify(msg, &sig).unwrap();

    assert_eq!(is_valid,true)
}