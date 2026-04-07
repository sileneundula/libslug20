# Oint-Keys: A New Standard For Keypairs That Abstracts From Old Formats Intended For Web 3.20 or OpenInternet Project

![Static Badge](https://img.shields.io/badge/%2Fsilene%2Fslug20-ointkeys-blue?style=flat-square)
![Crates.io Version](https://img.shields.io/crates/v/oint-keys?style=flat-square&link=https%3A%2F%2Fcrates.io%2Fcrates%2Foint-keys)
![Deps.rs Crate Dependencies (latest)](https://img.shields.io/deps-rs/oint-keys/latest?style=flat-square)
![Crates.io Total Downloads](https://img.shields.io/crates/d/oint-keys?style=flat-square&link=https%3A%2F%2Fcrates.io%2Fcrates%2Foint-keys)
![docs.rs](https://img.shields.io/docsrs/oint-keys?style=flat-square&link=https%3A%2F%2Fdocs.rs%2Foint-keys%2F)
![Crates.io License](https://img.shields.io/crates/l/oint-keys?style=flat-square)
![Crates.io Dependents](https://img.shields.io/crates/dependents/oint-keys?style=flat-square&link=https%3A%2F%2Fcrates.io%2Fcrates%2Foint-keys%2Freverse_dependencies)
![Crates.io User Total Downloads](https://img.shields.io/crates/udt/253136?style=flat-square&label=Silene0259%20Total%20Downloads&link=https%3A%2F%2Fcrates.io%2Fusers%2Fsileneundula)
![GitHub Repo stars](https://img.shields.io/github/stars/sileneundula/libslug20?style=flat-square&link=https%3A%2F%2Fgithub.com%2Fsileneundula%2Flibslug20%2Ftree%2Fmaster%2Foint-keys)




![Bluesky followers](https://img.shields.io/bluesky/followers/silene0259.bsky.social)
![Reddit User Karma](https://img.shields.io/reddit/user-karma/link/silene0259)
![YouTube Channel Subscribers](https://img.shields.io/youtube/channel/subscribers/UCCVb9sS4YjtGlK0oP-9oeig)

## Description

Oint-keys is a modular cryptography library offering many different algorithms all under one struct making it easy to use, and handling most of the cryptography in a clean, concise manner.

It is a standard for what cipher_suites to include and can be used with other types of libraries. It offers robust choices for the future threat model of quantum computers breaking classical cryptography.

## How To Use

```rust
use oint_keys::prelude::*;
use oint_keys::prelude::traits::{FromX59,IntoX59,LiberatoKeypairTrait,LiberatoSigning,LiberatoVerification};
use oint_keys::prelude::errors::SlugErrors;
use oint_keys::prelude::algorithms::Algorithms;

fn main() {
    let keypair = LiberatoKeypair::generate(Algorithms::ShulginSigning).unwrap();

    let msg: &str = "This is an example of signing using the oint-keys abstraction that support a variety of algorithms.";

    let sig = keypair.sign(msg).unwrap();

    let is_valid = keypair.pk.verify(msg, &sig).unwrap();

    assert_eq!(is_valid,true)
}

```

The algorithms supported are listed below:

- [X] ECDSA
    - [X] Secp256k1
- [X] EdDSA
    - [X] ED25519
    - [ ] ED25519 with Hedged Signatures
    - [X] ED448
    - [ ] ED448 with Hedged Signatures
- [X] Schnorr over Ristretto
- [X] BLS12-381
- [ ] RSA

### Post-Quantum

- [X] FALCON1024
- [X] ML-DSA3 (Dilithium65)
- [X] SPHINCS+ (SHAKE256) (Level 5)

### Oint-Standards

- [X] ShulginSigning: A SPHINCS+ (SHAKE256) (255 bit security) with ED25519 hybrid digital signing scheme
- [X] EsphandSigning: A FALCON1024 with ED25519 hybrid digital signing scheme
- [X] AbsolveSigning: A ML-DSA3 with ED25519 hybrid digital signing scheme


## TODO

- [ ] Add Encryption Algorithms
- [ ] Better Parsing
- [ ] More Traits
