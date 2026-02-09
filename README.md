# Slug20 Library

![Static Badge](https://img.shields.io/badge/%2Fsilene%2Fslug20-libslug-blue?style=flat-square)
![Crates.io Version](https://img.shields.io/crates/v/libslug?style=flat-square)
![Crates.io License](https://img.shields.io/crates/l/libslug?style=flat-square)
![Deps.rs Crate Dependencies (latest)](https://img.shields.io/deps-rs/libslug/latest?style=flat-square)
![Crates.io Total Downloads](https://img.shields.io/crates/d/libslug?style=flat-square)
![Crates.io Dependents](https://img.shields.io/crates/dependents/libslug?style=flat-square)


## Description

`slug20` is a tool used to encrypt data inspired by **minisign**. It is simple, minimilastic, and has advanced security built-in. It implements `zeroize`, `subtle`, and `subtle-encoding` for maxmimum security.

On top of encryption, it creates a new standard for Modern Certificates using YAML. Its format (`X59CERT`) is lightweight and can easily be serialized.

It extends to include development of modern, decentralized PKI systems and modular formats for use with different systems.

## Features

- **Default Encryption:** ECIES Encryption over Curve25519 using AES-GCM
- **Post-Quantum Encryption:** ML-KEM
- **Signature Schemes:** ED25519, Schnorr over Ristretto (Curve25519), BLS12-381, ECDSA (secp256k1)
- **Post-Quantum Signature Schemes:** SPHINCS+ (SHAKE256) (Level 5), ML_DSA56 (Level 3), FALCON1024
- **Hybrid Digital Signature Schemes:** EsphandSigning (FALCON1024 + ED25519), ShulginSigning (SPHINCS+ & ED25519), AbsolveSigning (ML-DSA3 + ED25519)
- **Cert Format:** X59 Certificate Standard, PEM
- **Message-Types:** Supports UTF-8 Messages (so we can include emojis)
- **Encryption:** AES-GCM 256 + XChaCha20-Poly1305
- **Randomness Generation:** Supports Randomness Generation from the Operating System. Supports VRFs via Schnorr
- **BIP39:** true, supported
- **BIP32:** still in works

## Progress On Signatures

### Classical

- [X] \[Signature] ED25519-dalek
  - [X] Generation
    - [X] OSCSPRNG
    - [X] Securerand-rs
  - [X] Signing
  - [X] Verifying

### Post-Quantum

- [X] \[Signature] FALCON1024
  - [X] Generation
    - [X] OSCSPRNG
  - [X] silene/slugencode
  - [X] Signing
  - [X] Verifying
  - [X] Serialization/Deserialization
  - [X] Zeroize
  - [X] Protocol Info
  - [ ] Derive Public Key From Secret
- [X] \[Signature] SPHINCS+ (SHAKE256) Level 5
  - [X] Generation
    - [X] OSCSPRNG
  - [X] Signing
  - [X] Verifying
  - [X] Serialization/Deserialization
  - [X] Zeroize
  - [ ] Protocol Info
  - [ ] Other
    - [ ] Derive Public Key From Secret  
## X59Registar

X59Registar is a novel project being developed for decentralized public-key infrastructures using the X59CERT format in YAML.
