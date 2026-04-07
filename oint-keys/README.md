# Oint-Keys: A New Standard For Keypairs That Abstracts From Old Formats

## TODO

- [ ] Add Encryption Algorithms
- [ ] Better Parsing
- [ ] More Traits

## Description

Oint-keys is a modular cryptography library offering many different algorithms all under one struct making it easy to use, and handling most of the cryptography in a clean, concise manner.

It is a standard for what cipher_suites to include and can be used with other types of libraries. It offers robust choices for the future threat model of quantum computers breaking classical cryptography.

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
