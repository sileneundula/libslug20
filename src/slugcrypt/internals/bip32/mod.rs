//! # BIP32: Key Derivation
//! 
//! This module includes Key Derivation from Bitcoin's Improvement Proposals's 32th proposal.

use bip32::{XPrv, Seed};
use bip32::PrivateKey;
use bip32::PublicKey;
use bip32::Error;
use serde::{Serialize,Deserialize};
use zeroize::{Zeroize,ZeroizeOnDrop};
use std::str::FromStr;

use fixedstr::str32;

use rand::rngs::OsRng;

use crate::errors::SlugErrors;

/// BIP32 Traits
pub mod traits;

/// # Key-Deriviation (BIP32)
/// 
/// ## Seed
/// 
/// - [ ] Generate from OSCSPRNG
/// - [ ] Generate from Mnemonic
pub struct KeyDeriviationAPI;

#[derive(Clone,Copy,PartialEq,PartialOrd,Hash,Serialize,Deserialize)]
pub struct MasterKey {
    pub mnemonic: MnemonicKeys,
}

impl MasterKey {
    pub fn from_str_whitespace<T: AsRef<str>>(s: T) -> Self {
        Self {
            mnemonic: MnemonicKeys::from_str_whitespace(s).unwrap()
        }
    }
}

/// # Mnemonic Keys (BIP32)
/// 
/// **Warning:** No Zeroize-Support
/// 
/// Uses a fixedstr of 32 bytes per word.
/// 
/// ## Word Lengths
/// 
/// - [X] 12 words
/// - [X] 16 words
/// - [X] 18 words
/// - [X] 24 words
#[derive(Clone,Copy,PartialEq,PartialOrd,Hash,Debug,Serialize,Deserialize)]
pub enum MnemonicKeys {
    _12words([str32;12]),
    _16words([str32;16]),
    _18words([str32;18]),
    _24words([str32;24]),
}

impl MnemonicKeys {
    pub fn new() {

    }
    pub fn from_str_whitespace<T: AsRef<str>>(s: T) -> Result<Self,SlugErrors> {
        let x: Vec<&str> = s.as_ref().split(" ").collect();

        match x.len() {
            12usize => {
                let mut output: [str32;12] = [str32::new();12];
                let mut i: usize = 0;

                for piece in x {
                    let value = str32::from_str(piece).unwrap();
                    output[i] = value;
                    i = i + 1;
                }
                return Ok(MnemonicKeys::_12words(output))
            }
            16usize => {
                let mut output: [str32;16] = [str32::new();16];
                let mut i: usize = 0;

                for piece in x {
                    let value = str32::from_str(piece).unwrap();
                    output[i] = value;
                    i = i + 1;
                }
                return Ok(MnemonicKeys::_16words(output))
            }
            18usize => {
                let mut output: [str32;18] = [str32::new();18];
                let mut i: usize = 0;

                for piece in x {
                    let value = str32::from_str(piece).unwrap();
                    output[i] = value;
                    i = i + 1;
                }
                return Ok(MnemonicKeys::_18words(output))
            }
            24usize => {
                let mut output: [str32;24] = [str32::new();24];
                let mut i: usize = 0;

                for piece in x {
                    let value = str32::from_str(piece).unwrap();
                    output[i] = value;
                    i = i + 1;
                }
                return Ok(MnemonicKeys::_24words(output))
            }
            _ => {
                return Err(SlugErrors::Other(String::from("Cannot convert BIP32 from string")))
            }

        }
    }
}