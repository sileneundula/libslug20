use libslug::slugcrypt::internals::bip39::SlugMnemonic;
use libslug::slugcrypt::internals::bip39::{SlugBIP39Languages,SlugBIP39Words};

fn main() {
    // Select Language
    let language = bip39::Language::English;
    // Select Number of Words In Phrase
    let length = bip39::MnemonicType::Words24;
    // Select Password
    let password: &str = "This is the password for the Seed";


    // Generate Phrase
    let phrase = SlugMnemonic::new(SlugBIP39Words::Words24, SlugBIP39Languages::English);
    
    
    // Get Seed
    let seed: Vec<u8> = phrase.to_seed(password).unwrap();
}