use crate::errors::SlugErrors;
use crate::slugcrypt::internals::bip39::{SlugBIP39Languages,SlugBIP39Words};
use crate::slugcrypt::internals::bip39::SlugMnemonic;

pub trait GenerateWithBIP39: Sized {
    fn generate_with_bip39() -> Result<Self,SlugErrors>;
    fn generate_with_bip39_adv<T: AsRef<str>>(mnemonic: SlugMnemonic, pass: T) -> Result<Self,SlugErrors>;
}