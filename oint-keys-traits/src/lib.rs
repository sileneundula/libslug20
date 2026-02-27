pub trait IsHybrid {

}

pub trait IsOintSignature {

}

pub trait IsOintPublicKey {

}

pub trait IsOintSecretKey {

}

pub trait Oint320PublicKey {
    fn public_key(&self) -> String;
    fn verify<T: IsOintSignature + Clone>(&self, sig: T) -> bool;
}

pub trait Oint320SecretKey {
    fn secret_key(&self) -> String;
    fn sign<T: AsRef<[u8]>>(&self, msg: T) -> String;
}

pub trait Oint320Signature {
    fn signature(&self) -> String;
}

pub trait IsAlgorithm {
    fn algorithm(&self) -> String;
    /// CIPHER SUITE
    /// 
    /// Label For The Chosen Cipher Suite
    fn cipher_suite(&self) -> String;
}

pub trait GenerateKeypair: Sized {
    fn generate<T: AsRef<str>>(algorithm: T) -> Self;
}
