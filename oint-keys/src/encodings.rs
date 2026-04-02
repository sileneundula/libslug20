#[derive(Debug,Clone,Copy,PartialEq,PartialOrd,Hash)]
pub enum OintKeyEncodings {
    // X59-FMT
    X59FMT,
    
    // PEM
    PEM,
    X59PEM,
    
    // Encodings
    Hex,
    Base32,
    Base32up,
    Base58,
    Base64,
    Base64urlsafe,
    Unknown,
}

impl OintKeyEncodings {
    pub fn as_label(&self) -> &str {
        match self {
            Self::X59FMT => return "x59-fmt",
            Self::Base32 => return "base32",
            Self::Base32up => return "base32up",
            Self::Base58 => return "base58",
            Self::Base64 => return "base64",
            Self::Base64urlsafe => return "base64url",
            Self::Hex => return "hex",
            Self::PEM => return "pem",
            Self::X59PEM => return "x59pem",
            Self::Unknown => return "unknown"
        }
    }
    pub fn from_label(label: &str) -> Self {
        match label {
            "x59-fmt" => return Self::X59FMT,
            "base32" => return Self::Base32,
            "base32up" => return Self::Base32up,
            "base58" => return Self::Base58,
            "base64" => return Self::Base64,
            "base64url" => return Self::Base64urlsafe,
            "hex" => return Self::Hex,
            "pem" => return Self::PEM,
            "x59pem" => return Self::X59PEM,
            _ => return Self::Unknown,
        }
    }
}