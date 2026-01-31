//! # X59 Data Format
//! 
//! ## Author
//! 
//! Joseph P. Tortorelli (Silene/0x20CB)
//! 
//! ## Features
//! 
//! - [X] X59-fmt
//!     - [X] X59Label (`[..]`)
//!         - [X] Attribute (`(!..)`)
//!         - [ ] Checksum
//!     - [ ] X59ParserSource (`@`)
//!     - [ ] X59DataType (`#`)
//!         - [ ] Source
//! 
//! TODO:
//! 
//! - [X] X59Label
//!     - [X] Display
//!     - [ ]
//! - [X] X59Source (@)
//!     - [ ] Source
//! - [X] X59Type (#)
//!     - [ ] Source

use crate::constants::OPEN;
use crate::constants::CLOSE;
use crate::constants::*;

use crate::errors::Errors;

use std::fmt;

use fixedstr::str64;
use fixedstr::str256;
use std::str::FromStr;

use slugencode::prelude::*;

/// # X59 Label
/// 
/// ## Description
/// 
/// The core component of `X59-fmt`, an *X59Label* functions to add context to values, including structured data in extensions.
/// 
/// X59Label consists of two data values:
/// 
/// 1. **Pieces** (UTF-8 String Pieces In A Vector)
/// 2. **Attribute** (An attribute data value that adds context using the `X59ParserSource`)
/// 
/// ## Example Code
/// 
/// ### Example
/// 
/// ```rust
/// use x59_fmt::prelude::X59Label;
/// 
/// fn main() {
///     // [example/path/parsed/extension]
///     let _label = X59Label::from_str("example/path/parsed/extension", None);
/// 
///     // [(!algorithm)example/path/parsed/extension] using `Source`
///     let label_with_attribute = X59Label::from_str("example/path/parsed/extension","algorithm")
/// 
///     // Outputs to a String
///     let output = label_with_attribute.into_string();
/// }
/// 
/// ```
/// 
/// ### Mutable Example
/// 
/// ```rust
/// 
/// use x59_fmt::prelude::X59Label;
/// 
/// fn main() {
///     // Generates New X59 Label
///     let mut label: X59Label = X59Label::new();
/// 
///     // Adds Pieces For Path of X59Label (`[test/example/path]<DATA>`)
///     label.add_pieces(vec!["test","example","path"]);
/// 
///     // Outputs into a string
///     let output: String = label.as_source_label();
/// }
/// 
/// ```
#[derive(Clone, Debug, PartialEq, PartialOrd, Hash)]
pub struct X59Label {
    pub pieces: Vec<str256>,
    pub attribute: str256,
}

/// # X59 Data Type
/// 
/// - [X] Contains easy conversions
/// - [X] Contains From_str and From_bytes
/// - [X] Contains Into_String For Text Values
/// - [ ] Contains checksum
/// - [ ] Contains Default function
/// - [ ] Contains Default for attribute/data type function formatting
pub struct X59Value {
    pub data: Vec<u8>,
}

impl X59Value {
    pub fn from_str<T: AsRef<str>>(s: T) -> Self {
        Self {
            data: s.as_ref().as_bytes().to_vec()
        }
    }
    pub fn from_bytes<T: AsRef<[u8]>>(s: T) -> Self {
        let x = s.as_ref().to_vec();

        Self {
            data: x,
        }
    }
    pub fn into_string(&self) -> Result<String, std::string::FromUtf8Error> {
        return String::from_utf8(self.data.to_vec())
    }
    /// # Encode Data
    pub fn encode(&self, encoding: SlugEncodings) -> Result<String,SlugEncodingError> {
        let x = SlugEncodingUsage::new(encoding);
        return x.encode(&self.data)
    }
    pub fn decode<T: AsRef<str>>(s: T, encoding: SlugEncodings) -> Result<Self,SlugEncodingError> {
        let x = SlugEncodingUsage::new(encoding);
        let x_2 = x.decode(s.as_ref())?;
        return Ok(Self {
            data:  x_2
        }
        )
    } 
}


/// # X59 Data Type
/// 
/// - [ ] Contains easy conversions
/// - [ ] Contains checksum
/// - [ ] Contains Default function
/// - [ ] Contains Default for attribute/data type function formatting
pub struct X59StructuredDataFormat {
    pub data: String,
}

/// # X59 Source (`@`)
/// 
/// The Source Parser. Defaults to X59 System and ecosystem.
/// 
/// ## Features
/// 
/// - Git-integration
/// 
/// - URL
/// 
/// - Registries
/// 
/// ## Example
/// 
/// `@git:<user>`
/// 
/// `@url:<url>`
/// 
/// `@source:<source_id>`
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Hash)]
pub struct X59Source {
    source: str256,
    parser_protocol: u32, // parser
    communication_protocol: u8, // comms
    provider: str256, // provider
}

/// # Type of Data (`#`)
/// 
/// `#pk`
/// 
/// `#peer`
/// 
/// 
#[derive(Clone, Debug, PartialEq, PartialOrd, Hash)]
pub struct X59Type {
    lib: TypeLibrary,
    _type: str64,
}

/// # X59 Constraint System
/// 
/// 
pub struct X59Constraints {
    constraint: String,
}

impl Default for X59Type {
    fn default() -> Self {
        X59Type {
            lib: TypeLibrary::default(),
            _type: str64::from_str("Raw").unwrap(),
        }
    }
}

/*
impl fmt::Display for X59Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Library: {}",&self.lib)
    }
}
*/    

#[derive(Clone, Debug, PartialEq, PartialOrd, Hash)]
pub enum TypeLibrary {
    X59std(u16), // X59std lib (assumed as default)
    
    Git(String),
    URL(String),
    Other(String),
}

/*
impl fmt::Display for TypeLibrary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if Self::X59std(0u16) == true {
            write!(f, "X59 Standard Library (Revision: 0x00)")
        }
        else if Self::X59std(1) == true {
            write!(f, "X59 Standard Library (Revision: 0x01)")
        }
        else if Self::X59std(0xFFu16) == true {
            write!(f, "X59 Standard Library Nightly (Revision 0xFF)")
        }
        else if Self::X59std(2) == true {
            write!(f, "X59 Standard Library Slim (Revision 0x02")
        }
        else {
            write!(f, "Unknown Library")
        }

        if self::TypeLibrary::X59std(0u16) {
            write!(f, "X59 Standard Library (Revision: 0x00)")
        }
    }
}
    */

impl Default for TypeLibrary {
    fn default() -> Self {
        TypeLibrary::X59std(0u16)
    }
}

impl X59Source {
    pub fn as_source_label(&self) -> String {
        let mut output: String = String::new();

        output.push_str(OPEN);
        output.push_str(SOURCE_SYMBOL);
        output.push_str(&self.source);
        output.push_str(CLOSE);

        return output
    }
    /// # Into String
    /// 
    /// Wrapper around `as_source_label` for ease of access
    pub fn into_string(&self) -> String {
        return self.as_source_label()
    }
}

impl Default for X59Source {
    fn default() -> Self {
        return Self {
            source: str256::from_str("X59System").unwrap(),
            parser_protocol: 0u32,
            communication_protocol: 0u8, // 1 = HTTP
            provider: str256::from_str("Default-Resolver").unwrap(),
        }
    }
}

impl X59Label {
    pub fn new<T: AsRef<str>>(attribute: T) -> Self {
        return Self {
            pieces: Vec::new(),
            attribute: str256::from_str(attribute.as_ref()).unwrap(),
        }
    }
    pub fn from_str<T: AsRef<str>>(s_path: T, attribute: T) -> Self {
        let x: Vec<&str> = s_path.as_ref().split("/").collect();

        let mut output: Vec<str256> = Vec::new();

        for i in x {
            output.push(str256::from_str(i).unwrap());
        }

        return Self {
            pieces: output,
            attribute: str256::from_str(attribute.as_ref()).unwrap(),
        }
    }
    /// # Add Piece To X59Label
    /// 
    /// Adds a singular piece to the path of an X59Label
    pub fn add_piece<T: AsRef<str>>(&mut self, piece: T) {
        self.pieces.push(str256::from_str(piece.as_ref()).unwrap())
    }
    /// # Add Pieces To X59Label (Using a Vector)
    /// 
    /// Adds multiple pieces to the path of the X59 Label
    pub fn add_pieces<T: AsRef<str>>(&mut self, pieces: Vec<T>) {
        for x in pieces {
            self.pieces.push(str256::from_str(x.as_ref()).unwrap())
        }
    }
    pub fn add_attribute<T: AsRef<str>>(&mut self, attribute: T) {
        self.attribute = str256::from_str(attribute.as_ref()).unwrap();
    }
    /// # As Label
    /// 
    /// Exports to a label
    pub fn as_label(&self) -> String {
        let mut output: String = String::new();

        output.push_str(OPEN);

        let mut i = 0usize;
        let mut length = self.pieces.len() - 1;
        
        if self.attribute == "" || self.attribute == " " {
            for x in &self.pieces {
                output.push_str(x);
                if i < length {
                    output.push_str(DELIMITER);
                    i = i + 1;
                }
                else {
                    output.push_str(CLOSE);
                }
            }
            return output
        }
        else {
            let attribute = Self::process_attribute(&self).expect("Failure In Attribute Assignment Due To No Attribute");

            // Push (!..)
            output.push_str(&attribute);

            for x in &self.pieces {
                output.push_str(x);
                if i < length {
                    output.push_str(DELIMITER);
                    i = i + 1;
                }
                else {
                    output.push_str(CLOSE);
                }
            }
            return output
        }
        
        
        

    }
    /// # Add Attribute
    /// 
    /// Adds an Attribute onto a label
    /// 
    /// ## Format
    /// 
    /// `(!<value>)` where value is some value and inside braces
    fn process_attribute(&self) -> Result<String,Errors> {
        let mut output: String = String::new();

        if self.attribute != "" || self.attribute != " " {
            output.push_str(OPEN_PAR); // (
            output.push_str(ATTRIBUTE_VALUE); // !

            output.push_str(&self.attribute);
            output.push_str(CLOSE_PAR);
        }
        else {
            return Err(Errors::NoAttributeInLabel)
        }
        return Ok(output)
    }
}

impl fmt::Display for X59Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let x = self.as_label();
        write!(f, "{}",x)
    }
}


#[test]
fn label_test() {
    let x = X59Label {
        pieces: vec![str256::from_str("example").unwrap(),str256::from_str("data").unwrap(),str256::from_str("end").unwrap()],
        attribute: str256::from_str("An Optional Attribute").unwrap(),
    };
    let output = x.as_label();

    println!("{}",output)
}