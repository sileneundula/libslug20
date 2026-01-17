//! # Derive From
//! 
//! ## Address Schemes
//! 
//! - [ ] Liberato-Address-Scheme (BLAKE2)
//!     - [ ] Variable Digest
//!     - [ ] Reserve Blake2s for 28-32 bytes
//!     - [ ] Reserve Blake2b for 32-64 bytes
//! - [ ] BLAKE3-Address-Scheme (BLAKE3)
//! 
//! ## Deriviation
//! 
//! - [ ] Public-Key
//!     - [ ] Formats
//!         - [ ] Bytes

use fixedstr::str64;

/// # DeriveFrom
pub struct DeriveFromAPI {
    _type: str64
}