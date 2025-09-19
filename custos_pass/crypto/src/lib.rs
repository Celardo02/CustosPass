//! # Crypto
//!
//! This crate contains all the traits, structures and cryptography logic of the CustosPass 
//! project.
 
// pub mod asym_enc;
pub mod hash;
pub mod sym_enc;

// TODO: insert the try_fips_mode a single time here instead of each function of each module

pub use aws_lc_rs::{digest::SHA512_OUTPUT_LEN, error::Unspecified};
pub use secure_string::SecureBytes;

// library constants [[[

/// Salt length in bytes.
/// Doubling minimum salt size advised in NIST SP 800-132 (December 2010) while waiting for its
/// revised version to be published
pub const SALT_LEN: usize = 64;

// ]]]


// OldKey struct [[[

/// Represents a key already used by a module of this crate
#[derive(Hash, Debug)]
pub struct OldKey {
    /// Hash of the key.
    hash: [u8; SHA512_OUTPUT_LEN],
    /// Value used to salt `hash`.
    salt: [u8; SALT_LEN]
}

impl OldKey {
    /// Creates a new instance of `OldKey` with the hash of the key and the value used to salt it.
    pub fn new(hash: [u8; SHA512_OUTPUT_LEN], salt: [u8; SALT_LEN]) -> OldKey {
        OldKey {
            hash,
            salt
        }
    }

    /// Returns the key hash.
    pub fn get_hash(&self) -> &[u8; SHA512_OUTPUT_LEN] {
        &self.hash
    }

    /// Returns the hash salt
    pub fn get_salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }
}

impl PartialEq for OldKey {
    fn eq(&self, other: &Self) -> bool {
       self.hash == other.hash 
    }
}

impl Eq for OldKey {}
 // ]]]
