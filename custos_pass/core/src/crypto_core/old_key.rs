//! # Old Key 
//!
//! This submodule provides a structure that allows to store hashes of previously used keys.

use super::{SALT_LEN, SecureBytes};

/// Represents an already used key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OldKey {
    /// Hash of the key.
    hash: SecureBytes,
    /// Value used to salt `hash`.
    salt: [u8; SALT_LEN]
}

impl OldKey {
    /// Creates a new instance of `OldKey` with the hash of the key and the value used to salt it.
    pub fn new(hash: SecureBytes, salt: [u8; SALT_LEN]) -> Self {
        OldKey {
            hash,
            salt
        }
    }

    /// Returns the key hash.
    pub fn get_hash(&self) -> &SecureBytes {
        &self.hash
    }

    /// Returns the hash salt
    pub fn get_salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }
}
