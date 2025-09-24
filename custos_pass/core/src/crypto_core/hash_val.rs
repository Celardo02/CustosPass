//! # Hash Val 
//!
//! This submodule provides a structure that allows to store hashes and their salts

use super::{SALT_LEN, SecureBytes};

/// Contains an hash value and the salt used to compute it
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashVal {
    /// Hash of the key.
    hash: SecureBytes,
    /// Value used to salt `hash`.
    salt: [u8; SALT_LEN]
}

impl HashVal {
    /// Creates a new instance of `HashVal` with an hash value and the value used to salt it.
    pub fn new(hash: SecureBytes, salt: [u8; SALT_LEN]) -> Self {
        HashVal {
            hash,
            salt
        }
    }

    /// Returns the hash value.
    pub fn get_hash(&self) -> &SecureBytes {
        &self.hash
    }

    /// Returns the hash salt.
    pub fn get_salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }
}
