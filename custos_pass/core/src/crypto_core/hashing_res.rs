//! # Hashing Res
//!
//! This submodule provides a structure to store the result of a hashing process.
//!
//! It includes the digest and salt used.

use super::{SALT_LEN, SecureBytes};

/// Contains the output of the hashing process.
#[derive(Debug, Clone)]
pub struct HashingRes {
    digest: SecureBytes,
    salt: [u8; SALT_LEN]
}

impl HashingRes {
    /// Creates a new instance of `HashingRes` with the hash digest and the value used to salt it.
    pub fn new(digest: SecureBytes, salt: [u8; SALT_LEN]) -> Self {
        HashingRes {
            digest,
            salt
        }
    }

    /// Returns the digest value.
    pub fn get_digest(&self) -> &SecureBytes {
        &self.digest
    }

    /// Returns the salt value.
    pub fn get_salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }
}
