//! # Sym Enc Res
//!
//! This submodule provides a structure to store the result of an AEAD encryption function

use super::{NONCE_LEN, SALT_LEN, SecureBytes};

/// Contains the output of the symmetric encryption process
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymEncRes {
    enc: SecureBytes,
    key_salt: [u8; SALT_LEN],
    enc_nonce: [u8; NONCE_LEN]
}

impl SymEncRes {
    /// Creates a new instance of `SymEncRes` with the encrypted text, the value used to salt the
    /// encryption key and the nonce used during the encryption
    pub fn new(enc: SecureBytes, key_salt: [u8; SALT_LEN], enc_nonce: [u8; NONCE_LEN]) -> Self {
        SymEncRes {
            enc,
            key_salt,
            enc_nonce
        }
    }

    pub fn get_enc(&self) -> &SecureBytes {
        &self.enc
    }

    pub fn get_key_salt(&self) -> &[u8; SALT_LEN] {
        &self.key_salt
    }

    pub fn get_enc_nonce(&self) -> &[u8; NONCE_LEN] {
        &self.enc_nonce
    }
}
