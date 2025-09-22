//! # Hash 
//!
//! This module provides hashing capabilities implemented via a key derivation function.
//!
//! # Security Note
//!
//! The current implementation is based on PBKDF2 algorithm provided by `aws_lc_rs` crate.
//!
//! Note that salt reuse for the same key is __NOT__ prevented by the module implementation.

use aws_lc_rs::{pbkdf2, rand::{self, SecureRandom}};
use std::num::NonZeroU32;
use crate::{CryptoErr, SecureBytes};

pub use aws_lc_rs::digest::SHA512_OUTPUT_LEN;

// constants [[[

/// KDF algorithm used by the module.
const KDF_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512;

/// KDF iteration factor used by the module. The iteration value is based on owasp's advice for
/// PBKDF2_HMAC_SHA512 at the moment of writing (19th September 2025).
/// (https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
const KDF_ITER_FACTOR: u32 = 210_000;

/// Salt length in bytes.
/// Doubling minimum salt size advised in NIST SP 800-132 (December 2010) while waiting for its
/// revised version to be published.
pub const SALT_LEN: usize = 64;

// ]]]

// hash trait [[[ 

/// Defines hashing behavior.
pub trait Hash {
    /// Derives an hash for the given `key` and `salt`.
    ///
    /// # Parameters
    /// - `key`: input key to derive the hash from
    /// - `salt`: value to salt the hash. This value must __NOT__ be reused with the same key
    /// - `out_len`: length of the hash
    ///
    /// # Returns
    ///
    /// Returns a `SecureBytes` containing the hash of the desired length.
    fn derive_hash(key: &SecureBytes, salt: &[u8; SALT_LEN], out_len: usize) -> SecureBytes;

    /// Verifies whether the hash of a provided key matches a previously derived one.
    ///
    /// # Parameters 
    ///
    /// - `new_key`: newly provided key to be hashed
    /// - `salt`: value used to salt `old_key`
    /// - `old_key`: previously derived key hash
    /// 
    /// # Returns
    ///
    /// Returns `true` if the hashes match, `false` otherwise.
    fn verify_hash(new_key: &SecureBytes, salt: &[u8; SALT_LEN], old_key: &SecureBytes) -> bool;

    /// Returns a salt value or `CryptoErr`.
    fn generate_salt(&self) -> Result<[u8; SALT_LEN], CryptoErr>;

}

// ]]]

// HashProvider [[[

/// Provides hashing capabilities.
///
/// # Security Note
///
/// Only __one instance__ of this class must be created at a time to guarantee secure number 
/// generation.
pub struct HashProvider { 
    /// Cryptographically secure random number generator.
    rng: rand::SystemRandom
}

impl HashProvider {
    pub fn new() -> Self {
        HashProvider {
            rng: rand::SystemRandom::new()
        }
    }
}

impl Hash for HashProvider {
    fn derive_hash(key: &SecureBytes, salt: &[u8; SALT_LEN], out_len: usize) -> SecureBytes {

        // in this case, no match is used as the argument is a non-zero constant
        let iter = NonZeroU32::new(KDF_ITER_FACTOR).unwrap();
        let mut out = SecureBytes::new(vec![0u8; out_len]);

        pbkdf2::derive(KDF_ALG, iter, salt, key.unsecure(), out.unsecure_mut());

        out
    }

    fn verify_hash(new_key: &SecureBytes, salt: &[u8; SALT_LEN], old_key: &SecureBytes) -> bool {

        // in this case, no match is used as the argument is a non-zero constant
        let iter = NonZeroU32::new(KDF_ITER_FACTOR).unwrap();
        
        pbkdf2::verify(KDF_ALG, iter, salt, new_key.unsecure(), old_key.unsecure()).is_ok()
    }

    fn generate_salt(&self) -> Result<[u8; SALT_LEN], CryptoErr> {

        let mut salt = [0u8; SALT_LEN];

        self.rng.fill(&mut salt)?;

        Ok(salt)
    }

}

// ]]]
