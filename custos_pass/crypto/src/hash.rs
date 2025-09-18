//! # Hash 
//!
//! This module provides hashing capabilities implemented via a key derivation function.
//!
//! # Security Considerations
//!
//! The current implementation is based on PBKDF2 algorithm provided by aws-ls-rc with FIPS 
//! compliance feature enabled. 
//!
//! Note that salt reuse is NOT prevented by the module implementation. It is the responsibility
//! of the module user to ensure that the same salt value is not reused when hashing the same input data

use aws_lc_rs::pbkdf2;
use std::num::NonZeroU32;

// constants [[[

/// KDF algorithm used by the module
const KDF_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512;

/// KDF iteration factor used by the module. The iteration value is based on owasp's adivece for
/// PBKDF2_HMAC_SHA512 at the moment of writing (19th Semptember 2025).
/// (https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
const KDF_ITER_FACTOR: u32 = 210_000;

/// Salt lenght in bytes.
/// Doubling minimum salt size advised in NIST SP 800-132 (December 2010) while waiting for its
/// revised version to be published
pub const SALT_LEN: usize = 64;

// ]]]

// hash trait [[[ 

/// Trait defining hashing behavior
pub trait Hash {
    /// Derives an hash for the given `key` and `salt`, storing the output in `hash`
    ///
    /// # Security Note
    ///
    /// each salt value __must__ be unique for each key value
    ///
    /// # Parameters
    /// - `salt`: value used to salt the hash
    /// - `key`: input key to derive the hash from 
    /// - `hash`: output hash
    fn derive_hash(salt: &[u8; SALT_LEN], key: &[u8], hash: &mut [u8]);

    /// Verifies if a provided key hash matches a previously derived one
    ///
    /// # Parameters 
    /// - `salt`: value used to salt `new_key`
    /// - `new_key`: newly provided key
    /// - `old_key`: previously derived key
    /// 
    /// # Returns
    ///
    /// `true` if the hashes match, `false` otherwise
    fn verify_hash(salt: &[u8; SALT_LEN], new_key: &[u8], old_key: & [u8]) -> bool;
}

// ]]]

pub struct HashProvider;

impl Hash for HashProvider {
    fn derive_hash(salt: &[u8; SALT_LEN], key: &[u8], hash: &mut [u8]) {
        // in this case, any match is used as the argument is a non-zero constant
        let iter = NonZeroU32::new(KDF_ITER_FACTOR).unwrap();

        pbkdf2::derive(KDF_ALG, iter, salt, key, hash);
    }

    fn verify_hash(salt: &[u8; SALT_LEN], new_key: &[u8], old_key: & [u8]) -> bool{
        // in this case, any match is used as the argument is a non-zero constant
        let iter = NonZeroU32::new(KDF_ITER_FACTOR).unwrap();
        
        pbkdf2::verify(KDF_ALG, iter, salt, new_key, old_key).is_ok()
    }
}
