//! # Hash 
//!
//! This module provides hashing capabilities implemented via a key derivation function.
//!
//! # Security Note
//!
//! The current implementation is based on PBKDF2 algorithm provided by `aws_lc_rs` crate with 
//! FIPS compliance feature enabled. 
//!
//! Note that salt reuse is prevented by the module implementation.

use aws_lc_rs::{pbkdf2, rand::{self, SecureRandom}};
use std::{collections::HashMap, num::NonZeroU32};
use crate::{SecureBytes, Unspecified};

pub use aws_lc_rs::digest::SHA512_OUTPUT_LEN;

// constants [[[

/// KDF algorithm used by the module
const KDF_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512;

/// KDF iteration factor used by the module. The iteration value is based on owasp's advice for
/// PBKDF2_HMAC_SHA512 at the moment of writing (19th September 2025).
/// (https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
const KDF_ITER_FACTOR: u32 = 210_000;

/// Salt length in bytes.
/// Doubling minimum salt size advised in NIST SP 800-132 (December 2010) while waiting for its
/// revised version to be published
pub const SALT_LEN: usize = 64;

// ]]]


// hash trait [[[ 

/// Defines hashing behavior.
pub trait Hash {
    /// Derives an hash for the given `key` and `salt`, storing the output in `out`.
    ///
    /// # Parameters
    /// - `key`: input key to derive the hash from 
    /// - `out`: output hash
    ///
    /// # Returns
    ///
    /// Returns the value used to salt the hash, if the latter was successfully derived; 
    /// `Unspecified` otherwise.
    fn derive_hash(&mut self, key: &SecureBytes, out: &mut SecureBytes) -> Result<[u8; SALT_LEN], Unspecified>;

    /// Verifies whether the hash of a provided key matches a previously derived one.
    ///
    /// # Parameters 
    ///
    /// - `salt`: value used to salt `new_key`
    /// - `new_key`: newly provided key to be hashed
    /// - `old_key`: previously derived key hash
    /// 
    /// # Returns
    ///
    /// Returns `true` if the hashes match, `false` otherwise.
    fn verify_hash(salt: &[u8; SALT_LEN], new_key: &[u8], old_key: & [u8]) -> bool;

    /// Returns a salt value or `Unspecified`.
    fn generate_salt(&self) -> Result<[u8; SALT_LEN], Unspecified>;

    /// Returns all previously used salts for each key that have been used.
    fn get_old_salts(&self) -> &HashMap<OldKey, Vec<[u8; SALT_LEN]>>;
}

// ]]]

/// Provides hashing capabilities.
///
/// # Security Note
///
/// Only __one instance__ of this class must be created at a time to guarantee security against salt 
/// reuse.
pub struct HashProvider { 
    /// Hash map containing all the salts that have ever been used for each key
    old_salts: HashMap<[u8;SHA512_OUTPUT_LEN], Vec<[u8; SALT_LEN]>>,
    /// cryptographically secure random number generator
    rng: rand::SystemRandom
}

impl HashProvider {
    /// Creates a new instance of `HashProvider` initializing its hash map with the parameter 
    /// `old_salts`.
    pub fn new(old_salts: HashMap<[u8;SHA512_OUTPUT_LEN], Vec<[u8; SALT_LEN]>>) -> HashProvider {
        HashProvider {
            old_salts,
            rng: rand::SystemRandom::new()
        }
    }

    /// Creates a new instance of `HashProvider` with an empty hash map.
    pub fn new_empty() -> HashProvider {
        HashProvider {
            old_salts: HashMap::new(),
            rng: rand::SystemRandom::new()
        }
    }
}

impl Hash for HashProvider {
    fn derive_hash(&mut self, key: &SecureBytes, out: &mut SecureBytes) -> Result<[u8; SALT_LEN], Unspecified> {

        // in this case, no match is used as the argument is a non-zero constant
        let iter = NonZeroU32::new(KDF_ITER_FACTOR).unwrap();
        let salt = self.generate_salt()?;

        // computing key hash
        pbkdf2::derive(KDF_ALG, iter, &salt, key.unsecure(), out.unsecure_mut());

        // computing out hash
        let out_salt = self.generate_salt()?;
        let mut out_hash = [0u8; SHA512_OUTPUT_LEN];

        pbkdf2::derive(KDF_ALG, iter, &out_salt, out.unsecure(), &mut out_hash);
        

        // checking whether out_hash is in old_salts or not
        self.old_salts.entry(out_hash).
            // adding the salt if out_old exists
            and_modify(|salt_vec| salt_vec.push(salt.clone())).
            // creating a new entry for out_old if it does not exist
            or_insert(
                vec![salt.clone()]
            );
        
        Ok(salt)

    }

    fn verify_hash(salt: &[u8; SALT_LEN], new_key: &[u8], old_key: & [u8]) -> bool {

        // in this case, no match is used as the argument is a non-zero constant
        let iter = NonZeroU32::new(KDF_ITER_FACTOR).unwrap();
        
        pbkdf2::verify(KDF_ALG, iter, salt, new_key, old_key).is_ok()
    }

    fn generate_salt(&self) -> Result<[u8; SALT_LEN], Unspecified> {

        let mut salt = [0u8; SALT_LEN];

        self.rng.fill(&mut salt)?;

        Ok(salt)
    }

    fn get_old_salts(&self) -> &HashMap<[u8;SHA512_OUTPUT_LEN], Vec<[u8; SALT_LEN]>>{
        &self.old_salts
    }
}
