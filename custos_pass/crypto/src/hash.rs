//! # Hash 
//!
//! This module provides hashing capabilities implemented via a key derivation function.
//!
//! # Security Note
//!
//! The current implementation is based on PBKDF2 algorithm provided by `aws_lc_rs` crate.
//!
//! Note that salt reuse for the same key is __NOT__ prevented by the module implementation.
//!
//! # Example
//!
//! ```
//! use crypto::hash::{Hash, HashProvider, SALT_LEN, SHA512_OUTPUT_LEN};
//! use crypto::SecureBytes;
//!
//! // key that needs to be hashed
//! let new_key = SecureBytes::new(Vec::from("key value"));
//! // hash output length
//! let len = SHA512_OUTPUT_LEN;
//! // hash salt. It can be an arbitrary value
//! let salt = [3u8;SALT_LEN];
//!
//! let old_key = HashProvider::derive_hash(&new_key, &salt, len);
//!
//! assert!(HashProvider::verify_hash(&new_key, &salt, &old_key));
//! ```

use aws_lc_rs::pbkdf2;
use std::num::NonZeroU32;
use crate::SecureBytes;

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
    ///
    /// # Panics
    ///
    /// Panics if `key` is empty or `out_len` is 0
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
    ///
    /// # Panics
    ///
    /// Panics if `new_key` or `old_key` is empty
    fn verify_hash(new_key: &SecureBytes, salt: &[u8; SALT_LEN], old_key: &SecureBytes) -> bool;
}

// ]]]

// HashProvider [[[

/// Provides hashing capabilities.
pub struct HashProvider;

impl Hash for HashProvider {
    fn derive_hash(key: &SecureBytes, salt: &[u8; SALT_LEN], out_len: usize) -> SecureBytes {
        // checking inputs
        assert!(!key.unsecure().is_empty(), "key is empty");
        assert_ne!(out_len, 0, "out_len is 0");

        // in this case, no match is used as the argument is a non-zero constant
        let iter = NonZeroU32::new(KDF_ITER_FACTOR).unwrap();
        let mut out = SecureBytes::new(vec![0u8; out_len]);

        pbkdf2::derive(KDF_ALG, iter, salt, key.unsecure(), out.unsecure_mut());

        out
    }

    fn verify_hash(new_key: &SecureBytes, salt: &[u8; SALT_LEN], old_key: &SecureBytes) -> bool {
        // checking inputs
        assert!(!new_key.unsecure().is_empty(), "new_key is empty");
        assert!(!old_key.unsecure().is_empty(), "old_key is empty");

        // in this case, no match is used as the argument is a non-zero constant
        let iter = NonZeroU32::new(KDF_ITER_FACTOR).unwrap();
        
        pbkdf2::verify(KDF_ALG, iter, salt, new_key.unsecure(), old_key.unsecure()).is_ok()
    }
}

// ]]]

// unit testing [[[

#[cfg(test)]
mod tests {
    use super::*;

    // derive_hash tests [[[

    /// Tests that `derive_hash` panics if `key` is empty
    #[test]
    #[should_panic]
    fn derive_hash_empty_key () {
        HashProvider::derive_hash(&SecureBytes::new(Vec::new()), &[1u8; SALT_LEN], 10);
    }

    /// Tests that `derive_hash` panics if `out_len` is 0
    #[test]
    #[should_panic]
    fn derive_hash_0_len () {
        HashProvider::derive_hash(&SecureBytes::new(Vec::from("test")), &[1u8; SALT_LEN], 0);
    }

    /// Tests that `derive_hash` panics if `key` is empty and `out_len` is 0
    #[test]
    #[should_panic]
    fn derive_hash_empty_key_0_outlen () {
        HashProvider::derive_hash(&SecureBytes::new(Vec::new()), &[1u8; SALT_LEN], 0);
    }

    /// Tests that `derive_hash` returns a `SecureBytes` with the desired length
    #[test]
    fn derive_hash_correct_outlen() {
        let len = 10;
        let sb = HashProvider::derive_hash(&SecureBytes::new(Vec::from("test")), &[1u8; SALT_LEN], len);

        assert_eq!(sb.unsecure().len(), len, "returned hash does not have the desired length");
    }

    /// Tests that `derive_hash` returns the same hash value given the same `key`, `salt` and `len`
    #[test]
    fn derive_hash_same_result() {
        let len = 10;
        let sb1 = HashProvider::derive_hash(&SecureBytes::new(Vec::from("test")), &[1u8; SALT_LEN], len);
        let sb2 = HashProvider::derive_hash(&SecureBytes::new(Vec::from("test")), &[1u8; SALT_LEN], len);

        assert_eq!(sb1, sb2, "hash value changed in spite of giving the same imputs");
    }

    /// Tests that `derive_hash` returns a value which is different from `key`, even if the hash 
    /// has the same length of `key`
    #[test]
    fn derive_hash_value() {
        let val = SecureBytes::new(Vec::from("key"));

        let hash = HashProvider::derive_hash(&val, &[1u8; SALT_LEN], val.unsecure().len());

        assert_ne!(val, hash, "returned hash value is the same of the input key");
    }

    /// Tests that `derive_hash` returns a different hash value given the same `salt` and
    /// `len`, but a different `key`
    #[test]
    fn derive_hash_diff_key() {
        let len = 10;
        let sb1 = HashProvider::derive_hash(&SecureBytes::new(Vec::from("test1")), &[1u8; SALT_LEN], len);
        let sb2 = HashProvider::derive_hash(&SecureBytes::new(Vec::from("test2")), &[1u8; SALT_LEN], len);

        assert_ne!(sb1, sb2, "returned hash value is the same inspite of using a different key");
    }

    /// Tests that `derive_hash` returns the a different hash value given the same `key` and
    /// `len`, but a different `salt`
    #[test]
    fn derive_hash_diff_salt() {
        let len = 10;
        let sb1 = HashProvider::derive_hash(&SecureBytes::new(Vec::from("test")), &[1u8; SALT_LEN], len);
        let sb2 = HashProvider::derive_hash(&SecureBytes::new(Vec::from("test")), &[2u8; SALT_LEN], len);

        assert_ne!(sb1, sb2, "returned hash value is the same inspite of using a different salt");
    }

    /// Tests that `derive_hash` returns the a different hash value given the same `key` and
    /// `salt`, but a different `len`
    #[test]
    fn derive_hash_diff_len() {
        let sb1 = HashProvider::derive_hash(&SecureBytes::new(Vec::from("test")), &[1u8; SALT_LEN], 10);
        let sb2 = HashProvider::derive_hash(&SecureBytes::new(Vec::from("test")), &[1u8; SALT_LEN], 20);

        assert_ne!(sb1, sb2, "returned hash is the same inspite of using a different length");
    }

    // ]]]

    // verify_hash tests [[[

    /// Tests that `verify_hash` panics if `new_key` is empty
    #[test]
    #[should_panic]
    fn verify_hash_empty_newkey () {
        HashProvider::verify_hash(&SecureBytes::new(Vec::new()), &[1u8; SALT_LEN], &SecureBytes::new(Vec::from("old_key")));
    }

    /// Tests that `verify_hash` panics if `old_key` is empty
    #[test]
    #[should_panic]
    fn verify_hash_empty_oldkey () {
        HashProvider::verify_hash(&SecureBytes::new(Vec::from("new_key")), &[1u8; SALT_LEN], &SecureBytes::new(Vec::new()));
    }

    /// Tests that `verify_hash` panics if both `old_key` and `new_key` are empty
    #[test]
    #[should_panic]
    fn verify_hash_empty_newkey_oldkey () {
        HashProvider::verify_hash(&SecureBytes::new(Vec::new()), &[1u8; SALT_LEN], &SecureBytes::new(Vec::new()));
    }

    /// Tests that `verify_hash` returns `true` if `new_key` hash salted with `salt` is `old_key`
    #[test]
    fn verify_hash_true () {
        let len = 10;
        let val = SecureBytes::new(Vec::from("key"));
        let salt = [1u8; SALT_LEN];

        let hash = HashProvider::derive_hash(&val, &salt, len);

        assert!(HashProvider::verify_hash(&val, &salt, &hash), "old_key is not verified as new_key hash");
    }

    /// Tests that `verify_hash` returns `false` if `old_key` is derived from a different key from
    /// `new_key`, even with the same salt value
    #[test]
    fn verify_hash_false_diff_newkey () {
        let len = 10;
        let val1 = SecureBytes::new(Vec::from("key"));
        let val2 = SecureBytes::new(Vec::from("another_key"));
        let salt = [1u8; SALT_LEN];

        let hash = HashProvider::derive_hash(&val1, &salt, len);

        assert!(!HashProvider::verify_hash(&val2, &salt, &hash), "old_key is verified as new_key hash, even if it is not (different key)");
    }

    /// Tests that `verify_hash` returns `false` if `old_key` is derived from `new_key`, but with 
    /// a different salt
    #[test]
    fn verify_hash_false_diff_salt () {
        let len = 10;
        let val = SecureBytes::new(Vec::from("key"));
        let salt1 = [1u8; SALT_LEN];
        let salt2 = [2u8; SALT_LEN];

        let hash = HashProvider::derive_hash(&val, &salt1, len);

        assert!(!HashProvider::verify_hash(&val, &salt2, &hash), "old_key is verified as new_key hash, even if it is not (different sal)");
    }
    // ]]]

}

// ]]]
