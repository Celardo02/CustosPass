//! # Hashing
//!
//! This module provides hashing functionality to `CryptoProvider`.
//!
//! # Example
//! ```
//! use crypto::{
//!     CryptoProvider, 
//!     hashing::{Hashing, SHA512_OUTPUT_LEN},
//!     rng::SystemRandom,
//!     SecureBytes
//! };
//!
//! let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
//!     Ok(cp) => cp,
//!     Err(_) => panic!("unable to create CryptoProvider")
//! };
//!
//! let key = SecureBytes::new(Vec::from("key"));
//! let out_len = SHA512_OUTPUT_LEN;
//!
//! let hash = match cp.derive_hash(&key, out_len) {
//!     Ok(h) => h,
//!     Err(_) => panic!("unable to compute the hash")
//! };
//!
//! let hash_check = match CryptoProvider::<SystemRandom>::verify_hash(&key, hash.get_salt(), hash.get_hash()) {
//!     Ok(hc) => hc,
//!     Err(_) => panic!("unable to verify the hash")
//! };
//!
//! assert!(hash_check);
//! ```

pub use aws_lc_rs::digest::SHA512_OUTPUT_LEN;

use crate::{
    CryptoErr, CryptoProvider, HashMap, SecureBytes, 
    rng::{RandomNumberGenerator, SecureRandom, SystemRandom}
};
use aws_lc_rs::pbkdf2;
use std::num::NonZeroU32;

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

// HashVal [[[

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

// ]]]

/// Defines the hashing behavior offered by `crypto` module.
pub trait Hashing {

    /// Derives the hash for `key`.
    ///
    /// # Parameters
    /// - `key`: input key to derive the hash from. It must __NOT__ be empty
    /// - `out_len`: required output hash length. It must __NOT__ be 0
    ///
    /// # Returns
    ///
    /// Returns an `HashVal` containing the hash or `CryptoErr` if any error occurs.
    fn derive_hash(&mut self, key: &SecureBytes, out_len: usize) -> Result<HashVal, CryptoErr>;

    /// Verifies whether the hash of a provided key matches a previously derived one.
    ///
    /// # Parameters 
    ///
    /// - `new_key`: newly provided key to be hashed. It must __NOT__ be empty
    /// - `salt`: value used to salt `new_key`
    /// - `old_key`: previously derived key hash. It must __NOT__ be empty
    /// 
    /// # Returns
    ///
    /// Returns `true` if the hashes match, `false` if they do not, `CryptoErr` if either `new_key`
    /// or `old_key` is empty.
    fn verify_hash(new_key: &SecureBytes, salt: &[u8; SALT_LEN],  old_key: &SecureBytes) -> Result<bool, CryptoErr>;

    /// Returns all previously used keys for each salt.
    fn get_old_salts(&self) -> &HashMap<[u8;SALT_LEN], Vec<HashVal>>;
}

// CryptoProvider implementations [[[

impl <T: SecureRandom> CryptoProvider<T> {
    /// Computes an hash value.
    ///
    /// # Security Note
    ///
    /// This method do __NOT__ prevent salt reuse, hence reuse prevention must be handled by the caller method or
    /// function. Any other usage of this associated function may lead to security issues.
    ///
    /// # Parameters
    ///
    /// - `key`: key from which derive the hash. It must __NOT__ be empty
    /// - `salt`: hash salt value
    /// - `out_len`: hash length. It must __NOT__ be 0
    ///
    /// # Returns
    ///
    /// Returns a `SecureBytes` containing the hash value or `CryptoErr` if any error occurs.
    pub(super) fn compute_hash(key: &SecureBytes, salt: &[u8; SALT_LEN], out_len: usize) -> Result<SecureBytes, CryptoErr> {
        if key.unsecure().is_empty() || out_len == 0 {
            return Err(CryptoErr)
        }

        // in this case, no match is used as the argument is a non-zero constant
        let iter = NonZeroU32::new(KDF_ITER_FACTOR).unwrap();
        let mut out = SecureBytes::new(vec![0u8; out_len]);

        pbkdf2::derive(KDF_ALG, iter, salt, key.unsecure(), out.unsecure_mut());

        Ok(out)
    }
}

impl <T: SecureRandom> Hashing for CryptoProvider<T> {
    fn derive_hash(&mut self, key: &SecureBytes, out_len: usize) -> Result<HashVal, CryptoErr> {
        // checking inputs
        if key.unsecure().is_empty() || out_len == 0 {
            return Err(CryptoErr)
        }

        let mut salt = self.rng.generate_salt()?; 

        let mut used_salt = true;

        let mut out = CryptoProvider::<SystemRandom>::compute_hash(key, &salt, out_len)?;

        // checking whether the salt has already been used at all
        while let Some(key_vec) = self.old_salts.get(&salt) && used_salt {
            used_salt = false;


            // checking whether key has already been used with the current salt value or not
            for k in key_vec { 
                match CryptoProvider::<SystemRandom>::verify_hash(&out, k.get_salt(), k.get_hash()) {
                    Ok(true) => {
                        // key has already been used with current salt value
                        used_salt = true;
                        salt = self.rng.generate_salt()?; 
                        out = CryptoProvider::<SystemRandom>::compute_hash(key, &salt, out_len)?;
                        // quitting the loop as no more old keys can match the current salt value
                        break;
                    },
                    Ok(false) => {},
                    Err(ce) => return Err(ce)
                }
            }
        }


        // computing the hash of out to avoid salt reuse in the future

        let salt_old = self.rng.generate_salt()?;
        let hash_old = CryptoProvider::<SystemRandom>::compute_hash(&out, &salt_old, SHA512_OUTPUT_LEN)?;
        let old_k = HashVal::new(hash_old, salt_old);

        self.old_salts.entry(salt)
            // as is less likely to get the same salt twice than getting a new one, clone method 
            // is invoked here instead of or_insert
            .and_modify(|key_vec| key_vec.push(old_k.clone()))
            .or_insert(vec![old_k]);

        Ok(HashVal::new(out, salt))
    }

    fn verify_hash(new_key: &SecureBytes, salt: &[u8; SALT_LEN],  old_key: &SecureBytes) -> Result<bool, CryptoErr> {
        // checking inputs
        if new_key.unsecure().is_empty() || old_key.unsecure().is_empty() {
            return Err(CryptoErr)
        }

        // in this case, no match is used as the argument is a non-zero constant
        let iter = NonZeroU32::new(KDF_ITER_FACTOR).unwrap();
        
        Ok(pbkdf2::verify(KDF_ALG, iter, salt, new_key.unsecure(), old_key.unsecure()).is_ok())
    }

    fn get_old_salts(&self) -> &HashMap<[u8;SALT_LEN], Vec<HashVal>> {
        &self.old_salts
    }
}

// ]]]

// unit testing [[[
#[cfg(test)]

mod tests {
    use super::*;
    use crate::rng::SystemRandom;
    use aws_lc_rs::test::rand::{FixedSliceSequenceRandom, FixedByteRandom};
    use core::cell::UnsafeCell;

    // compute_hash [[[

    /// Tests that `compute_hash` returns an error in case of empty key
    #[test]
    fn compute_hash_empty_key () {
        match CryptoProvider::<SystemRandom>::compute_hash(
            &SecureBytes::new(Vec::new()),
            &[1u8; SALT_LEN],
            10
        ) {
            Ok(_) => panic!("hash recomputed with an empty key"),
            Err(_) => {}
        }
    }
    
    /// Tests that `compute_hash` returns an error if `out_len` is 0
    #[test]
    fn compute_hash_0_outlen () {
        match CryptoProvider::<SystemRandom>::compute_hash(
            &SecureBytes::new(Vec::from("test")),
            &[1u8; SALT_LEN],
            0
        ) {
            Ok(_) => panic!("hash recomputed with out_len 0"),
            Err(_) => {}
        }
    }

    /// Tests that `compute_hash` returns the same value given the same inputs
    #[test]
    fn compute_hash_same_out () {
        let key = SecureBytes::new(Vec::from("test"));
        let salt = [1u8; SALT_LEN];
        let out_len = 10;

        let h1 = match CryptoProvider::<SystemRandom>::compute_hash(&key, &salt, out_len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h1")
        };

        let h2 = match CryptoProvider::<SystemRandom>::compute_hash(&key, &salt, out_len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h2")
        };

        assert_eq!(h1,h2, "compute_hash does not return the same output given the same inputs");
    }

    /// Tests that `compute_hash` returns a different value given the same inputs, but the key
    #[test]
    fn compute_hash_diff_key () {
        let key1 = SecureBytes::new(Vec::from("test1"));
        let key2 = SecureBytes::new(Vec::from("test2"));
        let salt = [1u8; SALT_LEN];
        let out_len = 10;

        let h1 = match CryptoProvider::<SystemRandom>::compute_hash(&key1, &salt, out_len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h1")
        };

        let h2 = match CryptoProvider::<SystemRandom>::compute_hash(&key2, &salt, out_len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h2")
        };

        assert_ne!(h1,h2, "compute_hash returns the same value in spite of using a different key");
    }

    /// Tests that `compute_hash` returns a different value given the same inputs, but the salt
    #[test]
    fn compute_hash_diff_salt () {
        let key = SecureBytes::new(Vec::from("test"));
        let salt1 = [1u8; SALT_LEN];
        let salt2 = [2u8; SALT_LEN];
        let out_len = 10;

        let h1 = match CryptoProvider::<SystemRandom>::compute_hash(&key, &salt1, out_len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h1")
        };

        let h2 = match CryptoProvider::<SystemRandom>::compute_hash(&key, &salt2, out_len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h2")
        };

        assert_ne!(h1,h2, "compute_hash returns the same value in spite of using a different salt");
    }

    /// Tests that `compute_hash` returns a different value given the same inputs, but the output
    /// length 
    #[test]
    fn compute_hash_diff_outlen () {
        let key = SecureBytes::new(Vec::from("test"));
        let salt = [1u8; SALT_LEN];
        let out_len1 = 10;
        let out_len2 = 20;

        let h1 = match CryptoProvider::<SystemRandom>::compute_hash(&key, &salt, out_len1) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h1")
        };

        let h2 = match CryptoProvider::<SystemRandom>::compute_hash(&key, &salt, out_len2) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h2")
        };

        assert_ne!(h1,h2, "compute_hash returns the same value in spite of using a different out_len");
    }

    /// Tests that `compute_hash` returns a `SecureBytes` of the desired length
    #[test]
    fn compute_hash_correct_outlen () {
        let key = SecureBytes::new(Vec::from("test"));
        let salt = [1u8; SALT_LEN];
        let out_len = 10;

        let h = match CryptoProvider::<SystemRandom>::compute_hash(&key, &salt, out_len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h1")
        };

        assert_eq!(h.unsecure().len(),out_len, "returned hash does not have the desired length");
    }

    /// Tests that `compute_hash` returns a value which is different from `key`, even if the hash
    /// has the same length of `key`
    #[test]
    fn compute_hash_value () {
        let key = SecureBytes::new(Vec::from("test"));
        let salt = [1u8; SALT_LEN];

        let h = match CryptoProvider::<SystemRandom>::compute_hash(&key, &salt, key.unsecure().len()) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h1")
        };

        assert_ne!(h,key, "h and key are the same");
    }

    // ]]]

    // derive_hash [[[

    // Tests that `derive_hash` returns an error if `key` is empty
    #[test]
    fn derive_hash_empty_key () {
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        }; 

        match cp.derive_hash(&SecureBytes::new(Vec::new()), 10) {
            Ok(_) => panic!("no error with empty key"),
            Err(_) => {}
        };

    }

    // Tests that `derive_hash` returns an error if `out_len` is 0
    #[test]
    fn derive_hash_0_outlen () {
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        }; 

        match cp.derive_hash(&SecureBytes::new(Vec::from("key")), 0) {
            Ok(_) => panic!("no error with empty key"),
            Err(_) => {}
        };

    }

    /// Tests that `derive_hash` returns an error if `key` is empty and `out_len` is 0
    #[test]
    fn derive_hash_empty_key_0_outlen () {
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        }; 

        match cp.derive_hash(&SecureBytes::new(Vec::new()), 0) {
            Ok(_) => panic!("no error with empty key and 0 out_len"),
            Err(_) => {}
        };
    }

    // Tests that `derive_hash` returns an `HashVal` containing an hash of the desired length
    #[test]
    fn derive_hash_correct_outlen () {
        
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        }; 

        let key = SecureBytes::new(Vec::from("key"));
        let out_len = 100;

        let h = match cp.derive_hash(&key, out_len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h")
        };

        assert_eq!(h.get_hash().unsecure().len(), out_len, "HashVal.get_hash does not have the desired length");
    }

    // Tests that `derive_hash` returns two different `HashVal` with the same inputs
    #[test]
    fn derive_hash_same_inputs () {
        
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        }; 

        let key = SecureBytes::new(Vec::from("key"));
        let out_len = 100;

        let h1 = match cp.derive_hash(&key, out_len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h1")
        };

        let h2 = match cp.derive_hash(&key, out_len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h2")
        };

        assert_ne!(h1, h2, "derive_hash does not return 2 differente values");
    }

    // Tests that `derive_hash` returns an `HashVal` containing an hash that is different from
    // `key`, even if it has the same length of `key`
    #[test]
    fn derive_hash_value () {
        
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        }; 

        let key = SecureBytes::new(vec![1u8; SHA512_OUTPUT_LEN]);

        let h = match cp.derive_hash(&key, key.unsecure().len()) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h")
        };

        assert_ne!(h.get_hash(), &key, "HashVal and key are the same");
    }

    // Tests that `derive_hash` updates `CryptoProvider` field `old_salts` properly after using for
    // the first time a salt, that is adding a new entry in the hash map with the salt as the key
    // and an `HashVal` containing the hash of the computed hash as value
    #[test]
    fn derive_hash_new_salt () {

        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        }; 

        let key = SecureBytes::new(vec![1u8; 32]);
        let out_len = SHA512_OUTPUT_LEN;

        let h = match cp.derive_hash(&key, out_len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h")
        };

        match cp.old_salts.get(h.get_salt()) {
            Some(key_vec) => {
                assert_eq!(key_vec.len(), 1, "old_salts.get does not contain a single value");

                assert_eq!(
                    key_vec[0].get_hash(), 
                    &CryptoProvider::<SystemRandom>::compute_hash(
                        h.get_hash(), 
                        key_vec[0].get_salt(), 
                        key_vec[0].get_hash().unsecure().len()
                    ).unwrap(),
                    "h does not correspond to its hash"
                );

            },
            None => panic!("h.get_salt() not in cp.old_salts")
        };

    }

    // Tests that `old_salts` contains a different hash value from the output hash returned by 
    // `derive_hash`
    #[test]
    fn derive_hash_diff_hash () {

        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        }; 

        let key = SecureBytes::new(vec![1u8; 32]);
        let out_len = SHA512_OUTPUT_LEN;

        let h = match cp.derive_hash(&key, out_len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h")
        };

        match cp.old_salts.get(h.get_salt()) {
            Some(key_vec) => {
                assert_ne!(
                    key_vec[0].get_hash(), 
                    h.get_hash(),
                    "h.get_hash is the same value stored in old_salts"
                );

            },
            None => panic!("h.get_salt() not in cp.old_salts")
        };

    }

    // Tests that `derive_hash` updates `CryptoProvider` field `old_salts` properly after using 
    // again a salt with a new key, that is adding a new `HashVal` in the `Vec` related to the
    // salt which contains the hash of the computed hash
    #[test]
    fn derive_hash_same_salt () {

        let fixed_bytes = FixedByteRandom { byte: 1 };
        let mut cp = match CryptoProvider::new_empty(fixed_bytes) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        }; 

        let key1 = SecureBytes::new(vec![2u8; 32]);
        let key2 = SecureBytes::new(vec![3u8; 32]);
        let out_len = SHA512_OUTPUT_LEN;

        let h1 = match cp.derive_hash(&key1, out_len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h1")
        };

        let h2 = match cp.derive_hash(&key2, out_len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h2")
        };

        match cp.old_salts.get(h1.get_salt()) {
            Some(key_vec) => {
                assert_eq!(key_vec.len(), 2, "old_salts.get does not contain 2 values");

                assert_eq!(
                    key_vec[0].get_hash(), 
                    &CryptoProvider::<SystemRandom>::compute_hash(
                        h1.get_hash(), 
                        key_vec[0].get_salt(), 
                        key_vec[0].get_hash().unsecure().len()
                    ).unwrap(),
                    "h1 does not correspond to its hash"
                );

                assert_eq!(
                    key_vec[1].get_hash(), 
                    &CryptoProvider::<SystemRandom>::compute_hash(
                        h2.get_hash(), 
                        key_vec[1].get_salt(), 
                        key_vec[1].get_hash().unsecure().len()
                    ).unwrap(),
                    "h2 does not correspond to its hash"
                );

            },
            None => panic!("h1.get_salt() not in cp.old_salts")
        };

    }

    // Tests that `derive_hash` regenerate the salt value when it has already been used for a given
    // key
    #[test]
    fn derive_hash_regen_salt () {

        let salt1 = [1u8; SALT_LEN];
        let salt_filler = [3u8; SALT_LEN];
        let salt2 = [2u8; SALT_LEN];
        let fixed_seq = FixedSliceSequenceRandom {
            bytes: &[&salt1, &salt_filler, &salt1, &salt2, &salt_filler],
            current: UnsafeCell::new(0)
        };
        let mut cp = match CryptoProvider::new_empty(fixed_seq) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        }; 

        let key = SecureBytes::new(vec![1u8; 32]);
        let out_len = SHA512_OUTPUT_LEN;

        let h1 = match cp.derive_hash(&key, out_len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h1")
        };

        let h2 = match cp.derive_hash(&key, out_len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h2")
        };

        assert_ne!(h1.get_salt(), h2.get_salt(), "h2 was generated using the same salt of h1");
    }

    // ]]]

    // verify_hash tests [[[

    /// Tests that `verify_hash` returns an error if `new_key` is empty
    #[test]
    fn verify_hash_empty_newkey () {
        match CryptoProvider::<SystemRandom>::verify_hash(&SecureBytes::new(Vec::new()), &[1u8; SALT_LEN], &SecureBytes::new(Vec::from("old_key"))) {
            Ok(_) => panic!("no error with empty new_key"),
            Err(_) => {}
        };
    }

    /// Tests that `verify_hash` returns an error if `old_key` is empty
    #[test]
    fn verify_hash_empty_oldkey () {
        match CryptoProvider::<SystemRandom>::verify_hash(&SecureBytes::new(Vec::from("new_key")), &[1u8; SALT_LEN], &SecureBytes::new(Vec::new())) {
            Ok(_) => panic!("no error with empty old_key"),
            Err(_) => {}
        };
    }

    /// Tests that `verify_hash` returns an error if both `old_key` and `new_key` are empty
    #[test]
    fn verify_hash_empty_newkey_oldkey () {
        match CryptoProvider::<SystemRandom>::verify_hash(&SecureBytes::new(Vec::new()), &[1u8; SALT_LEN], &SecureBytes::new(Vec::new())) {
            Ok(_) => panic!("no error with empty old_key and new_key"),
            Err(_) => {}
        };
    }

    /// Tests that `verify_hash` returns `Ok(true)` if `new_key` hash salted with `salt` is `old_key`
    #[test]
    fn verify_hash_true () {
        let len = 10;
        let val = SecureBytes::new(Vec::from("key"));

        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CrytoProvider")
        };

        let h = match cp.derive_hash(&val, len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h")
        };

        assert!(
            CryptoProvider::<SystemRandom>::verify_hash(&val, h.get_salt(), h.get_hash()).unwrap(),
            "new_key does not correspond to old_key"
        );
    }

    /// Tests that `verify_hash` returns `Ok(false)` if `old_key` is derived from a different key from
    /// `new_key`, even with the same salt value
    #[test]
    fn verify_hash_false_diff_newkey () {
        let len = 10;
        let val1 = SecureBytes::new(Vec::from("key"));
        let val2 = SecureBytes::new(Vec::from("another_key"));

        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CrytoProvider")
        };

        let h = match cp.derive_hash(&val1, len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h")
        };

        assert!(
            !CryptoProvider::<SystemRandom>::verify_hash(&val2, h.get_salt(), h.get_hash()).unwrap(),
            "old_key is not the hash of val2"
        );
    }

    /// Tests that `verify_hash` returns `Ok(false)` if `old_key` is derived from `new_key`, but with 
    /// a different salt
    #[test]
    fn verify_hash_false_diff_salt () {
        let len = 10;
        let val = SecureBytes::new(Vec::from("key"));

        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CrytoProvider")
        };

        let h = match cp.derive_hash(&val, len) {
            Ok(h) => h,
            Err(_) => panic!("unable to compute h")
        };

        let mut salt = match cp.rng.generate_salt() {
            Ok(s) => s,
            Err(_) => panic!("unable to generate a new salt value")
        };

        while &salt == h.get_salt() {
            salt = match cp.rng.generate_salt() {
                Ok(s) => s,
                Err(_) => panic!("unable to generate a new salt value")
            };
        }

        assert!(
            !CryptoProvider::<SystemRandom>::verify_hash(&val, &salt, h.get_hash()).unwrap(),
            "new_key does not correspond to old_key"
        );
    }
    // ]]]
}

// ]]]
