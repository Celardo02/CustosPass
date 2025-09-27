//! # Crypto Core
//!
//! This module provides access to all the features of the cryptographic library.
//!
//! # Example 
//! ```
//! use core::crypto_core::CryptoProvider;
//! use crypto::rng::SystemRandom;
//! use std::collections::HashMap;
//!
//! // Initializing CryptoProvider with empty hash maps
//! let cp = match CryptoProvider::new_empty(SystemRandom::new()) {
//!     Ok(cp) => cp,
//!     Err(_) => panic!("unable to create CryptoProvider")
//! };
//! ```

pub mod sym_enc_res;
pub mod hash_val;

pub mod crypto_core_hashing;
pub mod crypto_core_sym;

use aws_lc_rs::try_fips_mode;
use std::collections::HashMap;

use crypto::{
    hash::{Hash, HashProvider, SALT_LEN, SHA512_OUTPUT_LEN},
    rng::{RandomNumberGenerator, Rng, SecureRandom},
    sym_enc::NONCE_LEN,
    SecureBytes,
    CryptoErr
};

use crate::crypto_core::hash_val::HashVal;

/// Provides cryptographic capabilities.
///
/// # Security Note
///
/// Only __one instance__ of this class must be created at a time to guarantee salt and nonce 
/// reuse prevention.
pub struct CryptoProvider<T: SecureRandom> {
    rng: Rng<T>,

    /// Hash map storing all the keys that have ever been used for each salt value in the 
    /// key derivation function.
    old_salts: HashMap<[u8;SALT_LEN], Vec<HashVal>>,

    /// Hash map storing all the keys that have ever been used for each nonce value in the
    /// encryption function
    old_nonces: HashMap<[u8;NONCE_LEN], Vec<HashVal>>
}

impl <T: SecureRandom> CryptoProvider<T> {
    /// Initialize a new instance of CryptoProvider.
    ///
    /// # Returns 
    ///
    /// Returns `CryptoProvider` if no error occurs, `CryptoErr` otherwise
    pub fn new_empty(rng: T) -> Result<Self, CryptoErr> {
        // checks if fips mode is enabled
        try_fips_mode().map_err(|_| CryptoErr)?;

        Ok( 
            CryptoProvider { 
                rng: Rng::new(rng),
                old_salts: HashMap::new(),
                old_nonces: HashMap::new()
            }
        )
    }


    /// Initialize a new instance of `CryptoProvider` with existing `old_salts` and `old_nonces`
    /// hash maps.
    ///
    /// # Returns 
    ///
    /// Returns `CryptoProvider` if no error occurs, `CryptoErr` otherwise
    pub fn new(
        rng: T,
        old_salts: HashMap<[u8;SALT_LEN], Vec<HashVal>>,
        old_nonces: HashMap<[u8; NONCE_LEN], Vec<HashVal>>
    ) -> Result<Self, CryptoErr> {
        // checks if fips mode is enabled
        try_fips_mode().map_err(|_| CryptoErr)?;

        Ok(
            CryptoProvider {
                rng: Rng::new(rng),
                old_salts,
                old_nonces
            }
        )
    }
}
