//! # Crypto
//!
//! This crate contains all the traits, structures and cryptography logic of the CustosPass 
//! project.
//!
//! # Example 
//! ```
//! use crypto::{CryptoProvider, rng::SystemRandom};
//! use std::collections::HashMap;
//!
//! // Initializing CryptoProvider with empty hash maps
//! let cp = match CryptoProvider::new_empty(SystemRandom::new()) {
//!     Ok(cp) => cp,
//!     Err(_) => panic!("unable to create CryptoProvider")
//! };
//!
//! // you can now use cp to perform hashing and symmetric encryption operations or to generate
//! // random values
//! ```
 
pub mod hashing;
pub mod symmetric;
pub mod rng;

pub use secure_string::SecureBytes;

use aws_lc_rs::try_fips_mode;
use std::collections::HashMap;
use crate::{
    hashing::{HashVal, SALT_LEN},
    rng::{Rng, SecureRandom},
    symmetric::NONCE_LEN
};
use error::{Err, ErrSrc};

const ERR_DESCR: &str = "no description";

// crypto provider [[[

/// Provides cryptographic capabilities.
///
/// # Security Note
///
/// Only __one instance__ of this class must be created at a time to guarantee: 
///     - salt and nonce reuse prevention
///     - criptographically secure random number generation
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
    /// Returns `CryptoProvider` if no error occurs, `Err` otherwise
    pub fn new_empty(rng: T) -> Result<Self, Err> {
        // checks if fips mode is enabled
        try_fips_mode().map_err(|_| Err::new(ERR_DESCR, ErrSrc::Crypto))?;

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
    /// Returns `CryptoProvider` if no error occurs, `Err` otherwise
    pub fn new(
        rng: T,
        old_salts: HashMap<[u8;SALT_LEN], Vec<HashVal>>,
        old_nonces: HashMap<[u8; NONCE_LEN], Vec<HashVal>>
    ) -> Result<Self, Err> {
        // checks if fips mode is enabled
        try_fips_mode().map_err(|_| Err::new(ERR_DESCR, ErrSrc::Crypto))?;

        Ok(
            CryptoProvider {
                rng: Rng::new(rng),
                old_salts,
                old_nonces
            }
        )
    }
}

// ]]]
