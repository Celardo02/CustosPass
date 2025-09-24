//! # Crypto Core
//!
//! This module provide access to all the cryptography library functionalities

pub mod old_key;
pub mod sym_enc_res;
pub mod crypto_core_hashing;

use aws_lc_rs::try_fips_mode;
use std::collections::HashMap;

use crypto::{
    hash::{Hash, HashProvider, SALT_LEN, SHA512_OUTPUT_LEN},
    sym_enc::{KEY_LEN, NONCE_LEN},
    SecureBytes,
    CryptoErr
};

use crate::crypto_core::{
    old_key::OldKey,
    sym_enc_res::SymEncRes,
    crypto_core_hashing::*
};

/// Provides cryptographic capabilities.
///
/// # Security Note
///
/// Only __one instance__ of this class must be created at a time to guarantee salt and nonce 
/// reuse prevention.
pub struct CryptoProvider {
    hash: HashProvider,

    /// Hash map storing all the keys that have ever been used for each salt value in the 
    /// key derivation function.
    old_salts: HashMap<[u8;SALT_LEN], Vec<OldKey>>,

    /// Hash map storing all the keys that have ever been used for each nonce value in the
    /// encryption function
    old_nonces: HashMap<[u8;NONCE_LEN], Vec<OldKey>>
}

impl CryptoProvider {
    /// Initialize a new instance of CryptoProvider.
    ///
    /// # Returns 
    ///
    /// Returns `CryptoProvider` if no error occurs, `CryptoErr` otherwise
    pub fn new_empty() -> Result<Self, CryptoErr> {
        // checks if fips mode is enabled
        try_fips_mode().map_err(|_| CryptoErr)?;

        Ok( 
            CryptoProvider { 
                hash: HashProvider::new(),
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
        old_salts: HashMap<[u8;SALT_LEN], Vec<OldKey>>,
        old_nonces: HashMap<[u8; NONCE_LEN], Vec<OldKey>>
    ) -> Result<Self, CryptoErr> {
        // checks if fips mode is enabled
        try_fips_mode().map_err(|_| CryptoErr)?;

        Ok(
            CryptoProvider {
                hash: HashProvider::new(),
                old_salts,
                old_nonces
            }
        )
    }
}
