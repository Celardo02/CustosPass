//! # Rng 
//!
//! This module provides cryptographically secure random number generation capabilities.


use aws_lc_rs::rand::{self, SecureRandom};
use crate::{
    CryptoErr,
    hash::SALT_LEN,
    sym_enc::NONCE_LEN
};

/// Allows to generate cryptographically secure random numbers.
///
/// # Security Note
///
/// Only __one instance__ of this class must be created at a time to guarantee secure number 
/// generation.
pub struct Rng {
    /// Cryptographically secure random number generator.
    rng: rand::SystemRandom
}

impl Rng {
    pub fn new() -> Self {
        Rng {
            rng: rand::SystemRandom::new()
        }
    }
}

pub trait RandomNumberGenerator {
    /// Returns a random bytes `Vec` with the desired length or `CryptoErr`.
    fn generate(&self, len: usize) -> Result<Vec<u8>, CryptoErr>;

    /// Wrapper of `generate` method that returns a random salt value or `CryptoErr`.
    fn generate_salt(&self) -> Result<[u8; SALT_LEN], CryptoErr>;

    /// Wrapper of `generate` method that returns a random nonce value or `CryptoErr`.
    fn generate_nonce(&self) -> Result<[u8; NONCE_LEN], CryptoErr>;

}

impl RandomNumberGenerator for Rng {
    fn generate_salt(&self) -> Result<[u8; SALT_LEN], CryptoErr> {

        let salt: [u8; SALT_LEN] = self.generate(SALT_LEN)?
            .try_into()
            // try_into should never fail as the length of the array is the same passed to generate
            // method
            .unwrap();

        Ok(salt)
    }

    /// Returns a random nonce value or `CryptoErr`.
    fn generate_nonce(&self) -> Result<[u8; NONCE_LEN], CryptoErr> {
        
        let nonce: [u8; NONCE_LEN] = self.generate(NONCE_LEN)?
            .try_into()
            // try_into should never fail as the length of the array is the same passed to generate
            // method
            .unwrap();

        Ok(nonce)
    }

    fn generate(&self, len: usize) -> Result<Vec<u8>, CryptoErr> {
        let mut val = vec![0u8; len];

        self.rng.fill(&mut val)?;

        Ok(val)
    }
}
