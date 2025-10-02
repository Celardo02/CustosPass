//! # Rng 
//!
//! This module provides cryptographically secure random number generation capabilities.
//!
//! # Example 
//! ```
//! use crypto::{
//!     hashing::SALT_LEN,
//!     symmetric::NONCE_LEN,
//!     rng::{Rng, RandomNumberGenerator, SystemRandom}
//! };
//!
//! use error::{Err, ErrSrc};
//!
//! // create only one instance of Rng
//! let rng = Rng::new(SystemRandom::new());
//!
//! // generating a random value with an arbitrary length
//! let len = 10;
//! let random = match rng.generate(10) {
//!     Ok(r) => r,
//!     Err(e) => panic!("An error occurred: {}", e)
//! };
//!
//! assert_eq!(random.len(), 10);
//!
//! // generating a random salt value SALT_LEN long
//! let random_salt = match rng.generate_salt() {
//!     Ok(s) => s,
//!     Err(e) => panic!("An error occurred: {}", e)
//! };
//!
//! assert!(!random_salt.is_empty());
//!
//! // generating a random nonce value NONCE_LEN long
//! let random_nonce = match rng.generate_nonce() {
//!     Ok(n) => n,
//!     Err(e) => panic!("An error occurred: {}", e)
//! };
//!
//! assert!(!random_nonce.is_empty());
//! ```


pub use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use crate::{
    Err, ErrSrc, ERR_DESCR,
    hashing::SALT_LEN,
    symmetric::NONCE_LEN
};

/// Allows to generate cryptographically secure random numbers.
///
/// # Security Note
///
/// Only __one instance__ of this class must be created at a time to guarantee secure number 
/// generation.
pub struct Rng<T: SecureRandom> {
    /// Cryptographically secure random number generator.
    rng: T
}

impl <T: SecureRandom> Rng<T> {
    pub fn new(rng: T) -> Self {
        Rng {
            rng
        }
    }
}

pub trait RandomNumberGenerator {
    /// Returns a random bytes `Vec` with the desired length or `Err`.
    fn generate(&self, len: usize) -> Result<Vec<u8>, Err>;

    /// Wrapper of `generate` method that returns a random salt value or `Err`.
    fn generate_salt(&self) -> Result<[u8; SALT_LEN], Err>;

    /// Wrapper of `generate` method that returns a random nonce value or `Err`.
    fn generate_nonce(&self) -> Result<[u8; NONCE_LEN], Err>;

}

impl <T: SecureRandom> RandomNumberGenerator for Rng<T> {
    fn generate_salt(&self) -> Result<[u8; SALT_LEN], Err> {

        let salt: [u8; SALT_LEN] = self.generate(SALT_LEN)?
            .try_into()
            // try_into should never fail as the length of the array is the same passed to generate
            // method
            .unwrap();

        Ok(salt)
    }

    /// Returns a random nonce value or `Err`.
    fn generate_nonce(&self) -> Result<[u8; NONCE_LEN], Err> {
        
        let nonce: [u8; NONCE_LEN] = self.generate(NONCE_LEN)?
            .try_into()
            // try_into should never fail as the length of the array is the same passed to generate
            // method
            .unwrap();

        Ok(nonce)
    }

    fn generate(&self, len: usize) -> Result<Vec<u8>, Err> {
        let mut val = vec![0u8; len];

        self.rng.fill(&mut val).map_err(|_| Err::new(ERR_DESCR, ErrSrc::Crypto))?;

        Ok(val)
    }
}

// unit testing [[[
#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that `generate` actually generates a value of the desired length
    #[test]
    fn generate_fill() -> Result<(), Err> {
        let rng = Rng::new(SystemRandom::new());
        let len = 10;

        let val = rng.generate(len)?;

        assert_eq!(val.len(), len, "rng.generate does not generate a value with the desired length");

        Ok(())
    }

    /// Tests that `generate` does not always return the same value
    #[test]
    fn generate_ne() {
        let rng = Rng::new(SystemRandom::new());
        let len = 10;

        let val1 = match rng.generate(len) {
            Ok(v) => v,
            Err(_) =>  panic!("unable to generate val1")
        };

        let val2 = match rng.generate(len) {
            Ok(v) => v,
            Err(_) => panic!("unable to generate val2")
        };

        assert_ne!(val1, val2, "rng.generate returned the same value");
    }
}
// ]]]
