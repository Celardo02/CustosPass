//! # Crypto
//!
//! This crate contains all the traits, structures and cryptography logic of the CustosPass 
//! project.
 
pub mod hash;
pub mod rng;
pub mod sym_enc;

use std::{error, fmt::{Display, Formatter, Result}};

pub use secure_string::SecureBytes;

// CryptoErr [[[

/// A generic error that does not leak any information.
#[derive(Debug)]
pub struct CryptoErr;

impl Display for CryptoErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "Cryptographic error")
    }
}

impl<E: error::Error> From<E> for CryptoErr {
    fn from(_err: E) -> Self {
        CryptoErr
    }
}
// ]]]
