//! # Crypto errors
//!
//! This module contains all the errors that `crypto` module can generate.

use std::fmt;

// CryptoErrKind [[[

/// Describes the kind of error that occurred.
#[derive(Debug, Clone)]
pub enum CryptoErrKind {
    InpuNullOrEmpty,
}

impl fmt::Display for CryptoErrKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CryptoErrKind::InpuNullOrEmpty => write!(f, "input null or empty")
        }
    }
}

// ]]]

// CryptoErrOrigin [[[

/// Describes the cryptography operation type that originated the error.
#[derive(Debug, Clone)]
pub enum CryptoErrOrigin {
    SymmetricEncryption,
    AsymmetricEncryption,
    Hashing
}

impl fmt::Display for CryptoErrOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CryptoErrOrigin::SymmetricEncryption => write!(f, "symmetric encryption"),
            CryptoErrOrigin::AsymmetricEncryption => write!(f, "asymmetric encryption"),
            CryptoErrOrigin::Hashing => write!(f, "hashing")
        }
    }
}

// ]]]

/// Contains all the useful information about an error.
#[derive(Debug, Clone)]
pub struct CryptoErr{
    orig: CryptoErrOrigin,
    kind: CryptoErrKind,
    msg: String
}

impl CryptoErr {
    /// Creates a new CryptoErr from a known kind of error and an error message.
    pub fn new(kind: CryptoErrKind, orig: CryptoErrOrigin, msg: &str) -> CryptoErr {
        CryptoErr {
            kind,
            orig,
            msg: String::from(msg)
        }
    }

    /// Returns the error kind.
    pub fn get_kind(&self) -> &CryptoErrKind {
        &self.kind
    }

    /// Returns the error operation type.
    pub fn get_orig(&self) -> &CryptoErrOrigin {
        &self.orig
    }

    /// returns the error message.
    pub fn get_msg(&self) -> &str {
        &self.msg
    }
}

impl fmt::Display for CryptoErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cryptography module error (origin {0}): {1}", self.orig, self.msg)
    }
}
