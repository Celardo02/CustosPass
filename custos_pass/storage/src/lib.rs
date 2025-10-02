//! # Storage
//!
//! This crate contains all the traits, structures and persistence logic of the CustosPass project.

pub mod pers_mst;

pub use secure_string::SecureString;

pub const SPEC_CHARS: [char; 10] = ['-', '+', '_', '&', '%', '@', '$', '?', '!', '#'];
