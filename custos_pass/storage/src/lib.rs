//! # Storage
//!
//! This crate contains all the traits, structures and persistence logic of the CustosPass project.

pub mod pers_mst;

pub const SPEC_CHARS: [char; 10] = ['-', '+', '_', '&', '%', '@', '$', '?', '!', '#'];
pub const MIN_PWD_LEN: usize = 10;
