//! # Master Password Persistence
//!
//! This module provides the persistence logic to store the vault master password.

use chrono::{NaiveDate, TimeDelta, Utc};
use domain::mst_pwd::{MstPwd, Master};
use error::{Err, ErrSrc};
use crypto::{CryptoProvider, SecureBytes, hashing::{Hashing, HashVal}, rng::SystemRandom};
use crate::{SPEC_CHARS, SecureString};


/// Master password expiration time delta. It corresponds to 3 months expressed in seconds
/// (assuming that eah month has 30 days for simplicity).
const MST_EXP: i64 = 3 * 30 * 24 * 60 * 60;

pub trait PersMst<H: Hashing, M: MstPwd> {
    /// Checks whether the master password is expired or not.
    ///
    /// # Returns
    ///
    /// Returns `true` if the master passwrod is expired, `false` otherwise.
    fn check_exp(&self) -> bool;

    /// Returns the master password hash and related salt.
    fn get_mst(&self) -> &M;

    /// Sets the master password value to a given one.
    ///
    /// # Parameters
    ///
    /// - `new_mst`: new master password value that will not be out of date for 3 months. It must:
    ///     - be at least 10 characters long
    ///     - contain at least:
    ///         - a capital letter
    ///         - a lowercase letter
    ///         - a number
    ///         - a special character from `SPEC_CHARS`
    /// - `hash_provider`: provides required hashing functionality to store the master password
    ///
    /// # Returns
    ///
    /// Returns `()` if the master password was set successfully, `Err` otherwise.
    fn set_mst(&mut self, new_mst: &SecureString, hash_provider: &mut H) -> Result<(), Err>;

    /// Validates a given password against the master password hash.
    ///
    /// # Parameters
    ///
    /// - `pwd`: password to validate
    ///
    /// # Returns
    ///
    /// Returns `true` if `pwd` correspond to the master password, `false` if they do not, `Err` if
    /// `pwd` is empty.
    fn validate_pwd(&self, pwd: &SecureBytes) -> Result<bool, Err>;

    /// Returns old master password hashes an related salts.
    fn get_old_msts(&self) -> &Vec<HashVal>;
}


// PersMaster [[[

pub struct PersMaster {
    mst: Master,
    old_mst: Vec<HashVal>
}

impl PersMaster {
    /// Creates a new instance of PersMaster
    ///
    /// # Parameters
    ///
    /// - `mst`: master password value
    /// - `old_mst`: previously used master passwords. A new `Vec` is created if `None`
    pub fn new(mst: Master, old_mst: Option<Vec<HashVal>>) -> Self {
        let om = match old_mst {
            Some(om) => om,
            None => Vec::new()
        };

        Self {
            mst,
            old_mst: om
        }
    }
}

impl PersMst<CryptoProvider<SystemRandom>, Master> for PersMaster {
    fn check_exp(&self) -> bool {
        self.mst.get_exp_date() >= &Utc::now().date_naive()
    }

    fn get_mst(&self) -> &Master {
        &self.mst
    }

    fn set_mst(&mut self, new_mst: &SecureString, hash_provider: &mut CryptoProvider<SystemRandom>) -> Result<(), Err> {
        unimplemented!()
    }

    fn validate_pwd(&self, pwd: &SecureBytes) -> Result<bool, Err> {
        if pwd.unsecure().is_empty() {
            return Err(Err::new("empty password to validate", ErrSrc::Storage));
        }

        CryptoProvider::<SystemRandom>::verify_hash(
            pwd,
            self.mst.get_hash_val().get_salt(),
            self.mst.get_hash_val().get_hash()
        )
    }

    fn get_old_msts(&self) -> &Vec<HashVal> {
        &self.old_mst
    }
}
// ]]]
