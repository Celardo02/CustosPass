//! # Master Password
//!
//! This module defines how the master password and its related data are defined.

use crypto::hashing::HashVal;
use chrono::{NaiveDate, Utc};
use error::{Err, ErrSrc};

/// Defines the behavior of a struct storing master password data.
pub trait MstPwd {
    /// Returns an  `HashVal` containing the master password hash.
    fn get_hash_val(&self) -> &HashVal;

    /// Sets a new master password hash
    ///
    /// # Parameters
    ///
    /// - `h`: `HashVal` containing the master password hash and salt used to derive it
    fn set_hash_val(&mut self, h: HashVal);

    /// Returns the expiration date of the master password.
    fn get_exp_date(&self) -> &NaiveDate;

    /// Sets a new master password expiration date.
    ///
    /// # Parameters
    ///
    /// - `ed`: new expiration date
    ///
    /// # Returns 
    ///
    /// Returns `()` if `ed` does not predate or is equal to the current expiration date, `Err`
    /// otherwise.
    fn set_exp_date(&mut self, ed: NaiveDate) -> Result<(), Err>;
}

// A master password struct.
pub struct Master {
    hash_val: HashVal,
    exp_date: NaiveDate
}

impl Master {
    /// Creates a new Master instance with the given hash and exp_date value. Expiration date is
    /// based on UTC
    ///
    /// # Returns
    ///
    /// Returns `Master` if `exp_date` does not predate or is equal to the creation date of the struct, `Err`
    /// otherwise.
    pub fn new(hash: HashVal, exp_date:NaiveDate) -> Result<Self, Err> {
        if exp_date <= Utc::now().date_naive() {
            return Err(Err::new("can not create an already expired master password", ErrSrc::Domain));
        }

        Ok(Self {
            hash_val: hash,
            exp_date
        })
    }
}

impl MstPwd for Master {
    fn get_hash_val(&self) -> &HashVal {
        &self.hash_val
    }

    fn set_hash_val(&mut self, h: HashVal) {
        self.hash_val = h;
    }

    fn get_exp_date(&self) -> &NaiveDate {
        &self.exp_date
    }

    fn set_exp_date(&mut self, ed: NaiveDate) -> Result<(), Err> {
        if ed <= self.exp_date {
            return Err(Err::new("new expiration date predates or is equal to the current one", ErrSrc::Domain));
        }

        self.exp_date = ed;

        Ok(())
    }
}
