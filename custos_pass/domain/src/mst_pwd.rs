//! # Master Password
//!
//! This module defines how the master password and its related data are defined.

use crypto::hashing::HashVal;
use chrono::{NaiveDate, TimeDelta, Utc};
use error::{Err, ErrSrc};

/// Master password expiration time delta. It corresponds to 3 months expressed in seconds
/// (assuming that each month has 30 days for simplicity).
pub const MST_EXP: i64 = 3 * 30 * 24 * 60 * 60;

/// Defines the behavior of a struct storing master password data.
pub trait MstPwd where Self: Sized{
    /// Creates a new master password instance with the given hash. The password will be valid for
    /// `MST_EXP` seconds. Time measurments are based on UTC timeszone.
    fn new(hash: HashVal) -> Self;

    /// Creates a new master password instance with the given hash and exp_date value. Expiration date is
    /// based on UTC
    ///
    /// # Returns
    ///
    /// Returns `Self` if `exp_date` does not predate or is equal to the creation date of the struct, `Err`
    /// otherwise.
    fn new_with_date(hash: HashVal, exp_date:NaiveDate) -> Result<Self, Err>;

    /// Returns an  `HashVal` containing the master password hash.
    fn get_hash_val(&self) -> &HashVal;

    /// Sets a new master password hash and sets its expiration date t
    ///
    /// # Parameters
    ///
    /// - `h`: `HashVal` containing the master password hash and salt used to derive it
    fn set_hash_val(&mut self, h: HashVal);

    /// Returns the expiration date of the master password.
    fn get_exp_date(&self) -> &NaiveDate;
}

// Master [[[

// A master password struct.
#[derive(Clone, Debug)]
pub struct Master {
    hash_val: HashVal,
    exp_date: NaiveDate
}

impl MstPwd for Master {
    fn new(hash: HashVal) -> Self {
        let exp_date = Utc::now()
            .date_naive()
            .checked_add_signed(TimeDelta::seconds(MST_EXP))
            // this unwrap call should never panic as MST_EXP is not outside of the allowed
            // interval
            .unwrap();

        Self {
            hash_val: hash,
            exp_date
        }
    }

    fn new_with_date(hash: HashVal, exp_date:NaiveDate) -> Result<Self, Err> {
        if exp_date <= Utc::now().date_naive() {
            return Err(Err::new("can not create an already expired master password", ErrSrc::Domain));
        }

        Ok(Self {
            hash_val: hash,
            exp_date
        })
    }

    fn get_hash_val(&self) -> &HashVal {
        &self.hash_val
    }

    fn set_hash_val(&mut self, h: HashVal) {
        // updating hash vaulue
        self.hash_val = h;

        // udating expiration date. unwrap is used as MST_EXP is a contant value that should not
        // make the method panic
        self.exp_date = Utc::now().date_naive().checked_add_signed(TimeDelta::seconds(MST_EXP)).unwrap();
    }

    fn get_exp_date(&self) -> &NaiveDate {
        &self.exp_date
    }
}
// ]]]

// testing [[[
#[cfg(test)]

mod test {
    use super::*;
    use crypto::{SecureBytes, CryptoProvider, hashing::{Hashing, SHA512_OUTPUT_LEN}, rng::SystemRandom,};

    // seconds in a day
    const DAY: i64 = 60 * 60 * 24;

    /// Tests that `set_hash_val` updates the expiration date
    #[test]
    fn set_hash_val_update() {
        let pwd = SecureBytes::new(Vec::from("pwd"));
        let mut cp = CryptoProvider::new_empty(SystemRandom::new())
            .expect("unable to create CryptoProvider");

        let hv = cp.derive_hash(&pwd, SHA512_OUTPUT_LEN)
                .expect("unable to derive HashVal");

        let exp = Utc::now().date_naive()
            .checked_add_signed(TimeDelta::seconds(DAY))
            .expect("unable to get current date + 1 day");

        let mut m = Master::new(hv.clone(), exp)
            .expect("unable to create m");

        m.set_hash_val(hv);

        assert_eq!(
            m.get_exp_date(),
            &Utc::now()
                .date_naive()
                .checked_add_signed(TimeDelta::seconds(MST_EXP))
                .expect("unable to get current date + MST_EXP"),
            "new expiration date has not got a time delta of MST_EXP"
        );

    }
}

// ]]
