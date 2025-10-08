//! # Master Password
//!
//! This module defines how the master password and its related data are defined.

use crypto::hashing::HashVal;
use chrono::{NaiveDate, TimeDelta, Utc};
use error::{Err, ErrSrc};

/// Master password expiration time delta. It corresponds to 3 months expressed in seconds
/// (assuming that each month has 30 days for simplicity).
const MST_EXP: i64 = 3 * 30 * 24 * 60 * 60;

/// Defines the behavior of a struct storing master password data.
pub trait MstPwd where Self: Sized{
    /// Creates a new master password instance with the given hash. The password will be valid for
    /// 3 months. Time measurments are based on UTC timeszone.
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

    /// Sets a new master password hash and updates its expiration date to be valid for 3 months
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
    use crypto::{SecureBytes, hashing::SALT_LEN};

    // seconds in a day
    const DAY: i64 = 60 * 60 * 24;

    // new [[[
    /// Tests that `new` returns a `Master` instance that expires after 3 months
    #[test]
    fn new_3_months () {
        let hv = HashVal::new(SecureBytes::new(Vec::from("master")), [1u8; SALT_LEN])
            .expect("unable to create HashVal");
        let m = Master::new(hv);

        assert_eq!(
            m.exp_date,
            Utc::now().date_naive().checked_add_signed(TimeDelta::seconds(MST_EXP)).unwrap(),
            "new associated function does not set expiration date properly"
        );
    }

    /// Tests that `new` actually sets `hash_val` field with `hash` argument
    #[test]
    fn new_value(){
        let hv = HashVal::new(SecureBytes::new(Vec::from("master")), [1u8; SALT_LEN])
            .expect("unable to create HashVal");
        let m = Master::new(hv.clone());

        assert_eq!(hv, m.hash_val, "hash argument is ignored");
    }
    // ]]]

    // new with date [[[
    /// Tests that `new_with_date` actually sets `hash_val` and `exp_date` fields with the provided
    /// arguments
    #[test]
    fn new_with_date_value(){
        let hv = HashVal::new(SecureBytes::new(Vec::from("master")), [1u8; SALT_LEN])
            .expect("unable to create HashVal");
        let exp = Utc::now().date_naive().checked_add_signed(TimeDelta::seconds(DAY)).unwrap();
        let m = Master::new_with_date(hv.clone(), exp.clone())
            .expect("unable to create Master");

        assert_eq!(hv, m.hash_val, "hash argument is ignored");
        assert_eq!(exp, m.exp_date, "exp_date argument is ignored");
    }

    /// Tests that `new_with_date` returns an error if `exp_date` argument predates 
    /// the current day
    #[test]
    fn new_with_date_predate(){
        let hv = HashVal::new(SecureBytes::new(Vec::from("master")), [1u8; SALT_LEN])
            .expect("unable to create HashVal");
        let exp = Utc::now().date_naive().checked_add_signed(TimeDelta::seconds(-DAY)).unwrap();

        assert!(
            Master::new_with_date(hv, exp).is_err(),
            "no error when exp_date predates the current day"
        );
    }

    /// Tests that `new_with_date` returns an error if `exp_date` argument is equal to 
    /// the current day
    #[test]
    fn new_with_date_current_date(){
        let hv = HashVal::new(SecureBytes::new(Vec::from("master")), [1u8; SALT_LEN])
            .expect("unable to create HashVal");
        let exp = Utc::now().date_naive();

        assert!(
            Master::new_with_date(hv, exp).is_err(),
            "no error when exp_date is equal to the current day"
        );
    }
    // ]]]

    // set hash val [[[

    /// Tests that `set_hash_val` updates the expiration date
    #[test]
    fn set_hash_val_date() {
        let hv = HashVal::new(SecureBytes::new(Vec::from("master")), [1u8; SALT_LEN])
            .expect("unable to create HashVal");

        let exp = Utc::now().date_naive().checked_add_signed(TimeDelta::seconds(DAY)).unwrap();

        let mut m = Master::new_with_date(hv.clone(), exp)
            .expect("unable to create m");

        m.set_hash_val(hv);

        assert_eq!(
            m.get_exp_date(),
            &Utc::now()
                .date_naive()
                .checked_add_signed(TimeDelta::seconds(MST_EXP))
                .unwrap(),
            "new expiration date has not got a time delta of MST_EXP"
        );
    }

    /// Tests that `set_hash_val` updates `hash_val` field value
    #[test]
    fn set_hash_val_update() {
        let hv = HashVal::new(SecureBytes::new(Vec::from("master")), [1u8; SALT_LEN])
            .expect("unable to create HashVal");

        let exp = Utc::now().date_naive().checked_add_signed(TimeDelta::seconds(DAY)).unwrap();

        let mut m = Master::new_with_date(hv, exp)
            .expect("unable to create m");

        let hv2 = HashVal::new(SecureBytes::new(Vec::from("new_master")), [1u8; SALT_LEN])
            .expect("unable to create HashVal 2");

        m.set_hash_val(hv2.clone());

        assert_eq!(m.get_hash_val(), &hv2, "set_hash_val does not update hash val field");
    }

    // ]]]

    /// Tests that `get_hash_val` actually returns `hash_val` field value
    #[test]
    fn get_hash_val_value() {
        let hv = HashVal::new(SecureBytes::new(Vec::from("master")), [1u8; SALT_LEN])
            .expect("unable to create HashVal");
        let m = Master::new(hv.clone());

        assert_eq!(&hv, m.get_hash_val(), "get_hash_val does not return the correct value");
    }

    /// Tests that `get_exp_date` actually returns `exp_date` field value
    #[test]
    fn get_exp_date_value() {
        let hv = HashVal::new(SecureBytes::new(Vec::from("master")), [1u8; SALT_LEN])
            .expect("unable to create HashVal");
        let exp = Utc::now().date_naive().checked_add_signed(TimeDelta::seconds(DAY)).unwrap();
        let m = Master::new_with_date(hv, exp.clone())
            .expect("unable to create Master");

        assert_eq!(&exp, m.get_exp_date(), "get_exp_date does not return the correct value");
    }

}

// ]]
