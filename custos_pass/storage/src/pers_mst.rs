//! # Master Password Persistence
//!
//! This module provides the persistence logic to store the vault master password.
//!
//! # Example
//! ```
//! use crypto::{CryptoProvider, SecureBytes, hashing::Hashing, rng::SystemRandom};
//! use storage::pers_mst::{PersMst, PersMaster};
//! use domain::mst_pwd::Master;
//!
//! let pwd = SecureBytes::new(Vec::from("A_strong_password1"));
//! let mut cp = CryptoProvider::new_empty(SystemRandom::new())
//!     .expect("unable to create CryptoProvider");
//!
//! // creating the storage layer
//! let mut pers = PersMaster::<Master>::new_with_bytes(pwd.clone(), None, &mut cp)
//!     .expect("unable to create PersMaster");
//!
//! // checking that the newly created master password is not expired yet
//! assert!(!pers.check_exp());
//!
//! // checking that pwd is the master password
//! assert!(pers.validate_pwd::<CryptoProvider<SystemRandom>>(&pwd).unwrap());
//!
//! // setting a new master password
//! let new_pwd = SecureBytes::new(Vec::from("A_newly_created_master_password1"));
//! pers.set_mst(new_pwd.clone(), &mut cp);
//!
//! // checking that the master password has been changed as expected
//! assert!(pers.validate_pwd::<CryptoProvider<SystemRandom>>(&new_pwd).unwrap());
//! assert!(!pers.validate_pwd::<CryptoProvider<SystemRandom>>(&pwd).unwrap());
//! ```

use crate::{MIN_PWD_LEN, SPEC_CHARS};
use chrono::Utc;
use crypto::{SecureBytes, hashing::{Hashing, HashVal, SHA512_OUTPUT_LEN}};
use domain::mst_pwd::MstPwd;
use error::{Err, ErrSrc};
use regex::RegexSet;
use zeroize::Zeroize;


pub trait PersMst<M: MstPwd> {
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
    fn set_mst<H: Hashing>(&mut self, new_mst: SecureBytes, hash_provider: &mut H) -> Result<(), Err>;

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
    fn validate_pwd<H: Hashing>(&self, pwd: &SecureBytes) -> Result<bool, Err>;

    /// Returns old master password hashes an related salts.
    fn get_old_mst(&self) -> &Vec<HashVal>;
}


// PersMaster [[[

pub struct PersMaster<M: MstPwd> {
    mst: M,
    old_mst: Vec<HashVal>
}

impl<M:MstPwd> PersMaster<M> {
    /// Creates a new instance of `PersMaster` from a master password and a `Vec` of old master
    /// password hashes.
    ///
    /// # Security Note
    ///
    /// `mst` is assumed to be derived from a valid master password. No validation is done
    /// by this associated function.
    ///
    /// Use `new_with_bytes` if master password validation is needed.
    pub fn new(mst: M, old_mst: Option<Vec<HashVal>>) -> Self {
        let om = match old_mst {
            Some(om) => om,
            None => Vec::new()
        };

        Self {
            mst,
            old_mst: om
        }
    }

    /// Creates a new instance of PersMaster from a master password and a `Vec` of old master
    /// password hashes.
    ///
    /// # Parameters
    ///
    /// - `mst_bytes`: master password value. It must be:
    ///     - be at least 10 characters long
    ///     - contain at least:
    ///         - a capital letter
    ///         - a lowercase letter
    ///         - a number
    ///         - a special character from `SPEC_CHARS`
    ///
    ///     The string will be zeroized not to store the password in plaintext
    ///
    /// - `old_mst`: previously used master passwords. A new `Vec` is created if `None`
    ///
    /// # Returns
    ///
    /// Returns `PersMaster` if no error occurs, `Err` otherwise.
    pub fn new_with_bytes<H: Hashing>(
        mst_bytes: SecureBytes,
        old_mst: Option<Vec<HashVal>>,
        hash_provider: &mut H)
    -> Result<Self, Err> {

        PersMaster::<M>::validate_mst(&mst_bytes)?;

        let mst_hash = hash_provider.derive_hash(&mst_bytes, SHA512_OUTPUT_LEN)?;

        Ok(PersMaster::<M>::new(M::new(mst_hash), old_mst))
    }

    /// Validates the master password string ensuring that it:
    ///     - is at least 10 characters long
    ///     - contains at least:
    ///         + a capital letter
    ///         + a lowercase letter
    ///         + a number
    ///         + a special character from `SPEC_CHARS`
    ///
    /// # Returns
    ///
    /// Returns `()` if `mst` is valid, an `Err` describing what went wrong otherwise.
    fn validate_mst(mst: &SecureBytes) -> Result<(), Err> {
        
        // convertig new_mst to a string to perform validation
        let mut mst_str = match String::from_utf8(mst.unsecure().to_vec()) {
            Ok(mst) => mst,
            Err(_) => return Err(Err::new("new master password is not a utf-8 string", ErrSrc::Storage))
        };

        if mst_str.chars().count() < MIN_PWD_LEN {
            mst_str.zeroize();
            return Err(Err::new(&format!("new master password must be at least {} characters long", MIN_PWD_LEN), ErrSrc::Storage));
        }

        // creating regular expression patterns set
        let number = r"[0-9]+";
        let capital = r"[A-Z]+";
        let lower_case = r"[a-z]+";
        let mut symbol = String::from(r"[");
        for c in SPEC_CHARS {
            symbol.push(c);
        }
        symbol += "]+";


        let match_set = match RegexSet::new([number, capital, lower_case, &symbol]) {
            Ok(rs) => rs,
            Err(_) => { 
                mst_str.zeroize();
                return Err(Err::new(
                    "unable to create the master password requirements checker",
                    ErrSrc::Storage))
            }
        };

        let match_res = match_set.matches(&mst_str);

        mst_str.zeroize();

        if !match_res.matched_all() {
            let mut err_msg = format!("new master password must contain:\n\t- a capital letter\n\t- a lower case letter\n\t- a number\n\t- a special character between: ");
            for c in SPEC_CHARS {
                err_msg.push(c);
                err_msg += ", ";
            }

            return Err(Err::new(&err_msg, ErrSrc::Storage));
        }

        Ok(())

    }
}

// ]]]

// PersMst for PersMaster [[[

impl <M:MstPwd> PersMst<M> for PersMaster<M> {
    fn check_exp(&self) -> bool {
        self.mst.get_exp_date() <= &Utc::now().date_naive()
    }

    fn get_mst(&self) -> &M {
        &self.mst
    }

    fn set_mst<H: Hashing>(&mut self, new_mst: SecureBytes, hash_provider: &mut H) -> Result<(), Err> {

        PersMaster::<M>::validate_mst(&new_mst)?;

        if
            H::verify_hash(
                &new_mst,
                self.mst.get_hash_val().get_salt(),
                self.mst.get_hash_val().get_hash()
            // both new_pwd and old_pwd arguments of verify hash can not be null: new_mst must be
            // longer than MIN_PWD_LEN to get here, and old_mst content are SHA512_OUTPUT_LEN long
            ).unwrap()
            ||
            self.old_mst.iter().any(
                |pwd|
                H::verify_hash(&new_mst, pwd.get_salt(), pwd.get_hash()).unwrap()
            )
        {
            return Err(Err::new("new master password is equal to an old one", ErrSrc::Storage));
        }

        // creating new master password hash
        let new_mst_hash = hash_provider.derive_hash(&new_mst, SHA512_OUTPUT_LEN)?;

        // storing old master password in old_mst
        self.old_mst.push(self.mst.get_hash_val().clone());
        // updating master password value
        self.mst.set_hash_val(new_mst_hash);

        Ok(())

    }

    fn validate_pwd<H: Hashing>(&self, pwd: &SecureBytes) -> Result<bool, Err> {
        H::verify_hash(
            pwd,
            self.mst.get_hash_val().get_salt(),
            self.mst.get_hash_val().get_hash()
        )
    }

    fn get_old_mst(&self) -> &Vec<HashVal> {
        &self.old_mst
    }
}
// ]]]

// unit testing [[[
#[cfg(test)]

mod tests {
    use super::*;
    use crypto::hashing::SALT_LEN;
    use chrono::{NaiveDate, TimeDelta};
    use crypto::{CryptoProvider, rng::SystemRandom};
    use domain::mst_pwd::Master;

    // MockMst [[[
    /// Mock MstPwd implementation that does not perform any control on expiration date
    struct MockMst {
        hash: HashVal,
        exp: NaiveDate
    }

    impl MstPwd for MockMst {
        fn new(_: HashVal) -> Self {
            unimplemented!();
        }

        fn new_with_date(hash: HashVal, exp: NaiveDate) -> Result<Self, Err> {
            Ok(Self {
                hash,
                exp
            })
        }

        fn get_exp_date(&self) -> &NaiveDate {
            &self.exp
        }

        fn set_hash_val(&mut self, h: HashVal) {
           self.hash = h;
        }

        fn get_hash_val(&self) -> &HashVal {
            &self.hash
        }
    }
    // ]]]

    // setup_mst [[[
    fn setup_mst_mock(td: TimeDelta) -> MockMst {
        let pwd = SecureBytes::new(Vec::from("Abcdefgh1_"));
        let mut cp = CryptoProvider::new_empty(SystemRandom::new())
            .expect("unable to create CryptoProvider");
        
        let hv = cp.derive_hash(&pwd, SHA512_OUTPUT_LEN)
            .expect("unable to create mst HashVal");

        let exp = Utc::now().date_naive().checked_add_signed(td)
            .expect("unable to set expiration date");
        
        MockMst::new_with_date(hv, exp).unwrap()
    }

    fn setup_mst_master() -> Master {
        let pwd = SecureBytes::new(Vec::from("Abcdefgh1_"));
        let mut cp = CryptoProvider::new_empty(SystemRandom::new())
            .expect("unable to create CryptoProvider");
        
        let hv = cp.derive_hash(&pwd, SHA512_OUTPUT_LEN)
            .expect("unable to create mst HashVal");

        Master::new(hv)
    }
    // ]]]

    // validate_mst [[[
    
    /// Tests that `validate_mst` returns `()` if the master password is valid
    #[test]
    fn validate_mst_valid () {
        // looping on all capital letters
        for letter in b'A' ..= b'Z' {
            let mut mst_str = String::from("bcdefgh1_");
            mst_str.push(letter as char);
            let mst = SecureBytes::new(mst_str.as_bytes().to_vec());

            assert!(
                PersMaster::<Master>::validate_mst(&mst).is_ok(),
                "error with a valid master password (letter {})", letter as char
            );
        }

        // looping on all lower case letters
        for letter in b'a' ..= b'z' {
            let mut mst_str = String::from("BCDEFGH1_");
            mst_str.push(letter as char);
            let mst = SecureBytes::new(mst_str.as_bytes().to_vec());

            assert!(
                PersMaster::<Master>::validate_mst(&mst).is_ok(),
                "error with a valid master password (letter {})", letter as char
            );
        }

        // looping on all digits
        for digit in 0 ..= 9 {
            let mut mst_str = String::from("Abcdefgh_");
            mst_str += &digit.to_string();
            let mst = SecureBytes::new(mst_str.as_bytes().to_vec());

            assert!(
                PersMaster::<Master>::validate_mst(&mst).is_ok(),
                "error with a valid master password (digit {})", digit
            );
        }

        // looping on all symbols
        for symbol in SPEC_CHARS {
            let mut mst_str = String::from("Abcdefgh1");
            mst_str.push(symbol);
            let mst = SecureBytes::new(mst_str.as_bytes().to_vec());

            assert!(
                PersMaster::<Master>::validate_mst(&mst).is_ok(),
                "error with a valid master password (symbol {})", symbol
            );
        }


    }

    /// Tests that `validate_mst` returns an error if the master password is shorter than `MIN_PWD_LEN` 
    #[test]
    fn validate_mst_shorter () {
        let mst = SecureBytes::new(Vec::from("Abcdefg1_"));
        
        assert!(PersMaster::<Master>::validate_mst(&mst).is_err(), "no error with a short password");
    }

    /// Tests that `validate_mst` returns an error if the master password is not a utf-8 string
    #[test]
    fn validate_mst_no_str () {
        let mst = SecureBytes::new(Vec::from([1u8;20]));
        
        assert!(PersMaster::<Master>::validate_mst(&mst).is_err(), "no error with a password that is not a string");
    }

    /// Tests that `validate_mst` returns an error if the master password does not contain a
    /// capital letter
    #[test]
    fn validate_mst_no_lower () {
        let mst = SecureBytes::new(Vec::from("abcdefgh1_"));
        
        assert!(PersMaster::<Master>::validate_mst(&mst).is_err(), "no error with a password missing a capital letter");
    }

    /// Tests that `validate_mst` returns an error if the master password does not contain a
    /// lower case letter
    #[test]
    fn validate_mst_no_capital () {
        let mst = SecureBytes::new(Vec::from("ABCDEFGH1_"));
        
        assert!(PersMaster::<Master>::validate_mst(&mst).is_err(), "no error with a password missing a lower case letter");
    }

    /// Tests that `validate_mst` returns an error if the master password does not contain a
    /// number
    #[test]
    fn validate_mst_no_number () {
        let mst = SecureBytes::new(Vec::from("Abcdefghi_"));
        
        assert!(PersMaster::<Master>::validate_mst(&mst).is_err(), "no error with a password missing a number");
    }

    /// Tests that `validate_mst` returns an error if the master password does not contain a
    /// symbol
    #[test]
    fn validate_mst_no_symbol () {
        let mst = SecureBytes::new(Vec::from("Abcdefgh1i"));
        
        assert!(PersMaster::<Master>::validate_mst(&mst).is_err(), "no error with a password missing a symbol");
    }

    // ]]]

    // new [[[
    /// Tests that `new` initialize `self.old_mst` when method argument is `None`
    #[test]
    fn new_none() {
        let pm = PersMaster::new(setup_mst_master(), None);
        assert_eq!(pm.old_mst, Vec::new(), "old_mst is not initialized to Vec::new()");
    }

    /// Tests that `new` assigns to `self.old_mst` the value of `old_mst` argument when it is not
    /// `None`
    #[test]
    fn new_some() {
        let hv = HashVal::new(SecureBytes::new(Vec::from("mst")), [1u8; SALT_LEN])
            .expect("unable to create HashVal");

        let pm = PersMaster::new(setup_mst_master(), Some(vec![hv.clone()]));
        assert_eq!(pm.old_mst, vec![hv], "self.old_mst is not initialized to old_mst argument");
    }

    /// Tests that `new` assigns to `self.mst` the value of `mst` argument
    #[test]
    fn new_mst() {
        let pwd = setup_mst_master();

        let pm = PersMaster::new(pwd.clone(), None);
        assert_eq!(pm.mst.get_hash_val(), pwd.get_hash_val(), "self.mst is not initialized to mst argument");
    }
    // ]]]

    // new_with_bytes [[[

    // passsword validation tests are skipped here as validate_mst is also tested

    /// Tests that `new_with_bytes` initialize `self.old_mst` when method argument is `None`
    #[test]
    fn new_with_bytes_none() {
        let sb = SecureBytes::new(Vec::from("A_strong_password1"));
        let mut cp = CryptoProvider::new_empty(SystemRandom::new())
            .expect("unable to create CryptoProvider");

        let pm = PersMaster::<Master>::new_with_bytes(sb, None, &mut cp)
            .expect("unable to create PersMaster");

        assert_eq!(pm.old_mst, Vec::new(), "old_mst is not initialized to Vec::new()");
    }

    /// Tests that `new_with_bytes` assigns to `self.old_mst` the value of `old_mst` argument when it is not
    /// `None`
    #[test]
    fn new_with_bytes_some() {
        let sb = SecureBytes::new(Vec::from("A_strong_password1"));
        let mut cp = CryptoProvider::new_empty(SystemRandom::new())
            .expect("unable to create CryptoProvider");
        let hv = HashVal::new(SecureBytes::new(Vec::from("mst")), [1u8; SALT_LEN])
            .expect("unable to create HashVal");

        let pm = PersMaster::<Master>::new_with_bytes(sb, Some(vec![hv.clone()]), &mut cp)
            .expect("unable to create PersMaster");

        assert_eq!(pm.old_mst, vec![hv], "self.old_mst is not initialized to old_mst argument");
    }

    /// Tests that `new_with_bytes` assigns to `self.mst` the value of `mst` argument
    #[test]
    fn new_with_bytes_mst() {

        let sb = SecureBytes::new(Vec::from("A_strong_password1"));
        let mut cp = CryptoProvider::new_empty(SystemRandom::new())
            .expect("unable to create CryptoProvider");

        let pm = PersMaster::<Master>::new_with_bytes(sb.clone(), None, &mut cp)
            .expect("unable to create PersMaster");

        assert!(
            CryptoProvider::<SystemRandom>::verify_hash(
                &sb,
                pm.mst.get_hash_val().get_salt(),
                pm.mst.get_hash_val().get_hash()
            ).expect("unable to verify sb hash"),
            "self.mst is not initialized with mst_bytes argument"
        );
    }
    // ]]]

    // check_exp [[[
    /// Tests that `check_exp` returns `true` if the password is expired
    #[test]
    fn check_exp_true() {
        // setting a password expired during the current date
        let pm = PersMaster::new(setup_mst_mock(TimeDelta::seconds(0)), None);
        assert!(pm.check_exp(), "master password expired on the current day is not considered expired");

        // setting an expired passwrod from a day
        let pm2 = PersMaster::new(setup_mst_mock(TimeDelta::seconds(-60 * 60 * 24)), None);
        assert!(pm2.check_exp(), "master password expired from a day is not considered expired");
    }

    /// Tests that `check_exp` returns `false` if the password is not expired
    #[test]
    fn check_exp_false() {
        let pm = PersMaster::new(setup_mst_master(), None);
        assert!(!pm.check_exp(), "non-expired master password is considered expired");
    }
    // ]]]

    // set_mst [[[
    
    // passsword validation tests are skipped here as validate_mst is also tested

    /// Tests that `set_mst` actually set a new master password value
    #[test]
    fn set_mst_value() {
        let pwd = setup_mst_master();
        let mut pm = PersMaster::new(pwd.clone(), None);

        let pwd2 = SecureBytes::new(Vec::from("New_mst_value1"));
        let mut cp = CryptoProvider::new_empty(SystemRandom::new())
            .expect("unable to create CryptoProvider");

        pm.set_mst(pwd2.clone(), &mut cp).expect("unable to set a new master password value");

        assert_ne!(pwd.get_hash_val(), pm.mst.get_hash_val(), "master password is still equal to the original one");
        assert!(
            CryptoProvider::<SystemRandom>::verify_hash(
                &pwd2,
                pm.mst.get_hash_val().get_salt(),
                pm.mst.get_hash_val().get_hash()
            ).expect("unable to verify pwd2 hash"),
            "new master password hash does not correspond to its value"
        );

    }

    /// Tests that `set_mst` return an error when a password has already been used
    #[test]
    fn set_mst_used() {
        let mut cp = CryptoProvider::new_empty(SystemRandom::new())
            .expect("unable to create CryptoProvider");

        let pwd = SecureBytes::new(Vec::from("A_master_password1"));
        let pwd2 = SecureBytes::new(Vec::from("A_new_master_password1"));
        let old = Some(vec![cp.derive_hash(&pwd2, SHA512_OUTPUT_LEN).expect("unable to derive pwd hash val")]);

        let mut pm = PersMaster::<Master>::new_with_bytes(pwd.clone(), old, &mut cp)
            .expect("unable to create PersMaster");

        assert!(pm.set_mst(pwd, &mut cp).is_err(), "current master password has been set again");
        assert!(pm.set_mst(pwd2, &mut cp).is_err(), "old master password value has been set again");
    }

    /// Tests that `set_mst` updates old_password `Vec` when a new password is set
    #[test]
    fn set_mst_update_old() {
        let pwd = setup_mst_master();
        let mut pm = PersMaster::new(pwd.clone(), None);

        let pwd2 = SecureBytes::new(Vec::from("New_mst_value1"));
        let mut cp = CryptoProvider::new_empty(SystemRandom::new())
            .expect("unable to create CryptoProvider");

        assert!(!pm.old_mst.contains(pwd.get_hash_val()));

        pm.set_mst(pwd2, &mut cp)
            .expect("unable to set the new master password");

        assert!(pm.old_mst.contains(pwd.get_hash_val()));

    }
    // ]]]

    // validate_pwd [[[

    /// Tests that `validate_pwd` returns `true` when the provided master password is correct
    #[test]
    fn validate_pwd_true() {
        let mut cp = CryptoProvider::new_empty(SystemRandom::new())
            .expect("unable to create CryptoProvider");

        let pwd = SecureBytes::new(Vec::from("A_master_password1"));

        let pm = PersMaster::<Master>::new_with_bytes(pwd.clone(), None, &mut cp)
            .expect("unable to create PersMaster");

        assert!(
            pm.validate_pwd::<CryptoProvider<SystemRandom>>(&pwd).expect("unable to perform validation"),
            "unable to validate the correct master password"
        );
    }


    /// Tests that `validate_pwd` returns `false` when the provided master password is correct
    #[test]
    fn validate_pwd_false() {
        let mut cp = CryptoProvider::new_empty(SystemRandom::new())
            .expect("unable to create CryptoProvider");

        let pwd = SecureBytes::new(Vec::from("A_master_password1"));
        let pwd2 = SecureBytes::new(Vec::from("A_new_master_password1"));

        let pm = PersMaster::<Master>::new_with_bytes(pwd.clone(), None, &mut cp)
            .expect("unable to create PersMaster");

        assert!(
            !pm.validate_pwd::<CryptoProvider<SystemRandom>>(&pwd2).expect("unable to perform validation"),
            "unable to validate the correct master password"
        );
    }
    // ]]]

    /// Tests that `get_mst` returns the correct master password
    #[test]
    fn get_mst_value(){
        let pwd = setup_mst_master();
        let pm = PersMaster::new(pwd.clone(), None);

        assert_eq!(pwd.get_hash_val(), pm.get_mst().get_hash_val(), "returned master password is incorrect");
    }

    /// Tests that `get_old_mst` returns the correct `Vec<HashVal>`
    #[test]
    fn get_old_mst_value(){
        let pwd = SecureBytes::new(Vec::from("A_master_password1"));
        let mut cp = CryptoProvider::new_empty(SystemRandom::new())
            .expect("unable to create CryptoProvider");

        let hv = cp.derive_hash(&SecureBytes::new(Vec::from("Another_mst_pwd1")), SHA512_OUTPUT_LEN)
            .expect("unable to dervie hv value");

        let old = Some(vec![hv.clone()]);
        let pm = PersMaster::<Master>::new_with_bytes(pwd.clone(), old, &mut cp)
            .expect("unable to create PersMaster");

        assert_eq!(vec![hv], pm.old_mst, "returned master password is incorrect");
    }
}
// ]]]
