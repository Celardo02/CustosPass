//! # Master Password Persistence
//!
//! This module provides the persistence logic to store the vault master password.

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
    fn set_mst<H: Hashing>(&mut self, new_mst: &SecureBytes, hash_provider: &mut H) -> Result<(), Err>;

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
    /// Use `new_with_bytes` master password if validation is needed.
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

    fn set_mst<H: Hashing>(&mut self, new_mst: &SecureBytes, hash_provider: &mut H) -> Result<(), Err> {

        if self.old_mst.iter().any(
            |pwd|
            // both new_pwd and old_pwd arguments of verify hash can not be null: new_mst must be
            // longer than MIN_PWD_LEN to get here, and old_mst content are SHA512_OUTPUT_LEN long
            H::verify_hash(&new_mst, pwd.get_salt(), pwd.get_hash()).unwrap()
        ){
            return Err(Err::new("new master password is equal to an old one", ErrSrc::Storage));
        }


        PersMaster::<M>::validate_mst(&new_mst)?;

        // creating new master password hash
        let new_mst_hash = hash_provider.derive_hash(&new_mst, SHA512_OUTPUT_LEN)?;

        // storing old master password in old_mst
        self.old_mst.push(self.mst.get_hash_val().clone());
        // updating master password value
        self.mst.set_hash_val(new_mst_hash);

        Ok(())

    }

    fn validate_pwd<H: Hashing>(&self, pwd: &SecureBytes) -> Result<bool, Err> {
        if pwd.unsecure().is_empty() {
            return Err(Err::new("empty password to validate", ErrSrc::Storage));
        }

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

