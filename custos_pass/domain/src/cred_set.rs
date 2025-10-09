//! # Credential Set
//!
//! This module defines how a credential set and its related data are defined.

use crypto::SecureBytes;
use chrono::{NaiveDate, TimeDelta, Utc};
use error::{Err, ErrSrc};

/// Credential set expiration time delta. It corresponds to 3 months expressed in seconds
/// (assuming that each month has 30 days for simplicity).
const CRED_EXP: i64 = 3 * 30 * 24 * 60 * 60;

// CredSet trait [[[
/// Defines the behavior of a struct storing credential set data.
pub trait CredSet where Self: Sized{
    /// Creates a new credential set instance with a default expiration date.
    ///
    /// # Parameters
    ///
    /// - `pwd`: password value: it must
    ///     - be at least 10 characters long
    ///     - contain at least:
    ///         - a capital letter
    ///         - a lowercase letter
    ///         - a number
    ///         - a special character from `SPEC_CHARS`
    /// - `expiring`: credential set will be valid for 3 months if `true`; it will never
    /// expire otherwise. Expiration date is based on UTC timezone
    /// - `id`: credential set id. It must __NOT__ be empty
    /// - `mail`: credential set e-mail. If not `None`, it must __NOT__ be empty
    /// - `txt`: credential set free text. If not `None`, it must __NOT__ be empty
    ///
    /// # Returns
    ///
    /// Returns `Self` if `pwd` is valid and each argument is `None` or not empty; `Err` otherwise.
    fn new(pwd: SecureBytes, expiring: bool, id: String, mail: Option<String>, txt: Option<String>) -> Result<Self, Err>;

    /// Creates a new credential set instance with a given expiration date.
    ///
    /// # Parameters
    ///
    /// - `pwd`: password value: it must
    ///     - be at least 10 characters long
    ///     - contain at least:
    ///         - a capital letter
    ///         - a lowercase letter
    ///         - a number
    ///         - a special character from `SPEC_CHARS`
    /// - `expiring`: expiration date. The credential set will never expire if `None`.
    /// Expiration date is based on UTC timezone and must __NOT__ predate or be equal to the
    /// creation date of the struct
    /// - `id`: credential set id. It must __NOT__ be empty
    /// - `mail`: credential set e-mail. If not `None`, it must __NOT__ be empty
    /// - `txt`: credential set free text. If not `None`, it must __NOT__ be empty
    ///
    /// # Returns
    ///
    /// Returns `Self` if `pwd` is valid, `exp_date` does not predate or is equal to
    /// the creation date of the struct and each of the other values is `None` or not empty; `Err` otherwise.
    fn new_with_date(pwd: SecureBytes, expiring: Option<NaiveDate>, id: String, mail: Option<String>, txt: Option<String>) -> Result<Self, Err>;

    /// Returns the credential set password.
    fn get_pwd(&self) -> &SecureBytes;

    /// Sets a new password for the credential and updates its expiration date to be valid for 3
    /// months.
    ///
    /// # Parameters
    ///
    /// - `new_pwd`: new password that must:
    ///     - be at least 10 characters long
    ///     - contain at least:
    ///         - a capital letter
    ///         - a lowercase letter
    ///         - a number
    ///         - a special character from `SPEC_CHARS`
    ///
    /// # Returns
    ///
    /// Returns `()` if `new_pwd` is valid, `Err` otherwise.
    fn set_pwd(&mut self, new_pwd: SecureBytes) -> Result<(), Err>;

    /// Returns the expiration date of the credential set or `None`, if it is set as never expiring.
    fn get_exp_date(&self) -> &Option<NaiveDate>;

    /// Returns the credential set id.
    fn get_id(&self) -> &String;

    /// Sets a new credential set id. 
    ///
    /// # Parameters
    ///
    /// - `id`: new id vaulue. It must __NOT__ be empty
    ///
    /// # Returns
    ///
    /// Returns `()` if `id` is not empty, `Err` otherwise.
    fn set_id(&mut self, id: String) -> Result<(), Err>;

    /// Returns the credential set e-mail if exists; `None` otherwise.
    fn get_mail(&self) -> &Option<String>;

    /// Sets a new e-mail for the credential set.
    ///
    /// # Parameters
    ///
    /// - `mail`: e-mail value. If not `None`, it must:
    ///     - __NOT__ be empty
    ///     - have at least a character before the '@'
    ///     - have at least a character before the '.' that follos the '@'
    ///     - have at least a character after the '.' that follows the '@'
    ///
    /// # Returns
    ///
    /// Returns `()` if `mail` is a valid e-mail, `Err` otherwise.
    fn set_mail(&mut self, mail: Option<String>) -> Result<(), Err>;

    /// Returns the free text related to the credential set if exists; `None` otherwise
    fn get_txt(&self) -> &Option<String>;

    /// Sets a new credential set free text. 
    ///
    /// # Parameters
    ///
    /// - `txt`: free text vaulue. If not `None`, it must __NOT__ be empty
    ///
    /// # Returns
    ///
    /// Returns `()` if `tzt` is not empty, `Err` otherwise.
    fn set_txt(&mut self, txt: Option<String>) -> Result<(), Err>;
}
// ]]]

// CredEntry [[[

// A credential set struct.
#[derive(Clone, Debug)]
pub struct CredEntry {
    pwd: SecureBytes,
    exp_date: Option<NaiveDate>,
    id: String,
    mail: Option<String>,
    txt: Option<String>
}

impl PartialEq for CredEntry {
    fn eq(&self, other: &CredEntry) -> bool {
        &self.id == other.get_id()
    }
}

impl Eq for CredEntry {}

// ]]]

// impl CredSet for CredEntry [[[

impl CredSet for CredEntry {
    fn new(pwd: SecureBytes, expiring: bool, id: String, mail: Option<String>, txt: Option<String>) -> Result<Self, Err>{

        let exp;
        if expiring {
            // unwrap should not give any issue as CRED_EXP is a constant value inside the valid
            // interval for TimeDelta::seconds
            exp = Some(Utc::now().date_naive().checked_add_signed(TimeDelta::seconds(CRED_EXP)).unwrap());
        } else {
            exp = None
        }

        CredEntry::new_with_date(pwd, exp, id, mail, txt)


    }

    fn new_with_date(pwd: SecureBytes, expiring: Option<NaiveDate>, id: String, mail: Option<String>, txt: Option<String>) -> Result<Self, Err>{

        if id.is_empty() {
            return Err(Err::new("id argument must not be empty", ErrSrc::Domain));
        }

        if let Some(e) = expiring && e <= Utc::now().date_naive() {
            return Err(Err::new("if not None, expiration date can not predate or be equal to the current date", ErrSrc::Domain));
        }

        if let Some(m) = &mail && m.is_empty() {
            return Err(Err::new("if not None, mail argument must not be empty", ErrSrc::Domain));
        }

        if let Some(t) = &txt && t.is_empty() {
            return Err(Err::new("if not None, txt argument must not be empty", ErrSrc::Domain));
        }

        crate::validate_pwd(&pwd)?;

        Ok(Self {
            pwd,
            exp_date: expiring,
            id,
            mail,
            txt
        })
    }

    fn get_pwd(&self) -> &SecureBytes{
        &self.pwd
    }

    fn set_pwd(&mut self, new_pwd: SecureBytes) -> Result<(), Err>{
        crate::validate_pwd(&new_pwd)?;

        self.pwd = new_pwd;
        self.exp_date = Some(Utc::now()
            .date_naive()
            .checked_add_signed(
                TimeDelta::seconds(CRED_EXP)
                // unwrap should give any issue as CRED_EXP is a constant value within the valid
                // interval of TimeDelta::seconds. It is used to ensure that non None value is
                // accidentally set
            ).unwrap()
        );

        Ok(())

    }

    fn get_exp_date(&self) -> &Option<NaiveDate>{
        &self.exp_date
    }

    fn get_id(&self) -> &String{
        &self.id
    }

    fn set_id(&mut self, id: String) -> Result<(), Err>{
        if id.is_empty() {
            return Err(Err::new("id must not be empty", ErrSrc::Domain));
        }

        self.id = id;

        Ok(())
    }

    fn get_mail(&self) -> &Option<String>{
        &self.mail
    }

    fn set_mail(&mut self, mail: Option<String>) -> Result<(), Err>{
        if let Some(m) = &mail && m.is_empty() {
            return Err(Err::new("if not None, mail must not be empty", ErrSrc::Domain));
        }

        self.mail = mail;

        Ok(())
    }

    fn get_txt(&self) -> &Option<String>{
        &self.txt
    }

    fn set_txt(&mut self, txt: Option<String>) -> Result<(), Err>{
        if let Some(t) = &txt && t.is_empty() {
            return Err(Err::new("if not None, free text must not be empty", ErrSrc::Domain));
        }

        self.txt = txt;

        Ok(())
    }

}
// ]]]

