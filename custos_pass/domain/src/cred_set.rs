//! # Credential Set
//!
//! This module defines how a credential set and its related data are defined.

use crypto::SecureBytes;
use chrono::{NaiveDate, TimeDelta, Utc};
use error::{Err, ErrSrc};
use regex::Regex;

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
    /// - `mail`: credential set e-mail. If not `None`, it must: 
    ///     - __NOT__ be empty
    ///     - follow the template _a@b.c_. A, b and c can have an arbitrary length and contain
    ///     anything but the space character
    /// - `notes`: credential set free text. If not `None`, it must __NOT__ be empty
    ///
    /// # Returns
    ///
    /// Returns `Self` if `pwd` is valid and each argument is `None` or not empty; `Err` otherwise.
    fn new(pwd: SecureBytes, expiring: bool, id: String, mail: Option<String>, notes: Option<String>) -> Result<Self, Err>;

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
    /// - `mail`: credential set e-mail. If not `None`, it must: 
    ///     - __NOT__ be empty
    ///     - follow the template _a@b.c_. A, b and c can have an arbitrary length and contain
    ///     anything but the space character
    /// - `notes`: credential set free text. If not `None`, it must __NOT__ be empty
    ///
    /// # Returns
    ///
    /// Returns `Self` if `pwd` is valid, `exp_date` does not predate or is equal to
    /// the creation date of the struct and each of the other values is `None` or not empty; `Err` otherwise.
    fn new_with_date(pwd: SecureBytes, expiring: Option<NaiveDate>, id: String, mail: Option<String>, notes: Option<String>) -> Result<Self, Err>;

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
    /// - `expiring`: new password will be valid for 3 months if `true`; the credential set will be
    /// never expiring if `false`
    ///
    /// # Returns
    ///
    /// Returns `()` if `new_pwd` is valid, `Err` otherwise.
    fn set_pwd(&mut self, new_pwd: SecureBytes, expiring: bool) -> Result<(), Err>;

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
    /// - `mail`: credential set e-mail. If not `None`, it must: 
    ///     - __NOT__ be empty
    ///     - follow the template _a@b.c_. A, b and c can have an arbitrary length and contain
    ///     anything but the space character
    ///
    /// # Returns
    ///
    /// Returns `()` if `mail` is a valid e-mail, `Err` otherwise.
    fn set_mail(&mut self, mail: Option<String>) -> Result<(), Err>;

    /// Returns the notes related to the credential set if exist; `None` otherwise
    fn get_notes(&self) -> &Option<String>;

    /// Sets new credential set notes. 
    ///
    /// # Parameters
    ///
    /// - `notes`: free text value. If not `None`, it must __NOT__ be empty
    ///
    /// # Returns
    ///
    /// Returns `()` if `tzt` is not empty, `Err` otherwise.
    fn set_notes(&mut self, notes: Option<String>) -> Result<(), Err>;
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
    notes: Option<String>
}

impl PartialEq for CredEntry {
    fn eq(&self, other: &CredEntry) -> bool {
        &self.id == other.get_id()
    }
}

impl Eq for CredEntry {}

impl CredEntry {
    /// Checks that an e-mail is in the format _a@b.c_, where _a_, _b_ and _c_ can have an
    /// arbitrary length and contain anything but the space character
    fn check_mail(mail: &String) -> Result<(), Err> {
        let reg = Regex::new(r"^[\S]+@[\S]+\.[\S]+$")
            .map_err(|_| Err::new("unable to create e-mail requirements checker", ErrSrc::Domain))?;

        if !reg.is_match(mail) {
            return Err(Err::new("e-mail must follow the template a@b.c, where a, b and c can have an arbitrary length and contain anything but the space character", ErrSrc::Domain));
        }

        Ok(())
    }
}

// ]]]

// impl CredSet for CredEntry [[[

impl CredSet for CredEntry {
    fn new(pwd: SecureBytes, expiring: bool, id: String, mail: Option<String>, notes: Option<String>) -> Result<Self, Err>{

        let exp;
        if expiring {
            // unwrap should not give any issue as CRED_EXP is a constant value inside the valid
            // interval for TimeDelta::seconds
            exp = Some(Utc::now().date_naive().checked_add_signed(TimeDelta::seconds(CRED_EXP)).unwrap());
        } else {
            exp = None
        }

        CredEntry::new_with_date(pwd, exp, id, mail, notes)


    }

    fn new_with_date(pwd: SecureBytes, expiring: Option<NaiveDate>, id: String, mail: Option<String>, notes: Option<String>) -> Result<Self, Err>{

        if id.is_empty() {
            return Err(Err::new("id argument must not be empty", ErrSrc::Domain));
        }

        if let Some(e) = expiring && e <= Utc::now().date_naive() {
            return Err(Err::new("if not None, expiration date can not predate or be equal to the current date", ErrSrc::Domain));
        }

        if let Some(m) = &mail && let Err(e) = CredEntry::check_mail(m) {
            return Err(e);
        }

        if let Some(t) = &notes && t.is_empty() {
            return Err(Err::new("if not None, notes argument must not be empty", ErrSrc::Domain));
        }

        crate::validate_pwd(&pwd)?;

        Ok(Self {
            pwd,
            exp_date: expiring,
            id,
            mail,
            notes
        })
    }

    fn get_pwd(&self) -> &SecureBytes{
        &self.pwd
    }

    fn set_pwd(&mut self, new_pwd: SecureBytes, expiring: bool) -> Result<(), Err>{
        crate::validate_pwd(&new_pwd)?;

        self.pwd = new_pwd;
        if expiring {
            self.exp_date = Some(Utc::now()
                .date_naive()
                .checked_add_signed(
                    TimeDelta::seconds(CRED_EXP)
                    // unwrap should give any issue as CRED_EXP is a constant value within the valid
                    // interval of TimeDelta::seconds. It is used to ensure that non None value is
                    // accidentally set
                ).unwrap()
            );
        } else {
            self.exp_date = None;
        }

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
        if let Some(m) = &mail && let Err(e) = CredEntry::check_mail(m) {
            return Err(e);
        }

        self.mail = mail;

        Ok(())
    }

    fn get_notes(&self) -> &Option<String>{
        &self.notes
    }

    fn set_notes(&mut self, notes: Option<String>) -> Result<(), Err>{
        if let Some(t) = &notes && t.is_empty() {
            return Err(Err::new("if not None, free text must not be empty", ErrSrc::Domain));
        }

        self.notes = notes;

        Ok(())
    }

}
// ]]]

// unit testing [[[
#[cfg(test)]

mod tests {
    use super::*;

    // check_mail [[[

    /// Tests that `check_mail` returns `()` if the mail is valid
    #[test]
    fn check_mail_valid() {
        let mail = String::from("a.valid@e.mail.com");

        assert!(CredEntry::check_mail(&mail).is_ok(), "error with a vaid mail");
    }

    /// Tests that `check_mail` returns an error if the mail is empty
    #[test]
    fn check_mail_empty() {
        let mail = String::new();

        assert!(CredEntry::check_mail(&mail).is_err(), "no error with an empty mail");
    }

    /// Tests that `check_mail` returns an error if the mail misses the @
    #[test]
    fn check_mail_no_at() {
        let mail = String::from("invalidmail.com");

        assert!(CredEntry::check_mail(&mail).is_err(), "no error with a mail missing the @");
    }

    /// Tests that `check_mail` returns an error if the mail misses the .
    #[test]
    fn check_mail_no_dot() {
        let mail = String::from("invalid@mailcom");

        assert!(CredEntry::check_mail(&mail).is_err(), "no error with a mail missing the .");
    }

    /// Tests that `check_mail` returns an error if the mail misses the text before the @
    #[test]
    fn check_mail_no_txt() {
        let mail = String::from("@invalid.mail.com");

        assert!(CredEntry::check_mail(&mail).is_err(), "no error with a mail missing the text before the @");
    }
    // ]]]

    // new [[[

    // NOTE: all the tests that concern id, mail and notes are performed by new_with_date unit
    // testing, as new calls that associated function internally

    /// Tests that `new` returns an instance of CredEntry filled with the associated function
    /// arguments when expiring is true
    #[test]
    fn new_value_true() {
        let pwd = SecureBytes::new(Vec::from("A_secure_password1"));
        let id = String::from("id");
        let expiring = true;

        // None case
        
        let mail = None;
        let notes = None;

        let ce = CredEntry::new(pwd.clone(), expiring, id.clone(), mail.clone(), notes.clone())
            .expect("unable to create CredEntry (None case)");

        assert_eq!(ce.pwd, pwd, "pwd does not correspond to ce.pwd (None case)");
        assert_eq!(ce.id, id, "id does not correspond to ce.id (None case)");
        assert_eq!(
            ce.exp_date,
            Some(Utc::now()
                .date_naive()
                .checked_add_signed(TimeDelta::seconds(CRED_EXP))
                // expect is used to detect unwanted None coming from checked_add_signed
                .expect("unable to compute current date (None case)")
            ),
            "expiring date is not valid for CRED_EXP (None case)");
        assert_eq!(ce.mail, mail, "mail does not correspond to ce.mail (None case)");
        assert_eq!(ce.notes, notes, "notes does not correspond to ce.notes (None case)");

        // Some case

        let mail = Some(String::from("a@mail.com"));
        let notes = Some(String::from("notes"));

        let ce = CredEntry::new(pwd.clone(), expiring, id.clone(), mail.clone(), notes.clone())
            .expect("unable to create CredEntry (Some case)");

        assert_eq!(ce.pwd, pwd, "pwd does not correspond to ce.pwd (Some case)");
        assert_eq!(ce.id, id, "id does not correspond to ce.id (Some case)");
        assert_eq!(
            ce.exp_date,
            Some(Utc::now()
                .date_naive()
                .checked_add_signed(TimeDelta::seconds(CRED_EXP))
                // expect is used to detect unwanted None coming from checked_add_signed
                .expect("unable to compute current date (Some case)")
            ),
            "expiring date is not valid for CRED_EXP (Some case)");
        assert_eq!(ce.mail, mail, "mail does not correspond to ce.mail (Some case)");
        assert_eq!(ce.notes, notes, "notes does not correspond to ce.notes (Some case)");
    }

    /// Tests that `new` returns an instance of CredEntry filled with the associated function
    /// arguments when expiring is false
    #[test]
    fn new_value_false() {
        let pwd = SecureBytes::new(Vec::from("A_secure_password1"));
        let id = String::from("id");
        let expiring = false;

        // None case
        
        let mail = None;
        let notes = None;

        let ce = CredEntry::new(pwd.clone(), expiring, id.clone(), mail.clone(), notes.clone())
            .expect("unable to create CredEntry (None case)");

        assert_eq!(ce.pwd, pwd, "pwd does not correspond to ce.pwd (None case)");
        assert_eq!(ce.id, id, "id does not correspond to ce.id (None case)");
        assert_eq!(
            ce.exp_date,
            None,
            "exp_date is not set to be never expiring (None case)");
        assert_eq!(ce.mail, mail, "mail does not correspond to ce.mail (None case)");
        assert_eq!(ce.notes, notes, "notes does not correspond to ce.notes (None case)");

        // Some case

        let mail = Some(String::from("a@mail.com"));
        let notes = Some(String::from("notes"));

        let ce = CredEntry::new(pwd.clone(), expiring, id.clone(), mail.clone(), notes.clone())
            .expect("unable to create CredEntry (Some case)");

        assert_eq!(ce.pwd, pwd, "pwd does not correspond to ce.pwd (Some case)");
        assert_eq!(ce.id, id, "id does not correspond to ce.id (Some case)");
        assert_eq!(
            ce.exp_date,
            None,
            "exp_date is not set to be never expiring (Some case)");
        assert_eq!(ce.mail, mail, "mail does not correspond to ce.mail (Some case)");
        assert_eq!(ce.notes, notes, "notes does not correspond to ce.notes (Some case)");
    }

    // ]]]

    // new_with_date [[[
    /// Tests that `new_with_date` returns an instance of CredEntry filled with the associated function
    /// arguments
    #[test]
    fn new_with_date_value() {
        let pwd = SecureBytes::new(Vec::from("A_secure_password1"));
        let id = String::from("id");

        // None case
        
        let expiring = None;
        let mail = None;
        let notes = None;

        let ce = CredEntry::new_with_date(pwd.clone(), expiring.clone(), id.clone(), mail.clone(), notes.clone())
            .expect("unable to create CredEntry (None case)");

        assert_eq!(ce.pwd, pwd, "pwd does not correspond to ce.pwd (None case)");
        assert_eq!(ce.id, id, "id does not correspond to ce.id (None case)");
        assert_eq!(ce.exp_date, expiring, "exp_date is not set to be never expiring");
        assert_eq!(ce.mail, mail, "mail does not correspond to ce.mail (None case)");
        assert_eq!(ce.notes, notes, "notes does not correspond to ce.notes (None case)");

        // Some case

        let expiring = Some(Utc::now()
            .date_naive()
            .checked_add_signed(TimeDelta::seconds(60 * 60 * 24))
            // expect is used to avoid unwanted None coming from checked_add_signed
            .expect("unable to create expiring date (Some case)")
        );
        let mail = Some(String::from("a@mail.com"));
        let notes = Some(String::from("notes"));

        let ce = CredEntry::new_with_date(pwd.clone(), expiring.clone(), id.clone(), mail.clone(), notes.clone())
            .expect("unable to create CredEntry (Some case)");

        assert_eq!(ce.pwd, pwd, "pwd does not correspond to ce.pwd (Some case)");
        assert_eq!(ce.id, id, "id does not correspond to ce.id (Some case)");
        assert_eq!(ce.exp_date, expiring, "expiring does not correspond to ce.expiring");
        assert_eq!(ce.mail, mail, "mail does not correspond to ce.mail (Some case)");
        assert_eq!(ce.notes, notes, "notes does not correspond to ce.notes (Some case)");
    }


    /// Tests that `new_with_date` returns an error if expiring equal to the current day 
    #[test]
    fn new_with_date_exp_today() {
        let pwd = SecureBytes::new(Vec::from("A_secure_password1"));
        let id = String::new();
        let expiring = Some(Utc::now().date_naive());

        // None case
        
        let mail = None;
        let notes = None;

        assert!(
            CredEntry::new_with_date(pwd.clone(), expiring.clone(), id.clone(), mail.clone(), notes.clone()).is_err(),
            "no error with credential set expiring today (None case)"
        );

        // Some case

        let mail = Some(String::from("a@mail.com"));
        let notes = Some(String::from("notes"));

        assert!(
            CredEntry::new_with_date(pwd, expiring, id, mail, notes).is_err(),
            "no error with credential set expiring today (Some case)"
        );
    }

    /// Tests that `new_with_date` returns an error if expiring predates the current day 
    #[test]
    fn new_with_date_exp_predate() {
        let pwd = SecureBytes::new(Vec::from("A_secure_password1"));
        let id = String::new();
        let expiring = Some(Utc::now()
            .date_naive()
            .checked_sub_signed(TimeDelta::seconds(60 * 60 * 24))
            // expect used to avoid unwanted None from checked_sub_signed
            .expect("unable to get expiring date")
        );

        // None case
        
        let mail = None;
        let notes = None;

        assert!(
            CredEntry::new_with_date(pwd.clone(), expiring.clone(), id.clone(), mail.clone(), notes.clone()).is_err(),
            "no error with exp_date predating today (None case)"
        );

        // Some case

        let mail = Some(String::from("a@mail.com"));
        let notes = Some(String::from("notes"));

        assert!(
            CredEntry::new_with_date(pwd, expiring, id, mail, notes).is_err(),
            "no error with exp_date predating today (Some case)"
        );
    }

    /// Tests that `new_with_date` returns an error if id is empty
    #[test]
    fn new_with_date_id_empty() {
        let pwd = SecureBytes::new(Vec::from("A_secure_password1"));
        let id = String::new();

        // None case
        
        let expiring = None;
        let mail = None;
        let notes = None;

        assert!(
            CredEntry::new_with_date(pwd.clone(), expiring, id.clone(), mail.clone(), notes.clone()).is_err(),
            "no error with empty id (None case)"
        );

        // Some case

        let expiring = Some(Utc::now()
            .date_naive()
            .checked_add_signed(TimeDelta::seconds(60 * 60 * 24))
            // expect is used to avoid unwanted None coming from checked_add_signed
            .expect("unable to create expiring date (Some case)")
        );
        let mail = Some(String::from("a@mail.com"));
        let notes = Some(String::from("notes"));

        assert!(
            CredEntry::new_with_date(pwd, expiring, id, mail, notes).is_err(),
            "no error with empty id (Some case)"
        );
    }

    /// Tests that `new_with_date` returns an error if mail is empty and not `None`
    #[test]
    fn new_with_date_mail_empty() {
        let pwd = SecureBytes::new(Vec::from("A_secure_password1"));
        let id = String::from("id");
        let mail = Some(String::new());

        // None case
        
        let expiring = None;
        let notes = None;

        assert!(
            CredEntry::new_with_date(pwd.clone(), expiring, id.clone(), mail.clone(), notes.clone()).is_err(),
            "no error with empty mail (None case)"
        );

        // Some case

        let expiring = Some(Utc::now()
            .date_naive()
            .checked_add_signed(TimeDelta::seconds(60 * 60 * 24))
            // expect is used to avoid unwanted None coming from checked_add_signed
            .expect("unable to create expiring date (Some case)")
        );
        let notes = Some(String::from("notes"));

        assert!(
            CredEntry::new_with_date(pwd, expiring, id, mail, notes).is_err(),
            "no error with empty mail (Some case)"
        );
    }

    /// Tests that `new_with_date` returns an error if notes is empty and not `None`
    #[test]
    fn new_with_date_notes_empty() {
        let pwd = SecureBytes::new(Vec::from("A_secure_password1"));
        let id = String::from("id");
        let notes = Some(String::new());

        // None case
        
        let expiring = None;
        let mail = None;

        assert!(
            CredEntry::new_with_date(pwd.clone(), expiring, id.clone(), mail.clone(), notes.clone()).is_err(),
            "no error with empty notes (None case)"
        );

        // Some case

        let expiring = Some(Utc::now()
            .date_naive()
            .checked_add_signed(TimeDelta::seconds(60 * 60 * 24))
            // expect is used to avoid unwanted None coming from checked_add_signed
            .expect("unable to create expiring date (Some case)")
        );
        let mail = Some(String::from("a@mail.com"));

        assert!(
            CredEntry::new_with_date(pwd, expiring, id, mail, notes).is_err(),
            "no error with empty notes (Some case)"
        );
    }
    // ]]]

    // pwd getter and setter [[[

    /// Tests that `get_pwd` returns the correct value
    #[test]
    fn get_pwd_value() {
        let pwd = SecureBytes::new(Vec::from("A_secure_password1"));
        let ce = CredEntry::new(pwd.clone(), true, String::from("id"), None, None)
            .expect("unable to create CredEntry");

        assert_eq!(ce.get_pwd(), &pwd, "pwd does not correspond to ce.get_pwd");
    }

    /// Tests that `set_pwd` actually updates pwd value
    #[test]
    fn set_pwd_value() {
        let pwd = SecureBytes::new(Vec::from("A_secure_password1"));
        let mut ce = CredEntry::new(pwd, true, String::from("id"), None, None)
            .expect("unable to create CredEntry");

        let pwd2 = SecureBytes::new(Vec::from("Another_password1"));
        ce.set_pwd(pwd2.clone(),false)
            .expect("unable to set another password value");

        assert_eq!(ce.pwd, pwd2, "pwd value has not been updated");
    }

    /// Tests that `set_pwd` updates exp_date to `None` if `expiring` is `false`
    #[test]
    fn set_pwd_exp_none() {
        let pwd = SecureBytes::new(Vec::from("A_secure_password1"));
        let mut ce = CredEntry::new(pwd, true, String::from("id"), None, None)
            .expect("unable to create CredEntry");

        let pwd2 = SecureBytes::new(Vec::from("Another_password1"));
        ce.set_pwd(pwd2.clone(), false)
            .expect("unable to set another password value");

        assert_eq!(ce.exp_date, None, "exp_date has not been updated to None");
    }
    
    /// Tests that `set_pwd` updates exp_date to be valid for 3 months if `expiring` is `true`
    #[test]
    fn set_pwd_exp_some() {
        let pwd = SecureBytes::new(Vec::from("A_secure_password1"));
        let mut ce = CredEntry::new(pwd, false, String::from("id"), None, None)
            .expect("unable to create CredEntry");

        let pwd2 = SecureBytes::new(Vec::from("Another_password1"));
        ce.set_pwd(pwd2.clone(), true)
            .expect("unable to set another password value");

        assert_eq!(
            ce.exp_date, 
            Utc::now().date_naive().checked_add_signed(TimeDelta::seconds(CRED_EXP)),
            "exp_date has not been updated to be valid for 3 months");
    }

    // ]]]

    /// Tests that `get_exp_date` returns the correct value
    #[test]
    fn get_exp_date_value() {
        let ce = CredEntry::new(
            SecureBytes::new(Vec::from("A_secure_password1")),
            false,
            String::from("id"),
            None,
            None
        ).expect("unable to create CredEntry");

        assert_eq!(ce.get_exp_date(), &None, "exp_date is not equal to ce.exp_date");
    }

    // id getter and setter [[[
    /// Tests that `get_id` returns the correct value
    #[test]
    fn get_id_value() {
        let id = String::from("id");
        let ce = CredEntry::new(SecureBytes::new(Vec::from("A_secure_pwd1")), false, id.clone(), None, None)
            .expect("unable to create CredEntry");

        assert_eq!(ce.get_id(), &id, "id is not equal to ce.get_id");
    }

    /// Tests that `set_id` actually updates id value
    #[test]
    fn set_id_value() {
        let mut ce = CredEntry::new(
            SecureBytes::new(Vec::from("A_secure_password1")),
            false,
            String::from("id"),
            None,
            None
        ).expect("unable to create CredEntry");

        let id = String::from("new_id");
        ce.set_id(id.clone()).expect("unable to updated id value");

        assert_eq!(ce.id, id, "id value has not been updated");

    }

    /// Tests that `set_id` returns an error if id string is empty
    #[test]
    fn set_id_empty() {
        let mut ce = CredEntry::new(
            SecureBytes::new(Vec::from("A_secure_password1")),
            false,
            String::from("id"),
            None,
            None
        ).expect("unable to create CredEntry");

        let id = String::new();
        assert!(ce.set_id(id).is_err(), "no error with empty id");
    }
    // ]]]
    
    // mail getter and setter [[[
    /// Tests that `get_mail` returns the correct value
    #[test]
    fn get_mail_value() {
        let ce = CredEntry::new(SecureBytes::new(Vec::from("A_secure_pwd1")), false, String::from("id"), None, None)
            .expect("unable to create CredEntry");

        assert_eq!(ce.get_mail(), &None, "mail is not equal to ce.get_mail");
    }

    /// Tests that `set_mail` actually updates mail value
    #[test]
    fn set_mail_value() {
        let mut ce = CredEntry::new(
            SecureBytes::new(Vec::from("A_secure_password1")),
            false,
            String::from("id"),
            None,
            None
        ).expect("unable to create CredEntry");

        let mail = Some(String::from("new@mail.com"));
        ce.set_mail(mail.clone()).expect("unable to updated mail value");

        assert_eq!(ce.mail, mail, "mail value has not been updated");

    }

    /// Tests that `set_mail` returns an error if mail string is empty
    #[test]
    fn set_mail_empty() {
        let mut ce = CredEntry::new(
            SecureBytes::new(Vec::from("A_secure_password1")),
            false,
            String::from("id"),
            None,
            None
        ).expect("unable to create CredEntry");

        let mail = Some(String::new());
        assert!(ce.set_mail(mail).is_err(), "no error with empty mail");
    }
    // ]]]
    
    // notes getter and setter [[[

    /// Tests that `get_notes` returns the correct value
    #[test]
    fn get_notes_value() {
        let ce = CredEntry::new(SecureBytes::new(Vec::from("A_secure_pwd1")), false, String::from("id"), None, None)
            .expect("unable to create CredEntry");

        assert_eq!(ce.get_notes(), &None, "notes is not equal to ce.get_notes");
    }

    /// Tests that `set_notes` actually updates notes value
    #[test]
    fn set_notes_value() {
        let mut ce = CredEntry::new(
            SecureBytes::new(Vec::from("A_secure_password1")),
            false,
            String::from("id"),
            None,
            None
        ).expect("unable to create CredEntry");

        let notes = Some(String::from("new_notes"));
        ce.set_notes(notes.clone()).expect("unable to updated notes value");

        assert_eq!(ce.notes, notes, "notes value has not been updated");

    }

    /// Tests that `set_notes` returns an error if notes string is empty
    #[test]
    fn set_notes_empty() {
        let mut ce = CredEntry::new(
            SecureBytes::new(Vec::from("A_secure_password1")),
            false,
            String::from("id"),
            None,
            None
        ).expect("unable to create CredEntry");

        let notes = Some(String::new());
        assert!(ce.set_notes(notes).is_err(), "no error with empty notes");
    }
    // ]]]
}
// ]]]
