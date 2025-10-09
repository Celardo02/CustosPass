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

// unit testing [[[
#[cfg(test)]

mod tests {
    use super::*;

    // new [[[
    /// Tests that `new` returns an instance of CredEntry filled with the associated function
    /// arguments when expiring is true
    #[test]
    fn new_value_true() {
        let pwd = SecureBytes::new(Vec::from("A_secure_password1"));
        let id = String::from("id");
        let expiring = true;

        // None case
        
        let mail = None;
        let txt = None;

        let ce = CredEntry::new(pwd.clone(), expiring, id.clone(), mail.clone(), txt.clone())
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
        assert_eq!(ce.txt, txt, "txt does not correspond to ce.txt (None case)");

        // Some case

        let mail = Some(String::from("mail"));
        let txt = Some(String::from("txt"));

        let ce = CredEntry::new(pwd.clone(), expiring, id.clone(), mail.clone(), txt.clone())
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
        assert_eq!(ce.txt, txt, "txt does not correspond to ce.txt (Some case)");
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
        let txt = None;

        let ce = CredEntry::new(pwd.clone(), expiring, id.clone(), mail.clone(), txt.clone())
            .expect("unable to create CredEntry (None case)");

        assert_eq!(ce.pwd, pwd, "pwd does not correspond to ce.pwd (None case)");
        assert_eq!(ce.id, id, "id does not correspond to ce.id (None case)");
        assert_eq!(
            ce.exp_date,
            None,
            "exp_date is not set to be never expiring (None case)");
        assert_eq!(ce.mail, mail, "mail does not correspond to ce.mail (None case)");
        assert_eq!(ce.txt, txt, "txt does not correspond to ce.txt (None case)");

        // Some case

        let mail = Some(String::from("mail"));
        let txt = Some(String::from("txt"));

        let ce = CredEntry::new(pwd.clone(), expiring, id.clone(), mail.clone(), txt.clone())
            .expect("unable to create CredEntry (Some case)");

        assert_eq!(ce.pwd, pwd, "pwd does not correspond to ce.pwd (Some case)");
        assert_eq!(ce.id, id, "id does not correspond to ce.id (Some case)");
        assert_eq!(
            ce.exp_date,
            None,
            "exp_date is not set to be never expiring (Some case)");
        assert_eq!(ce.mail, mail, "mail does not correspond to ce.mail (Some case)");
        assert_eq!(ce.txt, txt, "txt does not correspond to ce.txt (Some case)");
    }

    /// Tests that `new` returns an error if id is empty
    #[test]
    fn new_id_empty() {
        let pwd = SecureBytes::new(Vec::from("A_secure_password1"));
        let id = String::new();
        let expiring = true;

        // None case
        
        let mail = None;
        let txt = None;

        assert!(
            CredEntry::new(pwd.clone(), expiring, id.clone(), mail.clone(), txt.clone()).is_err(),
            "no error with empty id (None case)"
        );

        // Some case

        let mail = Some(String::from("mail"));
        let txt = Some(String::from("txt"));

        assert!(
            CredEntry::new(pwd, expiring, id, mail, txt).is_err(),
            "no error with empty id (Some case)"
        );
    }

    /// Tests that `new` returns an error if mail is empty and not `None`
    #[test]
    fn new_mail_empty() {
        let pwd = SecureBytes::new(Vec::from("A_secure_password1"));
        let id = String::from("id");
        let expiring = true;
        let mail = Some(String::new());

        // None case
        
        let txt = None;

        assert!(
            CredEntry::new(pwd.clone(), expiring, id.clone(), mail.clone(), txt.clone()).is_err(),
            "no error with empty mail (None case)"
        );

        // Some case

        let txt = Some(String::from("txt"));

        assert!(
            CredEntry::new(pwd, expiring, id, mail, txt).is_err(),
            "no error with empty mail (Some case)"
        );
    }

    /// Tests that `new` returns an error if txt is empty and not `None`
    #[test]
    fn new_txt_empty() {
        let pwd = SecureBytes::new(Vec::from("A_secure_password1"));
        let id = String::from("id");
        let expiring = true;
        let txt = Some(String::new());

        // None case
        
        let mail = None;

        assert!(
            CredEntry::new(pwd.clone(), expiring, id.clone(), mail.clone(), txt.clone()).is_err(),
            "no error with empty txt (None case)"
        );

        // Some case

        let mail = Some(String::from("mail"));

        assert!(
            CredEntry::new(pwd, expiring, id, mail, txt).is_err(),
            "no error with empty txt (Some case)"
        );
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
        let txt = None;

        let ce = CredEntry::new_with_date(pwd.clone(), expiring.clone(), id.clone(), mail.clone(), txt.clone())
            .expect("unable to create CredEntry (None case)");

        assert_eq!(ce.pwd, pwd, "pwd does not correspond to ce.pwd (None case)");
        assert_eq!(ce.id, id, "id does not correspond to ce.id (None case)");
        assert_eq!(ce.exp_date, expiring, "exp_date is not set to be never expiring");
        assert_eq!(ce.mail, mail, "mail does not correspond to ce.mail (None case)");
        assert_eq!(ce.txt, txt, "txt does not correspond to ce.txt (None case)");

        // Some case

        let expiring = Some(Utc::now()
            .date_naive()
            .checked_add_signed(TimeDelta::seconds(60 * 60 * 24))
            // expect is used to avoid unwanted None coming from checked_add_signed
            .expect("unable to create expiring date (Some case)")
        );
        let mail = Some(String::from("mail"));
        let txt = Some(String::from("txt"));

        let ce = CredEntry::new_with_date(pwd.clone(), expiring.clone(), id.clone(), mail.clone(), txt.clone())
            .expect("unable to create CredEntry (Some case)");

        assert_eq!(ce.pwd, pwd, "pwd does not correspond to ce.pwd (Some case)");
        assert_eq!(ce.id, id, "id does not correspond to ce.id (Some case)");
        assert_eq!(ce.exp_date, expiring, "expiring does not correspond to ce.expiring");
        assert_eq!(ce.mail, mail, "mail does not correspond to ce.mail (Some case)");
        assert_eq!(ce.txt, txt, "txt does not correspond to ce.txt (Some case)");
    }


    /// Tests that `new_with_date` returns an error if expiring equal to the current day 
    #[test]
    fn new_with_date_exp_today() {
        let pwd = SecureBytes::new(Vec::from("A_secure_password1"));
        let id = String::new();
        let expiring = Some(Utc::now().date_naive());

        // None case
        
        let mail = None;
        let txt = None;

        assert!(
            CredEntry::new_with_date(pwd.clone(), expiring.clone(), id.clone(), mail.clone(), txt.clone()).is_err(),
            "no error with credential set expiring today (None case)"
        );

        // Some case

        let mail = Some(String::from("mail"));
        let txt = Some(String::from("txt"));

        assert!(
            CredEntry::new_with_date(pwd, expiring, id, mail, txt).is_err(),
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
        let txt = None;

        assert!(
            CredEntry::new_with_date(pwd.clone(), expiring.clone(), id.clone(), mail.clone(), txt.clone()).is_err(),
            "no error with exp_date predating today (None case)"
        );

        // Some case

        let mail = Some(String::from("mail"));
        let txt = Some(String::from("txt"));

        assert!(
            CredEntry::new_with_date(pwd, expiring, id, mail, txt).is_err(),
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
        let txt = None;

        assert!(
            CredEntry::new_with_date(pwd.clone(), expiring, id.clone(), mail.clone(), txt.clone()).is_err(),
            "no error with empty id (None case)"
        );

        // Some case

        let expiring = Some(Utc::now()
            .date_naive()
            .checked_add_signed(TimeDelta::seconds(60 * 60 * 24))
            // expect is used to avoid unwanted None coming from checked_add_signed
            .expect("unable to create expiring date (Some case)")
        );
        let mail = Some(String::from("mail"));
        let txt = Some(String::from("txt"));

        assert!(
            CredEntry::new_with_date(pwd, expiring, id, mail, txt).is_err(),
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
        let txt = None;

        assert!(
            CredEntry::new_with_date(pwd.clone(), expiring, id.clone(), mail.clone(), txt.clone()).is_err(),
            "no error with empty mail (None case)"
        );

        // Some case

        let expiring = Some(Utc::now()
            .date_naive()
            .checked_add_signed(TimeDelta::seconds(60 * 60 * 24))
            // expect is used to avoid unwanted None coming from checked_add_signed
            .expect("unable to create expiring date (Some case)")
        );
        let txt = Some(String::from("txt"));

        assert!(
            CredEntry::new_with_date(pwd, expiring, id, mail, txt).is_err(),
            "no error with empty mail (Some case)"
        );
    }

    /// Tests that `new_with_date` returns an error if txt is empty and not `None`
    #[test]
    fn new_with_date_txt_empty() {
        let pwd = SecureBytes::new(Vec::from("A_secure_password1"));
        let id = String::from("id");
        let txt = Some(String::new());

        // None case
        
        let expiring = None;
        let mail = None;

        assert!(
            CredEntry::new_with_date(pwd.clone(), expiring, id.clone(), mail.clone(), txt.clone()).is_err(),
            "no error with empty txt (None case)"
        );

        // Some case

        let expiring = Some(Utc::now()
            .date_naive()
            .checked_add_signed(TimeDelta::seconds(60 * 60 * 24))
            // expect is used to avoid unwanted None coming from checked_add_signed
            .expect("unable to create expiring date (Some case)")
        );
        let mail = Some(String::from("mail"));

        assert!(
            CredEntry::new_with_date(pwd, expiring, id, mail, txt).is_err(),
            "no error with empty txt (Some case)"
        );
    }
    // ]]]
}
// ]]]
