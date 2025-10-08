//! # Domain
//!
//! This crate contains the domain data of the CustosPass project

pub mod mst_pwd;
pub mod cred_set;

pub const SPEC_CHARS: [char; 10] = ['-', '+', '_', '&', '%', '@', '$', '?', '!', '#'];
pub const MIN_PWD_LEN: usize = 10;

use crypto::SecureBytes;
use error::{Err, ErrSrc};
use regex::RegexSet;
use zeroize::Zeroize;

/// Validates the provided password ensuring that it:
///- is at least 10 characters long
///- contains at least:
///    - a capital letter
///    - a lowercase letter
///    - a number
///    - a special character from `SPEC_CHARS`
///
/// # Returns
///
/// Returns `()` if `pwd` is valid, an `Err` describing what went wrong otherwise.
pub fn validate_pwd(pwd: &SecureBytes) -> Result<(), Err> {

    // convertig pwd to a string to perform validation
    let mut pwd_str = match String::from_utf8(pwd.unsecure().to_vec()) {
        Ok(mst) => mst,
        Err(_) => return Err(Err::new("new master password is not a utf-8 string", ErrSrc::Domain))
    };

    if pwd_str.chars().count() < MIN_PWD_LEN {
        pwd_str.zeroize();
        return Err(Err::new(&format!("new master password must be at least {} characters long", MIN_PWD_LEN), ErrSrc::Domain));
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
            pwd_str.zeroize();
            return Err(Err::new(
                "unable to create the master password requirements checker",
                ErrSrc::Domain))
        }
    };

    let match_res = match_set.matches(&pwd_str);

    pwd_str.zeroize();

    if !match_res.matched_all() {
        let mut err_msg = format!("new master password must contain:\n\t- a capital letter\n\t- a lower case letter\n\t- a number\n\t- a special character between: ");
        for c in SPEC_CHARS {
            err_msg.push(c);
            err_msg += ", ";
        }

        return Err(Err::new(&err_msg, ErrSrc::Domain));
    }

    Ok(())

}

// unit testing [[[
#[cfg(test)]

mod tests {
    use super::*;

    // validate_pwd [[[
    
    /// Tests that `validate_pwd` returns `()` if the master password is valid
    #[test]
    fn validate_pwd_valid () {
        // looping on all capital letters
        for letter in b'A' ..= b'Z' {
            let mut mst_str = String::from("bcdefgh1_");
            mst_str.push(letter as char);
            let mst = SecureBytes::new(mst_str.as_bytes().to_vec());

            assert!(
                validate_pwd(&mst).is_ok(),
                "error with a valid master password (letter {})", letter as char
            );
        }

        // looping on all lower case letters
        for letter in b'a' ..= b'z' {
            let mut mst_str = String::from("BCDEFGH1_");
            mst_str.push(letter as char);
            let mst = SecureBytes::new(mst_str.as_bytes().to_vec());

            assert!(
                validate_pwd(&mst).is_ok(),
                "error with a valid master password (letter {})", letter as char
            );
        }

        // looping on all digits
        for digit in 0 ..= 9 {
            let mut mst_str = String::from("Abcdefgh_");
            mst_str += &digit.to_string();
            let mst = SecureBytes::new(mst_str.as_bytes().to_vec());

            assert!(
                validate_pwd(&mst).is_ok(),
                "error with a valid master password (digit {})", digit
            );
        }

        // looping on all symbols
        for symbol in SPEC_CHARS {
            let mut mst_str = String::from("Abcdefgh1");
            mst_str.push(symbol);
            let mst = SecureBytes::new(mst_str.as_bytes().to_vec());

            assert!(
                validate_pwd(&mst).is_ok(),
                "error with a valid master password (symbol {})", symbol
            );
        }


    }

    /// Tests that `validate_pwd` returns an error if the master password is shorter than `MIN_PWD_LEN` 
    #[test]
    fn validate_pwd_shorter () {
        let mst = SecureBytes::new(Vec::from("Abcdefg1_"));
        
        assert!(validate_pwd(&mst).is_err(), "no error with a short password");
    }

    /// Tests that `validate_pwd` returns an error if the master password is not a utf-8 string
    #[test]
    fn validate_pwd_no_str () {
        let mst = SecureBytes::new(Vec::from([1u8;20]));
        
        assert!(validate_pwd(&mst).is_err(), "no error with a password that is not a string");
    }

    /// Tests that `validate_pwd` returns an error if the master password does not contain a
    /// capital letter
    #[test]
    fn validate_pwd_no_lower () {
        let mst = SecureBytes::new(Vec::from("abcdefgh1_"));
        
        assert!(validate_pwd(&mst).is_err(), "no error with a password missing a capital letter");
    }

    /// Tests that `validate_pwd` returns an error if the master password does not contain a
    /// lower case letter
    #[test]
    fn validate_pwd_no_capital () {
        let mst = SecureBytes::new(Vec::from("ABCDEFGH1_"));
        
        assert!(validate_pwd(&mst).is_err(), "no error with a password missing a lower case letter");
    }

    /// Tests that `validate_pwd` returns an error if the master password does not contain a
    /// number
    #[test]
    fn validate_pwd_no_number () {
        let mst = SecureBytes::new(Vec::from("Abcdefghi_"));
        
        assert!(validate_pwd(&mst).is_err(), "no error with a password missing a number");
    }

    /// Tests that `validate_pwd` returns an error if the master password does not contain a
    /// symbol
    #[test]
    fn validate_pwd_no_symbol () {
        let mst = SecureBytes::new(Vec::from("Abcdefgh1i"));
        
        assert!(validate_pwd(&mst).is_err(), "no error with a password missing a symbol");
    }

    // ]]]
}
// ]]]
