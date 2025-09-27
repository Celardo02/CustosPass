//! # sym_enc
//!
//! This module provides symmetric encryption capabilities using an AEAD agorithm.
//!
//! # Security Note
//!
//! Current implementation is based on the aes-gcm crate in the 
//! [Rust Crypto repository](https://github.com/RustCrypto/AEADs/tree/master/aes-gcm).
//!
//! Nonce reuse is __NOT__ prevented by the module implementation.
//!
//! # Example
//! ```
//! use crypto::{
//!     CryptoErr,
//!     SecureBytes,
//!     sym_enc::{KEY_LEN, NONCE_LEN, SymEncProvider, SymmetricEnc},
//!     rng::{Rng, RandomNumberGenerator, SystemRandom}
//! };
//! 
//!
//! let rng = Rng::new(SystemRandom::new());
//! let key_bytes: [u8; KEY_LEN] = rng.generate(KEY_LEN).unwrap().try_into().unwrap();
//! let key = SecureBytes::new(Vec::from(key_bytes));
//! let nonce = rng.generate_nonce().unwrap();
//! let plain = SecureBytes::new(Vec::from("plaintext"));
//!
//! let enc = match SymEncProvider::encrypt(&key, None, &nonce, &plain) {
//!     Ok(e) => e,
//!     Err(_) => panic!("unable to encrypt plain")
//! };
//!
//! let pl = match SymEncProvider::decrypt(&key, None, &nonce, &enc) {
//!     Ok(p) => p,
//!     Err(_) => panic!("unable to decrypt enc")
//! };
//!
//! assert_eq!(plain, pl);
//! ```


use crate::{SecureBytes, CryptoErr};
use aes_gcm::{
    aead::{Aead, generic_array::GenericArray, KeyInit, Payload},
    Aes256Gcm, Key
};

// constants [[[

/// symmetric key length in bytes
pub const KEY_LEN: usize = 256 / 8 ;

/// nonce length in bytes
pub const NONCE_LEN: usize = 96 / 8;

// ]]]

// SymEncProvider [[[ 

pub struct SymEncProvider;

impl SymEncProvider {
    /// Checks if the inputs provided to encryption and decryption function are properly set
    ///
    /// # Parameters
    ///
    /// - `key`: encryption/decryption key
    /// - `aad`: additional authenticated data
    /// - `bytes`: plaintext/ciphertext
    ///
    /// # Panics
    ///
    /// Panics if `key` is not `KEY_LEN` long, `bytes` is empty or `aad` is not None and is empty
    fn check_inputs(key: &SecureBytes, aad: Option<&[u8]>, bytes: &SecureBytes) {
        assert_eq!(key.unsecure().len(), KEY_LEN);
        assert!(!bytes.unsecure().is_empty());

        if let Some(a) = aad { 
            assert!(!a.is_empty());
        }
    }
}

// ]]]

// SymmetricEnc trait [[[

pub trait SymmetricEnc {
    /// Encrypts `plain` using `key` and including `aad` in the process.
    ///
    /// # Security Note
    ///
    /// No key derivation function is applied to `key` by this method. It is highly recommended 
    /// to use a kdf output as key value or to use a very strong encryption key.
    ///
    /// # Parameters
    ///
    /// - `key`: encryption key. Key must be `KEY_LEN` long
    /// - `aad`: additional authenticated data. Set it to `None` if not needed
    /// - `nonce`: nonce use by the encryption algorithm. This value must __NOT__ be reused with
    /// the same encryption key 
    /// - `plain`: plaintext that will be encrypted. It must __NOT__ be empty
    ///
    /// # Returns
    ///
    /// Returns a `SecureBytes` containing the chipertext if no error occurs, `CryptoErr` otherwise.
    ///
    /// # Panics
    ///
    /// Panics if `key` is not `KEY_LEN` long, `plain` is empty or `aad` is `Some(a)` and `a` is empty
    fn encrypt (
        key: &SecureBytes,
        aad: Option<&[u8]>,
        nonce: &[u8; NONCE_LEN],
        plain: &SecureBytes )
    -> Result<SecureBytes, CryptoErr>;

    /// Decrypts `enc` using `key`, `nonce`, and including `aad` in the process.
    ///
    /// # Parameters
    ///
    /// - `key`: key used in the encryption process of `enc`
    /// - `aad`: additional authenticated data used in the encryption process of `enc`
    /// - `nonce`: nonce used in the encryption process of `enc`
    /// - `enc`: chipertext. It must __NOT__ be empty
    ///
    /// # Returns
    ///
    /// Returns a `SecureBytes` containig the plaintext if no error occurs, `CryptoErr` otherwise.
    ///
    /// # Panics
    ///
    /// Panics if `key` is not `KEY_LEN` long, `enc` is empty or `aad` is `Some(a)` and `a` is empty
    fn decrypt (
        key: &SecureBytes,
        aad: Option<&[u8]>,
        nonce: &[u8; NONCE_LEN],
        enc: &SecureBytes)
    -> Result<SecureBytes, CryptoErr>;
}


impl SymmetricEnc for SymEncProvider {

    fn encrypt (
        key: &SecureBytes,
        aad: Option<&[u8]>,
        nonce: &[u8; NONCE_LEN],
        plain: &SecureBytes )
    -> Result<SecureBytes, CryptoErr> {

        SymEncProvider::check_inputs(key, aad, plain);

        let aes_key = Key::<Aes256Gcm>::from_slice(key.unsecure());

        let cipher = Aes256Gcm::new(&aes_key);

        let enc = match aad {
            Some(a) => {
                let payload = Payload {
                    msg: plain.unsecure(),
                    aad: a
                };
                // generic array can not panic as NONCE_LEN is enforced by nonce type
                cipher.encrypt(GenericArray::from_slice(nonce), payload)
            },
            None => cipher.encrypt(GenericArray::from_slice(nonce), plain.unsecure())
        }.map_err(|_| CryptoErr)?;


        // no memory leak happens as enc is borrowed by SecureBytes, hence it will get zeroized
        Ok(SecureBytes::new(enc))
    }

    fn decrypt (
        key: &SecureBytes,
        aad: Option<&[u8]>,
        nonce: &[u8; NONCE_LEN],
        enc: &SecureBytes)
    -> Result<SecureBytes, CryptoErr>{ 


        SymEncProvider::check_inputs(key, aad, enc);


        let aes_key = Key::<Aes256Gcm>::from_slice(key.unsecure());

        let cipher = Aes256Gcm::new(&aes_key);

        let plain = match aad {
            Some(a) => {
                let payload = Payload {
                    msg: enc.unsecure(),
                    aad: a
                };
                // generic array can not panic as NONCE_LEN is enforced by nonce type
                cipher.decrypt(GenericArray::from_slice(nonce), payload)
            },
            None => cipher.decrypt(GenericArray::from_slice(nonce), enc.unsecure())
        }.map_err(|_| CryptoErr)?;


        // no memory leak happens as enc is borrowed by SecureBytes, hence it will get zeroized
        Ok(SecureBytes::new(plain))
    }
}

// ]]]

// unit testing [[[ 
#[cfg(test)]
mod tests {
    use super::*;

    // encrypt [[[

    /// Tests that `encrypt` panics if `key` is shorter than `KEY_LEN`
    #[test]
    #[should_panic]
    fn encrypt_smaller_key () {
        match SymEncProvider::encrypt(
            &SecureBytes::new(vec![1u8;KEY_LEN - 5]),
            None,
            &[2u8; NONCE_LEN],
            &SecureBytes::new(Vec::from("plain"))
        ) {
            _ => {}
        };
    }

    /// Tests that `encrypt` panics if `key` is longer than `KEY_LEN`
    #[test]
    #[should_panic]
    fn encrypt_longer_key () {
        match SymEncProvider::encrypt(
            &SecureBytes::new(vec![1u8;KEY_LEN + 5]),
            None,
            &[2u8; NONCE_LEN],
            &SecureBytes::new(Vec::from("plain"))
        ) {
            _ => {}
        };
    }

    /// Tests that `encrypt` panics if `aad` is `Some(a)` and `a` is empty
    #[test]
    #[should_panic]
    fn encrypt_empty_aad () {
        match SymEncProvider::encrypt(
            &SecureBytes::new(vec![1u8;KEY_LEN]),
            Some(&[]),
            &[2u8; NONCE_LEN],
            &SecureBytes::new(Vec::from("plain"))
        ) {
            _ => {}
        };
    }

    /// Tests that `encrypt` panics if `plain` is empty
    #[test]
    #[should_panic]
    fn encrypt_empty_plain () {
        match SymEncProvider::encrypt(
            &SecureBytes::new(vec![1u8;KEY_LEN]),
            None,
            &[2u8; NONCE_LEN],
            &SecureBytes::new(Vec::new())
        ) {
            _ => {}
        };
    }

    /// Tests that `encrypt` return a different value from the plaintext
    #[test]
    fn encrypt_plain () {
        let key = SecureBytes::new(vec![3u8;KEY_LEN]);
        let nonce = [1u8; NONCE_LEN];
        let plain = SecureBytes::new(Vec::from("plain"));

        // testing with None aad
        let enc = match SymEncProvider::encrypt(&key, None, &nonce, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain with None aad")
        };

        assert_ne!(enc, plain);

        // testing with Some aad
        let enc2 = match SymEncProvider::encrypt(&key, Some([1u8;5].as_slice()), &nonce, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain with Some aad")
        };

        assert_ne!(enc2, plain);
        assert_ne!(enc, enc2);
    }

    /// Tests that `encrypt` returns the same output given the same inputs
    #[test]
    fn encrypt_same_out () {
        let key = SecureBytes::new(vec![3u8;KEY_LEN]);
        let nonce = [1u8; NONCE_LEN];
        let plain = SecureBytes::new(Vec::from("plain"));

        // testing with None aad
        let enc1 = match SymEncProvider::encrypt(&key, None, &nonce, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the first time")
        };

        let enc2 = match SymEncProvider::encrypt(&key, None, &nonce, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the second time")
        };

        assert_eq!(enc1, enc2);

        // testing with Some aad
        let aad = Some([1u8;5].as_slice());
        let enc3 = match SymEncProvider::encrypt(&key, aad, &nonce, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the third time")
        };

        let enc4 = match SymEncProvider::encrypt(&key, aad, &nonce, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the fourth time")
        };

        assert_eq!(enc3, enc4);
    }

    /// Tests that `encrypt` returns a different output given the same inputs but the key
    #[test]
    fn encrypt_diff_key () {
        let key1 = SecureBytes::new(vec![3u8;KEY_LEN]);
        let key2 = SecureBytes::new(vec![4u8;KEY_LEN]);
        let nonce = [1u8; NONCE_LEN];
        let plain = SecureBytes::new(Vec::from("plain"));

        // testing with None aad
        let enc1 = match SymEncProvider::encrypt(&key1, None, &nonce, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the first time")
        };

        let enc2 = match SymEncProvider::encrypt(&key2, None, &nonce, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the second time")
        };

        assert_ne!(enc1, enc2);
        
        // testing with Some aad
        let aad = Some([1u8; 5].as_slice());
        let enc3 = match SymEncProvider::encrypt(&key1, aad, &nonce, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the first time")
        };

        let enc4 = match SymEncProvider::encrypt(&key2, aad, &nonce, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the second time")
        };

        assert_ne!(enc3, enc4);
    }

    /// Tests that `encrypt` returns a different output given the same inputs but the aad
    #[test]
    fn encrypt_diff_aad () {
        let key = SecureBytes::new(vec![3u8;KEY_LEN]);
        // checking different length, value with the same length, Some vs None
        let aad1 = Some([1u8;10].as_slice());
        let aad2 = Some([1u8;20].as_slice());
        let aad3 = Some([2u8;10].as_slice());
        let aad4 = None;
        let nonce = [1u8; NONCE_LEN];
        let plain = SecureBytes::new(Vec::from("plain"));

        let enc1 = match SymEncProvider::encrypt(&key, aad1, &nonce, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the first time")
        };

        let enc2 = match SymEncProvider::encrypt(&key, aad2, &nonce, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the second time")
        };

        let enc3 = match SymEncProvider::encrypt(&key, aad3, &nonce, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the third time")
        };

        let enc4 = match SymEncProvider::encrypt(&key, aad4, &nonce, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the fourth time")
        };

        assert_ne!(enc1, enc2);
        assert_ne!(enc1, enc3);
        assert_ne!(enc1, enc4);
        assert_ne!(enc2, enc3);
        assert_ne!(enc2, enc4);
        assert_ne!(enc3, enc4);
    }

    /// Tests that `encrypt` returns a different output given the same inputs but the nonce
    #[test]
    fn encrypt_diff_nonce () {
        let key = SecureBytes::new(vec![3u8;KEY_LEN]);
        let nonce1 = [1u8; NONCE_LEN];
        let nonce2 = [2u8; NONCE_LEN];
        let plain = SecureBytes::new(Vec::from("plain"));

        // testing with None aad
        let enc1 = match SymEncProvider::encrypt(&key, None, &nonce1, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the first time")
        };

        let enc2 = match SymEncProvider::encrypt(&key, None, &nonce2, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the second time")
        };

        assert_ne!(enc1, enc2);

        // testing with Some aad
        let aad = Some([1u8; 5].as_slice());
        let enc3 = match SymEncProvider::encrypt(&key, aad, &nonce1, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the third time")
        };

        let enc4 = match SymEncProvider::encrypt(&key, aad, &nonce2, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the fourth time")
        };

        assert_ne!(enc3, enc4);
    }

    /// Tests that `encrypt` returns a different output given the same inputs but the plaintext
    #[test]
    fn encrypt_diff_plain () {
        let key = SecureBytes::new(vec![3u8;KEY_LEN]);
        let nonce = [1u8; NONCE_LEN];
        let plain1 = SecureBytes::new(Vec::from("plain1"));
        let plain2 = SecureBytes::new(Vec::from("plain2"));

        // testing with None aad
        let enc1 = match SymEncProvider::encrypt(&key, None, &nonce, &plain1) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the first time")
        };

        let enc2 = match SymEncProvider::encrypt(&key, None, &nonce, &plain2) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the second time")
        };

        assert_ne!(enc1, enc2);

        // testing with Some aad
        let aad = Some([1u8; 5].as_slice());
        let enc3 = match SymEncProvider::encrypt(&key, aad, &nonce, &plain1) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the first time")
        };

        let enc4 = match SymEncProvider::encrypt(&key, aad, &nonce, &plain2) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain the second time")
        };

        assert_ne!(enc3, enc4);
    }

    // ]]]

    // decrypt [[[ 

    /// Tests that `decrypt` panics if `key` is shorter than `KEY_LEN`
    #[test]
    #[should_panic]
    fn decrypt_smaller_key () {
        match SymEncProvider::decrypt(
            &SecureBytes::new(vec![1u8;KEY_LEN - 5]),
            None,
            &[2u8; NONCE_LEN],
            &SecureBytes::new(Vec::from("enc"))
        ) {
            _ => {}
        };
    }

    /// Tests that `decrypt` panics if `key` is longer than `KEY_LEN`
    #[test]
    #[should_panic]
    fn decrypt_longer_key () {
        match SymEncProvider::decrypt(
            &SecureBytes::new(vec![1u8;KEY_LEN + 5]),
            None,
            &[2u8; NONCE_LEN],
            &SecureBytes::new(Vec::from("enc"))
        ) {
            _ => {}
        };
    }

    /// Tests that `decrypt` panics if `aad` is `Some(a)` and `a` is empty
    #[test]
    #[should_panic]
    fn decrypt_empty_aad () {
        match SymEncProvider::decrypt(
            &SecureBytes::new(vec![1u8;KEY_LEN]),
            Some(&[]),
            &[2u8; NONCE_LEN],
            &SecureBytes::new(Vec::from("enc"))
        ) {
            _ => {}
        };
    }

    /// Tests that `decrypt` panics if `enc` is empty
    #[test]
    #[should_panic]
    fn decrypt_empty_enc () {
        match SymEncProvider::encrypt(
            &SecureBytes::new(vec![1u8;KEY_LEN]),
            None,
            &[2u8; NONCE_LEN],
            &SecureBytes::new(Vec::new())
        ) {
            _ => {}
        };
    }

    /// Tests that `decrypt` actually decrypts the ciphertext
    #[test]
    fn decrypt_cipher () {
        let key = SecureBytes::new(vec![3u8;KEY_LEN]);
        let nonce = [1u8; NONCE_LEN];
        let plain = SecureBytes::new(Vec::from("plain"));

        // testing with None aad
        let enc = match SymEncProvider::encrypt(&key, None, &nonce, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain")
        };

        let plain_res =  match SymEncProvider::decrypt(&key, None, &nonce, &enc) {
            Ok(p) => p,
            Err(_) => panic!("unable to decrypt enc")
        };

        assert_eq!(plain, plain_res);

        // testing with Some aad
        let aad = Some([3u8;5].as_slice());

        let enc2 = match SymEncProvider::encrypt(&key, aad, &nonce, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain")
        };

        let plain_res2 =  match SymEncProvider::decrypt(&key, aad, &nonce, &enc2) {
            Ok(p) => p,
            Err(_) => panic!("unable to decrypt enc")
        };

        assert_eq!(plain, plain_res2);
    }

    /// Tests that `decrypt` returns the same output given the same inputs
    #[test]
    fn decrypt_same_out () {
        let key = SecureBytes::new(vec![3u8;KEY_LEN]);
        let nonce = [1u8; NONCE_LEN];
        let pl = SecureBytes::new(Vec::from("plain"));


        // testing with none aad
        let enc = match SymEncProvider::encrypt(&key, None, &nonce, &pl) {
            Ok(e) => e,
            Err(_) => panic!("unable to encrypt pl with none aad")
        };

        let plain1 = match SymEncProvider::decrypt(&key, None, &nonce, &enc) {
            Ok(p) => p,
            Err(_) => panic!("unable to decrypt enc the first time")
        };

        let plain2 = match SymEncProvider::decrypt(&key, None, &nonce, &enc) {
            Ok(p) => p,
            Err(_) => panic!("unable to decrypt enc the second time")
        };

        assert_eq!(plain1, plain2);

        // testing with Some aad
        let aad = Some([1u8; 5].as_slice());
        let enc2 = match SymEncProvider::encrypt(&key, aad, &nonce, &pl) {
            Ok(e) => e,
            Err(_) => panic!("unable to encrypt pl with some aad")
        };

        let plain3 = match SymEncProvider::decrypt(&key, aad, &nonce, &enc2) {
            Ok(p) => p,
            Err(_) => panic!("unable to decrypt enc the third time")
        };

        let plain4 = match SymEncProvider::decrypt(&key, aad, &nonce, &enc2) {
            Ok(p) => p,
            Err(_) => panic!("unable to decrypt enc the fourth time")
        };

        assert_eq!(plain3, plain4);
    }

    /// Tests that `decrypt` returns an error given the right inputs but the key
    #[test]
    fn decrypt_diff_key () {
        let key1 = SecureBytes::new(vec![3u8;KEY_LEN]);
        let key2 = SecureBytes::new(vec![4u8;KEY_LEN]);
        let nonce = [1u8; NONCE_LEN];
        let pl = SecureBytes::new(Vec::from("plain"));

        // testing with None aad
        let enc = match SymEncProvider::encrypt(&key1, None, &nonce, &pl) {
            Ok(e) => e,
            Err(_) => panic!("unable to encrypt pl with none aad")
        };

        match SymEncProvider::decrypt(&key2, None, &nonce, &enc) {
            Ok(_) => panic!("no error with wrong key (none aad)"),
            Err(e) => e
        };

        // testing with Some aad
        let aad = Some([1u8;5].as_slice());
        let enc2 = match SymEncProvider::encrypt(&key1, aad, &nonce, &pl) {
            Ok(e) => e,
            Err(_) => panic!("unable to encrypt pl with some aad")
        };

        match SymEncProvider::decrypt(&key2, aad, &nonce, &enc2) {
            Ok(_) => panic!("no error with wrong key (some aad)"),
            Err(e) => e
        };
    }

    /// Tests that `decrypt` returns an error given the same inputs but the aad
    #[test]
    fn decrypt_diff_aad () {
        let key = SecureBytes::new(vec![3u8;KEY_LEN]);
        // checking different length, value with the same length, Some vs None
        let aad1 = Some([1u8;10].as_slice());
        let aad2 = Some([1u8;20].as_slice());
        let aad3 = Some([2u8;10].as_slice());
        let aad4 = None;
        let nonce = [1u8; NONCE_LEN];
        let pl = SecureBytes::new(Vec::from("plain"));
        let enc = match SymEncProvider::encrypt(&key, aad4, &nonce, &pl) {
            Ok(e) => e,
            Err(_) => panic!("unable to encrypt pl with aad4")
        };

        match SymEncProvider::decrypt(&key, aad1, &nonce, &enc) {
            Ok(_) => panic!("no error with first wrong aad"),
            Err(e) => e
        };

        match SymEncProvider::decrypt(&key, aad2, &nonce, &enc) {
            Ok(_) => panic!("no error with second wrong aad"),
            Err(e) => e
        };

        match SymEncProvider::decrypt(&key, aad3, &nonce, &enc) {
            Ok(_) => panic!("no error with third wrong aad"),
            Err(e) => e
        };

        let enc2 = match SymEncProvider::encrypt(&key,aad1, &nonce, &pl) {
            Ok(e) => e,
            Err(_) => panic!("unable to encrypt pl with aad1")
        };

        match SymEncProvider::decrypt(&key, aad4, &nonce, &enc2) {
            Ok(_) => panic!("no error with fourth wrong aad"),
            Err(e) => e
        };
    }

    /// Tests that `decrypt` returns an error given the same inputs but the nonce
    #[test]
    fn decrypt_diff_nonce () {
        let key = SecureBytes::new(vec![3u8;KEY_LEN]);
        let nonce1 = [1u8; NONCE_LEN];
        let nonce2 = [2u8; NONCE_LEN];
        let pl = SecureBytes::new(Vec::from("plain"));

        // testing with None aad
        let enc = match SymEncProvider::encrypt(&key, None, &nonce1, &pl) {
            Ok(e) => e,
            Err(_) => panic!("unable to encrypt pl with none aad")
        };

        match SymEncProvider::decrypt(&key, None, &nonce2, &enc) {
            Ok(_) => panic!("no error with wrong nonce (none aad)"),
            Err(e) => e
        };

        
        // testing with some aad
        let aad = Some([1u8;5].as_slice());
        let enc2 = match SymEncProvider::encrypt(&key, aad, &nonce1, &pl) {
            Ok(e) => e,
            Err(_) => panic!("unable to encrypt pl with some aad")
        };

        match SymEncProvider::decrypt(&key, aad, &nonce2, &enc2) {
            Ok(_) => panic!("no error with wrong nonce (some aad)"),
            Err(e) => e
        };

    }

    // ]]]
}
// ]]]
