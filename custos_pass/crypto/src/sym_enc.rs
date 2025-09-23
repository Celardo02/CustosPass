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
        assert_eq!(!key.unsecure().len(), KEY_LEN);
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
