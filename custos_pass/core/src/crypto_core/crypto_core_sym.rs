//! # Crypto Core Sym 
//!
//! This submodule provides symmetric encryption capabilities to `CryptoProvider`.
//!
//! # Example
//! ```
//! use core::crypto_core::{CryptoProvider, crypto_core_sym::CryptoCoreSymEnc, sym_enc_res::SymEncRes};
//! use crypto::{rng::SystemRandom, SecureBytes};
//!
//! let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
//!     Ok(cp) => cp,
//!     Err(_) => panic!("unable to create CryptoProvier")
//! };
//!
//! let key = SecureBytes::new(Vec::from("a_strong_key"));
//! let aad = None;
//! let plain = SecureBytes::new(Vec::from("plaintext"));
//!
//! let enc = match cp.encrypt(&key, aad, &plain) {
//!     Ok(enc) => enc,
//!     Err(_) => panic!("unable to perform encryption")
//! };
//!
//! let plain_res = match CryptoProvider::<SystemRandom>::decrypt(&key, enc.get_key_salt(), aad, enc.get_enc_nonce(), &enc.get_enc()) {
//!     Ok(pl) => pl,
//!     Err(_) => panic!("unable to perform decryption")
//! };
//!
//! assert_eq!(plain_res, plain, "plaintext does not correspond to decrypted plaintext");
//! ```

use super::{
    crypto_core_hashing::CryptoCoreHashing,
    sym_enc_res::SymEncRes,
    RandomNumberGenerator, SecureRandom,
    CryptoErr, CryptoProvider, NONCE_LEN, SALT_LEN, SHA512_OUTPUT_LEN, SecureBytes
};

use crypto::{
    rng::SystemRandom,
    sym_enc::{KEY_LEN, SymmetricEnc, SymEncProvider}
};


pub trait CryptoCoreSymEnc{
    /// Encrypts `plain` using `key` and including `aad` in the process.
    ///
    /// # Security Note
    ///
    /// `key` is not directly used as encryption key: the output of `compute_hash` in
    /// `CryptoProvider` applied to it is used instead.
    ///
    /// # Parameters
    ///
    /// - `key`: encryption key. Key must __NOT__ be empty
    /// - `aad`: additional authenticated data. Set it to `None` if not needed
    /// - `plain`: plaintext that will be encrypted. It must __NOT__ be empty
    ///
    /// # Returns
    ///
    /// Returns a `SymEncRes` if no error occurs, `CryptoErr` otherwise.
    fn encrypt (
        &mut self,
        key: &SecureBytes,
        aad: Option<&[u8]>,
        plain: &SecureBytes 
    ) -> Result<SymEncRes, CryptoErr>;

    /// Decrypts `enc` using `key`, `nonce`, and including `aad` in the process.
    ///
    /// # Parameters
    ///
    /// - `key`: key used in the encryption process of `enc`
    /// - `key_salt`: salt used to derive the encryption key from `key`
    /// - `aad`: additional authenticated data used in the encryption process of `enc`
    /// - `nonce`: nonce used in the encryption process of `enc`
    /// - `enc`: ciphertext. It must __NOT__ be empty
    ///
    /// # Returns
    ///
    /// Returns a `SecureBytes` containig the plaintext if no error occurs, `CryptoErr` otherwise.
    fn decrypt (
        key: &SecureBytes,
        key_salt: &[u8; SALT_LEN],
        aad: Option<&[u8]>,
        nonce: &[u8; NONCE_LEN],
        enc: &SecureBytes
    ) -> Result<SecureBytes, CryptoErr>;
}

// CryptoCoreSymEnc for CryptoProvider [[[

impl <T: SecureRandom> CryptoCoreSymEnc for CryptoProvider<T> {
    fn encrypt (
        &mut self,
        key: &SecureBytes,
        aad: Option<&[u8]>,
        plain: &SecureBytes 
    ) -> Result<SymEncRes, CryptoErr> {

        check_inputs(key, aad, plain)?;

        let enc_key = self.compute_hash(key, KEY_LEN)?;

        let mut nonce = self.rng.generate_nonce()?;
        
        let mut used_nonce = true;
        
        // checking whether the nonce has already been used at all.
        while let Some(key_vec) = self.old_nonces.get(&nonce) && used_nonce {
            used_nonce = false;
            // checking whether enc_key has already been used with the current nonce value or not
            for k in key_vec { 
                match CryptoProvider::<SystemRandom>::verify_hash(enc_key.get_hash(), k.get_salt(), k.get_hash()) {
                    Ok(true) => {
                        // enc_key has already been used with current nonce value
                        used_nonce = true;
                        nonce = self.rng.generate_nonce()?; 
                        // quitting the loop as no more old keys can match the current one
                        break;
                    },
                    Ok(false) => {},
                    Err(ce) => return Err(ce)
                }
            }
        }

        let enc = SymEncProvider::encrypt(enc_key.get_hash(), aad, &nonce, plain)?;
        
        // computing the hash of enc_key to avoid nonce reuse
        let old_k = self.compute_hash(enc_key.get_hash(), SHA512_OUTPUT_LEN)?;

        self.old_nonces.entry(nonce)
            // as is less likely to get the same nonce twice than getting a new one, clone method 
            // is invoked here instead of or_insert
            .and_modify(|key_vec| key_vec.push(old_k.clone()))
            .or_insert(vec![old_k]);

        Ok(SymEncRes::new(enc, enc_key.get_salt().clone(), nonce))
    }

    fn decrypt (
        key: &SecureBytes,
        key_salt: &[u8; SALT_LEN],
        aad: Option<&[u8]>,
        nonce: &[u8; NONCE_LEN],
        enc: &SecureBytes
    ) -> Result<SecureBytes, CryptoErr> {

        check_inputs(key, aad, enc)?;

        let enc_key = CryptoProvider::<SystemRandom>::recompute_hash(key, key_salt, KEY_LEN)?;

        let plain = SymEncProvider::decrypt(&enc_key, aad, nonce, enc)?;

        Ok(plain)
    }
}

/// Checks whether the inputs of `encrypt` and decrypt are empty or not.
///
/// # Parameters
///
/// - `key`: encryption/decryption key
/// - `aad`: additional authenticated data 
/// - `bytes`: plaintext/ciphertext
///
/// # Returns 
///
/// Returns () if:
/// - `key` is not empty
/// - `aad` is `None` or `Some(a)` and `a` is not empty
/// - `bytes` is not empty
/// `CryptoErr` is returned otherwise.
fn check_inputs(key: &SecureBytes, aad: Option<&[u8]>, bytes: &SecureBytes) -> Result<(), CryptoErr> {
    let mut res = Ok(());

    if key.unsecure().is_empty() || bytes.unsecure().is_empty() {
        res = Err(CryptoErr);
    }

    if let Some(a) = aad && a.is_empty() {
        res = Err(CryptoErr);
    }

    res
}

// ]]]

// Unit testing [[[
#[cfg(test)]

mod testing {
    use super::*;
    use aws_lc_rs::test::rand::{FixedByteRandom, FixedSliceSequenceRandom};
    use std::collections::HashMap;
    use core::cell::UnsafeCell;

    // encrypt [[[

    /// Tests if `encrypt` returns an error when the key is empty
    #[test]
    fn encrypt_empty_key() {
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        };

        let key = SecureBytes::new(Vec::new());
        let aad = None;
        let plain = SecureBytes::new(Vec::from("plaintext"));

        match cp.encrypt(&key, aad, &plain) {
            Ok(_) => panic!("no error with empty key"),
            Err(_) => {}
        };
    }

    /// Tests if `encrypt` returns an error when the aad is Some(a) and a is empty
    #[test]
    fn encrypt_empty_some_aad() {
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        };

        let key = SecureBytes::new(Vec::from("key"));
        let aad = Some([].as_slice());
        let plain = SecureBytes::new(Vec::from("plaintext"));

        match cp.encrypt(&key, aad, &plain) {
            Ok(_) => panic!("no error with empty Some aad"),
            Err(_) => {}
        };
    }

    /// Tests if `encrypt` returns an error when the plaintext is empty
    #[test]
    fn encrypt_empty_plain() {
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        };

        let key = SecureBytes::new(Vec::from("key"));
        let aad = None;
        let plain = SecureBytes::new(Vec::new());

        match cp.encrypt(&key, aad, &plain) {
            Ok(_) => panic!("no error with empty plaintext"),
            Err(_) => {}
        };
    }

    /// Tests if `encrypt` returns a different value from plaintext with a shorter key than KEY_LEN
    #[test]
    fn encrypt_shorter_key () {
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        };

        // None aad
        let key = SecureBytes::new(vec![2u8; KEY_LEN - 5]);
        let plain = SecureBytes::new(Vec::from("plaintext"));

        let enc = match cp.encrypt(&key, None, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with None aad")
        };

        assert_ne!(&plain, enc.get_enc(), "enc is not different from plain with None aad");

        // some aad
        let aad = Some([1u8;10].as_slice());

        let enc2 = match cp.encrypt(&key, aad, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with Some aad")
        };

        assert_ne!(&plain, enc2.get_enc(), "enc2 is not different from plain with Some aad");
    }

    /// Tests if `encrypt` returns a different value from plaintext with a longer key than KEY_LEN
    #[test]
    fn encrypt_longer_key () {
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        };

        // None aad
        let key = SecureBytes::new(vec![2u8;KEY_LEN + 5]);
        let plain = SecureBytes::new(Vec::from("plaintext"));

        let enc = match cp.encrypt(&key, None, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with None aad")
        };

        assert_ne!(&plain, enc.get_enc(), "enc is not different from plain with None aad");

        // some aad
        let aad = Some([1u8;10].as_slice());

        let enc2 = match cp.encrypt(&key, aad, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with Some aad")
        };

        assert_ne!(&plain, enc2.get_enc(), "enc2 is not different from plain with Some aad");
    }

    /// Tests if `encrypt` returns different ciphertext given the same inputs
    #[test]
    fn encrypt_unique_enc () {
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        };

        // None aad
        let key = SecureBytes::new(vec![2u8;KEY_LEN + 5]);
        let plain = SecureBytes::new(Vec::from("plaintext"));

        let enc1 = match cp.encrypt(&key, None, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with None aad (enc1)")
        };

        let enc2 = match cp.encrypt(&key, None, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with None aad (enc2)")
        };

        assert_ne!(enc1.get_enc(), enc2.get_enc(), "enc1.get_enc and enc2.get_enc are the same");

        // some aad
        let aad = Some([1u8;10].as_slice());

        let enc3 = match cp.encrypt(&key, aad, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with Some aad (enc3)")
        };

        let enc4 = match cp.encrypt(&key, aad, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with Some aad (enc4)")
        };

        assert_ne!(enc3.get_enc(), enc4.get_enc(), "enc3.get_enc and enc4.get_enc are the same");
    }

    /// Tests if `encrypt` returns a unique pair of encryption key and nonce values given the same inputs
    #[test]
    fn encrypt_unique_key_nonce () {
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        };

        // None aad
        let key = SecureBytes::new(vec![2u8;KEY_LEN + 5]);
        let plain = SecureBytes::new(Vec::from("plaintext"));

        let enc1 = match cp.encrypt(&key, None, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with None aad (enc1)")
        };

        let enc_key1 = match CryptoProvider::<SystemRandom>::recompute_hash(&key, enc1.get_key_salt(), KEY_LEN) {
            Ok(ek) => ek,
            Err(_) => panic!("unable to compute encryption key of enc1")
        };

        let enc2 = match cp.encrypt(&key, None, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with None aad (enc2)")
        };

        let enc_key2 = match CryptoProvider::<SystemRandom>::recompute_hash(&key, enc2.get_key_salt(), KEY_LEN) {
            Ok(ek) => ek,
            Err(_) => panic!("unable to compute encryption key of enc2")
        };

        assert!(
            (enc_key1 != enc_key2) || (enc1.get_enc_nonce() != enc2.get_enc_nonce()),
            "encryption process generates the same key-nonce pair 2 times (none aad)"
        );

        // some aad
        let aad = Some([1u8;10].as_slice());

        let enc3 = match cp.encrypt(&key, aad, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with Some aad (enc3)")
        };

        let enc_key3 = match CryptoProvider::<SystemRandom>::recompute_hash(&key, enc3.get_key_salt(), KEY_LEN) {
            Ok(ek) => ek,
            Err(_) => panic!("unable to compute encryption key of enc3")
        };

        let enc4 = match cp.encrypt(&key, aad, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with Some aad (enc4)")
        };

        let enc_key4 = match CryptoProvider::<SystemRandom>::recompute_hash(&key, enc4.get_key_salt(), KEY_LEN) {
            Ok(ek) => ek,
            Err(_) => panic!("unable to compute encryption key of enc4")
        };

        assert!(
            (enc_key3 != enc_key4) || (enc3.get_enc_nonce() != enc4.get_enc_nonce()),
            "encryption process generate the same key-nonce pair 2 times (some aad)"
        );
    }

    /// Tests if `encrypt` updates `CryptoProvider` field `old_nonces` properly after using for the
    /// first time a nonce, that is adding a new entry in the hasmap having the nonce as key and 
    /// an `HashVal` of the encryption key as value
    #[test]
    fn encrypt_new_nonce () {
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        };

        assert!(cp.old_nonces.is_empty(), "old_nonces is not initialized");

        // None aad
        let key = SecureBytes::new(vec![2u8;KEY_LEN + 5]);
        let plain = SecureBytes::new(Vec::from("plaintext"));


        let enc = match cp.encrypt(&key, None, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with None aad)")
        };

        let enc_key = match CryptoProvider::<SystemRandom>::recompute_hash(&key, enc.get_key_salt(), KEY_LEN) {
            Ok(ek) => ek, 
            Err(_) => panic!("unable to compute encryption key (enc_key)")
        };

        match cp.old_nonces.get(enc.get_enc_nonce()) {
            Some(key_vec) => {
                assert_eq!(key_vec.len(), 1, "key_vec does not contain a single value (None aad)");

                assert_eq!(
                    key_vec[0].get_hash(),
                    &CryptoProvider::<SystemRandom>::recompute_hash(
                        &enc_key, 
                        key_vec[0].get_salt(), 
                        key_vec[0].get_hash().unsecure().len()
                    ).unwrap(),
                    "enc_key does not correspond to its hash (None aad)"
                );

            },
            None => panic!("no key_vec for a used nonce value (None aad)")
        };

        // some aad
        cp.old_nonces = HashMap::new();
        let aad = Some([3u8;10].as_slice());

        let enc2 = match cp.encrypt(&key, aad, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with Some aad (enc2)")
        };

        let enc_key2 = match CryptoProvider::<SystemRandom>::recompute_hash(&key, enc2.get_key_salt(), KEY_LEN) {
            Ok(ek) => ek, 
            Err(_) => panic!("unable to compute encryption key (enc_key2)")
        };

        match cp.old_nonces.get(enc2.get_enc_nonce()) {
            Some(key_vec) => {
                assert_eq!(key_vec.len(), 1, "key_vec does not contain a single value (Some aad)");

                assert_eq!(
                    key_vec[0].get_hash(),
                    &CryptoProvider::<SystemRandom>::recompute_hash(
                        &enc_key2, 
                        key_vec[0].get_salt(), 
                        key_vec[0].get_hash().unsecure().len()
                    ).unwrap(),
                    "enc_key2 does not correspond to its hash"
                );

            },
            None => panic!("no key_vec for a used nonce value (some aad)")
        };
    }

    /// Tests if `encrypt` updates `CryptoProvider` field `old_nonces` properly after using again a
    /// nonce value with a new key, that is adding a new `HashVal` in the `Vec` related to the
    /// nonce value
    #[test]
    fn encrypt_same_nonce () {
        let fixed_byte = FixedByteRandom { byte: 1};
        let mut cp = match CryptoProvider::new_empty(fixed_byte) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        };

        assert!(cp.old_nonces.is_empty(), "old_nonces is not initialized");

        // None aad
        let key = SecureBytes::new(vec![2u8;KEY_LEN + 5]);
        let plain = SecureBytes::new(Vec::from("plaintext"));


        let enc = match cp.encrypt(&key, None, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with None aad (enc)")
        };

        let enc_key = match CryptoProvider::<SystemRandom>::recompute_hash(&key, enc.get_key_salt(), KEY_LEN) {
            Ok(ek) => ek, 
            Err(_) => panic!("unable to compute enc_key (none aad)")
        };

        let key2 = SecureBytes::new(vec![4u8;KEY_LEN]);
        let enc2 = match cp.encrypt(&key2, None, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with None aad (enc2)")
        };

        let enc_key2 = match CryptoProvider::<SystemRandom>::recompute_hash(&key2, enc2.get_key_salt(), KEY_LEN) {
            Ok(ek) => ek, 
            Err(_) => panic!("unable to compute enc_key2 (none aad)")
        };

        match cp.old_nonces.get(enc.get_enc_nonce()) {
            Some(key_vec) => {
                assert_eq!(key_vec.len(), 2, "key_vec does not contain 2 elements (none aad)");

                assert_eq!(
                    key_vec[0].get_hash(),
                    &CryptoProvider::<SystemRandom>::recompute_hash(
                        &enc_key, 
                        key_vec[0].get_salt(), 
                        key_vec[0].get_hash().unsecure().len()
                    ).unwrap(),
                    "enc_key2 does not correspond to its hash"
                );

                assert_eq!(
                    key_vec[1].get_hash(),
                    &CryptoProvider::<SystemRandom>::recompute_hash(
                        &enc_key2, 
                        key_vec[1].get_salt(), 
                        key_vec[1].get_hash().unsecure().len()
                    ).unwrap(),
                    "enc_key does not correspond to its hash"
                );

            },
            None => panic!("no key_vec for a used nonce value (none aad)")
        };

        // some aad
        cp.old_nonces = HashMap::new();
        let aad = Some([3u8;10].as_slice());

        let key3 = SecureBytes::new(vec![5u8; 45]);
        let enc3 = match cp.encrypt(&key3, aad, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with Some aad (enc3)")
        };

        let enc_key3 = match CryptoProvider::<SystemRandom>::recompute_hash(&key3, enc3.get_key_salt(), KEY_LEN) {
            Ok(ek) => ek, 
            Err(_) => panic!("unable to compute enc_key3 (some aad)")
        };

        let key4 = SecureBytes::new(vec![6u8;35]);
        let enc4 = match cp.encrypt(&key4, None, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with Some aad (enc4)")
        };

        let enc_key4 = match CryptoProvider::<SystemRandom>::recompute_hash(&key4, enc4.get_key_salt(), KEY_LEN) {
            Ok(ek) => ek, 
            Err(_) => panic!("unable to compute enc_key4 (none aad)")
        };

        match cp.old_nonces.get(enc3.get_enc_nonce()) {
            Some(key_vec) => {
                assert_eq!(key_vec.len(), 2, "key_vec does not contain 2 elements (Some aad)");

                assert_eq!(
                    key_vec[0].get_hash(),
                    &CryptoProvider::<SystemRandom>::recompute_hash(
                        &enc_key3, 
                        key_vec[0].get_salt(), 
                        key_vec[0].get_hash().unsecure().len()
                    ).unwrap(),
                    "enc_key3 does not correspond to its hash"
                );

                assert_eq!(
                    key_vec[1].get_hash(),
                    &CryptoProvider::<SystemRandom>::recompute_hash(
                        &enc_key4, 
                        key_vec[1].get_salt(), 
                        key_vec[1].get_hash().unsecure().len()
                    ).unwrap(),
                    "enc_key4 does not correspond to its hash"
                );

            },
            None => panic!("no key_vec for a used nonce value (Some aad)")
        };
    }


    /// Tests if `encrypt` updates `CryptoProvider` field `old_nonces` properly after using again a
    /// nonce value with the same key, that is regenerating a new nonce value until it has never
    /// been used with that key
    #[test]
    fn encrypt_regen_nonce () {
        let salt_filler = [1u8; SALT_LEN];
        let nonce1 = [2u8; NONCE_LEN];
        let nonce2 = [3u8; NONCE_LEN];
        let fixed_byte = FixedSliceSequenceRandom {
            bytes: &[
                // none aad
                &salt_filler, &salt_filler, &nonce1, &salt_filler, &salt_filler, &salt_filler, &salt_filler, &nonce1, &nonce2, &salt_filler, &salt_filler,
                // some aad
                &salt_filler, &salt_filler, &nonce1, &salt_filler, &salt_filler, &salt_filler, &salt_filler, &nonce1, &nonce2, &salt_filler, &salt_filler],
            current: UnsafeCell::new(0)
        };
        let mut cp = match CryptoProvider::new_empty(fixed_byte) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        };

        assert!(cp.old_nonces.is_empty(), "old_nonces is not initialized");

        // None aad
        let key = SecureBytes::new(vec![2u8;KEY_LEN + 5]);
        let plain = SecureBytes::new(Vec::from("plaintext"));


        let enc = match cp.encrypt(&key, None, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with None aad (enc)")
        };

        // erasing old_salts
        cp.old_salts = HashMap::new();

        let enc2 = match cp.encrypt(&key, None, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with None aad (enc2)")
        };

        assert_ne!(enc2.get_enc_nonce(), enc.get_enc_nonce());

        // Some aad

        // erasing old salts and nonces
        cp.old_nonces = HashMap::new();
        cp.old_salts = HashMap::new();

        let aad = Some([7u8;40].as_slice());
        let key = SecureBytes::new(vec![2u8;KEY_LEN + 5]);
        let plain = SecureBytes::new(Vec::from("plaintext"));


        let enc = match cp.encrypt(&key, aad, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with None aad (enc)")
        };

        // erasing old_salts
        cp.old_salts = HashMap::new();

        let enc2 = match cp.encrypt(&key, aad, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to perform encryption with None aad (enc2)")
        };

        assert_ne!(enc2.get_enc_nonce(), enc.get_enc_nonce());
    }
    
    // ]]]

    // decrypt [[[ 
    /// Tests if `decrypt` returns an error when the key is empty
    #[test]
    fn decrypt_empty_key() {
        let key = SecureBytes::new(Vec::new());
        let key_salt = [1u8; SALT_LEN];
        let aad = None;
        let nonce = [2u8; NONCE_LEN];
        let enc = SecureBytes::new(Vec::from("ciphertext"));

        match CryptoProvider::<SystemRandom>::decrypt(&key, &key_salt, aad, &nonce, &enc) {
            Ok(_) => panic!("no error with an empty key"),
            Err(_) => {}
        }
    }

    /// Tests if `decrypt` returns an error when the aad is Some(a) and a is empty
    #[test]
    fn decrypt_empty_some_aad() {
        let key = SecureBytes::new(Vec::from("key"));
        let key_salt = [1u8; SALT_LEN];
        let aad = Some([].as_slice());
        let nonce = [2u8; NONCE_LEN];
        let enc = SecureBytes::new(Vec::from("ciphertext"));

        match CryptoProvider::<SystemRandom>::decrypt(&key, &key_salt, aad, &nonce, &enc) {
            Ok(_) => panic!("no error with an empty aad"),
            Err(_) => {}
        }
    }

    /// Tests if `decrypt` returns an error when the ciphertext is empty
    #[test]
    fn decrypt_empty_plain() {
        let key = SecureBytes::new(Vec::from("key"));
        let key_salt = [1u8; SALT_LEN];
        let aad = None;
        let nonce = [2u8; NONCE_LEN];
        let enc = SecureBytes::new(Vec::new());

        match CryptoProvider::<SystemRandom>::decrypt(&key, &key_salt, aad, &nonce, &enc) {
            Ok(_) => panic!("no error with an empty ciphertext"),
            Err(_) => {}
        }
    }

    /// Tests that `decrypt` actually decrypts enc
    #[test]
    fn decrypt_ciphertext () {
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        };

        // None aad
        let key = SecureBytes::new(Vec::from("key"));
        let aad = None;
        let plain = SecureBytes::new(Vec::from("plaintext"));

        let enc = match cp.encrypt(&key, aad, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain (none aad)")
        };

        let plain_res = match CryptoProvider::<SystemRandom>::decrypt(&key, enc.get_key_salt(), aad, enc.get_enc_nonce(), enc.get_enc()) {
            Ok(pl) => pl,
            Err(_) => panic!("unable to decrypt enc (none aad)")
        };

        assert_eq!(plain, plain_res, "decrypted plaintext does not correspond to original plaintext (none aad)");

        // Some aad
        let aad = Some([2u8;35].as_slice());

        let enc2 = match cp.encrypt(&key, aad, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain (some aad)")
        };

        let plain_res2 = match CryptoProvider::<SystemRandom>::decrypt(&key, enc2.get_key_salt(), aad, enc2.get_enc_nonce(), enc2.get_enc()) {
            Ok(pl) => pl,
            Err(_) => panic!("unable to decrypt enc (some aad)")
        };

        assert_eq!(plain, plain_res2, "decrypted plaintext does not correspond to original plaintext (some aad)");

    }

    /// Tests if `decrypt` returns the same output given the same inputs
    #[test]
    fn decrypt_same_out () {
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        };

        // None aad
        let key = SecureBytes::new(Vec::from("key"));
        let aad = None;
        let plain = SecureBytes::new(Vec::from("plaintext"));

        let enc = match cp.encrypt(&key, aad, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain (none aad)")
        };

        let plain_res = match CryptoProvider::<SystemRandom>::decrypt(&key, enc.get_key_salt(), aad, enc.get_enc_nonce(), enc.get_enc()) {
            Ok(pl) => pl,
            Err(_) => panic!("unable to decrypt enc the first time (none aad)")
        };
        
        let plain_res2 = match CryptoProvider::<SystemRandom>::decrypt(&key, enc.get_key_salt(), aad, enc.get_enc_nonce(), enc.get_enc()) {
            Ok(pl) => pl,
            Err(_) => panic!("unable to decrypt enc the second time (none aad)")
        };

        assert_eq!(plain_res, plain_res2, "decrypt returns two different plaintext with the same inputs (none aad)");

        // Some aad
        let aad2 = Some([2u8;35].as_slice());

        let enc2 = match cp.encrypt(&key, aad2, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain (some aad)")
        };

        let plain_res3 = match CryptoProvider::<SystemRandom>::decrypt(&key, enc2.get_key_salt(), aad2, enc2.get_enc_nonce(), enc2.get_enc()) {
            Ok(pl) => pl,
            Err(_) => panic!("unable to decrypt enc the first time (some aad)")
        };
        
        let plain_res4 = match CryptoProvider::<SystemRandom>::decrypt(&key, enc2.get_key_salt(), aad2, enc2.get_enc_nonce(), enc2.get_enc()) {
            Ok(pl) => pl,
            Err(_) => panic!("unable to decrypt enc the second time (some aad)")
        };

        assert_eq!(plain_res3, plain_res4, "decrypt returns two different plaintext with the same inputs (some aad)");

    }

    /// Tests if `decrypt` returns an error given the same inputs but the key
    #[test]
    fn decrypt_diff_key () {
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        };

        // None aad
        let key = SecureBytes::new(Vec::from("key"));
        let key2 = SecureBytes::new(Vec::from("another_key"));
        let aad = None;
        let plain = SecureBytes::new(Vec::from("plaintext"));

        let enc = match cp.encrypt(&key, aad, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain (none aad)")
        };

        match CryptoProvider::<SystemRandom>::decrypt(&key2, enc.get_key_salt(), aad, enc.get_enc_nonce(), enc.get_enc()) {
            Ok(_) => panic!("no error with the wrong key (none aad)"),
            Err(_) => {}
        };

        // Some aad
        let aad2 = Some([2u8;35].as_slice());

        let enc2 = match cp.encrypt(&key, aad2, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain (none aad)")
        };

        match CryptoProvider::<SystemRandom>::decrypt(&key2, enc2.get_key_salt(), aad2, enc2.get_enc_nonce(), enc2.get_enc()) {
            Ok(_) => panic!("no error with the wrong key (some aad)"),
            Err(_) => {}
        };

    }

    /// Tests if `decrypt` returns an error given the same inputs but the key salt
    #[test]
    fn decrypt_diff_key_salt () {
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        };

        // None aad
        let key = SecureBytes::new(Vec::from("key"));
        let aad = None;
        let plain = SecureBytes::new(Vec::from("plaintext"));

        let enc = match cp.encrypt(&key, aad, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain (none aad)")
        };

        let mut wrong_salt = [10u8; SALT_LEN];

        while &wrong_salt == enc.get_key_salt() {
            wrong_salt = match cp.rng.generate_salt() {
                Ok(s) => s,
                Err(_) => panic!("unable to generate a salt value (none aad)")
            }
        };

        match CryptoProvider::<SystemRandom>::decrypt(&key, &wrong_salt, aad, enc.get_enc_nonce(), enc.get_enc()) {
            Ok(_) => panic!("no error with the wrong salt (none aad)"),
            Err(_) => {}
        };

        // Some aad
        let aad2 = Some([2u8;35].as_slice());

        let enc2 = match cp.encrypt(&key, aad2, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain (none aad)")
        };

        let mut wrong_salt2 = [10u8; SALT_LEN];

        while &wrong_salt2 == enc.get_key_salt() {
            wrong_salt2 = match cp.rng.generate_salt() {
                Ok(s) => s,
                Err(_) => panic!("unable to generate a salt value (some aad)")
            };
        }

        match CryptoProvider::<SystemRandom>::decrypt(&key, &wrong_salt2, aad2, enc2.get_enc_nonce(), enc2.get_enc()) {
            Ok(_) => panic!("no error with the wrong salt (some aad)"),
            Err(_) => {}
        };

    }

    /// Tests if `decrypt` returns an error given the same inputs but the aad
    #[test]
    fn decrypt_diff_aad () {
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        };

        // None aad
        let key = SecureBytes::new(Vec::from("key"));
        let aad1 = Some([1u8;10].as_slice());
        let aad2 = Some([1u8;20].as_slice());
        let aad3 = Some([2u8;10].as_slice());
        let aad4 = None;
        let plain = SecureBytes::new(Vec::from("plaintext"));

        let enc = match cp.encrypt(&key, aad1, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain (enc)")
        };

        match CryptoProvider::<SystemRandom>::decrypt(&key, enc.get_key_salt(), aad2, enc.get_enc_nonce(), enc.get_enc()) {
            Ok(_) => panic!("no error with the wrong aad (aad2)"),
            Err(_) => {}
        };

        match CryptoProvider::<SystemRandom>::decrypt(&key, enc.get_key_salt(), aad3, enc.get_enc_nonce(), enc.get_enc()) {
            Ok(_) => panic!("no error with the wrong aad (aad3)"),
            Err(_) => {}
        };

        match CryptoProvider::<SystemRandom>::decrypt(&key, enc.get_key_salt(), aad4, enc.get_enc_nonce(), enc.get_enc()) {
            Ok(_) => panic!("no error with the wrong aad (aad4)"),
            Err(_) => {}
        };

        let enc2 = match cp.encrypt(&key, aad2, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain (enc2)")
        };

        match CryptoProvider::<SystemRandom>::decrypt(&key, enc2.get_key_salt(), aad1, enc2.get_enc_nonce(), enc2.get_enc()) {
            Ok(_) => panic!("no error with the wrong aad (aad1)"),
            Err(_) => {}
        };

    }

    /// Tests if `decrypt` returns an error given the same inputs but the nonce
    #[test]
    fn decrypt_diff_nonce () {
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        };

        // None aad
        let key = SecureBytes::new(Vec::from("key"));
        let aad = None;
        let plain = SecureBytes::new(Vec::from("plaintext"));

        let enc = match cp.encrypt(&key, aad, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain (none aad)")
        };

        let mut wrong_nonce = [3u8; NONCE_LEN]; while &wrong_nonce == enc.get_enc_nonce() {
            wrong_nonce = match cp.rng.generate_nonce() {
                Ok(n) => n,
                Err(_) => panic!("unable to generate a new nonce (none aad)")
            };
        }

        match CryptoProvider::<SystemRandom>::decrypt(&key, enc.get_key_salt(), aad, &wrong_nonce, enc.get_enc()) {
            Ok(_) => panic!("no error with the wrong nonce (none aad)"),
            Err(_) => {}
        };

        // Some aad
        let aad2 = Some([2u8;35].as_slice());

        let enc2 = match cp.encrypt(&key, aad2, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain (none aad)")
        };

        let mut wrong_nonce2 = [3u8; NONCE_LEN];

        while &wrong_nonce2 == enc.get_enc_nonce() {
            wrong_nonce2 = match cp.rng.generate_nonce() {
                Ok(n) => n,
                Err(_) => panic!("unable to generate a new nonce (some aad)")
            };
        }

        match CryptoProvider::<SystemRandom>::decrypt(&key, enc2.get_key_salt(), aad2, &wrong_nonce2, enc2.get_enc()) {
            Ok(_) => panic!("no error with the wrong nonce (some aad)"),
            Err(_) => {}
        };

    }

    /// Tests if `decrypt` returns an error given the same inputs but the ciphertext
    #[test]
    fn decrypt_diff_cipher () {
        let mut cp = match CryptoProvider::new_empty(SystemRandom::new()) {
            Ok(cp) => cp,
            Err(_) => panic!("unable to create CryptoProvider")
        };

        // None aad
        let key = SecureBytes::new(Vec::from("key"));
        let aad = None;
        let plain = SecureBytes::new(Vec::from("plaintext"));
        let wrong_enc = SecureBytes::new(Vec::from("enc"));

        let enc = match cp.encrypt(&key, aad, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain (none aad)")
        };

        match CryptoProvider::<SystemRandom>::decrypt(&key, enc.get_key_salt(), aad, enc.get_enc_nonce(), &wrong_enc) {
            Ok(_) => panic!("no error with wrong ciphertext (none aad)"),
            Err(_) => {}
        };
        
        // Some aad
        let aad2 = Some([2u8;35].as_slice());

        let enc2 = match cp.encrypt(&key, aad2, &plain) {
            Ok(enc) => enc,
            Err(_) => panic!("unable to encrypt plain (some aad)")
        };

        match CryptoProvider::<SystemRandom>::decrypt(&key, enc2.get_key_salt(), aad, enc2.get_enc_nonce(), &wrong_enc) {
            Ok(_) => panic!("no error with wrong ciphertext (some aad)"),
            Err(_) => {}
        };
    }
    // ]]]
}

// ]]]
