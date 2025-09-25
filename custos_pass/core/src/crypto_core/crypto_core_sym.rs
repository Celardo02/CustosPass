//! # Crypto Core Sym 
//!
//! This submodule provides symmetric encryption capabilities to `CryptoProvider`.

use super::{
    crypto_core_hashing::CryptoCoreHashing,
    sym_enc_res::SymEncRes,
    CryptoErr, CryptoProvider, NONCE_LEN, SALT_LEN, SHA512_OUTPUT_LEN, SecureBytes
};

use crypto::{
    rng::RandomNumberGenerator,
    sym_enc::{KEY_LEN, SymmetricEnc, SymEncProvider}
};


pub trait CryptoCoreSymEnc{
    /// Encrypts `plain` using `key` and including `aad` in the process.
    ///
    /// # Security Note
    ///
    /// `key` is not directly used as encryption key; the output of `compute_hash` in
    /// `CryptoProvider` applied to it is used instead.
    ///
    /// # Parameters
    ///
    /// - `key`: encryption key. Key must be `KEY_LEN` long
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
    /// - `key_salt`: salt used to derive a key from `key`
    /// - `aad`: additional authenticated data used in the encryption process of `enc`
    /// - `nonce`: nonce used in the encryption process of `enc`
    /// - `enc`: chipertext. It must __NOT__ be empty
    ///
    /// # Returns
    ///
    /// Returns a `SecureBytes` containig the plaintext if no error occurs, `CryptoErr` otherwise.
    fn decrypt (
        &self,
        key: &SecureBytes,
        key_salt: &[u8; SALT_LEN],
        aad: Option<&[u8]>,
        nonce: &[u8; NONCE_LEN],
        enc: &SecureBytes
    ) -> Result<SecureBytes, CryptoErr>;
}

impl CryptoCoreSymEnc for CryptoProvider {
    fn encrypt (
        &mut self,
        key: &SecureBytes,
        aad: Option<&[u8]>,
        plain: &SecureBytes 
    ) -> Result<SymEncRes, CryptoErr> {

        check_inputs(key, aad, plain)?;

        let enc_key = self.compute_hash(key, KEY_LEN)?;

        let mut nonce = self.rng.generate_nonce()?;
        
        // checking whether the nonce has already been used at all.
        if let Some(key_vec) = self.old_nonces.get(&nonce) {
            let mut used_nonce = true;
            while used_nonce {
                used_nonce = false;

                // checking whether enc_key has already been used with the current nonce value or not
                for k in key_vec { 
                    match CryptoProvider::verify_hash(enc_key.get_hash(), k.get_salt(), k.get_hash()) {
                        Ok(true) => {
                            // nonce has already been used with current nonce value
                            used_nonce = true;
                            nonce = self.rng.generate_nonce()?; 
                            // quitting the loop as no more old keys can match the current one
                            break;
                        },
                        Ok(false) => (),
                        Err(ce) => return Err(ce)
                    }
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
        &self,
        key: &SecureBytes,
        key_salt: &[u8; SALT_LEN],
        aad: Option<&[u8]>,
        nonce: &[u8; NONCE_LEN],
        enc: &SecureBytes
    ) -> Result<SecureBytes, CryptoErr> {

        check_inputs(key, aad, enc)?;

        let enc_key = CryptoProvider::recompute_hash(key, key_salt, KEY_LEN);

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
/// - `bytes`: plaintext/chipertext
///
/// # Returns 
///
/// Returns () if:
/// - `key` is `KEY_LEN` long
/// - `aad` is `None` or `Some(a)` and `a` is not empty
/// - `bytes` is not empty
/// `CryptoErr` is returned otherwise.
fn check_inputs(key: &SecureBytes, aad: Option<&[u8]>, bytes: &SecureBytes) -> Result<(), CryptoErr> {
    let mut res = Ok(());

    if key.unsecure().len() != KEY_LEN || bytes.unsecure().is_empty() {
        res = Err(CryptoErr);
    }

    if let Some(a) = aad && a.is_empty() {
        res = Err(CryptoErr);
    }

    res
}
