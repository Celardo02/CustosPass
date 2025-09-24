//! # Crypto Core Hashing 
//!
//! This submodule provides hashing capabilities to `CryptoProvider`.

use super::{
    CryptoErr, CryptoProvider, OldKey, SecureBytes, 
    Hash,hashing_res::HashingRes, HashMap, HashProvider, SALT_LEN, SHA512_OUTPUT_LEN,
    RandomNumberGenerator, Rng
};

/// Define the hashing behavior offered by `core_crypto` module.
pub trait CryptoCoreHashing {

    /// Computes the hash for `key` and stores the output in `out`.
    ///
    /// # Parameters
    /// - `key`: input key to derive the hash from 
    /// - `out_len`: required output hash length
    ///
    /// # Returns
    ///
    /// Returns `HashingRes` or `CryptoErr` if any error occurs.
    fn compute_hash(&mut self, key: &SecureBytes, out_len: usize) -> Result<HashingRes, CryptoErr>;
    
    /// Verifies whether the hash of a provided key matches a previously derived one.
    ///
    /// # Parameters 
    ///
    /// - `new_key`: newly provided key to be hashed
    /// - `salt`: value used to salt `new_key`
    /// - `old_key`: previously derived key hash
    /// 
    /// # Returns
    ///
    /// Returns `true` if the hashes match, `false` otherwise.
    fn verify_hash( new_key: &SecureBytes, salt: &[u8; SALT_LEN],  old_key: &SecureBytes) -> bool;

    /// Returns all previously used keys for each salt.
    fn get_old_salts(&self) -> &HashMap<[u8;SALT_LEN], Vec<OldKey>>;
}

impl CryptoCoreHashing for CryptoProvider {
    fn compute_hash(&mut self, key: &SecureBytes, out_len: usize) -> Result<HashingRes, CryptoErr> {
        let mut salt = self.rng.generate_salt()?; 

        // checking whether the salt has already been used at all. Then, whether it has already
        // been used with key argument.
        while let Some(key_vec) = self.old_salts.get(&salt) 
            && key_vec.iter().any(|k| CryptoProvider::verify_hash(
                        &HashProvider::derive_hash(key, &salt, SHA512_OUTPUT_LEN), 
                        k.get_salt(), 
                        k.get_hash()
            )
        ) {
            salt = self.rng.generate_salt()?; 
        }

        let out = HashProvider::derive_hash(key, &salt, out_len);

        // computing the hash of out to avoid salt reuse in the future

        let salt_old = self.rng.generate_salt()?;
        // NOTE: the length of hash_old MUST be the same used as parameter in the derive associated
        // function called in the while loop
        let hash_old = HashProvider::derive_hash(&out, &salt_old, SHA512_OUTPUT_LEN);
        let old_k = OldKey::new(hash_old, salt_old);

        self.old_salts.entry(salt)
            // as is less likely to get the same salt twice than getting a new one, clone method 
            // is invoked here instead of or_insert
            .and_modify(|key_vec| key_vec.push(old_k.clone()))
            .or_insert(vec![old_k]);

        Ok(HashingRes::new(out, salt))
    }

    fn verify_hash(new_key: &SecureBytes, salt: &[u8; SALT_LEN],  old_key: &SecureBytes) -> bool {
        HashProvider::verify_hash(new_key, salt, old_key)
    }

    fn get_old_salts(&self) -> &HashMap<[u8;SALT_LEN], Vec<OldKey>> {
        &self.old_salts
    }
}
