use crypto::{hash::{Hash, HashProvider, SALT_LEN, SHA512_OUTPUT_LEN},SecureBytes, Unspecified};
use std::collections::HashMap;

// OldKey struct [[[

/// Represents an already used key.
#[derive(Clone, Debug)]
pub struct OldKey {
    /// Hash of the key.
    hash: SecureBytes,
    /// Value used to salt `hash`.
    salt: [u8; SALT_LEN]
}

impl OldKey {
    /// Creates a new instance of `OldKey` with the hash of the key and the value used to salt it.
    pub fn new(hash: SecureBytes, salt: [u8; SALT_LEN]) -> Self {
        OldKey {
            hash,
            salt
        }
    }

    /// Returns the key hash.
    pub fn get_hash(&self) -> &SecureBytes {
        &self.hash
    }

    /// Returns the hash salt
    pub fn get_salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }
}
// ]]]

/// Provides cryptographic capabilities.
///
/// # Security Note
///
/// Only __one instance__ of this class must be created at a time to guarantee salt and nonce 
/// reuse prevention.
pub struct CryptoProvider {
    hash: HashProvider,

    /// Hash map storing all the keys that have ever been used for each salt value in the 
    /// key derivation function.
    old_salts: HashMap<[u8;SALT_LEN], Vec<OldKey>>,
}

impl CryptoProvider {
    /// Initialize a new instance of CryptoProvider.
    pub fn new_empty() -> Self {
        CryptoProvider { 
            hash: HashProvider::new(),

            old_salts: HashMap::new()
        }
    }


    /// Initialize a new instance of `CryptoProvider` with an existing `old_salts` hash map.
    pub fn new(old_salts: HashMap<[u8;SALT_LEN], Vec<OldKey>>) -> Self {
        CryptoProvider {
            hash: HashProvider::new(),

            old_salts
        }
    }
}

// CoreCryptoHashing [[[

/// Define the hashing behavior offered by `core_crypto` module
pub trait CoreCryptoHashing {

    /// Computes the hash for `key` and stores the output in `out`.
    ///
    /// # Parameters
    /// - `key`: input key to derive the hash from 
    /// - `out`: output hash
    /// - `out_len`: output hash length
    ///
    /// # Returns
    ///
    /// Returns the value used to salt `out` or `Unspecified` if any error occurs.
    fn compute_hash(&mut self, key: &SecureBytes, out: &mut SecureBytes, out_len: usize) -> Result<[u8; SALT_LEN], Unspecified>;
    
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

impl CoreCryptoHashing for CryptoProvider {
    fn compute_hash(&mut self, key: &SecureBytes, out: &mut SecureBytes, out_len: usize) -> Result<[u8; SALT_LEN], Unspecified> {
        let mut salt = self.hash.generate_salt()?; 

        // checking whether the salt has already been used at all. Then, whether it has already
        // been used with key argument.
        //
        // In both cases, the salt is regenerated
        while let Some(key_vec) = self.old_salts.get(&salt) 
            && key_vec.iter().any(|k| CryptoProvider::verify_hash(
                        &HashProvider::derive_hash(key, &salt, SHA512_OUTPUT_LEN), 
                        k.get_salt(), 
                        k.get_hash()
            )
        ) {
            salt = self.hash.generate_salt()?; 
        }

        let salt_old = self.hash.generate_salt()?;
        // NOTE: the length of hash_old MUST be the same used as parameter in the derive associated
        // function called in the while loop
        let hash_old = HashProvider::derive_hash(out, &salt_old, SHA512_OUTPUT_LEN);
        let old_k = OldKey::new(hash_old, salt_old);

        self.old_salts.entry(salt)
            // as is less likely to get the same salt twice than getting a new one, clone method 
            // is invoked here instead of or_insert
            .and_modify(|key_vec| key_vec.push(old_k.clone()))
            .or_insert(vec![old_k]);

        *out = HashProvider::derive_hash(key, &salt, out_len);

        Ok(salt)
    }

    fn verify_hash(new_key: &SecureBytes, salt: &[u8; SALT_LEN],  old_key: &SecureBytes) -> bool {
        HashProvider::verify_hash(new_key, salt, old_key)
    }

    fn get_old_salts(&self) -> &HashMap<[u8;SALT_LEN], Vec<OldKey>> {
        &self.old_salts
    }
}
// ]]]
