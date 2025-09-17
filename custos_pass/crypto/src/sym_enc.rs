//! # sym_enc
//!
//! This module provides symmetric encryption capabilities through a stateful
//! structure that ensures security. 
//!
//! # Security Considerations
//!
//! Current implementation is based on AES GCM algorithm provided by aws-ls-rc with FIPS 
//! compliance feature enabled. 
//!
//! Nonce reuse is prevented by the module implementation. 


use aws_lc_rs::aead::{self, Aad, RandomizedNonceKey, Nonce, AES_256_GCM};
use crate::crypto_errors::{CryptoErr, CryptoErrOrigin, CryptoErrKind};
use secure_string::{SecureArray, SecureVec};

// Aes algorithm variant that will be used 
const AES_ALG: &aead::Algorithm = &AES_256_GCM;
// lenght of the aes key in bytes
pub const KEY_LEN: usize = 32;

// SymEncResult struct [[[

pub struct SymEncResult {
    output: SecureVec<u8>,
    nonce: Nonce
}

impl SymEncResult {
    pub fn new(output: SecureVec<u8>, nonce: Nonce) -> SymEncResult {
        SymEncResult {
            output,
            nonce
        }
    }

    pub fn get_output (&self) -> &SecureVec<u8> {
        &self.output
    }

    pub fn get_nonce (&self) -> &Nonce {
        &self.nonce
    }
}

// ]]]

// SymEncProvider [[[

pub struct SymEncProvider{
    // IMPORTANT: this struct must be changed with an hash map -> 
    //      key = hash of the key used in the encryption 
    //      value = associated nonce
    // all the struct methods must be changed accordingly
    old_nonces: Vec<Nonce>
}

impl SymEncProvider {
    pub fn new(old_nonces: Vec<Nonce>) -> SymEncProvider {
        SymEncProvider {
            old_nonces
        }
    }

    pub fn new_empty() -> SymEncProvider {
        SymEncProvider {
            old_nonces: Vec::new()
        }
    }


    fn contains_nonce(&self, nonce: &Nonce) -> bool {
        self.old_nonces.iter().any(|n| n.as_ref() == nonce.as_ref())
    }

    fn try_encrypt(&self, aes_key: &RandomizedNonceKey, plain: &SecureVec<u8>, aad: Aad<Vec<u8>>) -> Result<SymEncResult, CryptoErr> {
        let mut out = Vec::from(plain.unsecure());

        let nonce = aes_key.seal_in_place_append_tag(aad, &mut out)
            .map_err(|_| CryptoErr::new(CryptoErrKind::EncryptionFailed, CryptoErrOrigin::SymmetricEncryption, "aes encryption process failed"))?;

        Ok(SymEncResult::new(SecureVec::from(out), nonce))
    }

}

// ]]]

// SymmetricEnc trait [[[

pub trait SymmetricEnc {
    fn encrypt (&mut self, key: &SecureArray<u8, KEY_LEN>, aad: Aad<Vec<u8>>, plain: &SecureVec<u8> ) -> Result<SymEncResult, CryptoErr>;
    fn decrypt (&self, key: &SecureArray<u8, KEY_LEN>, aad: Aad<Vec<u8>>, enc: &SecureVec<u8>) -> Result<SecureVec<u8>, CryptoErr>;
    fn get_old_nonces(&self) -> &Vec<Nonce>;
}

impl SymmetricEnc for SymEncProvider {

    fn encrypt (&mut self, key: &SecureArray<u8, KEY_LEN>, aad: Aad<Vec<u8>>, plain: &SecureVec<u8> ) -> Result<SymEncResult, CryptoErr> {

        // checking whether plain text is empty or not
        if plain.unsecure().is_empty() { 
            return Err(CryptoErr::new(CryptoErrKind::InpuNullOrEmpty, CryptoErrOrigin::SymmetricEncryption, "plain text is empty"));
        }

        // IMPORTANT: kdf function output must be used instead of key.unsecure()
        let aes_key = RandomizedNonceKey::new(AES_ALG, key.unsecure())
            .map_err(|_| CryptoErr::new(CryptoErrKind::AesKeyGenFailed, CryptoErrOrigin::SymmetricEncryption, "aes key generation process failed"))?;

        let mut res = self.try_encrypt(&aes_key, &plain, Aad::from(Vec::from(aad.as_ref())))?;

        // if the nonce has already been used, the encryption process is repeated.
        // Even though this is really inefficient in theory, the probability that a specific 
        // nonce has already been used for a specificy derived key value is almost impossible, 
        // hence this implementation compromise between code readability and efficiency
        while self.contains_nonce(&res.get_nonce()) {
            res = self.try_encrypt(&aes_key, &plain, Aad::from(Vec::from(aad.as_ref())))?;
        }
            
        self.old_nonces.push(Nonce::from(res.get_nonce().as_ref()));

        Ok(res)
    }

    fn decrypt (&self, key: &SecureArray<u8, KEY_LEN>, aad: Aad<Vec<u8>>, enc: &SecureVec<u8>) -> Result<SecureVec<u8>, CryptoErr>{
        unimplemented!();
    }

    fn get_old_nonces (&self) -> &Vec<Nonce> {
        &self.old_nonces
    }

}

// ]]]
