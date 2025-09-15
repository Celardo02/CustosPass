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


pub  mod sym_enc {

    use aws_lc_rs::aead::{self, Aad, RandomizedNonceKey, Nonce, AES_256_GCM};
    use std::{convert, io};

    // Aes algorithm variant that will be used 
    const AES_ALG: &aead::Algorithm = &AES_256_GCM;
    // lenght of the aes key in bytes
    const KEY_LEN: usize = 32;

    pub trait SymmetricEnc {
        fn encrypt<T> (&self, key: [u8; KEY_LEN], aad: Aad<T>, plain: Vec<u8> ) -> Result<Vec<u8>, io::Error> 
            where
                T: convert::AsRef<[u8]>;
        fn decrypt<T> (&self, key: [u8; KEY_LEN], aad: Aad<T>, enc: Vec<u8>) -> Result<Vec<u8>, io::Error>
            where
                T: convert::AsRef<[u8]>;
        fn get_old_nonces(&self) -> Vec<Nonce>;
    }

    pub struct SymEncProvider {
        old_nonces: Vec<Nonce>
    }

    impl SymmetricEnc for SymEncProvider {

        fn encrypt<T> (&self, key: [u8; KEY_LEN], aad: Aad<T>, plain: Vec<u8> ) -> Result<Vec<u8>, io::Error> 
            where
                T: convert::AsRef<[u8]>{
            unimplemented!();
        }

        fn decrypt<T> (&self, key: [u8; KEY_LEN], aad: Aad<T>, enc: Vec<u8>) -> Result<Vec<u8>, io::Error>
            where
                T: convert::AsRef<[u8]> {
            unimplemented!();
        }
        fn get_old_nonces(&self) -> Vec<Nonce> {
            unimplemented!();
        }

    }
}
