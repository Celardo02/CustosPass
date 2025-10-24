//! # Credential Sets Persistence
//!
//! This module provides the persistence logic to store vault credential sets.


use chrono::Utc;
use crypto::SecureBytes;
use domain::cred_set::CredSet;
use error::{Err, ErrSrc};
use avl::AvlTreeMap;

// PersCredSet [[[

/// Provides credential sets persistence behavior.
pub trait PersCredSet<C: CredSet> {
    /// Stores a new credential set in the storage layer.
    ///
    /// # Parameters
    ///
    /// - `cred_set`: credential set
    ///
    /// # Returns
    ///
    /// Returns `()` the id of `cred_set` is unique, `Err` otherwise
    fn create(cred_set: C) -> Result<(), Err>;

    /// Searches a credential set with the given id.
    ///
    /// # Parameters 
    ///
    /// - `id`: credential set id
    ///
    /// # Returns
    ///
    /// Returns the searched credential set if exists; `None` otherwise.
    fn read_id(id: &String) -> Option<&C>;

    /// Searches all the credential sets that contain the given string within their id or username.
    ///
    /// # Parameters 
    ///
    /// - `text`: text to search
    ///
    /// # Returns
    ///
    /// Returns a `Vec` of credential sets that contain `text` in their id or username if they
    /// exist; `None` otherwise.
    fn read_text(text: &String) -> Option<Vec<&C>>;

    /// Updates a credential set with the given id.
    ///
    /// # Parameters
    ///
    /// - `id`: id of the credential set that needs to be updated
    /// - `cred_set`: updated credential set
    ///
    /// # Returns 
    ///
    /// Returns `()` if a credential set with the given id exists and the id in `cred_set` is
    /// unique, `Err` otherwise.
    fn update(id: &String, cred_set: C) -> Result<(), Err>;

    /// Deletes a credential set with the given id.
    ///
    /// # Parameters
    ///
    /// - `id`: id of the credential set to be deleted
    ///
    /// # Returns
    ///
    /// Returns `()` if a credential set with the given id exists, `Err` otherwise.
    fn delete(id: &String) -> Result<(), Err>;

    /// Returns all the credential sets in the storage layer if they exist.
    fn list_all() -> Option<Vec<C>>;

    /// Returns all the expired credential sets if they exist.
    fn check_expired() -> Option<Vec<C>>;

    /// Returns all the non-expiring credential sets if they exist.
    fn check_non_expiring() -> Option<Vec<C>>;
}

// ]]]

// CredStorage [[[


/// Provides credential sets storage functionality.
///
/// # Security Note
///
/// Only one instance of this struct must be created at a time. Not doing so may lead to security
/// issues.
pub struct CredStorage <C: CredSet> {
    /// `Vec` containing credential sets. All the elements must be scanned each time for searches 
    /// as support for finding a string that is not at the beginning of a credential set field 
    /// must be ensured
    cs_vec: Vec<C>,
    /// Avl tree containing a copy of all credential sets keys associated with their index in 
    /// `cs_vec`. This field is used to optimize delete and update operations.
    cs_tree: AvlTreeMap<String, usize>
}


impl <C: CredSet> CredStorage<C> {
    /// Creates an instance of `CredStorage`.
    ///
    /// # Parameters
    ///
    /// - `cred_set`: vector of credential sets. If it is set to `None`, 
    ///     the persistence layer is assumed to be empty and a new `Vec` is created
    pub fn new(cred_sets: Option<Vec<C>>) -> Self {
        let cs_vec;

        if let Some(creds) = cred_sets {
            cs_vec = creds;
        } else {
            cs_vec = Vec::new();
        }

        // unwrap is used as the constant must always be a valid value
        let mut cs_tree = AvlTreeMap::new();

        // init of the avl tree
        for (index, cred) in cs_vec.iter().enumerate() {
            cs_tree.insert(cred.get_id().clone(), index);
        }

        Self{
            cs_vec,
            cs_tree
        }
    }
}
// ]]]

// PersCredSet for CredStorage [[[

impl <C: CredSet> PersCredSet<C> for CredStorage<C> {
    fn create(cred_set: C) -> Result<(), Err>{
        unimplemented!();
    }

    fn read_id(id: &String) -> Option<&C>{
        unimplemented!();
    }


    fn read_text(text: &String) -> Option<Vec<&C>>{
        unimplemented!();
    }


    fn update(id: &String, cred_set: C) -> Result<(), Err>{
        unimplemented!();
    }

    fn delete(id: &String) -> Result<(), Err>{
        unimplemented!();
    }

    fn list_all() -> Option<Vec<C>>{
        unimplemented!();
    }

    fn check_expired() -> Option<Vec<C>>{
        unimplemented!();
    }

    fn check_non_expiring() -> Option<Vec<C>>{
        unimplemented!();
    }


}

// ]]]
