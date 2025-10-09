//! # Credential Sets Persistence
//!
//! This module provides the persistence logic to store vault credential sets.


use chrono::Utc;
use crypto::SecureBytes;
use domain::cred_set::CredSet;
use error::{Err, ErrSrc};

// PersCredSet [[[
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
pub struct CredStorage {
}
// ]]]
