//! # Credential Sets Persistence
//!
//! This module provides the persistence logic to store vault credential sets.


use chrono::Utc;
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
    /// Returns `()` if the id of `cred_set` is unique, `Err` otherwise
    fn create(&mut self, cred_set: C) -> Result<(), Err>;

    /// Searches a credential set with the given id.
    ///
    /// # Parameters 
    ///
    /// - `id`: credential set id
    ///
    /// # Returns
    ///
    /// Returns the searched credential set if exists; `None` otherwise.
    fn read_id(&self, id: &String) -> Option<&C>;

    /// Searches all the credential sets that contain the given string within their id, username 
    /// or notes fields.
    ///
    /// # Parameters 
    ///
    /// - `text`: text to search
    ///
    /// # Returns
    ///
    /// Returns all the credential sets that contain `text` in their id, username, or notes 
    /// if they exist; an empty `Vec` otherwise.
    fn read_text(&self, text: &String) -> Vec<&C>;

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
    /// unique or equal to `id`, `Err` otherwise.
    fn update(&mut self, id: &String, cred_set: C) -> Result<(), Err>;

    /// Deletes a credential set with the given id.
    ///
    /// # Parameters
    ///
    /// - `id`: id of the credential set to be deleted
    ///
    /// # Returns
    ///
    /// Returns `()` if a credential set with the given id exists, `Err` otherwise.
    fn delete(&mut self, id: &String) -> Result<(), Err>;

    /// Clones and returns all the credential sets in the storage layer if they exist; an empty `Vec`
    /// otherwise.
    fn list_all(&self) -> &Vec<C>;

    /// Returns all the expired credential set ids or an empty `Vec`.
    fn check_expired(&self) -> Vec<&String>;

    /// Returns all the non-expiring credential set ids or an empty `Vec`.
    fn check_non_expiring(&self) -> Vec<&String>;
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
    /// `cs_vec`. This field is used to optimize search by complete id, delete and update operations.
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
    fn create(&mut self, cred_set: C) -> Result<(), Err>{
        if self.cs_tree.contains_key(cred_set.get_id()) {
            return Err(Err::new("Credential set id is already in use", ErrSrc::Storage))
        }

        // the index of cred_set in cs_vec will be the current length of cs_vec as cred_set will 
        // be appended to it
        self.cs_tree.insert(cred_set.get_id().clone(), self.cs_vec.len());
        self.cs_vec.push(cred_set);

        Ok(())

    }

    fn read_id(&self, id: &String) -> Option<&C>{
        let mut cred = None;

        if let Some(index) = self.cs_tree.get(id) {
            cred = self.cs_vec.get(*index);
        }

        cred
    }


    fn read_text(&self, text: &String) -> Vec<&C>{
        unimplemented!();
    }


    fn update(&mut self, id: &String, cred_set: C) -> Result<(), Err>{
        // Returns an error if cred_set.get_id has been updated (different from the old one, 
        // which is id) and is already in use
        if id != cred_set.get_id() && self.cs_tree.contains_key(cred_set.get_id()) {
            return Err(Err::new("Updated credential set id is already in use", ErrSrc::Storage))
        }

        if id == cred_set.get_id() {
            // no cs_tree update needed as the updated id in cred_set is equal to the old one
            let c = self.cs_vec.get_mut(
                *self.cs_tree
                    .get(id)
                    .expect("Unable to get an existing credential set index")
            ).expect("unable to get a mutable reference to an existing credential set");

            *c = cred_set;
        } else {
            // cs_tree update needed as the updated id in cred_set is not equal to the old one. 
            // Therefore, same cs_vec index must be associated to the new id value
            let index = self.cs_tree
                .remove(id)
                .expect("Unable to remove an existing credential set index");

            let c = self.cs_vec
                .get_mut(index)
                .expect("Unable to get a mutable reference to an existing credential set");

            self.cs_tree.insert(cred_set.get_id().clone(), index);

            *c = cred_set;
        }

        Ok(())
    }

    fn delete(&mut self, id: &String) -> Result<(), Err>{
        if !self.cs_tree.contains_key(id) {
            return Err(Err::new("Credential set id to delete does not exist", ErrSrc::Storage))
        }
        
        let index = self.cs_tree
            .remove(id)
            .expect("Unable to remove an existing credential set index");

        self.cs_vec.swap_remove(index);

        // index updates must take place only if the deleted element was not the only one in 
        // cs_tree
        if !self.cs_tree.is_empty() {
            // updating the index of the element in cs_vec that was swapped with the deleted one
            let swapped = self.cs_tree.get_mut(
                self.cs_vec
                    .get(index)
                    .expect("Unable to get the swapped credential set value")
                    .get_id()
            ).expect("Unable to get a mutable reference to an existing credential set index");

            *swapped = index;
        }

        Ok(())
    }

    fn list_all(&self) -> &Vec<C>{
        &self.cs_vec
    }

    fn check_expired(&self) -> Vec<&String>{
        let mut exp = Vec::new();

        for c in self.cs_vec.iter() {
            if let Some(date) = c.get_exp_date() && date <= &Utc::now().date_naive() {
                exp.push(c.get_id())
            }
        }

        exp
    }

    fn check_non_expiring(&self) -> Vec<&String>{
        let mut non_exp = Vec::new();

        for c in self.cs_vec.iter() {
            if c.get_exp_date().is_none() {
                non_exp.push(c.get_id())
            }
        }

        non_exp
    }


}

// ]]]
