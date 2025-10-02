use std::{fmt::{Display, Formatter, Result as Res}};

/// Represents the error source.
#[derive(Debug)]
pub enum ErrSrc {
    Core,
    Crypto,
    Domain,
    Storage
}

impl Display for ErrSrc {
    fn fmt(&self, f: &mut Formatter<'_>) -> Res {
        match self {
            ErrSrc::Core => write!(f, "Core"),
            ErrSrc::Crypto => write!(f, "Crypto"),
            ErrSrc::Domain => write!(f, "Domain"),
            ErrSrc::Storage => write!(f, "Storage")
        }
    }
}


/// An error that define what went wrong while creating a domain struct instance.
#[derive(Debug)]
pub struct Err {
    descr: String,
    source: ErrSrc
}

impl Err {
    pub fn new(descr: &str, source: ErrSrc) -> Self {
        Self {
            descr: String::from(descr),
            source
        }
    }

    pub fn get_descr(&self) -> &str {
        &self.descr
    }

    pub fn get_source(&self) -> &ErrSrc {
        &self.source
    }
}

impl Display for Err {
    fn fmt(&self, f: &mut Formatter<'_>) -> Res {
        write!(f, "source:{0},\nerror: {1}", self.source, self.descr)
    }
}
