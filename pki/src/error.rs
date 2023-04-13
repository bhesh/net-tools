//! Possible Error Definitions

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    InvalidOid,
    Rsa(rsa::errors::Error),
}

macro_rules! FromError {
    ( $from:ty, $enum:ident ) => {
        impl From<$from> for Error {
            fn from(other: $from) -> Self {
                Error::$enum(other)
            }
        }
    };
}
FromError!(rsa::errors::Error, Rsa);
