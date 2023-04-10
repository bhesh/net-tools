//! Possible errors

pub type Result<T> = std::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Der(x509_cert::der::Error),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<x509_cert::der::Error> for Error {
    fn from(e: x509_cert::der::Error) -> Self {
        Error::Der(e)
    }
}
