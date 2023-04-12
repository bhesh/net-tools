//! DER reimports

pub use x509_cert::der::{
    pem::{LineEnding, PemLabel},
    Choice, DateTime, Decode, DecodePem, DecodeValue, Encode, EncodePem, EncodeValue, Enumerated,
    Error, ErrorKind, FixedTag, Header, Length, Reader, Result, Sequence, Tag, Tagged, ValueOrd,
    Writer,
};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Format {
    Pem,
    Der,
}
