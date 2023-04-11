//! ASN.1 Formats

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Format {
    Pem,
    Der,
}
