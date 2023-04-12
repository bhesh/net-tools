//! ASN.1 Core Crypto Object Definitions

pub use const_oid::{db, AssociatedOid, ObjectIdentifier};
pub use x509_cert::{
    attr::*,
    der::asn1::*,
    ext::*,
    name::{DistinguishedName, Name, RelativeDistinguishedName},
    serial_number::SerialNumber,
    spki::{
        AlgorithmIdentifierOwned as AlgorithmIdentifier,
        SubjectPublicKeyInfoOwned as SubjectPublicKeyInfo,
    },
    time::{Time, Validity},
};

#[cfg(test)]
mod tests {

    use crate::asn1::core::db;

    #[test]
    fn lookup_oid() {
        let name = db::DB
            .by_oid(&db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION)
            .expect("signature algorithm not found");
        assert_eq!("sha256WithRSAEncryption", name);
    }

    #[test]
    fn lookup_name() {
        let oid = db::DB
            .by_name("sha256WithRSAEncryption")
            .expect("signature algorithm not found");
        assert_eq!(&db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION, oid);
    }
}
