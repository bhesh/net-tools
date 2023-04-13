//! Hashing

use crate::{
    asn1::core::{db, ObjectIdentifier},
    digest::{Hasher, Sha1, Sha224, Sha256, Sha384, Sha512},
    signatures::error::Error,
};
use std::convert::TryFrom;

pub enum HashSystem {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl TryFrom<&ObjectIdentifier> for HashSystem {
    type Error = Error;

    fn try_from(value: &ObjectIdentifier) -> Result<Self, Self::Error> {
        match value {
            &db::rfc5912::SHA_1_WITH_RSA_ENCRYPTION => Ok(HashSystem::Sha1),
            &db::rfc5912::SHA_224_WITH_RSA_ENCRYPTION => Ok(HashSystem::Sha224),
            &db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION => Ok(HashSystem::Sha256),
            &db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION => Ok(HashSystem::Sha384),
            &db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION => Ok(HashSystem::Sha512),
            &db::rfc5912::DSA_WITH_SHA_1 => Ok(HashSystem::Sha1),
            &db::rfc5912::ECDSA_WITH_SHA_224 => Ok(HashSystem::Sha224),
            &db::rfc5912::ECDSA_WITH_SHA_256 => Ok(HashSystem::Sha256),
            &db::rfc5912::ECDSA_WITH_SHA_384 => Ok(HashSystem::Sha384),
            &db::rfc5912::ECDSA_WITH_SHA_512 => Ok(HashSystem::Sha512),
            _ => Err(Error::InvalidOid),
        }
    }
}

impl HashSystem {
    pub fn hash(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            HashSystem::Sha1 => Sha1::hash(msg).to_vec(),
            HashSystem::Sha224 => Sha224::hash(msg).to_vec(),
            HashSystem::Sha256 => Sha256::hash(msg).to_vec(),
            HashSystem::Sha384 => Sha384::hash(msg).to_vec(),
            HashSystem::Sha512 => Sha512::hash(msg).to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        asn1::core::db,
        signatures::{HashSystem, error::Result},
    };

    #[test]
    fn sha1() {
        let oid = &db::rfc5912::SHA_1_WITH_RSA_ENCRYPTION;
        let system: HashSystem = oid.try_into().expect("could not convert OID");
        let output = system.hash(b"Hello, world!");
        assert_eq!(
            &output[..],
            &[
                148, 58, 112, 45, 6, 243, 69, 153, 174, 225, 248, 218, 142, 249, 247, 41, 96, 49,
                214, 153
            ]
        );
    }

    #[test]
    fn sha224() {
        let oid = &db::rfc5912::SHA_224_WITH_RSA_ENCRYPTION;
        let system: HashSystem = oid.try_into().expect("could not convert OID");
        let output = system.hash(b"Hello, world!");
        assert_eq!(
            &output[..],
            &[
                133, 82, 216, 183, 167, 220, 84, 118, 203, 158, 37, 222, 230, 154, 128, 145, 41, 7,
                100, 183, 242, 166, 79, 230, 231, 142, 149, 104
            ]
        );
    }

    #[test]
    fn sha256() {
        let oid = &db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION;
        let system: HashSystem = oid.try_into().expect("could not convert OID");
        let output = system.hash(b"Hello, world!");
        assert_eq!(
            &output[..],
            &[
                49, 95, 91, 219, 118, 208, 120, 196, 59, 138, 192, 6, 78, 74, 1, 100, 97, 43, 31,
                206, 119, 200, 105, 52, 91, 252, 148, 199, 88, 148, 237, 211
            ]
        );
    }

    #[test]
    fn sha384() {
        let oid = &db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION;
        let system: HashSystem = oid.try_into().expect("could not convert OID");
        let output = system.hash(b"Hello, world!");
        assert_eq!(
            &output[..],
            &[
                85, 188, 85, 107, 13, 47, 224, 252, 229, 130, 186, 95, 224, 123, 170, 255, 240, 53,
                101, 54, 56, 199, 172, 13, 84, 148, 194, 166, 76, 11, 234, 28, 197, 115, 49, 199,
                193, 42, 69, 205, 188, 167, 244, 195, 74, 8, 158, 235
            ]
        );
    }

    #[test]
    fn sha512() {
        let oid = &db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION;
        let system: HashSystem = oid.try_into().expect("could not convert OID");
        let output = system.hash(b"Hello, world!");
        assert_eq!(
            &output[..],
            &[
                193, 82, 124, 216, 147, 193, 36, 119, 61, 129, 25, 17, 151, 12, 143, 230, 232, 87,
                214, 223, 93, 201, 34, 107, 216, 161, 96, 97, 76, 12, 217, 99, 164, 221, 234, 43,
                148, 187, 125, 54, 2, 30, 249, 216, 101, 213, 206, 162, 148, 168, 45, 212, 154, 11,
                178, 105, 245, 31, 110, 122, 87, 247, 148, 33
            ]
        );
    }

    #[test]
    fn fail() {
        let oid = &db::rfc4519::CN;
        let res: Result<HashSystem> = oid.try_into();
        match res {
            Ok(_) => panic!("HashSystem was made successfully"),
            Err(_) => {}
        }
    }
}
