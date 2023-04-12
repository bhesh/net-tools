//! Systems

use crate::{
    asn1::core::{db, ObjectIdentifier},
    digest::{Digest, Sha1, Sha224, Sha256, Sha384, Sha512},
};

pub enum HashSystem {
    None,
    Sha1(Sha1),
    Sha224(Sha224),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl From<&ObjectIdentifier> for HashSystem {
    fn from(value: &ObjectIdentifier) -> Self {
        match value {
            &db::rfc5912::SHA_1_WITH_RSA_ENCRYPTION => HashSystem::Sha1(Sha1::new()),
            &db::rfc5912::SHA_224_WITH_RSA_ENCRYPTION => HashSystem::Sha224(Sha224::new()),
            &db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION => HashSystem::Sha256(Sha256::new()),
            &db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION => HashSystem::Sha384(Sha384::new()),
            &db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION => HashSystem::Sha512(Sha512::new()),
            &db::rfc5912::DSA_WITH_SHA_1 => HashSystem::Sha1(Sha1::new()),
            &db::rfc5912::ECDSA_WITH_SHA_224 => HashSystem::Sha224(Sha224::new()),
            &db::rfc5912::ECDSA_WITH_SHA_256 => HashSystem::Sha256(Sha256::new()),
            &db::rfc5912::ECDSA_WITH_SHA_384 => HashSystem::Sha384(Sha384::new()),
            &db::rfc5912::ECDSA_WITH_SHA_512 => HashSystem::Sha512(Sha512::new()),
            _ => HashSystem::None,
        }
    }
}
