//! Digest

pub use digest::{core_api::OutputSizeUser, Digest};
pub use generic_array::{ArrayLength, GenericArray};
pub use sha1;
pub use sha2;

pub trait Hasher {
    type OutputSize;

    fn hash(msg: &[u8]) -> GenericArray<u8, Self::OutputSize>
    where
        Self::OutputSize: ArrayLength<u8>;
}

pub struct Sha1;

impl Hasher for Sha1 {
    type OutputSize = <sha1::Sha1 as OutputSizeUser>::OutputSize;

    fn hash(msg: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        let mut h = sha1::Sha1::new();
        h.update(msg);
        h.finalize()
    }
}

pub struct Sha224;

impl Hasher for Sha224 {
    type OutputSize = <sha2::Sha224 as OutputSizeUser>::OutputSize;

    fn hash(msg: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        let mut h = sha2::Sha224::new();
        h.update(msg);
        h.finalize()
    }
}
pub struct Sha256;

impl Hasher for Sha256 {
    type OutputSize = <sha2::Sha256 as OutputSizeUser>::OutputSize;

    fn hash(msg: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        let mut h = sha2::Sha256::new();
        h.update(msg);
        h.finalize()
    }
}
pub struct Sha384;

impl Hasher for Sha384 {
    type OutputSize = <sha2::Sha384 as OutputSizeUser>::OutputSize;

    fn hash(msg: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        let mut h = sha2::Sha384::new();
        h.update(msg);
        h.finalize()
    }
}

pub struct Sha512;

impl Hasher for Sha512 {
    type OutputSize = <sha2::Sha512 as OutputSizeUser>::OutputSize;

    fn hash(msg: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        let mut h = sha2::Sha512::new();
        h.update(msg);
        h.finalize()
    }
}

#[cfg(test)]
mod tests {

    use crate::digest::{Hasher, Sha1, Sha224, Sha256, Sha384, Sha512};

    #[test]
    fn sha1() {
        let output = Sha1::hash(b"Hello, world!");
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
        let output = Sha224::hash(b"Hello, world!");
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
        let output = Sha256::hash(b"Hello, world!");
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
        let output = Sha384::hash(b"Hello, world!");
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
        let output = Sha512::hash(b"Hello, world!");
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
}

/*
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
*/
