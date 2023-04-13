//! Signing/Verifying Keys

use crate::{
    asn1::{
        core::{db, ObjectIdentifier},
        pkcs8::DecodePublicKey,
    },
    digest::{
        sha1::Sha1,
        sha2::{Sha224, Sha256, Sha384, Sha512},
        Digest,
    },
    rsa::{
        pkcs1v15::{Signature, VerifyingKey},
        signature::Verifier,
        RsaPrivateKey, RsaPublicKey,
    },
    signatures::error,
};

pub enum SignatureScheme {
    Sha1WithRsaEncryption,
    Sha224WithRsaEncryption,
    Sha256WithRsaEncryption,
    Sha384WithRsaEncryption,
    Sha512WithRsaEncryption,
    DsaWithSha1,
    EcdsaWithSha224,
    EcdsaWithSha256,
    EcdsaWithSha384,
    EcdsaWithSha512,
}

impl TryFrom<&ObjectIdentifier> for SignatureScheme {
    type Error = error::Error;

    fn try_from(value: &ObjectIdentifier) -> Result<Self, Self::Error> {
        match value {
            &db::rfc5912::SHA_1_WITH_RSA_ENCRYPTION => Ok(SignatureScheme::Sha1WithRsaEncryption),
            &db::rfc5912::SHA_224_WITH_RSA_ENCRYPTION => {
                Ok(SignatureScheme::Sha224WithRsaEncryption)
            }
            &db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
                Ok(SignatureScheme::Sha256WithRsaEncryption)
            }
            &db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION => {
                Ok(SignatureScheme::Sha384WithRsaEncryption)
            }
            &db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION => {
                Ok(SignatureScheme::Sha512WithRsaEncryption)
            }
            &db::rfc5912::DSA_WITH_SHA_1 => Ok(SignatureScheme::DsaWithSha1),
            &db::rfc5912::ECDSA_WITH_SHA_224 => Ok(SignatureScheme::EcdsaWithSha224),
            &db::rfc5912::ECDSA_WITH_SHA_256 => Ok(SignatureScheme::EcdsaWithSha256),
            &db::rfc5912::ECDSA_WITH_SHA_384 => Ok(SignatureScheme::EcdsaWithSha384),
            &db::rfc5912::ECDSA_WITH_SHA_512 => Ok(SignatureScheme::EcdsaWithSha512),
            _ => Err(error::Error::InvalidOid),
        }
    }
}

impl TryFrom<ObjectIdentifier> for SignatureScheme {
    type Error = error::Error;

    fn try_from(value: ObjectIdentifier) -> Result<Self, Self::Error> {
        match &value {
            &db::rfc5912::SHA_1_WITH_RSA_ENCRYPTION => Ok(SignatureScheme::Sha1WithRsaEncryption),
            &db::rfc5912::SHA_224_WITH_RSA_ENCRYPTION => {
                Ok(SignatureScheme::Sha224WithRsaEncryption)
            }
            &db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
                Ok(SignatureScheme::Sha256WithRsaEncryption)
            }
            &db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION => {
                Ok(SignatureScheme::Sha384WithRsaEncryption)
            }
            &db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION => {
                Ok(SignatureScheme::Sha512WithRsaEncryption)
            }
            &db::rfc5912::DSA_WITH_SHA_1 => Ok(SignatureScheme::DsaWithSha1),
            &db::rfc5912::ECDSA_WITH_SHA_224 => Ok(SignatureScheme::EcdsaWithSha224),
            &db::rfc5912::ECDSA_WITH_SHA_256 => Ok(SignatureScheme::EcdsaWithSha256),
            &db::rfc5912::ECDSA_WITH_SHA_384 => Ok(SignatureScheme::EcdsaWithSha384),
            &db::rfc5912::ECDSA_WITH_SHA_512 => Ok(SignatureScheme::EcdsaWithSha512),
            _ => Err(error::Error::InvalidOid),
        }
    }
}

impl SignatureScheme {
    /*
    pub fn sign(&self, private_key: &[u8], msg: &[u8]) -> error::Result<()> {
    match self {
    SignatureScheme::Sha1WithRsaEncryption => {
    SignatureScheme::rsa_verify::<Sha1>(public_key, msg, sig)
    }
    SignatureScheme::Sha224WithRsaEncryption => {
    SignatureScheme::rsa_verify::<Sha224>(public_key, msg, sig)
    }
    SignatureScheme::Sha256WithRsaEncryption => {
    SignatureScheme::rsa_verify::<Sha256>(public_key, msg, sig)
    }
    SignatureScheme::Sha384WithRsaEncryption => {
    SignatureScheme::rsa_verify::<Sha384>(public_key, msg, sig)
    }
    SignatureScheme::Sha512WithRsaEncryption => {
    SignatureScheme::rsa_verify::<Sha512>(public_key, msg, sig)
    }
    SignatureScheme::DsaWithSha1 => Err(error::Error::Verification),
    SignatureScheme::EcdsaWithSha224 => Err(error::Error::Verification),
    SignatureScheme::EcdsaWithSha256 => Err(error::Error::Verification),
    SignatureScheme::EcdsaWithSha384 => Err(error::Error::Verification),
    SignatureScheme::EcdsaWithSha512 => Err(error::Error::Verification),
    }
    }
    */

    pub fn rsa_verify<D: Digest>(public_key: &[u8], msg: &[u8], sig: &[u8]) -> error::Result<()> {
        let pubkey: VerifyingKey<D> = match RsaPublicKey::from_public_key_der(public_key) {
            Ok(pk) => pk.into(),
            Err(_) => return Err(error::Error::InvalidPublicKey),
        };
        let signature: Signature = match sig.try_into() {
            Ok(s) => s,
            Err(_) => return Err(error::Error::InvalidSignature),
        };
        match pubkey.verify(msg, &signature) {
            Ok(_) => Ok(()),
            Err(_) => Err(error::Error::Verification),
        }
    }

    pub fn verify(&self, public_key: &[u8], msg: &[u8], sig: &[u8]) -> error::Result<()> {
        match self {
            SignatureScheme::Sha1WithRsaEncryption => {
                SignatureScheme::rsa_verify::<Sha1>(public_key, msg, sig)
            }
            SignatureScheme::Sha224WithRsaEncryption => {
                SignatureScheme::rsa_verify::<Sha224>(public_key, msg, sig)
            }
            SignatureScheme::Sha256WithRsaEncryption => {
                SignatureScheme::rsa_verify::<Sha256>(public_key, msg, sig)
            }
            SignatureScheme::Sha384WithRsaEncryption => {
                SignatureScheme::rsa_verify::<Sha384>(public_key, msg, sig)
            }
            SignatureScheme::Sha512WithRsaEncryption => {
                SignatureScheme::rsa_verify::<Sha512>(public_key, msg, sig)
            }
            SignatureScheme::DsaWithSha1 => Err(error::Error::Verification),
            SignatureScheme::EcdsaWithSha224 => Err(error::Error::Verification),
            SignatureScheme::EcdsaWithSha256 => Err(error::Error::Verification),
            SignatureScheme::EcdsaWithSha384 => Err(error::Error::Verification),
            SignatureScheme::EcdsaWithSha512 => Err(error::Error::Verification),
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        asn1::{
            cert::Certificate,
            der::{DecodePem, Encode},
            pkcs8::DecodePrivateKey,
        },
        rsa::RsaPrivateKey,
        signatures::SignatureScheme,
    };
    use std::{fs::File, io::Read};

    fn load_public_pem(filename: &str) -> Certificate {
        let mut data = Vec::new();
        let mut file = File::open(filename).expect("error opening file");
        file.read_to_end(&mut data).expect("error reading file");
        Certificate::from_pem(&data).expect("error reading DER certificate")
    }

    fn load_private_pem(filename: &str) -> RsaPrivateKey {
        RsaPrivateKey::read_pkcs8_pem_file(filename).expect("error reading private key")
    }

    #[test]
    fn verify_good() {
        let cert = load_public_pem("testdata/rsa2048-crt.pem");
        let scheme: SignatureScheme = cert
            .signature_algorithm
            .oid
            .try_into()
            .expect("could not get SignatureScheme");
        let public_key = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("error encoding public key");
        let msg = cert
            .tbs_certificate
            .to_der()
            .expect("error encoding message");
        let sig = cert.signature.as_bytes().expect("error encoding signature");
        match scheme.verify(&public_key, &msg, &sig) {
            Ok(_) => {}
            Err(e) => panic!("{:?}", e),
        }
    }
}
