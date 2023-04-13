//! Signature and Encryption Schemes

use crate::error::Result;
use rsa::{self, RsaPublicKey, SignatureScheme};

pub trait Verifier {
    fn verify(self, msg: &[u8], sig: &[u8]) -> Result<()>;
}

pub struct RsaVerifier<'a, S>
where
    S: SignatureScheme,
{
    scheme: S,
    verifying_key: &'a RsaPublicKey,
}

impl<'a, S> RsaVerifier<'a, S>
where
    S: SignatureScheme,
{
    pub fn new(scheme: S, verifying_key: &'a RsaPublicKey) -> Self {
        RsaVerifier {
            scheme,
            verifying_key,
        }
    }
}

impl<'a, S> Verifier for RsaVerifier<'a, S>
where
    S: SignatureScheme,
{
    fn verify(self, hashed: &[u8], sig: &[u8]) -> Result<()> {
        Ok(self.scheme.verify(self.verifying_key, hashed, sig)?)
    }
}

#[cfg(test)]
mod tests {

    use crate::{RsaVerifier, Verifier};
    use core::alloc::Vec;
    use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Sign, RsaPublicKey};
    use sha2::Sha256;
    use std::{fs::File, io::Read};
    use x509_cert::{
        der::{DecodePem, Encode},
        Certificate,
    };

    fn load_public_pem(filename: &str) -> Certificate {
        let mut data = Vec::new();
        let mut file = File::open(filename).expect("error opening file");
        file.read_to_end(&mut data).expect("error reading file");
        Certificate::from_pem(&data).expect("error reading DER certificate")
    }

    #[test]
    fn verify_good() {
        let cert = load_public_pem("testdata/rsa2048-crt.pem");
        let public_key = RsaPublicKey::from_public_key_der(
            &cert
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .expect("error encoding public key"),
        )
        .expect("error encoding RSA key");
        let msg = cert
            .tbs_certificate
            .to_der()
            .expect("error encoding message");
        let sig = cert
            .signature
            .as_bytes()
            .expect("signature is not octet-aligned");
        let verifier = RsaVerifier::new(Pkcs1v15Sign::new::<Sha256>(), &public_key);
    }
}

/*
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
fn rsa_verify<S: rsa::SignatureScheme>(key: &RsaPublicKey, msg: &[u8], sig) -> Result<()> {
}
}
*/
