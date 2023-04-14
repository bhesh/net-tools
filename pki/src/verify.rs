//! Signature Verification

use crate::error::{Error, Result};
use const_oid::{db, ObjectIdentifier};
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Sign, RsaPublicKey, SignatureScheme};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

/// Trait for verifying structures
pub trait Verifier {
    /// Verify function
    fn verify(self, hashed: &[u8], sig: &[u8]) -> Result<()>;
}

/// RSA signature verifier
pub struct RsaVerifier<'a, S>
where
    S: SignatureScheme,
{
    /// RSA SignatureScheme - In PKI, for RSA, this is almost always Pkcs1v15
    scheme: S,

    /// RSA Public Key
    verifying_key: &'a RsaPublicKey,
}

impl<'a, S> RsaVerifier<'a, S>
where
    S: SignatureScheme,
{
    /// Creates an RSA signature verifier given the scheme and public key
    pub fn new(scheme: S, verifying_key: &'a RsaPublicKey) -> Self {
        Self {
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

/// Validates the signature given an OID, public key, message, and signature
pub fn verify(oid: &ObjectIdentifier, public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    match oid {
        &db::rfc5912::SHA_1_WITH_RSA_ENCRYPTION => {
            let pk = RsaPublicKey::from_public_key_der(&public_key)?;
            let verifier = RsaVerifier::new(Pkcs1v15Sign::new::<Sha1>(), &pk);
            Ok(verifier.verify(&Sha1::digest(&msg), &sig)?)
        }
        &db::rfc5912::SHA_224_WITH_RSA_ENCRYPTION => {
            let pk = RsaPublicKey::from_public_key_der(&public_key)?;
            let verifier = RsaVerifier::new(Pkcs1v15Sign::new::<Sha224>(), &pk);
            Ok(verifier.verify(&Sha224::digest(&msg), &sig)?)
        }
        &db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
            let pk = RsaPublicKey::from_public_key_der(&public_key)?;
            let verifier = RsaVerifier::new(Pkcs1v15Sign::new::<Sha256>(), &pk);
            Ok(verifier.verify(&Sha256::digest(&msg), &sig)?)
        }
        &db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION => {
            let pk = RsaPublicKey::from_public_key_der(&public_key)?;
            let verifier = RsaVerifier::new(Pkcs1v15Sign::new::<Sha384>(), &pk);
            Ok(verifier.verify(&Sha384::digest(&msg), &sig)?)
        }
        &db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION => {
            let pk = RsaPublicKey::from_public_key_der(&public_key)?;
            let verifier = RsaVerifier::new(Pkcs1v15Sign::new::<Sha512>(), &pk);
            Ok(verifier.verify(&Sha512::digest(&msg), &sig)?)
        }
        /*
        &db::rfc5912::DSA_WITH_SHA_1 => {}
        &db::rfc5912::ECDSA_WITH_SHA_224 => {}
        &db::rfc5912::ECDSA_WITH_SHA_256 => {}
        &db::rfc5912::ECDSA_WITH_SHA_384 => {}
        &db::rfc5912::ECDSA_WITH_SHA_512 => {}
        */
        _ => Err(Error::InvalidOid),
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        error::Error,
        verify::{verify, RsaVerifier, Verifier},
    };
    use der::{DecodePem, Encode};
    use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Sign, RsaPublicKey};
    use sha2::{Digest, Sha256};
    use x509_cert::Certificate;

    const PUBLIC_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgIUZ+evGd94OegJAuRime281jEJh7UwDQYJKoZIhvcNAQEL
BQAwGTEXMBUGA1UEAwwOcnNhMjA0OC1zaGEyNTYwHhcNMjMwNDE0MTUwNzQzWhcN
MjYwNDEzMTUwNzQzWjAZMRcwFQYDVQQDDA5yc2EyMDQ4LXNoYTI1NjCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAIh6/32L7lnScThXsxnub+ATmL4HRxIl
ad//hlwerxLzXpYKvik8tIMb3gYiy83sU1PNXdCVegoMxi4+Di0deV9CX1VAUFeG
SAZRp5Ib5ZtsfgoyuqEHc4U/WzX6V5XdxJfwP6spI/rUsjBEY2g+ltRWWXQGSr/v
iOiNKwhx1rrXIsqCaFb39zIGYlyi/bpQwwmfkXgIEhkezbDdPWyqRT9XstWElOaV
clxMFoPLmWfPeQJF250c6GxAIZKN5B+qVvGC/THy928+RGZpsriOf0Izkdd2iiF/
kkmcmRAe9TFdEOPgLOHdjhyCC2rVjX65vQkRUeWn+mke1MrtZKePsY8CAwEAAaNT
MFEwHQYDVR0OBBYEFBkcFiSUOy5O4PnQ3lB87P1Uo16jMB8GA1UdIwQYMBaAFBkc
FiSUOy5O4PnQ3lB87P1Uo16jMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBABwMVy/mVaG8Mc9aX15hrnQD3XMD7lvASqeiTtaS16x8GOkemoAjjDih
mQ4hLN7ZnOj/eqaURxizBJd4f8VGxATlOWlDJO7AQbDQxx6jtJVZqhcw/elp/mga
7MZClbBZdKaFWCHNX6Q8hkKYc5AunVz/psyH5B5AQnPDQi3RcrqIccok3OCQNdGJ
SGIqHGE1ztNTTjmgzIyMpV0/fBEvCJfWVVyGP4vn7QN5ofUs/p+giRf1KGcmbRVI
QmOnlIJzMJB81/BUqxmJPApOjFumHc4Vx362V/uCbnwHKlO1m8kgilaOsXzFz+/h
VMhbXUpvpTLfrE9uM/R0W1X0j8YOl78=
-----END CERTIFICATE-----";

    #[test]
    fn verify_rsa_good() {
        let cert = Certificate::from_pem(&PUBLIC_PEM).expect("error parsing certificate");
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
        verifier
            .verify(&Sha256::digest(&msg), &sig)
            .expect("Verification failed");
    }

    #[test]
    fn verify_rsa_bad() {
        let cert = Certificate::from_pem(&PUBLIC_PEM).expect("error parsing certificate");
        let public_key = RsaPublicKey::from_public_key_der(
            &cert
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .expect("error encoding public key"),
        )
        .expect("error encoding RSA key");
        let msg = cert.to_der().expect("error encoding message");
        let sig = cert
            .signature
            .as_bytes()
            .expect("signature is not octet-aligned");
        let verifier = RsaVerifier::new(Pkcs1v15Sign::new::<Sha256>(), &public_key);
        match verifier.verify(&Sha256::digest(&msg), &sig) {
            Ok(_) => panic!("should not have been good"),
            Err(Error::Verification) => {}
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn verify_rsa_good_from_oid() {
        let cert = Certificate::from_pem(&PUBLIC_PEM).expect("error parsing certificate");
        let public_key = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("error encoding public key");
        let msg = cert
            .tbs_certificate
            .to_der()
            .expect("error encoding message");
        let sig = cert
            .signature
            .as_bytes()
            .expect("signature is not octet-aligned");
        let oid = &cert.signature_algorithm.oid;
        verify(oid, &public_key, &msg, &sig).expect("error verifying");
    }

    #[test]
    fn verify_rsa_bad_from_oid() {
        let cert = Certificate::from_pem(&PUBLIC_PEM).expect("error parsing certificate");
        let public_key = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("error encoding public key");
        let msg = cert.to_der().expect("error encoding message");
        let sig = cert
            .signature
            .as_bytes()
            .expect("signature is not octet-aligned");
        let oid = &cert.signature_algorithm.oid;
        match verify(oid, &public_key, &msg, &sig) {
            Ok(_) => panic!("should not have been good"),
            Err(Error::Verification) => {}
            Err(e) => panic!("{:?}", e),
        }
    }
}
