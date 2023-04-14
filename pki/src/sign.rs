//! Signature Generation

use crate::{dummy_rng::DummyRng, error::Result};
use alloc::vec::Vec;
use rsa::{rand_core::CryptoRngCore, RsaPrivateKey, SignatureScheme};

/// Trait for signing structures
pub trait Signer {
    /// Sign function
    fn sign(self, hashed: &[u8]) -> Result<Vec<u8>>;
}

/// Trait for signing structures
pub trait RandomizedSigner {
    /// Sign function
    fn sign_with_rng<Rng: CryptoRngCore>(self, rng: &mut Rng, hashed: &[u8]) -> Result<Vec<u8>>;
}

/// RSA signature verifier
pub struct RsaSigner<'a, S>
where
    S: SignatureScheme,
{
    /// RSA SignatureScheme. In PKI this is typically Pkcs1v15Sign
    scheme: S,

    /// RSA Public Key
    signing_key: &'a RsaPrivateKey,
}

impl<'a, S> RsaSigner<'a, S>
where
    S: SignatureScheme,
{
    /// Creates an RSA signature verifier given the scheme and public key
    pub fn new(scheme: S, signing_key: &'a RsaPrivateKey) -> Self {
        RsaSigner {
            scheme,
            signing_key,
        }
    }
}

impl<'a, S> Signer for RsaSigner<'a, S>
where
    S: SignatureScheme,
{
    fn sign(self, hashed: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .scheme
            .sign(None::<&mut DummyRng>, self.signing_key, hashed)?)
    }
}

impl<'a, S> RandomizedSigner for RsaSigner<'a, S>
where
    S: SignatureScheme,
{
    fn sign_with_rng<Rng: CryptoRngCore>(self, rng: &mut Rng, hashed: &[u8]) -> Result<Vec<u8>> {
        Ok(self.scheme.sign(Some(rng), self.signing_key, hashed)?)
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        cert::Certificate,
        sign::{RandomizedSigner, RsaSigner, Signer},
        verify::{RsaVerifier, Verifier},
    };
    use der::{DecodePem, Encode};
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
    use rsa::{
        pkcs8::{DecodePrivateKey, DecodePublicKey},
        Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
    };
    use sha1::Sha1;
    use sha2::Digest;

    const RSA_SHA1_PRIV: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC4MY+MvLzta51+
jDeCX3mrpW6Kak9xzSElHL3s6syvwwHt4eytkDdjmIu+ApIonr4bzHaVoDJlmVEm
8qCAllZhWh08k3L0RZOt1Y1i56vBwjS2SnfLeDSbr75DAgKTdv5DccwvdgAjmeX+
txn7JUZvyzxJ7yp6Hz51GwfjwwvjUT2rrik/wxRLOT7nKDdFFU8/RF0K+Fbu99/X
WY+tl2bF+hJtbk0xACSrc46db0pLDjrUVok+iVRA9g7gQDComR8UwOoTYQn11x/Q
Q98HVFZXV0aw5rxW8LGPoIERHxcn+SKKeAS4pVCf0DbAeKVOZC2kBLowlm80ckJh
4TID5MJnAgMBAAECggEAO/yMCyImh03uZ1nD9DYi2mdQpkx0HhRXsI35PrDDQ5SH
StEyst3OZCW4kQOmVQtJz6TZk+Yts4/ocX5ADlCnxiHCdslwfSQxscHkP2tCsSIN
57Y96Gp3+6ITHSCI9TyiFxX3ERfleLK0yC0ajYO4ukzekBePZmFJhnrsqV0KwJdV
u6PrjxturqKmr+cxNXvztaKyQqQ8O7fT3ffX1Lb+iDr0LDmL9OJ/st7JK3wCmSRt
1mRZn8mshY9+wcG1IImjB3lAaNDKVBve+FSK2k1xIb2IabOns+Ri70VZJU1Lhi1H
7fDzJzbXdeXAmZd0bqbEkuDQv6p543bmGTVShdmh1QKBgQDeLb/saYV2OjQH8odm
pT6Qj4+JUTkhw6PY9h5ZvPhTDa6yntGl0YGGH8Z1AaziceQ0jUkJbKtkxh+Z5fGl
X1eYZt0nh6vRlLCfmRT6eQB6mlzZz1vbXXG/ckCV8DoLvb3CMWhCGyZ0WXI+cV4N
FPZuJs8/+NK3r0v0Bwbw+gHaowKBgQDUO4pYy5Pv1KlAKRk/ihXVHVdbWlajFFWe
//CstOXgVvYDGFmjukMK7vun9yEzlNUX3otWTlDosbq3YxhltIL9dpxUUs37D1dK
6qKwfZqgGz7Nikb69asrtyTdmN5FGId6k6Sh064Gn7KscnA6P3KLAymSUhC2qcnp
0Uj5/QhZbQKBgG+aW4XNm5S/t9MmKI2PA9ZpxpgbjK9BLtSVDLnXCoXtoYtn67d3
fbB51Z6AsO8udotPTRjG1XFRdB5COxfuxHlxcjWhGNW18uK4aqlGjs8HKwzd9C5E
yhZ4taibewzayq75Un2iVbasF472M2Au33qFVCW2P2K1U1nJDduOOdAxAoGAAaUk
gWOyld1UIocvBusPGEPN9YtRuJnjwAPD3dLZJVAHQCbkKvy6oE8R7E9iFoBE1paH
Bfg9cFBQXjOKcN9hVI2i0JSDvDp2NsJy2GNg23Tam8VCn5df6ErXIlCZCHgUNMMI
N6joZGzAec25SPpM7P7tR5ETSBcw1Xsl0apAclECgYBsAiofJAxMb+LbtIe3WsJl
qD6waZNy5PJ9hI9ymjAbqetOlJvXXmcdC1MxPp0qAyGULbQGiRTKWUaxDgB2kf8v
pZyQmtbYVFBAS4YUJpfr+AWhKOllWZt1LARtgNzKbafImRmMGTFCSjjRrPapA0FD
CjQ+7UyGw6Br+u9Hf4PctA==
-----END PRIVATE KEY-----";

    const RSA_SHA1_PUB: &str = "-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIUS5G6A2pfVuXRi9zRiLIJl9PEOJAwDQYJKoZIhvcNAQEF
BQAwFzEVMBMGA1UEAwwMcnNhMjA0OC1zaGExMB4XDTIzMDQxNDE1MDc0M1oXDTI2
MDQxMzE1MDc0M1owFzEVMBMGA1UEAwwMcnNhMjA0OC1zaGExMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuDGPjLy87Wudfow3gl95q6VuimpPcc0hJRy9
7OrMr8MB7eHsrZA3Y5iLvgKSKJ6+G8x2laAyZZlRJvKggJZWYVodPJNy9EWTrdWN
YuerwcI0tkp3y3g0m6++QwICk3b+Q3HML3YAI5nl/rcZ+yVGb8s8Se8qeh8+dRsH
48ML41E9q64pP8MUSzk+5yg3RRVPP0RdCvhW7vff11mPrZdmxfoSbW5NMQAkq3OO
nW9KSw461FaJPolUQPYO4EAwqJkfFMDqE2EJ9dcf0EPfB1RWV1dGsOa8VvCxj6CB
ER8XJ/kiingEuKVQn9A2wHilTmQtpAS6MJZvNHJCYeEyA+TCZwIDAQABo1MwUTAd
BgNVHQ4EFgQUAxIT+Y3nargbP5uXqALw9d2CwegwHwYDVR0jBBgwFoAUAxIT+Y3n
argbP5uXqALw9d2CwegwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQUFAAOC
AQEAlFwpgA48FqgAvH94XANVjgbUW9ZFWKk9CElJBpLT/OwG/hotk5ILIhkLzzKV
+fjLlRZOYSBU/TpspWcPJ3PJLA5Qgg3Bw1aXXLzNSFqhg/q9SJjam5LDK/dc4gt+
HRGNn5NJdhHP4otHInAT6aE6vxSx/09szjPgm4KKg0vf1qefEHOKbttdE6nY9oiY
Eo/okLk/cPKBzSVLzxNG5bpR9pPCoC+FAIn8ABIh6Ue8BzvamR8vE+phge/gurQM
s2r9E6jZqQUTJ3IFY/EXX6h8SDTLFI9aHNf3ROnWTIne2BbJzlBt8+9XGlgkgvEY
MGZEHd38Z/K1nOxOEjUS5xGdkQ==
-----END CERTIFICATE-----";

    #[test]
    fn sign_rsa_sha1() {
        let private_key =
            RsaPrivateKey::from_pkcs8_pem(&RSA_SHA1_PRIV).expect("error loading private key");
        let cert = Certificate::from_pem(&RSA_SHA1_PUB).expect("error loading public certificate");
        let public_key = RsaPublicKey::from_public_key_der(
            &cert
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .expect("error extracting public key"),
        )
        .expect("error making RSA public key");

        // Sign a message
        let signer = RsaSigner::new(Pkcs1v15Sign::new::<Sha1>(), &private_key);
        let hashed = Sha1::digest(b"Hello, world!");
        let sig = signer.sign(&hashed).expect("signature failed");

        // Verify that message
        let verifier = RsaVerifier::new(Pkcs1v15Sign::new::<Sha1>(), &public_key);
        verifier.verify(&hashed, &sig).expect("verification failed");
    }

    #[test]
    fn sign_rsa_sha1_with_rng() {
        let private_key =
            RsaPrivateKey::from_pkcs8_pem(&RSA_SHA1_PRIV).expect("error loading private key");
        let cert = Certificate::from_pem(&RSA_SHA1_PUB).expect("error loading public certificate");
        let public_key = RsaPublicKey::from_public_key_der(
            &cert
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .expect("error extracting public key"),
        )
        .expect("error making RSA public key");

        // Sign a message
        let signer = RsaSigner::new(Pkcs1v15Sign::new::<Sha1>(), &private_key);
        let mut rng = ChaCha8Rng::from_seed([0xCC; 32]);
        let hashed = Sha1::digest(b"Hello, world!");
        let sig = signer
            .sign_with_rng(&mut rng, &hashed)
            .expect("signature failed");

        // Verify that message
        let verifier = RsaVerifier::new(Pkcs1v15Sign::new::<Sha1>(), &public_key);
        verifier.verify(&hashed, &sig).expect("verification failed");
    }
}
