//! ASN.1 CSR Objects

pub use x509_cert::request::{CertReq, CertReqInfo, ExtensionReq, Version};

#[cfg(test)]
mod tests {

    use crate::asn1::{
        der::{Decode, DecodePem, Encode, EncodePem, Format, LineEnding},
        error::Result,
        req::CertReq,
    };
    use std::{fs::File, io::Read};

    fn read(filename: &str, format: Format) -> Result<CertReq> {
        let mut data = Vec::new();
        let mut file = File::open(filename).expect("error opening file");
        file.read_to_end(&mut data).expect("error reading file");
        Ok(match format {
            Format::Der => CertReq::from_der(&data)?,
            Format::Pem => CertReq::from_pem(&data)?,
        })
    }

    #[test]
    fn read_good_der() {
        let cert = read("testdata/rsa2048-csr.der", Format::Der);
        match cert {
            Ok(_) => {}
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn read_bad_der() {
        let cert = read("testdata/rsa2048-csr.pem", Format::Der);
        match cert {
            Ok(_) => panic!("CSR was read"),
            Err(_) => {}
        }
    }

    #[test]
    fn read_good_pem() {
        let cert = read("testdata/rsa2048-csr.pem", Format::Pem);
        match cert {
            Ok(_) => {}
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn read_bad_pem() {
        let cert = read("testdata/rsa2048-csr.der", Format::Pem);
        match cert {
            Ok(_) => panic!("CSR was read"),
            Err(_) => {}
        }
    }

    #[test]
    fn write_der() {
        let mut data = Vec::new();
        let mut file = File::open("testdata/rsa2048-csr.der").expect("error opening file");
        file.read_to_end(&mut data).expect("error reading file");
        let cert = CertReq::from_der(&data).expect("error reading DER CSR");
        let der = cert.to_der().expect("error formatting DER CSR");
        assert_eq!(&der, &data);
    }

    #[test]
    fn write_pem() {
        let mut data = Vec::new();
        let mut file = File::open("testdata/rsa2048-csr.pem").expect("error opening file");
        file.read_to_end(&mut data).expect("error reading file");
        let cert = CertReq::from_pem(&data).expect("error reading PEM CSR");
        let pem = cert
            .to_pem(LineEnding::CRLF)
            .expect("error formatting PEM CSR");
        assert_eq!(pem.as_bytes(), &data);
    }
}
