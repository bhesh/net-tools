//! ASN.1 X.509 Certificate Objects

pub use x509_cert::{Certificate, PkiPath, TbsCertificate, Version};

#[cfg(test)]
mod tests {

    use crate::asn1::{
        cert::Certificate,
        der::{Decode, DecodePem, Encode, EncodePem, Format, LineEnding},
        error::Result,
    };
    use std::{fs::File, io::Read};

    fn read(filename: &str, format: Format) -> Result<Certificate> {
        let mut data = Vec::new();
        let mut file = File::open(filename).expect("error opening file");
        file.read_to_end(&mut data).expect("error reading file");
        Ok(match format {
            Format::Der => Certificate::from_der(&data)?,
            Format::Pem => Certificate::from_pem(&data)?,
        })
    }

    #[test]
    fn read_good_der() {
        let cert = read("testdata/rsa2048-crt.der", Format::Der);
        match cert {
            Ok(_) => {}
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn read_bad_der() {
        let cert = read("testdata/rsa2048-crt.pem", Format::Der);
        match cert {
            Ok(_) => panic!("certificate was read"),
            Err(_) => {}
        }
    }

    #[test]
    fn read_good_pem() {
        let cert = read("testdata/rsa2048-crt.pem", Format::Pem);
        match cert {
            Ok(_) => {}
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn read_bad_pem() {
        let cert = read("testdata/rsa2048-crt.der", Format::Pem);
        match cert {
            Ok(_) => panic!("certificate was read"),
            Err(_) => {}
        }
    }

    #[test]
    fn write_der() {
        let mut data = Vec::new();
        let mut file = File::open("testdata/rsa2048-crt.der").expect("error opening file");
        file.read_to_end(&mut data).expect("error reading file");
        let cert = Certificate::from_der(&data).expect("error reading DER certificate");
        let der = cert.to_der().expect("error formatting DER certificate");
        assert_eq!(&der, &data);
    }

    #[test]
    fn write_pem() {
        let mut data = Vec::new();
        let mut file = File::open("testdata/rsa2048-crt.pem").expect("error opening file");
        file.read_to_end(&mut data).expect("error reading file");
        let cert = Certificate::from_pem(&data).expect("error reading PEM certificate");
        let pem = cert
            .to_pem(LineEnding::CRLF)
            .expect("error formatting PEM certificate");
        assert_eq!(pem.as_bytes(), &data);
    }
}
