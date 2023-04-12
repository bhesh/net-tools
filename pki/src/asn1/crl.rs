//! ASN.1 X.509 CRL Objects

pub use x509_cert::{
    crl::{CertificateList, RevokedCert, TbsCertList},
    Version,
};

#[cfg(test)]
mod tests {

    use crate::asn1::{
        crl::CertificateList,
        der::{Decode, Encode},
    };
    use std::{fs::File, io::Read};

    #[test]
    fn read_der() {
        let mut data = Vec::new();
        let mut file = File::open("testdata/GoodCACRL.crl").expect("error opening file");
        file.read_to_end(&mut data).expect("error reading file");
        let crl = CertificateList::from_der(&data);
        match crl {
            Ok(_) => {}
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn write_der() {
        let mut data = Vec::new();
        let mut file = File::open("testdata/GoodCACRL.crl").expect("error opening file");
        file.read_to_end(&mut data).expect("error reading file");
        let crl = CertificateList::from_der(&data).expect("error loading CRL");
        let der = crl.to_der().expect("error formatting CRL");
        assert_eq!(&der, &data);
    }
}
