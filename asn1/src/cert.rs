//! ASN.1 X.509

use crate::{error, Format};
use std::io::Read;
use x509_cert::{
    der::{Decode, DecodePem},
    Certificate,
};

pub fn load(file: &mut dyn Read, format: Format) -> error::Result<Certificate> {
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(match format {
        Format::Pem => Certificate::from_pem(&data)?,
        Format::Der => Certificate::from_der(&data)?,
    })
}

pub fn load_der(file: &mut dyn Read) -> error::Result<Certificate> {
    load(file, Format::Der)
}

pub fn load_pem(file: &mut dyn Read) -> error::Result<Certificate> {
    load(file, Format::Pem)
}

#[cfg(test)]
mod tests {

    use crate::cert;
    use std::fs::File;

    #[test]
    fn load_good_der() {
        let mut file = File::open("testdata/amazon.der").expect("error opening file");
        let cert = cert::load_der(&mut file);
        match cert {
            Ok(_) => {}
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    #[should_panic]
    fn load_bad_der() {
        let mut file = File::open("testdata/amazon.pem").expect("error opening file");
        let cert = cert::load_der(&mut file);
        match cert {
            Ok(_) => {}
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn load_good_pem() {
        let mut file = File::open("testdata/amazon.pem").expect("error opening file");
        let cert = cert::load_pem(&mut file);
        match cert {
            Ok(_) => {}
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    #[should_panic]
    fn load_bad_pem() {
        let mut file = File::open("testdata/amazon.der").expect("error opening file");
        let cert = cert::load_pem(&mut file);
        match cert {
            Ok(_) => {}
            Err(e) => panic!("{:?}", e),
        }
    }
}
