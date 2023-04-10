//! x509 Parser

use crate::error;
use clap::{Parser, ValueEnum};
use const_oid::db;
use std::{fs, io::Read, path::PathBuf};
use x509_cert::{
    der::{Decode, DecodePem},
    Certificate,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long = "in", value_name = "FILE")]
    infile: Option<PathBuf>,

    #[arg(long = "out", value_name = "FILE")]
    outfile: Option<PathBuf>,

    #[arg(long, value_name = "FORMAT", value_enum, default_value_t = Format::Pem)]
    inform: Format,

    #[arg(long, value_name = "FORMAT", value_enum, default_value_t = Format::Pem)]
    outform: Format,

    #[arg(long, default_value_t = false)]
    text: bool,
}

fn print_certificate(cert: &Certificate) {
    println!("Certificate:");
    println!("    Data:");
    println!("        Version: {:?}", cert.tbs_certificate.version);
    println!("        Serial Number:");
    println!("            {}", cert.tbs_certificate.serial_number);
    let signature_algo = match db::DB.by_oid(&cert.tbs_certificate.signature.oid) {
        Some(name) => String::from(name),
        None => format!("{}", cert.tbs_certificate.signature.oid),
    };
    println!("        Signature Algorithm: {}", signature_algo);
    println!("        Issuer: {}", cert.tbs_certificate.issuer);
    println!("        Validity:");
    let validity = cert.tbs_certificate.validity;
    println!("            notBefore: {}", validity.not_before);
    println!("            notAfter: {}", validity.not_after);
    println!("        Subject: {}", cert.tbs_certificate.subject);
    println!("        Signature: {:?}", cert.tbs_certificate.signature);
}

fn main() -> Result<(), Error> {
    let args = Args::parse();
    let mut data = Vec::new();
    match args.infile {
        Some(infile) => {
            let mut handle = fs::File::open(infile)?;
            handle.read_to_end(&mut data)?;
        }
        None => {
            let mut handle = std::io::stdin();
            handle.read_to_end(&mut data)?;
        }
    }
    let cert = match args.inform {
        Format::Pem => Certificate::from_pem(&data)?,
        Format::Der => Certificate::from_der(&data)?,
    };
    if args.text {
        print_certificate(&cert);
    }
    Ok(())
}
