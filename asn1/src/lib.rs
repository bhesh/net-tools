//! x509 Library

use crate::error;
use const_oid::db;
use std::{fs, io::Read, path::PathBuf};
use x509_cert::{
    der::{Decode, DecodePem},
    Certificate,
};

fn parse_certificate(file: &dyn Read, max_size: u64) -> error::Result<Certificate> {
    let mut data = [0; max_size];
    handle.read(&mut data)?;
    Certificate::from_
}
