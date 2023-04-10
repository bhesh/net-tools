//! TLS Tool

use rustls::{ClientConfig, ClientConnection, Stream};
use std::{io::Write, net::TcpStream, sync::Arc};
use x509_cert::{der::Decode, Certificate};

#[derive(Debug)]
enum Error {
    DnsNameError,
    Tls(rustls::Error),
    Io(std::io::Error),
    Der(x509_cert::der::Error),
}

impl From<rustls::client::InvalidDnsNameError> for Error {
    fn from(_: rustls::client::InvalidDnsNameError) -> Self {
        Error::DnsNameError
    }
}

impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Error::Tls(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<x509_cert::der::Error> for Error {
    fn from(e: x509_cert::der::Error) -> Self {
        Error::Der(e)
    }
}

struct Verifier;

impl rustls::client::ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::client::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

fn main() -> Result<(), Error> {
    let tls = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(Verifier))
        .with_no_client_auth();
    let server_name = "google.com".try_into()?;
    let mut conn = ClientConnection::new(Arc::new(tls), server_name)?;
    let mut sock = TcpStream::connect("google.com:443")?;
    let mut tls = Stream::new(&mut conn, &mut sock);
    tls.flush()?; // complete the handshake
    if let Some(certificates) = conn.peer_certificates() {
        for der in certificates {
            let cert = Certificate::from_der(der.as_ref())?;
            println!("Subject: {}", cert.tbs_certificate.subject);
            println!("Issuer: {}", cert.tbs_certificate.issuer);
            println!("Not Before: {}", cert.tbs_certificate.validity.not_before);
            println!("Not After: {}", cert.tbs_certificate.validity.not_after);
            println!("");
        }
    }
    Ok(())
}
