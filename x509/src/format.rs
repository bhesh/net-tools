//! X.509 Certificate Formats

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Format {
    Pem,
    Der,
}
