use bstr::BStr;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Parse(#[from] ParseError),
}

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("Datagram was too short to be valid")]
    TooShort,
    #[error("Expected type byte {}, got {} instead", .expected, .got)]
    InvalidType { expected: u8, got: u8 },
    #[error("Expected Session ID {}, got {} instead", .expected, .got)]
    SessionIdMismatch { expected: u32, got: u32 },
    #[error("Datagram ended unexpectedly")]
    UnexpectedEndOfData,
    #[error("Failed to parse {:?} as {}", <&BStr>::from(.bytes.as_slice()), .ty)]
    PartParseFailed {
        bytes: Vec<u8>,
        ty: &'static str,
        #[source]
        source: Option<Box<dyn std::error::Error>>,
    },
    #[error("Expected key {:?}, got {:?} instead", <&BStr>::from(*.expected), <&BStr>::from(.got.as_slice()))]
    UnexpectedKey {
        expected: &'static [u8],
        got: Vec<u8>,
    },
}
