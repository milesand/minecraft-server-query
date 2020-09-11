//! Error types.

/// Query API Error type.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// `std::io` Error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Error while parsing.
    #[error(transparent)]
    Parse(#[from] ParseError),
}

/// Parsing errors.
#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    /// The input was invalid, and could not be parsed as requested kind of data.
    #[error("Failed to parse input as {}", .requested_kind)]
    MalformedInput { requested_kind: &'static str },

    /// The input is potentially valid, but the end of input was reached.
    ///
    /// If this error occured with full buffer, you should try reading the datagram with a larger buffer and try again.
    #[error("End of input reached unexpectedly")]
    UnexpectedEndOfInput,
}
