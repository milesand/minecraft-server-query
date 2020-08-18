#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Parse(#[from] ParseError),
}

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("An unspecified error occured while parsing")]
    Unspecified,
}
