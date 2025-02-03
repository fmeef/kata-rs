pub(crate) type Result<T> = std::result::Result<T, SubrosaErr>;

#[derive(thiserror::Error, Debug)]
pub enum SubrosaErr {
    #[error("Invalid row")]
    InvalidRow,
    #[error("{0}")]
    SqliteError(#[from] rusqlite::Error),
    #[error("{0}")]
    MigrationError(#[from] rusqlite_migration::Error),
    #[error("{0}")]
    DecodeError(#[from] prost::DecodeError),
    #[error("{0}")]
    EncodeError(#[from] prost::EncodeError),
    #[error("Message parse error")]
    ParseError,
}

impl From<SubrosaErr> for rusqlite::Error {
    fn from(_: SubrosaErr) -> Self {
        rusqlite::Error::InvalidQuery
    }
}
