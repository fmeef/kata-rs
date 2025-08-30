pub(crate) type Result<T> = std::result::Result<T, InternalErr>;

#[derive(thiserror::Error, Debug)]
pub enum InternalErr {
    #[error("Invalid row")]
    InvalidRow,
    #[error("{0}")]
    SqliteError(#[from] rusqlite::Error),
    #[error("{0}")]
    MigrationError(#[from] rusqlite_migration::Error),
    #[error("{0}")]
    Anyhow(#[from] anyhow::Error),
}

impl From<InternalErr> for rusqlite::Error {
    fn from(_: InternalErr) -> Self {
        rusqlite::Error::InvalidQuery
    }
}
