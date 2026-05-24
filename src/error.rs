use latkerlo_jvotci::Jvonunfli;
use std::ops::Range;
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
    #[error("{0}")]
    Generic(&'static str),
    #[error("{0}")]
    NotFound(&'static str),
    #[error("KeyID is not supported for this action")]
    FingerprintRequired,
    #[error("Lojban error {0}")]
    Lojban(Jvonunfli),
    #[error("Key offset out of range")]
    KeySlice,
    #[error("Overlapping ranges {0} len={1:?}")]
    KeyOverlap(&'static str, Range<usize>),
    #[error("Identicon size error")]
    IdenticonSize,
    #[error("Not representable as {0}")]
    NotRepr(&'static str),
    #[error("Hex encode error")]
    Hex(#[from] hex::FromHexError),
}

impl From<InternalErr> for rusqlite::Error {
    fn from(_: InternalErr) -> Self {
        rusqlite::Error::InvalidQuery
    }
}
