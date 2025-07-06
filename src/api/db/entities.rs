use super::connection::SubrosaDb;
use crate::error::Result;
use chrono::NaiveDateTime;
use fallible_iterator::FallibleIterator;
use flutter_rust_bridge::frb;
use macros::{dao, query, FromRow};
pub use rusqlite::types::Value;
pub use rusqlite::vtab::array::Array;
use rusqlite::{Row, Rows, ToSql};

pub use uuid::Uuid;

#[allow(dead_code)]
#[frb]
pub trait GetParams {
    fn has_params() -> bool {
        true
    }
    #[frb(ignore)]
    fn get_params<'a>(&'a self) -> Vec<(&'a str, &'a dyn ToSql)>;
}

#[allow(dead_code)] // Needed for derive macro
#[frb]
pub trait FromRow: Sized {
    fn is_entity() -> bool {
        true
    }
    #[frb(ignore)]
    fn from_row(row: &Row) -> Result<Self>;
    #[frb(ignore)]
    fn from_rows(rows: Rows) -> impl FallibleIterator<Item = Self> {
        rows.map(|thing| Ok(Self::from_row(thing)?))
    }
}

#[derive(FromRow, Debug, Clone)]
#[table("newsgroup")]
#[frb(opaque)]
pub struct NewsGroup {
    #[primary]
    pub uuid: Uuid,
    pub description: String,
    pub parent_hash: Option<Vec<u8>>,
    pub parent: Option<Uuid>,
    pub group_name: String,
    pub sent: bool,
}

#[dao]
pub trait TestDao {
    #[query("select * from newsgroup where uuid = :uuid")]
    fn test(&self, uuid: &Uuid) -> Result<Vec<NewsGroup>>;

    #[query("select * from newsgroup")]
    fn test_nullable(&self) -> Result<Option<NewsGroup>>;

    #[query("select * from newsgroup")]
    fn test_one(&self) -> Result<NewsGroup>;
}

impl FromRow for NaiveDateTime {
    fn from_row(row: &rusqlite::Row) -> Result<Self> {
        Ok(row.get(0)?)
    }
}

impl TestDao for SubrosaDb {}

#[cfg(test)]
mod test {}
