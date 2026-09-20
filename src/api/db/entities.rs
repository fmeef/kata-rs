use super::connection::SqliteDb;
use crate::error::AppResult;
use chrono::NaiveDateTime;
use fallible_iterator::FallibleIterator;
use flutter_rust_bridge::frb;
use macros::query;
use macros::{dao, FromRow};
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
    fn from_row(row: &Row) -> AppResult<Self>;
    #[frb(ignore)]
    fn from_rows(rows: Rows) -> impl FallibleIterator<Item = Self> {
        rows.map(|thing| Ok(Self::from_row(thing)?))
    }
}

/// Example entity
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

/// Example dao
#[dao]
pub trait TestDao {
    #[query("select * from newsgroup where uuid = :uuid")]
    fn test(&self, uuid: &Uuid) -> AppResult<Vec<NewsGroup>>;

    #[query("select * from newsgroup")]
    fn test_nullable(&self) -> AppResult<Option<NewsGroup>>;

    #[query("select * from newsgroup")]
    fn test_one(&self) -> AppResult<NewsGroup>;
}

impl FromRow for NaiveDateTime {
    fn from_row(row: &rusqlite::Row) -> AppResult<Self> {
        Ok(row.get(0)?)
    }
}

impl TestDao for SqliteDb {}

#[cfg(test)]
mod test {}
