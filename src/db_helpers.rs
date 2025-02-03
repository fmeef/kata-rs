use crate::error::Result;
use fallible_iterator::{FallibleIterator, IteratorExt};

use rusqlite::{Row, Rows, ToSql};

#[allow(dead_code)] // Needed for derive macro
pub(crate) trait FromRow: Sized {
    fn from_row(row: &Row) -> Result<Self>;
    fn from_rows(rows: Rows) -> impl FallibleIterator<Item = Self> {
        rows.map(|thing| Ok(Self::from_row(thing)?))
    }
}

impl FromRow for i64 {
    fn from_row(row: &Row) -> Result<Self> {
        Ok(row.get(0)?)
    }
}

#[allow(dead_code)]
pub(crate) trait GetParams {
    fn get_params<'a>(&'a self) -> Vec<(&'a str, &'a dyn ToSql)>;
}

#[allow(dead_code)]
pub(crate) trait IntoModel<T> {
    fn into_model(&self) -> Result<T>;
    fn model_iter(self) -> impl FallibleIterator<Item = T>;
}

impl<'a, T> IntoModel<T> for Row<'a>
where
    T: FromRow,
{
    fn into_model(&self) -> Result<T> {
        T::from_row(self)
    }
    fn model_iter(self) -> impl FallibleIterator<Item = T> {
        [T::from_row(&self)].into_iter().transpose_into_fallible()
    }
}
