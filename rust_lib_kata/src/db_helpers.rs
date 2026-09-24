use crate::{api::db::entities::FromRow, error::AppResult};
use fallible_iterator::{FallibleIterator, IteratorExt};
use flutter_rust_bridge::frb;
use rusqlite::Row;

impl FromRow for i64 {
    fn from_row(row: &Row) -> AppResult<Self> {
        Ok(row.get(0)?)
    }
}

#[allow(dead_code)]
#[frb(ignore)]
pub(crate) trait IntoModel<T> {
    #[frb(ignore)]
    fn into_model(&self) -> AppResult<T>;
    #[frb(ignore)]
    fn model_iter(self) -> impl FallibleIterator<Item = T>;
}

impl<'a, T> IntoModel<T> for Row<'a>
where
    T: FromRow,
{
    fn into_model(&self) -> AppResult<T> {
        T::from_row(self)
    }
    fn model_iter(self) -> impl FallibleIterator<Item = T> {
        [T::from_row(&self)].into_iter().transpose_into_fallible()
    }
}
