use lazy_static::lazy_static;
use rusqlite_migration::Migrations;

use crate::error::Result;

use super::connection::SubrosaDb;

lazy_static! {
    static ref MIGRATIONS: Migrations<'static> = Migrations::new(vec![]);
}

pub fn run_migrations(conn: &SubrosaDb) -> Result<()> {
    let mut conn = conn.0.conn.lock().unwrap();
    conn.pragma_update_and_check(None, "journal_mode", &"WAL", |_| Ok(()))?;
    MIGRATIONS.to_latest(&mut conn)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::MIGRATIONS;

    #[test]
    fn check_migrations() {
        MIGRATIONS.validate().unwrap()
    }
}
