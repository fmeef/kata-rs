use lazy_static::lazy_static;
use rusqlite_migration::{Migrations, M};

use crate::error::Result;

use super::connection::SubrosaDb;

lazy_static! {
    static ref MIGRATIONS: Migrations<'static> = Migrations::new(vec![M::up(
        r#"CREATE TABLE IF NOT EXISTS `newsgroup` (
            `uuid` TEXT NOT NULL,
            `description` TEXT NOT NULL DEFAULT '',
            `parent_hash` BLOB,
            `parent` TEXT, `group_name`
            TEXT NOT NULL,
            `sent` BOOLEAN NOT NULL DEFAULT 'false',
            PRIMARY KEY(`uuid`)
            );
            CREATE INDEX IF NOT EXISTS `index_newsgroup_parent` ON `newsgroup` (`parent`);
            CREATE TABLE IF NOT EXISTS `posts` (
                `header` TEXT,
                `body` TEXT,
                `sig` BLOB,
                `receive_date`
                INTEGER NOT NULL DEFAULT 0,
                `post_id` TEXT NOT NULL,
                `identity` TEXT,
                `parent_group` TEXT NOT NULL,
                `sent` BOOLEAN NOT NULL DEFAULT 'false',
                PRIMARY KEY(`post_id`)
                );

                CREATE TABLE IF NOT EXISTS `identity` (
                `uuid` TEXT NOT NULL,
                `fingerprint` TEXT,
                `user_name` TEXT,
                `bio` TEXT,
                `owned` INTEGER,
                `image_bytes` BLOB,
                PRIMARY KEY(`uuid`)
                );

                CREATE TABLE IF NOT EXISTS `User` (
                    `identity` TEXT NOT NULL,
                    `user_name` TEXT NOT NULL,
                    `bio` TEXT NOT NULL,
                    `owned` INTEGER NOT NULL,
                    `image_bytes` BLOB, PRIMARY KEY(`identity`)
                );
        "#,
    )]);
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
