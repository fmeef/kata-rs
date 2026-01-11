use lazy_static::lazy_static;
use rusqlite_migration::{Migrations, M};

use crate::error::Result;

use super::connection::SqliteDb;

lazy_static! {
    static ref MIGRATIONS: Migrations<'static> = Migrations::new(vec![
        M::up(
            r#"
        -- A table for all the certificates.
        CREATE TABLE certs (
            keyid TEXT NOT NULL,
            fingerprint TEXT PRIMARY KEY NOT NULL,
            data BLOB NOT NULL
        );

        CREATE INDEX IF NOT EXISTS certs_keyid
            ON certs (keyid);

        -- A mapping from subkey key IDs and fingerprints to certs.
        CREATE TABLE keys (
            cert_fingerprint TEXT NOT NULL,
            keyid TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            FOREIGN KEY(cert_fingerprint) REFERENCES certs(fingerprint) ON DELETE CASCADE,
            UNIQUE(cert_fingerprint, fingerprint)
        );

        CREATE INDEX IF NOT EXISTS keys_fingerprint
            ON keys (fingerprint);
        CREATE INDEX IF NOT EXISTS keys_keyid
            ON keys (keyid);

        -- A mapping from user IDs to certs.
        CREATE TABLE userids (
            cert_fingerprint TEXT NOT NULL,
            userid TEXT NOT NULL,
            email TEXT,
            domain TEXT,
            FOREIGN KEY(cert_fingerprint) REFERENCES certs(fingerprint) ON DELETE CASCADE,
            UNIQUE(cert_fingerprint, userid)
        );

        CREATE INDEX IF NOT EXISTS userids_userid
            ON userids (userid);
        CREATE INDEX IF NOT EXISTS userids_email
            ON userids (email);
        CREATE INDEX IF NOT EXISTS userids_domain
            ON userids (domain);
        "#
        )
        .down(
            r#"
        DROP TABLE IF EXISTS userids;
        DROP TABLE IF EXISTS keys;
        DROP TABLE IF EXISTS certs;
        DROP INDEX certs_keyid;
        DROP INDEX userids_domain;
        DROP INDEX userids_email;
        DROP INDEX userids_userid;
        DROP INDEX keys_keyid;
        DROP INDEX keys_fingerprint;
        "#
        ),
        M::up(
            r#"
        ALTER TABLE certs ADD COLUMN role TEXT;
        CREATE INDEX IF NOT EXISTS role_idx
            ON certs (role);
        "#
        )
        .down(
            r#"
            ALTER TABLE certs DROP COLUMN role;
            DROP INDEX role_idx;
            "#
        ),
        M::up(
            r#"
        ALTER TABLE certs ADD COLUMN online BOOLEAN NOT NULL DEFAULT '0';
        "#
        )
        .down(
            r#"
            ALTER TABLE certs DROP COLUMN online;
            "#
        )
    ]);
}

pub fn run_migrations(conn: &SqliteDb) -> Result<()> {
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
