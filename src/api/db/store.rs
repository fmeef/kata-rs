use std::{str::FromStr, sync::Arc};

use flutter_rust_bridge::frb;
use sequoia_cert_store::{LazyCert, Store};
use sequoia_openpgp::{parse::Parse, Cert, Fingerprint, KeyHandle};

use crate::api::db::connection::SqliteDb;
use crate::error::Result;
use macros::{dao, query, FromRow};

#[derive(FromRow, Debug, Clone)]
#[table("certs")]
#[frb(opaque)]
pub struct DbCert {
    keyid: String,
    #[primary]
    fingerprint: String,
    data: Vec<u8>,
    has_private: bool,
}

#[dao]
pub trait CertDao {
    #[query("SELECT * FROM certs")]
    fn all_certs(&self) -> Result<Vec<DbCert>>;

    #[query("SELECT * FROM certs WHERE fingerprint = :fingerprint")]
    fn get_by_fingerprint(&self, fingerprint: &str) -> Result<DbCert>;

    #[query("SELECT * FROM certs WHERE keyid = :key_id")]
    fn get_by_id(&self, key_id: &str) -> Result<Vec<DbCert>>;

    #[query(
        "SELECT * FROM certs INNER JOIN userids
        ON cert_fingerprint = fingerprint WHERE email LIKE FORMAT('%%%s%%', :email)"
    )]
    fn get_by_email(&self, email: &str) -> Result<Vec<DbCert>>;

    #[query(
        "SELECT * FROM certs INNER JOIN userids
        ON cert_fingerprint = fingerprint WHERE userid LIKE FORMAT('%%%s%%', :userid)"
    )]
    fn get_by_userid(&self, userid: &str) -> Result<Vec<DbCert>>;

    #[query(
        "SELECT * FROM certs INNER JOIN userids
        ON cert_fingerprint = fingerprint WHERE domain LIKE FORMAT('%%%s%%', :domain)"
    )]
    fn get_by_domain(&self, domain: &str) -> Result<Vec<DbCert>>;
}

impl CertDao for SqliteDb {}

impl<'a> Store<'a> for SqliteDb {
    fn certs<'b>(
        &'b self,
    ) -> Box<dyn Iterator<Item = std::sync::Arc<sequoia_cert_store::LazyCert<'a>>> + 'b>
    where
        'a: 'b,
    {
        Box::new(
            self.all_certs()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|v| Cert::from_bytes(&v.data).ok())
                .map(|v| Arc::new(LazyCert::from_cert(v))),
        )
    }

    fn fingerprints<'b>(&'b self) -> Box<dyn Iterator<Item = sequoia_openpgp::Fingerprint> + 'b> {
        Box::new(
            self.all_certs()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|v| Fingerprint::from_str(&v.fingerprint).ok()),
        )
    }

    fn grep_email(
        &self,
        pattern: &str,
    ) -> sequoia_openpgp::Result<Vec<std::sync::Arc<sequoia_cert_store::LazyCert<'a>>>> {
        let mut out = Vec::new();
        for cert in self.get_by_email(pattern)? {
            let cert = Arc::new(LazyCert::from_cert(Cert::from_bytes(&cert.data)?));
            out.push(cert);
        }
        Ok(out)
    }

    fn grep_userid(
        &self,
        pattern: &str,
    ) -> sequoia_openpgp::Result<Vec<std::sync::Arc<sequoia_cert_store::LazyCert<'a>>>> {
        let mut out = Vec::new();
        for cert in self.get_by_userid(pattern)? {
            let cert = Arc::new(LazyCert::from_cert(Cert::from_bytes(&cert.data)?));
            out.push(cert);
        }
        Ok(out)
    }

    fn lookup_by_cert(
        &self,
        kh: &sequoia_openpgp::KeyHandle,
    ) -> sequoia_openpgp::Result<Vec<std::sync::Arc<sequoia_cert_store::LazyCert<'a>>>> {
        let mut out = Vec::new();
        match kh {
            KeyHandle::Fingerprint(f) => {
                let cert = self.get_by_fingerprint(&f.to_hex())?;
                out.push(Arc::new(LazyCert::from_cert(Cert::from_bytes(&cert.data)?)));
            }
            KeyHandle::KeyID(id) => {
                for cert in self.get_by_id(&id.to_hex())? {
                    out.push(Arc::new(LazyCert::from_cert(Cert::from_bytes(&cert.data)?)));
                }
            }
        };

        Ok(out)
    }

    fn lookup_by_cert_fpr(
        &self,
        fingerprint: &sequoia_openpgp::Fingerprint,
    ) -> sequoia_openpgp::Result<std::sync::Arc<sequoia_cert_store::LazyCert<'a>>> {
        let cert = self.get_by_fingerprint(&fingerprint.to_hex())?;
        let cert = Arc::new(LazyCert::from_cert(Cert::from_bytes(&cert.data)?));
        Ok(cert)
    }

    fn lookup_by_cert_or_subkey(
        &self,
        kh: &sequoia_openpgp::KeyHandle,
    ) -> sequoia_openpgp::Result<Vec<std::sync::Arc<sequoia_cert_store::LazyCert<'a>>>> {
        // TODO: what is this difference here?
        self.lookup_by_cert(kh)
    }

    fn lookup_by_email(
        &self,
        email: &str,
    ) -> sequoia_openpgp::Result<Vec<std::sync::Arc<sequoia_cert_store::LazyCert<'a>>>> {
        let mut out = Vec::new();
        for cert in self.get_by_email(email)? {
            let cert = Arc::new(LazyCert::from_cert(Cert::from_bytes(&cert.data)?));
            out.push(cert);
        }
        Ok(out)
    }

    fn lookup_by_email_domain(
        &self,
        domain: &str,
    ) -> sequoia_openpgp::Result<Vec<std::sync::Arc<sequoia_cert_store::LazyCert<'a>>>> {
        let mut out = Vec::new();
        for cert in self.get_by_domain(domain)? {
            let cert = Arc::new(LazyCert::from_cert(Cert::from_bytes(&cert.data)?));
            out.push(cert);
        }
        Ok(out)
    }

    fn lookup_by_userid(
        &self,
        userid: &sequoia_openpgp::packet::UserID,
    ) -> sequoia_openpgp::Result<Vec<std::sync::Arc<sequoia_cert_store::LazyCert<'a>>>> {
        todo!()
    }

    fn prefetch_all(&self) {
        //TODO: does this make any sense
    }

    fn prefetch_some(&self, _: &[sequoia_openpgp::KeyHandle]) {
        //TODO: does this make any sense
    }

    fn select_userid(
        &self,
        query: &sequoia_cert_store::store::UserIDQueryParams,
        pattern: &str,
    ) -> sequoia_openpgp::Result<Vec<std::sync::Arc<sequoia_cert_store::LazyCert<'a>>>> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use crate::api::db::{connection::SqliteDb, migrations::run_migrations, store::CertDao};

    #[test]
    fn test_by_email() {
        let db = rusqlite::Connection::open_in_memory().unwrap();

        let db = SqliteDb::from_conn(db);

        run_migrations(&db).unwrap();

        db.get_by_email("test").unwrap();
    }
}
