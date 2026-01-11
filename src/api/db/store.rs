use flutter_rust_bridge::frb;
use sequoia_openpgp::serialize::{MarshalInto, TSK};
use sequoia_openpgp::{parse::Parse, Cert};

use crate::api::db::connection::SqliteDb;
use crate::api::pgp::cert::PgpCert;
use crate::error::Result;
use macros::{dao, query, FromRow};

#[dao]
pub trait CertDao {
    #[query("SELECT * FROM certs")]
    fn all_certs(&self) -> Result<Vec<PgpDataCert>>;

    #[query("SELECT * FROM certs")]
    fn all_owned_certs(&self) -> Result<Vec<PgpDataCert>>;

    #[query(
        "SELECT * FROM certs INNER JOIN userids
        ON cert_fingerprint = fingerprint WHERE userid LIKE :userid"
    )]
    fn search_owned_certs(&self, userid: &str) -> Result<Vec<PgpDataCert>>;

    #[query("SELECT * FROM certs WHERE fingerprint = :fingerprint")]
    fn get_by_fingerprint(&self, fingerprint: &str) -> Result<PgpDataCert>;

    #[query("SELECT * FROM certs WHERE keyid = :key_id")]
    fn get_by_id(&self, key_id: &str) -> Result<Vec<PgpDataCert>>;

    #[query(
        "SELECT * FROM certs INNER JOIN userids
        ON cert_fingerprint = fingerprint WHERE email = :email"
    )]
    fn get_by_email(&self, email: &str) -> Result<Vec<PgpDataCert>>;

    #[query(
        "SELECT * FROM certs INNER JOIN userids
        ON cert_fingerprint = fingerprint WHERE userid = :userid"
    )]
    fn get_by_userid(&self, userid: &str) -> Result<Vec<PgpDataCert>>;

    #[query(
        "SELECT * FROM certs INNER JOIN userids
        ON cert_fingerprint = fingerprint WHERE email LIKE FORMAT('%%%s%%', :email)"
    )]
    fn grep_by_email(&self, email: &str) -> Result<Vec<PgpDataCert>>;

    #[query(
        "SELECT * FROM certs INNER JOIN userids
        ON cert_fingerprint = fingerprint WHERE userid LIKE FORMAT('%%%s%%', :userid)"
    )]
    fn grep_by_userid(&self, userid: &str) -> Result<Vec<PgpDataCert>>;

    #[query(
        "SELECT * FROM certs INNER JOIN userids
        ON cert_fingerprint = fingerprint WHERE email LIKE FORMAT('%%%s', :email)"
    )]
    fn grep_by_email_anchor_end(&self, email: &str) -> Result<Vec<PgpDataCert>>;

    #[query(
        "SELECT * FROM certs INNER JOIN userids
        ON cert_fingerprint = fingerprint WHERE userid LIKE FORMAT('%%%s', :userid)"
    )]
    fn grep_by_userid_anchor_end(&self, userid: &str) -> Result<Vec<PgpDataCert>>;

    #[query(
        "SELECT * FROM certs INNER JOIN userids
        ON cert_fingerprint = fingerprint WHERE email LIKE FORMAT('%s%%', :email)"
    )]
    fn grep_by_email_anchor_start(&self, email: &str) -> Result<Vec<PgpDataCert>>;

    #[query(
        "SELECT * FROM certs INNER JOIN userids
        ON cert_fingerprint = fingerprint WHERE userid LIKE FORMAT('%s%%', :userid)"
    )]
    fn grep_by_userid_anchor_start(&self, userid: &str) -> Result<Vec<PgpDataCert>>;

    #[query(
        "SELECT * FROM certs INNER JOIN userids
        ON cert_fingerprint = fingerprint WHERE domain LIKE FORMAT('%%%s%%', :domain)"
    )]
    fn get_by_domain(&self, domain: &str) -> Result<Vec<PgpDataCert>>;

    #[query("DELETE FROM certs WHERE fingerprint = :fingerprint")]
    fn delete_by_fingerprint(&self, fingerprint: &str) -> Result<()>;

    #[query("SELECT fingerprint FROM certs WHERE role = :role")]
    fn get_fingerprint_for_role(&self, role: &str) -> Result<Option<OnlyFingerprint>>;

    #[query("UPDATE certs SET role = :role WHERE fingerprint = :fingerprint")]
    fn update_role(&self, fingerprint: &str, role: &str) -> Result<()>;

    #[query("UPDATE certs SET role = NULL where role = :role")]
    fn clear_role(&self, role: &str) -> Result<()>;

    #[query("SELECT online FROM certs WHERE fingerprint = :fingerprint")]
    fn is_online(&self, fingerprint: &str) -> Result<Option<OnlyOnline>>;
}

#[derive(Clone, FromRow)]
pub struct OnlyFingerprint {
    #[primary]
    pub fingerprint: String,
}

#[derive(Clone, FromRow)]
pub struct OnlyOnline {
    #[primary]
    pub online: bool,
}

impl CertDao for SqliteDb {}

impl SqliteDb {
    pub fn check_online(&self, fingerprint: &str) -> bool {
        match self.is_online(fingerprint) {
            Ok(Some(v)) => v.online,
            _ => false,
        }
    }
}

#[derive(FromRow, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[table("certs")]
#[frb(opaque)]
pub struct PgpDataCert {
    keyid: String,
    #[primary]
    pub(crate) fingerprint: String,
    data: Vec<u8>,
    role: Option<String>,
    online: bool,
}

// impl StoreUpdate for SqliteDb {
//     fn update(&self, cert: Arc<LazyCert<'a>>) -> sequoia_openpgp::Result<()> {

//     }

//     fn update_by(&self, cert: Arc<LazyCert<'a>>,
//                      merge_strategy: &dyn sequoia_cert_store::store::MergeCerts<'a>)
//             -> sequoia_openpgp::Result<Arc<LazyCert<'a>>> {

//     }
// }

impl PgpDataCert {
    pub(crate) fn merge(&self, cert: Cert) -> anyhow::Result<Cert> {
        let secret = Cert::from_bytes(&self.data)?;
        secret.merge_public(cert)
    }

    pub(crate) fn as_tsk(cert: PgpCert, tsk: TSK) -> Result<Self> {
        let data = tsk.export_to_vec()?;
        let out = Self {
            keyid: cert.keyid,
            fingerprint: cert.fingerprint,
            online: cert.online,
            role: None,
            data,
        };

        Ok(out)
    }
}

// impl<'a> Store<'a> for SqliteDb {
//     fn certs<'b>(
//         &'b self,
//     ) -> Box<dyn Iterator<Item = std::sync::Arc<sequoia_cert_store::LazyCert<'a>>> + 'b>
//     where
//         'a: 'b,
//     {
//         Box::new(
//             self.all_certs()
//                 .unwrap_or_default()
//                 .into_iter()
//                 .filter_map(|v| Cert::from_bytes(&v.data).ok())
//                 .map(|v| Arc::new(LazyCert::from_cert(v))),
//         )
//     }

//     fn fingerprints<'b>(&'b self) -> Box<dyn Iterator<Item = sequoia_openpgp::Fingerprint> + 'b> {
//         Box::new(
//             self.all_certs()
//                 .unwrap_or_default()
//                 .into_iter()
//                 .filter_map(|v| Fingerprint::from_str(&v.fingerprint).ok()),
//         )
//     }

//     fn grep_email(
//         &self,
//         pattern: &str,
//     ) -> sequoia_openpgp::Result<Vec<std::sync::Arc<sequoia_cert_store::LazyCert<'a>>>> {
//         let mut out = Vec::new();
//         for cert in self.grep_by_email(pattern)? {
//             let cert = Arc::new(LazyCert::from_cert(Cert::from_bytes(&cert.data)?));
//             out.push(cert);
//         }
//         Ok(out)
//     }

//     fn grep_userid(
//         &self,
//         pattern: &str,
//     ) -> sequoia_openpgp::Result<Vec<std::sync::Arc<sequoia_cert_store::LazyCert<'a>>>> {
//         let mut out = Vec::new();
//         for cert in self.grep_by_userid(pattern)? {
//             let cert = Arc::new(LazyCert::from_cert(Cert::from_bytes(&cert.data)?));
//             out.push(cert);
//         }
//         Ok(out)
//     }

//     fn lookup_by_cert(
//         &self,
//         kh: &sequoia_openpgp::KeyHandle,
//     ) -> sequoia_openpgp::Result<Vec<std::sync::Arc<sequoia_cert_store::LazyCert<'a>>>> {
//         let mut out = Vec::new();
//         match kh {
//             KeyHandle::Fingerprint(f) => {
//                 let cert = self.get_by_fingerprint(&f.to_hex())?;
//                 out.push(Arc::new(LazyCert::from_cert(Cert::from_bytes(&cert.data)?)));
//             }
//             KeyHandle::KeyID(id) => {
//                 for cert in self.get_by_id(&id.to_hex())? {
//                     out.push(Arc::new(LazyCert::from_cert(Cert::from_bytes(&cert.data)?)));
//                 }
//             }
//         };

//         Ok(out)
//     }

//     fn lookup_by_cert_fpr(
//         &self,
//         fingerprint: &sequoia_openpgp::Fingerprint,
//     ) -> sequoia_openpgp::Result<std::sync::Arc<sequoia_cert_store::LazyCert<'a>>> {
//         let cert = self.get_by_fingerprint(&fingerprint.to_hex())?;
//         let cert = Arc::new(LazyCert::from_cert(Cert::from_bytes(&cert.data)?));
//         Ok(cert)
//     }

//     fn lookup_by_cert_or_subkey(
//         &self,
//         kh: &sequoia_openpgp::KeyHandle,
//     ) -> sequoia_openpgp::Result<Vec<std::sync::Arc<sequoia_cert_store::LazyCert<'a>>>> {
//         // TODO: what is this difference here?
//         self.lookup_by_cert(kh)
//     }

//     fn lookup_by_email(
//         &self,
//         email: &str,
//     ) -> sequoia_openpgp::Result<Vec<std::sync::Arc<sequoia_cert_store::LazyCert<'a>>>> {
//         let mut out = Vec::new();
//         for cert in self.get_by_email(email)? {
//             let cert = Arc::new(LazyCert::from_cert(Cert::from_bytes(&cert.data)?));
//             out.push(cert);
//         }
//         Ok(out)
//     }

//     fn lookup_by_email_domain(
//         &self,
//         domain: &str,
//     ) -> sequoia_openpgp::Result<Vec<std::sync::Arc<sequoia_cert_store::LazyCert<'a>>>> {
//         let mut out = Vec::new();
//         for cert in self.get_by_domain(domain)? {
//             let cert = Arc::new(LazyCert::from_cert(Cert::from_bytes(&cert.data)?));
//             out.push(cert);
//         }
//         Ok(out)
//     }

//     fn lookup_by_userid(
//         &self,
//         userid: &sequoia_openpgp::packet::UserID,
//     ) -> sequoia_openpgp::Result<Vec<std::sync::Arc<sequoia_cert_store::LazyCert<'a>>>> {
//         let mut out = BTreeSet::new();
//         if let Some(name) = userid.name()? {
//             for cert in self.get_by_userid(name)? {
//                 out.insert(cert);
//             }
//         }

//         if let Some(email) = userid.email()? {
//             for cert in self.get_by_email(email)? {
//                 out.insert(cert);
//             }
//         }

//         Ok(out
//             .into_iter()
//             .filter_map(|v| Cert::from_bytes(&v.data).ok())
//             .map(|v| Arc::new(LazyCert::from_cert(v)))
//             .collect())
//     }

//     fn prefetch_all(&self) {
//         //TODO: does this make any sense
//     }

//     fn prefetch_some(&self, _: &[sequoia_openpgp::KeyHandle]) {
//         //TODO: does this make any sense
//     }

//     fn select_userid(
//         &self,
//         query: &sequoia_cert_store::store::UserIDQueryParams,
//         pattern: &str,
//     ) -> sequoia_openpgp::Result<Vec<std::sync::Arc<sequoia_cert_store::LazyCert<'a>>>> {
//         let mut out = Vec::new();
//         let res = if query.email() {
//             if query.anchor_end() {
//                 self.grep_by_email_anchor_end(pattern)?
//             } else if query.anchor_start() {
//                 self.grep_by_email_anchor_start(pattern)?
//             } else {
//                 self.grep_by_email(pattern)?
//             }
//         } else {
//             if query.anchor_end() {
//                 self.grep_by_userid_anchor_end(pattern)?
//             } else if query.anchor_start() {
//                 self.grep_by_userid_anchor_start(pattern)?
//             } else {
//                 self.grep_by_userid(pattern)?
//             }
//         };

//         for cert in res {
//             let cert = Arc::new(LazyCert::from_cert(Cert::from_bytes(&cert.data)?));
//             out.push(cert);
//         }

//         Ok(out)
//     }
// }

#[cfg(test)]
mod test {
    use crate::api::db::{connection::SqliteDb, migrations::run_migrations, store::CertDao};

    #[test]
    fn test_by_email() {
        let db = rusqlite::Connection::open_in_memory().unwrap();

        let db = SqliteDb::from_conn(db);

        run_migrations(&db).unwrap();

        db.grep_by_email("test").unwrap();
    }

    #[test]
    fn only_fingerprint() {
        let db = rusqlite::Connection::open_in_memory().unwrap();

        let db = SqliteDb::from_conn(db);

        run_migrations(&db).unwrap();

        let v = db.get_fingerprint_for_role("test").unwrap();

        assert!(v.is_none());
    }
}
