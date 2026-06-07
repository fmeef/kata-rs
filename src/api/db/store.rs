use std::collections::{BTreeMap, BTreeSet};

use flutter_rust_bridge::frb;
use sequoia_openpgp::serialize::{MarshalInto, TSK};
use sequoia_openpgp::{parse::Parse, Cert};

use super::utils::HexConvert;
use crate::api::db::connection::SqliteDb;
use crate::api::pgp::cert::PgpCert;
use crate::api::pgp::circles::app::MemberTag;
use crate::api::pgp::circles::CircleOr;
use crate::api::pgp::UserHandle;
use crate::error::{InternalErr, Result};
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

    #[query(
        "SELECT id, member_id, parent_id, tag, circle_type, author, sig
        FROM circles LEFT JOIN circle_members ON member_id=id"
    )]
    fn get_circles_join(&self) -> Result<Vec<CircleWithMembers>>;

    #[query(
        "SELECT id, member_id, parent_id, tag, circle_type, author, sig
        FROM circles LEFT JOIN circle_members ON member_id=id
        WHERE id = :id OR parent_id = :id"
    )]
    fn get_circle_by_id(&self, id: &str) -> Result<Vec<CircleWithMembers>>;
}

#[frb(opaque)]
pub(crate) struct DbMembers {
    pub(crate) id: Vec<u8>,
    pub(crate) circle: CircleOr,
    pub(crate) members: BTreeSet<Vec<u8>>,
}

impl DbMembers {
    pub(crate) fn new(id: CircleOr) -> Result<Self> {
        Ok(Self {
            id: id.as_bytes().to_owned(),
            circle: id,
            members: BTreeSet::new(),
        })
    }
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
#[table("circles")]
#[frb(opaque)]
pub struct CircleData {
    #[primary]
    pub(crate) id: String,
    pub(crate) circle_type: String,
    pub(crate) author: Option<String>,
    pub(crate) sig: Option<Vec<u8>>,
}
#[derive(FromRow, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[table("circle_members")]
#[frb(opaque)]
pub struct CircleMembersData {
    #[primary]
    pub(crate) circle_member_id: Option<i64>,
    pub(crate) member_id: String,
    pub(crate) parent_id: String,
    pub(crate) tag: Option<String>,
}

#[derive(FromRow, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[table("circles")]
#[frb(opaque)]
pub struct CircleWithMembers {
    #[primary]
    id: String,
    member_id: Option<String>,
    parent_id: Option<String>,
    pub(crate) tag: Option<String>,
    pub(crate) circle_type: String,
    author: Option<String>,
    pub(crate) sig: Option<Vec<u8>>,
}

impl CircleWithMembers {
    fn get_bytes(&self, value: &str) -> Result<Vec<u8>> {
        match self.circle_type.as_str() {
            "circle" => Ok(Vec::<u8>::from_hex(value)?),
            "app" => Ok(UserHandle::from_hex(value)?.into_bytes()),
            "user" => Ok(UserHandle::from_hex(value)?.into_bytes()),
            v => Err(InternalErr::InvalidCircleType(v.to_owned())),
        }
    }

    fn get_userhandle(&self, value: &str) -> Result<UserHandle> {
        match self.circle_type.as_str() {
            "circle" => Ok(UserHandle::RawBytes(Vec::<u8>::from_hex(value)?)),
            "app" => Ok(UserHandle::from_hex(value)?),
            "user" => Ok(UserHandle::from_hex(value)?),
            v => Err(InternalErr::InvalidCircleType(v.to_owned())),
        }
    }

    pub fn get_tag(&self) -> Result<Option<MemberTag>> {
        match self.tag.as_deref() {
            Some("delete") => Ok(Some(MemberTag::Delete)),
            Some("merge") => Ok(Some(MemberTag::Merge)),
            Some("overwrite") => Ok(Some(MemberTag::Overwrite)),
            None => Ok(None),
            _ => Err(InternalErr::InvalidMemberTag),
        }
    }

    pub fn get_author(&self) -> Result<Option<UserHandle>> {
        match self.author {
            Some(ref author) => Ok(Some(UserHandle::from_hex(author)?)),
            None => Ok(None),
        }
    }

    pub fn get_member_id(&self) -> Result<Option<Vec<u8>>> {
        match self.member_id {
            Some(ref member) => Ok(Some(self.get_bytes(member)?)),
            None => Ok(None),
        }
    }

    pub fn get_parent_id(&self) -> Result<Option<Vec<u8>>> {
        match self.parent_id {
            Some(ref parent) => Ok(Some(self.get_bytes(parent)?)),
            None => Ok(None),
        }
    }

    pub fn get_id(&self) -> Result<Vec<u8>> {
        self.get_bytes(&self.id)
    }

    pub fn get_id_userhandle(&self) -> Result<UserHandle> {
        self.get_userhandle(&self.id)
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

impl PgpDataCert {
    pub(crate) fn merge(&self, cert: Cert) -> anyhow::Result<Cert> {
        let secret = Cert::from_bytes(&self.data)?;
        secret.merge_public(cert)
    }

    pub(crate) fn as_tsk(cert: PgpCert, tsk: TSK) -> Result<Self> {
        let data = tsk.export_to_vec()?;
        let out = Self {
            keyid: cert.keyid,
            fingerprint: cert.fingerprint.name(),
            online: cert.online,
            role: None,
            data,
        };

        Ok(out)
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

    #[test]
    fn get_all_circles_join() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        let db = SqliteDb::from_conn(db);
        run_migrations(&db).unwrap();

        db.get_circles_join().unwrap();
        db.get_circle_by_id("test").unwrap();
    }
}
