use super::connection::SubrosaDb;
pub use crate::scatterbrain::types::Identity;
use crate::{
    api::proto::ToUuid,
    error::{Result, SubrosaErr},
    proto::{self, news_group::ParentOption, post::AuthorOr, user::Image},
};
use chrono::{NaiveDateTime, Utc};
use fallible_iterator::FallibleIterator;
use flutter_rust_bridge::frb;
use macros::{dao, query, FromRow};
pub use rusqlite::types::Value;
pub use rusqlite::vtab::array::Array;
use rusqlite::{Row, Rows, ToSql};
use sha2::Sha256;
pub use uuid::Uuid;

use sha1::{Digest, Sha1};

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

#[dao]
pub trait SubrosaDao {
    #[query("SELECT * FROM newsgroup WHERE uuid = :uuid")]
    fn get_group(&self, uuid: Uuid) -> Result<Option<NewsGroup>>;

    #[query("SELECT * FROM user WHERE identity = :identity")]
    fn get_user(&self, identity: Uuid) -> Result<Option<User>>;

    #[query("SELECT * from user")]
    fn get_all_users(&self) -> Result<Vec<User>>;

    #[query("SELECT * FROM user WHERE owned = :owned")]
    fn get_all_users_by_ownership(&self, owned: bool) -> Result<Vec<User>>;

    #[query("SELECT * FROM newsgroup WHERE parent IS NULL")]
    fn get_root_groups(&self) -> Result<Vec<NewsGroup>>;

    #[query("SELECT * FROM newsgroup WHERE parent = :parent")]
    fn get_groups_for_parent(&self, parent: &Uuid) -> Result<Vec<NewsGroup>>;

    #[query("DELETE FROM newsgroup WHERE uuid = :uuid")]
    fn delete_group(&self, uuid: Uuid) -> Result<()>;

    #[query("DELETE FROM posts WHERE uuid = :uuid")]
    fn delete_post(&self, uuid: Uuid) -> Result<()>;

    #[query("SELECT * FROM posts WHERE parent_group = :parent ORDER BY receive_date DESC")]
    fn get_posts(&self, parent: &Uuid) -> Result<Vec<Posts>>;

    #[query("SELECT * FROM posts WHERE sent = '0'")]
    fn get_unsent_posts(&self) -> Result<Vec<Posts>>;

    #[query("SELECT * from newsgroup WHERE sent = '0'")]
    fn get_unsent_groups(&self) -> Result<Vec<NewsGroup>>;

    #[query("SELECT receive_date FROM posts ORDER BY receive_date LIMIT 1")]
    fn get_last_sync_date(&self) -> Result<Option<NaiveDateTime>>;

    #[query("SELECT * FROM posts LEFT JOIN user ON user.identity = posts.identity WHERE parent_group = (:parent) ORDER BY receive_date DESC")]
    fn get_posts_with_identity(&self, parent: &Uuid) -> Result<Vec<PostWithIdentity>>;

    #[query("UPDATE posts SET sent = '1' WHERE post_id IN rarray(:ids)")]
    fn mark_sent_posts(&self, ids: Vec<Value>) -> Result<()>;

    #[query("UPDATE newsgroup SET sent = '1' WHERE uuid IN rarray(:ids)")]
    fn mark_sent_groups(&self, ids: Vec<Value>) -> Result<()>;

    #[query("SELECT * FOM identity where uuid = :uuid")]
    fn get_identity(&self, uuid: &Uuid) -> Result<CachedIdentity>;

    #[query(
        "
        WITH RECURSIVE
           post_count(n) AS (
               VALUES(:group)
               UNION
               SELECT uuid FROM newsgroup, post_count
               WHERE newsgroup.parent=post_count.n
           )
           SELECT COUNT(posts.id) FROM posts
           WHERE uuid IN post_count
        "
    )]
    fn get_total_posts(&self, group: &Uuid) -> Result<i64>;

    #[query(
        "
        WITH RECURSIVE
           parent(id) AS (
               select parent from newsgroup where uuid = :group
               UNION ALL
               SELECT parent FROM newsgroup, parent
               WHERE newsgroup.uuid=parent.id
            )
            SELECT * FROM newsgroup where uuid in parent OR uuid = :group
        "
    )]
    fn get_parents(&self, group: &Uuid) -> Result<Vec<NewsGroup>>;
}

pub trait TestTestDao {}

#[derive(FromRow)]
#[table("posts")]
pub struct Posts {
    pub header: Option<String>,
    pub body: Option<String>,
    pub sig: Option<Vec<u8>>,
    pub receive_date: NaiveDateTime,
    #[primary]
    pub post_id: Uuid,
    pub identity: Option<Uuid>,
    pub parent_group: Uuid,
    pub sent: bool,
}

#[derive(FromRow)]
pub struct PostWithIdentity {
    pub author: Option<String>,
    pub header: Option<String>,
    pub body: Option<String>,
    pub sig: Option<Vec<u8>>,
    pub receive_date: NaiveDateTime,
    #[primary]
    pub post_id: Uuid,
    pub identity: Option<Uuid>,
    pub parent_group: Uuid,
    pub sent: bool,
    pub fingerprint: Option<Uuid>,
    pub user_name: Option<String>,
    pub bio: Option<String>,
    pub owned: Option<bool>,
    pub image_bytes: Option<Vec<u8>>,
}

#[derive(FromRow)]
#[table("identity")]
pub struct CachedIdentity {
    #[primary]
    pub uuid: Uuid,
    pub fingerprint: Option<Uuid>,
    pub user_name: Option<String>,
    pub bio: Option<String>,
    pub owned: Option<bool>,
    pub image_bytes: Option<Vec<u8>>,
}
#[frb(opaque)]
pub struct Parent {
    uuid: Uuid,
    hash: Vec<u8>,
}

impl NewsGroup {
    #[frb(sync)]
    pub fn as_parent(&self) -> Parent {
        Parent {
            uuid: self.uuid,
            hash: self.hash(),
        }
    }

    #[frb(sync)]
    pub fn new(
        uuid: Uuid,
        description: String,
        parent: Option<Parent>,
        group_name: String,
        sent: bool,
    ) -> Self {
        let (parent_hash, parent) = match parent {
            None => (None, None),
            Some(Parent { uuid, hash }) => (Some(hash), Some(uuid)),
        };
        NewsGroup {
            uuid,
            description,
            parent_hash,
            parent,
            group_name,
            sent,
        }
    }

    pub fn hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();

        hasher.update(self.uuid.into_bytes());
        if let Some(ref hash) = self.parent_hash {
            hasher.update(hash);
        } else {
            hasher.update(&[]);
        }

        hasher.finalize().to_vec()
    }

    pub(crate) fn from_proto(proto: proto::NewsGroup) -> Result<NewsGroup> {
        let (parent, parent_hash) = match proto.parent_option {
            Some(ParentOption::Toplevel(_)) => (None, None),
            Some(ParentOption::Parent(p)) => {
                (p.parentuuid.map(|v| v.as_uuid()), Some(p.parenthash))
            }
            None => (None, None),
        };
        let ng = NewsGroup {
            uuid: proto.uuid.ok_or_else(|| SubrosaErr::ParseError)?.as_uuid(),
            description: proto.description,
            parent_hash,
            parent,
            group_name: proto.name,
            sent: true,
        };

        Ok(ng)
    }

    pub(crate) fn to_proto(self) -> proto::NewsGroup {
        let parent = match (self.parent, self.parent_hash) {
            (Some(parent), Some(parent_hash)) => Some(ParentOption::Parent(proto::Parent {
                parentuuid: Some(parent.as_proto()),
                parenthash: parent_hash,
            })),
            _ => Some(ParentOption::Toplevel(true)),
        };
        proto::NewsGroup {
            uuid: Some(self.uuid.as_proto()),
            description: self.description,
            parent_option: parent,
            name: self.group_name,
        }
    }
}

impl CachedIdentity {
    pub(crate) fn from_proto(proto: proto::User) -> Result<Self> {
        let v = CachedIdentity {
            uuid: proto
                .identity
                .ok_or_else(|| SubrosaErr::ParseError)?
                .as_uuid(),
            fingerprint: Some(
                proto
                    .identity
                    .ok_or_else(|| SubrosaErr::ParseError)?
                    .as_uuid(),
            ),
            user_name: Some(proto.name),
            bio: Some(proto.bio),
            owned: Some(false),
            image_bytes: match proto.image {
                Some(Image::Imagebytes(bytes)) => Some(bytes),
                _ => None,
            },
        };
        Ok(v)
    }
}

impl Posts {
    fn compat_post_id(&self) -> Uuid {
        let mut hash = Sha1::new();
        if let Some(ref body) = self.body {
            hash.update(body.as_bytes());
        }

        if let Some(ref header) = self.header {
            hash.update(header.as_bytes());
        }

        if let Some(ref author) = self.identity {
            hash.update(author.as_bytes());
        }

        hash.update(self.parent_group.as_bytes());

        Uuid::from_bytes(hash.finalize().as_slice()[0..16].try_into().unwrap())
    }

    pub(crate) fn from_proto(proto: proto::Post) -> Result<Self> {
        let fingerprint = match proto.author_or {
            Some(AuthorOr::Author(v)) => Some(v.as_uuid()),
            None => None,
        };
        let mut p = Posts {
            identity: fingerprint,
            header: Some(proto.header),
            body: Some(proto.body),
            parent_group: proto
                .parent
                .and_then(|v| v.uuid)
                .map(|v| v.as_uuid())
                .ok_or_else(|| SubrosaErr::ParseError)?,
            sig: Some(proto.sig),
            receive_date: Utc::now().naive_utc(),
            post_id: proto
                .uuid
                .map(|v| v.as_uuid())
                .unwrap_or_else(|| Uuid::new_v4()),
            sent: true,
        };

        if proto.uuid.is_none() {
            p.post_id = p.compat_post_id();
        }

        Ok(p)
    }

    pub(crate) fn to_proto(self, db: &SubrosaDb) -> Result<proto::Post> {
        let newsgroup = db.get_group(self.parent_group)?;

        let r = proto::Post {
            uuid: Some(self.post_id.as_proto()),
            header: self.header.unwrap_or_else(|| "".to_owned()),
            body: self.body.unwrap_or_else(|| "".to_owned()),
            parent: newsgroup.map(|v| v.to_proto()),
            sig: self.sig.unwrap_or_else(|| Vec::new()),
            author_or: self.identity.map(|v| AuthorOr::Author(v.as_proto())),
        };

        Ok(r)
    }

    #[frb(sync)]
    pub fn new(header: String, body: String, group: &Uuid) -> Posts {
        Posts {
            header: Some(header),
            body: Some(body),
            sig: None,
            receive_date: chrono::offset::Utc::now().naive_utc(),
            post_id: Uuid::new_v4(),
            identity: None,
            parent_group: *group,
            sent: false,
        }
    }

    #[frb(sync)]
    pub fn new_identity(header: String, body: String, author: Identity, group: &Uuid) -> Posts {
        Posts {
            header: Some(header),
            body: Some(body),
            sig: None,
            receive_date: chrono::offset::Utc::now().naive_utc(),
            post_id: Uuid::new_v4(),
            identity: author.fingerprint,
            parent_group: *group,
            sent: false,
        }
    }
}

#[derive(FromRow)]
pub struct User {
    #[primary]
    pub identity: Uuid,
    pub user_name: String,
    pub bio: String,
    pub owned: bool,
    pub image_bytes: Vec<u8>,
}

impl TestDao for SubrosaDb {}

impl SubrosaDao for SubrosaDb {}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use futures::FutureExt;
    use rusqlite::types::Value;
    use uuid::Uuid;

    use crate::api::db::{
        connection::{Crud, OnConflict, SubrosaDb},
        migrations::run_migrations,
    };

    use super::{NewsGroup, Posts, SubrosaDao, TestDao};

    #[test]
    fn insert_generated() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        let db = SubrosaDb::from_conn(db);
        run_migrations(&db).unwrap();

        let ng = NewsGroup {
            uuid: Uuid::new_v4(),
            description: "Test".to_owned(),
            parent_hash: None,
            parent: None,
            group_name: "test".to_owned(),
            sent: false,
        };

        ng.insert(&db).unwrap();
    }

    #[test]
    fn insert_on_conflict() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        let db = SubrosaDb::from_conn(db);
        run_migrations(&db).unwrap();

        let ng = NewsGroup {
            uuid: Uuid::new_v4(),
            description: "Test".to_owned(),
            parent_hash: None,
            parent: None,
            group_name: "test".to_owned(),
            sent: false,
        };

        ng.insert_on_conflict(&db, OnConflict::Ignore).unwrap();
        ng.insert_on_conflict(&db, OnConflict::Update).unwrap();
    }

    #[test]
    fn post_id() {
        let post = Posts::new(
            "test header".to_owned(),
            "test_body".to_owned(),
            &Uuid::new_v4(),
        );

        let post2 = Posts::new(
            "test header".to_owned(),
            "test_body".to_owned(),
            &Uuid::new_v4(),
        );

        let u1 = post.compat_post_id();

        let u2 = post2.compat_post_id();

        assert_ne!(u1, u2);
    }

    #[test]
    fn insert_posts() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        let db = SubrosaDb::from_conn(db);
        run_migrations(&db).unwrap();

        let group = Uuid::new_v4();
        let ng = Posts::new("test".to_owned(), "test".to_owned(), &group);

        ng.insert_on_conflict(&db, OnConflict::Ignore).unwrap();
        ng.insert_on_conflict(&db, OnConflict::Update).unwrap();
    }

    #[test]
    fn sync_date() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        let db = SubrosaDb::from_conn(db);
        run_migrations(&db).unwrap();

        let group = Uuid::new_v4();
        let ng = Posts::new("test".to_owned(), "test".to_owned(), &group);

        ng.insert_on_conflict(&db, OnConflict::Ignore).unwrap();
        ng.insert_on_conflict(&db, OnConflict::Update).unwrap();

        let d = db.get_last_sync_date().unwrap();
        assert!(d.is_some());
    }

    #[test]
    fn delete_generate_new() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        let db = SubrosaDb::from_conn(db);
        run_migrations(&db).unwrap();

        let ng = NewsGroup {
            uuid: Uuid::new_v4(),
            description: "Test".to_owned(),
            parent_hash: None,
            parent: None,
            group_name: "test".to_owned(),
            sent: false,
        };

        ng.insert(&db).unwrap();

        db.delete_group(ng.uuid).unwrap();

        let g = db.get_group(ng.uuid).unwrap();
        assert!(g.is_none());
    }

    #[test]
    fn mark_sent() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        rusqlite::vtab::array::load_module(&db).unwrap();
        let db = SubrosaDb::from_conn(db);
        run_migrations(&db).unwrap();

        let ng = NewsGroup {
            uuid: Uuid::new_v4(),
            description: "Test".to_owned(),
            parent_hash: None,
            parent: None,
            group_name: "test".to_owned(),

            sent: false,
        };

        let nge = NewsGroup {
            uuid: Uuid::new_v4(),
            description: "Test3".to_owned(),
            parent_hash: None,
            parent: None,
            group_name: "test".to_owned(),

            sent: false,
        };

        let ngp = NewsGroup {
            uuid: Uuid::new_v4(),
            description: "Test2".to_owned(),
            parent_hash: None,
            parent: Some(nge.uuid),
            group_name: "test".to_owned(),

            sent: false,
        };

        ng.insert(&db).unwrap();
        nge.insert(&db).unwrap();
        ngp.insert(&db).unwrap();

        let u1 = Value::from(ng.uuid);
        let u2 = Value::from(nge.uuid);
        let u3 = Value::from(ngp.uuid);

        let sent = db.get_unsent_groups().unwrap();
        assert_eq!(sent.len(), 3);

        db.mark_sent_groups(vec![u1, u2, u3]).unwrap();

        let sent = db.get_unsent_groups().unwrap();
        assert_eq!(sent.len(), 0);
    }

    #[test]
    fn select_parents() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        let db = SubrosaDb::from_conn(db);
        run_migrations(&db).unwrap();

        let ng = NewsGroup {
            uuid: Uuid::new_v4(),
            description: "Test".to_owned(),
            parent_hash: None,
            parent: None,
            group_name: "test".to_owned(),

            sent: false,
        };

        let nge = NewsGroup {
            uuid: Uuid::new_v4(),
            description: "Test3".to_owned(),
            parent_hash: None,
            parent: None,
            group_name: "test".to_owned(),

            sent: false,
        };

        let ngp = NewsGroup {
            uuid: Uuid::new_v4(),
            description: "Test2".to_owned(),
            parent_hash: None,
            parent: Some(nge.uuid),
            group_name: "test".to_owned(),

            sent: false,
        };

        ng.insert(&db).unwrap();
        nge.insert(&db).unwrap();
        ngp.insert(&db).unwrap();

        let p = db.get_parents(&ngp.uuid).unwrap();
        println!("{:?}\n{:?}\n{:?}:::\n\n\n{:?}", ng, nge, ngp, p);
        assert_eq!(p.len(), 2);
    }

    #[tokio::test]
    async fn neg_watcher() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        let db = SubrosaDb::from_conn(db);
        run_migrations(&db).unwrap();

        let uuid = Uuid::new_v4();

        let w = db.get_watcher();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let timeout = tx.clone();
        w.watch("never".to_owned(), move |c| {
            let test = tx.clone();
            async move {
                println!("cb inner");
                c.get_group(uuid).unwrap();
                test.send(true).unwrap();
            }
            .boxed()
        });
        //ng.insert(&db).unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            timeout.send(false).unwrap();
        });
        rx.recv().await.unwrap();
        assert!(!rx.recv().await.unwrap());
    }

    #[tokio::test]
    async fn watcher_drop() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        let db = SubrosaDb::from_conn(db);
        run_migrations(&db).unwrap();

        let uuid = Uuid::new_v4();
        let ng = NewsGroup {
            uuid,
            description: "Test".to_owned(),
            parent_hash: None,
            parent: None,
            group_name: "test".to_owned(),

            sent: false,
        };

        let w = db.get_watcher();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let timeout = tx.clone();
        w.watch("newsgroup".to_owned(), move |c| {
            let test = tx.clone();
            async move {
                println!("cb inner");
                c.get_group(uuid).unwrap();
                test.send(true).unwrap();
            }
            .boxed()
        });
        drop(w);
        ng.insert(&db).unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            timeout.send(false).unwrap();
        });
        rx.recv().await.unwrap();
        assert!(!rx.recv().await.unwrap());
        //assert!(*t.lock().unwrap());
    }

    #[tokio::test]
    async fn watcher() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        let db = SubrosaDb::from_conn(db);
        run_migrations(&db).unwrap();

        let uuid = Uuid::new_v4();
        let ng = NewsGroup {
            uuid,
            description: "Test".to_owned(),
            parent_hash: None,
            parent: None,
            group_name: "test".to_owned(),

            sent: false,
        };

        let w = db.get_watcher();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let timeout = tx.clone();
        w.watch("newsgroup".to_owned(), move |c| {
            let test = tx.clone();
            async move {
                println!("cb inner");
                c.get_group(uuid).unwrap();
                test.send(true).unwrap();
            }
            .boxed()
        });
        ng.insert(&db).unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            timeout.send(false).unwrap();
        });
        assert!(rx.recv().await.unwrap());
        //assert!(*t.lock().unwrap());
    }

    #[test]
    fn post_proto() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        let db = SubrosaDb::from_conn(db);
        run_migrations(&db).unwrap();
        let old = NewsGroup {
            uuid: Uuid::new_v4(),
            description: "test".to_owned(),
            parent_hash: None,
            parent: None,
            group_name: "test".to_owned(),
            sent: false,
        };

        let id = old.uuid;
        db.insert_group(&old).unwrap();
        let old = Posts::new("test".to_owned(), "".to_owned(), &id);

        let p = old.to_proto(&db).unwrap();

        let p = Posts::from_proto(p).unwrap();
    }

    #[test]
    fn group_proto() {
        let old = NewsGroup {
            uuid: Uuid::new_v4(),
            description: "test".to_owned(),
            parent_hash: None,
            parent: None,
            group_name: "test".to_owned(),
            sent: false,
        };

        let p = old.to_proto();

        let p = NewsGroup::from_proto(p).unwrap();
    }

    #[test]
    fn delete_generated() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        let db = SubrosaDb::from_conn(db);
        run_migrations(&db).unwrap();

        let ng = NewsGroup {
            uuid: Uuid::new_v4(),
            description: "Test".to_owned(),
            parent_hash: None,
            parent: None,
            group_name: "test".to_owned(),

            sent: false,
        };

        ng.insert(&db).unwrap();

        ng.delete(&db).unwrap();
    }

    #[test]
    fn update_generated() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        let db = SubrosaDb::from_conn(db);
        run_migrations(&db).unwrap();

        let mut ng = NewsGroup {
            uuid: Uuid::new_v4(),
            description: "Test".to_owned(),
            parent_hash: None,
            parent: None,
            group_name: "test".to_owned(),
            sent: false,
        };

        ng.insert(&db).unwrap();

        ng.description = "cry".to_owned();

        ng.update(&db).unwrap();
    }

    #[test]
    fn dao_select() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        let db = SubrosaDb::from_conn(db);
        run_migrations(&db).unwrap();

        let uuid = Uuid::new_v4();

        let ng = NewsGroup {
            uuid,
            description: "Test".to_owned(),
            parent_hash: None,
            parent: None,
            group_name: "test".to_owned(),
            sent: false,
        };

        ng.insert(&db).unwrap();

        db.test(&uuid).unwrap();
    }
}
